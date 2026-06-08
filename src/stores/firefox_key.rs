//! Firefox login decryption: master key from `key4.db`, then `logins.json`.
//!
//! Firefox protects logins with NSS. Each profile holds a master key in
//! `key4.db` (SQLite, read here through a snapshot like every other store):
//!
//! - `metadata` row `password`: `item1` is the global salt and `item2` is a
//!   PKCS#5 PBE envelope whose plaintext must be `password-check` plus
//!   padding. The PBE algorithm selects the scheme: SHA1/HMAC-3DES
//!   (`pbeWithSha1AndTripleDES-CBC`) on legacy profiles, PBES2 with
//!   PBKDF2-HMAC-SHA256 and AES-256-CBC (`pkcs5 PBES2`, Firefox 75+).
//! - `nssPrivate`: the row whose `a102` equals the NSS `CKA_ID` carries the
//!   encrypted master key in `a11`, under the same PBE envelope.
//!
//! The empty-password derivation is used throughout: a profile with a master
//! password set fails the password check and is reported unsupported.
//! `nssPrivate` can hold several generations of the master key at once (a
//! 3DES key from before the Firefox 75 migration plus the AES-256
//! replacement), so every candidate row is decrypted and kept; each
//! `logins.json` entry names its own cipher by OID and is decrypted with the
//! matching key. That also covers migration profiles where old 3DES entries
//! and new AES entries sit side by side. Pre-Firefox 58 `key3.db`
//! (Berkeley DB) profiles are unsupported.

use aes::cipher::BlockDecryptMut;
use base64::Engine as _;
use cbc::cipher::KeyIvInit;
use des::TdesEde3;
use hmac::Mac;
use rusqlite::Connection;
use sha1::Digest as _;

/// Expected PBE password-check plaintext, padding included.
const PASSWORD_CHECK: &[u8] = b"password-check\x02\x02";

/// NSS `CKA_ID` marking the private-key row and every login entry.
const CKA_ID: [u8; 16] = [
    0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

/// OID `pbeWithSha1AndTripleDES-CBC` (1.2.840.113549.1.12.5.1.3).
const OID_PBE_SHA1_3DES: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x05, 0x01, 0x03,
];
/// OID `pkcs5 PBES2` (1.2.840.113549.1.5.13).
const OID_PBE_S2: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d];
/// OID `pkcs5 PBKDF2` (1.2.840.113549.1.5.12).
const OID_PBKDF2: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c];
/// OID `hmacWithSHA256` (1.2.840.113549.2.9).
const OID_HMAC_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09];
/// OID `aes256-CBC` (2.16.840.1.101.3.4.1.42).
const OID_AES256_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a];

/// OID `des-ede3-cbc` (1.2.840.113549.3.7), the per-entry cipher on legacy
/// `logins.json` envelopes.
const OID_DES_EDE3_CBC: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x07];
/// The resolved Firefox master key(s) for one profile. Both generations are
/// kept when present; each `logins.json` entry selects its cipher by OID.
pub(crate) struct FirefoxKeys {
    /// 24-byte 3DES key (pre-Firefox 75 profiles).
    des3: Option<[u8; 24]>,
    /// 32-byte AES-256 key (Firefox 75+).
    aes: Option<[u8; 32]>,
}

impl FirefoxKeys {
    fn is_empty(&self) -> bool {
        self.des3.is_none() && self.aes.is_none()
    }

    /// Merges another candidate (different `nssPrivate` row) into this set.
    fn merge(&mut self, other: FirefoxKeys) {
        if self.des3.is_none() {
            self.des3 = other.des3;
        }
        if self.aes.is_none() {
            self.aes = other.aes;
        }
    }
}

impl std::fmt::Debug for FirefoxKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FirefoxKeys")
            .field("des3", &self.des3.is_some())
            .field("aes", &self.aes.is_some())
            .finish()
    }
}

impl Drop for FirefoxKeys {
    fn drop(&mut self) {
        if let Some(k) = &mut self.des3 {
            k.fill(0);
        }
        if let Some(k) = &mut self.aes {
            k.fill(0);
        }
    }
}

/// Resolves the profile's Firefox master key(s) from `key4.db`.
///
/// # Errors
/// Returns a machine-ish reason when no key can be used: no `key4.db`, a
/// master-password-protected profile, a missing private-key row or unknown
/// PBE schemes throughout. Never contains a secret.
pub(crate) fn resolve(profile_dir: &std::path::Path) -> Result<FirefoxKeys, String> {
    let key4 = profile_dir.join("key4.db");
    if !key4.is_file() {
        return Err("no key4.db (key3.db profiles are unsupported)".to_string());
    }
    let Some((_guard, copy)) = crate::sniff::snapshot(&key4) else {
        return Err("key4.db unreadable (locked or corrupt)".to_string());
    };
    let Ok(conn) = Connection::open(&copy) else {
        return Err("key4.db unreadable (locked or corrupt)".to_string());
    };

    // Global salt and password-check envelope.
    let Ok((global_salt, item2)) = conn.query_row(
        "SELECT item1, item2 FROM metadata WHERE id = 'password'",
        [],
        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
    ) else {
        return Err("key4.db metadata missing".to_string());
    };
    let check = decrypt_pbe(&item2, &global_salt)?;
    if check != PASSWORD_CHECK {
        return Err("master password set (unsupported)".to_string());
    }

    // The private-key row is the one whose a102 equals the CKA_ID.
    let mut stmt = conn
        .prepare("SELECT a11, a102 FROM nssPrivate")
        .map_err(|e| format!("key4.db nssPrivate unreadable: {e}"))?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, Option<Vec<u8>>>(0)?,
                row.get::<_, Option<Vec<u8>>>(1)?,
            ))
        })
        .map_err(|e| format!("key4.db nssPrivate unreadable: {e}"))?;
    let mut keys = FirefoxKeys {
        des3: None,
        aes: None,
    };
    for row in rows.flatten() {
        let (Some(a11), Some(key_id)) = row else {
            continue;
        };
        if key_id != CKA_ID {
            continue;
        }
        if let Ok(material) = decrypt_pbe(&a11, &global_salt) {
            if let Some(candidate) = single_key(material) {
                keys.merge(candidate);
            }
        }
    }
    if keys.is_empty() {
        Err("no Firefox private key row".to_string())
    } else {
        Ok(keys)
    }
}

/// Builds one candidate key from decrypted `a11` material, stripping PKCS#7
/// padding when present and falling back to the known length buckets
/// (24-byte 3DES key padded to 32, 32-byte AES key padded to 48).
fn single_key(material: Vec<u8>) -> Option<FirefoxKeys> {
    let trimmed = pkcs7_unpad(&material).unwrap_or(&material);
    match trimmed.len() {
        24 => {
            let mut key = [0u8; 24];
            key.copy_from_slice(trimmed);
            Some(FirefoxKeys {
                des3: Some(key),
                aes: None,
            })
        }
        32 => {
            let mut key = [0u8; 32];
            key.copy_from_slice(trimmed);
            Some(FirefoxKeys {
                des3: None,
                aes: Some(key),
            })
        }
        _ => None,
    }
}

/// Decrypts one `logins.json` entry (`encryptedUsername` /
/// `encryptedPassword`) under the master key. Returns `None` for malformed
/// envelopes, foreign key ids and padding failures.
/// Decrypts one `logins.json` entry (`encryptedUsername` /
/// `encryptedPassword`). The entry's OID selects the cipher and the matching
/// master key. Returns `None` for malformed envelopes, foreign key ids,
/// missing key generations and padding failures.
pub(crate) fn decrypt_entry(keys: &FirefoxKeys, b64: &str) -> Option<Vec<u8>> {
    let der = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    let top = der_parse(&der)?;
    let mut items = top.children();
    let key_id = items.next()?.content;
    if key_id != CKA_ID {
        return None;
    }
    let alg = items.next()?;
    let mut alg_items = alg.children();
    let oid = alg_items.next()?.content;
    let iv = alg_items.next()?.content;
    let ct = items.next()?.content;
    match oid {
        OID_AES256_CBC => keys.aes.as_ref().and_then(|k| aes_cbc(k, iv, ct)),
        OID_DES_EDE3_CBC => keys.des3.as_ref().and_then(|k| des3_cbc(k, iv, ct)),
        _ => None,
    }
}

/// AES-256-CBC open with PKCS#7 unpad; IV must be 16 bytes.
fn aes_cbc(key: &[u8; 32], iv: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    if ct.is_empty() || !ct.len().is_multiple_of(16) || iv.len() != 16 {
        return None;
    }
    let mut buf = ct.to_vec();
    cbc::Decryptor::<aes::Aes256>::new(key.into(), iv.into())
        .decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buf)
        .ok()
        .map(|p| p.to_vec())
}

/// 3DES-CBC open with PKCS#7 unpad; IV must be 8 bytes.
fn des3_cbc(key: &[u8; 24], iv: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    if ct.is_empty() || !ct.len().is_multiple_of(8) || iv.len() != 8 {
        return None;
    }
    let mut buf = ct.to_vec();
    cbc::Decryptor::<TdesEde3>::new(key.into(), iv.into())
        .decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buf)
        .ok()
        .map(|p| p.to_vec())
}

/// Decrypts a PBE envelope (`metadata.item2` or `nssPrivate.a11`):
/// `SEQUENCE { SEQUENCE { OID, params }, OCTET STRING ciphertext }`.
fn decrypt_pbe(envelope: &[u8], global_salt: &[u8]) -> Result<Vec<u8>, String> {
    let top = der_parse(envelope).ok_or_else(|| "malformed PBE envelope".to_string())?;
    let mut items = top.children();
    let params_seq = items
        .next()
        .ok_or_else(|| "PBE params missing".to_string())?;
    let ct = items
        .next()
        .ok_or_else(|| "PBE ciphertext missing".to_string())?
        .content;
    let mut param_items = params_seq.children();
    let oid = param_items
        .next()
        .ok_or_else(|| "PBE algorithm missing".to_string())?;
    let params = param_items
        .next()
        .ok_or_else(|| "PBE parameters missing".to_string())?;
    if oid.content == OID_PBE_SHA1_3DES {
        pbe_sha1_3des(&params, global_salt, ct)
    } else if oid.content == OID_PBE_S2 {
        pbes2(&params, global_salt, ct)
    } else {
        Err("unknown PBE scheme".to_string())
    }
}

/// `pbeWithSha1AndTripleDES-CBC`: params are
/// `SEQUENCE { OCTET STRING entrySalt, INTEGER 1 }`.
fn pbe_sha1_3des(params: &Der<'_>, global_salt: &[u8], ct: &[u8]) -> Result<Vec<u8>, String> {
    let mut items = params.children();
    let entry_salt = items
        .next()
        .ok_or_else(|| "3DES entry salt missing".to_string())?
        .content;
    let (key, iv) = kdf_3des(global_salt, entry_salt);
    decrypt_3des(&key, &iv, ct).ok_or_else(|| "3DES decrypt failed".to_string())
}

/// The SHA1/HMAC-3DES PBE key derivation (master password empty).
fn kdf_3des(global_salt: &[u8], entry_salt: &[u8]) -> ([u8; 24], [u8; 8]) {
    let mut hp = sha1::Sha1::new();
    hp.update(global_salt);
    let hp: [u8; 20] = hp.finalize_reset().into();
    let mut pes = entry_salt.to_vec();
    pes.resize(20, 0);
    let mut chp = sha1::Sha1::new();
    chp.update(hp);
    chp.update(entry_salt);
    let chp: [u8; 20] = chp.finalize_reset().into();
    let k1 = hmac_sha1(&chp, &[pes.as_slice(), entry_salt].concat());
    let tk = hmac_sha1(&chp, &pes);
    let k2 = hmac_sha1(&chp, &[tk.as_slice(), entry_salt].concat());
    let mut key = [0u8; 24];
    key[..20].copy_from_slice(&k1);
    key[20..].copy_from_slice(&k2[..4]);
    let mut iv = [0u8; 8];
    iv.copy_from_slice(&k2[12..20]);
    (key, iv)
}

fn hmac_sha1(key: &[u8; 20], data: &[u8]) -> [u8; 20] {
    let mut mac =
        <hmac::Hmac<sha1::Sha1> as Mac>::new_from_slice(key).expect("HMAC-SHA1 accepts any key");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&out);
    arr
}

/// Raw CBC decrypt (no padding): PBE envelopes carry their padding inside
/// the plaintext (the password check compares against a padded constant).
fn decrypt_3des(key: &[u8; 24], iv: &[u8; 8], ct: &[u8]) -> Option<Vec<u8>> {
    if ct.is_empty() || !ct.len().is_multiple_of(8) {
        return None;
    }
    let mut buf = ct.to_vec();
    cbc::Decryptor::<TdesEde3>::new(key.into(), iv.into())
        .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf)
        .ok()
        .map(|p| p.to_vec())
}

/// PBES2: params are
/// `SEQUENCE { SEQUENCE { OID PBKDF2, SEQUENCE { OCTET STRING salt, INTEGER
/// iterations, INTEGER 32, SEQUENCE { OID hmacWithSHA256 } } },
/// SEQUENCE { OID aes256-CBC, OCTET STRING ivParam } }`.
///
/// NSS stores a 14-byte IV parameter; the actual IV is its DER encoding
/// (`04 0e` header plus the 14 bytes), used verbatim as the AES IV.
fn pbes2(params: &Der<'_>, global_salt: &[u8], ct: &[u8]) -> Result<Vec<u8>, String> {
    let mut items = params.children();
    let kdf_seq = items
        .next()
        .ok_or_else(|| "PBES2 KDF missing".to_string())?;
    let enc_seq = items
        .next()
        .ok_or_else(|| "PBES2 encryption scheme missing".to_string())?;
    let mut kdf_items = kdf_seq.children();
    let kdf_oid = kdf_items
        .next()
        .ok_or_else(|| "PBES2 KDF OID missing".to_string())?;
    if kdf_oid.content != OID_PBKDF2 {
        return Err("unsupported PBES2 KDF".to_string());
    }
    let mut kdf_params = kdf_items
        .next()
        .ok_or_else(|| "PBES2 KDF params missing".to_string())?
        .children();
    let salt = kdf_params
        .next()
        .ok_or_else(|| "PBES2 salt missing".to_string())?
        .content;
    let iterations =
        der_int(kdf_params.next()).ok_or_else(|| "PBES2 iterations missing".to_string())?;
    let key_len =
        der_int(kdf_params.next()).ok_or_else(|| "PBES2 key length missing".to_string())? as usize;
    let prf_seq = kdf_params
        .next()
        .ok_or_else(|| "PBES2 PRF missing".to_string())?;
    let mut prf = prf_seq.children();
    let prf_oid = prf
        .next()
        .ok_or_else(|| "PBES2 PRF OID missing".to_string())?;
    if prf_oid.content != OID_HMAC_SHA256 {
        return Err("unsupported PBES2 PRF".to_string());
    }
    if key_len != 32 {
        return Err("unexpected PBES2 key length".to_string());
    }
    let mut enc = enc_seq.children();
    let enc_oid = enc
        .next()
        .ok_or_else(|| "PBES2 cipher OID missing".to_string())?;
    if enc_oid.content != OID_AES256_CBC {
        return Err("unsupported PBES2 cipher".to_string());
    }
    let iv_param = enc
        .next()
        .ok_or_else(|| "PBES2 IV missing".to_string())?
        .content;
    let mut iv = vec![0x04, 0x0e];
    iv.extend_from_slice(iv_param);

    // PBKDF2-HMAC-SHA256 over SHA1(globalSalt), master password empty.
    let mut k = sha1::Sha1::new();
    k.update(global_salt);
    let k: [u8; 20] = k.finalize_reset().into();
    let mut key = vec![0u8; key_len];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(&k, salt, iterations, &mut key);

    if ct.is_empty() || !ct.len().is_multiple_of(16) || iv.len() != 16 {
        return Err("PBES2 ciphertext malformed".to_string());
    }
    let key: &[u8; 32] = key
        .as_slice()
        .try_into()
        .map_err(|_| "PBES2 key".to_string())?;
    let iv: &[u8; 16] = iv
        .as_slice()
        .try_into()
        .map_err(|_| "PBES2 IV".to_string())?;
    let mut buf = ct.to_vec();
    cbc::Decryptor::<aes::Aes256>::new(key.into(), iv.into())
        .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf)
        .map(<[u8]>::to_vec)
        .map_err(|_| "PBES2 decrypt failed".to_string())
}

/// PKCS#7 unpad on a block multiple; `None` when the padding is invalid.
fn pkcs7_unpad(data: &[u8]) -> Option<&[u8]> {
    let &last = data.last()?;
    let pad = usize::from(last);
    if pad == 0 || pad > data.len() || !data[data.len() - pad..].iter().all(|&b| b == last) {
        return None;
    }
    Some(&data[..data.len() - pad])
}

// ---------------------------------------------------------------------------
// Minimal DER reader (SEQUENCE, OCTET STRING, OID, INTEGER; short+long form)
// ---------------------------------------------------------------------------

/// One parsed DER element. `children` holds the elements of a SEQUENCE.
pub(crate) struct Der<'a> {
    pub tag: u8,
    pub content: &'a [u8],
}

impl<'a> Der<'a> {
    /// Iterates the children when this element is a SEQUENCE (empty otherwise).
    fn children(&self) -> impl Iterator<Item = Der<'a>> {
        let mut out = Vec::new();
        if self.tag == 0x30 {
            let mut rest = self.content;
            while let Some((el, remaining)) = der_element(rest) {
                out.push(el);
                rest = remaining;
            }
        }
        out.into_iter()
    }
}

fn der_element(input: &[u8]) -> Option<(Der<'_>, &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&len_byte, rest) = rest.split_first()?;
    let (len, rest) = if len_byte & 0x80 == 0 {
        (usize::from(len_byte), rest)
    } else {
        let n = usize::from(len_byte & 0x7f);
        if n == 0 || n > std::mem::size_of::<usize>() || rest.len() < n {
            return None;
        }
        let mut len = 0usize;
        for &b in &rest[..n] {
            len = (len << 8) | usize::from(b);
        }
        (len, &rest[n..])
    };
    if rest.len() < len {
        return None;
    }
    let (content, remaining) = rest.split_at(len);
    Some((Der { tag, content }, remaining))
}

fn der_parse(data: &[u8]) -> Option<Der<'_>> {
    der_element(data).map(|(el, _)| el)
}

/// Reads a DER INTEGER as u32.
fn der_int(el: Option<Der<'_>>) -> Option<u32> {
    let content = el?.content;
    let mut value = 0u32;
    for &b in content {
        value = (value << 8) | u32::from(b);
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::BlockEncryptMut;
    use cbc::cipher::KeyIvInit;
    use rusqlite::Connection;

    /// OID `des-ede3-cbc` (1.2.840.113549.3.7), used in entry fixtures.
    const OID_DES_EDE3_CBC: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x07];

    // ---- minimal DER encoder for fixtures ----

    fn len_bytes(n: usize) -> Vec<u8> {
        if n < 0x80 {
            vec![n as u8]
        } else {
            let mut tmp = n;
            let mut bytes = vec![];
            while tmp > 0 {
                bytes.push((tmp & 0xff) as u8);
                tmp >>= 8;
            }
            bytes.reverse();
            let mut out = vec![0x80 | bytes.len() as u8];
            out.extend(bytes);
            out
        }
    }

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend(len_bytes(content.len()));
        out.extend(content);
        out
    }

    fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
        tlv(0x30, &parts.concat())
    }

    fn oct(data: &[u8]) -> Vec<u8> {
        tlv(0x04, data)
    }

    fn int(n: u32) -> Vec<u8> {
        let bytes = n.to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(3);
        tlv(0x02, &bytes[start..])
    }

    fn oid(bytes: &[u8]) -> Vec<u8> {
        tlv(0x06, bytes)
    }

    // ---- encryption helpers mirroring the production decrypt paths ----

    fn encrypt_3des(key: &[u8; 24], iv: &[u8; 8], padded: &[u8]) -> Vec<u8> {
        let mut buf = padded.to_vec();
        cbc::Encryptor::<TdesEde3>::new(key.into(), iv.into())
            .encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf, padded.len())
            .unwrap();
        buf[..padded.len()].to_vec()
    }

    fn pkcs7(data: &[u8], block: usize) -> Vec<u8> {
        let pad = block - (data.len() % block);
        let mut out = data.to_vec();
        out.extend(std::iter::repeat_n(pad as u8, pad));
        out
    }

    fn encrypt_aes(key: &[u8; 32], iv: &[u8; 16], padded: &[u8]) -> Vec<u8> {
        let mut buf = padded.to_vec();
        cbc::Encryptor::<aes::Aes256>::new(key.into(), iv.into())
            .encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf, padded.len())
            .unwrap();
        buf[..padded.len()].to_vec()
    }

    // ---- PBE envelope builders ----

    /// Builds a `pbeWithSha1AndTripleDES-CBC` envelope around `plaintext`
    /// (already padded to the 3DES block size).
    fn envelope_3des(global_salt: &[u8], entry_salt: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let (key, iv) = kdf_3des(global_salt, entry_salt);
        let ct = encrypt_3des(&key, &iv, plaintext);
        seq(&[
            seq(&[oid(OID_PBE_SHA1_3DES), seq(&[oct(entry_salt), int(1)])]),
            oct(&ct),
        ])
    }

    /// Builds a PBES2 (PBKDF2-HMAC-SHA256 + AES-256-CBC) envelope around
    /// `plaintext` (already padded to 16 bytes). Returns the envelope and
    /// the AES key for building entries.
    fn envelope_pbes2(
        global_salt: &[u8],
        entry_salt: &[u8],
        plaintext: &[u8],
    ) -> (Vec<u8>, [u8; 32]) {
        let k: [u8; 20] = sha1::Sha1::digest(global_salt).into();
        let mut key = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(&k, entry_salt, 1, &mut key);
        let iv_param = [0x42u8; 14];
        let mut iv = vec![0x04, 0x0e];
        iv.extend_from_slice(&iv_param);
        let ct = encrypt_aes(&key, iv.as_slice().try_into().unwrap(), plaintext);
        let envelope = seq(&[
            seq(&[
                oid(OID_PBE_S2),
                seq(&[
                    seq(&[
                        oid(OID_PBKDF2),
                        seq(&[
                            oct(entry_salt),
                            int(1),
                            int(32),
                            seq(&[oid(OID_HMAC_SHA256)]),
                        ]),
                    ]),
                    seq(&[oid(OID_AES256_CBC), oct(&iv_param)]),
                ]),
            ]),
            oct(&ct),
        ]);
        (envelope, key)
    }

    /// A login entry exactly as `logins.json` carries it (base64 of the
    /// DER), using the AES key when the profile has one and 3DES otherwise.
    fn entry(keys: &FirefoxKeys, plaintext: &[u8]) -> String {
        let (algo_oid, ct, iv): (&[u8], Vec<u8>, Vec<u8>) = if let Some(k) = &keys.aes {
            let iv = [0x22u8; 16];
            (
                OID_AES256_CBC,
                encrypt_aes(k, &iv, &pkcs7(plaintext, 16)),
                iv.to_vec(),
            )
        } else {
            let k = keys.des3.as_ref().expect("fixture has a 3DES key");
            let iv = [0x11u8; 8];
            (
                OID_DES_EDE3_CBC,
                encrypt_3des(k, &iv, &pkcs7(plaintext, 8)),
                iv.to_vec(),
            )
        };
        let der = seq(&[oct(&CKA_ID), seq(&[oid(algo_oid), oct(&iv)]), oct(&ct)]);
        base64::engine::general_purpose::STANDARD.encode(der)
    }

    /// Writes a synthetic `key4.db` (metadata + nssPrivate) into `dir`.
    fn write_key4(
        dir: &std::path::Path,
        global_salt: &[u8],
        password_check_envelope: &[u8],
        a11_envelope: &[u8],
    ) {
        let conn = Connection::open(dir.join("key4.db")).unwrap();
        conn.execute(
            "CREATE TABLE metadata (id TEXT PRIMARY KEY, item1 BLOB, item2 BLOB)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO metadata VALUES ('password', ?1, ?2)",
            rusqlite::params![global_salt, password_check_envelope],
        )
        .unwrap();
        conn.execute("CREATE TABLE nssPrivate (a11 BLOB, a102 BLOB)", [])
            .unwrap();
        conn.execute(
            "INSERT INTO nssPrivate VALUES (?1, ?2)",
            rusqlite::params![a11_envelope, CKA_ID.to_vec()],
        )
        .unwrap();
        drop(conn);
    }

    fn fixture_dir(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("crumble-test-ffkey-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn resolves_and_decrypts_3des_profile() {
        let dir = fixture_dir("3des");
        let global_salt = [0x33u8; 16];
        let check = envelope_3des(&global_salt, b"salt-one-salt-t", PASSWORD_CHECK);
        // 24-byte master key, PKCS#7 padded to 32 for the envelope.
        let mut master = [0xAAu8; 24];
        master[0] = 0x07;
        let a11 = envelope_3des(&global_salt, b"salt-two-salt-t", &pkcs7(&master, 8));
        write_key4(&dir, &global_salt, &check, &a11);

        let keys = resolve(&dir).expect("3DES key4.db must resolve");
        assert!(keys.des3.is_some() && keys.aes.is_none());
        let entry = entry(&keys, b"jane@example.com");
        assert_eq!(
            decrypt_entry(&keys, &entry).as_deref(),
            Some(b"jane@example.com".as_slice())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolves_and_decrypts_aes_profile() {
        let dir = fixture_dir("aes");
        let global_salt = [0x44u8; 16];
        let (check, _) = envelope_pbes2(&global_salt, &[0x55u8; 32], PASSWORD_CHECK);
        let mut master = [0xBBu8; 32];
        master[0] = 0x09;
        let (a11, _) = envelope_pbes2(&global_salt, &[0x66u8; 32], &pkcs7(&master, 16));
        write_key4(&dir, &global_salt, &check, &a11);

        let keys = resolve(&dir).expect("AES key4.db must resolve");
        assert!(keys.aes.is_some() && keys.des3.is_none());
        let entry = entry(&keys, b"hunter2");
        assert_eq!(
            decrypt_entry(&keys, &entry).as_deref(),
            Some(b"hunter2".as_slice())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn master_password_fails_the_check() {
        let dir = fixture_dir("mp");
        let global_salt = [0x77u8; 16];
        // Envelope whose plaintext is NOT the password-check constant.
        let check = envelope_3des(&global_salt, b"salt-one-salt_t", b"garbage-garbage!");
        let a11 = envelope_3des(&global_salt, b"salt-two-salt_t", &pkcs7(&[1u8; 24], 8));
        write_key4(&dir, &global_salt, &check, &a11);

        let err = resolve(&dir).unwrap_err();
        assert!(err.contains("master password"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_key4_and_foreign_entries_are_errors() {
        let dir = fixture_dir("none");
        let err = resolve(&dir).unwrap_err();
        assert!(err.contains("key4.db"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn foreign_key_id_entry_is_skipped() {
        let dir = fixture_dir("foreign");
        let global_salt = [0x88u8; 16];
        let check = envelope_3des(&global_salt, b"salt-one-salt_t", PASSWORD_CHECK);
        let a11 = envelope_3des(&global_salt, b"salt-two-salt_t", &pkcs7(&[2u8; 24], 8));
        write_key4(&dir, &global_salt, &check, &a11);
        let keys = resolve(&dir).unwrap();
        let key = keys.des3.as_ref().expect("fixture key is 3DES");

        let mut foreign_id = CKA_ID;
        foreign_id[0] = 0x11;
        let iv = [0x33u8; 8];
        let ct = encrypt_3des(key, &iv, &pkcs7(b"nope", 8));
        let der = seq(&[
            oct(&foreign_id),
            seq(&[oid(OID_DES_EDE3_CBC), oct(&iv)]),
            oct(&ct),
        ]);
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        assert!(decrypt_entry(&keys, &b64).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
