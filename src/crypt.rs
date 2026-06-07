//! Chromium per-value blob decryption under the per-provider master keys.
//!
//! Blob formats (all carry a 3-byte ASCII version tag):
//!
//! | tag   | meaning                                                        |
//! |-------|-----------------------------------------------------------------|
//! | `v20` | AES-256-GCM under the App-Bound master key (Windows).           |
//! | `v10` | Windows: AES-256-GCM under the DPAPI master key.                |
//! |       | macOS/Linux: AES-128-CBC under the PBKDF2 legacy key.           |
//! | `v11` | AES-128-CBC under an OS-keyring key (Linux), unsupported.       |
//! | none  | raw DPAPI ciphertext (legacy Windows rows).                     |
//!
//! GCM layout: `tag || nonce(12) || ciphertext || tag(16)`.
//! CBC layout: `tag || ciphertext`; the IV is 16 space bytes, PKCS#7 padded.
//!
//! Current Chromium registers the DPAPI and App-Bound providers at once, so
//! a migrated profile holds `v20` and `v10` rows simultaneously. Both keys
//! are carried in [`KeyBag`] and dispatch is strictly by blob tag.

use aes::cipher::BlockDecryptMut;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use cbc::cipher::KeyIvInit;

/// Chromium's KDF salt for the legacy Unix CBC scheme.
const LEGACY_SALT: &[u8; 9] = b"saltysalt";
/// The fixed CBC IV: 16 space bytes.
const LEGACY_IV: [u8; 16] = [0x20; 16];

/// The per-provider master keys a browser may hold simultaneously.
#[derive(Default)]
pub struct KeyBag {
    /// AES-256-GCM App-Bound key (`v20` blobs) from the browser's elevation
    /// service on Windows.
    pub app_bound: Option<[u8; 32]>,
    /// AES-256-GCM DPAPI key (`v10` blobs, Windows).
    pub dpapi: Option<[u8; 32]>,
    /// AES-128-CBC legacy key (`v10` blobs on macOS/Linux), PBKDF2-derived
    /// from the "Safe Storage" or well-known password.
    pub legacy: Option<[u8; 16]>,
}

impl KeyBag {
    /// True when no provider key resolved; extraction continues counts-only.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.app_bound.is_none() && self.dpapi.is_none() && self.legacy.is_none()
    }
}

impl std::fmt::Debug for KeyBag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Which providers resolved is diagnostic; the key bytes never are.
        f.debug_struct("KeyBag")
            .field("app_bound", &self.app_bound.is_some())
            .field("dpapi", &self.dpapi.is_some())
            .field("legacy", &self.legacy.is_some())
            .finish()
    }
}

impl Drop for KeyBag {
    fn drop(&mut self) {
        for key in [&mut self.app_bound, &mut self.dpapi].into_iter().flatten() {
            key.fill(0);
        }
        if let Some(k) = &mut self.legacy {
            k.fill(0);
        }
    }
}

/// Derives the legacy Unix CBC key: PBKDF2-HMAC-SHA1(password, "saltysalt",
/// `iterations`, 16 bytes). 1003 iterations on macOS, 1 on Linux.
#[cfg_attr(windows, allow(dead_code))]
#[must_use]
pub fn legacy_key_from_password(password: &[u8], iterations: u32) -> [u8; 16] {
    let mut key = [0u8; 16];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password, LEGACY_SALT, iterations, &mut key);
    key
}

/// Moves a freshly unwrapped 32-byte key into a fixed array, zeroing the
/// source vector. Windows-only (the unwrap happens inside the payload).
/// Callers verify the length before calling.
#[cfg(windows)]
#[must_use]
pub fn bag_key32(mut raw: Vec<u8>) -> [u8; 32] {
    let mut key = [0u8; 32];
    key.copy_from_slice(&raw);
    raw.fill(0);
    key
}

/// Decrypts one blob under the key its version tag selects. Returns `None`
/// for unsupported formats, missing keys and authentication or padding
/// failures; a single hostile blob must never abort a store read.
#[must_use]
pub fn unwrap_value(bag: &KeyBag, blob: &[u8]) -> Option<Vec<u8>> {
    match blob.get(..3) {
        Some(b"v20") => gcm_open(&bag.app_bound?, &blob[3..]),
        Some(b"v10") => {
            if let Some(key) = &bag.dpapi {
                gcm_open(key, &blob[3..])
            } else {
                cbc_open(&bag.legacy?, &blob[3..])
            }
        }
        Some(b"v11") => None, // OS-keyring wrapped: unsupported (documented).
        _ => untagged_open(blob),
    }
}

/// Decrypts a cookie value and applies Chromium's cookie-DB v24 rule (M128
/// era): plaintexts are prefixed with the SHA-256 digest of the cookie's
/// `host_key`. The prefix is verified before stripping; older databases carry
/// raw values, and stripping 32 bytes from those would silently truncate
/// them.
#[must_use]
pub fn unwrap_cookie(bag: &KeyBag, host: &str, blob: &[u8]) -> Option<String> {
    use sha2::Digest;
    let plain = unwrap_value(bag, blob)?;
    let digest = sha2::Sha256::digest(host.as_bytes());
    let value = if plain.len() >= 32 && plain[..32] == digest[..] {
        &plain[32..]
    } else {
        &plain[..]
    };
    Some(String::from_utf8_lossy(value).into_owned())
}

/// AES-256-GCM open of `nonce(12) || ciphertext || tag(16)`.
fn gcm_open(key: &[u8; 32], data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 12 + 16 {
        return None;
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let (nonce, ct) = data.split_at(12);
    cipher.decrypt(Nonce::from_slice(nonce), ct).ok()
}

/// AES-128-CBC open with the fixed space IV, stripping PKCS#7 padding.
fn cbc_open(key: &[u8; 16], data: &[u8]) -> Option<Vec<u8>> {
    if data.is_empty() || !data.len().is_multiple_of(16) {
        return None;
    }
    let mut buf = data.to_vec();
    let len = cbc::Decryptor::<aes::Aes128>::new(key.into(), &LEGACY_IV.into())
        .decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buf)
        .ok()
        .map(<[u8]>::len)?;
    buf.truncate(len);
    Some(buf)
}

/// On Windows a tag-less blob is raw DPAPI ciphertext; elsewhere the format
/// is unknown.
#[cfg(windows)]
fn untagged_open(blob: &[u8]) -> Option<Vec<u8>> {
    crate::win32::dpapi::unprotect(blob).ok()
}

#[cfg(not(windows))]
fn untagged_open(_blob: &[u8]) -> Option<Vec<u8>> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::Payload;

    const GCM_KEY: [u8; 32] = [7u8; 32];

    fn gcm_blob(tag: &[u8; 3], key: &[u8; 32], nonce: &[u8; 12], plain: &[u8]) -> Vec<u8> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        let ct = cipher
            .encrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: plain,
                    aad: b"",
                },
            )
            .unwrap();
        let mut blob = tag.to_vec();
        blob.extend_from_slice(nonce);
        blob.extend_from_slice(&ct);
        blob
    }

    #[test]
    fn gcm_roundtrip_and_provider_dispatch() {
        let app_bound = [1u8; 32];
        let dpapi = [2u8; 32];
        let bag = KeyBag {
            app_bound: Some(app_bound),
            dpapi: Some(dpapi),
            legacy: None,
        };
        let v20 = gcm_blob(b"v20", &app_bound, &[9u8; 12], b"new-value");
        let v10 = gcm_blob(b"v10", &dpapi, &[8u8; 12], b"old-value");
        assert_eq!(unwrap_value(&bag, &v20), Some(b"new-value".to_vec()));
        assert_eq!(unwrap_value(&bag, &v10), Some(b"old-value".to_vec()));

        // Strict dispatch: a v10 row never authenticates under the ABE key.
        let abe_only = KeyBag {
            app_bound: Some(app_bound),
            ..Default::default()
        };
        assert_eq!(unwrap_value(&abe_only, &v10), None);
        let dpapi_only = KeyBag {
            dpapi: Some(dpapi),
            ..Default::default()
        };
        assert_eq!(unwrap_value(&dpapi_only, &v20), None);
    }

    #[test]
    fn gcm_rejects_tampering_and_short_input() {
        let bag = KeyBag {
            dpapi: Some(GCM_KEY),
            ..Default::default()
        };
        let mut tampered = gcm_blob(b"v10", &GCM_KEY, &[1u8; 12], b"secret");
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(unwrap_value(&bag, &tampered), None);
        assert_eq!(unwrap_value(&bag, b"v10\0"), None);
        assert_eq!(unwrap_value(&bag, b"v11whatever"), None);
    }

    #[test]
    fn legacy_cbc_chromium_layout() {
        use cbc::cipher::{BlockEncryptMut, KeyIvInit};
        let raw = [9u8; 16];
        let bag = KeyBag {
            legacy: Some(raw),
            ..Default::default()
        };
        let plain = b"s3cret-cookie-value";
        let mut buf = plain.to_vec();
        buf.resize(32, 0);
        let ct_len = {
            let enc = cbc::Encryptor::<aes::Aes128>::new(&raw.into(), &LEGACY_IV.into());
            enc.encrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buf, plain.len())
                .unwrap()
                .len()
        };
        let mut blob = b"v10".to_vec();
        blob.extend_from_slice(&buf[..ct_len]);
        assert_eq!(unwrap_value(&bag, &blob), Some(plain.to_vec()));
    }

    #[test]
    fn pbkdf2_matches_rfc_vector() {
        let key = legacy_key_from_password(b"password", 1);
        assert_eq!(key.len(), 16);
        let mut out = [0u8; 20];
        pbkdf2::pbkdf2_hmac::<sha1::Sha1>(b"password", b"salt", 1, &mut out);
        assert_eq!(
            out,
            [
                0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60,
                0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6
            ]
        );
    }

    #[test]
    fn cookie_digest_prefix_verified_then_stripped() {
        use sha2::Digest;
        let bag = KeyBag {
            app_bound: Some(GCM_KEY),
            ..Default::default()
        };
        let host = ".example.com";
        // v24+ layout: digest || value.
        let mut plain = sha2::Sha256::digest(host.as_bytes()).to_vec();
        plain.extend_from_slice(b"cookie-value");
        let blob = gcm_blob(b"v20", &GCM_KEY, &[1u8; 12], &plain);
        assert_eq!(
            unwrap_cookie(&bag, host, &blob).as_deref(),
            Some("cookie-value")
        );
        // A bare digest strips to empty, not to the digest.
        let plain = sha2::Sha256::digest(host.as_bytes()).to_vec();
        let blob = gcm_blob(b"v20", &GCM_KEY, &[1u8; 12], &plain);
        assert_eq!(unwrap_cookie(&bag, host, &blob).as_deref(), Some(""));
        // Pre-v24 raw values (longer than 32 bytes, no prefix) survive intact.
        let long = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature-part";
        let blob = gcm_blob(b"v20", &GCM_KEY, &[1u8; 12], long);
        assert_eq!(
            unwrap_cookie(&bag, ".example.com", &blob).as_deref(),
            Some(std::str::from_utf8(long).unwrap())
        );
    }

    #[test]
    fn debug_redacts_key_material() {
        let bag = KeyBag {
            app_bound: Some([0xAA; 32]),
            ..Default::default()
        };
        let debug = format!("{bag:?}");
        assert!(!debug.contains("170"));
        assert!(debug.contains("app_bound: true"));
        assert!(!bag.is_empty());
        assert!(KeyBag::default().is_empty());
    }
}
