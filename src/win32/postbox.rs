//! The fixed-address mailbox page shared by the injector (writer) and the
//! hollowed payload (reader). The injector plants the request — browser id,
//! per-run auth token, the discovered per-user user-data root, and the raw
//! run options — at a known address before resuming the suspended browser;
//! the payload, re-entered through `main`, finds it via an environment
//! marker. The layout is pure data manipulation so it is unit-testable on
//! any host; only reading the page in the payload's own address space needs
//! `unsafe` (and lives in `proxy.rs`).
#![allow(unsafe_code)]

/// Environment variable carrying the mailbox address to the payload.
pub const MAILBOX_ENV: &str = "CRUMBLE_MAILBOX";
/// Marker distinguishing a genuine mailbox from foreign data at the address.
pub const MAGIC: u32 = 0x4352_4D42; // "CRMB"
/// Page state: a request has been planted.
pub const STATE_REQUEST: u32 = 1;
/// Offset of the request record within the page.
pub const REQUEST_OFFSET: usize = 0x10;
/// Offset of the fatal-error response region within the page.
pub const RESPONSE_OFFSET: usize = 0x1000;
/// Total mailbox size.
pub const MAILBOX_SIZE: usize = 0x2000;
/// Longest browser id accepted.
pub const MAX_ID_LEN: usize = 64;

/// The parsed request handed across the trust boundary.
#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    /// Browser id the payload must impersonate ("chrome", ...).
    pub browser_id: String,
    /// Per-run auth token (16 raw bytes); authenticates every pipe frame.
    pub token: Vec<u8>,
    /// The profile-owning user's user-data root (resolved per user by the
    /// injector — the payload must NOT re-resolve it from its own
    /// environment).
    pub user_data: std::path::PathBuf,
    /// The operator's options as JSON.
    pub options_json: String,
}

/// Serializes the request record into its page layout.
pub fn encode_request(browser_id: &str, blob: &[u8]) -> anyhow::Result<Vec<u8>> {
    if browser_id.len() > MAX_ID_LEN {
        anyhow::bail!("browser id too long for the mailbox");
    }
    let capacity = RESPONSE_OFFSET - REQUEST_OFFSET;
    if 8 + browser_id.len() + blob.len() > capacity {
        anyhow::bail!("request too large for the mailbox");
    }
    let mut buf = vec![0u8; REQUEST_OFFSET + 8 + browser_id.len() + blob.len()];
    buf[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    buf[4..8].copy_from_slice(&STATE_REQUEST.to_le_bytes());
    let at = REQUEST_OFFSET;
    buf[at..at + 4].copy_from_slice(&(browser_id.len() as u32).to_le_bytes());
    buf[at + 4..at + 8].copy_from_slice(&(blob.len() as u32).to_le_bytes());
    buf[at + 8..at + 8 + browser_id.len()].copy_from_slice(browser_id.as_bytes());
    buf[at + 8 + browser_id.len()..].copy_from_slice(blob);
    Ok(buf)
}

/// Builds the request blob: token, NUL-terminated user-data root, options
/// JSON. (Windows paths cannot contain NUL, so the separator is unambiguous.)
pub fn encode_blob(token: &[u8; 16], user_data: &std::path::Path, options_json: &str) -> Vec<u8> {
    let mut blob = token.to_vec();
    blob.extend_from_slice(user_data.to_string_lossy().as_bytes());
    blob.push(0);
    blob.extend_from_slice(options_json.as_bytes());
    blob
}

/// Splits a page image into (header-validated raw request, response region).
pub fn split_page(page: &[u8]) -> Option<(&[u8], &[u8])> {
    if page.len() < MAILBOX_SIZE {
        return None;
    }
    if u32::from_le_bytes(page[0..4].try_into().ok()?) != MAGIC
        || u32::from_le_bytes(page[4..8].try_into().ok()?) != STATE_REQUEST
    {
        return None;
    }
    Some((&page[REQUEST_OFFSET..], &page[RESPONSE_OFFSET..]))
}

/// Decodes a raw request record into its components.
pub fn decode_request(raw: &[u8]) -> Option<(String, Vec<u8>)> {
    if raw.len() < 8 {
        return None;
    }
    let id_len = u32::from_le_bytes(raw[0..4].try_into().ok()?) as usize;
    let blob_len = u32::from_le_bytes(raw[4..8].try_into().ok()?) as usize;
    if id_len == 0 || id_len > MAX_ID_LEN {
        return None;
    }
    let total = 8usize.checked_add(id_len)?.checked_add(blob_len)?;
    if total > RESPONSE_OFFSET - REQUEST_OFFSET || total > raw.len() {
        return None;
    }
    let id = String::from_utf8(raw[8..8 + id_len].to_vec()).ok()?;
    Some((id, raw[8 + id_len..total].to_vec()))
}

/// Decodes a full [`Request`] from the blob.
pub fn decode_blob(blob: &[u8]) -> Option<Request> {
    if blob.len() < 16 {
        return None;
    }
    let (token, rest) = blob.split_at(16);
    let nul = rest.iter().position(|&b| b == 0)?;
    let user_data = String::from_utf8(rest[..nul].to_vec()).ok()?;
    Some(Request {
        browser_id: String::new(), // filled by decode_request
        token: token.to_vec(),
        user_data: std::path::PathBuf::from(user_data),
        options_json: String::from_utf8_lossy(&rest[nul + 1..]).into_owned(),
    })
}

/// Serializes the fatal-error response record (ok flag + message).
pub fn encode_response(ok: bool, payload: &[u8]) -> Vec<u8> {
    let capacity = MAILBOX_SIZE - RESPONSE_OFFSET - 8;
    let len = payload.len().min(capacity);
    let mut buf = Vec::with_capacity(8 + len);
    buf.extend_from_slice(&(ok as u32).to_le_bytes());
    buf.extend_from_slice(&(len as u32).to_le_bytes());
    buf.extend_from_slice(&payload[..len]);
    buf
}

/// Decodes the response record.
pub fn decode_response(raw: &[u8]) -> Option<(bool, Vec<u8>)> {
    if raw.len() < 8 {
        return None;
    }
    let ok = u32::from_le_bytes(raw[0..4].try_into().ok()?) != 0;
    let len = u32::from_le_bytes(raw[4..8].try_into().ok()?) as usize;
    if len > raw.len() - 8 {
        return None;
    }
    Some((ok, raw[8..8 + len].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_layout_roundtrip() {
        let blob = encode_blob(
            &[9u8; 16],
            std::path::Path::new(r"C:\Users\jane\AppData\Local"),
            "{}",
        );
        let page = encode_request("chrome", &blob).unwrap();
        assert_eq!(u32::from_le_bytes(page[0..4].try_into().unwrap()), MAGIC);
        assert_eq!(
            u32::from_le_bytes(page[4..8].try_into().unwrap()),
            STATE_REQUEST
        );

        let (raw, _response) = split_page(&page).expect("valid page");
        let (id, decoded_blob) = decode_request(raw).unwrap();
        assert_eq!(id, "chrome");
        let request = decode_blob(&decoded_blob).unwrap();
        assert_eq!(request.token, vec![9u8; 16]);
        assert_eq!(
            request.user_data,
            std::path::Path::new(r"C:\Users\jane\AppData\Local")
        );
        assert_eq!(request.options_json, "{}");
    }

    #[test]
    fn oversized_request_rejected() {
        let blob = vec![0u8; RESPONSE_OFFSET - REQUEST_OFFSET];
        assert!(encode_request("chrome", &blob).is_err());
        assert!(encode_request(&"x".repeat(MAX_ID_LEN + 1), &[]).is_err());
    }

    #[test]
    fn response_roundtrip() {
        let encoded = encode_response(false, b"pipe unreachable");
        assert_eq!(
            decode_response(&encoded),
            Some((false, b"pipe unreachable".to_vec()))
        );
        assert!(decode_response(&encoded[..4]).is_none());
    }

    #[test]
    fn garbage_page_rejected() {
        let page = vec![0u8; MAILBOX_SIZE];
        assert!(split_page(&page).is_none());
        assert!(split_page(&[0u8; 16]).is_none());
    }
}
