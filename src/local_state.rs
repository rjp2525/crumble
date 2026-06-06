//! Parsing of a Chromium user-data root's `Local State` file: the wrapped
//! master keys (`os_crypt.app_bound_encrypted_key` / `os_crypt.encrypted_key`)
//! and the profile display-name map (`profile.info_cache`).

use std::collections::HashMap;
use std::path::Path;

#[cfg(any(windows, test))]
use base64::Engine;

/// Both wrapped master keys from `Local State`. Current Chromium registers
/// the DPAPI and App-Bound providers simultaneously — a migrated profile
/// holds NEW v20 rows (ABE key) and legacy v10 rows (DPAPI key) at once, so
/// both wrapped keys must be carried, not just the "best" one.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WrappedKeys {
    /// `app_bound_encrypted_key` with the 4-byte `"APPB"` prefix stripped —
    /// decryptable only by the browser's ABE elevation service.
    pub app_bound: Option<Vec<u8>>,
    /// `encrypted_key` with the 5-byte `"DPAPI"` prefix stripped —
    /// decryptable with DPAPI as the current user.
    pub dpapi: Option<Vec<u8>>,
}

impl WrappedKeys {
    /// True when neither provider's wrapped key is present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.app_bound.is_none() && self.dpapi.is_none()
    }
}

/// Reads every available wrapped master key from `<user_data>/Local State`.
/// Windows + tests only (production key resolution happens inside the
/// hollowed Windows payload).
#[cfg(any(windows, test))]
#[must_use]
pub fn wrapped_keys(user_data: &Path) -> WrappedKeys {
    let mut keys = WrappedKeys::default();
    let Some(os_crypt) = local_state_json(user_data).and_then(|j| j.get("os_crypt").cloned())
    else {
        return keys;
    };
    keys.app_bound = os_crypt
        .get("app_bound_encrypted_key")
        .and_then(serde_json::Value::as_str)
        .and_then(|b64| decode_prefixed(b64, b"APPB"));
    keys.dpapi = os_crypt
        .get("encrypted_key")
        .and_then(serde_json::Value::as_str)
        .and_then(|b64| decode_prefixed(b64, b"DPAPI"));
    keys
}

/// Base64-decodes a stored key and strips its ASCII prefix (`"APPB"` is 4
/// bytes, `"DPAPI"` 5), mirroring Chromium's `os_crypt` sync.
#[cfg(any(windows, test))]
fn decode_prefixed(b64: &str, prefix: &[u8]) -> Option<Vec<u8>> {
    let raw = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    if raw.len() <= prefix.len() || !raw.starts_with(prefix) {
        return None;
    }
    Some(raw[prefix.len()..].to_vec())
}

/// Maps profile directory names ("Default", "Profile 1", ...) to the
/// human-facing names recorded in `Local State` (`profile.info_cache`).
#[must_use]
pub fn profile_display_names(user_data: &Path) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Some(cache) = local_state_json(user_data)
        .and_then(|j| j.get("profile")?.get("info_cache")?.as_object().cloned())
    else {
        return out;
    };
    for (dir, info) in cache {
        if let Some(name) = info.get("name").and_then(serde_json::Value::as_str) {
            out.insert(dir.clone(), name.to_string());
        }
    }
    out
}

/// Parses `<user_data>/Local State`, tolerating a missing or malformed file.
fn local_state_json(user_data: &Path) -> Option<serde_json::Value> {
    let content = std::fs::read_to_string(user_data.join("Local State")).ok()?;
    serde_json::from_str(&content).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;

    fn write_local_state(dir: &Path, body: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("Local State"), body).unwrap();
    }

    #[test]
    fn both_providers_read_and_prefixes_stripped() {
        let dir = std::env::temp_dir().join(format!("crumble-test-ls-{}", std::process::id()));
        let appb = STANDARD.encode(b"APPB\x01\x02\x03\x04\x05");
        let dpapi = STANDARD.encode(b"DPAPI\x09\x08\x07");
        write_local_state(
            &dir,
            &format!(
                r#"{{"os_crypt":{{"app_bound_encrypted_key":"{appb}","encrypted_key":"{dpapi}"}}}}"#
            ),
        );
        let keys = wrapped_keys(&dir);
        assert_eq!(keys.app_bound, Some(vec![1, 2, 3, 4, 5]));
        assert_eq!(keys.dpapi, Some(vec![9, 8, 7]));
        assert!(!keys.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dpapi_only_and_malformed() {
        let dir = std::env::temp_dir().join(format!("crumble-test-ls2-{}", std::process::id()));
        let dpapi = STANDARD.encode(b"DPAPI\x09\x08\x07");
        write_local_state(
            &dir,
            &format!(r#"{{"os_crypt":{{"encrypted_key":"{dpapi}"}}}}"#),
        );
        let keys = wrapped_keys(&dir);
        assert_eq!(keys.app_bound, None);
        assert_eq!(keys.dpapi, Some(vec![9, 8, 7]));

        write_local_state(&dir, "not json");
        assert!(wrapped_keys(&dir).is_empty());
        write_local_state(&dir, r#"{"os_crypt":{"app_bound_encrypted_key":"!!!"}}"#);
        assert!(wrapped_keys(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn display_names_read() {
        let dir = std::env::temp_dir().join(format!("crumble-test-ls3-{}", std::process::id()));
        write_local_state(
            &dir,
            r#"{"profile":{"info_cache":{"Default":{"name":"Person 1"},"Profile 2":{"name":"Dev"}}}}"#,
        );
        let names = profile_display_names(&dir);
        assert_eq!(names.get("Default").unwrap(), "Person 1");
        assert_eq!(names.get("Profile 2").unwrap(), "Dev");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
