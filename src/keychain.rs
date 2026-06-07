//! macOS-only wrapper around `SecKeychainGetStatus`, a pure non-interactive
//! probe of the login keychain's lock state. Reading a Safe Storage password
//! with the `security` CLI can pop the system unlock dialog when the keychain
//! is locked, which would hang an unattended run, so the lock state is
//! checked first and both "locked" and "unknown" mean "skip the read".
//! Apple's headers name `SecKeychainGetStatus` as the way to verify a
//! keychain is unlocked. The API is deprecated in favor of `SecItem` but is
//! still fully present and supported on macOS.
#![allow(unsafe_code)]

/// `kSecUnlockStateStatus` from `Security/SecKeychain.h`.
const K_SEC_UNLOCK_STATE_STATUS: u32 = 1;

#[link(name = "Security", kind = "framework")]
extern "C" {
    // `SecKeychainRef` is an opaque pointer (NULL selects the default
    // keychain); `SecKeychainStatus` is a `UInt32`; `OSStatus` is `SInt32`.
    #[allow(non_snake_case)]
    fn SecKeychainGetStatus(keychain: *mut std::ffi::c_void, keychainStatus: *mut u32) -> i32;
}

/// Whether the default (login) keychain is currently unlocked, without ever
/// prompting or blocking. An error (in practice: no login keychain at all)
/// is returned for callers to treat the same as "locked".
pub fn login_keychain_unlocked() -> Result<bool, String> {
    let mut status: u32 = 0;
    // SAFETY: `status` is a valid, aligned, writable u32 for the call's
    // duration. NULL selects the default keychain and creates or retains no
    // object, so no CFRelease pair is needed. Unlike
    // SecKeychainUnlock/SecKeychainFindGenericPassword, SecKeychainGetStatus
    // performs no interactive UI regardless of lock state.
    let code = unsafe { SecKeychainGetStatus(std::ptr::null_mut(), &mut status) };
    if code != 0 {
        return Err(format!("SecKeychainGetStatus failed (OSStatus {code})"));
    }
    Ok(status & K_SEC_UNLOCK_STATE_STATUS != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_status_without_erroring_or_prompting() {
        // The point under test is that the call returns PROMPTLY; a hang
        // would mean it silently started prompting. Either outcome is fine: a
        // login keychain yields a bool, and a CI image without one yields an
        // error, which callers treat as "locked".
        let _ = login_keychain_unlocked();
    }
}
