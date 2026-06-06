//! DPAPI (`CryptUnprotectData`) behind a safe API.
//!
//! Chromium's legacy encryption (pre-App-Bound) wraps the master key with
//! DPAPI tied to the current user: `Local State`'s `os_crypt.encrypted_key`
//! is base64 of `"DPAPI" || dpapi_blob`, and very old per-value blobs are raw
//! DPAPI ciphertexts. Unprotecting works from any process running as the same
//! user.
#![allow(unsafe_code)]

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};

use super::{last_error, WinError};

/// Never show a DPAPI UI prompt (unattended runs only).
const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

/// Decrypts a DPAPI ciphertext as the current user.
///
/// # Errors
/// A Win32 error when `CryptUnprotectData` fails (wrong user, corrupted
/// blob), or a protocol error for input beyond the API's `u32` length limit
/// or a success return with a null buffer.
pub fn unprotect(ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
    if ciphertext.len() > u32::MAX as usize {
        anyhow::bail!("ciphertext exceeds the CryptUnprotectData length limit");
    }
    let input = CRYPT_INTEGER_BLOB {
        cbData: ciphertext.len() as u32,
        // The API declares a mutable pointer but does not write through it
        // for the input blob.
        pbData: ciphertext.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    // SAFETY: both blobs are valid for the call's duration; `output` is
    // written on success and read back below before being freed.
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(last_error("CryptUnprotectData"));
    }
    // A success with a null buffer would make the slice construction UB; a
    // zero-length result is a valid empty plaintext.
    if output.pbData.is_null() {
        if output.cbData == 0 {
            return Ok(Vec::new());
        }
        anyhow::bail!("CryptUnprotectData succeeded but returned a null buffer");
    }
    // SAFETY: on success `output.pbData` points to `output.cbData` readable
    // bytes allocated by the API with LocalAlloc (non-null, checked above).
    let plaintext =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    // SAFETY: `output.pbData` was allocated by CryptUnprotectData via
    // LocalAlloc; freeing it once here is correct.
    unsafe { LocalFree(output.pbData.cast()) };
    Ok(plaintext)
}

/// Error shape used by callers classifying failures.
#[allow(dead_code)]
pub(crate) fn is_win_error(err: &anyhow::Error) -> bool {
    err.downcast_ref::<WinError>().is_some()
}
