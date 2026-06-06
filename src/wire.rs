//! The authenticated frame protocol of the Windows payload channel, factored
//! out of the pipe transport so the validation logic is unit-testable on any
//! host (the transport itself is Windows-only, see `crate::win32::conduit`).
//!
//! Wire format: each frame is a 4-byte little-endian length prefix followed
//! by a UTF-8 JSON object. Every frame carries:
//!
//! * `auth` — the per-run token the injector generated and handed to the
//!   payload through its private mailbox page. A local process that guesses
//!   the pipe name cannot know it, so its frames are rejected.
//! * `seq` — a strictly increasing sequence number (0-based), so dropped,
//!   duplicated or reordered frames are detected.
//!
//! The receiving [`Validator`] additionally enforces the frame state machine
//! (one `status`, then `profile`/`row`/`note` events, then a terminal
//! `done`/`err`) and hard ceilings on frame size, total bytes and row count,
//! so a malfunctioning or malicious payload cannot exhaust memory.

// On non-Windows builds only the unit tests exercise this module (the pipe
// transport is Windows-only).
#![cfg_attr(not(any(test, windows)), allow(dead_code))]

use serde_json::Value;

use crate::model::{ProfileSummary, Row};

/// Largest single frame accepted (4 MiB).
pub(crate) const MAX_FRAME_BYTES: usize = 4 << 20;
/// Largest accepted aggregate stream (512 MiB).
pub(crate) const MAX_TOTAL_BYTES: u64 = 512 << 20;
/// Largest accepted row count.
pub(crate) const MAX_ROWS: usize = 200_000;

/// One validated frame event.
#[derive(Debug, PartialEq)]
pub(crate) enum Event {
    /// The payload's key status ("abe", "dpapi", "abe+dpapi", "error: ...").
    Status(String),
    /// A profile summary.
    Profile(ProfileSummary),
    /// One extracted row.
    Row(Row),
    /// A store-level failure note (merged into collection_errors).
    Note(String),
    /// Clean stream end.
    Done,
}

/// The payload-side emitter: stamps frames with `auth` and the next `seq`.
pub(crate) struct Emitter {
    token: String,
    next: u64,
}

impl Emitter {
    #[must_use]
    pub(crate) fn new(token: &str) -> Self {
        Self {
            token: token.to_string(),
            next: 0,
        }
    }

    /// Stamps `value` with the auth token and sequence number.
    pub(crate) fn stamp(&mut self, mut value: Value) -> Value {
        value["auth"] = Value::String(self.token.clone());
        value["seq"] = Value::from(self.next);
        self.next += 1;
        value
    }
}

/// The injector-side validator: auth, sequencing, state machine, ceilings.
pub(crate) struct Validator {
    token: String,
    expected_seq: u64,
    seen_status: bool,
    total_bytes: u64,
    rows: usize,
}

impl Validator {
    #[must_use]
    pub(crate) fn new(token: &str) -> Self {
        Self {
            token: token.to_string(),
            expected_seq: 0,
            seen_status: false,
            total_bytes: 0,
            rows: 0,
        }
    }

    /// Validates one raw frame, returning its event. Any protocol violation
    /// (bad auth, sequence gap, state-machine breach, ceiling overflow,
    /// malformed JSON) is a hard error — the stream aborts, never silently
    /// accepts.
    pub(crate) fn accept(&mut self, frame: &[u8]) -> anyhow::Result<Event> {
        if frame.len() > MAX_FRAME_BYTES {
            anyhow::bail!("frame exceeds {} bytes", MAX_FRAME_BYTES);
        }
        self.total_bytes += frame.len() as u64;
        if self.total_bytes > MAX_TOTAL_BYTES {
            anyhow::bail!("stream exceeds {} bytes", MAX_TOTAL_BYTES);
        }
        let value: Value = serde_json::from_slice(frame)?;
        if value.get("auth").and_then(Value::as_str) != Some(self.token.as_str()) {
            anyhow::bail!("frame with missing or wrong auth token");
        }
        if value.get("seq").and_then(Value::as_u64) != Some(self.expected_seq) {
            anyhow::bail!("frame sequence gap: expected {}", self.expected_seq);
        }
        self.expected_seq += 1;

        match value.get("t").and_then(Value::as_str) {
            Some("status") => {
                if self.seen_status || self.expected_seq != 1 {
                    anyhow::bail!("status frame out of order");
                }
                self.seen_status = true;
                Ok(Event::Status(
                    value
                        .get("key")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                        .to_string(),
                ))
            }
            Some("profile") => {
                self.require_status()?;
                let profile = serde_json::from_value::<ProfileSummary>(
                    value.get("p").cloned().unwrap_or(Value::Null),
                )?;
                Ok(Event::Profile(profile))
            }
            Some("note") => {
                self.require_status()?;
                Ok(Event::Note(
                    value
                        .get("m")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                ))
            }
            Some("done") => {
                self.require_status()?;
                Ok(Event::Done)
            }
            Some("err") => {
                let msg = value
                    .get("m")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown error");
                anyhow::bail!("payload reported: {msg}");
            }
            Some("row") => {
                self.require_status()?;
                let row =
                    serde_json::from_value::<Row>(value.get("r").cloned().unwrap_or(Value::Null))
                        .map_err(|e| anyhow::anyhow!("malformed row frame: {e}"))?;
                self.rows += 1;
                if self.rows > MAX_ROWS {
                    anyhow::bail!("stream exceeds {} rows", MAX_ROWS);
                }
                Ok(Event::Row(row))
            }
            // Unknown frame types are ignored (forward compatibility) — as
            // notes so the stream shape is preserved for the caller.
            _ => {
                self.require_status()?;
                Ok(Event::Note(String::new()))
            }
        }
    }

    fn require_status(&self) -> anyhow::Result<()> {
        if !self.seen_status {
            anyhow::bail!("data frame before status");
        }
        Ok(())
    }
}

/// Frame codec: 4-byte LE length prefix + JSON body.
pub(crate) mod codec {
    /// Prefixes `payload` with its length.
    pub(crate) fn encode(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + payload.len());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// Incrementally decodes length-prefixed frames from a byte stream.
    #[derive(Default)]
    pub(crate) struct Decoder {
        buf: Vec<u8>,
    }

    impl Decoder {
        #[must_use]
        pub(crate) fn new() -> Self {
            Self { buf: Vec::new() }
        }

        /// Feeds bytes; returns every complete frame in order.
        pub(crate) fn push(&mut self, bytes: &[u8]) -> Vec<Vec<u8>> {
            self.buf.extend_from_slice(bytes);
            let mut out = Vec::new();
            loop {
                if self.buf.len() < 4 {
                    break;
                }
                let len = u32::from_le_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]])
                    as usize;
                if self.buf.len() < 4 + len {
                    break;
                }
                out.push(self.buf[4..4 + len].to_vec());
                let rest = self.buf.split_off(4 + len);
                self.buf = rest;
            }
            out
        }
    }
}

/// Lowercase hex encoding (the per-run auth token travels as hex).
#[must_use]
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Login;

    fn drive(
        validator: &mut Validator,
        emitter: &mut Emitter,
        frames: Vec<Value>,
    ) -> Vec<anyhow::Result<Event>> {
        frames
            .into_iter()
            .map(|f| {
                let stamped = emitter.stamp(f);
                let bytes = serde_json::to_vec(&stamped).unwrap();
                validator.accept(&bytes)
            })
            .collect()
    }

    #[test]
    fn happy_path_status_row_done() {
        let mut validator = Validator::new("tok");
        let mut emitter = Emitter::new("tok");
        let results = drive(
            &mut validator,
            &mut emitter,
            vec![
                serde_json::json!({"t": "status", "key": "abe+dpapi"}),
                serde_json::json!({"t": "profile", "p": {"browser": "chrome", "profile": "Default", "credential_count": 3}}),
                serde_json::json!({"t": "note", "m": "chrome/Default/History: unreadable"}),
                serde_json::json!({"t": "row", "r": {"Login": {"browser": "chrome", "profile": "Default", "username": "u", "password": "p", "password_stored": true}}}),
                serde_json::json!({"t": "done"}),
            ],
        );
        assert!(results.iter().all(|r| r.is_ok()));
        assert!(matches!(&results[0], Ok(Event::Status(s)) if s == "abe+dpapi"));
        assert!(
            matches!(&results[1], Ok(Event::Profile(p)) if p.credential_count == 3 && p.profile == "Default")
        );
        assert!(matches!(&results[2], Ok(Event::Note(n)) if n.contains("unreadable")));
        assert!(matches!(&results[3], Ok(Event::Row(Row::Login(l))) if l.username == "u"));
        assert!(matches!(results[4], Ok(Event::Done)));
    }

    #[test]
    fn wrong_token_rejected() {
        let mut validator = Validator::new("tok");
        let mut other = Emitter::new("OTHER");
        let frame = serde_json::to_vec(&other.stamp(serde_json::json!({"t": "status"}))).unwrap();
        assert!(validator.accept(&frame).is_err());
    }

    #[test]
    fn sequence_gap_and_ordering_rejected() {
        let mut validator = Validator::new("tok");
        let mut emitter = Emitter::new("tok");
        let _ = emitter.stamp(serde_json::json!({"t": "status"})); // seq 0 burned
        let frame = serde_json::to_vec(&emitter.stamp(serde_json::json!({"t": "done"}))).unwrap();
        assert!(validator.accept(&frame).is_err(), "seq 1 before seq 0");

        let mut validator = Validator::new("tok");
        let mut emitter = Emitter::new("tok");
        let results = drive(
            &mut validator,
            &mut emitter,
            vec![serde_json::json!({"t": "profile"})],
        );
        assert!(results[0].is_err(), "data before status");

        let mut validator = Validator::new("tok");
        let results = drive(
            &mut validator,
            &mut Emitter::new("tok"),
            vec![
                serde_json::json!({"t": "status"}),
                serde_json::json!({"t": "status"}),
            ],
        );
        assert!(results[1].is_err(), "duplicate status");
    }

    #[test]
    fn error_frame_aborts_with_message() {
        let mut validator = Validator::new("tok");
        let results = drive(
            &mut validator,
            &mut Emitter::new("tok"),
            vec![
                serde_json::json!({"t": "status", "key": "unavailable"}),
                serde_json::json!({"t": "err", "m": "key resolution failed"}),
            ],
        );
        assert!(results[0].is_ok());
        let err = results[1].as_ref().unwrap_err().to_string();
        assert!(err.contains("key resolution failed"), "{err}");
    }

    #[test]
    fn codec_roundtrips_split_frames() {
        let a = codec::encode(b"hello");
        let b = codec::encode(b"world");
        let mut stream = a.clone();
        stream.extend_from_slice(&b);
        // Split mid-frame: decoder must buffer until complete.
        let mut decoder = codec::Decoder::new();
        assert!(decoder.push(&stream[..6]).is_empty());
        let frames = decoder.push(&stream[6..]);
        assert_eq!(frames, vec![b"hello".to_vec(), b"world".to_vec()]);
    }

    #[test]
    fn hex_encode_known_vectors() {
        assert_eq!(hex_encode(&[]), "");
        assert_eq!(hex_encode(&[0xDE, 0xAD, 0xBE, 0xEF]), "deadbeef");
    }

    #[test]
    fn login_row_json_roundtrip() {
        let row = Row::Login(Login {
            browser: "chrome".into(),
            profile: "Default".into(),
            username: "u".into(),
            password: "p".into(),
            password_stored: true,
            ..Default::default()
        });
        let value = serde_json::to_value(&row).unwrap();
        let back: Row = serde_json::from_value(value).unwrap();
        assert_eq!(row, back);
    }
}
