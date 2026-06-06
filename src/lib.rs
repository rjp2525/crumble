//! crumble — cross-platform browser artifact and credential extraction for
//! authorized red team engagements and DFIR.
//!
//! The library is organized as a pipeline:
//!
//! 1. [`inventory`] — locate installed browsers and their profiles.
//! 2. [`keys`] — resolve per-platform master keys (on the decryption path).
//! 3. [`stores`] — read artifact stores through [`sniff`] snapshots
//!    (live databases are never opened in place).
//! 4. [`pipeline`] — orchestrate collection under the run config
//!    ([`options::RunOptions`]: what to target, whether to decrypt, the EDR
//!    policy) and build the [`model::Report`].
//! 5. [`report`] — serialize the report (JSON / JSONL).
//!
//! What gets attempted is decided by the run config; everything a store
//! yields is emitted. There is no post-collection field filtering.

#![deny(unsafe_code)]

pub mod cli;
pub mod crypt;
pub mod guard;
pub mod inventory;
pub mod keys;
pub mod local_state;
pub mod model;
pub mod options;
pub mod pipeline;
pub mod report;
pub mod sniff;
pub mod stores;
pub mod timestamp;
pub mod wire;

// macOS: non-interactive login-keychain lock-state probe (Security.framework).
#[cfg(target_os = "macos")]
#[path = "keychain.rs"]
pub mod keychain;

// Windows-only machinery: DPAPI, the ABE `IElevator` COM client, and the
// same-image hollowing exchange. All `unsafe` in the crate lives under this
// module tree.
#[cfg(windows)]
#[path = "win32/mod.rs"]
pub mod win32;
