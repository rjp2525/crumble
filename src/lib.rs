//! crumble: cross-platform browser artifact and credential extraction for
//! authorized red team engagements and DFIR.
//!
//! The pipeline stages:
//!
//! 1. [`inventory`] finds installed browsers and their profiles.
//! 2. [`keys`] resolves per-platform master keys on the decryption path.
//! 3. [`stores`] reads artifact stores through [`sniff`] snapshots; live
//!    databases are never opened in place.
//! 4. [`pipeline`] runs collection under the config in
//!    [`options::RunOptions`] (what to target, whether to decrypt, the EDR
//!    policy) and builds the [`model::Report`].
//! 5. [`report`] serializes the report as JSON or JSONL.
//!
//! The run config decides what gets attempted. Whatever a store yields is
//! emitted; there is no post-collection field filtering.

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

// macOS: non-interactive login keychain lock-state probe (Security.framework).
#[cfg(target_os = "macos")]
#[path = "keychain.rs"]
pub mod keychain;

// Windows-only machinery: DPAPI, the ABE `IElevator` COM client and the
// same-image hollowing exchange. All `unsafe` in the crate lives in this
// module tree.
#[cfg(windows)]
#[path = "win32/mod.rs"]
pub mod win32;
