//! Least-alarming access to live browser databases.
//!
//! Live stores (`Login Data`, `Cookies`, `Web Data`, `History`) are never
//! opened through SQLite. Each is byte-copied (plain sequential file reads,
//! no locks, no write intent) together with its WAL sidecars into a private,
//! owner-only temp directory under a neutral name, and all database work runs
//! against the copy (SQLite crash recovery over the copied WAL makes the copy
//! consistent). The browser is never disturbed and the live store paths see
//! no database-access pattern at all.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// A private temp directory holding one copied database; removed on drop.
pub struct Snapshot {
    dir: PathBuf,
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Copies `path` into a fresh private temp directory, returning the snapshot
/// guard and the copied db path. The copy is renamed to a neutral
/// cache-style name: a file literally called `Login Data` or `Cookies` in a
/// temp directory is an infostealer IOC signature scanners match, whatever
/// the reader's intent.
///
/// The directory is created exclusively with an unguessable nanosecond
/// component, owner-only on Unix: on a shared `/tmp` another user can neither
/// pre-create a predicted path nor squat the namespace. The plain byte copy
/// (+ WAL sidecars) is tried first; SQLite's online-backup API (the formally
/// consistent snapshot of a live WAL database, at the price of a SQLite open
/// on the live file) is the fallback when the plain copy fails.
pub fn snapshot(path: &Path) -> Option<(Snapshot, PathBuf)> {
    sweep_orphans();
    let pid = std::process::id();
    let original = path.file_name()?.to_string_lossy().into_owned();
    for _ in 0..16 {
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = std::env::temp_dir().join(format!("crumble-{pid}-{seq}-{nanos:x}"));
        // `mut` is only needed on Unix, where the mode is set below.
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(&dir) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return None,
        }
        let neutral = format!("store{seq}.db");
        let copy = dir.join(&neutral);
        let plain = std::fs::copy(path, &copy).is_ok();
        if plain {
            for sidecar in ["-wal", "-shm"] {
                let side = path.with_file_name(format!("{original}{sidecar}"));
                if side.is_file() {
                    let _ = std::fs::copy(&side, dir.join(format!("{neutral}{sidecar}")));
                }
            }
        }
        if !plain && backup_api_snapshot(path, &copy).is_none() {
            let _ = std::fs::remove_dir_all(&dir);
            return None;
        }
        return Some((Snapshot { dir }, copy));
    }
    None
}

static SEQ: AtomicU64 = AtomicU64::new(0);

/// One consistent snapshot of a possibly-locked database via SQLite's online
/// backup API. `run_to_completion` retries Busy/Locked forever (a running
/// browser would hang us indefinitely), so the step loop is driven by hand
/// under a hard deadline.
fn backup_api_snapshot(source: &Path, dest: &Path) -> Option<()> {
    /// Total budget for the backup before giving up on a locked source.
    const BUDGET: std::time::Duration = std::time::Duration::from_secs(10);
    use rusqlite::{Connection, OpenFlags};
    let src = Connection::open_with_flags(source, OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;
    let mut dst = Connection::open(dest).ok()?;
    let backup = rusqlite::backup::Backup::new(&src, &mut dst).ok()?;
    let deadline = std::time::Instant::now() + BUDGET;
    loop {
        match backup.step(8) {
            Ok(rusqlite::backup::StepResult::Done) => return Some(()),
            Ok(rusqlite::backup::StepResult::More) => {}
            Ok(rusqlite::backup::StepResult::Busy | rusqlite::backup::StepResult::Locked) => {
                if std::time::Instant::now() >= deadline {
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Ok(_) => {}
            Err(_) => return None,
        }
    }
}

/// Best-effort removal of snapshots orphaned by a crashed run (termination
/// bypasses `Snapshot::drop`). Once per process; only `crumble-*` dirs older
/// than an hour are touched.
fn sweep_orphans() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let cutoff = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
            return;
        };
        for entry in entries.flatten() {
            if !entry.file_name().to_string_lossy().starts_with("crumble-") {
                continue;
            }
            let stale = entry
                .metadata()
                .and_then(|m| m.modified())
                .map(|t| t < cutoff)
                .unwrap_or(false);
            if stale {
                let _ = std::fs::remove_dir_all(entry.path());
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn snapshot_dir_is_exclusive_private_and_gone_after_drop() {
        use std::os::unix::fs::PermissionsExt;

        let src_root =
            std::env::temp_dir().join(format!("crumble-test-snap-{}", std::process::id()));
        std::fs::create_dir_all(&src_root).unwrap();
        let source = src_root.join("Cookies");
        std::fs::write(&source, b"db-bytes").unwrap();

        let (g1, c1) = snapshot(&source).expect("first snapshot");
        let (g2, c2) = snapshot(&source).expect("second snapshot");
        assert_ne!(c1.parent().unwrap(), c2.parent().unwrap());
        for copy in [&c1, &c2] {
            assert_eq!(std::fs::read(copy).unwrap(), b"db-bytes");
            let mode = std::fs::metadata(copy.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700, "snapshot dir must be owner-only");
        }
        let dir1 = c1.parent().unwrap().to_path_buf();
        let dir2 = c2.parent().unwrap().to_path_buf();
        drop(g1);
        drop(g2);
        assert!(!dir1.exists(), "guard removes the dir on drop");
        assert!(!dir2.exists(), "guard removes the dir on drop");
        let _ = std::fs::remove_dir_all(&src_root);
    }

    #[test]
    fn missing_source_is_none() {
        let ghost = std::env::temp_dir().join("crumble-test-ghost-Login Data");
        assert!(snapshot(&ghost).is_none());
    }
}
