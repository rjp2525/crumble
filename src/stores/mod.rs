//! Store access shared by the per-browser extractors.
//!
//! Robustness rules: stores are hostile input and schemas drift between
//! browser versions, so every artifact function fails OPEN (records the
//! failure and returns what it has) — never panics, never aborts the
//! profile. An existing store that cannot be read is recorded
//! ("browser/profile/store: reason"); it must never masquerade as an empty
//! one.

use std::path::Path;

use rusqlite::{Connection, Params, Row};

use crate::inventory::{Browser, Profile};
use crate::sniff;

/// Records one store-level failure, path-free.
pub(crate) fn note_error(
    errors: &mut Vec<String>,
    browser: &Browser,
    profile: &Profile,
    store: &str,
    reason: &str,
) {
    errors.push(format!("{}/{}/{store}: {reason}", browser.id, profile.name));
}

/// Snapshot-plus-open: `None` when the store simply does not exist, but an
/// EXISTING store that cannot be opened is recorded — it must never read as
/// "zero rows". The returned [`sniff::Snapshot`] keeps the copy alive while
/// the connection reads it lazily.
pub(crate) fn open_store(
    path: &Path,
    browser: &Browser,
    profile: &Profile,
    store: &str,
    errors: &mut Vec<String>,
) -> Option<(Connection, sniff::Snapshot)> {
    if !path.is_file() {
        return None;
    }
    let Some((guard, copy)) = sniff::snapshot(path) else {
        note_error(
            errors,
            browser,
            profile,
            store,
            "unreadable (locked or corrupt)",
        );
        return None;
    };
    // The copy is ours — open it read-write: a copied WAL sidecar makes
    // read-only opens fail (SQLite cannot rebuild the wal-index otherwise).
    // This is where crash recovery of the copied store happens, which is also
    // what makes the plain byte copy consistent.
    match Connection::open(&copy) {
        Ok(conn) => Some((conn, guard)),
        Err(_) => {
            note_error(
                errors,
                browser,
                profile,
                store,
                "unreadable (locked or corrupt)",
            );
            None
        }
    }
}

/// Failure reason recorded when a store's prepare or query step fails.
const QUERY_FAILED: &str = "query failed (schema or lock)";

/// Prepares `sql`, calls `visit` per row; `visit` returning `true` stops the
/// iteration early (aggregate `max_items` cap). A prepare/query failure is
/// recorded against the store and ends that store's extraction.
#[allow(clippy::too_many_arguments)]
pub(crate) fn each_row<P: Params>(
    db: &Connection,
    sql: &str,
    params: P,
    browser: &Browser,
    profile: &Profile,
    store: &str,
    errors: &mut Vec<String>,
    mut visit: impl FnMut(&Row) -> bool,
) {
    let Ok(mut stmt) = db.prepare(sql) else {
        note_error(errors, browser, profile, store, QUERY_FAILED);
        return;
    };
    let Ok(mut rows) = stmt.query(params) else {
        note_error(errors, browser, profile, store, QUERY_FAILED);
        return;
    };
    while let Ok(Some(row)) = rows.next() {
        if visit(row) {
            break;
        }
    }
}

/// Reads a text column as a lossy string (NULL/absent → "").
pub(crate) fn text(row: &Row, idx: usize) -> String {
    row.get::<_, Option<String>>(idx)
        .ok()
        .flatten()
        .unwrap_or_default()
}

/// Reads a blob column as bytes (NULL/absent → empty).
pub(crate) fn blob(row: &Row, idx: usize) -> Vec<u8> {
    row.get::<_, Option<Vec<u8>>>(idx)
        .ok()
        .flatten()
        .unwrap_or_default()
}

/// Reads an integer column (NULL/absent → 0).
pub(crate) fn int(row: &Row, idx: usize) -> i64 {
    row.get::<_, Option<i64>>(idx).ok().flatten().unwrap_or(0)
}

/// Exact row total for one store — counts are the exposure signal and must
/// not shrink with the `max_items` sample cap.
pub(crate) fn count_rows(db: &Connection, sql: &str) -> u32 {
    count_query(db, sql, [])
}

/// [`count_rows`] with a single `?1` cutoff parameter.
pub(crate) fn count_since(db: &Connection, sql: &str, cutoff: i64) -> u32 {
    count_query(db, sql, [cutoff])
}

fn count_query<P: Params>(db: &Connection, sql: &str, params: P) -> u32 {
    db.query_row(sql, params, |r| r.get::<_, i64>(0))
        .ok()
        .and_then(|n| u32::try_from(n).ok())
        .unwrap_or(0)
}

/// `" LIMIT n"` when `max_items > 0`, else empty.
pub(crate) fn limit_clause(max_items: u32) -> String {
    if max_items == 0 {
        String::new()
    } else {
        format!(" LIMIT {max_items}")
    }
}

/// Chromium-time cutoff (µs since 1601) for a `history_days` lookback.
pub(crate) fn chrome_cutoff_us(history_days: u32) -> i64 {
    if history_days == 0 {
        return 0;
    }
    now_unix_us() + crate::timestamp::EPOCH_DELTA_SECS * 1_000_000 - lookback_us(history_days)
}

/// Unix-time cutoff (µs since 1970) for a `history_days` lookback.
pub(crate) fn unix_cutoff_us(history_days: u32) -> i64 {
    if history_days == 0 {
        return 0;
    }
    now_unix_us() - lookback_us(history_days)
}

/// µs since the Unix epoch (0 if the system clock predates it).
fn now_unix_us() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}

/// µs in `history_days`, clamped so an absurd value can never overflow (100
/// years of lookback is indistinguishable from "everything").
fn lookback_us(history_days: u32) -> i64 {
    i64::from(history_days.min(36_500)) * 86_400 * 1_000_000
}

/// Maps Chromium's persisted `downloads.state` int to a string
/// (`history::DownloadState`: 0 in-progress, 1 complete, 2 cancelled,
/// 3 obsolete BUG_140687, 4 interrupted).
pub(crate) fn download_state(state: i64) -> &'static str {
    match state {
        0 => "in_progress",
        1 => "complete",
        2 => "cancelled",
        3 | 4 => "interrupted",
        _ => "unknown",
    }
}

pub(crate) mod chromium;
pub(crate) mod firefox;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn download_state_matches_chromium_enum() {
        assert_eq!(download_state(0), "in_progress");
        assert_eq!(download_state(1), "complete");
        assert_eq!(download_state(2), "cancelled");
        assert_eq!(download_state(3), "interrupted");
        assert_eq!(download_state(4), "interrupted");
        assert_eq!(download_state(99), "unknown");
    }

    #[test]
    fn limit_clause_only_when_capped() {
        assert_eq!(limit_clause(0), "");
        assert_eq!(limit_clause(25), " LIMIT 25");
    }
}
