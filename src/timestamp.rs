//! Timestamp conversion: Chromium stores microseconds since 1601-01-01 UTC
//! and Firefox microseconds since 1970-01-01; the report wants ISO 8601
//! strings. No date library: the civil-from-days math is the standard
//! proleptic Gregorian algorithm, unit-tested against known dates.

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds between the Windows (1601) and Unix (1970) epochs.
pub const EPOCH_DELTA_SECS: i64 = 11_644_473_600;

/// Largest representable ISO 8601 timestamp (9999-12-31T23:59:59Z).
const MAX_UNIX_SECS: i64 = 253_402_300_799;

/// Now, as an ISO-8601 UTC string.
#[must_use]
pub fn now_iso() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    unix_to_iso(secs)
}

/// Chromium µs since 1601 to ISO 8601. Zero, negative and out-of-range
/// values become "" (the report's "unknown" representation).
#[must_use]
pub fn chrome_us_to_iso(chrome_us: i64) -> String {
    if chrome_us <= 0 {
        return String::new();
    }
    unix_to_iso(chrome_us / 1_000_000 - EPOCH_DELTA_SECS)
}

/// Firefox µs since 1970 to ISO 8601. Same empty-string rule as
/// [`chrome_us_to_iso`].
#[must_use]
pub fn unix_us_to_iso(unix_us: i64) -> String {
    if unix_us <= 0 {
        return String::new();
    }
    unix_to_iso(unix_us / 1_000_000)
}

/// Unix seconds to ISO 8601 UTC. Out-of-range becomes "".
#[must_use]
pub fn unix_to_iso(unix_secs: i64) -> String {
    if !(0..=MAX_UNIX_SECS).contains(&unix_secs) {
        return String::new();
    }
    let days = unix_secs.div_euclid(86_400);
    let tod = unix_secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = tod / 3600;
    let minute = tod % 3600 / 60;
    let second = tod % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { y + 1 } else { y }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_boundaries() {
        assert_eq!(chrome_us_to_iso(0), "");
        assert_eq!(
            chrome_us_to_iso(EPOCH_DELTA_SECS * 1_000_000),
            "1970-01-01T00:00:00Z"
        );
        assert_eq!(unix_us_to_iso(0), "");
    }

    #[test]
    fn known_dates() {
        assert_eq!(unix_to_iso(0), "1970-01-01T00:00:00Z");
        assert_eq!(unix_to_iso(1_000_000_000), "2001-09-09T01:46:40Z");
        assert_eq!(unix_to_iso(1_700_000_000), "2023-11-14T22:13:20Z");
        // 2024-07-05T12:00:00Z = 1720180800 unix = 13364654400 chrome secs.
        assert_eq!(
            chrome_us_to_iso(13_364_654_400 * 1_000_000),
            "2024-07-05T12:00:00Z"
        );
        assert_eq!(
            unix_us_to_iso(1_720_180_800_000_000),
            "2024-07-05T12:00:00Z"
        );
    }

    #[test]
    fn leap_years() {
        assert_eq!(unix_to_iso(1_709_164_800), "2024-02-29T00:00:00Z");
        assert_eq!(unix_to_iso(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn out_of_range_is_empty() {
        assert_eq!(unix_to_iso(-1), "");
        assert_eq!(unix_to_iso(i64::MAX), "");
        assert_eq!(chrome_us_to_iso(-5), "");
    }
}
