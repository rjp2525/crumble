//! Firefox store extraction. Logins are NSS-encrypted and reported as
//! metadata only (hostname + `password_stored` are the exposure proof);
//! cookie values are plaintext; history/bookmarks live in `places.sqlite`,
//! autofill in `formhistory.sqlite`, extensions in `extensions.json`.
//! Firefox downloads (moz_annos) are not extracted by this version.

use rusqlite::Connection;

use crate::inventory::{Browser, Family, Profile};
use crate::model::{
    Autofill, Bookmark, Cookie, Extension, HistoryEntry, Login, ProfileSummary, Report,
};
use crate::options::RunOptions;
use crate::stores::{each_row, int, limit_clause, note_error, open_store, text};
use crate::timestamp;

/// Extracts every selected artifact of one Firefox profile into `report`.
pub(crate) fn all_rows(
    browser: &Browser,
    profile: &Profile,
    opts: &RunOptions,
    report: &mut Report,
    summary: &mut ProfileSummary,
    errors: &mut Vec<String>,
) {
    if browser.family != Family::Firefox {
        return;
    }
    if opts.wants_artifact("credentials") {
        logins_json(
            &profile.path.join("logins.json"),
            browser,
            profile,
            opts,
            report,
            summary,
            errors,
        );
    }
    if opts.wants_artifact("cookies") {
        if let Some((db, _snap)) = open_store(
            &profile.path.join("cookies.sqlite"),
            browser,
            profile,
            "cookies",
            errors,
        ) {
            cookies(&db, browser, profile, opts, report, summary, errors);
        }
    }
    if opts.wants_artifact("history") {
        if let Some((db, _snap)) = open_store(
            &profile.path.join("places.sqlite"),
            browser,
            profile,
            "places",
            errors,
        ) {
            history(&db, browser, profile, opts, report, summary, errors);
        }
    }
    if opts.wants_artifact("bookmarks") {
        if let Some((db, _snap)) = open_store(
            &profile.path.join("places.sqlite"),
            browser,
            profile,
            "places",
            errors,
        ) {
            bookmarks(&db, browser, profile, opts, report, errors);
        }
    }
    if opts.wants_artifact("autofill") {
        if let Some((db, _snap)) = open_store(
            &profile.path.join("formhistory.sqlite"),
            browser,
            profile,
            "formhistory",
            errors,
        ) {
            autofill(&db, browser, profile, opts, report, errors);
        }
    }
    if opts.wants_artifact("extensions") {
        extensions(
            &profile.path.join("extensions.json"),
            browser,
            profile,
            opts,
            report,
        );
    }
}

/// `logins.json`: usernames/passwords are NSS-encrypted (unsupported);
/// hostname + password_stored are the exposure proof.
fn logins_json(
    path: &std::path::Path,
    browser: &Browser,
    profile: &Profile,
    opts: &RunOptions,
    report: &mut Report,
    summary: &mut ProfileSummary,
    errors: &mut Vec<String>,
) {
    if !path.is_file() {
        return;
    }
    let parsed = std::fs::read_to_string(path)
        .ok()
        .and_then(|content| serde_json::from_str::<serde_json::Value>(&content).ok());
    let Some(json) = parsed else {
        note_error(
            errors,
            browser,
            profile,
            "logins.json",
            "unreadable or malformed",
        );
        return;
    };
    let Some(logins) = json.get("logins").and_then(serde_json::Value::as_array) else {
        return;
    };
    // Exact exposure count: the full array, before the max_items cap below.
    summary.credential_count = summary
        .credential_count
        .saturating_add(logins.len().min(u32::MAX as usize) as u32);
    for login in logins {
        if opts.max_items != 0 && report.credentials.len() >= opts.max_items as usize {
            break;
        }
        report.credentials.push(Login {
            browser: browser.id.to_string(),
            profile: profile.name.clone(),
            origin_url: json_str(login, "hostname"),
            action_url: String::new(),
            username: String::new(),
            password: String::new(),
            password_stored: login.get("encryptedPassword").is_some(),
            date_created: json_ms_time(login.get("timeCreated")),
            date_last_used: json_ms_time(login.get("timeLastUsed")),
            times_used: json_u32(login.get("timesUsed")),
        });
    }
}

fn cookies(
    db: &Connection,
    browser: &Browser,
    profile: &Profile,
    opts: &RunOptions,
    report: &mut Report,
    summary: &mut ProfileSummary,
    errors: &mut Vec<String>,
) {
    // Exact exposure count first, independent of the max_items sample cap.
    summary.cookie_count = summary
        .cookie_count
        .saturating_add(crate::stores::count_rows(
            db,
            "SELECT COUNT(*) FROM moz_cookies",
        ));
    let sql = format!(
        "SELECT host, name, path, isSecure, isHttpOnly, expiry, value FROM moz_cookies{}",
        limit_clause(opts.max_items)
    );
    each_row(
        db,
        &sql,
        [],
        browser,
        profile,
        "moz_cookies",
        errors,
        |row| {
            if opts.max_items != 0 && report.cookies.len() >= opts.max_items as usize {
                return true;
            }
            // Firefox stores cookie values in plaintext; session cookies are
            // credential-equivalent, so they land in the same row type.
            let value = text(row, 6);
            report.cookies.push(Cookie {
                browser: browser.id.to_string(),
                profile: profile.name.clone(),
                host: text(row, 0),
                name: text(row, 1),
                path: text(row, 2),
                value,
                is_secure: int(row, 3) != 0,
                is_httponly: int(row, 4) != 0,
                expires: timestamp::unix_to_iso(int(row, 5)),
            });
            false
        },
    );
}

fn history(
    db: &Connection,
    browser: &Browser,
    profile: &Profile,
    opts: &RunOptions,
    report: &mut Report,
    summary: &mut ProfileSummary,
    errors: &mut Vec<String>,
) {
    let cutoff = crate::stores::unix_cutoff_us(opts.history_days);
    // Exact exposure count first, independent of the max_items sample cap.
    summary.history_count = summary
        .history_count
        .saturating_add(crate::stores::count_since(
            db,
            "SELECT COUNT(*) FROM moz_places WHERE last_visit_date >= ?1",
            cutoff,
        ));
    let sql = format!(
        "SELECT url, title, visit_count, last_visit_date FROM moz_places \
         WHERE last_visit_date >= ?1 ORDER BY last_visit_date DESC{}",
        limit_clause(opts.max_items)
    );
    each_row(
        db,
        &sql,
        rusqlite::params![cutoff],
        browser,
        profile,
        "moz_places",
        errors,
        |row| {
            if opts.max_items != 0 && report.history.len() >= opts.max_items as usize {
                return true;
            }
            report.history.push(HistoryEntry {
                browser: browser.id.to_string(),
                profile: profile.name.clone(),
                url: text(row, 0),
                title: text(row, 1),
                visit_count: int(row, 2).clamp(0, u32::MAX as i64) as u32,
                last_visit: timestamp::unix_us_to_iso(int(row, 3)),
            });
            false
        },
    );
}

/// Bookmarks: `moz_bookmarks` rows of type 1 joined to `moz_places` for the
/// URL; `dateAdded` is µs epoch.
fn bookmarks(
    db: &Connection,
    browser: &Browser,
    profile: &Profile,
    opts: &RunOptions,
    report: &mut Report,
    errors: &mut Vec<String>,
) {
    let sql = format!(
        "SELECT b.title, p.url, b.dateAdded FROM moz_bookmarks b \
         JOIN moz_places p ON p.id = b.fk \
         WHERE b.type = 1 ORDER BY b.dateAdded DESC{}",
        limit_clause(opts.max_items)
    );
    each_row(
        db,
        &sql,
        [],
        browser,
        profile,
        "moz_bookmarks",
        errors,
        |row| {
            if opts.max_items != 0 && report.bookmarks.len() >= opts.max_items as usize {
                return true;
            }
            report.bookmarks.push(Bookmark {
                browser: browser.id.to_string(),
                profile: profile.name.clone(),
                title: text(row, 0),
                url: text(row, 1),
                folder: String::new(),
                added_at: timestamp::unix_us_to_iso(int(row, 2)),
            });
            false
        },
    );
}

fn autofill(
    db: &Connection,
    browser: &Browser,
    profile: &Profile,
    opts: &RunOptions,
    report: &mut Report,
    errors: &mut Vec<String>,
) {
    let sql = format!(
        "SELECT fieldname, value, timesUsed FROM moz_formhistory{}",
        limit_clause(opts.max_items)
    );
    each_row(
        db,
        &sql,
        [],
        browser,
        profile,
        "moz_formhistory",
        errors,
        |row| {
            if opts.max_items != 0 && report.autofill.len() >= opts.max_items as usize {
                return true;
            }
            report.autofill.push(Autofill {
                browser: browser.id.to_string(),
                profile: profile.name.clone(),
                name: text(row, 0),
                value: text(row, 1),
                count: int(row, 2).clamp(0, u32::MAX as i64) as u32,
            });
            false
        },
    );
}

/// The `extensions.json` registry (no XPI digging for id/name/version).
fn extensions(
    path: &std::path::Path,
    browser: &Browser,
    profile: &Profile,
    opts: &RunOptions,
    report: &mut Report,
) {
    let Ok(content) = std::fs::read_to_string(path) else {
        return;
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) else {
        return;
    };
    let Some(addons) = json.get("addons").and_then(serde_json::Value::as_array) else {
        return;
    };
    for addon in addons {
        // Only real extensions (skip themes, dictionaries, langpacks).
        if addon.get("type").and_then(serde_json::Value::as_str) != Some("extension") {
            continue;
        }
        if opts.max_items != 0 && report.extensions.len() >= opts.max_items as usize {
            break;
        }
        let name = addon
            .get("defaultLocale")
            .and_then(|l| l.get("name"))
            .and_then(serde_json::Value::as_str)
            .or_else(|| addon.get("name").and_then(serde_json::Value::as_str))
            .unwrap_or_default()
            .to_string();
        let permissions = addon
            .get("userPermissions")
            .and_then(|p| p.get("permissions"))
            .and_then(serde_json::Value::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        report.extensions.push(Extension {
            browser: browser.id.to_string(),
            profile: profile.name.clone(),
            id: json_str(addon, "id"),
            name,
            version: json_str(addon, "version"),
            enabled: addon
                .get("active")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            permissions,
        });
    }
}

fn json_str(value: &serde_json::Value, key: &str) -> String {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// Firefox/logins.json ms-since-epoch timestamps → ISO-8601.
fn json_ms_time(value: Option<&serde_json::Value>) -> String {
    value
        .and_then(serde_json::Value::as_i64)
        .map(|ms| timestamp::unix_to_iso(ms / 1000))
        .unwrap_or_default()
}

fn json_u32(value: Option<&serde_json::Value>) -> u32 {
    value
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
        .min(u32::MAX as u64) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::profiles;
    use rusqlite::Connection;

    #[test]
    fn firefox_fixture_extracts() {
        let root =
            std::env::temp_dir().join(format!("crumble-test-firefox-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let profile_path = root.join("Profiles/abc.default-release");
        std::fs::create_dir_all(&profile_path).unwrap();
        std::fs::write(
            root.join("profiles.ini"),
            "[Profile0]\nName=default-release\nIsRelative=1\nPath=Profiles/abc.default-release\nDefault=1\n",
        )
        .unwrap();

        let conn = Connection::open(profile_path.join("cookies.sqlite")).unwrap();
        conn.execute(
            "CREATE TABLE moz_cookies (host TEXT, name TEXT, path TEXT, isSecure INTEGER, \
             isHttpOnly INTEGER, expiry INTEGER, value TEXT)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO moz_cookies VALUES ('.example.com', 'sid', '/', 1, 1, 1893456000, 'abc123')",
            [],
        )
        .unwrap();
        drop(conn);

        let conn = Connection::open(profile_path.join("places.sqlite")).unwrap();
        conn.execute(
            "CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, \
             visit_count INTEGER, last_visit_date INTEGER)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO moz_places VALUES (1, 'https://example.com', 'Example', 7, 1720180800000000)",
            [],
        )
        .unwrap();
        conn.execute(
            "CREATE TABLE moz_bookmarks (id INTEGER PRIMARY KEY, type INTEGER, fk INTEGER, \
             parent INTEGER, title TEXT, dateAdded INTEGER)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO moz_bookmarks VALUES (1, 2, NULL, 0, 'Toolbar', 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO moz_bookmarks VALUES (2, 1, 1, 1, 'Example Bookmark', 1720180800000000)",
            [],
        )
        .unwrap();
        drop(conn);

        std::fs::write(
            profile_path.join("logins.json"),
            r#"{"logins":[{"hostname":"https://example.com","encryptedUsername":"u","encryptedPassword":"p","timeCreated":1720180800000,"timeLastUsed":1720180800000,"timesUsed":4}]}"#,
        )
        .unwrap();
        std::fs::write(
            profile_path.join("extensions.json"),
            r#"{"addons":[
                {"id":"uBlock0@raymondhill.net","type":"extension","version":"1.59.0","active":true,
                 "defaultLocale":{"name":"uBlock Origin"},
                 "userPermissions":{"permissions":["tabs","storage"],"origins":["<all_urls>"]}},
                {"id":"@theme-dark","type":"theme","version":"1.0","active":true},
                {"id":"disabled@example.com","type":"extension","version":"2.1","active":false,
                 "defaultLocale":{"name":"Off One"}}
            ]}"#,
        )
        .unwrap();

        let def = Browser {
            id: "firefox",
            label: "Firefox",
            family: Family::Firefox,
            user_data: root.clone(),
            safe_storage: "",
            abe: None,
            exe_candidates: Vec::new(),
        };
        let found = profiles(&def);
        assert_eq!(found.len(), 1);
        let opts = RunOptions::default();
        let mut report = Report::default();
        let mut summary = ProfileSummary::default();
        let mut errors = Vec::new();
        all_rows(
            &def,
            &found[0],
            &opts,
            &mut report,
            &mut summary,
            &mut errors,
        );

        assert_eq!(summary.cookie_count, 1);
        assert_eq!(summary.history_count, 1);
        assert_eq!(summary.credential_count, 1);
        assert!(report.credentials[0].password_stored);
        assert_eq!(report.cookies[0].value, "abc123");
        assert_eq!(report.history[0].last_visit, "2024-07-05T12:00:00Z");
        // Bookmarks: type-1 rows joined to moz_places.
        assert_eq!(report.bookmarks.len(), 1);
        assert_eq!(report.bookmarks[0].title, "Example Bookmark");
        assert_eq!(report.bookmarks[0].url, "https://example.com");
        // Extensions: themes skipped, active/permissions mapped.
        assert_eq!(report.extensions.len(), 2);
        let ublock = &report.extensions[0];
        assert_eq!(ublock.id, "uBlock0@raymondhill.net");
        assert_eq!(ublock.name, "uBlock Origin");
        assert!(ublock.enabled);
        assert_eq!(ublock.permissions, vec!["tabs", "storage"]);
        assert!(!report.extensions[1].enabled);
        let _ = std::fs::remove_dir_all(&root);
    }
}
