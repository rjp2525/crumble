//! Report serialization: indented JSON, or JSONL with a summary record
//! followed by one record per artifact row (each carrying a `kind`
//! discriminator). Everything collected is emitted — there is no
//! post-collection field filtering.

use crate::model::Report;
use crate::options::Format;

/// Serializes the report in `format` (to a String).
#[must_use]
pub fn render(report: &Report, format: Format) -> String {
    match format {
        Format::Json => format!(
            "{}\n",
            serde_json::to_string_pretty(report).unwrap_or_default()
        ),
        Format::Jsonl => jsonl(report),
    }
}

/// One JSON object per line: a summary record first, then one record per
/// artifact row carrying a `kind` discriminator.
fn jsonl(report: &Report) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let summary = serde_json::json!({
        "kind": "summary",
        "generated_at": report.generated_at,
        "host": report.host,
        "counts": {
            "profiles": report.profiles.len(),
            "credentials": report.credentials.len(),
            "cookies": report.cookies.len(),
            "credit_cards": report.credit_cards.len(),
            "iban_entries": report.iban_entries.len(),
            "oauth_tokens": report.oauth_tokens.len(),
            "autofill": report.autofill.len(),
            "history": report.history.len(),
            "downloads": report.downloads.len(),
            "bookmarks": report.bookmarks.len(),
            "extensions": report.extensions.len(),
        },
        "key_status": report.key_status,
        "collection_errors": report.collection_errors,
        "findings": report.findings,
    });
    let _ = writeln!(
        out,
        "{}",
        serde_json::to_string(&summary).unwrap_or_default()
    );
    let mut line = |kind: &str, value: &serde_json::Value| {
        let mut record = value.clone();
        record["kind"] = serde_json::Value::String(kind.to_string());
        let _ = writeln!(
            out,
            "{}",
            serde_json::to_string(&record).unwrap_or_default()
        );
    };
    for row in &report.profiles {
        line("profile", &serde_json::to_value(row).unwrap_or_default());
    }
    for row in &report.credentials {
        line("credential", &serde_json::to_value(row).unwrap_or_default());
    }
    for row in &report.cookies {
        line("cookie", &serde_json::to_value(row).unwrap_or_default());
    }
    for row in &report.credit_cards {
        line(
            "credit_card",
            &serde_json::to_value(row).unwrap_or_default(),
        );
    }
    for row in &report.iban_entries {
        line("iban", &serde_json::to_value(row).unwrap_or_default());
    }
    for row in &report.oauth_tokens {
        line(
            "oauth_token",
            &serde_json::to_value(row).unwrap_or_default(),
        );
    }
    for row in &report.autofill {
        line("autofill", &serde_json::to_value(row).unwrap_or_default());
    }
    for row in &report.history {
        line("history", &serde_json::to_value(row).unwrap_or_default());
    }
    for row in &report.downloads {
        line("download", &serde_json::to_value(row).unwrap_or_default());
    }
    for row in &report.bookmarks {
        line("bookmark", &serde_json::to_value(row).unwrap_or_default());
    }
    for row in &report.extensions {
        line("extension", &serde_json::to_value(row).unwrap_or_default());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Card, Cookie, Token};

    fn sample() -> Report {
        let mut report = Report {
            profiles: vec![crate::model::ProfileSummary {
                browser: "chrome".into(),
                profile: "Default".into(),
                display_name: "Person 1".into(),
                path: r"C:\Users\jane\AppData\Local\Google\Chrome\User Data\Default".into(),
                is_default: true,
                credential_count: 1,
                cookie_count: 1,
                history_count: 1,
            }],
            credentials: vec![crate::model::Login {
                browser: "chrome".into(),
                profile: "Default".into(),
                origin_url: "https://example.com".into(),
                action_url: "https://example.com/auth".into(),
                username: "jane@example.com".into(),
                password: "hunter2".into(),
                password_stored: true,
                ..Default::default()
            }],
            cookies: vec![Cookie {
                browser: "chrome".into(),
                profile: "Default".into(),
                host: ".example.com".into(),
                name: "sid".into(),
                path: "/".into(),
                value: "session-secret".into(),
                ..Default::default()
            }],
            credit_cards: vec![Card {
                browser: "chrome".into(),
                profile: "Default".into(),
                name: "Jane Doe".into(),
                number_enc: "Y2lwaGVydGV4dA==".into(),
                number: "4111111111111111".into(),
                ..Default::default()
            }],
            oauth_tokens: vec![Token {
                browser: "chrome".into(),
                profile: "Default".into(),
                client_id: "AccountId-1".into(),
                access_token: "ya29.secret".into(),
                refresh_token: "1//secret".into(),
                ..Default::default()
            }],
            ..Report::default()
        };
        report.key_status.insert("chrome".into(), "abe".into());
        report
    }

    #[test]
    fn renders_json_and_jsonl() {
        let report = sample();
        let json = render(&report, Format::Json);
        assert!(json.contains("\"credentials\""));
        assert!(json.contains("\"key_status\""));
        assert!(!json.contains("identifiers_included"));
        let jsonl = render(&report, Format::Jsonl);
        let lines: Vec<&str> = jsonl.lines().collect();
        assert!(lines[0].contains("\"kind\":\"summary\""));
        assert!(lines.iter().any(|l| l.contains("\"kind\":\"credential\"")));
        assert!(lines.iter().any(|l| l.contains("\"kind\":\"cookie\"")));
    }
}
