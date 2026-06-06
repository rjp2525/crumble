//! The report model: one `Report` per run, mirroring the artifact classes the
//! tool understands. Field semantics follow the browser stores they come from;
//! counts are exact, row payloads are sample-capped by
//! [`crate::options::RunOptions::max_items`].

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Severity of a [`Finding`], lowest to highest.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Purely informational.
    #[default]
    Info,
    /// A store existed but could not be read.
    Low,
    /// Decryptable secret material was present.
    Medium,
}

/// One discovered browser profile with per-store exposure counts. Counts are
/// the always-emitted signal; they never depend on the row sample cap.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProfileSummary {
    /// Browser id ("chrome", "firefox", ...).
    pub browser: String,
    /// On-disk profile name ("Default", "Profile 1", ...).
    pub profile: String,
    /// Human-facing profile name recorded by the browser.
    pub display_name: String,
    /// Absolute profile directory.
    pub path: String,
    /// Whether this is the browser's default profile.
    pub is_default: bool,
    /// Exact rows in the login stores.
    pub credential_count: u32,
    /// Exact rows in the cookie store.
    pub cookie_count: u32,
    /// Exact rows in the history store (after the lookback filter).
    pub history_count: u32,
}

/// A stored login.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Login {
    pub browser: String,
    pub profile: String,
    pub origin_url: String,
    pub action_url: String,
    pub username: String,
    /// Decrypted password; empty when no key resolved or decryption failed.
    pub password: String,
    /// Exposure proof: a password blob existed, regardless of decryption.
    pub password_stored: bool,
    pub date_created: String,
    pub date_last_used: String,
    pub times_used: u32,
}

/// A cookie. Firefox values are plaintext; Chromium values are decrypted when
/// a key is available.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Cookie {
    pub browser: String,
    pub profile: String,
    pub host: String,
    pub name: String,
    pub path: String,
    /// Plaintext value; empty when no key resolved or decryption failed.
    pub value: String,
    pub is_secure: bool,
    pub is_httponly: bool,
    /// ISO-8601 expiry; empty for session cookies.
    pub expires: String,
}

/// A payment card. `number_enc` (the ciphertext) is the always-safe exposure
/// proof and is always present.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Card {
    pub browser: String,
    pub profile: String,
    /// Name on card.
    pub name: String,
    /// Base64 of the ciphertext blob.
    pub number_enc: String,
    /// Decrypted number; empty when no key resolved or decryption failed.
    pub number: String,
    pub expiry_month: u32,
    pub expiry_year: u32,
    pub billing_address: String,
    pub date_added: String,
}

/// A stored IBAN (SEPA account record).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Iban {
    pub browser: String,
    pub profile: String,
    pub name: String,
    /// Decrypted IBAN; empty when no key resolved or decryption failed.
    pub iban: String,
    pub bic: String,
    pub bank_name: String,
    pub account_number: String,
    pub date_added: String,
}

/// An OAuth token record (Chromium `token_service` holds Google account
/// refresh tokens).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Token {
    pub browser: String,
    pub profile: String,
    pub provider: String,
    /// The `service` key — identifies the signed-in account.
    pub client_id: String,
    pub access_token: String,
    /// Decrypted refresh token; empty when no key resolved or decryption failed.
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: u32,
    pub scope: Vec<String>,
    pub created_at: String,
}

/// One autofill name/value pair.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Autofill {
    pub browser: String,
    pub profile: String,
    pub name: String,
    /// The filled value.
    pub value: String,
    pub count: u32,
}

/// A history visit.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HistoryEntry {
    pub browser: String,
    pub profile: String,
    pub url: String,
    pub title: String,
    pub visit_count: u32,
    pub last_visit: String,
}

/// A download.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Download {
    pub browser: String,
    pub profile: String,
    pub url: String,
    pub target_path: String,
    pub total_bytes: u64,
    pub received_bytes: u64,
    /// `in_progress` | `complete` | `cancelled` | `interrupted` | `unknown`.
    pub state: String,
    pub started_at: String,
    pub finished_at: String,
}

/// A bookmark.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Bookmark {
    pub browser: String,
    pub profile: String,
    pub title: String,
    pub url: String,
    /// Slash-joined folder path from the root.
    pub folder: String,
    pub added_at: String,
}

/// An installed extension.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Extension {
    pub browser: String,
    pub profile: String,
    pub id: String,
    pub name: String,
    pub version: String,
    pub enabled: bool,
    pub permissions: Vec<String>,
}

/// An always-safe exposure finding: counts and key status only, never raw
/// identifiers or secrets.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub evidence: BTreeMap<String, String>,
}

/// The full run output. Everything collected is emitted: there is no
/// consent-tier filtering — the operator's selection decides what is
/// attempted, and whatever a store yields lands here.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub generated_at: String,
    pub host: String,
    pub profiles: Vec<ProfileSummary>,
    pub credentials: Vec<Login>,
    pub cookies: Vec<Cookie>,
    pub credit_cards: Vec<Card>,
    pub iban_entries: Vec<Iban>,
    pub oauth_tokens: Vec<Token>,
    pub autofill: Vec<Autofill>,
    pub history: Vec<HistoryEntry>,
    pub downloads: Vec<Download>,
    pub bookmarks: Vec<Bookmark>,
    pub extensions: Vec<Extension>,
    pub findings: Vec<Finding>,
    /// Master-key outcome per browser, keyed by browser id
    /// ("abe", "dpapi", "keychain", "peanuts", "unavailable: ...").
    pub key_status: BTreeMap<String, String>,
    /// Store-level failures ("browser/profile/store: reason"). An unreadable
    /// store is recorded, never reported as empty.
    pub collection_errors: Vec<String>,
}

impl Report {
    /// Appends a row to its artifact vector, honoring the aggregate
    /// `max_items` cap (0 = unlimited).
    #[must_use]
    pub fn row_fits(&self, row: &Row, max_items: u32) -> bool {
        if max_items == 0 {
            return true;
        }
        let len = match row {
            Row::Login(_) => self.credentials.len(),
            Row::Cookie(_) => self.cookies.len(),
            Row::Card(_) => self.credit_cards.len(),
            Row::Iban(_) => self.iban_entries.len(),
            Row::Token(_) => self.oauth_tokens.len(),
            Row::Autofill(_) => self.autofill.len(),
        };
        len < max_items as usize
    }

    /// Pushes `row` without a cap check (callers pre-check with [`row_fits`]).
    pub fn push_row(&mut self, row: Row) {
        match row {
            Row::Login(r) => self.credentials.push(r),
            Row::Cookie(r) => self.cookies.push(r),
            Row::Card(r) => self.credit_cards.push(r),
            Row::Iban(r) => self.iban_entries.push(r),
            Row::Token(r) => self.oauth_tokens.push(r),
            Row::Autofill(r) => self.autofill.push(r),
        }
    }
}

/// A secret- or payment-class row, as streamed between the hollowed Windows
/// payload and the parent process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Row {
    Login(Login),
    Cookie(Cookie),
    Card(Card),
    Iban(Iban),
    Token(Token),
    Autofill(Autofill),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn row_fits_caps_aggregate() {
        let mut report = Report::default();
        let row = Row::Login(Login::default());
        assert!(report.row_fits(&row, 0));
        assert!(report.row_fits(&row, 1));
        report.push_row(row.clone());
        assert!(!report.row_fits(&row, 1));
        assert!(report.row_fits(&row, 2));
    }
}
