//! Run options and their fail-closed selection semantics.
//!
//! Selection is validated against the known browser ids and artifact
//! classes. Unknown names are dropped, and a list that names ONLY unknown
//! values makes the whole selection match nothing. Widening an all-typo
//! selection to "everything" would extract far more than the operator asked
//! for.

use serde::{Deserialize, Serialize};

/// Every browser id the tool understands.
pub const ALL_BROWSERS: &[&str] = &[
    "chrome", "edge", "brave", "chromium", "opera", "vivaldi", "firefox", "safari",
];

/// Every artifact class the tool understands. `credentials` also covers the
/// other secret stores (payment cards, IBANs, OAuth tokens).
pub const ALL_ARTIFACTS: &[&str] = &[
    "profiles",
    "credentials",
    "history",
    "downloads",
    "cookies",
    "autofill",
    "bookmarks",
    "extensions",
];

/// Output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    /// Indented JSON (default).
    #[default]
    Json,
    /// One JSON object per line.
    Jsonl,
}

/// Everything a run needs to know beyond the environment: what to target and
/// what to try to collect.
///
/// Serializable: the Windows in-browser payload receives exactly the
/// options the operator passed. The request channel is the trust boundary;
/// the payload re-validates them before touching any secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RunOptions {
    /// Selected browsers (empty = all detected).
    pub browsers: Vec<String>,
    /// Selected artifact classes (empty = all).
    pub artifacts: Vec<String>,
    /// Set when a provided selection named ONLY unknown values: the run then
    /// matches nothing. Never serialized (derived from the raw lists).
    #[serde(skip)]
    pub selection_invalid: bool,
    /// Attempt master-key resolution and decrypt secret values (default).
    /// Off (`--no-decrypt`) = counts + plaintext artifacts only: no keychain
    /// read, no DPAPI/ABE unwrap, no in-browser extraction.
    pub decrypt: bool,
    /// Skip intrusive key retrieval when an EDR/AV product is detected.
    /// Default off: a standalone operator decides their own risk posture.
    /// Enable on cautious engagements.
    pub respect_edr: bool,
    /// History/download lookback in days (0 = unlimited).
    pub history_days: u32,
    /// Aggregate row cap per artifact class (0 = unlimited).
    pub max_items: u32,
    /// Output format.
    pub format: Format,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            browsers: Vec::new(),
            artifacts: Vec::new(),
            selection_invalid: false,
            decrypt: true,
            respect_edr: false,
            history_days: 0,
            max_items: 0,
            format: Format::Json,
        }
    }
}

impl RunOptions {
    /// Normalizes a raw selection: drops unknown names, flags all-typo lists.
    /// `None` = "key absent" (= all).
    pub fn normalize(
        browsers: Option<Vec<String>>,
        artifacts: Option<Vec<String>>,
        mut rest: Self,
    ) -> Self {
        let mut browsers = browsers.unwrap_or_default();
        let mut artifacts = artifacts.unwrap_or_default();
        rest.selection_invalid =
            is_all_unknown(&browsers, ALL_BROWSERS) || is_all_unknown(&artifacts, ALL_ARTIFACTS);
        browsers.retain(|b| ALL_BROWSERS.contains(&b.as_str()));
        artifacts.retain(|a| ALL_ARTIFACTS.contains(&a.as_str()));
        rest.browsers = browsers;
        rest.artifacts = artifacts;
        rest
    }

    /// Whether `browser` (a known id) is targeted by this run.
    #[must_use]
    pub fn wants_browser(&self, browser: &str) -> bool {
        !self.selection_invalid
            && (self.browsers.is_empty() || self.browsers.iter().any(|b| b == browser))
    }

    /// Whether `artifact` (a known class) is selected.
    #[must_use]
    pub fn wants_artifact(&self, artifact: &str) -> bool {
        !self.selection_invalid
            && (self.artifacts.is_empty() || self.artifacts.iter().any(|a| a == artifact))
    }
}

/// True when `names` is non-empty and every entry is unknown: a restriction
/// the operator clearly meant, spelled entirely wrong.
fn is_all_unknown(names: &[String], known: &[&str]) -> bool {
    !names.is_empty() && names.iter().all(|n| !known.contains(&n.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_collect_everything() {
        let opts = RunOptions::default();
        assert!(opts.decrypt, "decryption on by default");
        assert!(!opts.respect_edr, "standalone: operator's call, not ours");
        for b in ALL_BROWSERS {
            assert!(opts.wants_browser(b));
        }
        for a in ALL_ARTIFACTS {
            assert!(opts.wants_artifact(a));
        }
    }

    #[test]
    fn unknown_names_dropped() {
        let opts = RunOptions::normalize(
            Some(vec!["chrome".into(), "netscape".into()]),
            Some(vec!["cookies".into(), "registry".into()]),
            RunOptions::default(),
        );
        assert_eq!(opts.browsers, vec!["chrome"]);
        assert_eq!(opts.artifacts, vec!["cookies"]);
        assert!(!opts.selection_invalid);
        assert!(opts.wants_browser("chrome"));
        assert!(!opts.wants_browser("edge"));
    }

    #[test]
    fn all_typo_selection_matches_nothing() {
        let opts =
            RunOptions::normalize(Some(vec!["netscape".into()]), None, RunOptions::default());
        assert!(opts.selection_invalid);
        for b in ALL_BROWSERS {
            assert!(!opts.wants_browser(b), "fail-closed must not match {b}");
        }
        // Same for an all-typo artifact list.
        let opts =
            RunOptions::normalize(None, Some(vec!["registry".into()]), RunOptions::default());
        assert!(opts.selection_invalid);
        assert!(!opts.wants_artifact("cookies"));
        // Explicitly empty lists still mean "all" (they are not typos).
        let opts = RunOptions::normalize(Some(vec![]), Some(vec![]), RunOptions::default());
        assert!(!opts.selection_invalid);
        assert!(opts.wants_browser("firefox"));
        assert!(opts.wants_artifact("cookies"));
    }
}
