//! Command-line parsing (manual — no argument-parsing dependency).

use anyhow::{bail, Context};

use crate::options::{Format, RunOptions};

const USAGE: &str = "\
crumble — extract the crumbs browsers leave behind (authorized use only)

USAGE:
    crumble [OPTIONS]

OPTIONS:
    -b, --browser <id>      target browser: chrome|edge|brave|chromium|opera|vivaldi|firefox|safari
                            (repeatable; omitted = all detected)
    -a, --artifact <id>     artifact class: profiles|credentials|history|downloads|cookies|
                            autofill|bookmarks|extensions (repeatable; omitted = all)
        --decrypt           resolve master keys and decrypt secret values (default)
        --no-decrypt        counts + plaintext artifacts only: no keychain read, no
                            DPAPI/ABE unwrap, no in-browser extraction
        --respect-edr       skip intrusive key retrieval when EDR/AV is detected
                            (default off — you decide your own risk posture)
        --no-respect-edr    attempt decryption even with EDR/AV present (default)
        --history-days <n>  limit history/download lookback to the last n days (0 = all)
        --max-items <n>     cap rows per artifact class across the run (0 = all);
                            counts always reflect the full store
        --format <fmt>      json (default) | jsonl
    -h, --help              print this help
";

/// Parses argv into [`RunOptions`]; `--help` exits the process with code 0
/// after printing usage.
pub fn parse<I: Iterator<Item = String>>(args: I) -> anyhow::Result<RunOptions> {
    let mut browsers: Option<Vec<String>> = None;
    let mut artifacts: Option<Vec<String>> = None;
    let mut decrypt = true;
    let mut respect_edr = false;
    let mut history_days = 0u32;
    let mut max_items = 0u32;
    let mut format = Format::Json;

    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        let flag = arg.as_str();
        match flag {
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            "--decrypt" => decrypt = true,
            "--no-decrypt" => decrypt = false,
            "--respect-edr" => respect_edr = true,
            "--no-respect-edr" => respect_edr = false,
            "-b" | "--browser" | "-a" | "--artifact" | "--history-days" | "--max-items"
            | "--format" => {
                let value = args
                    .next()
                    .with_context(|| format!("{flag} requires a value"))?;
                match flag {
                    "-b" | "--browser" => browsers
                        .get_or_insert_with(Vec::new)
                        .push(value.to_ascii_lowercase()),
                    "-a" | "--artifact" => artifacts
                        .get_or_insert_with(Vec::new)
                        .push(value.to_ascii_lowercase()),
                    "--history-days" => {
                        history_days = value.parse().context("--history-days wants an integer")?;
                    }
                    "--max-items" => {
                        max_items = value.parse().context("--max-items wants an integer")?;
                    }
                    "--format" => {
                        format = match value.as_str() {
                            "json" => Format::Json,
                            "jsonl" => Format::Jsonl,
                            other => bail!("--format must be json|jsonl, got {other}"),
                        };
                    }
                    _ => unreachable!(),
                }
            }
            _ if flag.starts_with("--browser=") => browsers
                .get_or_insert_with(Vec::new)
                .push(flag["--browser=".len()..].to_ascii_lowercase()),
            _ if flag.starts_with("--artifact=") => artifacts
                .get_or_insert_with(Vec::new)
                .push(flag["--artifact=".len()..].to_ascii_lowercase()),
            _ if flag.starts_with("--history-days=") => {
                history_days = flag["--history-days=".len()..]
                    .parse()
                    .context("--history-days wants an integer")?;
            }
            _ if flag.starts_with("--max-items=") => {
                max_items = flag["--max-items=".len()..]
                    .parse()
                    .context("--max-items wants an integer")?;
            }
            _ if flag.starts_with("--format=") => {
                format = match &flag["--format=".len()..] {
                    "json" => Format::Json,
                    "jsonl" => Format::Jsonl,
                    other => bail!("--format must be json|jsonl, got {other}"),
                };
            }
            _ => bail!("unknown argument {flag:?} (see --help)"),
        }
    }

    let rest = RunOptions {
        selection_invalid: false,
        decrypt,
        respect_edr,
        history_days,
        max_items,
        format,
        ..RunOptions::default()
    };
    Ok(RunOptions::normalize(browsers, artifacts, rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(words: &[&str]) -> anyhow::Result<RunOptions> {
        parse(words.iter().map(|s| (*s).to_string()))
    }

    #[test]
    fn parses_selection_and_flags() {
        let opts = argv(&[
            "--browser",
            "chrome",
            "--browser=firefox",
            "-a",
            "cookies",
            "--no-decrypt",
            "--respect-edr",
            "--history-days",
            "30",
            "--max-items",
            "5",
            "--format",
            "jsonl",
        ])
        .unwrap();
        assert_eq!(opts.browsers, vec!["chrome", "firefox"]);
        assert_eq!(opts.artifacts, vec!["cookies"]);
        assert!(!opts.decrypt);
        assert!(opts.respect_edr);
        assert_eq!(opts.history_days, 30);
        assert_eq!(opts.max_items, 5);
        assert_eq!(opts.format, Format::Jsonl);
    }

    #[test]
    fn defaults_collect_everything() {
        let opts = argv(&[]).unwrap();
        assert!(opts.decrypt);
        assert!(!opts.respect_edr);
        assert_eq!(opts.format, Format::Json);
    }

    #[test]
    fn unknown_flag_errors() {
        assert!(argv(&["--definitely-not-a-flag"]).is_err());
        assert!(argv(&["--browser"]).is_err(), "missing value");
    }
}
