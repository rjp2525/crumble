//! EDR/AV detection driving the polite-by-default key-retrieval gate.
//!
//! When an encrypted artifact class is selected and an EDR/AV product is
//! running, the pipeline skips its intrusive key-retrieval paths (process
//! manipulation on Windows, the Keychain read on macOS, the DPAPI unwrap)
//! and records why: an authorized assessment must not read as an infostealer
//! to the customer's SOC and get the device isolated. Counts — the exposure
//! proof — are collected regardless. Matching is case-insensitive substring
//! over process names, deliberately broad; a false positive only makes the
//! tool MORE conservative.

use sysinfo::{ProcessesToUpdate, System};

struct Fingerprint {
    /// Lowercase needle matched as a substring of the process name.
    needle: &'static str,
    /// Human-readable product the needle identifies.
    product: &'static str,
}

const fn fp(needle: &'static str, product: &'static str) -> Fingerprint {
    Fingerprint { needle, product }
}

/// Known EDR/AV agents keyed by a distinctive process-name token.
const FINGERPRINTS: &[Fingerprint] = &[
    fp("falcond", "CrowdStrike Falcon"),
    fp("csfalcon", "CrowdStrike Falcon"),
    fp("csagent", "CrowdStrike Falcon"),
    fp("falcon-sensor", "CrowdStrike Falcon"),
    fp("sentinelagent", "SentinelOne"),
    fp("sentineld", "SentinelOne"),
    fp("sentinelone", "SentinelOne"),
    fp("mssense", "Microsoft Defender for Endpoint"),
    fp("senseir", "Microsoft Defender for Endpoint"),
    fp("msmpeng", "Microsoft Defender"),
    fp("wdavdaemon", "Microsoft Defender"),
    fp("windefend", "Microsoft Defender"),
    fp("carbonblack", "VMware Carbon Black"),
    fp("cbagentd", "VMware Carbon Black"),
    fp("repmgr", "VMware Carbon Black"),
    fp("cortex", "Palo Alto Cortex XDR"),
    fp("cyserver", "Palo Alto Cortex XDR"),
    fp("traps", "Palo Alto Traps"),
    fp("cylancesvc", "BlackBerry Cylance"),
    fp("cylance", "BlackBerry Cylance"),
    fp("sophos", "Sophos"),
    fp("savservice", "Sophos"),
    fp("ekrn", "ESET"),
    fp("eset", "ESET"),
    fp("ds_agent", "Trend Micro Deep Security"),
    fp("tmlisten", "Trend Micro"),
    fp("ntrtscan", "Trend Micro"),
    fp("mfemms", "McAfee/Trellix"),
    fp("masvc", "McAfee/Trellix"),
    fp("mcafee", "McAfee/Trellix"),
    fp("trellix", "Trellix"),
    fp("bdservicehost", "Bitdefender"),
    fp("bitdefender", "Bitdefender"),
    fp("klnagent", "Kaspersky"),
    fp("kaspersky", "Kaspersky"),
    fp("elastic-endpoint", "Elastic Defend"),
    fp("elastic-agent", "Elastic Agent"),
    fp("wazuh", "Wazuh"),
    fp("ossec", "OSSEC"),
    fp("mbamservice", "Malwarebytes"),
    fp("malwarebytes", "Malwarebytes"),
    fp("taniumclient", "Tanium"),
    fp("ccsvchst", "Symantec Endpoint Protection"),
    fp("sisidsservice", "Symantec Endpoint Protection"),
    fp("jamfprotect", "Jamf Protect"),
    fp("redcanary", "Red Canary"),
];

/// The distinct EDR/AV products detected among running processes (sorted,
/// de-duplicated). Empty = none seen.
#[must_use]
pub fn detected() -> Vec<&'static str> {
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All, true);
    let mut products: Vec<&'static str> = Vec::new();
    for process in sys.processes().values() {
        let name = process.name().to_string_lossy().to_ascii_lowercase();
        for fingerprint in FINGERPRINTS {
            if name.contains(fingerprint.needle) && !products.contains(&fingerprint.product) {
                products.push(fingerprint.product);
            }
        }
    }
    products.sort_unstable();
    products
}

/// Case-insensitive substring match of one process-name-ish string against
/// the fingerprint table (test seam).
#[cfg(test)]
fn matches(value: &str) -> Option<&'static str> {
    let lower = value.to_ascii_lowercase();
    FINGERPRINTS
        .iter()
        .find(|f| lower.contains(f.needle))
        .map(|f| f.product)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_hit() {
        assert_eq!(
            matches("MsSense.exe"),
            Some("Microsoft Defender for Endpoint")
        );
        assert_eq!(
            matches("/usr/libexec/wdavdaemon"),
            Some("Microsoft Defender")
        );
        assert_eq!(matches("SentinelAgent"), Some("SentinelOne"));
        assert_eq!(matches("bash"), None);
        assert_eq!(matches(""), None);
    }
}
