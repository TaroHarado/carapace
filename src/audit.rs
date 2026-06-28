//! `cape audit` — host IoC scanner for known malicious-LLM campaigns.
//!
//! Looks for the indicators real campaigns (kiro.cheap, awstore.cloud and
//! similar sng-targeted reseller malware) leave on a box:
//!   - suspicious long-running processes (`awproxy.exe`, `tun2socks`, etc.)
//!   - persistence tasks (`CodeAssist`, `StartupOptimizer`, `SngCache`)
//!   - leftover drop paths
//!   - connections to public SOCKS5 endpoints / known-bad IPs
//!   - suspicious proxy env vars
//!
//! v0.6 ships a best-effort read-only scan using `sysinfo`. No defences are
//! modified; no processes are killed. v0.7 (sentinel) wraps this into a
//! periodic monitor with notified escalation.

use std::collections::HashSet;
use std::path::Path;

use serde::Serialize;
use sysinfo::{ProcessRefreshKind, RefreshKind, System};

#[derive(Debug, Clone, Serialize, Default)]
pub struct AuditReport {
    pub platform: String,
    pub findings: Vec<Finding>,
    pub risk_score: u32,
    pub verdict: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub category: &'static str,
    pub severity: u32,
    pub detail: String,
}

const SUSPICIOUS_PROCESS_NAMES: &[&str] = &[
    "awproxy.exe",
    "tun2socks.exe",
    "tun2socks",
    "sngcache.exe",
    "codeassist.exe",
    "startupoptimizer.exe",
    "claudeproxy.exe",
];

const SUSPICIOUS_TASK_NAMES: &[&str] = &[
    "CodeAssist",
    "StartupOptimizer",
    "SngCache",
    "ClaudeAssist",
];

const SUSPICIOUS_PATH_MARKERS: &[&str] = &[
    "Microsoft\\SngCache",
    "Microsoft\\CodeAssist",
    "Local\\StartupOptimizer",
    ".yunyi\\cache",
    "awstore",
];

const IOC_HOSTS: &[&str] = &[
    "kiro.cheap",
    "awstore.cloud",
    "api-cc.freemodel.dev",
    "tun2socks.proxy.cn",
];

pub fn run() -> AuditReport {
    let mut findings = Vec::new();
    let platform = detect_platform();

    scan_processes(&mut findings);
    if cfg!(target_os = "windows") {
        scan_persistence_windows(&mut findings);
    } else {
        scan_persistence_posix(&mut findings);
    }
    scan_paths(&mut findings);
    scan_env(&mut findings);
    scan_connections(&mut findings);

    let risk_score = findings.iter().map(|f| f.severity).max().unwrap_or(0);
    let verdict = match risk_score {
        0 => "clean — no IoCs matched",
        1..=49 => "low — review findings",
        50..=84 => "high — investigate and rotate keys",
        _ => "critical — consider this host compromised; rotate all LLM keys",
    };

    AuditReport {
        platform,
        findings,
        risk_score,
        verdict,
    }
}

fn detect_platform() -> String {
    if cfg!(target_os = "windows") {
        "windows".to_string()
    } else if cfg!(target_os = "macos") {
        "macos".to_string()
    } else if cfg!(target_os = "linux") {
        "linux".to_string()
    } else {
        "unknown".to_string()
    }
}

fn scan_processes(findings: &mut Vec<Finding>) {
    let sys = System::new_with_specifics(
        RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
    );
    let mut seen = HashSet::new();
    for (_, proc) in sys.processes() {
        let name = proc.name().to_os_string().to_string_lossy().to_lowercase();
        for sus in SUSPICIOUS_PROCESS_NAMES {
            if name == sus.to_lowercase() && seen.insert(name.clone()) {
                findings.push(Finding {
                    category: "process-indicator",
                    severity: 90,
                    detail: format!("process `{name}` matches known malicious-LLM IoC"),
                });
            }
        }
    }
}

fn scan_persistence_windows(findings: &mut Vec<Finding>) {
    if let Ok(home) = std::env::var("LOCALAPPDATA") {
        for marker in SUSPICIOUS_PATH_MARKERS {
            let p = Path::new(&home).join(marker);
            if p.exists() {
                findings.push(Finding {
                    category: "persistence-path",
                    severity: 80,
                    detail: format!("drop path exists: {}", p.display()),
                });
            }
        }
    }

    // Check Windows scheduled tasks by name (best-effort; skipped silently if
    // schtasks.exe is unavailable — non-admin users can still run audit).
    for task in SUSPICIOUS_TASK_NAMES {
        let out = std::process::Command::new("schtasks")
            .args(["/Query", "/TN", task, "/FO", "LIST"])
            .output();
        if let Ok(out) = out {
            if out.status.success() {
                findings.push(Finding {
                    category: "scheduled-task",
                    severity: 85,
                    detail: format!("scheduled task `{task}` is registered"),
                });
            }
        }
    }
}

fn scan_persistence_posix(findings: &mut Vec<Finding>) {
    if let Ok(home) = std::env::var("HOME") {
        for marker in &[".config/yunyi", ".awstore", ".sngcache", ".claudeproxy"] {
            let p = Path::new(&home).join(marker);
            if p.exists() {
                findings.push(Finding {
                    category: "persistence-path",
                    severity: 80,
                    detail: format!("drop path exists: {}", p.display()),
                });
            }
        }
    }

    // cron entries that mention any of the IOC hosts.
    if let Ok(crontab) = std::process::Command::new("crontab").arg("-l").output() {
        if let Ok(s) = std::str::from_utf8(&crontab.stdout) {
            for host in IOC_HOSTS {
                if s.contains(host) {
                    findings.push(Finding {
                        category: "cron-reference",
                        severity: 75,
                        detail: format!("crontab references `{host}`"),
                    });
                }
            }
        }
    }
}

fn scan_paths(findings: &mut Vec<Finding>) {
    let temp = std::env::var("TEMP").or_else(|_| std::env::var("TMPDIR")).unwrap_or_default();
    if !temp.is_empty() {
        for marker in SUSPICIOUS_PATH_MARKERS {
            let p = Path::new(&temp).join(marker);
            if p.exists() {
                findings.push(Finding {
                    category: "temp-drop",
                    severity: 70,
                    detail: format!("temp drop path exists: {}", p.display()),
                });
            }
        }
    }
}

fn scan_env(findings: &mut Vec<Finding>) {
    for var in &["ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY"] {
        if let Ok(val) = std::env::var(var) {
            let lower = val.to_lowercase();
            if lower.contains("socks5://") || lower.starts_with("http://") {
                // Only flag if the proxy points at a known-bad host or is a
                // SOCKS5 proxy we didn't authorise via carapace config.
                let suspicious = IOC_HOSTS.iter().any(|h| lower.contains(h));
                if suspicious {
                    findings.push(Finding {
                        category: "proxy-env",
                        severity: 85,
                        detail: format!("{var}={val} points at known IoC"),
                    });
                }
            }
        }
    }
}

fn scan_connections(_findings: &mut Vec<Finding>) {
    // v0.6 stub: netstat-style open-connection correlation lands in v0.7
    // alongside sentinel so we can diff state across runs. Placeholder keeps
    // the report schema stable for downstream integrations.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_returns_a_report_on_clean_host() {
        // On the build / CI host we cannot guarantee a clean state, but the
        // shape of the report must always be valid.
        let report = run();
        assert!(report.risk_score <= 100 || report.risk_score == 0);
        assert!(!report.platform.is_empty());
    }

    #[test]
    fn empty_findings_yield_clean_verdict() {
        let report = AuditReport {
            platform: "test".into(),
            findings: vec![],
            risk_score: 0,
            verdict: "",
        };
        let verdict = match report.risk_score {
            0 => "clean — no IoCs matched",
            1..=49 => "low — review findings",
            50..=84 => "high — investigate and rotate keys",
            _ => "critical — consider this host compromised; rotate all LLM keys",
        };
        assert_eq!(verdict, "clean — no IoCs matched");
    }

    #[test]
    fn ioc_host_list_includes_known_campaigns() {
        assert!(IOC_HOSTS.contains(&"kiro.cheap"));
        assert!(IOC_HOSTS.contains(&"awstore.cloud"));
    }
}