//! Persistent provider history store.
//!
//! V1 used an ad-hoc per-host snapshot file to compute drift. That was enough
//! for a local demo, but not enough for a real monitoring backbone. V2 starts
//! here: append-only JSONL history per provider host.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::deep_scan::{DeepScanMetrics, DeepScanReport};
use crate::identity::IdentityReport;
use crate::probes::AgentVerdict;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub checked_at: String,
    pub upstream: String,
    pub host: String,
    pub claimed_model: Option<String>,
    pub use_case: String,
    pub identity: IdentityReport,
    pub metrics: DeepScanMetrics,
    pub verdict: AgentVerdict,
    pub agent_safety_score: u32,
}

pub fn default_root() -> PathBuf {
    crate::paths::state_dir("history")
}

pub fn host_path(root: &Path, host: &str) -> PathBuf {
    let sanitized = host.replace([':', '/'], "_");
    root.join(format!("{sanitized}.jsonl"))
}

pub fn from_report(report: &DeepScanReport) -> HistoryEntry {
    HistoryEntry {
        checked_at: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "?".to_string()),
        upstream: report.upstream.clone(),
        host: extract_host(&report.upstream),
        claimed_model: report.claimed_model.clone(),
        use_case: report.use_case.clone(),
        identity: report.identity.clone(),
        metrics: report.metrics.clone(),
        verdict: report.verdict,
        agent_safety_score: report.battery.agent_safety_score,
    }
}

pub fn append(root: &Path, entry: &HistoryEntry) -> anyhow::Result<()> {
    if !root.exists() {
        std::fs::create_dir_all(root)?;
    }
    let path = host_path(root, &entry.host);
    let line = serde_json::to_string(entry)?;
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{line}")?;
    Ok(())
}

pub fn load_host(root: &Path, host: &str) -> anyhow::Result<Vec<HistoryEntry>> {
    let path = host_path(root, host);
    if !path.exists() {
        return Ok(vec![]);
    }
    let raw = std::fs::read_to_string(path)?;
    let stream = serde_json::Deserializer::from_str(&raw).into_iter::<HistoryEntry>();
    let mut out = Vec::new();
    for value in stream {
        out.push(value?);
    }
    Ok(out)
}

pub fn latest(root: &Path, host: &str) -> anyhow::Result<Option<HistoryEntry>> {
    Ok(load_host(root, host)?.pop())
}

fn extract_host(url: &str) -> String {
    let without_scheme = url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    without_scheme.split('/').next().unwrap_or(without_scheme).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{IdentityReport, IdentityRisk, ModelFamily};

    fn sample_entry() -> HistoryEntry {
        HistoryEntry {
            checked_at: "2026-06-28T00:00:00Z".into(),
            upstream: "https://api.deepseek.com".into(),
            host: "api.deepseek.com".into(),
            claimed_model: Some("DeepSeek V4 Flash".into()),
            use_case: "coding-agent".into(),
            identity: IdentityReport {
                claimed_model: Some("DeepSeek V4 Flash".into()),
                claimed_family: ModelFamily::DeepSeek,
                observed_family: ModelFamily::DeepSeek,
                confidence: 88,
                risk: IdentityRisk::Low,
                reasons: vec!["official provider hostname".into()],
            },
            metrics: DeepScanMetrics {
                latency_p50_ms: 800,
                latency_p95_ms: 1200,
                successful_probes: 20,
                uptime_confidence: crate::deep_scan::UptimeConfidence::High,
            },
            verdict: AgentVerdict::AgentSafe,
            agent_safety_score: 95,
        }
    }

    #[test]
    fn append_and_load_round_trip() {
        let root = std::env::temp_dir().join(format!("carapace-history-{}-{}", std::process::id(), rand::random::<u64>()));
        let _ = std::fs::remove_dir_all(&root);
        let entry = sample_entry();
        append(&root, &entry).unwrap();
        let loaded = load_host(&root, &entry.host).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].host, entry.host);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn latest_returns_last_entry() {
        let root = std::env::temp_dir().join(format!("carapace-history-{}-{}", std::process::id(), rand::random::<u64>()));
        let _ = std::fs::remove_dir_all(&root);
        let mut first = sample_entry();
        first.checked_at = "2026-06-28T00:00:00Z".into();
        let mut second = sample_entry();
        second.checked_at = "2026-06-28T01:00:00Z".into();
        append(&root, &first).unwrap();
        append(&root, &second).unwrap();
        let latest = latest(&root, &first.host).unwrap().unwrap();
        assert_eq!(latest.checked_at, second.checked_at);
        let _ = std::fs::remove_dir_all(&root);
    }
}
