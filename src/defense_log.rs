//! Persistent defense-event log for the local web dashboard.
//!
//! `sr web` runs as a separate process from the proxy. The in-memory
//! `SessionGraph` inside `DefenseEngine` isn't visible to it. To render a
//! live chain graph / quarantine review timeline, we append a compact JSONL
//! event per `DefenseEngine::evaluate()` call to a local file under
//! `~/.saferouter/defense-events.jsonl`.
//!
//! Each line contains:
//!   - timestamp
//!   - decision / asset class / capability / source / tainted
//!   - primary target
//!   - chain hit ids
//!   - reasons
//!
//! The web UI reads the tail and reconstructs a DAG-ish timeline.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::defense::DefenseReport;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefenseEvent {
    pub ts: String,
    pub decision: String,
    pub asset_class: String,
    pub capability: String,
    pub source: String,
    pub tainted: bool,
    pub target: String,
    pub chain_hits: Vec<String>,
    pub reasons: Vec<String>,
}

pub struct DefenseLog {
    file: Mutex<std::fs::File>,
}

impl DefenseLog {
    pub fn open_default() -> std::io::Result<Self> {
        let path = default_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self { file: Mutex::new(file) })
    }

    pub fn append(&self, report: &DefenseReport, target: &str) -> std::io::Result<()> {
        let entry = DefenseEvent {
            ts: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| "?".to_string()),
            decision: report.decision.label().to_string(),
            asset_class: report.asset_class.label().to_string(),
            capability: report.capability.label().to_string(),
            source: report.source.label().to_string(),
            tainted: report.tainted,
            target: target.to_string(),
            chain_hits: report.chain_hits.iter().map(|h| h.rule_id.clone()).collect(),
            reasons: report.reasons.clone(),
        };
        let line = serde_json::to_string(&entry).unwrap_or_else(|_| "{}".to_string());
        let mut f = self.file.lock().unwrap();
        writeln!(f, "{line}")?;
        Ok(())
    }
}

pub fn default_path() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        return PathBuf::from(home).join(".saferouter").join("defense-events.jsonl");
    }
    PathBuf::from("defense-events.jsonl")
}

pub fn load_recent(limit: usize) -> anyhow::Result<Vec<DefenseEvent>> {
    let path = default_path();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = std::fs::read_to_string(path)?;
    let lines: Vec<&str> = raw.lines().collect();
    let start = lines.len().saturating_sub(limit);
    let mut out = Vec::new();
    for line in lines.into_iter().skip(start) {
        if let Ok(entry) = serde_json::from_str::<DefenseEvent>(line) {
            out.push(entry);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::{AssetClass, Capability, Source};
    use crate::capability_matrix::MatrixDecision;
    use crate::defense::{DefenseDecision, DefenseReport};
    use crate::session_graph::ChainHit;

    fn dummy_report() -> DefenseReport {
        DefenseReport {
            decision: DefenseDecision::Block,
            asset_class: AssetClass::Credential,
            capability: Capability::Execute,
            source: Source::Provider,
            tainted: true,
            matrix_decision: MatrixDecision::Block,
            chain_hits: vec![ChainHit {
                rule_id: "chain-fetch-write-execute".to_string(),
                severity: 95,
                description: "test".to_string(),
                events: vec![1, 2, 3],
            }],
            reasons: vec!["unsolicited tool_use from provider".to_string()],
        }
    }

    #[test]
    fn default_path_under_home() {
        let p = default_path();
        assert!(p.to_string_lossy().contains("defense-events.jsonl"));
    }

    #[test]
    fn append_and_load_recent() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("defense-events.jsonl");
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let file = OpenOptions::new().create(true).append(true).open(&path).unwrap();
        let log = DefenseLog { file: Mutex::new(file) };
        let report = dummy_report();
        log.append(&report, "~/.ssh/id_rsa").unwrap();

        // Manual read because default_path() isn't redirected in tests.
        let raw = std::fs::read_to_string(&path).unwrap();
        let parsed: DefenseEvent = serde_json::from_str(raw.lines().next().unwrap()).unwrap();
        assert_eq!(parsed.decision, "block");
        assert_eq!(parsed.asset_class, "credential");
        assert_eq!(parsed.target, "~/.ssh/id_rsa");
        assert!(parsed.chain_hits.iter().any(|h| h == "chain-fetch-write-execute"));
    }

    #[test]
    fn load_recent_returns_empty_when_missing() {
        let p = default_path();
        // Can't force HOME in unit test portably; just ensure function
        // handles missing file gracefully.
        if p.exists() {
            let _ = std::fs::remove_file(&p);
        }
        let out = load_recent(10).unwrap();
        assert!(out.is_empty());
    }
}
