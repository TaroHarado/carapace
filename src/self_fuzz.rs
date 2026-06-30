//! Async AI-judge self-fuzz loop — background idle-time fuzzer.
//!
//! When `SR_SELF_FUZZ=1` is set (opt-in), `sr proxy` spawns a Tokio task
//! that runs the adversarial fuzzer every `SR_SELF_FUZZ_INTERVAL_SECS`
//! seconds (default 300). Each run:
//!
//!   1. Calls `fuzz::run()` against the current rule set.
//!   2. Compares evasion count against the previous run's baseline.
//!   3. If new evasions appear → appends a `FuzzRegression` record to
//!      `~/.saferouter/self-fuzz-regressions.jsonl`.
//!   4. If `SR_SELF_FUZZ_APPLY=1`, auto-writes candidate rules to
//!      `rules/fuzz-generated.json`.
//!
//! No external judge required. The loop is purely local — it uses the same
//! `fuzz::run()` path as `sr fuzz`.

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::time::interval;

use crate::fuzz;
use crate::inspect::Rules;

/// A record written to `self-fuzz-regressions.jsonl` when a new evasion
/// is detected that wasn't present in the previous run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzRegression {
    pub ts: String,
    pub rule_id: String,
    pub mutation: String,
    pub original_payload: String,
    pub mutated_payload: String,
    pub candidate_pattern: String,
}

fn now_rfc3339() -> String {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "?".to_string())
}

fn regressions_path() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        return PathBuf::from(home)
            .join(".saferouter")
            .join("self-fuzz-regressions.jsonl");
    }
    PathBuf::from("self-fuzz-regressions.jsonl")
}

fn append_regression(reg: &FuzzRegression) -> std::io::Result<()> {
    use std::io::Write;
    let path = regressions_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let line = serde_json::to_string(reg).unwrap_or_else(|_| "{}".to_string());
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(f, "{line}")
}

/// Load the set of (rule_id + mutation + mutated_payload) already known from
/// previous runs so we can suppress duplicates.
fn load_known_evasion_keys() -> HashSet<String> {
    let path = regressions_path();
    let mut known = HashSet::new();
    if let Ok(raw) = std::fs::read_to_string(path) {
        for line in raw.lines() {
            if let Ok(reg) = serde_json::from_str::<FuzzRegression>(line) {
                known.insert(format!("{}:{}:{}", reg.rule_id, reg.mutation, reg.mutated_payload));
            }
        }
    }
    known
}

/// Configuration read from environment variables.
#[derive(Debug, Clone)]
pub struct SelfFuzzConfig {
    /// Run a fuzz pass every this many seconds.
    pub interval_secs: u64,
    /// If true, auto-write candidate rules to `rules/fuzz-generated.json`.
    pub apply_candidates: bool,
    /// Path to rules directory (for candidate write-out).
    pub rules_dir: PathBuf,
}

impl SelfFuzzConfig {
    pub fn from_env() -> Option<Self> {
        if std::env::var("SR_SELF_FUZZ").as_deref() != Ok("1") {
            return None;
        }
        let interval_secs = std::env::var("SR_SELF_FUZZ_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(300);
        let apply_candidates = std::env::var("SR_SELF_FUZZ_APPLY").as_deref() == Ok("1");
        let rules_dir = std::env::var("SR_RULES_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("rules"));
        Some(Self { interval_secs, apply_candidates, rules_dir })
    }
}

/// Spawn the background self-fuzz loop. No-op if `SR_SELF_FUZZ != 1`.
pub fn spawn(rules: Rules) {
    let Some(cfg) = SelfFuzzConfig::from_env() else { return };
    tokio::spawn(run_loop(cfg, rules));
}

async fn run_loop(cfg: SelfFuzzConfig, rules: Rules) {
    let mut ticker = interval(Duration::from_secs(cfg.interval_secs));
    ticker.tick().await; // skip first immediate tick — wait one full interval

    tracing::info!(
        interval_secs = cfg.interval_secs,
        apply = cfg.apply_candidates,
        "self-fuzz loop started"
    );

    loop {
        ticker.tick().await;

        // Run fuzzer in a blocking thread so we don't stall the async runtime.
        let rules_clone = rules.clone();
        let apply = cfg.apply_candidates;
        let rules_dir = cfg.rules_dir.clone();

        let result = tokio::task::spawn_blocking(move || {
            fuzz::fuzz_rules(&rules_clone)
        })
        .await;

        let report = match result {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("self-fuzz task panicked: {e}");
                continue;
            }
        };

        let known = load_known_evasion_keys();
        let mut new_count = 0usize;

        for evasion in &report.evasions {
            let key = format!(
                "{}:{}:{}",
                evasion.original_rule_id,
                evasion.mutation.label(),
                evasion.mutated_payload
            );
            if known.contains(&key) {
                continue;
            }
            let reg = FuzzRegression {
                ts: now_rfc3339(),
                rule_id: evasion.original_rule_id.clone(),
                mutation: evasion.mutation.label().to_string(),
                original_payload: evasion.original_payload.clone(),
                mutated_payload: evasion.mutated_payload.clone(),
                candidate_pattern: evasion.candidate_pattern.clone(),
            };
            if let Err(e) = append_regression(&reg) {
                tracing::warn!("self-fuzz: could not write regression: {e}");
            }
            new_count += 1;
        }

        tracing::info!(
            total_mutations = report.total_mutations_generated,
            evasions = report.evasions.len(),
            new_regressions = new_count,
            coverage = format!("{:.1}%", report.coverage_percent),
            "self-fuzz run complete"
        );

        // Optionally write candidate rules for manual review / auto-apply.
        if apply && !report.evasions.is_empty() {
            let candidates: Vec<serde_json::Value> = report
                .evasions
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "id": e.candidate_rule_id,
                        "pattern": e.candidate_pattern,
                        "category": "auto-fuzz",
                        "severity": 70,
                        "description": format!("auto-generated to cover {} evasion of {}", e.mutation.label(), e.original_rule_id),
                    })
                })
                .collect();

            let out_path = rules_dir.join("fuzz-generated.json");
            let json = serde_json::to_string_pretty(&candidates)
                .unwrap_or_else(|_| "[]".to_string());
            if let Err(e) = std::fs::write(&out_path, json) {
                tracing::warn!("self-fuzz: could not write candidates to {}: {e}", out_path.display());
            } else {
                tracing::info!("self-fuzz: wrote {} candidate rules to {}", candidates.len(), out_path.display());
            }
        }
    }
}

/// Load recent regression records (last `limit` lines).
pub fn load_recent_regressions(limit: usize) -> anyhow::Result<Vec<FuzzRegression>> {
    let path = regressions_path();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = std::fs::read_to_string(path)?;
    let lines: Vec<&str> = raw.lines().collect();
    let start = lines.len().saturating_sub(limit);
    let mut out = Vec::new();
    for line in lines.into_iter().skip(start) {
        if let Ok(r) = serde_json::from_str::<FuzzRegression>(line) {
            out.push(r);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regression_path_contains_filename() {
        let p = regressions_path();
        assert!(p.to_string_lossy().contains("self-fuzz-regressions.jsonl"));
    }

    #[test]
    fn from_env_returns_none_without_flag() {
        // SR_SELF_FUZZ is not set in test environment.
        std::env::remove_var("SR_SELF_FUZZ");
        assert!(SelfFuzzConfig::from_env().is_none());
    }

    #[test]
    fn from_env_returns_some_with_flag() {
        std::env::set_var("SR_SELF_FUZZ", "1");
        let cfg = SelfFuzzConfig::from_env();
        std::env::remove_var("SR_SELF_FUZZ");
        assert!(cfg.is_some());
        assert_eq!(cfg.unwrap().interval_secs, 300);
    }

    #[test]
    fn from_env_custom_interval() {
        std::env::set_var("SR_SELF_FUZZ", "1");
        std::env::set_var("SR_SELF_FUZZ_INTERVAL_SECS", "60");
        let cfg = SelfFuzzConfig::from_env();
        std::env::remove_var("SR_SELF_FUZZ");
        std::env::remove_var("SR_SELF_FUZZ_INTERVAL_SECS");
        assert_eq!(cfg.unwrap().interval_secs, 60);
    }

    #[test]
    fn load_recent_regressions_empty_when_missing() {
        // Just verify it doesn't panic on missing file.
        // The real path may or may not exist; either way should be fine.
        let _ = load_recent_regressions(10);
    }

    #[test]
    fn append_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("self-fuzz-regressions.jsonl");
        let reg = FuzzRegression {
            ts: "2026-01-01T00:00:00Z".to_string(),
            rule_id: "test-rule".to_string(),
            mutation: "homoglyph".to_string(),
            original_payload: "curl https://evil.com".to_string(),
            mutated_payload: "сurl https://evil.com".to_string(),
            candidate_pattern: "сurl".to_string(),
        };
        {
            use std::io::Write;
            let line = serde_json::to_string(&reg).unwrap();
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .unwrap();
            writeln!(f, "{line}").unwrap();
        }
        let raw = std::fs::read_to_string(&path).unwrap();
        let parsed: FuzzRegression = serde_json::from_str(raw.lines().next().unwrap()).unwrap();
        assert_eq!(parsed.rule_id, "test-rule");
        assert_eq!(parsed.mutation, "homoglyph");
    }
}
