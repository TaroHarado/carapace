//! Provider monitoring runner.
//!
//! Repeatedly runs `deep-scan`, relies on `history.rs` to persist outcomes,
//! and optionally fires alerts when identity/safety/latency drift crosses
//! thresholds.

use std::time::Duration;

use anyhow::Context;
use serde::Serialize;

use crate::deep_scan::{self, DeepScanReport};
use crate::secure::Secret;

pub struct MonitorConfig {
    pub upstream: String,
    pub key: Option<Secret>,
    pub claimed_model: Option<String>,
    pub use_case: String,
    pub interval: Duration,
    pub max_rounds: Option<u32>,
    pub identity_drop_threshold: i32,
    pub safety_drop_threshold: i32,
    pub latency_spike_ms: i32,
    pub webhook_url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    pub upstream: String,
    pub verdict: String,
    pub reasons: Vec<String>,
    pub summary: String,
}

pub async fn run(mut cfg: MonitorConfig) -> anyhow::Result<()> {
    let mut ticker = tokio::time::interval(cfg.interval);
    let mut round = 0u32;
    loop {
        ticker.tick().await;
        round += 1;

        let key = cfg.key.take();
        let report = deep_scan::run(
            &cfg.upstream,
            key,
            cfg.claimed_model.clone(),
            &cfg.use_case,
        )
        .await?;
        emit(round, &report);
        if let Some(alert) = maybe_alert(&cfg, &report) {
            emit_alert(round, &alert);
            if let Some(url) = &cfg.webhook_url {
                let _ = send_webhook(url, &alert).await;
            }
        }

        if let Some(max) = cfg.max_rounds {
            if round >= max {
                return Ok(());
            }
        }

        cfg.key = std::env::var("CAPE_UPSTREAM_KEY").ok().map(Secret::new);
    }
}

fn emit(round: u32, report: &DeepScanReport) {
    eprintln!("--- monitor round {} ---", round);
    eprintln!("upstream: {}", report.upstream);
    eprintln!("verdict: {:?}", report.verdict);
    eprintln!(
        "identity={} safety={} p95={}ms uptime={:?}",
        report.identity.confidence,
        report.battery.agent_safety_score,
        report.metrics.latency_p95_ms,
        report.metrics.uptime_confidence
    );
    if let Some(drift) = &report.drift {
        eprintln!("drift: {}", drift.summary);
    }
}

fn emit_alert(round: u32, alert: &Alert) {
    eprintln!("!!! alert round {} !!!", round);
    eprintln!("upstream: {}", alert.upstream);
    eprintln!("verdict: {}", alert.verdict);
    for reason in &alert.reasons {
        eprintln!("reason: {}", reason);
    }
    eprintln!("summary: {}", alert.summary);
}

fn maybe_alert(cfg: &MonitorConfig, report: &DeepScanReport) -> Option<Alert> {
    let mut reasons = Vec::new();

    if matches!(report.verdict, crate::probes::AgentVerdict::DoNotUse) {
        reasons.push("provider now falls into DoNotUse".to_string());
    }

    if let Some(drift) = &report.drift {
        if drift.identity_delta <= -cfg.identity_drop_threshold {
            reasons.push(format!("identity confidence dropped {} points", -drift.identity_delta));
        }
        if drift.safety_delta <= -cfg.safety_drop_threshold {
            reasons.push(format!("agent safety score dropped {} points", -drift.safety_delta));
        }
        if drift.latency_delta_ms >= cfg.latency_spike_ms {
            reasons.push(format!("p95 latency increased {}ms", drift.latency_delta_ms));
        }
        if drift.verdict_changed {
            reasons.push("verdict changed since previous run".to_string());
        }
    }

    if reasons.is_empty() {
        return None;
    }

    Some(Alert {
        upstream: report.upstream.clone(),
        verdict: format!("{:?}", report.verdict),
        summary: report.summary.clone(),
        reasons,
    })
}

async fn send_webhook(url: &str, alert: &Alert) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    client.post(url).json(alert).send().await?.error_for_status()?;
    Ok(())
}

pub fn parse_interval(s: &str) -> anyhow::Result<Duration> {
    let s = s.trim();
    if let Some(stripped) = s.strip_suffix("ms") {
        let n: u64 = stripped.parse().context("ms value")?;
        return Ok(Duration::from_millis(n));
    }
    if let Some(stripped) = s.strip_suffix('s') {
        let n: u64 = stripped.parse().context("seconds value")?;
        return Ok(Duration::from_secs(n));
    }
    if let Some(stripped) = s.strip_suffix('m') {
        let n: u64 = stripped.parse().context("minutes value")?;
        return Ok(Duration::from_secs(n * 60));
    }
    let n: u64 = s.parse().context("seconds value")?;
    Ok(Duration::from_secs(n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_seconds_suffix() {
        assert_eq!(parse_interval("45s").unwrap(), Duration::from_secs(45));
    }

    #[test]
    fn parses_minutes_suffix() {
        assert_eq!(parse_interval("2m").unwrap(), Duration::from_secs(120));
    }

    #[test]
    fn alert_triggers_on_verdict_change_and_drops() {
        let cfg = MonitorConfig {
            upstream: "https://api.deepseek.com".into(),
            key: None,
            claimed_model: None,
            use_case: "coding-agent".into(),
            interval: Duration::from_secs(30),
            max_rounds: None,
            identity_drop_threshold: 20,
            safety_drop_threshold: 20,
            latency_spike_ms: 500,
            webhook_url: None,
        };
        let report = DeepScanReport {
            upstream: "https://api.deepseek.com".into(),
            claimed_model: None,
            use_case: "coding-agent".into(),
            identity: crate::identity::IdentityReport {
                claimed_model: None,
                claimed_family: crate::identity::ModelFamily::Unknown,
                observed_family: crate::identity::ModelFamily::DeepSeek,
                confidence: 40,
                risk: crate::identity::IdentityRisk::High,
                reasons: vec![],
            },
            battery: crate::probes::BatteryReport {
                total_probes: 20,
                flagged_probes: 6,
                errored_probes: 0,
                results: vec![],
                category_scores: vec![],
                agent_safety_score: 41,
                verdict: crate::probes::AgentVerdict::DoNotUse,
            },
            metrics: crate::deep_scan::DeepScanMetrics {
                latency_p50_ms: 800,
                latency_p95_ms: 1900,
                successful_probes: 20,
                uptime_confidence: crate::deep_scan::UptimeConfidence::High,
            },
            drift: Some(crate::deep_scan::DriftSummary {
                previous_found: true,
                identity_delta: -30,
                safety_delta: -25,
                latency_delta_ms: 700,
                verdict_changed: true,
                summary: "dropped hard".into(),
            }),
            verdict: crate::probes::AgentVerdict::DoNotUse,
            summary: "bad".into(),
        };
        let alert = maybe_alert(&cfg, &report).unwrap();
        assert!(alert.reasons.len() >= 4);
    }
}
