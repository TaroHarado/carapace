//! `cape sentinel` — background host monitor.
//!
//! Runs `audit::run` on a fixed interval and reports new findings as they
//! appear. This is the cheaper "always-on" companion to a one-shot audit:
//! you set it going while you work and it tells you the moment your host
//! starts exhibiting IoC behaviour.
//!
//! v0.7 wires the same audit-and-notify loop, but adds diffing against the
//! previous run (so we only surface *new* indicators) and optional webhook
//! notification. This file is intentionally minimal — the audit engine is
//! the source of truth, sentinel just paces it.

use std::time::Duration;

use anyhow::Context;
use tokio::time;

use crate::audit;

pub struct SentinelConfig {
    pub interval: Duration,
    pub max_rounds: Option<u32>,
}

impl Default for SentinelConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(30),
            max_rounds: None,
        }
    }
}

pub async fn run(cfg: SentinelConfig) -> anyhow::Result<()> {
    let mut ticker = time::interval(cfg.interval);
    let mut round: u32 = 0;
    let mut prev_score: u32 = 0;
    tracing::info!(?cfg.interval, "sentinel up");

    loop {
        ticker.tick().await;
        round += 1;
        let report = audit::run();
        if report.risk_score != prev_score {
            emit(&report, round);
            prev_score = report.risk_score;
        }
        if let Some(max) = cfg.max_rounds {
            if round >= max {
                tracing::info!(round, "sentinel reached max_rounds, exiting");
                return Ok(());
            }
        }
    }
}

fn emit(report: &audit::AuditReport, round: u32) {
    eprintln!("--- sentinel round {round} ---");
    eprintln!("risk: {} ({})", report.risk_score, report.verdict);
    for f in &report.findings {
        eprintln!("[{}] {}", f.category, f.detail);
    }
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
    fn parses_milliseconds_suffix() {
        assert_eq!(parse_interval("750ms").unwrap(), Duration::from_millis(750));
    }

    #[test]
    fn parses_minutes_suffix() {
        assert_eq!(parse_interval("5m").unwrap(), Duration::from_secs(300));
    }

    #[test]
    fn bare_value_is_seconds() {
        assert_eq!(parse_interval("60").unwrap(), Duration::from_secs(60));
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_interval("soon").is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sentinel_exits_after_max_rounds() {
        let cfg = SentinelConfig {
            interval: Duration::from_millis(5),
            max_rounds: Some(2),
        };
        // We don't assert findings — CI hosts vary. We assert it returns.
        run(cfg).await.unwrap();
    }
}