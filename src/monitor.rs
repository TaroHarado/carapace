//! Provider monitoring runner.
//!
//! This is the first real `v2` backbone: repeatedly run deep-scan for one
//! provider, rely on `history.rs` to persist outcomes, and print drift deltas.

use std::time::Duration;

use anyhow::Context;

use crate::deep_scan::{self, DeepScanReport};
use crate::secure::Secret;

pub struct MonitorConfig {
    pub upstream: String,
    pub key: Option<Secret>,
    pub claimed_model: Option<String>,
    pub use_case: String,
    pub interval: Duration,
    pub max_rounds: Option<u32>,
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

        if let Some(max) = cfg.max_rounds {
            if round >= max {
                return Ok(());
            }
        }

        // Reinsert key for next loop.
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
}
