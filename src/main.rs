//! `cape` — carapace CLI entry point.

use std::net::SocketAddr;

use anyhow::Context;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use carapace::audit;
use carapace::cli::{Cli, Commands, Mode};
use carapace::proxy::{self, ProxyConfig};
use carapace::record::{EncryptedForensics, Recorder};
use carapace::scan;
use carapace::secure::Secret;
use carapace::sentinel;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose, cli.quiet);

    match cli.command {
        Commands::Proxy {
            upstream,
            listen,
            upstream_key,
            mode,
            log,
            rules,
            blocklist,
            forensics,
            forensics_pass,
        } => {
            let listen_addr: SocketAddr = listen
                .parse()
                .with_context(|| format!("invalid --listen `{listen}`"))?;
            let key = match upstream_key {
                Some(k) => Secret::new(k),
                None => Secret::empty(),
            };
            let recorder = Recorder::open(&log).context("open log")?;
            let loaded_rules = carapace::inspect::load_from_files(
                rules.as_deref(),
                blocklist.as_deref(),
            )
            .context("load rules/blocklist")?;
            let judge = carapace::judge::from_env().map(std::sync::Arc::new);
            let forensics = match (forensics, forensics_pass) {
                (Some(path), Some(pass)) => Some(std::sync::Arc::new(
                    EncryptedForensics::open(
                        path.to_str().unwrap_or(""),
                        &pass,
                    )
                    .context("open forensics store")?,
                )),
                (Some(_), None) => anyhow::bail!("--forensics requires --forensics-pass"),
                (None, _) => None,
            };
            let cfg = ProxyConfig {
                upstream,
                listen: listen_addr,
                upstream_key: key,
                mode,
                recorder: std::sync::Arc::new(recorder),
                forensics,
                rules: std::sync::Arc::new(loaded_rules),
                judge,
            };
            proxy::run(cfg).await
        }
        Commands::Scan { upstream, key } => {
            let key = key.map(Secret::new);
            let report = scan::run(&upstream, key).await?;
            eprintln!("risk: {:?} ({})", report.verdict, report.risk_score);
            if !report.categories.is_empty() {
                eprintln!("categories: {}", report.categories.join(" "));
            }
            eprintln!("protocol: {}", report.protocol);
            eprintln!("bytes: {}", report.bytes_received);
            eprintln!("note: {}", report.note);
            if report.risk_score >= 60 {
                std::process::exit(2);
            }
            Ok(())
        }
        Commands::Audit => {
            let report = audit::run();
            eprintln!("platform: {}", report.platform);
            eprintln!("risk: {} — {}", report.risk_score, report.verdict);
            if report.findings.is_empty() {
                eprintln!("no indicators matched");
            } else {
                for f in &report.findings {
                    eprintln!("[{}] {} (sev={})", f.category, f.detail, f.severity);
                }
            }
            if report.risk_score >= 60 {
                std::process::exit(2);
            }
            Ok(())
        }
        Commands::Sentinel { interval } => {
            let dur = sentinel::parse_interval(&interval)
                .with_context(|| format!("invalid --interval `{interval}`"))?;
            sentinel::run(carapace::sentinel::SentinelConfig {
                interval: dur,
                max_rounds: None,
            })
            .await
        }
        Commands::Feed { url, pubkey, out } => {
            let out = out.to_str().unwrap_or(".").to_string();
            eprintln!("cape feed: fetching {url}");
            let fetched = carapace::feed::fetch_remote(&url)
                .await
                .context("fetch remote feed")?;
            eprintln!(
                "feed: v{} generated {}",
                fetched.manifest.version, fetched.manifest.generated_at
            );
            if let Some(pk) = &pubkey {
                match fetched.manifest.verify_signature_with_pubkey(pk) {
                    Ok(()) => eprintln!("feed: signature OK (pubkey {pk})"),
                    Err(e) => {
                        eprintln!("feed: signature FAIL — {e}");
                        anyhow::bail!("feed signature verification failed");
                    }
                }
            } else {
                eprintln!("feed: no --pubkey given, signature NOT verified");
            }
            if fetched.manifest.verify_integrity(&fetched.rules, &fetched.blocklist) {
                eprintln!("feed: integrity OK");
            } else {
                eprintln!("feed: integrity FAIL — hashes don't match");
                anyhow::bail!("feed integrity check failed");
            }
            std::fs::write(format!("{out}/rules.json"), &fetched.rules)
                .context("write rules.json")?;
            std::fs::write(format!("{out}/blocklist.json"), &fetched.blocklist)
                .context("write blocklist.json")?;
            std::fs::write(
                format!("{out}/manifest.json"),
                serde_json::to_string_pretty(&fetched.manifest)?,
            )
            .context("write manifest.json")?;
            eprintln!("feed: wrote rules.json, blocklist.json, manifest.json to {out}");
            Ok(())
        }
    }
}

fn init_tracing(verbose: u8, quiet: bool) {
    let filter = if quiet {
        EnvFilter::new("error,carapace=warn")
    } else {
        match verbose {
            0 => EnvFilter::new("info,carapace=info"),
            1 => EnvFilter::new("debug,carapace=debug"),
            _ => EnvFilter::new("trace,carapace=trace"),
        }
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

// keep `Mode` in scope for `Block` default-checking later
const _: fn(Mode) = |_| {};
