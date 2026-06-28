//! `cape` — carapace CLI entry point.

use std::net::SocketAddr;

use anyhow::Context;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use carapace::cli::{Cli, Commands, Mode};
use carapace::proxy::{self, ProxyConfig};
use carapace::record::Recorder;
use carapace::scan;
use carapace::secure::Secret;

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
            rules: _,
            blocklist: _,
        } => {
            let listen_addr: SocketAddr = listen
                .parse()
                .with_context(|| format!("invalid --listen `{listen}`"))?;
            let key = match upstream_key {
                Some(k) => Secret::new(k),
                None => Secret::empty(),
            };
            let recorder = Recorder::open(&log).context("open log")?;
            let cfg = ProxyConfig {
                upstream,
                listen: listen_addr,
                upstream_key: key,
                mode,
                recorder: std::sync::Arc::new(recorder),
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
            eprintln!("cape audit: host IoC scan not implemented in v0.1.0");
            Ok(())
        }
        Commands::Sentinel { interval } => {
            eprintln!("cape sentinel: background monitor not implemented in v0.1.0 (interval={interval})");
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
