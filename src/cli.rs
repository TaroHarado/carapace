//! CLI surface: clap-derived commands.
//!
//! Four verbs — proxy | scan | audit | sentinel.
//! Mirrors holone's UX (proven), with explicit defaults that match safe usage:
//!   - default `block` mode (not `monitor`)
//!   - stderr alerting in addition to JSONL log
//!   - `--upstream-key` zeroized in place

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "cape",
    bin_name = "cape",
    version,
    about = "local guard against malicious LLM providers — wire-level inspection proxy",
    long_about = "carapace sits on the wire between your AI client and an upstream LLM \
provider, reassembles SSE streams, and inspects every tool_use / text chunk for \
prompt-injection, download-and-execute, persistence, anti-forensics and known IoCs. \
Your API key is zeroized after use; never logged."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Increase verbosity (-v info, -vv debug, -vvv trace).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Suppress all non-alert output.
    #[arg(short, long, global = true)]
    pub quiet: bool,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Stand up the inspecting reverse proxy in front of an upstream provider.
    Proxy {
        /// Upstream base URL, e.g. https://api.anthropic.com or https://api.example-reseller.com
        #[arg(long, env = "CAPE_UPSTREAM")]
        upstream: String,

        /// Listen address for the local proxy.
        #[arg(long, env = "CAPE_LISTEN", default_value = "127.0.0.1:8787")]
        listen: String,

        /// API key passed to upstream. Forwarded verbatim, never logged.
        /// If omitted, the client's own Authorization header is forwarded.
        #[arg(long, env = "CAPE_UPSTREAM_KEY")]
        upstream_key: Option<String>,

        /// Detection mode: `block` rewrites suspicious tool_use, `monitor` only logs.
        #[arg(long, env = "CAPE_MODE", default_value = "block")]
        mode: Mode,

        /// JSONL log path. `-` means stderr.
        #[arg(long, env = "CAPE_LOG", default_value = "-")]
        log: String,

        /// Custom rules file (overrides built-in).
        #[arg(long)]
        rules: Option<PathBuf>,

        /// Custom IoC blocklist file (overrides built-in).
        #[arg(long)]
        blocklist: Option<PathBuf>,

        /// Encrypted forensics store path. Suspicious upstream responses are
        /// appended here under XChaCha20-Poly1305, never in plaintext.
        #[arg(long)]
        forensics: Option<PathBuf>,

        /// Passphrase for `--forensics`. Required if `--forensics` is set.
        /// Used to derive the encryption key; not stored anywhere.
        #[arg(long, env = "CAPE_FORENSICS_PASS")]
        forensics_pass: Option<String>,
    },

    /// Probe an upstream with a tool-less prompt and report a risk score.
    Scan {
        #[arg(long)]
        upstream: String,

        #[arg(long, env = "CAPE_UPSTREAM_KEY")]
        key: Option<String>,
    },

    /// Produce a certification-style provider score from a canary scan.
    Score {
        #[arg(long)]
        upstream: String,

        #[arg(long, env = "CAPE_UPSTREAM_KEY")]
        key: Option<String>,

        /// Output format: json | markdown
        #[arg(long, default_value = "markdown")]
        format: String,

        /// Optional output file for the report.
        #[arg(long)]
        out: Option<PathBuf>,

        /// Optional SVG badge output path.
        #[arg(long)]
        badge: Option<PathBuf>,
    },

    /// Generate a publish-ready certification bundle (report + badge + signed registry entry).
    Certify {
        #[arg(long)]
        upstream: String,

        #[arg(long, env = "CAPE_UPSTREAM_KEY")]
        key: Option<String>,

        /// Output directory for report.md, badge.svg and entry.json.
        #[arg(long, default_value = ".")]
        out: PathBuf,

        /// Optional base64-encoded Ed25519 secret key for signing entry.json.
        #[arg(long, env = "CAPE_CERTIFY_SECRET")]
        signing_key: Option<String>,
    },

    /// One-shot pipeline: scan -> score -> certify -> add to local registry.
    Verify {
        #[arg(long)]
        upstream: String,

        #[arg(long, env = "CAPE_UPSTREAM_KEY")]
        key: Option<String>,

        /// Output directory for report.md, badge.svg and entry.json.
        #[arg(long, default_value = ".")]
        out: PathBuf,

        /// Optional base64-encoded Ed25519 secret key for signing entry.json.
        #[arg(long, env = "CAPE_CERTIFY_SECRET")]
        signing_key: Option<String>,

        /// Optional local registry path. Defaults to ~/.carapace/registry.json.
        #[arg(long)]
        registry: Option<PathBuf>,
    },

    /// Manage the local provider trust registry.
    Registry {
        #[command(subcommand)]
        action: RegistryCmd,
    },

    /// One-shot host audit: known IoCs for malicious-LLM campaigns.
    Audit,

    /// Background host monitor: re-run audit on an interval.
    Sentinel {
        #[arg(long, default_value = "30s")]
        interval: String,
    },

    /// Fetch and verify a signed remote threat feed (rules + blocklist + IoCs).
    Feed {
        /// Remote manifest URL (JSON, signed).
        #[arg(long)]
        url: String,

        /// Ed25519 public key (base64) to verify the feed signature.
        /// If omitted, only integrity hashes are checked (no signature trust).
        #[arg(long, env = "CAPE_FEED_PUBKEY")]
        pubkey: Option<String>,

        /// Output directory for rules.json + blocklist.json.
        #[arg(long, default_value = ".")]
        out: PathBuf,
    },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, clap::ValueEnum, Default)]
pub enum Mode {
    /// Passive: log alerts only (you must watch logs yourself).
    Monitor,
    /// Active: rewrite suspicious tool_use to a safe stub before it reaches the client.
    #[default]
    Block,
}

#[derive(Subcommand, Debug)]
pub enum RegistryCmd {
    /// Add a signed entry.json artifact to the local registry cache.
    Add {
        #[arg(long)]
        entry: PathBuf,

        #[arg(long)]
        registry: Option<PathBuf>,
    },

    /// List cached providers.
    List {
        #[arg(long)]
        registry: Option<PathBuf>,
    },

    /// Show the full cached entry for one host.
    Show {
        #[arg(long)]
        host: String,

        #[arg(long)]
        registry: Option<PathBuf>,
    },

    /// Verify every registry entry against a known Ed25519 pubkey.
    Verify {
        #[arg(long)]
        pubkey: String,

        #[arg(long)]
        registry: Option<PathBuf>,
    },

    /// Merge a signed remote registry feed into the local cache.
    Sync {
        #[arg(long)]
        url: String,

        #[arg(long)]
        pubkey: String,

        #[arg(long)]
        registry: Option<PathBuf>,
    },
}
