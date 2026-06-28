//! carapace — local guard against malicious LLM providers.
//!
//! Wire-level inspection proxy: sits between AI client and upstream provider,
//! reassembles SSE streams, scans for prompt-injection / tool-use abuse,
//! alerts or blocks. Memory-safe key handling, crash-isolated core.

pub mod audit;
pub mod artifact;
pub mod bundle;
pub mod certify;
pub mod cli;
pub mod deep_scan;
pub mod feed;
pub mod identity;
pub mod inspect;
pub mod judge;
pub mod mockevil;
pub mod policy;
pub mod probes;
pub mod protocol;
pub mod proxy;
pub mod record;
pub mod registry;
pub mod scan;
pub mod score;
pub mod secure;
pub mod session;
pub mod sentinel;
pub mod tools;
pub mod web;

pub use cli::{Cli, Commands};

pub const NAME: &str = "carapace";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const BIN: &str = "cape";
