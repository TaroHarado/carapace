//! carapace — local guard against malicious LLM providers.
//!
//! Wire-level inspection proxy: sits between AI client and upstream provider,
//! reassembles SSE streams, scans for prompt-injection / tool-use abuse,
//! alerts or blocks. Memory-safe key handling, crash-isolated core.

pub mod cli;
pub mod feed;
pub mod inspect;
pub mod mockevil;
pub mod protocol;
pub mod proxy;
pub mod record;
pub mod scan;
pub mod secure;
pub mod tools;

pub use cli::{Cli, Commands};

pub const NAME: &str = "carapace";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const BIN: &str = "cape";
