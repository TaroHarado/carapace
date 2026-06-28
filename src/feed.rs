//! Threat-feed manifest primitives.
//!
//! v0.5 does **not** ship a hosted proprietary feed yet; what it does ship is
//! the data model and local integrity checks the cloud feed will plug into.
//! This keeps the OSS core honest: users can see exactly what a signed feed is
//! supposed to contain before we ever ask them to trust one.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeedManifest {
    pub version: String,
    pub generated_at: String,
    pub rules_sha256: String,
    pub blocklist_sha256: String,
    /// Detached signature placeholder. v0.5 leaves this empty; v0.6 will
    /// support cosign/sigstore verification against a published public key.
    pub signature: Option<String>,
}

impl FeedManifest {
    pub fn local(version: &str, generated_at: &str, rules: &str, blocklist: &str) -> Self {
        Self {
            version: version.to_string(),
            generated_at: generated_at.to_string(),
            rules_sha256: sha256_hex(rules.as_bytes()),
            blocklist_sha256: sha256_hex(blocklist.as_bytes()),
            signature: None,
        }
    }

    pub fn verify(&self, rules: &str, blocklist: &str) -> bool {
        self.rules_sha256 == sha256_hex(rules.as_bytes())
            && self.blocklist_sha256 == sha256_hex(blocklist.as_bytes())
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_verifies_builtin_files() {
        let rules = include_str!("../rules/default.json");
        let blocklist = include_str!("../rules/blocklist.json");
        let mf = FeedManifest::local("v0.5-dev", "2026-06-28T00:00:00Z", rules, blocklist);
        assert!(mf.verify(rules, blocklist));
    }

    #[test]
    fn manifest_detects_tampering() {
        let rules = include_str!("../rules/default.json");
        let blocklist = include_str!("../rules/blocklist.json");
        let mf = FeedManifest::local("v0.5-dev", "2026-06-28T00:00:00Z", rules, blocklist);
        assert!(!mf.verify(&(rules.to_owned() + "\n "), blocklist));
    }
}
