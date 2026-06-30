//! Local provider registry / trust cache.
//!
//! `cape certify` creates publishable artifacts.
//! `cape registry` turns those artifacts into a local trust graph:
//!
//! - cache signed entries on disk
//! - list what has been certified
//! - verify signatures against a known pubkey
//! - inspect the latest known score for a provider
//!
//! This is the missing bridge between a one-off audit artifact and an actual
//! long-lived trust network.

use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::certify::RegistryEntry;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Registry {
    pub entries: Vec<RegistryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryFeed {
    pub schema_version: String,
    pub generated_at: String,
    pub entries: Vec<RegistryEntry>,
    /// Optional detached signature over the feed digest.
    pub signature: Option<String>,
}

impl Registry {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read registry `{}`", path.display()))?;
        let reg = serde_json::from_str(&raw)
            .with_context(|| format!("parse registry `{}`", path.display()))?;
        Ok(reg)
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)
            .with_context(|| format!("write registry `{}`", path.display()))?;
        Ok(())
    }

    /// Insert or replace the latest entry for the same host.
    pub fn add(&mut self, entry: RegistryEntry) {
        self.entries.retain(|e| e.host != entry.host);
        self.entries.push(entry);
        self.entries.sort_by(|a, b| a.host.cmp(&b.host));
    }

    pub fn list(&self) -> &[RegistryEntry] {
        &self.entries
    }

    pub fn get_by_host(&self, host: &str) -> Option<&RegistryEntry> {
        self.entries.iter().find(|e| e.host.eq_ignore_ascii_case(host))
    }

    pub fn verify_all(&self, pubkey_b64: &str) -> Vec<(String, anyhow::Result<()>)> {
        self.entries
            .iter()
            .map(|e| (e.host.clone(), e.verify_with_pubkey(pubkey_b64)))
            .collect()
    }

    pub fn merge(&mut self, other: Registry) {
        for entry in other.entries {
            self.add(entry);
        }
    }

    pub fn to_feed(&self) -> RegistryFeed {
        RegistryFeed {
            schema_version: "1".to_string(),
            generated_at: time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| "?".to_string()),
            entries: self.entries.clone(),
            signature: None,
        }
    }
}

pub async fn fetch_remote_registry(url: &str) -> anyhow::Result<Registry> {
    let resp = reqwest::get(url).await?.error_for_status()?;
    let raw = resp.text().await?;
    // Accept either the plain registry or the wrapped signed feed format.
    if let Ok(feed) = serde_json::from_str::<RegistryFeed>(&raw) {
        Ok(Registry {
            entries: feed.entries,
        })
    } else {
        let reg = serde_json::from_str(&raw)
            .with_context(|| format!("parse remote registry from `{url}`"))?;
        Ok(reg)
    }
}

impl RegistryFeed {
    pub fn signing_digest(&self) -> [u8; 32] {
        let bytes = serde_json::to_vec(&(&self.schema_version, &self.generated_at, &self.entries))
            .expect("serializable registry feed");
        let digest = sha2::Sha256::digest(bytes);
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    pub fn sign_with_base64_secret(&mut self, secret_b64: &str) -> anyhow::Result<()> {
        use base64::Engine as _;
        use ed25519_dalek::{Signer, SigningKey};

        let secret = base64::engine::general_purpose::STANDARD.decode(secret_b64.as_bytes())?;
        let arr: [u8; 32] = secret
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("signing key must be 32 raw bytes in base64"))?;
        let sk = SigningKey::from_bytes(&arr);
        let sig = sk.sign(&self.signing_digest());
        self.signature = Some(base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()));
        Ok(())
    }

    pub fn verify_with_pubkey(&self, pubkey_b64: &str) -> anyhow::Result<()> {
        use base64::Engine as _;
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let sig_b64 = self.signature.as_ref().ok_or_else(|| anyhow::anyhow!("missing feed signature"))?;
        let sig_bytes = base64::engine::general_purpose::STANDARD.decode(sig_b64.as_bytes())?;
        let sig = Signature::from_slice(&sig_bytes)?;

        let pk_bytes = base64::engine::general_purpose::STANDARD.decode(pubkey_b64.as_bytes())?;
        let arr: [u8; 32] = pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("pubkey must decode to 32 bytes"))?;
        let vk = VerifyingKey::from_bytes(&arr)?;
        vk.verify(&self.signing_digest(), &sig)?;
        Ok(())
    }
}

pub fn default_registry_path() -> PathBuf {
    crate::paths::state_path("registry.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certify::RegistryEntry;
    use crate::scan::{RiskLevel, ScanReport};
    use crate::score::{render_badge_svg, score_provider};
    use base64::Engine as _;
    use ed25519_dalek::{SigningKey, VerifyingKey};

    fn sample_entry(host: &str) -> RegistryEntry {
        let scan = ScanReport {
            upstream: format!("https://{host}"),
            protocol: "openai".into(),
            risk_score: 0,
            verdict: RiskLevel::Clean,
            categories: vec![],
            unsolicited_tool_uses: 0,
            bytes_received: 42,
            note: "clean".into(),
        };
        let score = score_provider(&format!("https://{host}"), scan);
        let badge = render_badge_svg(&score);
        RegistryEntry::from_score(&score, &badge)
    }

    #[test]
    fn add_replaces_same_host() {
        let mut reg = Registry::default();
        reg.add(sample_entry("api.deepseek.com"));
        reg.add(sample_entry("api.deepseek.com"));
        assert_eq!(reg.entries.len(), 1);
    }

    #[test]
    fn get_by_host_finds_entry() {
        let mut reg = Registry::default();
        reg.add(sample_entry("api.deepseek.com"));
        assert!(reg.get_by_host("api.deepseek.com").is_some());
    }

    #[test]
    fn save_and_load_round_trip() {
        let path = std::env::temp_dir().join(format!(
            "carapace-registry-{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        let mut reg = Registry::default();
        reg.add(sample_entry("api.deepseek.com"));
        reg.save(&path).unwrap();
        let loaded = Registry::load(&path).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn feed_sign_and_verify_round_trip() {
        let mut reg = Registry::default();
        reg.add(sample_entry("api.deepseek.com"));
        let mut feed = reg.to_feed();

        let sk = SigningKey::generate(&mut rand_core::OsRng);
        let secret_b64 = base64::engine::general_purpose::STANDARD.encode(sk.to_bytes());
        let pub_b64 = base64::engine::general_purpose::STANDARD.encode(VerifyingKey::from(&sk).to_bytes());

        feed.sign_with_base64_secret(&secret_b64).unwrap();
        feed.verify_with_pubkey(&pub_b64).unwrap();
    }
}
