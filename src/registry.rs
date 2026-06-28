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

use crate::certify::RegistryEntry;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Registry {
    pub entries: Vec<RegistryEntry>,
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
}

pub fn default_registry_path() -> PathBuf {
    if cfg!(target_os = "windows") {
        if let Ok(home) = std::env::var("USERPROFILE") {
            return PathBuf::from(home).join(".carapace").join("registry.json");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".carapace").join("registry.json");
    }
    PathBuf::from("registry.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certify::RegistryEntry;
    use crate::scan::{RiskLevel, ScanReport};
    use crate::score::{render_badge_svg, score_provider};

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
}
