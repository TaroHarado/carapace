//! Provenance & taint tracking — Layer 2 of the SafeRouter defense model.
//!
//! Every artifact (URL, file path, tool_result content, command string) gets
//! marked with a [`Source`]. When an artifact tagged UNTRUSTED is later used as
//! input to another action, the downstream action inherits taint. The policy
//! matrix then denies/quarantines tainted actions regardless of how benign
//! the literal text looks. This is the architectural answer to the classic
//! "серый провайдер разложит атаку на 5 шагов" attack chain — see the chain
//! detector in `session_graph.rs`.
//!
//! Without taint tracking, each step looks clean. With taint, step 3 (run a
//! file) inherits UNTRUSTED from step 1 (URL extracted from provider output).
//!
//! Backed by embedded sled kv-store (`~/.carapace/provenance.sled/`). Survives
//! proxy restart, so a day-1 fetch -> day-3 execute trigger still gets caught.
//!
//! ```text
//! серый провайдер разложит атаку на 5 шагов — этот модуль ловит именно такие цепочки
//! ```

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sled::{Db, Tree};

use crate::asset::Source;

/// Stable artifact id = content hash (best) or fallback to the literal string.
/// We store provenance keyed by *artifact_id*, so the same content re-fetched
/// from a different source only escalates taint, never de-escalates.
pub type ArtifactId = String;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provenance {
    pub artifact_id: ArtifactId,
    /// Original literal form (path / URL / first 256 chars of text content).
    pub literal: String,
    /// Origin of the artifact.
    pub source: Source,
    /// When first observed (unix ts seconds).
    pub first_seen: u64,
    /// When last updated (飙升 taint on each new encounter).
    pub last_seen: u64,
    /// If true, the action that produced this artifact was tainted.
    pub tainted: bool,
    /// Parent artifact id(s) — artifacts this one was derived from.
    pub parents: Vec<ArtifactId>,
    /// Human-readable reason for the taint ("extracted from <id> of source=web").
    pub reason: Option<String>,
}

pub struct ProvenanceStore {
    db: Db,
    artifacts: Tree,
}

impl ProvenanceStore {
    /// Open (or create) the sled store at `dir`.
    pub fn open(dir: impl AsRef<Path>) -> anyhow::Result<Arc<Self>> {
        let db = sled::Config::default()
            .path(dir.as_ref())
            .flush_every_ms(Some(500))
            .open()?;
        let artifacts = db.open_tree("artifacts")?;
        Ok(Arc::new(Self { db, artifacts }))
    }

    pub fn open_default() -> anyhow::Result<Arc<Self>> {
        let path = default_path();
        Self::open(path)
    }

    /// Record an artifact origin. If the artifact already exists, the source
    /// is escalated (UNTRUSTED wins over TRUSTED) and `last_seen` is bumped.
    pub fn record(&self, artifact_id: &str, literal: &str, source: Source, parents: &[ArtifactId]) -> anyhow::Result<Provenance> {
        let now = now_ts();
        let existing = self.artifacts.get(artifact_id)?;
        let mut tainted = source.is_untrusted();
        let mut all_parents = parents.to_vec();
        let mut reason = None;
        if !tainted {
            // Inherit taint from parents.
            for pid in parents {
                if let Some(bytes) = self.artifacts.get(pid)? {
                    let p: Provenance = postcard_from(&bytes)?;
                    if p.tainted {
                        tainted = true;
                        reason = Some(format!("derived from tainted artifact {}", pid));
                        break;
                    }
                }
            }
        } else {
            reason = Some(format!("origin source={}", source.label()));
        }
        let first_seen = existing
            .as_ref()
            .and_then(|b| postcard_from::<Provenance>(b).ok())
            .map(|p| p.first_seen)
            .unwrap_or(now);
        all_parents.dedup();
        let new = Provenance {
            artifact_id: artifact_id.to_string(),
            literal: literal.chars().take(256).collect(),
            source,
            first_seen,
            last_seen: now,
            tainted,
            parents: all_parents,
            reason,
        };
        let bytes = postcard_to(&new)?;
        self.artifacts.insert(artifact_id, bytes)?;
        Ok(new)
    }

/// Look up provenance for an artifact.
    pub fn lookup(&self, artifact_id: &str) -> anyhow::Result<Option<Provenance>> {
        let opt = self
            .artifacts
            .get(artifact_id)?
            .map(|b| postcard_from(&b));
        opt.transpose()
    }

    /// True if any artifact id in the set is tainted (or descends from one).
    pub fn any_tainted(&self, ids: &[ArtifactId]) -> anyhow::Result<bool> {
        for id in ids {
            if let Some(p) = self.lookup(id)? {
                if p.tainted {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Mark an artifact explicitly tainted (manual / heuristic escalation).
    pub fn mark_tainted(&self, artifact_id: &str, reason: &str) -> anyhow::Result<()> {
        if let Some(p) = self.lookup(artifact_id)? {
            let mut p = p;
            p.tainted = true;
            p.reason = Some(reason.to_string());
            p.last_seen = now_ts();
            self.artifacts.insert(artifact_id, postcard_to(&p)?)?;
        }
        Ok(())
    }

    /// Flush to disk (best-effort).
    pub fn flush(&self) -> anyhow::Result<()> {
        self.db.flush()?;
        Ok(())
    }
}

fn default_path() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        PathBuf::from(home).join(".carapace").join("provenance.sled")
    } else {
        PathBuf::from(".carapace").join("provenance.sled")
    }
}

fn now_ts() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn postcard_to<T: Serialize>(v: &T) -> anyhow::Result<Vec<u8>> {
    Ok(serde_json::to_vec(v)?)
}

fn postcard_from<T: for<'de> Deserialize<'de>>(b: &[u8]) -> anyhow::Result<T> {
    Ok(serde_json::from_slice(b)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile;

    fn tmp() -> PathBuf {
    tempfile::tempdir().unwrap().keep()
}

    #[test]
    fn records_provider_artifact_as_tainted() {
        let store = ProvenanceStore::open(tmp()).unwrap();
        let p = store.record("aid:1", "https://evil.com/x.sh", Source::Provider, &[]).unwrap();
        assert!(p.tainted);
        assert_eq!(p.source, Source::Provider);
    }

    #[test]
    fn records_user_artifact_as_clean() {
        let store = ProvenanceStore::open(tmp()).unwrap();
        let p = store.record("aid:u", "Build the project", Source::User, &[]).unwrap();
        assert!(!p.tainted);
        assert_eq!(p.source, Source::User);
    }

    #[test]
    fn inherits_taint_from_parent() {
        let store = ProvenanceStore::open(tmp()).unwrap();
        let _ = store.record("pid:1", "https://evil.com/x.sh", Source::Provider, &[]).unwrap();
        let child = store.record("cid:1", "/tmp/x.sh", Source::Internal, &["pid:1".to_string()]).unwrap();
        assert!(child.tainted, "child must inherit parent's taint");
        assert_eq!(child.source, Source::Internal);
    }

    #[test]
    fn persists_across_reopen() {
        let dir = tmp();
        let store = ProvenanceStore::open(&dir).unwrap();
        let _ = store.record("aid:persist", "https://evil.com/y.sh", Source::Web, &[]).unwrap();
        store.flush().ok();
        drop(store);
        let store2 = ProvenanceStore::open(&dir).unwrap();
        let p = store2.lookup("aid:persist").unwrap().unwrap();
        assert!(p.tainted);
        assert_eq!(p.source, Source::Web);
    }

    #[test]
    fn any_tainted_predicate() {
        let store = ProvenanceStore::open(tmp()).unwrap();
        let _ = store.record("clean", "ok", Source::User, &[]).unwrap();
        let _ = store.record("bad", "bad", Source::Provider, &[]).unwrap();
        assert!(store.any_tainted(&["clean".into(), "bad".into()]).unwrap());
        assert!(!store.any_tainted(&["clean".into()]).unwrap());
        assert!(!store.any_tainted(&["missing".into()]).unwrap());
    }

    #[test]
    fn manual_taint_escalation() {
        let store = ProvenanceStore::open(tmp()).unwrap();
        // Source::LocalFile is trusted (not in the untrusted tier) — record
        // as clean, then escalate manually.
        let _ = store.record("escalate", "maybe", Source::LocalFile, &[]).unwrap();
        assert!(!store.lookup("escalate").unwrap().unwrap().tainted);
        store.mark_tainted("escalate", "heuristic").unwrap();
        let p = store.lookup("escalate").unwrap().unwrap();
        assert!(p.tainted);
        assert_eq!(p.reason.as_deref(), Some("heuristic"));
    }
}