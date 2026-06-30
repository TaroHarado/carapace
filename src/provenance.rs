//! Provenance & taint tracking вЂ” Layer 2 of the SafeRouter defense model.
//!
//! Every artifact (URL, file path, tool_result content, command string) gets
//! marked with a [`Source`]. When an artifact tagged UNTRUSTED is later used as
//! input to another action, the downstream action inherits taint. The policy
//! matrix then denies/quarantines tainted actions regardless of how benign
//! the literal text looks. This is the architectural answer to the classic
//! "СЃРµСЂС‹Р№ РїСЂРѕРІР°Р№РґРµСЂ СЂР°Р·Р»РѕР¶РёС‚ Р°С‚Р°РєСѓ РЅР° 5 С€Р°РіРѕРІ" attack chain вЂ” see the chain
//! detector in `session_graph.rs`.
//!
//! Without taint tracking, each step looks clean. With taint, step 3 (run a
//! file) inherits UNTRUSTED from step 1 (URL extracted from provider output).
//!
//! Backed by embedded sled kv-store (`~/.saferouter/provenance.sled/`). Survives
//! proxy restart, so a day-1 fetch -> day-3 execute trigger still gets caught.
//!
//! ```text
//! СЃРµСЂС‹Р№ РїСЂРѕРІР°Р№РґРµСЂ СЂР°Р·Р»РѕР¶РёС‚ Р°С‚Р°РєСѓ РЅР° 5 С€Р°РіРѕРІ вЂ” СЌС‚РѕС‚ РјРѕРґСѓР»СЊ Р»РѕРІРёС‚ РёРјРµРЅРЅРѕ С‚Р°РєРёРµ С†РµРїРѕС‡РєРё
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
    /// When last updated (йЈ™еЌ‡ taint on each new encounter).
    pub last_seen: u64,
    /// If true, the action that produced this artifact was tainted.
    pub tainted: bool,
    /// Parent artifact id(s) вЂ” artifacts this one was derived from.
    pub parents: Vec<ArtifactId>,
    /// Human-readable reason for the taint ("extracted from <id> of source=web").
    pub reason: Option<String>,
}

pub struct ProvenanceStore {
    db: Db,
    artifacts: Tree,
    baseline: Tree,
}

impl ProvenanceStore {
    /// Open (or create) the sled store at `dir`.
    pub fn open(dir: impl AsRef<Path>) -> anyhow::Result<Arc<Self>> {
        let db = sled::Config::default()
            .path(dir.as_ref())
            .flush_every_ms(Some(500))
            .open()?;
        let artifacts = db.open_tree("artifacts")?;
        let baseline = db.open_tree("baseline")?;
        Ok(Arc::new(Self { db, artifacts, baseline }))
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

    /// Garbage-collect taint entries older than `max_age_secs`. Untaints
    /// artifacts whose `last_seen` is older than the cutoff by setting
    /// `tainted = false`. The provenance record stays (for audit) but the
    /// taint flag is cleared so downstream actions are no longer blocked by
    /// stale taint from days ago.
    ///
    /// Returns the count of entries that were un-tainted.
    pub fn gc_taint(&self, max_age_secs: u64) -> anyhow::Result<usize> {
        let cutoff = now_ts().saturating_sub(max_age_secs);
        let mut untainted = 0usize;
        for entry in self.artifacts.iter() {
            let (key, val) = entry?;
            let mut p: Provenance = match serde_json::from_slice(&val) {
                Ok(e) => e,
                Err(_) => continue,
            };
            if p.tainted && p.last_seen < cutoff {
                p.tainted = false;
                p.reason = Some(format!("taint expired (gc at {})", now_ts()));
                self.artifacts.insert(&key, serde_json::to_vec(&p)?)?;
                untainted += 1;
            }
        }
        Ok(untainted)
    }

    /// Flush to disk (best-effort).
    pub fn flush(&self) -> anyhow::Result<()> {
        self.db.flush()?;
        Ok(())
    }
}

fn default_path() -> PathBuf {
    crate::paths::state_path("provenance.sled")
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

/// Persisted behavioral baseline (Layer 7). Serialized per-session and
/// stored in the `baseline` sled tree. On the next proxy start, the
/// session graph for the same session_id loads this entry and seeds
/// its learning window's capabilities + asset classes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselinePersistEntry {
    pub session_id: String,
    pub capabilities: Vec<String>,
    pub assets: Vec<String>,
    pub finalized: bool,
    pub first_seen_ts: u64,
    pub last_seen_ts: u64,
}

impl ProvenanceStore {
    /// Persist a session's baseline to sled. Keyed by `session_id`.
    pub fn save_baseline(&self, session_id: &str, entry: &BaselinePersistEntry) -> anyhow::Result<()> {
        let val = serde_json::to_vec(entry)?;
        self.baseline.insert(session_id.as_bytes(), val)?;
        Ok(())
    }

    /// Load a persisted baseline. Returns None if no saved baseline.
    pub fn load_baseline(&self, session_id: &str) -> anyhow::Result<Option<BaselinePersistEntry>> {
        match self.baseline.get(session_id.as_bytes())? {
            Some(b) => Ok(Some(serde_json::from_slice(&b)?)),
            None => Ok(None),
        }
    }

    /// Garbage-collect baselines older than `max_age_secs`.
    pub fn gc_baselines(&self, max_age_secs: u64) -> anyhow::Result<usize> {
        let cutoff = now_ts().saturating_sub(max_age_secs);
        let mut removed = 0usize;
        for entry in self.baseline.iter() {
            let (key, val) = entry?;
            let parsed: BaselinePersistEntry = match serde_json::from_slice(&val) {
                Ok(e) => e,
                Err(_) => {
                    let _ = self.baseline.remove(&key);
                    removed += 1;
                    continue;
                }
            };
            if parsed.last_seen_ts < cutoff {
                let _ = self.baseline.remove(&key);
                removed += 1;
            }
        }
        Ok(removed)
    }
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

    #[test]
    fn baseline_saves_and_loads() {
        let store = ProvenanceStore::open(tmp()).unwrap();
        let entry = BaselinePersistEntry {
            session_id: "sess-1".to_string(),
            capabilities: vec!["read:file".to_string(), "write:file".to_string()],
            assets: vec!["project".to_string()],
            finalized: true,
            first_seen_ts: 1_000,
            last_seen_ts: 2_000,
        };
        store.save_baseline("sess-1", &entry).unwrap();
        let loaded = store.load_baseline("sess-1").unwrap().unwrap();
        assert_eq!(loaded.session_id, "sess-1");
        assert_eq!(loaded.capabilities.len(), 2);
        assert!(loaded.capabilities.contains(&"read:file".to_string()));
        assert!(loaded.finalized);
    }

    #[test]
    fn baseline_load_returns_none_for_unknown_session() {
        let store = ProvenanceStore::open(tmp()).unwrap();
        assert!(store.load_baseline("never-seen").unwrap().is_none());
    }

    #[test]
    fn baseline_endures_restart() {
        let dir = tmp();
        {
            let store = ProvenanceStore::open(&dir).unwrap();
            let entry = BaselinePersistEntry {
                session_id: "sess-restart".to_string(),
                capabilities: vec!["execute:shell".to_string()],
                assets: vec!["executable".to_string()],
                finalized: false,
                first_seen_ts: 100,
                last_seen_ts: 200,
            };
            store.save_baseline("sess-restart", &entry).unwrap();
            store.flush().unwrap();
        }
        let store2 = ProvenanceStore::open(&dir).unwrap();
        let loaded = store2.load_baseline("sess-restart").unwrap().unwrap();
        assert_eq!(loaded.session_id, "sess-restart");
        assert!(loaded.capabilities.contains(&"execute:shell".to_string()));
    }

    #[test]
    fn gc_baselines_removes_old_entries() {
        let store = ProvenanceStore::open(tmp()).unwrap();
        let old = BaselinePersistEntry {
            session_id: "old-sess".to_string(),
            capabilities: vec![],
            assets: vec![],
            finalized: true,
            first_seen_ts: 1,
            last_seen_ts: 1,
        };
        let young = BaselinePersistEntry {
            session_id: "young-sess".to_string(),
            capabilities: vec![],
            assets: vec![],
            finalized: true,
            first_seen_ts: now_ts() - 100,
            last_seen_ts: now_ts(),
        };
        store.save_baseline("old-sess", &old).unwrap();
        store.save_baseline("young-sess", &young).unwrap();
        let removed = store.gc_baselines(1000).unwrap();
        assert_eq!(removed, 1);
        assert!(store.load_baseline("old-sess").unwrap().is_none());
assert!(store.load_baseline("young-sess").unwrap().is_some());
    }
}
