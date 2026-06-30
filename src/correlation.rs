//! Cross-agent correlation — Layer 8.5 (post-chain alert).
//!
//! When two or more independent agent sessions send the same tainted URL /
//! artifact to the outside world within the same workspace, it is highly likely
//! that one compromised agent is being used as a relay or that a prompt-
//! injection campaign is coordinated across multiple agents.
//!
//! This module maintains a lightweight sled tree
//! (`~/.saferouter/correlation.sled/`) keyed by
//!
//!   `<workspace_hash>:<artifact_id>`  →  `CorrelationRecord`
//!
//! On every `record_outbound()` call the caller supplies:
//!   - `workspace`  – canonical path of the shared workspace (or CWD)
//!   - `session_id` – current agent session
//!   - `artifact_id` – sha256 or URL/path literal
//!
//! If a *different* session_id already recorded the same artifact in the same
//! workspace, `record_outbound()` returns `Some(CorrelationAlert)`.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sled::Db;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationRecord {
    /// Sessions that sent this artifact outbound from this workspace.
    pub sessions: Vec<String>,
    pub artifact_id: String,
    pub workspace: String,
    pub first_seen: u64,
    pub last_seen: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationAlert {
    pub artifact_id: String,
    pub workspace: String,
    /// All sessions involved, including the triggering one.
    pub sessions: Vec<String>,
    pub message: String,
}

pub struct CorrelationStore {
    db: Db,
}

impl CorrelationStore {
    pub fn open(dir: &std::path::Path) -> sled::Result<Self> {
        let db = sled::open(dir)?;
        Ok(Self { db })
    }

    pub fn open_default() -> sled::Result<Self> {
        Self::open(&default_path())
    }

    /// Record an outbound send of `artifact_id` from `workspace` by `session_id`.
    ///
    /// Returns `Some(CorrelationAlert)` if a *different* session already sent
    /// the same artifact from the same workspace.
    pub fn record_outbound(
        &self,
        workspace: &str,
        session_id: &str,
        artifact_id: &str,
    ) -> sled::Result<Option<CorrelationAlert>> {
        let key = format!("{workspace}:{artifact_id}");
        let now = now_secs();

        // fetch_and_update returns the OLD value; we read back the new one explicitly.
        self.db.fetch_and_update(key.as_bytes(), |old| {
            let mut rec: CorrelationRecord = old
                .and_then(|b| serde_json::from_slice(b).ok())
                .unwrap_or_else(|| CorrelationRecord {
                    sessions: vec![],
                    artifact_id: artifact_id.to_string(),
                    workspace: workspace.to_string(),
                    first_seen: now,
                    last_seen: now,
                });
            rec.last_seen = now;
            if !rec.sessions.contains(&session_id.to_string()) {
                rec.sessions.push(session_id.to_string());
            }
            Some(serde_json::to_vec(&rec).unwrap_or_default())
        })?;

        // Read back the *new* value to check for multi-session correlation.
        let rec: CorrelationRecord = match self.db.get(key.as_bytes())? {
            Some(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|_| CorrelationRecord {
                sessions: vec![session_id.to_string()],
                artifact_id: artifact_id.to_string(),
                workspace: workspace.to_string(),
                first_seen: now,
                last_seen: now,
            }),
            None => return Ok(None),
        };

        if rec.sessions.len() >= 2 && rec.sessions.iter().any(|s| s != session_id) {
            return Ok(Some(CorrelationAlert {
                artifact_id: artifact_id.to_string(),
                workspace: workspace.to_string(),
                sessions: rec.sessions.clone(),
                message: format!(
                    "MULTI-AGENT EXFIL: artifact '{}' sent outbound from workspace '{}' by {} independent sessions: {}",
                    artifact_id,
                    workspace,
                    rec.sessions.len(),
                    rec.sessions.join(", ")
                ),
            }));
        }

        Ok(None)
    }

    /// Return all records that have been seen by 2+ sessions (active alerts).
    pub fn active_alerts(&self) -> sled::Result<Vec<CorrelationAlert>> {
        let mut alerts = Vec::new();
        for item in self.db.iter() {
            let (_, v) = item?;
            if let Ok(rec) = serde_json::from_slice::<CorrelationRecord>(&v) {
                if rec.sessions.len() >= 2 {
                    alerts.push(CorrelationAlert {
                        artifact_id: rec.artifact_id.clone(),
                        workspace: rec.workspace.clone(),
                        sessions: rec.sessions.clone(),
                        message: format!(
                            "MULTI-AGENT EXFIL: '{}' in '{}' by sessions: {}",
                            rec.artifact_id,
                            rec.workspace,
                            rec.sessions.join(", ")
                        ),
                    });
                }
            }
        }
        Ok(alerts)
    }

    /// Prune records older than `max_age_secs`.
    pub fn gc(&self, max_age_secs: u64) -> sled::Result<usize> {
        let now = now_secs();
        let mut pruned = 0usize;
        let mut to_delete = Vec::new();
        for item in self.db.iter() {
            let (k, v) = item?;
            if let Ok(rec) = serde_json::from_slice::<CorrelationRecord>(&v) {
                if now.saturating_sub(rec.last_seen) > max_age_secs {
                    to_delete.push(k);
                }
            }
        }
        for k in to_delete {
            self.db.remove(k)?;
            pruned += 1;
        }
        Ok(pruned)
    }
}

pub fn default_path() -> PathBuf {
    crate::paths::state_path("correlation.sled")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_store() -> (CorrelationStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = CorrelationStore::open(dir.path()).unwrap();
        (store, dir)
    }

    #[test]
    fn no_alert_single_session() {
        let (store, _dir) = tmp_store();
        let alert = store
            .record_outbound("/workspace/proj", "session-A", "sha256:abc123")
            .unwrap();
        assert!(alert.is_none(), "single session should not alert");
    }

    #[test]
    fn alert_on_second_session_same_artifact() {
        let (store, _dir) = tmp_store();
        store
            .record_outbound("/workspace/proj", "session-A", "sha256:deadbeef")
            .unwrap();
        let alert = store
            .record_outbound("/workspace/proj", "session-B", "sha256:deadbeef")
            .unwrap();
        assert!(alert.is_some(), "second session should trigger alert");
        let a = alert.unwrap();
        assert_eq!(a.artifact_id, "sha256:deadbeef");
        assert!(a.sessions.contains(&"session-A".to_string()));
        assert!(a.sessions.contains(&"session-B".to_string()));
    }

    #[test]
    fn no_alert_different_workspace() {
        let (store, _dir) = tmp_store();
        store
            .record_outbound("/workspace/proj-A", "session-A", "sha256:deadbeef")
            .unwrap();
        let alert = store
            .record_outbound("/workspace/proj-B", "session-B", "sha256:deadbeef")
            .unwrap();
        assert!(alert.is_none(), "different workspace should not correlate");
    }

    #[test]
    fn same_session_no_duplicate_alert() {
        let (store, _dir) = tmp_store();
        store
            .record_outbound("/workspace/proj", "session-A", "sha256:abc")
            .unwrap();
        let alert = store
            .record_outbound("/workspace/proj", "session-A", "sha256:abc")
            .unwrap();
        assert!(alert.is_none(), "same session re-sending should not alert");
    }

    #[test]
    fn active_alerts_returns_multi_session_records() {
        let (store, _dir) = tmp_store();
        store
            .record_outbound("/ws", "s1", "art-X")
            .unwrap();
        store
            .record_outbound("/ws", "s2", "art-X")
            .unwrap();
        let alerts = store.active_alerts().unwrap();
        assert!(!alerts.is_empty());
        assert!(alerts.iter().any(|a| a.artifact_id == "art-X"));
    }

    #[test]
    fn gc_removes_old_records() {
        let (store, _dir) = tmp_store();
        store
            .record_outbound("/ws", "s1", "old-art")
            .unwrap();
        // Force last_seen to 0 by writing directly
        let key = "/ws:old-art";
        let rec = CorrelationRecord {
            sessions: vec!["s1".to_string()],
            artifact_id: "old-art".to_string(),
            workspace: "/ws".to_string(),
            first_seen: 0,
            last_seen: 0,
        };
        store
            .db
            .insert(key.as_bytes(), serde_json::to_vec(&rec).unwrap())
            .unwrap();
        let pruned = store.gc(60).unwrap();
        assert!(pruned >= 1);
    }
}
