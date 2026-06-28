//! Local session state store.
//!
//! The arbiter needs memory, but not raw chat logs forever. This module stores
//! compact structured state per agent session: intent, grants, and notable
//! actions. JSON-on-disk is enough for v1 and keeps the format inspectable.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    pub session_id: String,
    pub created_at: String,
    pub current_task: String,
    pub grants: Grants,
    pub events: Vec<SessionEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Grants {
    pub repo_read: bool,
    pub repo_write: bool,
    pub env_read: bool,
    pub outbound_network: bool,
    pub config_write: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEvent {
    pub ts: String,
    pub kind: EventKind,
    pub decision: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventKind {
    UserIntent { summary: String },
    FileRead { path: String },
    FileWrite { path: String },
    Command { command: String },
    OutboundSend { label: String },
    GrantChanged { name: String, value: bool },
}

pub fn default_root() -> PathBuf {
    if cfg!(target_os = "windows") {
        if let Ok(home) = std::env::var("USERPROFILE") {
            return PathBuf::from(home).join(".carapace").join("sessions");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".carapace").join("sessions");
    }
    PathBuf::from("sessions")
}

pub fn new(task: &str) -> SessionState {
    let session_id = format!(
        "sess-{}",
        time::OffsetDateTime::now_utc().unix_timestamp_nanos()
    );
    SessionState {
        session_id,
        created_at: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "?".to_string()),
        current_task: task.to_string(),
        grants: Grants::default(),
        events: vec![SessionEvent {
            ts: time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| "?".to_string()),
            kind: EventKind::UserIntent {
                summary: task.to_string(),
            },
            decision: None,
        }],
    }
}

pub fn session_path(root: &Path, id: &str) -> PathBuf {
    root.join(format!("{id}.json"))
}

pub fn save(root: &Path, session: &SessionState) -> anyhow::Result<()> {
    if !root.exists() {
        std::fs::create_dir_all(root)?;
    }
    let path = session_path(root, &session.session_id);
    std::fs::write(path, serde_json::to_string_pretty(session)?)?;
    Ok(())
}

pub fn load(root: &Path, id: &str) -> anyhow::Result<SessionState> {
    let path = session_path(root, id);
    let raw = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw)?)
}

pub fn append_event(session: &mut SessionState, kind: EventKind, decision: Option<String>) {
    session.events.push(SessionEvent {
        ts: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "?".to_string()),
        kind,
        decision,
    });
}

pub fn set_grant(session: &mut SessionState, name: &str, value: bool) {
    match name {
        "repo_read" => session.grants.repo_read = value,
        "repo_write" => session.grants.repo_write = value,
        "env_read" => session.grants.env_read = value,
        "outbound_network" => session.grants.outbound_network = value,
        "config_write" => session.grants.config_write = value,
        _ => {}
    }
    append_event(
        session,
        EventKind::GrantChanged {
            name: name.to_string(),
            value,
        },
        None,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_session_has_intent_event() {
        let s = new("fix npm build");
        assert_eq!(s.current_task, "fix npm build");
        assert_eq!(s.events.len(), 1);
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = std::env::temp_dir().join(format!("carapace-sessions-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = new("setup env");
        save(&dir, &s).unwrap();
        let loaded = load(&dir, &s.session_id).unwrap();
        assert_eq!(loaded.session_id, s.session_id);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
