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
    pub enforcement_mode: EnforcementMode,
    pub recent_decisions: Vec<DecisionRecord>,
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
    CorrectiveInstruction { message: String },
}

/// How the arbiter reacts to a risky action.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum EnforcementMode {
    /// Block dangerous actions outright.
    #[default]
    Enforce,
    /// Intercept, send a corrective instruction back to the model, let it try again.
    Correct,
    /// Allow everything but log/forensics it.
    Observe,
    /// Passthrough, no interception at all.
    Off,
}

/// Compact record of a recent arbiter decision, so context survives across steps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionRecord {
    pub ts: String,
    pub action_kind: String,
    pub target: String,
    pub decision: String,
    pub enforcement_mode: EnforcementMode,
}

pub fn default_root() -> PathBuf {
    crate::paths::state_dir("sessions")
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
        enforcement_mode: EnforcementMode::default(),
        recent_decisions: Vec::new(),
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

pub fn append_decision(session: &mut SessionState, action_kind: &str, target: &str, decision: &str) {
    let record = DecisionRecord {
        ts: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "?".to_string()),
        action_kind: action_kind.to_string(),
        target: target.to_string(),
        decision: decision.to_string(),
        enforcement_mode: session.enforcement_mode,
    };
    session.recent_decisions.push(record);
    if session.recent_decisions.len() > 20 {
        session.recent_decisions.remove(0);
    }
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

    #[test]
    fn enforcement_mode_defaults_to_enforce() {
        let s = new("test");
        assert_eq!(s.enforcement_mode, EnforcementMode::Enforce);
    }

    #[test]
    fn decision_records_are_kept() {
        let mut s = new("test");
        append_decision(&mut s, "file-read", ".env", "Ask");
        append_decision(&mut s, "command", "npm test", "Allow");
        assert_eq!(s.recent_decisions.len(), 2);
    }

    #[test]
    fn decision_records_capped_at_20() {
        let mut s = new("test");
        for i in 0..25 {
            append_decision(&mut s, "command", &format!("cmd{i}"), "Allow");
        }
        assert_eq!(s.recent_decisions.len(), 20);
    }
}
