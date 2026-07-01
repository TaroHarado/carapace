//! Remote tool-call policy — allowlist / denylist for tool names seen by the
//! proxy.
//!
//! Historical note: this module started as an MCP-only gate. The newer
//! `SR_TOOL_*` env vars are the preferred names; legacy `SR_MCP_*` aliases are
//! still supported for compatibility. In the current proxy path, the policy is
//! applied to reassembled remote `tool_use` events generically, not just
//! JSON-RPC MCP `tools/call` frames.
//!
//! ## Policy resolution order
//!
//! 1. If the tool name is in `deny` → Block (highest priority).
//! 2. If `allow` is non-empty and the tool name is NOT in `allow` → Block.
//! 3. Otherwise → Allow.
//!
//! ## Environment-variable configuration (no config file required)
//!
//! ```text
//! SR_TOOL_ALLOW=Bash,Read,Write         # preferred allowlist name
//! SR_TOOL_DENY=exec,shell,eval          # preferred denylist name
//! SR_TOOL_POLICY=strict                 # preferred mode name
//!                                       # permissive (default) = allow unless denied
//! SR_MCP_ALLOW=...                      # legacy alias
//! SR_MCP_DENY=...                       # legacy alias
//! SR_MCP_POLICY=...                     # legacy alias
//! ```
//!
//! ## File-based configuration
//!
//! `SR_TOOL_POLICY_FILE=/path/to/mcp-policy.json` loads:
//! Legacy alias: `SR_MCP_POLICY_FILE`.
//!
//! ```json
//! {
//!   "allow": ["Bash", "Read", "Write"],
//!   "deny":  ["exec", "shell"],
//!   "mode":  "strict"
//! }
//! ```

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// Policy decision for a single remote tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum McpPolicyDecision {
    Allow,
    Block,
}

impl McpPolicyDecision {
    pub fn is_block(self) -> bool {
        self == McpPolicyDecision::Block
    }
}

/// Enforcement mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum McpPolicyMode {
    /// Allow everything not explicitly denied (default).
    #[default]
    Permissive,
    /// Deny everything not explicitly allowed.
    Strict,
}

/// The compiled policy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct McpPolicy {
    /// Tools that are explicitly allowed (used in Strict mode or as override).
    #[serde(default)]
    pub allow: HashSet<String>,
    /// Tools that are always blocked.
    #[serde(default)]
    pub deny: HashSet<String>,
    /// Enforcement mode.
    #[serde(default)]
    pub mode: McpPolicyMode,
}

impl McpPolicy {
    /// Build a policy from environment variables.
    ///
    /// Preferred env names: `SR_TOOL_ALLOW`, `SR_TOOL_DENY`,
    /// `SR_TOOL_POLICY`, `SR_TOOL_POLICY_FILE`.
    /// Legacy aliases: `SR_MCP_ALLOW`, `SR_MCP_DENY`, `SR_MCP_POLICY`,
    /// `SR_MCP_POLICY_FILE`.
    pub fn from_env() -> Self {
        // Check for file-based config first.
        if let Some(path) = env_first(&["SR_TOOL_POLICY_FILE", "SR_MCP_POLICY_FILE"]) {
            if let Ok(raw) = std::fs::read_to_string(&path) {
                if let Ok(p) = serde_json::from_str::<McpPolicy>(&raw) {
                    tracing::info!(path, "mcp-policy: loaded from file");
                    return p;
                }
            }
        }

        let allow = parse_csv_env_multi(&["SR_TOOL_ALLOW", "SR_MCP_ALLOW"]);
        let deny = parse_csv_env_multi(&["SR_TOOL_DENY", "SR_MCP_DENY"]);
        let mode = match env_first(&["SR_TOOL_POLICY", "SR_MCP_POLICY"])
            .as_deref()
            .unwrap_or("permissive") {
            "strict" => McpPolicyMode::Strict,
            _ => McpPolicyMode::Permissive,
        };
        McpPolicy { allow, deny, mode }
    }

    /// Returns `true` when no policy has been configured (all defaults).
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty() && self.mode == McpPolicyMode::Permissive
    }

    /// Evaluate whether `tool_name` is permitted.
    pub fn evaluate(&self, tool_name: &str) -> McpPolicyDecision {
        // Deny-list takes highest priority regardless of mode.
        if self.deny.contains(tool_name) {
            tracing::warn!(tool_name, "mcp-policy: tool blocked by deny-list");
            return McpPolicyDecision::Block;
        }
        // In strict mode, tool must be in the allow-list.
        if self.mode == McpPolicyMode::Strict && !self.allow.is_empty() && !self.allow.contains(tool_name) {
            tracing::warn!(tool_name, "mcp-policy: tool blocked (not in allow-list, strict mode)");
            return McpPolicyDecision::Block;
        }
        McpPolicyDecision::Allow
    }
}

fn env_first(vars: &[&str]) -> Option<String> {
    vars.iter().find_map(|var| std::env::var(var).ok())
}

fn parse_csv_env_multi(vars: &[&str]) -> HashSet<String> {
    env_first(vars)
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Convenience: build the global policy once and return it. Returns `None`
/// when no relevant env vars are set (avoids allocating an empty policy on
/// every request).
pub fn global_policy() -> Option<McpPolicy> {
    let p = McpPolicy::from_env();
    if p.is_empty() { None } else { Some(p) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    fn policy(allow: &[&str], deny: &[&str], mode: McpPolicyMode) -> McpPolicy {
        McpPolicy {
            allow: allow.iter().map(|s| s.to_string()).collect(),
            deny: deny.iter().map(|s| s.to_string()).collect(),
            mode,
        }
    }

    #[test]
    fn deny_list_blocks_regardless_of_mode() {
        let p = policy(&[], &["exec", "shell"], McpPolicyMode::Permissive);
        assert_eq!(p.evaluate("exec"), McpPolicyDecision::Block);
        assert_eq!(p.evaluate("shell"), McpPolicyDecision::Block);
        assert_eq!(p.evaluate("Read"), McpPolicyDecision::Allow);
    }

    #[test]
    fn strict_mode_blocks_unlisted_tool() {
        let p = policy(&["Bash", "Read"], &[], McpPolicyMode::Strict);
        assert_eq!(p.evaluate("Bash"), McpPolicyDecision::Allow);
        assert_eq!(p.evaluate("Read"), McpPolicyDecision::Allow);
        assert_eq!(p.evaluate("WebFetch"), McpPolicyDecision::Block);
    }

    #[test]
    fn permissive_mode_allows_unlisted_tool() {
        let p = policy(&["Bash"], &[], McpPolicyMode::Permissive);
        // Allow-list is ignored in permissive mode (only deny-list matters).
        assert_eq!(p.evaluate("WebFetch"), McpPolicyDecision::Allow);
    }

    #[test]
    fn deny_beats_allow_in_strict_mode() {
        let p = policy(&["Bash", "exec"], &["exec"], McpPolicyMode::Strict);
        // Even though "exec" is in allow, deny wins.
        assert_eq!(p.evaluate("exec"), McpPolicyDecision::Block);
        assert_eq!(p.evaluate("Bash"), McpPolicyDecision::Allow);
    }

    #[test]
    fn empty_policy_is_empty() {
        let p = McpPolicy::default();
        assert!(p.is_empty());
    }

    #[test]
    fn empty_allow_list_in_strict_mode_allows_everything() {
        // If allow is empty in strict mode, nothing to compare against →
        // fall through to Allow (avoids foot-gun of locking out all tools).
        let p = policy(&[], &[], McpPolicyMode::Strict);
        assert_eq!(p.evaluate("Bash"), McpPolicyDecision::Allow);
    }

    #[test]
    fn from_env_parses_allow_deny_vars() {
        let _guard = env_lock();
        std::env::remove_var("SR_TOOL_POLICY_FILE");
        std::env::remove_var("SR_MCP_POLICY_FILE");
        std::env::set_var("SR_TOOL_ALLOW", "Bash,Read");
        std::env::set_var("SR_TOOL_DENY", "exec");
        std::env::set_var("SR_TOOL_POLICY", "strict");
        let p = McpPolicy::from_env();
        std::env::remove_var("SR_TOOL_ALLOW");
        std::env::remove_var("SR_TOOL_DENY");
        std::env::remove_var("SR_TOOL_POLICY");
        assert!(p.allow.contains("Bash"));
        assert!(p.deny.contains("exec"));
        assert_eq!(p.mode, McpPolicyMode::Strict);
    }

    #[test]
    fn from_env_legacy_aliases_still_work() {
        let _guard = env_lock();
        std::env::remove_var("SR_TOOL_POLICY_FILE");
        std::env::remove_var("SR_MCP_POLICY_FILE");
        std::env::set_var("SR_MCP_ALLOW", "Bash,Read");
        std::env::set_var("SR_MCP_DENY", "exec");
        std::env::set_var("SR_MCP_POLICY", "strict");
        let p = McpPolicy::from_env();
        std::env::remove_var("SR_MCP_ALLOW");
        std::env::remove_var("SR_MCP_DENY");
        std::env::remove_var("SR_MCP_POLICY");
        assert!(p.allow.contains("Bash"));
        assert!(p.deny.contains("exec"));
        assert_eq!(p.mode, McpPolicyMode::Strict);
    }

    #[test]
    fn preferred_tool_envs_override_legacy_mcp_envs() {
        let _guard = env_lock();
        std::env::remove_var("SR_TOOL_POLICY_FILE");
        std::env::remove_var("SR_MCP_POLICY_FILE");
        std::env::set_var("SR_TOOL_ALLOW", "Read");
        std::env::set_var("SR_MCP_ALLOW", "Bash");
        let p = McpPolicy::from_env();
        std::env::remove_var("SR_TOOL_ALLOW");
        std::env::remove_var("SR_MCP_ALLOW");
        assert!(p.allow.contains("Read"));
        assert!(!p.allow.contains("Bash"));
    }

    #[test]
    fn from_env_empty_vars_gives_empty_policy() {
        let _guard = env_lock();
        std::env::remove_var("SR_TOOL_ALLOW");
        std::env::remove_var("SR_TOOL_DENY");
        std::env::remove_var("SR_TOOL_POLICY");
        std::env::remove_var("SR_TOOL_POLICY_FILE");
        std::env::remove_var("SR_MCP_ALLOW");
        std::env::remove_var("SR_MCP_DENY");
        std::env::remove_var("SR_MCP_POLICY");
        std::env::remove_var("SR_MCP_POLICY_FILE");
        let p = McpPolicy::from_env();
        assert!(p.is_empty());
    }

    #[test]
    fn global_policy_returns_none_when_unconfigured() {
        let _guard = env_lock();
        std::env::remove_var("SR_TOOL_ALLOW");
        std::env::remove_var("SR_TOOL_DENY");
        std::env::remove_var("SR_TOOL_POLICY");
        std::env::remove_var("SR_TOOL_POLICY_FILE");
        std::env::remove_var("SR_MCP_ALLOW");
        std::env::remove_var("SR_MCP_DENY");
        std::env::remove_var("SR_MCP_POLICY");
        std::env::remove_var("SR_MCP_POLICY_FILE");
        assert!(global_policy().is_none());
    }

    #[test]
    fn global_policy_returns_some_when_configured() {
        let _guard = env_lock();
        std::env::remove_var("SR_TOOL_POLICY_FILE");
        std::env::remove_var("SR_MCP_POLICY_FILE");
        std::env::set_var("SR_TOOL_DENY", "exec");
        let p = global_policy();
        std::env::remove_var("SR_TOOL_DENY");
        assert!(p.is_some());
    }
}
