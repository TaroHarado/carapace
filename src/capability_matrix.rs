//! Capability mediation matrix — Layer 1 of the SafeRouter defense model.
//!
//! Combines three axes — [`Source`] × [`Capability`] × [`AssetClass`] — into a
//! deterministic policy decision. This is *cleaner* than the legacy
//! `policy::evaluate` (which only knows `ActionKind` + `ProviderRisk`), and
//! replaces the original cosmetic "scan the literal text" approach.
//!
//! Rows below are evaluated in order, first hit wins. Higher index = more
//! specific. If no row matches, the matrix falls through to default-permit
//! for read/write on Project/Internal assets (the only auto-approve cases).
//!
//! This is separate from `inspect.rs` (text-rule detection) and from
//! `session_graph.rs` (chain detection). The current proxy should consult all
//! three and merge the verdicts. Eventually this matrix becomes the primary
//! decision oracle; the rule scanner becomes a taint source feeding this.

use serde::{Deserialize, Serialize};

use crate::asset::{AssetClass, Capability, Source};

/// Decision returned by the matrix. Aligns with `policy::Decision` plus an
/// `AllowWithAudit` middle tier for "let it through but record".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MatrixDecision {
    Allow,
    AllowWithAudit,
    Ask,
    Quarantine,
    Block,
}

impl MatrixDecision {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::AllowWithAudit => "allow:audit",
            Self::Ask => "ask",
            Self::Quarantine => "quarantine",
            Self::Block => "block",
        }
    }
}

/// Input row to the matrix — one event being evaluated.
#[derive(Debug, Clone)]
pub struct MatrixInput {
    pub source: Source,
    pub capability: Capability,
    pub asset: AssetClass,
    /// True if the artifact was already tainted upstream (provenance.rs).
    pub tainted: bool,
}

/// Evaluate one event against the matrix.
pub fn evaluate(input: &MatrixInput) -> MatrixDecision {
    use AssetClass::*;
    use Capability::*;

    // ----- Layer 1a: HARD DENY regardless of source ------------------------
    //
    // These asset classes are never auto-approved. The matrix doesn't even
    // need a source — these zones are off-limits to agents in any context
    // that wasn't an explicit human-origin access.
    if input.asset.is_hard_deny_for_auto() && input.source != Source::User {
        return MatrixDecision::Block;
    }
    // Even from User, executing against a hard-deny asset class makes no
    // sense semantically and is always blocked.
    if input.asset.is_hard_deny_for_auto() && input.capability == Capability::Execute {
        return MatrixDecision::Block;
    }

    // Keychain + WalletData + CloudMetadata block even on user requests with
    // audit-only carve-outs (we still want the fact of access recorded).
    if matches!(input.asset, Keychain | WalletData | CloudMetadata) && input.source == Source::User {
        return MatrixDecision::AllowWithAudit;
    }

    // BrowserData only user-direct + audit; never auto from provider/markup.
    if input.asset == BrowserData && input.source == Source::User {
        return MatrixDecision::AllowWithAudit;
    }

    // ----- Layer 1b: Source × Capability matrix ----------------------------
    //
    // The provider can never directly induce execute / shell / download /
    // network-post. Even with a UI assist ("approve this"), we route to Ask
    // for human to review, never to Allow.
    if matches!(input.source, Source::Provider | Source::Web | Source::Mcp | Source::Unknown) {
        if matches!(input.capability, Execute | BrowserDownload | NetworkPost | McpInvoke) {
            return MatrixDecision::Block;
        }
        if matches!(input.capability, NetworkFetch | ClipboardRead | UiAutomation) {
            return MatrixDecision::Ask;
        }
        // WriteFile from provider-output into Temp/Executable/AiClientConfig =
        // quarantine (download-without-execute boundary).
        if input.capability == WriteFile
            && matches!(input.asset, Temp | Executable | AiClientConfig | System)
        {
            return MatrixDecision::Quarantine;
        }
        // WriteFile from provider-output into Project = treat as Ask (provider
        // editing user code is the Claude Code / Cursor pattern, but it must
        // never silently create new files outside CWD).
        if input.capability == WriteFile && input.asset == Project {
            return MatrixDecision::Ask;
        }
        // ReadFile from provider-output on Credential/Keychain = Block (already
        // handled by hard-deny above but be explicit for credential-only class).
        if input.capability == ReadFile && input.asset == Credential {
            return MatrixDecision::Block;
        }
    }

    // ----- Layer 1c: Taint override ---------------------------------------
    //
    // If the artifact is tainted, the action is at minimum Ask regardless of
    // what the literal content looks like. Tainted Execute = Block (taint-leap
    // pattern is the most dangerous).
    if input.tainted {
        if matches!(input.capability, Execute | NetworkPost | BrowserDownload | McpInvoke) {
            return MatrixDecision::Block;
        }
        return MatrixDecision::Ask;
    }

    // ----- Layer 1d: Ask-only asset tiers ----------------------------------
    //
    // System, AI-client-config, Executable, Unknown — never auto-approved,
    // regardless of source. Even user requests on these paths warrant a
    // sanity check (or at least an audit log entry).
    if input.asset.is_ask_only() && input.source != Source::User {
        return MatrixDecision::Ask;
    }
    if input.asset.is_ask_only() && input.source == Source::User {
        // User explicit on a sensitive path → audit.
        return MatrixDecision::AllowWithAudit;
    }

    // ----- Layer 1e: Default-permit for low-risk project I/O --------------
    //
    // ReadFile / WriteFile on Project from User OR Internal are the only
    // true Allow cases.
    if matches!(input.source, Source::User | Source::Internal)
        && matches!(input.capability, ReadFile | WriteFile)
        && input.asset == Project
    {
        return MatrixDecision::Allow;
    }

    // ReadFile on Log/Config from Internal/User → allow with audit.
    if matches!(input.source, Source::User | Source::Internal)
        && input.capability == ReadFile
        && matches!(input.asset, Log | Config)
    {
        return MatrixDecision::AllowWithAudit;
    }

    // ReadFile on External (URL fetch from user) → allow (browser navigation
    // is normal). NetworkPost from User on External → Ask.
    if input.source == Source::User
        && input.capability == NetworkFetch
        && input.asset == External
    {
        return MatrixDecision::Allow;
    }
    if input.source == Source::User && input.capability == NetworkPost && input.asset == External {
        return MatrixDecision::Ask;
    }

    // Default-deny anything we don't recognize. Fail-closed is safer than
    // fail-open for an agent firewall.
    MatrixDecision::Ask
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inp(source: Source, cap: Capability, asset: AssetClass, tainted: bool) -> MatrixInput {
        MatrixInput { source, capability: cap, asset, tainted }
    }

    #[test]
    fn provider_execute_always_blocks() {
        let d = evaluate(&inp(Source::Provider, Capability::Execute, AssetClass::Project, false));
        assert_eq!(d, MatrixDecision::Block);
    }

    #[test]
    fn user_execute_blocks_on_unsafe_asset() {
        let d = evaluate(&inp(Source::User, Capability::Execute, AssetClass::Credential, false));
        assert_eq!(d, MatrixDecision::Block);
    }

    #[test]
    fn user_direct_project_io_allowed() {
        assert_eq!(
            evaluate(&inp(Source::User, Capability::ReadFile, AssetClass::Project, false)),
            MatrixDecision::Allow
        );
        assert_eq!(
            evaluate(&inp(Source::User, Capability::WriteFile, AssetClass::Project, false)),
            MatrixDecision::Allow
        );
    }

    #[test]
    fn provider_read_credential_blocks() {
        let d = evaluate(&inp(Source::Provider, Capability::ReadFile, AssetClass::Credential, false));
        assert_eq!(d, MatrixDecision::Block);
    }

    #[test]
    fn provider_write_to_temp_quarantines() {
        let d = evaluate(&inp(Source::Provider, Capability::WriteFile, AssetClass::Temp, false));
        assert_eq!(d, MatrixDecision::Quarantine);
    }

    #[test]
    fn provider_write_to_project_asks() {
        let d = evaluate(&inp(Source::Provider, Capability::WriteFile, AssetClass::Project, false));
        assert_eq!(d, MatrixDecision::Ask);
    }

    #[test]
    fn tainted_execute_blocks() {
        let d = evaluate(&inp(Source::Internal, Capability::Execute, AssetClass::Executable, true));
        assert_eq!(d, MatrixDecision::Block);
    }

    #[test]
    fn tainted_readfile_asks() {
        let d = evaluate(&inp(Source::Internal, Capability::ReadFile, AssetClass::Project, true));
        assert_eq!(d, MatrixDecision::Ask);
    }

    #[test]
    fn wallet_user_access_audits() {
        let d = evaluate(&inp(Source::User, Capability::ReadFile, AssetClass::WalletData, false));
        assert_eq!(d, MatrixDecision::AllowWithAudit);
    }

    #[test]
    fn keychain_user_access_audits() {
        let d = evaluate(&inp(Source::User, Capability::ReadFile, AssetClass::Keychain, false));
        assert_eq!(d, MatrixDecision::AllowWithAudit);
    }

    #[test]
    fn system_auto_from_internal_asks() {
        let d = evaluate(&inp(Source::Internal, Capability::ReadFile, AssetClass::System, false));
        assert_eq!(d, MatrixDecision::Ask);
    }

    #[test]
    fn unknown_asset_user_audits() {
        let d = evaluate(&inp(Source::User, Capability::ReadFile, AssetClass::Unknown, false));
        assert_eq!(d, MatrixDecision::AllowWithAudit);
    }

    #[test]
    fn cloud_metadata_provider_blocks() {
        let d = evaluate(&inp(Source::Provider, Capability::NetworkFetch, AssetClass::CloudMetadata, false));
        assert_eq!(d, MatrixDecision::Block);
    }

    #[test]
    fn user_url_fetch_allowed() {
        let d = evaluate(&inp(Source::User, Capability::NetworkFetch, AssetClass::External, false));
        assert_eq!(d, MatrixDecision::Allow);
    }

    #[test]
    fn user_network_post_asks() {
        let d = evaluate(&inp(Source::User, Capability::NetworkPost, AssetClass::External, false));
        assert_eq!(d, MatrixDecision::Ask);
    }

    #[test]
    fn provider_network_post_blocks() {
        let d = evaluate(&inp(Source::Provider, Capability::NetworkPost, AssetClass::External, false));
        assert_eq!(d, MatrixDecision::Block);
    }

    #[test]
    fn browser_data_from_provider_blocks() {
        let d = evaluate(&inp(Source::Provider, Capability::ReadFile, AssetClass::BrowserData, false));
        assert_eq!(d, MatrixDecision::Block);
    }

    #[test]
    fn browser_data_from_user_audits() {
        let d = evaluate(&inp(Source::User, Capability::ReadFile, AssetClass::BrowserData, false));
        assert_eq!(d, MatrixDecision::AllowWithAudit);
    }

    #[test]
    fn provider_browser_navigate_asks() {
        let d = evaluate(&inp(Source::Provider, Capability::BrowserNavigate, AssetClass::External, false));
        assert_eq!(d, MatrixDecision::Ask);
    }

    #[test]
    fn fail_closed_on_unrecognized_combination() {
        // Combination we don't explicitly handle should never be Allow.
        let d = evaluate(&inp(Source::Unknown, Capability::UiAutomation, AssetClass::Unknown, false));
        assert_ne!(d, MatrixDecision::Allow);
    }
}