//! Asset classifier — maps a path/URL/object to an asset class.
//!
//! Layer 4 of the SafeRouter model: hard policy boundaries per asset class.
//!
//! Goal: not regex-detect "looks malicious", but classify the *target* of a
//! tool call into one of {Project, System, Credential, BrowserData, WalletData,
//! Keychain, Executable, Config, Log, Temp, External, Unknown} and feed that
//! into the policy matrix. Unlike text-rule matching, asset class is a
//! property of the *target*, not the *content*, so it survives obfuscation:
//! a `cat` of wallet keystore doesn't need to match a regex — the path itself
//! is in the WalletData class.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AssetClass {
    /// Source-controlled files inside the user's CWD / project root.
    Project,
    /// System files outside CWD: /etc, /usr, /bin, C:\Windows, C:\Program Files.
    System,
    /// SSH keys, AWS/Kube/GCloud/Terraform/Docker creds, .env, .netrc, .pypirc.
    Credential,
    /// Browser profile storage: Chrome/Firefox/Safari cookies, login data,
    /// Local Storage / leveldb for Discord/Slack/Telegram, 1Password vault.
    BrowserData,
    /// Crypto wallet keystores: solana/id.json, .ethereum/keystore, .electrum,
    /// MetaMask extension storage, Monero, wallet.dat.
    WalletData,
    /// OS keychain: macOS keychain, Windows Credential Manager, GPG secret keys,
    /// Kerberos tickets, ssh-agent identities, NetworkManager WiFi profiles.
    Keychain,
    /// Executable artifacts: .exe, .dll, .so, .dylib, .sh, .ps1, .py with +x,
    /// binaries under ~/bin, /usr/local/bin, %PATH%.
    Executable,
    /// AI client config: .claude/, .cursor/, .mcp.json, CLAUDE.md, AGENTS.md,
    /// .aider, opencode.json, hooks (PreToolUse, PostToolUse).
    AiClientConfig,
    /// Generic config: .bashrc, .zshrc, .gitconfig, .npmrc, systemd units.
    Config,
    /// System and app logs: /var/log, journal, .bash_history, .python_history.
    Log,
    /// Temp directories: /tmp, /var/tmp, %TEMP%, $TMPDIR.
    Temp,
    /// External URL / network resource.
    External,
    /// Cloud metadata IMDS endpoints.
    CloudMetadata,
    /// Could not classify; treat as Unknown = high caution.
    Unknown,
}

impl AssetClass {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::System => "system",
            Self::Credential => "credential",
            Self::BrowserData => "browser-data",
            Self::WalletData => "wallet-data",
            Self::Keychain => "keychain",
            Self::Executable => "executable",
            Self::AiClientConfig => "ai-client-config",
            Self::Config => "config",
            Self::Log => "log",
            Self::Temp => "temp",
            Self::External => "external",
            Self::CloudMetadata => "cloud-metadata",
            Self::Unknown => "unknown",
        }
    }

    /// True if this class is in the "never auto-approve" tier.
    pub fn is_hard_deny_for_auto(&self) -> bool {
        matches!(
            self,
            Self::Credential
                | Self::BrowserData
                | Self::WalletData
                | Self::Keychain
                | Self::CloudMetadata
        )
    }

    /// True if this class is "ask-only" (not hard-deny, but never auto-approve).
    pub fn is_ask_only(&self) -> bool {
        matches!(
            self,
            Self::System | Self::AiClientConfig | Self::Executable | Self::Unknown
        )
    }
}

/// Classify a target string (path or URL) into an [`AssetClass`].
///
/// Heuristics ordered from most-specific to most-generic. First hit wins.
/// All string comparisons are case-insensitive.
pub fn classify(target: &str) -> AssetClass {
    let lower = target.to_lowercase();
    let t = lower.as_str();

    // ----- 1. URLs / cloud metadata --------------------------------------

    if t.starts_with("http://") || t.starts_with("https://") {
        if t.contains("169.254.169.254")
            || t.contains("fd00:ec2::254")
            || t.contains("metadata.google.internal")
            || t.contains("169.254.169.254/metadata")
        {
            return AssetClass::CloudMetadata;
        }
        return AssetClass::External;
    }

    // ----- 2. Crypto wallet keystores (explicit IDs / paths) --------------

    if t.contains(".config/solana/id.json")
        || t.contains(".config/solana/")
        || t.contains(".ethereum/keystore")
        || t.contains(".local/share/io.parity/keys")
        || t.contains(".bitmonero")
        || t.contains(".monero/")
        || t.contains(".electrum/wallets")
        || t.contains("wallet.dat")
        || t.contains("ejbalbakpfchcnkbfecjbdpjpbhjidad")
        || t.contains("nkbffbiehnkfdejgbdadndhfjmoiamgp")
        || t.contains("/.eth/keystore")
    {
        return AssetClass::WalletData;
    }

    // ----- 3. Browser profile data ---------------------------------------

    if (t.contains("/chrome/") || t.contains("\\chrome\\"))
        && (t.contains("cookies") || t.contains("login data") || t.contains("local state"))
    {
        return AssetClass::BrowserData;
    }
    if t.contains("/firefox/")
        && (t.contains("logins.json")
            || t.contains("signons.sqlite")
            || t.contains("key4.db")
            || t.contains("cookies.sqlite"))
    {
        return AssetClass::BrowserData;
    }
    if (t.contains("discord") && t.contains("local storage/leveldb"))
        || (t.contains("discord") && t.contains("/cookies"))
    {
        return AssetClass::BrowserData;
    }
    if t.contains("slack")
        && (t.contains("local storage") || t.contains("storage.json"))
        || t.contains("/slack/")
    {
        return AssetClass::BrowserData;
    }
    if t.contains("1password")
        || t.contains(".opvault")
        || t.contains("com.agilebits")
        || t.contains("chrome-extension://aeblfdkhhhdcdjpifkkdgpbfmblmgjfn")
    {
        return AssetClass::BrowserData;
    }

    // ----- 4. SSH keys & cloud creds -------------------------------------

    if t.contains(".ssh/id_rsa")
        || t.contains(".ssh/id_ed25519")
        || t.contains(".ssh/id_ecdsa")
        || t.contains(".ssh/id_dsa")
        || t.contains(".ssh/identity")
        || t.contains(".aws/credentials")
        || t.contains(".aws/config")
        || t.contains(".kube/config")
        || t.contains(".docker/config.json")
        || t.contains(".config/gcloud/credentials")
        || t.contains(".config/gcloud/application_default")
        || t.contains(".config/gcloud/legacy_credentials")
        || t.contains(".terraform.d/credentials")
        || t.contains(".terraform.d/terraform.rc")
        || t.contains(".netrc")
        || t.contains(".pypirc")
        || t.contains(".npmrc")
        || t.contains("/var/run/secrets/kubernetes.io/serviceaccount/")
    {
        return AssetClass::Credential;
    }

    // ----- 5. .env variants (treat as creds) -----------------------------

    if t.ends_with("/.env")
        || t.ends_with("\\.env")
        || t.ends_with(".env")
        || t.ends_with(".env.local")
        || t.ends_with(".env.production")
        || t.ends_with(".env.development")
        || t.ends_with("/.env.example")
        || t.ends_with("/.env.sample")
        || t.ends_with("/.env.template")
    {
        // Note: .env.example etc. are NOT secrets, but the policy above treats
        // them as Ask rather than Block anyway. Classify as Credential so the
        // matrix never auto-approves any .env variant.
        return AssetClass::Credential;
    }

    // ----- 6. OS keychains / Kerberos / GPG secrets ----------------------

    if t.contains("/library/keychains/")
        || t.contains("login.keychain")
        || t.contains("com.apple.keychainaccess")
        || t.contains("/appdata/roaming/microsoft/credentials")
        || t.contains("/appdata/local/microsoft/credentials")
        || t.contains(".gnupg/secring.gpg")
        || t.contains(".gnupg/private-keys")
        || t.contains(".gnupg/private-keys-v1.d")
        || t.contains("krb5cc_")
        || t.contains("/etc/krb5.conf")
        || t.contains("/etc/krb5.keytab")
        || t.contains("networkmanager/system-connections")
    {
        return AssetClass::Keychain;
    }

    // ----- 7. AI client config (high-risk even from user) ----------------

    if t.contains("/.claude/")
        || t.contains("/.cursor/")
        || t.contains("/.mcp/")
        || t.ends_with("/.mcp.json")
        || t == ".mcp.json"
        || t.ends_with("/claude.md")
        || t == "claude.md"
        || t.ends_with("/agents.md")
        || t == "agents.md"
        || t.ends_with("/.cursorrules")
        || t == ".cursorrules"
        || t.ends_with("/.cursorignore")
        || t == ".cursorignore"
        || t.ends_with("/opencode.json")
        || t == "opencode.json"
        || t.ends_with("/.aider.conf.yml")
        || t == ".aider.conf.yml"
        || t.ends_with("/.aider.conf.toml")
        || t == ".aider.conf.toml"
        || t.ends_with("/.aider.input.history")
        || t.contains("/.continue/")
        || t.contains("pretooluse")
        || t.contains("posttooluse")
    {
        return AssetClass::AiClientConfig;
    }

    // ----- 8. REPL / shell histories (Log) -------------------------------

    if t.ends_with(".bash_history")
        || t.ends_with(".zsh_history")
        || t.ends_with(".python_history")
        || t.ends_with(".mysql_history")
        || t.ends_with(".psql_history")
        || t.ends_with(".rediscli_history")
        || t.ends_with(".lesshst")
        || t.ends_with(".viminfo")
        || t.ends_with(".node_repl_history")
    {
        return AssetClass::Log;
    }

    // ----- 9. System logs (var/log, EventLog, Library/Logs) ---------------

    if t.starts_with("/var/log/")
        || t.starts_with("/private/var/log/")
        || t.starts_with("/library/logs/")
        || t.starts_with("\\windows\\logs\\")
        || t.contains("eventlog")
    {
        return AssetClass::Log;
    }

    // ----- 10. Temp dirs (BEFORE executable check — downloaded payload) ---

    if t.starts_with("/tmp/")
        || t.starts_with("/var/tmp/")
        || t.starts_with("/private/tmp/")
        || t.starts_with("/private/var/tmp/")
        || t.starts_with("/tmp")
        || t.starts_with("/var/tmp")
        || t.starts_with("c:\\windows\\temp\\")
        || t.starts_with("c:\\windows\\temp")
        || (t.starts_with("c:\\users\\") && t.contains("\\appdata\\local\\temp\\"))
        || t.contains("/$tmpdir/")
    {
        return AssetClass::Temp;
    }

    // ----- 11. System files (absolute paths under OS roots) ---------------

    if t.starts_with("/etc/")
        || t.starts_with("/usr/")
        || t.starts_with("/bin/")
        || t.starts_with("/sbin/")
        || t.starts_with("/lib/")
        || t.starts_with("/lib64/")
        || t.starts_with("/boot/")
        || t.starts_with("/proc/")
        || t.starts_with("/sys/")
        || t.starts_with("/dev/")
        || t.starts_with("/run/")
        || t.starts_with("/srv/")
        || t.starts_with("c:\\windows\\")
        || t.starts_with("c:\\program files\\")
        || t.starts_with("c:\\program files (x86)\\")
        || t.starts_with("c:\\programdata\\")
    {
        return AssetClass::System;
    }
    // Bare home or /home — treated as system; reading $HOME listing = recon.
    if t == "~"
        || t == "$home"
        || t == "/root"
        || t == "/home"
        || (t.starts_with("/home/") && t.split('/').count() == 3)
    {
        return AssetClass::System;
    }

    // ----- 12. Shell dot-config (Config, not AiClientConfig) --------------

    if t.ends_with("/.bashrc")
        || t.ends_with("/.zshrc")
        || t.ends_with("/.profile")
        || t.ends_with("/.bash_profile")
        || t.ends_with("/.zprofile")
        || t.ends_with("/.gitconfig")
        || t.ends_with("/.config/git/config")
        || t.ends_with("/.git-credentials")
        || t.ends_with("/.config/fish/config.fish")
        || t.ends_with("/.inputrc")
        || t.ends_with("/.tmux.conf")
        || t.ends_with("/.vimrc")
    {
        return AssetClass::Config;
    }

    // ----- 13. Executable extensions / known binary paths ---------------

    if t.ends_with(".exe")
        || t.ends_with(".dll")
        || t.ends_with(".so")
        || t.ends_with(".dylib")
        || t.ends_with(".bat")
        || t.ends_with(".cmd")
        || t.ends_with(".ps1")
        || t.ends_with(".sh")
        || t.ends_with(".bash")
        || t.ends_with(".zsh")
        || t.ends_with(".command")
        || t.starts_with("/usr/local/bin/")
        || t.starts_with("/usr/bin/")
        || t.starts_with("/opt/homebrew/bin/")
        || t.starts_with("/usr/sbin/")
        || t.starts_with("/bin/")
        || t.starts_with("/sbin/")
        || t.starts_with("$home/bin/")
        || t.starts_with("~/bin/")
        || t.starts_with("/opt/")
        || t.contains(".app/contents/macos/")
    {
        return AssetClass::Executable;
    }

    // ----- 14. Absolute paths under common project roots ----------------

    if (t.starts_with("/home/") || t.starts_with("/users/"))
        && (t.contains("/projects/")
            || t.contains("/code/")
            || t.contains("/dev/")
            || t.contains("/src/")
            || t.contains("/workspace/")
            || t.contains("/repos/")
            || t.contains("/github/")
            || t.contains("/gitlab/")
            || t.contains("/debi")
            || t.contains("/carapace"))
    {
        return AssetClass::Project;
    }

    // ----- 15. Relative CWD references (./ x, x.txt) -> Project ---------

    if t.starts_with("./")
        || t.starts_with(".\\")
        || t.starts_with("../")
        || t.starts_with("..\\")
    {
        return AssetClass::Project;
    }
    // Bare filename OR relative path with no leading /, \, ~, drive letter
    // (e.g. "src/main.rs", "README.md", ".gitignore") — assume it's a CWD
    // reference. The earlier system / credential / wallet patterns already
    // caught anything dangerous.
    if !t.starts_with('/')
        && !t.starts_with('\\')
        && !t.starts_with('~')
        && !t.contains(':')
    {
        return AssetClass::Project;
    }

    AssetClass::Unknown
}

/// Companion classifier for the *source* of an action — Layer 1 (Capability).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Source {
    /// Direct user input through the client prompt.
    User,
    /// Output of the upstream LLM provider response.
    Provider,
    /// Content fetched from a web page (via WebFetch / browser).
    Web,
    /// Output of an MCP server tool.
    Mcp,
    /// Local file outside any trust domain above.
    LocalFile,
    /// Agent's own internal reasoning / plan, no external origin.
    Internal,
    /// Unknown — treat as low-trust.
    Unknown,
}

impl Source {
    pub fn label(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Provider => "provider",
            Self::Web => "web",
            Self::Mcp => "mcp",
            Self::LocalFile => "local-file",
            Self::Internal => "internal",
            Self::Unknown => "unknown",
        }
    }

    /// True if the source is in the "untrusted tier" for taint tracking.
    pub fn is_untrusted(&self) -> bool {
        matches!(self, Self::Provider | Self::Web | Self::Mcp | Self::Unknown)
    }
}

/// Capability class of an action — Layer 1 second axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Capability {
    ReadFile,
    WriteFile,
    Execute,
    NetworkFetch,
    NetworkPost,
    BrowserNavigate,
    BrowserDownload,
    McpInvoke,
    SecretAccess,
    ClipboardRead,
    UiAutomation,
}

impl Capability {
    pub fn label(&self) -> &'static str {
        match self {
            Self::ReadFile => "read:file",
            Self::WriteFile => "write:file",
            Self::Execute => "execute:shell",
            Self::NetworkFetch => "network:fetch",
            Self::NetworkPost => "network:post",
            Self::BrowserNavigate => "browser:navigate",
            Self::BrowserDownload => "browser:download",
            Self::McpInvoke => "mcp:invoke",
            Self::SecretAccess => "secret:access",
            Self::ClipboardRead => "clipboard:read",
            Self::UiAutomation => "ui:automation",
        }
    }

    /// Map a tool name + path/command label to a capability class.
    /// Heuristic — caller can override.
    pub fn from_tool_call(tool_name: &str, input_hint: &str) -> Self {
        let n = tool_name.to_lowercase();
        let h = input_hint.to_lowercase();
        match n.as_str() {
            "bash" | "shell" | "exec" | "execute" | "run" | "terminal" => Self::Execute,
            "read" | "cat" | "view" | "head" | "tail" | "less" => Self::ReadFile,
            "write" | "edit" | "create" | "patch" | "modify" => Self::WriteFile,
            "webfetch" | "fetch" | "curl" | "wget" | "http" => Self::NetworkFetch,
            "websearch" | "search" => Self::NetworkFetch,
            "browser" | "playwright" | "puppeteer" | "selenium" => {
                if h.contains("download") {
                    Self::BrowserDownload
                } else {
                    Self::BrowserNavigate
                }
            }
            "mcp" | "mcpinvoke" => Self::McpInvoke,
            "clipboard" | "paste" => Self::ClipboardRead,
            "computer" | "ui" | "automation" => Self::UiAutomation,
            // Heuristic on the input: if it mentions http URLs, it's a fetch.
            _ if h.starts_with("http://") || h.starts_with("https://") => Self::NetworkFetch,
            _ => Self::ReadFile,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_key_is_credential() {
        assert_eq!(classify("~/.ssh/id_rsa"), AssetClass::Credential);
        assert_eq!(classify("/home/u/.ssh/id_ed25519"), AssetClass::Credential);
    }

    #[test]
    fn aws_creds_is_credential() {
        assert_eq!(classify("~/.aws/credentials"), AssetClass::Credential);
        assert_eq!(classify("/home/u/.kube/config"), AssetClass::Credential);
    }

    #[test]
    fn solana_wallet_is_wallet_data() {
        assert_eq!(
            classify("~/.config/solana/id.json"),
            AssetClass::WalletData
        );
    }

    #[test]
    fn metamask_extension_storage_is_wallet_data() {
        assert_eq!(
            classify("chrome-extension://ejbalbakpfchcnkbfecjbdpjpbhjidad/Local Storage"),
            AssetClass::WalletData
        );
    }

    #[test]
    fn chrome_login_data_is_browser_data() {
        assert!(matches!(
            classify("/home/u/AppData/Local/Google/Chrome/User Data/Default/Cookies"),
            AssetClass::BrowserData
        ));
    }

    #[test]
    fn discord_leveldb_is_browser_data() {
        assert!(matches!(
            classify("~/AppData/Roaming/Discord/Local Storage/leveldb"),
            AssetClass::BrowserData
        ));
    }

    #[test]
    fn claude_settings_is_ai_client_config() {
        assert_eq!(classify("~/.claude/settings.json"), AssetClass::AiClientConfig);
        assert_eq!(classify("./CLAUDE.md"), AssetClass::AiClientConfig);
        assert_eq!(classify(".mcp.json"), AssetClass::AiClientConfig);
    }

    #[test]
    fn etc_passwd_is_system() {
        assert_eq!(classify("/etc/passwd"), AssetClass::System);
        assert_eq!(classify("C:\\Windows\\System32\\drivers\\etc\\hosts"), AssetClass::System);
    }

    #[test]
    fn tmp_is_temp() {
        assert_eq!(classify("/tmp/payload.sh"), AssetClass::Temp);
        assert_eq!(classify("C:\\Windows\\Temp\\payload.exe"), AssetClass::Temp);
    }

    #[test]
    fn bash_history_is_log() {
        assert_eq!(classify("~/.bash_history"), AssetClass::Log);
        assert_eq!(classify("~/.python_history"), AssetClass::Log);
    }

    #[test]
    fn aws_imds_url_is_cloud_metadata() {
        assert_eq!(
            classify("http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
            AssetClass::CloudMetadata
        );
    }

    #[test]
    fn random_https_url_is_external() {
        assert_eq!(classify("https://example.com/api"), AssetClass::External);
    }

    #[test]
    fn k8s_serviceaccount_token_is_credential() {
        assert_eq!(
            classify("/var/run/secrets/kubernetes.io/serviceaccount/token"),
            AssetClass::Credential
        );
    }

    #[test]
    fn hard_deny_tier_for_secrets() {
        assert!(AssetClass::Credential.is_hard_deny_for_auto());
        assert!(AssetClass::BrowserData.is_hard_deny_for_auto());
        assert!(AssetClass::WalletData.is_hard_deny_for_auto());
        assert!(AssetClass::Keychain.is_hard_deny_for_auto());
        assert!(AssetClass::CloudMetadata.is_hard_deny_for_auto());
        assert!(!AssetClass::Project.is_hard_deny_for_auto());
    }

    #[test]
    fn ask_only_tier() {
        assert!(AssetClass::System.is_ask_only());
        assert!(AssetClass::AiClientConfig.is_ask_only());
        assert!(AssetClass::Executable.is_ask_only());
        assert!(AssetClass::Unknown.is_ask_only());
        assert!(!AssetClass::Project.is_ask_only());
    }

    #[test]
    fn source_untrusted_tier() {
        assert!(Source::Provider.is_untrusted());
        assert!(Source::Web.is_untrusted());
        assert!(Source::Mcp.is_untrusted());
        assert!(!Source::User.is_untrusted());
        assert!(!Source::Internal.is_untrusted());
    }

    #[test]
    fn capability_from_tool_name() {
        assert_eq!(Capability::from_tool_call("Bash", "ls"), Capability::Execute);
        assert_eq!(Capability::from_tool_call("Read", "file.txt"), Capability::ReadFile);
        assert_eq!(Capability::from_tool_call("Write", "out.txt"), Capability::WriteFile);
        assert_eq!(
            Capability::from_tool_call("WebFetch", "https://example.com"),
            Capability::NetworkFetch
        );
    }

    #[test]
    fn relative_path_is_project() {
        assert_eq!(classify("src/main.rs"), AssetClass::Project);
        assert_eq!(classify("./README.md"), AssetClass::Project);
    }
}