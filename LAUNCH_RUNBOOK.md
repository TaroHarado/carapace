# SafeRouter / carapace Launch Runbook

This is the operator checklist for the **first public release**.

## 0. Preconditions

Before doing anything public, confirm:

- `cargo test --quiet` is green
- `cargo clippy --all-targets -- -D warnings` is green
- local smoke passes (`scripts/smoke-local.*`)
- release smoke passes (`scripts/smoke-release.*`)
- release tag exists (`v1.0.0-rc1` or newer)

## 1. Build confidence from the real artifact

Do **not** trust source-tree success alone.

Run one of:

```powershell
./scripts/verify-release-artifact.ps1
```

```bash
./scripts/verify-release-artifact.sh
```

Success criteria:

- binary downloads from GitHub release successfully
- `cape --help` works
- `cape audit` works
- `cape registry list` works
- `scripts/smoke-local.*` passes against the downloaded binary

## 2. Generate visuals

Run:

```powershell
./scripts/capture-demo.ps1
```

or:

```bash
./scripts/capture-demo.sh
```

Expected files:

- `captures/saferouter-1440.png`
- `captures/saferouter-390.png`

You want **at least**:

1. full hero screenshot
2. report wall after verify
3. registry / history screenshot

## 3. Dry-run the demo flow

Open the local product and walk through exactly this sequence:

1. open `http://127.0.0.1:8484`
2. verify semantic arbiter status is visible
3. submit quick scan / verify flow
4. confirm score / identity / safety / drift update
5. start local session
6. toggle grants
7. evaluate policy for `.env`
8. confirm registry rows render
9. confirm recent checks timeline updates after verify

If any of those feel confusing, fix copy/UI before posting.

## 4. Minimal public claim set

These claims are safe:

- local-first safety layer for third-party LLM endpoints
- model identity confidence
- agent safety battery
- signed trust artifacts
- local provider registry
- monitoring / drift detection

Do **not** claim:

- perfect safety
- full proof of model identity
- universal protection against passive prompt theft

## 5. Posting order

Recommended order:

1. **X thread**
2. **Show HN**
3. **Habr**
4. **VC.ru**

Why:

- X gives quick feedback and catches obvious copy issues
- HN gives technical scrutiny
- Habr/VC can then borrow from refined copy and screenshots

## 6. First feedback loop

Watch for:

- people asking if you store API keys
- people asking if it works with their client/provider
- people asking what the arbiter actually does
- complaints about false positives in battery/policy decisions
- requests for hosted monitoring / public provider index

That is your v2 prioritization input.

## 7. Post-launch discipline

For the first 48 hours:

- reply quickly
- do not promise dates you can't hit
- log every real provider request and client request into issues
- keep one running list: `launch-feedback.md` or GitHub issues labels

The goal of launch is not applause. The goal is to find the fastest path from
strong beta to real product direction.
