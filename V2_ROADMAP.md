# SafeRouter / carapace — V2.0 Roadmap

## Current Architecture

Current `v1` / beta is a **local-first trust firewall**:

- local proxy / scanner / deep-scan engine
- local session + policy arbiter
- local web UI (`cape web`)
- score / certify / verify / registry / feed / artifact pipeline
- signed trust artifacts and local registry cache

This is already strong as a local product, but **still single-user / single-machine biased**.

`v2.0` should not mean “more commands”. It should mean:

> **multi-provider, multi-run, continuously monitored trust graph with real network effects**

That is the jump from “security CLI + local UI” to “trust platform”.

---

## What Would Actually Make It V2.0

### 1. Continuous Monitoring Engine

Not `scan once`, but:

- schedule probes every N minutes/hours
- keep time-series history
- compute drift from prior baselines
- alert on:
  - identity confidence drops
  - unsafe probe count spikes
  - latency p95 drift
  - tool-call anomaly drift

**Why it matters:** this creates a data moat. A competitor can copy UI/code; they cannot instantly copy months of provider behavior history.

---

### 2. Public / Hosted Trust Graph

The local registry is good, but `v2.0` needs a **networked trust graph**:

- public provider directory
- signed provider records
- last checked timestamp
- trust deltas over time
- optional proof links to report artifacts

Think:

```text
SafeRouter Index
  provider -> score -> identity confidence -> drift -> last checked -> report links
```

**Why it matters:** this is what turns artifacts into a real platform and category surface.

---

### 3. Hosted Monitoring / Team Layer

For solo developers, local-first is enough.

For `v2.0`, teams need:

- multiple endpoints monitored in one place
- saved API providers per org
- notifications (Slack/Telegram/email/webhook)
- policy presets by team
- local agent install + central visibility

This is the first strong paid layer.

---

### 4. Real Runtime Interception

Right now the stateful arbiter exists as policy foundation.

`v2.0` should wire it into actual execution points:

- command wrapper / command firewall
- file-read / file-write wrapper
- secret redaction on outbound send
- optional repo sandbox mode

This is where “keep auto-approve on, we’ll stop dangerous stuff” becomes real.

---

### 5. Stronger Model Identity System

Current identity is a confidence heuristic.

`v2.0` should add:

- deeper fingerprint prompt suite
- variance checks across multiple runs
- model-family confusion matrix
- downgrade detection
- “behavior closer to X than claimed Y” output

Not proof, but much more defensible confidence.

---

## Possible Approaches

### Approach A — Local-first++

Keep everything local, just add monitoring + richer reports.

**Pros**
- trust story remains clean
- no hosted key handling
- easy for security audience

**Cons**
- weaker network effects
- hard to monetize beyond power users
- no public trust graph moat

---

### Approach B — Open Core + Hosted Trust Layer

Keep local engine OSS, add hosted monitoring / index / provider graph.

**Pros**
- strongest product path
- clear monetization
- hard to copy once data accumulates
- preserves local-first trust anchor

**Cons**
- backend/ops complexity
- privacy/legal surface grows

---

### Approach C — Full SaaS Early

Push everything to hosted scan/monitoring quickly.

**Pros**
- easier onboarding
- faster B2B story

**Cons**
- weakest trust story for a security product
- hosted key handling friction
- more likely to scare away the exact security-native audience that would champion the product early

---

## Recommended Approach

### Choose B — Open Core + Hosted Trust Layer

This is the right `v2.0` shape.

Keep:

- `carapace` local engine OSS
- local SafeRouter daemon/UI
- local proxy + policy + forensics

Add hosted:

- monitored provider graph
- shared registry feeds
- reports/history storage
- team dashboards / notifications

That gives:

1. clean trust story
2. strong distribution
3. real moat through historical data
4. obvious paid layer

---

## V2.0 Milestones

### V2.0-A — Monitoring Backbone

- scheduler for repeated scans
- historical store (SQLite first, Postgres later)
- drift snapshots persisted per provider
- alert rules

### V2.0-B — Hosted Index

- signed registry feed endpoint
- provider directory frontend
- public report pages
- provider compare pages

### V2.0-C — Runtime Enforcement

- command firewall
- file access policy hook
- secret redaction path
- repo sandbox mode

### V2.0-D — Team / Monetization Layer

- multiple monitored endpoints
- org dashboard
- webhooks / alerts
- billing / plans

---

## What To Build Next (Strict Order)

1. **Monitoring scheduler + history store**
2. **Hosted provider index API + static directory page**
3. **Public report pages from signed bundles**
4. **Runtime command/file hooks**
5. **Notifications / team layer**

If we skip 1 and go straight to SaaS UI, we get a shallow dashboard.
If we do 1 first, everything else compounds.

---

## Release Criteria for V2.0

We should call it `v2.0` only when all of this is true:

- continuously monitored provider history exists
- drift is not just local cache, but persisted + queryable
- public/shared registry feed is live
- local runtime enforcement hooks exist beyond just proxying
- at least one team/hosted workflow exists

Until then, we are shipping a very strong `v1.x` line.

---

## Short Answer

If you want **real** `v2.0`, копать надо не в “ещё больше CLI-команд”, а в:

1. **continuous monitoring**
2. **trust graph / hosted registry**
3. **runtime enforcement hooks**

That is where the real moat lives.
