const form = document.getElementById("scanForm");
const state = document.getElementById("scanState");
const hostLabel = document.getElementById("hostLabel");
const honestyScore = document.getElementById("honestyScore");
const agentScore = document.getElementById("agentScore");
const finalVerdict = document.getElementById("finalVerdict");
const identityDetail = document.getElementById("identityDetail");
const agentDetail = document.getElementById("agentDetail");
const driftScore = document.getElementById("driftScore");
const driftDetail = document.getElementById("driftDetail");
const observedFamily = document.getElementById("observedFamily");
const latencyLine = document.getElementById("latencyLine");
const uptimeLine = document.getElementById("uptimeLine");
const useCase = document.getElementById("useCase");
const registryRows = document.getElementById("registryRows");
const judgeStatus = document.getElementById("judgeStatus");
const historyTimeline = document.getElementById("historyTimeline");
const sessionTask = document.getElementById("sessionTask");
const startSessionBtn = document.getElementById("startSessionBtn");
const sessionMeta = document.getElementById("sessionMeta");
const policyKind = document.getElementById("policyKind");
const policyTarget = document.getElementById("policyTarget");
const policyEvalBtn = document.getElementById("policyEvalBtn");
const policyResult = document.getElementById("policyResult");

let activePolicyKind = "file-read";
let currentSessionId = null;

let activeUseCase = "coding-agent";

for (const button of useCase.querySelectorAll("button")) {
  button.addEventListener("click", () => {
    for (const b of useCase.querySelectorAll("button")) b.classList.remove("active");
    button.classList.add("active");
    activeUseCase = button.dataset.value;
  });
}

if (policyKind) {
  for (const button of policyKind.querySelectorAll("button")) {
    button.addEventListener("click", () => {
      for (const b of policyKind.querySelectorAll("button")) b.classList.remove("active");
      button.classList.add("active");
      activePolicyKind = button.dataset.value;
    });
  }
}

for (const grantBtn of document.querySelectorAll(".grant-btn")) {
  grantBtn.addEventListener("click", async () => {
    if (!currentSessionId) {
      policyResult.textContent = "Start a session first";
      return;
    }
    const grant = grantBtn.dataset.grant;
    const active = grantBtn.classList.toggle("active-grant");
    try {
      await fetch("/api/session/grant", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ session_id: currentSessionId, name: grant, value: active }),
      });
      policyResult.textContent = `Grant ${grant}=${active} updated`;
    } catch {
      policyResult.textContent = "Grant update failed";
    }
  });
}

if (startSessionBtn) {
  startSessionBtn.addEventListener("click", async () => {
    try {
      const res = await fetch("/api/session/init", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ task: sessionTask.value.trim() || "SafeRouter session" }),
      });
      if (!res.ok) throw new Error();
      const data = await res.json();
      currentSessionId = data.session_id;
      sessionMeta.textContent = `Session ${data.session_id} / task: ${data.current_task}`;
      policyResult.textContent = "Session ready";
    } catch {
      sessionMeta.textContent = "Session init failed";
    }
  });
}

if (policyEvalBtn) {
  policyEvalBtn.addEventListener("click", async () => {
    if (!currentSessionId) {
      policyResult.textContent = "Start a session first";
      return;
    }
    try {
      const res = await fetch("/api/policy/evaluate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          session_id: currentSessionId,
          action_kind: activePolicyKind,
          target: policyTarget.value,
          provider_risk: "high",
        }),
      });
      if (!res.ok) throw new Error();
      const data = await res.json();
      policyResult.textContent = `Decision: ${data.decision}`;
    } catch {
      policyResult.textContent = "Policy evaluation failed";
    }
  });
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const url = document.getElementById("baseUrl").value.trim();
  const apiKey = document.getElementById("apiKey").value.trim();
  const claimedModel = document.getElementById("claimedModel").value.trim();

  const host = safeHost(url);
  hostLabel.textContent = host || "custom endpoint";

  state.textContent = "Scanning";

  try {
    const verifyRes = await fetch("/api/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        base_url: url,
        api_key: apiKey,
        claimed_model: claimedModel,
        use_case: activeUseCase,
      }),
    });

    if (!verifyRes.ok) throw new Error("local API unavailable");

    const verify = await verifyRes.json();
    const scenario = liveVerdict(verify.score, verify.deep_scan);

    animateNumber(honestyScore, scenario.honesty);
    animateNumber(agentScore, scenario.agent);
    finalVerdict.textContent = scenario.text;
    identityDetail.textContent = scenario.identity;
    agentDetail.textContent = scenario.agentDetail;
    driftScore.textContent = scenario.driftScore;
    driftDetail.textContent = scenario.driftDetail;
    observedFamily.textContent = scenario.observedFamily;
    latencyLine.textContent = scenario.latency;
    uptimeLine.textContent = scenario.uptime;
    state.textContent = scenario.state;
    refreshHistory(host).catch(() => {});
  } catch {
    const scenario = mockVerdict(activeUseCase, claimedModel, host);
    animateNumber(honestyScore, scenario.honesty);
    animateNumber(agentScore, scenario.agent);
    finalVerdict.textContent = scenario.text;
    identityDetail.textContent = scenario.identity;
    agentDetail.textContent = scenario.agentDetail;
    driftScore.textContent = scenario.driftScore;
    driftDetail.textContent = scenario.driftDetail;
    observedFamily.textContent = scenario.observedFamily;
    latencyLine.textContent = scenario.latency;
    uptimeLine.textContent = scenario.uptime;
    requestAnimationFrame(() => {
      state.textContent = `${scenario.state} (mock)`;
    });
  }
});

refreshRegistry().catch(() => {});
refreshHealth().catch(() => {});
refreshHistory().catch(() => {});

function safeHost(url) {
  try {
    const parsed = new URL(url);
    return parsed.host;
  } catch {
    return url.replace(/^https?:\/\//, "").split("/")[0];
  }
}

function animateNumber(node, target) {
  const label = node.querySelector("span");
  let value = 0;
  const start = performance.now();
  const duration = 650;

  const tick = (now) => {
    const progress = Math.min((now - start) / duration, 1);
    value = Math.round(target * easeOutCubic(progress));
    node.innerHTML = `${value}<span>/100</span>`;
    if (progress < 1) requestAnimationFrame(tick);
  };

  requestAnimationFrame(tick);
  if (label) label.textContent = "/100";
}

function easeOutCubic(t) {
  return 1 - Math.pow(1 - t, 3);
}

function mockVerdict(useCase, model, host) {
  const text = `${host} / ${model}`.toLowerCase();
  const official = text.includes("anthropic") || text.includes("openai") || text.includes("deepseek") || text.includes("z.ai");

  if (useCase === "chat") {
    return official
      ? { honesty: 88, agent: 79, text: "Looks safe enough for chat usage", state: "Chat-safe", identity: "Observed family aligns with claimed provider", agentDetail: "Chat use case does not trigger critical agent probes", driftScore: "Stable", driftDetail: "No historical drift sampled yet", observedFamily: "Provider match", latency: "1.1s p95", uptime: "Not enough data" }
      : { honesty: 62, agent: 58, text: "Acceptable for chat. Not for agents.", state: "Chat-only", identity: "Claim matches observed family with weak confidence", agentDetail: "No critical coding-agent probes run in chat mode", driftScore: "Stable", driftDetail: "No historical drift sampled yet", observedFamily: "Unknown", latency: "1.2s p95", uptime: "Not enough data" };
  }

  if (useCase === "web3") {
    return { honesty: official ? 74 : 49, agent: official ? 52 : 31, text: "Wallet / key workflows need strict manual review", state: "High risk", identity: official ? "Observed family aligns with claimed provider" : "Observed family unclear on third-party host", agentDetail: "High-risk wallet / secret probes triggered", driftScore: "Watch", driftDetail: "No continuous sample yet", observedFamily: official ? "Provider match" : "Unknown", latency: "1.9s p95", uptime: "Not enough data" };
  }

  if (useCase === "enterprise") {
    return { honesty: official ? 83 : 55, agent: official ? 71 : 44, text: official ? "Promising, but continuous monitoring required" : "Not enough trust for enterprise agent usage", state: official ? "Monitor" : "Block", identity: official ? "Claim and provider family align" : "Third-party routing lowers identity confidence", agentDetail: "Enterprise probes need continuous monitoring", driftScore: "Monitor", driftDetail: "Run repeated checks to establish drift baseline", observedFamily: official ? "Provider match" : "Unknown", latency: "1.6s p95", uptime: "Not enough data" };
  }

  return official
    ? { honesty: 84, agent: 69, text: "Borderline. Monitor before auto-approve.", state: "Review", identity: "Observed family matches the claimed provider", agentDetail: "Some probes flagged, but no catastrophic pattern", driftScore: "Stable", driftDetail: "No previous drift sample on this endpoint", observedFamily: "Provider match", latency: "1.4s p95", uptime: "Not enough data" }
    : { honesty: 57, agent: 41, text: "Not recommended for coding agents", state: "Chat-only", identity: "Claim is weaker than observed provider signals", agentDetail: "Multiple unsafe probe paths triggered", driftScore: "Unknown", driftDetail: "First measurement only", observedFamily: "Unknown / proxy", latency: "1.8s p95", uptime: "Not enough data" };
}

function liveVerdict(score, deep) {
  const honesty = deep.identity?.confidence ?? score.total ?? 0;
  const agent = deep.battery?.agent_safety_score ?? 0;
  let state = "Review";
  let text = deep.summary || score.summary || "Safety report generated";

  if (deep.verdict === "AgentSafe") state = "Agent-safe";
  else if (deep.verdict === "ChatOnly") state = "Chat-only";
  else if (deep.verdict === "DoNotUse") state = "Block";

  return {
    honesty,
    agent,
    text,
    state,
    identity: `Observed family: ${deep.identity?.observed_family ?? "Unknown"}. Risk: ${deep.identity?.risk ?? "Unknown"}`,
    agentDetail: `Flagged probes: ${deep.battery?.flagged_probes ?? 0}/${deep.battery?.total_probes ?? 0}`,
    driftScore: deep.drift?.previous_found ? (deep.drift.verdict_changed ? "Changed" : "Stable") : "New",
    driftDetail: deep.drift?.summary ?? "No previous run on this host yet",
    observedFamily: deep.identity?.observed_family ?? "Unknown",
    latency: `${deep.metrics?.latency_p50_ms ?? 0}ms p50 / ${deep.metrics?.latency_p95_ms ?? 0}ms p95`,
    uptime: deep.metrics?.uptime_confidence ?? "Not enough data",
  };
}

async function refreshRegistry() {
  const res = await fetch("/api/registry");
  if (!res.ok) throw new Error("registry unavailable");
  const registry = await res.json();
  if (!registryRows || !Array.isArray(registry.entries) || registry.entries.length === 0) return;

  registryRows.innerHTML = "";
  for (const entry of registry.entries.slice(0, 6)) {
    const row = document.createElement("div");
    row.className = "table-row";
    const verdictText = entry.grade === "A" ? "Agent-safe" : entry.grade === "B" || entry.grade === "C" ? "Chat-only" : "Do not use";
    const verdictClass = entry.grade === "A" ? "safe-text" : entry.grade === "B" || entry.grade === "C" ? "warning-text" : "danger-text";
    row.innerHTML = `
      <span>${entry.host}</span>
      <span>${entry.upstream}</span>
      <span>${entry.total}/100</span>
      <span>${entry.statement}</span>
      <strong class="${verdictClass}">${verdictText}</strong>
    `;
    registryRows.appendChild(row);
  }
}

async function refreshHistory(host = null) {
  if (!historyTimeline) return;
  const res = await fetch("/api/history", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(host ? { host } : {}),
  });
  if (!res.ok) throw new Error("history unavailable");
  const history = await res.json();
  if (!Array.isArray(history) || history.length === 0) {
    historyTimeline.innerHTML = `
      <div class="history-item">
        <span>no scans yet</span>
        <strong>run verify</strong>
      </div>
    `;
    return;
  }

  historyTimeline.innerHTML = "";
  for (const item of history.slice(0, 4)) {
    const driftLabel = `${item.identity.confidence}/100 identity · ${item.agent_safety_score}/100 safety`;
    const row = document.createElement("div");
    row.className = "history-item";
    row.innerHTML = `
      <span>${item.checked_at}</span>
      <strong>${driftLabel}</strong>
    `;
    historyTimeline.appendChild(row);
  }
}

async function refreshHealth() {
  try {
    const res = await fetch("/api/health");
    if (!res.ok) throw new Error();
    const health = await res.json();
    if (judgeStatus) {
      judgeStatus.textContent = `Semantic arbiter: ${health.semantic_arbiter}`;
    }
  } catch {
    if (judgeStatus) {
      judgeStatus.textContent = "Semantic arbiter: local daemon offline (mock mode)";
    }
  }
}
