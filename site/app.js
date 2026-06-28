const form = document.getElementById("scanForm");
const state = document.getElementById("scanState");
const hostLabel = document.getElementById("hostLabel");
const honestyScore = document.getElementById("honestyScore");
const agentScore = document.getElementById("agentScore");
const finalVerdict = document.getElementById("finalVerdict");
const useCase = document.getElementById("useCase");

let activeUseCase = "coding-agent";

for (const button of useCase.querySelectorAll("button")) {
  button.addEventListener("click", () => {
    for (const b of useCase.querySelectorAll("button")) b.classList.remove("active");
    button.classList.add("active");
    activeUseCase = button.dataset.value;
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
    const [scoreRes, deepRes] = await Promise.all([
      fetch("/api/score", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ base_url: url, api_key: apiKey }),
      }),
      fetch("/api/deep-scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          base_url: url,
          api_key: apiKey,
          claimed_model: claimedModel,
          use_case: activeUseCase,
        }),
      }),
    ]);

    if (!scoreRes.ok || !deepRes.ok) throw new Error("local API unavailable");

    const score = await scoreRes.json();
    const deep = await deepRes.json();
    const scenario = liveVerdict(score, deep);

    animateNumber(honestyScore, scenario.honesty);
    animateNumber(agentScore, scenario.agent);
    finalVerdict.textContent = scenario.text;
    state.textContent = scenario.state;
  } catch {
    const scenario = mockVerdict(activeUseCase, claimedModel, host);
    animateNumber(honestyScore, scenario.honesty);
    animateNumber(agentScore, scenario.agent);
    finalVerdict.textContent = scenario.text;
    requestAnimationFrame(() => {
      state.textContent = `${scenario.state} (mock)`;
    });
  }
});

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
      ? { honesty: 88, agent: 79, text: "Looks safe enough for chat usage", state: "Chat-safe" }
      : { honesty: 62, agent: 58, text: "Acceptable for chat. Not for agents.", state: "Chat-only" };
  }

  if (useCase === "web3") {
    return { honesty: official ? 74 : 49, agent: official ? 52 : 31, text: "Wallet / key workflows need strict manual review", state: "High risk" };
  }

  if (useCase === "enterprise") {
    return { honesty: official ? 83 : 55, agent: official ? 71 : 44, text: official ? "Promising, but continuous monitoring required" : "Not enough trust for enterprise agent usage", state: official ? "Monitor" : "Block" };
  }

  return official
    ? { honesty: 84, agent: 69, text: "Borderline. Monitor before auto-approve.", state: "Review" }
    : { honesty: 57, agent: 41, text: "Not recommended for coding agents", state: "Chat-only" };
}

function liveVerdict(score, deep) {
  const honesty = score.total ?? 0;
  const agent = deep.battery?.agent_safety_score ?? 0;
  let state = "Review";
  let text = deep.summary || score.summary || "Safety report generated";

  if (deep.verdict === "AgentSafe") state = "Agent-safe";
  else if (deep.verdict === "ChatOnly") state = "Chat-only";
  else if (deep.verdict === "DoNotUse") state = "Block";

  return { honesty, agent, text, state };
}
