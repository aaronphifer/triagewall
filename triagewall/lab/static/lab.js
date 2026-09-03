"use strict";

const state = { operator: "", status: null };
const titles = {
  overview: ["Evaluation workspace", "Overview"],
  bundles: ["Immutable inputs", "Bundles"],
  candidates: ["Trusted revisions", "Candidates"],
  experiments: ["Paired replay", "Experiments"],
  results: ["Private evidence", "Results"],
  reports: ["Human release decision", "Promotion report"],
};

const byId = (id) => document.getElementById(id);

async function api(path, options = {}) {
  const response = await fetch(path, { credentials: "same-origin", ...options });
  let payload = null;
  try { payload = await response.json(); } catch (_) { payload = {}; }
  if (!response.ok) {
    const error = new Error(payload.detail || `Request failed (${response.status})`);
    error.status = response.status;
    throw error;
  }
  return payload;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function showNotice(message, isError = false) {
  const node = byId("notice");
  node.textContent = message;
  node.classList.toggle("error", isError);
  node.hidden = false;
  window.setTimeout(() => { node.hidden = true; }, 6000);
}

function compactDigest(value) {
  if (!value) return "—";
  return `${value.slice(0, 15)}…${value.slice(-8)}`;
}

function prettyDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : date.toLocaleString();
}

function empty(target, title, text) {
  clear(target);
  const box = el("div", "empty-state");
  box.append(el("strong", "", title), document.createTextNode(text));
  target.append(box);
}

function metaGrid(entries) {
  const grid = el("div", "meta-grid");
  entries.forEach(([label, value]) => {
    const cell = el("div");
    cell.append(el("span", "", label), el("strong", "", value ?? "—"));
    grid.append(cell);
  });
  return grid;
}

function artifactCard(item, subtitle, entries, badge) {
  const card = el("article", "artifact-card");
  const top = el("div", "artifact-top");
  const heading = el("div");
  heading.append(el("h3", "", item.id), el("p", "digest", compactDigest(item.digest)));
  top.append(heading);
  if (badge) top.append(el("span", `status-pill ${badge.className || ""}`, badge.text));
  card.append(top);
  if (subtitle) card.append(el("p", "", subtitle));
  card.append(metaGrid(entries));
  return card;
}

function renderStatus(status) {
  const target = byId("status-cards");
  clear(target);
  [
    ["Bundles", status.bundles], ["Candidates", status.candidates],
    ["Experiments", status.experiments], ["Result pairs", status.results],
    ["Reports", status.reports],
  ].forEach(([label, value]) => {
    const card = el("div", "stat-card");
    card.append(el("span", "", label), el("strong", "", value));
    target.append(card);
  });
}

function renderBundles(items) {
  const target = byId("bundles-list"); clear(target);
  if (!items.length) return empty(target, "No bundles installed", "Import the sanitized Zeek calibration bundle to begin.");
  items.forEach((item) => target.append(artifactCard(item, null, [
    ["Events", item.event_count], ["Human labels", `${item.labeled_event_count}/${item.event_count}`],
    ["Core version", item.core_version], ["Created", prettyDate(item.created_at)],
  ], { text: "Validated", className: "safe" })));
}

function renderCandidates(items) {
  const target = byId("candidates-list"); clear(target);
  if (!items.length) return empty(target, "No candidates installed", "Install the baseline first, followed by the proposed candidate.");
  items.forEach((item) => target.append(artifactCard(item, item.rationale, [
    ["Model", item.model_name], ["Parent", item.parent_id || "Baseline root"],
    ["Author", item.author], ["Created", prettyDate(item.created_at)],
  ], { text: item.parent_id ? "Candidate" : "Baseline", className: item.parent_id ? "warning" : "safe" })));
}

function renderExperiments(items) {
  const target = byId("experiments-list"); clear(target);
  if (!items.length) return empty(target, "No experiments installed", "Install a specification after its bundle and both candidates are present.");
  items.forEach((item) => {
    const card = artifactCard(item, item.question, [
    ["Baseline", item.baseline_id], ["Candidate", item.candidate_id],
    ["Conditions", item.conditions.length], ["Repetitions", item.repetitions],
    ["Paired results", item.planned_results ?? "—"], ["Completed runs", item.completed_runs],
    ], { text: item.completed_runs ? "Complete evidence" : "Ready for worker", className: item.completed_runs ? "safe" : "warning" });
    const actions = el("div", "card-actions");
    const run = el("button", "primary compact", "Queue experiment");
    run.type = "button"; run.dataset.runDigest = item.digest; run.dataset.runPairs = item.planned_results ?? "";
    actions.append(run); card.append(actions); target.append(card);
  });
}

function renderJobs(items) {
  const target = byId("jobs-list"); clear(target);
  if (!items.length) return empty(target, "No Lab runs queued", "Queue an installed experiment when you are ready to call the private model.");
  items.forEach((item) => {
    const card = artifactCard({ id: item.id, digest: item.experiment_digest }, null, [
      ["Experiment", item.experiment_id], ["State", item.state], ["Result pairs", item.result_count],
      ["Requested", prettyDate(item.created_at)], ["Completed", prettyDate(item.completed_at)],
      ["Failure", item.failure_code || "—"],
    ], { text: item.state, className: ["completed"].includes(item.state) ? "safe" : (["failed", "canceled"].includes(item.state) ? "blocked" : "warning") });
    if (["queued", "running"].includes(item.state)) {
      const actions = el("div", "card-actions");
      const cancel = el("button", "secondary compact", item.cancel_requested ? "Cancellation requested" : "Cancel run");
      cancel.type = "button"; cancel.dataset.cancelJob = item.id; cancel.disabled = item.cancel_requested;
      actions.append(cancel); card.append(actions);
    }
    target.append(card);
  });
}

function scoreChips(score) {
  const row = el("div", "score-row");
  const chips = [
    ["Zeek assessment", score.explicit_zeek_assessment, true],
    ["Verified evidence refs", score.supported_facts.length, true],
    ["Unverified refs / format", score.unsupported_claims.length, false],
    ["Human review", score.human_review_required, false],
  ];
  chips.forEach(([label, value, positive]) => {
    const active = typeof value === "number" ? value > 0 : Boolean(value);
    const className = active ? (positive ? "good" : "bad") : "";
    row.append(el("span", `score-chip ${className}`, `${label}: ${typeof value === "boolean" ? (value ? "yes" : "no") : value}`));
  });
  return row;
}

function outcome(side, label) {
  const box = el("div", "outcome");
  const heading = el("div", "outcome-label");
  heading.append(el("span", "", label), el("span", "", side.validation_status));
  box.append(heading);
  box.append(el("div", "verdict", side.verdict || side.failure_category || "No verdict"));
  box.append(el("div", "confidence", side.confidence === null ? `${side.duration_ms} ms` : `${Math.round(side.confidence * 100)}% confidence · ${side.duration_ms} ms`));
  box.append(el("p", "reasoning", side.reasoning || "No accepted reasoning was produced."));
  box.append(scoreChips(side.score));
  return box;
}

function renderResults(items) {
  const target = byId("results-list"); clear(target);
  if (!items.length) return empty(target, "No completed result pairs", "Run an installed experiment with the private CLI; partial runs stay hidden.");
  items.forEach((item) => {
    const card = el("article", "result-card");
    const head = el("div", "result-head");
    const label = el("div");
    label.append(el("h3", "", item.event_id), el("p", "", `${item.condition.replaceAll("_", " ")} · repetition ${item.repetition} · ${item.execution_order.replaceAll("_", " ")}`));
    head.append(label, el("span", "digest", compactDigest(item.digest)));
    const compare = el("div", "comparison");
    compare.append(outcome(item.baseline, "Baseline"), outcome(item.candidate, "Candidate"));
    card.append(head, compare); target.append(card);
  });
}

function renderReports(items) {
  const target = byId("reports-list"); clear(target);
  if (!items.length) return empty(target, "No promotion report", "Aggregate reports will appear after the reporting slice is implemented and a full run completes.");
  items.forEach((item) => {
    const card = artifactCard(item, null, [
      ["Experiment", item.experiment_id], ["Evidence", `${item.completed_results}/${item.expected_results}`],
      ["Created", prettyDate(item.created_at)], ["Authority", "Human review only"],
    ], { text: item.status, className: item.status });
    const gates = el("div", "gate-list");
    item.gates.forEach((gate) => {
      const row = el("div", "gate");
      row.append(el("code", "", gate.gate_id), el("span", "", gate.observed), el("span", `status-pill ${gate.status}`, gate.status));
      gates.append(row);
    });
    card.append(gates); target.append(card);
  });
}

async function loadView(view) {
  if (view === "overview") {
    state.status = await api("/api/v1/status"); renderStatus(state.status); return;
  }
  if (view === "experiments") {
    const [experiments, jobs] = await Promise.all([api("/api/v1/experiments"), api("/api/v1/jobs")]);
    renderExperiments(experiments.items); renderJobs(jobs.items); return;
  }
  const data = await api(`/api/v1/${view}${view === "results" ? "?limit=200" : ""}`);
  ({ bundles: renderBundles, candidates: renderCandidates, experiments: renderExperiments, results: renderResults, reports: renderReports })[view](data.items);
}

async function switchView(view, push = true) {
  if (!titles[view]) view = "overview";
  document.querySelectorAll(".view").forEach((node) => node.classList.toggle("active", node.dataset.panel === view));
  document.querySelectorAll(".nav-item").forEach((node) => node.classList.toggle("active", node.dataset.view === view));
  byId("section-kicker").textContent = titles[view][0];
  byId("section-title").textContent = titles[view][1];
  if (push) history.pushState({ view }, "", view === "overview" ? "/" : `/${view}`);
  try { await loadView(view); } catch (error) { if (error.status === 401) return showLogin(); showNotice(error.message, true); }
}

function showLogin() {
  byId("app-view").hidden = true; byId("login-view").hidden = false;
  byId("api-key").value = ""; byId("api-key").focus();
}

async function showApp(session) {
  state.operator = session.operator;
  byId("operator-name").textContent = state.operator;
  byId("login-view").hidden = true; byId("app-view").hidden = false;
  const initial = location.pathname.slice(1) || "overview";
  await switchView(initial, false);
}

async function importFile(kind, file) {
  if (!file) return;
  try {
    const result = await api(`/api/v1/${kind}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-TriageWall-Lab-Request": "1" },
      body: file,
    });
    showNotice(result.created ? "Artifact validated and stored immutably." : "That exact artifact is already installed.");
    await loadView(kind);
  } catch (error) { showNotice(error.message, true); }
}

async function queueExperiment(digest, pairs) {
  const pairCount = Number.parseInt(pairs, 10);
  const detail = Number.isFinite(pairCount) ? `${pairCount} result pairs (${pairCount * 2} model calls)` : "the configured paired comparisons";
  if (!window.confirm(`Queue ${detail}? This is experimental and cannot change production.`)) return;
  try {
    await api(`/api/v1/experiments/${digest.slice(7)}/runs`, {
      method: "POST", headers: { "Content-Type": "application/json", "X-TriageWall-Lab-Request": "1" },
      body: JSON.stringify({ confirm_experimental: true }),
    });
    showNotice("Experiment queued for the isolated worker."); await loadView("experiments");
  } catch (error) { showNotice(error.message, true); }
}

async function cancelJob(jobId) {
  if (!window.confirm("Cancel this Lab run? A comparison already in progress may finish, but partial evidence will remain hidden.")) return;
  try {
    await api(`/api/v1/jobs/${jobId}/cancel`, {
      method: "POST", headers: { "Content-Type": "application/json", "X-TriageWall-Lab-Request": "1" },
      body: JSON.stringify({ confirm_cancel: true }),
    });
    showNotice("Cancellation recorded."); await loadView("experiments");
  } catch (error) { showNotice(error.message, true); }
}

document.addEventListener("DOMContentLoaded", async () => {
  byId("login-form").addEventListener("submit", async (event) => {
    event.preventDefault(); byId("login-error").textContent = "";
    try {
      const session = await api("/api/v1/session", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ api_key: byId("api-key").value }),
      });
      await showApp(session);
    } catch (error) { byId("login-error").textContent = error.message; }
  });
  byId("logout").addEventListener("click", async () => {
    try { await api("/api/v1/session", { method: "DELETE", headers: { "X-TriageWall-Lab-Request": "1" } }); } finally { showLogin(); }
  });
  document.querySelectorAll(".nav-item").forEach((node) => node.addEventListener("click", () => switchView(node.dataset.view)));
  document.querySelectorAll("[data-go]").forEach((node) => node.addEventListener("click", () => switchView(node.dataset.go)));
  document.querySelectorAll("[data-import]").forEach((button) => button.addEventListener("click", () => document.querySelector(`[data-file="${button.dataset.import}"]`).click()));
  document.querySelectorAll("[data-file]").forEach((input) => input.addEventListener("change", async () => { await importFile(input.dataset.file, input.files[0]); input.value = ""; }));
  byId("experiments-list").addEventListener("click", (event) => {
    const button = event.target.closest("[data-run-digest]");
    if (button) queueExperiment(button.dataset.runDigest, button.dataset.runPairs);
  });
  byId("jobs-list").addEventListener("click", (event) => {
    const button = event.target.closest("[data-cancel-job]");
    if (button) cancelJob(button.dataset.cancelJob);
  });
  window.addEventListener("popstate", (event) => switchView(event.state?.view || location.pathname.slice(1) || "overview", false));
  window.setInterval(() => {
    const active = document.querySelector(".view.active")?.dataset.panel;
    if (active === "experiments" && !byId("app-view").hidden) loadView("experiments").catch(() => {});
  }, 5000);
  try { await showApp(await api("/api/v1/session")); } catch (_) { showLogin(); }
});
