"use strict";

const state = { operator: "", status: null };
const titles = {
  overview: ["Safe testing area", "Home"],
  bundles: ["Advanced details", "Evidence bundles"],
  candidates: ["Advanced details", "Model candidates"],
  experiments: ["Choose and run", "Run tests"],
  results: ["Advanced details", "Individual results"],
  reports: ["Plain-language decisions", "Test results"],
};

const gateLabels = {
  canary_disclosure: "Protected hidden safety markers",
  injected_instruction_followed: "Ignored instructions hidden in alert evidence",
  unsupported_zeek_claims: "Used only facts supported by Zeek evidence",
  zeek_claim_when_absent: "Did not claim Zeek evidence when none was supplied",
  invalid_or_incomplete: "Returned a valid answer for every comparison",
  explicit_matched_assessment: "Explained Zeek's contribution for every matched alert",
  missed_real: "Did not introduce newly missed real alerts",
  true_positive_recall: "Preserved detection of real alerts",
  kappa_pipeline: "Preserved overall decision quality",
  kappa_model_only: "Preserved model-only decision quality",
  uncertain_outcomes: "Did not add unjustified uncertainty",
  material_subset_improvement: "Used more supported facts when Zeek mattered",
  repetition_stability: "Produced stable decisions across repeated runs",
};

const safetyGateIds = new Set([
  "canary_disclosure",
  "injected_instruction_followed",
  "zeek_claim_when_absent",
]);

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
    ["Evidence bundles", status.bundles], ["Model versions", status.candidates],
    ["Installed tests", status.experiments], ["Completed comparisons", status.results],
    ["Test reports", status.reports],
  ].forEach(([label, value]) => {
    const card = el("div", "stat-card");
    card.append(el("span", "", label), el("strong", "", value));
    target.append(card);
  });
}

function reportDecision(report) {
  const failed = report.gates.filter((gate) => gate.status !== "pass");
  if (report.status === "eligible" && failed.length === 0) {
    return {
      label: "Passed",
      className: "safe",
      title: "This change passed the Lab checks",
      summary: "The candidate met the configured safety, evidence, quality, and stability requirements.",
      action: "Review the proposed change and normal release checks before considering any Core deployment.",
    };
  }
  if (failed.some((gate) => safetyGateIds.has(gate.gate_id))) {
    return {
      label: "Unsafe",
      className: "blocked",
      title: "Stop: a safety boundary failed",
      summary: "The candidate followed or exposed information that untrusted alert evidence must not control.",
      action: "Fix the safety boundary before doing more model-quality tuning or running a larger test.",
    };
  }
  const failedIds = new Set(failed.map((gate) => gate.gate_id));
  let action = "Inspect the failed checks, adjust the candidate, and repeat the small smoke test.";
  if (failedIds.has("unsupported_zeek_claims") || failedIds.has("explicit_matched_assessment") || failedIds.has("invalid_or_incomplete")) {
    action = "Fix the structured Zeek assessment and scoring contract, then repeat the small smoke test.";
  } else if (failedIds.size === 1 && failedIds.has("repetition_stability")) {
    action = "Run the test with at least two repetitions to confirm that the result is stable.";
  }
  return {
    label: "Needs work",
    className: "warning",
    title: "Do not use this change yet",
    summary: `${failed.length} ${failed.length === 1 ? "check needs" : "checks need"} attention before this candidate can move forward.`,
    action,
  };
}

function appendBulletList(parent, values, emptyText) {
  const list = el("ul", "plain-list");
  if (!values.length) list.append(el("li", "muted", emptyText));
  values.forEach((value) => list.append(el("li", "", value)));
  parent.append(list);
}

function renderLatestDecision(reports, jobs) {
  const target = byId("latest-decision");
  clear(target);
  const activeJob = jobs.find((job) => ["queued", "running"].includes(job.state));
  if (activeJob) {
    target.classList.remove("safe", "warning", "blocked");
    target.classList.add("warning");
    target.append(el("span", "status-pill warning", activeJob.state === "running" ? "Running" : "Waiting"));
    target.append(el("p", "eyebrow", "Current test"), el("h3", "", activeJob.experiment_id));
    target.append(el("p", "decision-summary", activeJob.state === "running"
      ? `${activeJob.result_count} comparisons are complete so far. Lab will create a decision when the run finishes.`
      : "The test is queued for the isolated worker."));
    const button = el("button", "secondary", "View progress");
    button.type = "button";
    button.addEventListener("click", () => switchView("experiments"));
    target.append(button);
    return;
  }
  const report = reports[0];
  if (!report) {
    target.classList.remove("safe", "warning", "blocked");
    target.append(el("span", "status-pill", "No result yet"));
    target.append(el("p", "eyebrow", "Latest decision"), el("h3", "", "Run a test to get a recommendation"));
    target.append(el("p", "decision-summary", "Lab will compare current behavior with one proposed change and explain the outcome here."));
    const button = el("button", "primary", "Choose a test");
    button.type = "button";
    button.addEventListener("click", () => switchView("experiments"));
    target.append(button);
    return;
  }
  const decision = reportDecision(report);
  target.classList.remove("safe", "warning", "blocked");
  target.classList.add(decision.className);
  target.append(el("span", `status-pill ${decision.className}`, decision.label));
  target.append(el("p", "eyebrow", "Latest decision"), el("h3", "", decision.title));
  target.append(el("p", "decision-summary", decision.summary));
  target.append(el("strong", "next-action-label", "Recommended next step"));
  target.append(el("p", "next-action", decision.action));
  const button = el("button", "secondary", "View test result");
  button.type = "button";
  button.addEventListener("click", () => switchView("reports"));
  target.append(button);
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
    const card = el("article", "artifact-card test-card");
    const top = el("div", "artifact-top");
    const heading = el("div");
    heading.append(el("p", "eyebrow", "Installed test"), el("h3", "", item.question));
    top.append(heading, el("span", `status-pill ${item.completed_runs ? "safe" : "warning"}`, item.completed_runs ? "Previously tested" : "Ready"));
    card.append(top);
    const calls = item.planned_results === null || item.planned_results === undefined ? "—" : item.planned_results * 2;
    card.append(metaGrid([
      ["Comparisons", item.planned_results ?? "—"], ["Model calls", calls], ["Repetitions", item.repetitions],
    ]));
    const details = el("details", "advanced-details compact-details");
    details.append(el("summary", "", "Advanced test details"));
    details.append(metaGrid([
      ["Test ID", item.id], ["Current version", item.baseline_id], ["Proposed version", item.candidate_id],
      ["Evidence conditions", item.conditions.join(", ")], ["Completed runs", item.completed_runs], ["Digest", item.digest],
    ]));
    card.append(details);
    const actions = el("div", "card-actions");
    const run = el("button", "primary", "Run test");
    run.type = "button"; run.dataset.runDigest = item.digest; run.dataset.runPairs = item.planned_results ?? "";
    actions.append(run); card.append(actions); target.append(card);
  });
}

function renderJobs(items) {
  const target = byId("jobs-list"); clear(target);
  if (!items.length) return empty(target, "No Lab runs queued", "Queue an installed experiment when you are ready to call the private model.");
  items.forEach((item) => {
    const failed = ["failed", "canceled"].includes(item.state);
    const card = el("article", "artifact-card run-card");
    const top = el("div", "artifact-top");
    const heading = el("div");
    heading.append(el("h3", "", item.experiment_id), el("p", "", item.state === "completed" ? "Test finished and a report is available." : (failed ? "This run did not complete." : `${item.result_count} comparisons completed so far.`)));
    top.append(heading, el("span", `status-pill ${item.state === "completed" ? "safe" : (failed ? "blocked" : "warning")}`, item.state));
    card.append(top);
    const details = el("details", "advanced-details compact-details");
    details.append(el("summary", "", "Run details"));
    details.append(metaGrid([
      ["Run ID", item.id], ["Started", prettyDate(item.started_at || item.created_at)], ["Completed", prettyDate(item.completed_at)],
      ["Result pairs", item.result_count], ["Failure", item.failure_code || "—"], ["Digest", item.experiment_digest],
    ]));
    card.append(details);
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
    ["Injection instruction followed", score.injected_instruction_followed, false],
    ["Canary disclosed", score.canary_disclosed, false],
    ["Zeek claimed when absent", score.claims_zeek_when_absent, false],
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
  if (!items.length) return empty(target, "No test result yet", "Run an installed test. A plain-language result will appear here after all comparisons finish.");
  items.forEach((item) => {
    const decision = reportDecision(item);
    const failed = item.gates.filter((gate) => gate.status !== "pass");
    const passed = item.gates.filter((gate) => gate.status === "pass");
    const card = el("article", `decision-card report-decision ${decision.className}`);
    const top = el("div", "decision-top");
    const heading = el("div");
    heading.append(el("p", "eyebrow", "Test decision"), el("h3", "", decision.title));
    top.append(heading, el("span", `status-pill ${decision.className}`, decision.label));
    card.append(top, el("p", "decision-summary", decision.summary));
    const columns = el("div", "decision-columns");
    const worked = el("section", "decision-section");
    worked.append(el("h4", "", "What worked"));
    appendBulletList(worked, passed.slice(0, 5).map((gate) => gateLabels[gate.gate_id] || gate.gate_id), "No checks passed.");
    const attention = el("section", "decision-section");
    attention.append(el("h4", "", "What needs attention"));
    appendBulletList(attention, failed.map((gate) => gateLabels[gate.gate_id] || gate.gate_id), "Nothing—every configured check passed.");
    columns.append(worked, attention);
    card.append(columns);
    const next = el("div", "recommended-action");
    next.append(el("strong", "", "Recommended next step"), el("p", "", decision.action));
    card.append(next);
    const details = el("details", "advanced-details");
    details.append(el("summary", "", "Advanced metrics and gate evidence"));
    details.append(metaGrid([
      ["Test", item.experiment_id], ["Evidence", `${item.completed_results}/${item.expected_results}`],
      ["Created", prettyDate(item.created_at)], ["Report digest", item.digest],
    ]));
    const gates = el("div", "gate-list");
    item.gates.forEach((gate) => {
      const row = el("div", "gate");
      row.append(el("code", "", gate.gate_id), el("span", "", gate.observed), el("span", `status-pill ${gate.status}`, gate.status));
      gates.append(row);
    });
    details.append(gates);
    card.append(details); target.append(card);
  });
}

async function loadView(view) {
  if (view === "overview") {
    const [status, reports, jobs] = await Promise.all([
      api("/api/v1/status"), api("/api/v1/reports"), api("/api/v1/jobs"),
    ]);
    state.status = status;
    renderStatus(status);
    renderLatestDecision(reports.items, jobs.items);
    return;
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
