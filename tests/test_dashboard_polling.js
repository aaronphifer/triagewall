const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const {
  startIndependentPolling,
} = require("../triagewall/dashboard/static/polling.js");

const STATIC_DIR = path.join(
  __dirname,
  "..",
  "triagewall",
  "dashboard",
  "static",
);

// A DOM stub small enough to read, but real enough to run dashboard.js end to
// end. It exists so the draft-preservation and focus-tracking guarantees are
// proven by executing the shipped script rather than by matching its text.
function createElement(id) {
  const listeners = new Map();
  const classes = new Set();
  let innerHTML = "";
  const element = {
    id,
    value: "",
    textContent: "",
    disabled: false,
    hidden: false,
    title: "",
    focused: false,
    innerHTMLWrites: 0,
    dataset: {},
    style: {},
    // Backed by a real set so visibility toggles can be asserted.
    classList: {
      add: (...names) => names.forEach((name) => classes.add(name)),
      remove: (...names) => names.forEach((name) => classes.delete(name)),
      toggle(name, force) {
        const on = force === undefined ? !classes.has(name) : Boolean(force);
        if (on) classes.add(name);
        else classes.delete(name);
        return on;
      },
      contains: (name) => classes.has(name),
    },
    setAttribute() {},
    removeAttribute() {},
    getAttribute: () => null,
    scrollIntoView() {},
    querySelectorAll: () => [],
    querySelector: () => null,
    contains: () => false,
    closest: () => null,
    focus() {
      this.focused = true;
    },
    addEventListener(type, handler) {
      if (!listeners.has(type)) listeners.set(type, []);
      listeners.get(type).push(handler);
    },
    dispatch(type, event) {
      (listeners.get(type) ?? []).forEach((handler) => handler(event));
    },
  };
  Object.defineProperty(element, "innerHTML", {
    get: () => innerHTML,
    set(value) {
      innerHTML = value;
      element.innerHTMLWrites += 1;
    },
  });
  return element;
}

function runDashboard({
  pathname,
  search = "",
  verdicts = [],
  searchScope = null,
  searchWindow = "search-window-token",
  defer = () => false,
  fail = () => false,
  // Extra fields merged into the stubbed detail verdict so redaction and
  // asset-context shapes can be modelled per test.
  detailVerdict = null,
}) {
  // Records what the dashboard asked the configuration editor to do, so a
  // refused handoff can be proven by absence rather than by reading markup.
  const configEditorCalls = [];
  const elements = new Map();
  const documentListeners = new Map();
  const intervals = [];
  const pushedUrls = [];
  const pushedStates = [];
  const replacedUrls = [];
  const deferred = [];
  const windowListeners = new Map();
  const saved = new Map();
  // Controlled timers so debounce behaviour is asserted deterministically
  // rather than by waiting out a real 300ms.
  const timers = [];
  let timerId = 0;
  const setTimeoutStub = (handler, delay) => {
    timerId += 1;
    timers.push({ id: timerId, handler, delay, done: false });
    return timerId;
  };
  const clearTimeoutStub = (id) => {
    const timer = timers.find((entry) => entry.id === id);
    if (timer) timer.done = true;
  };

  // Models the queue list well enough for focus behaviour: cards are derived
  // from the data-event-id attributes actually present in the rendered markup,
  // so contains()/querySelector() answer against what is really on screen.
  //
  // listRows is the queue the fake server returns; tests reassign it to model
  // rows being inserted, reordered or removed between refreshes.
  let listRows = verdicts;
  const queueCards = new Map();
  function attachQueueListModel(element) {
    const renderedIds = () =>
      [...String(element.innerHTML).matchAll(/data-event-id="(\d+)"/g)].map((m) =>
        Number(m[1]),
      );
    const cardFor = (eventId) => {
      if (!queueCards.has(eventId)) {
        const card = createElement(`queue-card-${eventId}`);
        card.dataset.eventId = String(eventId);
        card.closest = (selector) =>
          selector === "[data-event-id]" || selector === "[data-idx]" ? card : null;
        card.focus = (options) => {
          card.focused = true;
          card.focusOptions = options;
          document.activeElement = card;
        };
        queueCards.set(eventId, card);
      }
      return queueCards.get(eventId);
    };
    element.renderedEventIds = renderedIds;
    element.cardFor = cardFor;
    element.querySelector = (selector) => {
      const match = /\[data-event-id="(\d+)"\]/.exec(String(selector));
      if (!match) return null;
      const eventId = Number(match[1]);
      return renderedIds().includes(eventId) ? cardFor(eventId) : null;
    };
    element.contains = (node) => {
      const eventId = Number(node?.dataset?.eventId);
      return (
        Number.isInteger(eventId) &&
        queueCards.get(eventId) === node &&
        renderedIds().includes(eventId)
      );
    };
  }

  const document = {
    title: "",
    activeElement: null,
    body: { classList: { add() {}, remove() {}, toggle() {} } },
    getElementById(id) {
      if (!elements.has(id)) {
        const element = createElement(id);
        // Any focusable element becomes the active element, so a refresh that
        // wrongly stole focus from the search box would be visible.
        element.focus = (options) => {
          element.focused = true;
          element.focusOptions = options;
          document.activeElement = element;
        };
        if (id === "verdicts") attachQueueListModel(element);
        elements.set(id, element);
      }
      return elements.get(id);
    },
    // Only id selectors resolve. That is enough for the listeners the script
    // attaches by id, and anything else yields an empty list rather than a
    // fake element that would make a test pass for the wrong reason.
    querySelectorAll(selector) {
      const parts = String(selector).split(",").map((part) => part.trim());
      if (!parts.every((part) => /^#[\w-]+$/.test(part))) return [];
      return parts.map((part) => this.getElementById(part.slice(1)));
    },
    querySelector: () => null,
    addEventListener(type, handler) {
      if (!documentListeners.has(type)) documentListeners.set(type, []);
      documentListeners.get(type).push(handler);
    },
  };

  const response = (body) => ({
    ok: true,
    status: 200,
    json: () => Promise.resolve(body),
  });

  // Bodies are derived from the requested id so a response can be traced back
  // to the navigation that asked for it.
  function bodyFor(target) {
    if (target.includes("/api/health")) {
      return { status: "ok", last_alert_age_seconds: 1, storage: {} };
    }
    if (target.includes("/api/v1/stats")) return { mode: "local", stats: {} };
    if (target.includes("/api/v1/spc-anomalies")) {
      return { available: false, anomalies: [] };
    }
    const feedback = target.match(/\/api\/v1\/feedback\/(\d+)$/);
    if (feedback) return { ok: true, agreed: true };
    const investigation = target.match(/\/api\/v1\/verdicts\/(\d+)\/investigation/);
    if (investigation) {
      const id = Number(investigation[1]);
      const params = new URL(target, "http://localhost").searchParams;
      const responseSearchWindow = params.has("signature")
        ? (params.get("search_window") ?? (
            typeof searchWindow === "function"
              ? searchWindow(params, { eventId: id })
              : searchWindow
          ))
        : null;
      return {
        window_hours: 24,
        search_window: responseSearchWindow,
        recurrence: {
          available: true,
          signature_id: id,
          source_type: "suricata",
          occurrences: 1,
          first_seen: null,
          last_seen: null,
          real_count: 1,
          false_positive_count: 0,
          uncertain_count: 0,
          unclassified_count: 0,
          exact: true,
          truncated: false,
          candidate_limit: 2000,
          candidates_examined: 1,
        },
        related: [
          {
            relationship: "same_rule",
            label: "Same rule",
            reason: "same rule",
            exact: true,
            truncated: false,
            candidate_limit: 2000,
            candidates_examined: 1,
            alerts: [
              {
                id: id * 10,
                timestamp: null,
                processed_at: null,
                signature_id: id,
                signature: `related-of-${id}`,
                verdict: "real",
                confidence: 0.5,
                src_ip: null,
                dest_ip: null,
                source_type: "suricata",
                relationship: "same_rule",
              },
            ],
          },
        ],
        neighbors: {
          previous: { id: 1000 + id, signature: `previous-of-${id}` },
          next: { id: 2000 + id, signature: `next-of-${id}` },
        },
      };
    }
    const detail = target.match(/\/api\/v1\/verdicts\/(\d+)$/);
    if (detail) {
      const id = Number(detail[1]);
      return {
        mode: "local",
        verdict: {
          id,
          verdict: "real",
          signature: `signature-${id}`,
          confidence: 0.9,
          sensor_context: { source: "suricata" },
          ...(detailVerdict ?? {}),
        },
      };
    }
    const list = target.match(/\/api\/v1\/verdicts\?(.*)$/);
    if (list) {
      const params = new URLSearchParams(list[1]);
      const tag = params.get("model") || "any";
      const cursor = params.get("cursor");
      const responseSearchWindow = typeof searchWindow === "function"
        ? searchWindow(params)
        : searchWindow;
      // Cursors carry their page depth so several Load Older pages can be
      // walked. Rows are tagged with the filter that asked for them, so a
      // response can be traced back to the request that produced it.
      const page = cursor ? Number(cursor.split("-").at(-1)) : 0;
      const rows = listRows.length
        ? listRows
        : [
            {
              id: 100 + page,
              verdict: "real",
              signature: page ? `row-${tag}-older-${page}` : `row-${tag}`,
              confidence: 0.5,
              human_verdict: null,
            },
          ];
      // The server is the source of truth for review state: once feedback has
      // been saved, every later read reflects it. That is what no-store buys.
      return {
        mode: "local",
        verdicts: rows.map((row) =>
          saved.has(row.id) ? { ...row, ...saved.get(row.id) } : row,
        ),
        next_cursor: `cursor-${tag}-${page + 1}`,
        search_scope: params.has("signature") ? searchScope : null,
        search_window: params.has("signature") ? responseSearchWindow : null,
      };
    }
    return { mode: "local", verdicts: listRows, next_cursor: null };
  }

  const fetchCalls = [];
  const fetchStub = (url, options) => {
    const target = String(url);
    fetchCalls.push({ url: target, options });
    // A write commits when its response is produced, not when it is issued, so
    // a deferred POST leaves the fixture unreviewed until it is released. That
    // is what lets a test interleave a genuine pre-commit queue read.
    const commit = () => {
      const posted = target.match(/\/api\/v1\/feedback\/(\d+)$/);
      if (!posted || options?.method !== "POST") return;
      const payload = JSON.parse(options.body);
      saved.set(Number(posted[1]), {
        human_verdict: payload.human_verdict,
        human_notes: payload.notes,
        agreed: 1,
      });
    };
    const failure = () => ({ ok: false, status: 500, json: () => Promise.resolve({}) });
    if (defer(target)) {
      return new Promise((resolve) => {
        deferred.push({
          url: target,
          release: () => {
            commit();
            // Body is built at release time so it reflects whatever has
            // committed by then.
            resolve(response(bodyFor(target)));
          },
          reject: () => resolve(failure()),
        });
      });
    }
    if (fail(target)) return Promise.resolve(failure());
    commit();
    return Promise.resolve(response(bodyFor(target)));
  };

  // A real location object: pushState moves it, so the script's own
  // "am I still on this alert?" checks are exercised rather than stubbed out.
  const location = { pathname, search, href: `http://localhost${pathname}${search}` };
  const navigate = (url) => {
    const [nextPath, query = ""] = String(url).split("?");
    location.pathname = nextPath;
    location.search = query ? `?${query}` : "";
    location.href = `http://localhost${url}`;
  };

  const sandbox = {
    document,
    AbortController,
    window: {
      location,
      history: {
        state: null,
        pushState(state, _title, url) {
          pushedUrls.push(url);
          pushedStates.push(state);
          this.state = state;
          navigate(url);
        },
        replaceState(state, _title, url) {
          if (!url) return;
          replacedUrls.push(url);
          this.state = state;
          navigate(url);
        },
      },
      addEventListener(type, handler) {
        if (!windowListeners.has(type)) windowListeners.set(type, []);
        windowListeners.get(type).push(handler);
      },
      scrollTo() {},
      TriagewallConfigEditor: {
        seedFromAlert(verdict, action) {
          configEditorCalls.push({ call: "seedFromAlert", action });
        },
        load() {
          configEditorCalls.push({ call: "load" });
        },
      },
    },
    fetch: fetchStub,
    // The real polling module, with its scheduler captured so ticks are fired
    // by the test rather than by a live 30s timer.
    startIndependentPolling: (options) =>
      startIndependentPolling({
        ...options,
        setTimer: (handler) => intervals.push(handler),
      }),
    URL,
    URLSearchParams,
    setTimeout: setTimeoutStub,
    clearTimeout: clearTimeoutStub,
    console,
    navigator: {},
  };
  sandbox.globalThis = sandbox;

  // Appended in the same lexical scope so the probe can read the script's
  // top-level `let` bindings, which vm does not expose on the sandbox object.
  const probe = `
;globalThis.__probe = {
  open: (id, options) => openDetailById(id, options),
  configFromAlert: (action) => openConfigurationFromAlert(action),
  setFilter: (key, value) => { currentFilter[key] = value; },
  applyFilters: () => applyFilters(),
  loadOlder: () => loadOlder(),
  returnToLive: () => returnToLive(),
  load: (options) => load(options),
  feedback: (id, agentVerdict, customVerdict, notes) =>
    feedback(id, agentVerdict, customVerdict, notes),
  state: () => ({
    currentView,
    activeDetail,
    activeInvestigation,
    currentFilter: { ...currentFilter },
    currentVerdicts: currentVerdicts.map((row) => ({ ...row })),
    nextCursor,
    queueSearchScope,
    queueSearchWindow,
    detailSearchWindow,
    historySearchWindow: window.history.state?.searchWindow ?? null,
    browsingHistory,
    focusedIndex,
  }),
};`;

  vm.runInNewContext(
    fs.readFileSync(path.join(STATIC_DIR, "dashboard.js"), "utf8") + probe,
    sandbox,
    { filename: "dashboard.js" },
  );

  return {
    document,
    fetchCalls,
    pushedUrls,
    pushedStates,
    replacedUrls,
    location,
    api: sandbox.__probe,
    configEditorCalls,
    deferred,
    releaseDeferred: (predicate = () => true) => {
      const queued = deferred.filter(({ url }) => predicate(url));
      queued.forEach((entry) => {
        deferred.splice(deferred.indexOf(entry), 1);
        entry.release();
      });
    },
    rejectDeferred: (predicate = () => true) => {
      const queued = deferred.filter(({ url }) => predicate(url));
      queued.forEach((entry) => {
        deferred.splice(deferred.indexOf(entry), 1);
        entry.reject();
      });
    },
    setVerdicts: (rows) => {
      listRows = rows;
    },
    // Focus a rendered queue card the way a Tab press would.
    focusCard: (eventId) => {
      const card = document.getElementById("verdicts").querySelector(
        `[data-event-id="${eventId}"]`,
      );
      card?.focus();
      return card;
    },
    activeEventId: () => {
      const id = Number(document.activeElement?.dataset?.eventId);
      return Number.isInteger(id) ? id : null;
    },
    tick: () => intervals.forEach((handler) => handler()),
    pendingTimers: () => timers.filter((timer) => !timer.done),
    // Fire every timer scheduled so far, as elapsing past the longest delay
    // would. Cancelled timers stay cancelled.
    advanceTimers() {
      const due = timers.filter((timer) => !timer.done);
      due.forEach((timer) => {
        timer.done = true;
        timer.handler();
      });
    },
    // Simulates the browser restoring a history entry: move the URL, then
    // deliver popstate, exactly as a back/forward press would.
    goBackTo(url, state = null) {
      navigate(url);
      sandbox.window.history.state = state;
      (windowListeners.get("popstate") ?? []).forEach((handler) => handler({ state }));
    },
    dispatchKey: (key, target = { tagName: "DIV" }) =>
      (documentListeners.get("keydown") ?? []).forEach((handler) =>
        handler({ key, target, preventDefault() {} }),
      ),
    async settle() {
      for (let index = 0; index < 40; index += 1) {
        await new Promise((resolve) => setImmediate(resolve));
      }
    },
  };
}

test("starts SPC without waiting for the main dashboard request", () => {
  const calls = [];
  const timers = [];

  startIndependentPolling({
    loadMain: () => {
      calls.push("main");
      return new Promise(() => {});
    },
    loadSpc: () => calls.push("spc"),
    setTimer: (callback, delay) => timers.push({ callback, delay }),
  });

  assert.deepEqual(calls, ["spc", "main"]);
  assert.equal(timers.length, 2);
  assert.deepEqual(timers.map(({ delay }) => delay), [30_000, 30_000]);
});

test("keeps SPC polling when the main dashboard request fails", async () => {
  let mainCalls = 0;
  let spcCalls = 0;
  const errors = [];
  const timers = [];

  startIndependentPolling({
    loadMain: () => {
      mainCalls += 1;
      return Promise.reject(new Error("verdicts unavailable"));
    },
    loadSpc: () => {
      spcCalls += 1;
    },
    setTimer: (callback) => timers.push(callback),
    onError: (error) => errors.push(error.message),
  });

  await Promise.resolve();
  assert.equal(mainCalls, 1);
  assert.equal(spcCalls, 1);
  assert.deepEqual(errors, ["verdicts unavailable"]);

  timers.forEach((callback) => callback());
  await Promise.resolve();
  assert.equal(mainCalls, 2);
  assert.equal(spcCalls, 2);
  assert.deepEqual(errors, ["verdicts unavailable", "verdicts unavailable"]);
});

test("dashboard wires SPC outside the verdict-loading function", () => {
  const scriptPath = path.join(
    __dirname,
    "..",
    "triagewall",
    "dashboard",
    "static",
    "dashboard.js",
  );
  const script = fs.readFileSync(scriptPath, "utf8");
  const loadStart = script.indexOf("async function load({");
  const loadEnd = script.indexOf("function renderHealth", loadStart);

  assert.notEqual(loadStart, -1);
  assert.notEqual(loadEnd, -1);
  assert.doesNotMatch(script.slice(loadStart, loadEnd), /loadSpc\s*\(/);
  assert.match(script, /startIndependentPolling\(\{\s*\r?\n\s*loadMain: \(\) => \{/);
  assert.match(script, /\r?\n\s*loadSpc,\r?\n\}\);/);

  const indexPath = path.join(
    __dirname,
    "..",
    "triagewall",
    "dashboard",
    "static",
    "index.html",
  );
  const html = fs.readFileSync(indexPath, "utf8");
  assert.match(html, /<script src="\/static\/polling\.js"><\/script>/);
  assert.match(html, /<script src="\/static\/dashboard\.js"><\/script>/);
});

test("dashboard renders source-aware labels and escapes dynamic identifiers", () => {
  const scriptPath = path.join(
    __dirname,
    "..",
    "triagewall",
    "dashboard",
    "static",
    "dashboard.js",
  );
  const script = fs.readFileSync(scriptPath, "utf8");

  assert.match(script, /sensor === "wazuh" \? "Rule" : "SID"/);
  assert.match(script, /Agent \$\{agent\.name\}/);
  assert.match(script, /<span class="queue-endpoint queue-source">\$\{escapeHtml\(source\)\}<\/span>/);
  assert.match(script, /SID \$\{escapeHtml\(anomaly\.signature_id\)\}/);
  assert.match(
    script,
    /\$\{ruleLabel\} \$\{escapeHtml\(verdict\.signature_id \?\? "\?"\)\}/,
  );
  assert.match(script, /badge badge-sensor/);
});

test("dashboard renders storage allocation from the health endpoint", () => {
  const indexPath = path.join(
    __dirname,
    "..",
    "triagewall",
    "dashboard",
    "static",
    "index.html",
  );
  const html = fs.readFileSync(indexPath, "utf8");
  const script = fs.readFileSync(
    path.join(path.dirname(indexPath), "dashboard.js"),
    "utf8",
  );

  assert.match(html, /id="storageMeta"/);
  assert.match(script, /storage\.total_on_disk_bytes/);
  assert.match(script, /function formatBytes\(value\)/);
});

test("dashboard has no runtime dependency on third-party CDNs", () => {
  const indexPath = path.join(
    __dirname,
    "..",
    "triagewall",
    "dashboard",
    "static",
    "index.html",
  );
  const html = fs.readFileSync(indexPath, "utf8");

  assert.doesNotMatch(html, /cdn\.|fonts\.googleapis|fonts\.gstatic/i);
  assert.match(html, /href="\/static\/dashboard\.css"/);
});

test("dashboard uses separate queue, overview, behavioral, and integrity views", () => {
  const indexPath = path.join(
    __dirname,
    "..",
    "triagewall",
    "dashboard",
    "static",
    "index.html",
  );
  const html = fs.readFileSync(indexPath, "utf8");

  assert.ok(html.indexOf('data-view="triage"') < html.indexOf('data-view="overview"'));
  assert.match(html, /class="decision-columns"/);
  assert.match(html, /href="\/triage" data-view-link="triage"/);
  assert.match(html, /href="\/overview" data-view-link="overview"/);
  assert.match(html, /href="\/behavioral" data-view-link="behavioral"/);
  assert.match(html, /href="\/integrity" data-view-link="integrity"/);
  assert.match(html, /data-view="integrity"/);
  assert.match(html, /Implemented controls — not inferred incident counters/);
  assert.doesNotMatch(html, />Cases<\/a>|>Reports<\/a>|>Hunt<\/a>/);
});

test("dashboard uses cursor pagination and URL-backed queue filters", () => {
  const script = fs.readFileSync(
    path.join(
      __dirname,
      "..",
      "triagewall",
      "dashboard",
      "static",
      "dashboard.js",
    ),
    "utf8",
  );

  assert.match(script, /const PAGE_SIZE = 50;/);
  assert.match(script, /params\.set\("limit", String\(PAGE_SIZE\)\)/);
  assert.match(script, /params\.set\("cursor", cursor\)/);
  assert.match(script, /window\.history\.replaceState/);
  assert.match(script, /currentFilter\.source/);
  assert.match(script, /currentFilter\.review/);
  assert.match(script, /decisions loaded/);
});

test("dashboard detail route escapes raw events and supports review notes", () => {
  const staticDir = path.join(
    __dirname,
    "..",
    "triagewall",
    "dashboard",
    "static",
  );
  const html = fs.readFileSync(path.join(staticDir, "index.html"), "utf8");
  const script = fs.readFileSync(path.join(staticDir, "dashboard.js"), "utf8");

  assert.match(html, /data-view="detail"/);
  assert.match(html, /id="detailPageContent"/);
  assert.doesNotMatch(html, /<dialog id="detailDrawer"/);
  assert.match(script, /\/api\/v1\/verdicts\/\$\{eventId\}/);
  assert.match(script, /<pre class="raw-event">\$\{escapeHtml\(rawAlert\)\}<\/pre>/);
  assert.match(script, /id="detailNotes" maxlength="2000"/);
  assert.match(script, /notes \}\),/);
});

function readDashboardScript() {
  return fs.readFileSync(
    path.join(
      __dirname,
      "..",
      "triagewall",
      "dashboard",
      "static",
      "dashboard.js",
    ),
    "utf8",
  );
}

test("detail navigation preserves the queue query string", () => {
  const script = readDashboardScript();

  assert.match(script, /function queueQueryString\(\)/);
  // Opening an alert, leaving it, and the back link all carry the filters.
  assert.match(script, /`\/triage\/\$\{eventId\}\$\{queueQueryString\(\)\}`/);
  assert.match(script, /`\/triage\$\{queueQueryString\(\)\}`/);
  assert.match(script, /function syncQueueLinks\(\)/);
  // The old behaviour pushed a bare path and dropped the analyst's view.
  assert.doesNotMatch(script, /pushState\(\{\}, "", "\/triage"\)/);
  assert.doesNotMatch(
    script,
    /pushState\(\{\}, "", `\/triage\/\$\{Number\(verdict\.id\)\}`\)/,
  );
});

test("previous and next come from the server, not the loaded page", () => {
  const script = readDashboardScript();

  assert.match(
    script,
    /\/api\/v1\/verdicts\/\$\{eventId\}\/investigation\?\$\{params\}/,
  );
  assert.match(script, /function renderDetailNavigation\(neighbors\)/);
  assert.match(script, /neighbors\?\.previous \?\? null/);
  assert.match(script, /neighbors\?\.next \?\? null/);
  // Deep links and refreshes have no loaded queue page to index into, so the
  // navigation renderer must not consult it. Scoped to that function: the
  // queue's own focus tracking legitimately searches currentVerdicts.
  const navStart = script.indexOf("function renderDetailNavigation(");
  const navEnd = script.indexOf("async function loadInvestigation", navStart);
  assert.notEqual(navStart, -1);
  assert.notEqual(navEnd, -1);
  assert.doesNotMatch(script.slice(navStart, navEnd), /currentVerdicts/);
});

test("investigation panels escape sensor text and state their scope", () => {
  const script = readDashboardScript();

  assert.match(script, /function renderRecurrence\(data\)/);
  assert.match(script, /function renderRelated\(data\)/);
  assert.match(script, /id="relatedPanel"/);
  assert.match(script, /id="recurrencePanel"/);
  // Sensor-controlled strings are escaped everywhere they are rendered.
  assert.match(
    script,
    /<span class="related-signature">\$\{escapeHtml\(alert\.signature \?\? "Unnamed alert"\)\}<\/span>/,
  );
  assert.match(script, /\$\{escapeHtml\(group\.reason\)\}/);
  assert.match(
    script,
    /\$\{escapeHtml\(relatedScopeNote\(group, data\.window_hours\)\)\}/,
  );
  // Every group says why it is related, and a bounded scan admits it is partial.
  assert.match(script, /function relatedScopeNote\(group, windowHours\)/);
  assert.match(script, /related-scope-partial/);
  assert.match(script, /so older matches in this window are not shown/);
  assert.match(script, /Partial: counted matches among the/);
  assert.match(script, /First examined/);
  // Recurrence is namespaced by source type, not by signature id alone.
  assert.match(script, /Suricata and Wazuh identifiers are counted separately/);
});

test("source-specific context is derived only from the retained record", () => {
  const script = readDashboardScript();

  assert.match(script, /function renderSourceContext\(verdict, sensor\)/);
  assert.match(
    script,
    /sensor === "wazuh" \? "Wazuh rule context" : "Suricata flow context"/,
  );
  // Wazuh-only fields never appear under Suricata labels and vice versa.
  assert.match(script, /readRawScalar\(raw, \["manager", "name"\]\)/);
  assert.match(script, /readRawScalar\(raw, \["location"\]\)/);
  assert.match(script, /readRawScalar\(raw, \["decoder", "name"\]\)/);
  assert.match(script, /readRawList\(raw, \["rule", "groups"\]\)/);
  assert.match(script, /readRawScalar\(raw, \["in_iface"\]\)/);
  assert.match(script, /readRawScalar\(raw, \["pkt_src"\]\)/);
  // Absent values are stated, not blanked, and nested objects are rejected.
  assert.match(script, /function derivedField\(label, value\)/);
  assert.match(script, /"Not recorded"/);
  assert.match(script, /typeof value === "object"\) return null;/);
});

test("sensor panels interpret evidence instead of leading with implementation fields", () => {
  const script = readDashboardScript();

  assert.match(script, /function suricataObservation\(verdict, raw\)/);
  assert.match(script, /What Suricata observed/);
  assert.match(script, /What this does not prove/);
  assert.match(script, /A signature match is evidence of the observed pattern/);
  assert.match(script, /function zeekConnectionAssessment\(connection\)/);
  assert.match(script, /What Zeek confirmed/);
  assert.match(script, /How this affects the verdict/);
  assert.match(script, /independently confirmed the same network flow/);
  assert.match(script, /Evidence still missing/);
  assert.match(script, /Technical details/);
});

test("Suricata evidence renders a useful escaped observation", async () => {
  const harness = runDashboard({
    pathname: "/triage/7",
    detailVerdict: {
      src_ip: "10.0.0.7",
      src_port: 51000,
      dest_ip: "198.51.100.20",
      dest_port: 80,
      proto: "TCP",
      raw_alert: JSON.stringify({
        app_proto: "http",
        alert: { action: "allowed", rev: 1, gid: 1 },
        flow: { bytes_toserver: 340, bytes_toclient: 592 },
        http: { hostname: "example.test", url: "/download", http_method: "GET" },
        payload_printable: "<img src=x onerror=alert(1)>",
      }),
    },
  });
  await harness.settle();

  const html = harness.document.getElementById("detailPageContent").innerHTML;
  assert.match(html, /Suricata matched this signature on TCP traffic/);
  assert.match(html, /The alert observed the traffic but did not block it/);
  assert.match(html, /GET example\.test\/download/);
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.doesNotMatch(html, /<img src=x onerror=alert\(1\)>/);
});

test("stored Zeek evidence leads with confirmation and limitations", async () => {
  const harness = runDashboard({
    pathname: "/triage/8",
    detailVerdict: {
      zeek_context: {
        eligibility_reason: "eligible",
        lookup_status: "matched",
        source_instance: "zeek-local",
        match_strategy: "exact_tuple_interval",
        candidate_count: 1,
        recorded_at: "2026-08-31T00:00:00Z",
        context: {
          connections: [{
            uid: "C1",
            service: "http",
            duration: 1,
            orig_bytes: 340,
            resp_bytes: 592,
            conn_state: "SF",
            missed_bytes: 0,
            direction: "same_as_alert",
          }],
        },
      },
    },
  });
  await harness.settle();

  const html = harness.document.getElementById("detailPageContent").innerHTML;
  assert.match(html, /Zeek independently confirmed the same network flow/);
  assert.match(html, /Connection metadata alone is neutral/);
  assert.match(html, /Not included in automatic enrichment/);
  assert.match(html, /Investigate further with Zeek/);
  assert.doesNotMatch(html, /<dt>Eligibility<\/dt>/);
});

test("Zeek context is summarized safely and deeper lookup stays exact", () => {
  const script = readDashboardScript();

  assert.match(script, /function zeekPanelMarkup\(zeek/);
  assert.match(script, /id="zeekContextPanel"/);
  assert.match(script, /Not evaluated\. Zeek enrichment was disabled/);
  assert.match(script, /JSON\.stringify\(context, null, 2\)/);
  assert.match(script, /<pre class="raw-event">\$\{escapeHtml\(contextJson\)\}<\/pre>/);
  assert.match(
    script,
    /\/api\/v1\/verdicts\/\$\{eventId\}\/zeek-context/,
  );
  assert.match(script, /Investigate further with Zeek/);
  assert.match(script, /bounded linked DNS, HTTP, TLS, file, and notice evidence/);
  assert.doesNotMatch(script, /window_before_seconds|window_after_seconds/);
});

test("a deep link still loads the detail view on the initial load", async () => {
  const harness = runDashboard({ pathname: "/triage/7" });
  await harness.settle();

  const urls = harness.fetchCalls.map(({ url }) => url);
  assert.ok(urls.some((url) => url.endsWith("/api/v1/verdicts/7")));
  assert.ok(urls.some((url) => url.includes("/api/v1/verdicts/7/investigation")));
  assert.ok(harness.document.getElementById("detailPageContent").innerHTMLWrites > 0);
});

test("detail and investigation are fetched with no-store", async () => {
  const harness = runDashboard({ pathname: "/triage/7" });
  await harness.settle();

  const perEvent = harness.fetchCalls.filter(({ url }) =>
    /\/api\/v1\/verdicts\/7(\/investigation)?(\?|$)/.test(url),
  );
  assert.equal(perEvent.length, 2);
  for (const call of perEvent) {
    assert.equal(call.options?.cache, "no-store", `missing no-store for ${call.url}`);
  }
});

test("a scheduled polling tick preserves an unsaved review note", async () => {
  const harness = runDashboard({ pathname: "/triage/7" });
  await harness.settle();

  const notes = harness.document.getElementById("detailNotes");
  notes.value = "half-written justification";
  const detail = harness.document.getElementById("detailPageContent");
  const writesBeforeTick = detail.innerHTMLWrites;
  const fetchesBeforeTick = harness.fetchCalls.length;

  harness.tick();
  await harness.settle();

  assert.equal(notes.value, "half-written justification");
  assert.equal(
    detail.innerHTMLWrites,
    writesBeforeTick,
    "polling replaced the detail DOM and destroyed the draft",
  );
  // Health and stats must keep refreshing while the detail body is left alone.
  const polled = harness.fetchCalls.slice(fetchesBeforeTick).map(({ url }) => url);
  assert.ok(polled.some((url) => url.includes("/api/health")));
  assert.ok(polled.some((url) => url.includes("/api/v1/stats")));
  assert.ok(!polled.some((url) => /\/api\/v1\/verdicts\/7/.test(url)));
});

test("a queue load delayed by global reads cannot become a detail refresh", async () => {
  const harness = runDashboard({
    pathname: "/triage",
    defer: (url) => url.includes("/api/health"),
  });
  await harness.settle();
  assert.equal(harness.deferred.length, 1, "the queue load should be waiting on health");

  // Detail navigation owns its own request and renders while the older queue
  // load is still suspended before its route-specific branch.
  harness.api.open(7);
  await harness.settle();
  const notes = harness.document.getElementById("detailNotes");
  const sentinel = "draft owned by the direct detail navigation";
  notes.value = sentinel;
  const detail = harness.document.getElementById("detailPageContent");
  const writesBeforeRelease = detail.innerHTMLWrites;
  const detailFetchesBeforeRelease = harness.fetchCalls.filter(({ url }) =>
    /\/api\/v1\/verdicts\/7(\/investigation)?(\?|$)/.test(url),
  ).length;

  harness.releaseDeferred((url) => url.includes("/api/health"));
  await harness.settle();

  assert.equal(harness.location.pathname, "/triage/7");
  assert.equal(harness.api.state().activeDetail.id, 7);
  assert.equal(notes.value, sentinel, "the old queue load destroyed the detail draft");
  assert.equal(
    detail.innerHTMLWrites,
    writesBeforeRelease,
    "the old queue load remounted the detail route",
  );
  assert.equal(
    harness.fetchCalls.filter(({ url }) =>
      /\/api\/v1\/verdicts\/7(\/investigation)?(\?|$)/.test(url),
    ).length,
    detailFetchesBeforeRelease,
    "the old queue load issued a second detail refresh",
  );
});

test("a delayed detail load remains bound to its original alert", async () => {
  let holdHealth = false;
  const harness = runDashboard({
    pathname: "/triage/7",
    defer: (url) => holdHealth && url.includes("/api/health"),
  });
  await harness.settle();
  assert.equal(harness.api.state().activeDetail.id, 7);

  holdHealth = true;
  const staleLoad = harness.api.load({ refreshDetail: true });
  await harness.settle();
  assert.equal(harness.deferred.length, 1, "the detail load should be waiting on health");

  holdHealth = false;
  harness.api.open(8);
  await harness.settle();
  const notes = harness.document.getElementById("detailNotes");
  const sentinel = "alert eight draft";
  notes.value = sentinel;
  const detail = harness.document.getElementById("detailPageContent");
  const writesBeforeRelease = detail.innerHTMLWrites;
  const eventEightFetches = harness.fetchCalls.filter(({ url }) =>
    /\/api\/v1\/verdicts\/8(\/investigation)?(\?|$)/.test(url),
  ).length;

  harness.releaseDeferred((url) => url.includes("/api/health"));
  await staleLoad;
  await harness.settle();

  assert.equal(harness.location.pathname, "/triage/8");
  assert.equal(harness.api.state().activeDetail.id, 8);
  assert.equal(notes.value, sentinel);
  assert.equal(detail.innerHTMLWrites, writesBeforeRelease);
  assert.equal(
    harness.fetchCalls.filter(({ url }) =>
      /\/api\/v1\/verdicts\/8(\/investigation)?(\?|$)/.test(url),
    ).length,
    eventEightFetches,
  );
});

test("a delayed detail load cannot reclaim the same alert after it is reopened", async () => {
  let deferFirstHealth = true;
  const harness = runDashboard({
    pathname: "/triage/7",
    defer: (url) => {
      if (!url.includes("/api/health") || !deferFirstHealth) return false;
      deferFirstHealth = false;
      return true;
    },
  });
  await harness.settle();
  assert.equal(harness.deferred.length, 1, "the initial detail load should be suspended");

  // Leave the original detail generation, then open the same URL as a new
  // detail session. Path and event id are intentionally identical.
  harness.dispatchKey("Escape");
  await harness.settle();
  assert.equal(harness.location.pathname, "/triage");
  harness.api.open(7);
  await harness.settle();

  const notes = harness.document.getElementById("detailNotes");
  const sentinel = "draft from the reopened alert";
  notes.value = sentinel;
  const detail = harness.document.getElementById("detailPageContent");
  const writesBeforeRelease = detail.innerHTMLWrites;
  const detailFetchesBeforeRelease = harness.fetchCalls.filter(({ url }) =>
    /\/api\/v1\/verdicts\/7(\/investigation)?(\?|$)/.test(url),
  ).length;

  harness.releaseDeferred((url) => url.includes("/api/health"));
  await harness.settle();

  assert.equal(harness.location.pathname, "/triage/7");
  assert.equal(harness.api.state().activeDetail.id, 7);
  assert.equal(notes.value, sentinel);
  assert.equal(detail.innerHTMLWrites, writesBeforeRelease);
  assert.equal(
    harness.fetchCalls.filter(({ url }) =>
      /\/api\/v1\/verdicts\/7(\/investigation)?(\?|$)/.test(url),
    ).length,
    detailFetchesBeforeRelease,
    "the retired detail generation refreshed the reopened alert",
  );
});

test("focusing a queue card syncs the index so Enter opens that card", async () => {
  const verdicts = [
    { id: 11, verdict: "real", signature: "one", confidence: 0.5 },
    { id: 22, verdict: "real", signature: "two", confidence: 0.5 },
    { id: 33, verdict: "real", signature: "three", confidence: 0.5 },
  ];
  const harness = runDashboard({ pathname: "/triage", verdicts });
  await harness.settle();

  // Tab moves DOM focus to the third card without touching the arrow keys.
  harness.document.getElementById("verdicts").dispatch("focusin", {
    target: { closest: () => ({ dataset: { idx: "2" } }) },
  });
  harness.dispatchKey("Enter");
  await harness.settle();

  assert.ok(
    harness.pushedUrls.some((url) => String(url).startsWith("/triage/33")),
    `expected the focused card to open, got ${JSON.stringify(harness.pushedUrls)}`,
  );
});

test("D opens the focused alert with the review note focused", async () => {
  const verdicts = [
    { id: 11, verdict: "real", signature: "one", confidence: 0.5, human_verdict: null },
  ];
  const harness = runDashboard({ pathname: "/triage", verdicts });
  await harness.settle();

  harness.dispatchKey("d");
  await harness.settle();

  assert.ok(harness.pushedUrls.some((url) => String(url).startsWith("/triage/11")));
  assert.equal(harness.document.getElementById("detailNotes").focused, true);
});

test("a superseded detail navigation cannot overwrite the current alert", async () => {
  // Alert 7's detail and investigation responses are held open; alert 8's
  // resolve immediately.
  const harness = runDashboard({
    pathname: "/triage",
    verdicts: [{ id: 7, verdict: "real", signature: "seven", confidence: 0.5 }],
    defer: (url) => /\/api\/v1\/verdicts\/7(\/investigation)?(\?|$)/.test(url),
  });
  await harness.settle();

  harness.api.open(7);
  await harness.settle();
  assert.ok(harness.deferred.length > 0, "alert 7 should still be in flight");

  harness.api.open(8);
  await harness.settle();

  // Alert 7 answers only now, after the operator has moved to alert 8.
  harness.releaseDeferred();
  await harness.settle();

  const state = harness.api.state();
  assert.equal(harness.location.pathname, "/triage/8");
  assert.equal(state.currentView, "detail");
  assert.equal(state.activeDetail.id, 8);
  assert.equal(state.activeInvestigation.recurrence.signature_id, 8);

  const detail = harness.document.getElementById("detailPageContent").innerHTML;
  assert.match(detail, /signature-8/);
  assert.doesNotMatch(detail, /signature-7/);

  const related = harness.document.getElementById("relatedPanel").innerHTML;
  assert.match(related, /related-of-8/);
  assert.doesNotMatch(related, /related-of-7/);
  assert.doesNotMatch(related, /temporarily unavailable/);

  const recurrence = harness.document.getElementById("recurrencePanel").innerHTML;
  assert.doesNotMatch(recurrence, /temporarily unavailable/);

  assert.equal(
    harness.document.getElementById("previousAlertButton").dataset.eventId,
    1008,
  );
  assert.equal(
    harness.document.getElementById("nextAlertButton").dataset.eventId,
    2008,
  );

  // Feedback raised from the detail page must target the alert on screen.
  harness.document.getElementById("detailPageContent").dispatch("click", {
    target: {
      closest: (selector) =>
        selector === "[data-detail-feedback]"
          ? { dataset: { detailFeedback: "real" } }
          : null,
    },
  });
  await harness.settle();
  const posted = harness.fetchCalls.filter(({ url }) => url.includes("/api/v1/feedback/"));
  assert.equal(posted.length, 1);
  assert.match(posted[0].url, /\/api\/v1\/feedback\/8$/);
});

test("leaving the detail view retires an in-flight request", async () => {
  const harness = runDashboard({
    pathname: "/triage",
    defer: (url) => /\/api\/v1\/verdicts\/7(\/investigation)?(\?|$)/.test(url),
  });
  await harness.settle();

  harness.api.open(7);
  await harness.settle();

  harness.dispatchKey("Escape");
  await harness.settle();
  const writesAfterClose =
    harness.document.getElementById("detailPageContent").innerHTMLWrites;

  harness.releaseDeferred();
  await harness.settle();

  assert.equal(harness.location.pathname, "/triage");
  assert.equal(harness.api.state().activeDetail, null);
  assert.equal(
    harness.document.getElementById("detailPageContent").innerHTMLWrites,
    writesAfterClose,
    "a retired request rendered into the detail view after navigating away",
  );
});

test("the queue list is fetched with no-store", async () => {
  const harness = runDashboard({ pathname: "/triage" });
  await harness.settle();

  const listCalls = harness.fetchCalls.filter(({ url }) =>
    /\/api\/v1\/verdicts\?/.test(url),
  );
  assert.ok(listCalls.length > 0);
  for (const call of listCalls) {
    assert.equal(call.options?.cache, "no-store", `missing no-store for ${call.url}`);
  }
});

test("a saved review is visible on return to the queue and blocks a second write", async () => {
  const harness = runDashboard({
    pathname: "/triage",
    verdicts: [
      { id: 11, verdict: "real", signature: "one", confidence: 0.5, human_verdict: null },
    ],
  });
  await harness.settle();
  assert.equal(harness.api.state().currentVerdicts[0].human_verdict, null);

  harness.api.open(11);
  await harness.settle();
  harness.document.getElementById("detailNotes").value = "owner confirmed the host";
  harness.document.getElementById("detailPageContent").dispatch("click", {
    target: {
      closest: (selector) =>
        selector === "[data-detail-feedback]"
          ? { dataset: { detailFeedback: "real" } }
          : null,
    },
  });
  await harness.settle();

  const firstPost = harness.fetchCalls.filter(({ url }) =>
    url.includes("/api/v1/feedback/"),
  );
  assert.equal(firstPost.length, 1);
  assert.equal(JSON.parse(firstPost[0].options.body).notes, "owner confirmed the host");

  // Back to the queue: the refetched row must carry the saved review.
  harness.dispatchKey("Escape");
  await harness.settle();
  const row = harness.api.state().currentVerdicts[0];
  assert.equal(row.human_verdict, "real");
  assert.equal(row.human_notes, "owner confirmed the host");

  // The one-key agree action is guarded on human_verdict, so a stale row would
  // let it fire again and overwrite the saved note with an empty one.
  harness.document.getElementById("verdicts").dispatch("focusin", {
    target: { closest: () => ({ dataset: { idx: "0" } }) },
  });
  harness.dispatchKey("a");
  await harness.settle();

  const allPosts = harness.fetchCalls.filter(({ url }) =>
    url.includes("/api/v1/feedback/"),
  );
  assert.equal(allPosts.length, 1, "a second feedback POST was submitted");
});

test("an old filter's response cannot replace the newer filter's rows", async () => {
  const harness = runDashboard({
    pathname: "/triage",
    defer: (url) => /\/api\/v1\/verdicts\?.*model=llm/.test(url),
  });
  await harness.settle();
  assert.ok(harness.deferred.length > 0, "the llm query should still be in flight");

  harness.api.setFilter("model", "prefilter");
  harness.api.applyFilters();
  await harness.settle();
  assert.equal(harness.api.state().currentVerdicts[0].signature, "row-prefilter");

  // The superseded llm query answers only now.
  harness.releaseDeferred();
  await harness.settle();

  const state = harness.api.state();
  assert.equal(state.currentFilter.model, "prefilter");
  assert.equal(state.currentVerdicts.length, 1);
  assert.equal(state.currentVerdicts[0].signature, "row-prefilter");
  assert.match(harness.document.getElementById("verdicts").innerHTML, /row-prefilter/);
  assert.doesNotMatch(harness.document.getElementById("verdicts").innerHTML, /row-llm/);
  // Retirement is silent: it is not a failure the operator needs to see.
  assert.equal(harness.document.getElementById("toast").textContent, "");
  assert.doesNotMatch(
    harness.document.getElementById("freshness").textContent,
    /unavailable/,
  );
});

test("a filter change invalidates an in-flight Load Older page", async () => {
  const harness = runDashboard({
    pathname: "/triage",
    defer: (url) => url.includes("cursor="),
  });
  await harness.settle();
  assert.equal(harness.api.state().currentVerdicts[0].signature, "row-llm");
  assert.equal(harness.api.state().nextCursor, "cursor-llm-1");

  harness.api.loadOlder();
  await harness.settle();
  assert.ok(harness.deferred.length > 0, "the older page should still be in flight");

  harness.api.setFilter("model", "prefilter");
  harness.api.applyFilters();
  await harness.settle();

  // The old-filter page answers after the filters changed.
  harness.releaseDeferred();
  await harness.settle();

  const state = harness.api.state();
  assert.equal(state.currentVerdicts.length, 1, "old-filter rows were appended");
  assert.equal(state.currentVerdicts[0].signature, "row-prefilter");
  assert.doesNotMatch(
    harness.document.getElementById("verdicts").innerHTML,
    /row-llm-older/,
  );
  assert.equal(harness.document.getElementById("toast").textContent, "");
});

test("history restores each entry's own filters", async () => {
  const harness = runDashboard({ pathname: "/triage", search: "?model=llm" });
  await harness.settle();
  assert.equal(harness.api.state().currentFilter.model, "llm");

  // Back to an entry recorded with the policy path selected.
  harness.goBackTo("/triage?model=prefilter");
  await harness.settle();
  let state = harness.api.state();
  assert.equal(state.currentFilter.model, "prefilter");
  assert.equal(state.currentVerdicts[0].signature, "row-prefilter");
  assert.match(harness.fetchCalls.at(-1).url, /model=prefilter/);

  // Forward again to the model entry.
  harness.goBackTo("/triage?model=llm");
  await harness.settle();
  state = harness.api.state();
  assert.equal(state.currentFilter.model, "llm");
  assert.equal(state.currentVerdicts[0].signature, "row-llm");
});

test("history restore clears filters the restored entry does not carry", async () => {
  const harness = runDashboard({
    pathname: "/triage",
    search: "?model=llm&verdict=real&source=wazuh&review=unreviewed&signature=scan",
  });
  await harness.settle();
  assert.equal(harness.api.state().currentFilter.verdict, "real");
  assert.equal(harness.api.state().currentFilter.signature, "scan");

  harness.goBackTo("/triage");
  await harness.settle();

  const state = harness.api.state();
  // Re-spread into this realm: the sandbox object has a different prototype.
  // model is the documented exception: a bare URL means the product default,
  // never All, which is only ever expressed as an explicit model=all.
  assert.deepEqual({ ...state.currentFilter }, {
    verdict: "",
    signature: "",
    model: "llm",
    source: "",
    review: "",
  });
  // The visible controls follow the restored state, not the newer memory.
  assert.equal(harness.document.getElementById("sigFilter").value, "");
  assert.equal(harness.document.getElementById("sourceFilter").value, "");
  assert.equal(harness.document.getElementById("reviewFilter").value, "");
  const requested = harness.fetchCalls.at(-1).url;
  assert.doesNotMatch(requested, /verdict=|source=|review=|signature=/);
  assert.match(requested, /model=llm/);
});

test("a restored detail entry investigates with that entry's filters", async () => {
  const harness = runDashboard({ pathname: "/triage", search: "?model=llm" });
  await harness.settle();

  harness.goBackTo("/triage/5?model=prefilter&review=unreviewed");
  await harness.settle();

  assert.equal(harness.api.state().currentFilter.model, "prefilter");
  assert.equal(harness.api.state().activeDetail.id, 5);
  const investigation = harness.fetchCalls
    .map(({ url }) => url)
    .filter((url) => url.includes("/api/v1/verdicts/5/investigation"))
    .at(-1);
  assert.match(investigation, /model=prefilter/);
  assert.match(investigation, /review=unreviewed/);

  // Previous/next inherit the restored filters too.
  harness.document.getElementById("nextAlertButton").dispatch("click", {});
  await harness.settle();
  assert.match(String(harness.pushedUrls.at(-1)), /^\/triage\/2005\?/);
  assert.match(String(harness.pushedUrls.at(-1)), /model=prefilter/);
});

test("searched detail navigation keeps the queue search window", async () => {
  const searchWindow = "opaque-window-from-queue";
  const harness = runDashboard({
    pathname: "/triage",
    search: "?model=llm&signature=scan",
    searchWindow,
  });
  await harness.settle();

  await harness.api.open(100);
  await harness.settle();
  let investigation = harness.fetchCalls
    .map(({ url }) => url)
    .filter((url) => url.includes("/api/v1/verdicts/100/investigation"))
    .at(-1);
  assert.equal(new URL(`http://localhost${investigation}`).searchParams.get("search_window"), searchWindow);
  assert.equal(harness.pushedStates.at(-1).searchWindow, searchWindow);

  harness.document.getElementById("nextAlertButton").dispatch("click", {});
  await harness.settle();
  investigation = harness.fetchCalls
    .map(({ url }) => url)
    .filter((url) => url.includes("/investigation"))
    .at(-1);
  assert.equal(new URL(`http://localhost${investigation}`).searchParams.get("search_window"), searchWindow);
  assert.equal(harness.pushedStates.at(-1).searchWindow, searchWindow);

  harness.goBackTo("/triage/100?model=llm&signature=scan", { searchWindow });
  await harness.settle();
  investigation = harness.fetchCalls
    .map(({ url }) => url)
    .filter((url) => url.includes("/api/v1/verdicts/100/investigation"))
    .at(-1);
  assert.equal(new URL(`http://localhost${investigation}`).searchParams.get("search_window"), searchWindow);

  harness.goBackTo("/triage/100?signature=scan", { searchWindow });
  await harness.settle();
  investigation = harness.fetchCalls
    .map(({ url }) => url)
    .filter((url) => url.includes("/api/v1/verdicts/100/investigation"))
    .at(-1);
  assert.equal(new URL(`http://localhost${investigation}`).searchParams.get("search_window"), searchWindow);
});

test("a direct searched detail persists its captured window for navigation", async () => {
  const searchWindow = "window-captured-by-investigation";
  const harness = runDashboard({
    pathname: "/triage/100",
    search: "?model=llm&signature=scan",
    searchWindow,
  });
  await harness.settle();

  let state = harness.api.state();
  assert.equal(state.detailSearchWindow, searchWindow);
  assert.equal(state.historySearchWindow, searchWindow);

  harness.document.getElementById("nextAlertButton").dispatch("click", {});
  await harness.settle();
  const investigation = harness.fetchCalls
    .map(({ url }) => url)
    .filter((url) => url.includes("/investigation"))
    .at(-1);
  assert.equal(
    new URL(`http://localhost${investigation}`).searchParams.get("search_window"),
    searchWindow,
  );
  state = harness.api.state();
  assert.equal(state.detailSearchWindow, searchWindow);
});

test("a superseded investigation cannot publish its captured window", async () => {
  const harness = runDashboard({
    pathname: "/triage/5",
    search: "?model=llm&signature=scan",
    searchWindow: (_params, { eventId }) => `window-${eventId}`,
    defer: (url) => url.includes("/api/v1/verdicts/5/investigation"),
  });
  await harness.settle();

  await harness.api.open(6);
  await harness.settle();
  assert.equal(harness.api.state().detailSearchWindow, "window-6");

  harness.releaseDeferred();
  await harness.settle();
  assert.equal(harness.api.state().detailSearchWindow, "window-6");
  assert.equal(harness.api.state().historySearchWindow, "window-6");
});

test("a superseded search response cannot replace the current search window", async () => {
  const harness = runDashboard({
    pathname: "/triage",
    search: "?model=llm&signature=old",
    searchWindow: (params) => `window-${params.get("signature")}`,
    defer: (url) => /[?&]signature=old(?:&|$)/.test(url),
  });
  await harness.settle();
  assert.ok(harness.deferred.length > 0);

  harness.api.setFilter("signature", "new");
  harness.api.applyFilters();
  await harness.settle();
  assert.equal(harness.api.state().queueSearchWindow, "window-new");

  harness.releaseDeferred();
  await harness.settle();
  assert.equal(harness.api.state().queueSearchWindow, "window-new");
});

test("Load Older refuses a changed search window without splicing rows", async () => {
  const harness = runDashboard({
    pathname: "/triage",
    search: "?model=llm&signature=scan",
    searchWindow: (params) => params.has("cursor") ? "window-changed" : "window-original",
  });
  await harness.settle();
  assert.equal(harness.api.state().queueSearchWindow, "window-original");

  await harness.api.loadOlder();
  await harness.settle();
  const state = harness.api.state();
  assert.equal(state.queueSearchWindow, "window-original");
  assert.equal(state.currentVerdicts.length, 1);
  assert.equal(state.browsingHistory, false);
  assert.match(
    harness.document.getElementById("toast").textContent,
    /search window changed/,
  );
});

test("clearing queue search drops its window before opening detail", async () => {
  const harness = runDashboard({
    pathname: "/triage",
    search: "?model=llm&signature=scan",
    searchWindow: "window-scan",
  });
  await harness.settle();
  assert.equal(harness.api.state().queueSearchWindow, "window-scan");

  harness.api.setFilter("signature", "");
  harness.api.applyFilters();
  await harness.settle();
  assert.equal(harness.api.state().queueSearchWindow, null);

  await harness.api.open(100);
  await harness.settle();
  const investigation = harness.fetchCalls
    .map(({ url }) => url)
    .filter((url) => url.includes("/api/v1/verdicts/100/investigation"))
    .at(-1);
  assert.equal(new URL(`http://localhost${investigation}`).searchParams.get("search_window"), null);
});

test("whitespace-only queue search is omitted from queue and investigation requests", async () => {
  const harness = runDashboard({
    pathname: "/triage",
    search: "?model=llm&signature=%20%20%20",
    searchWindow: "window-that-must-not-be-used",
  });
  await harness.settle();

  const queueRequest = harness.fetchCalls
    .map(({ url }) => url)
    .find((url) => url.includes("/api/v1/verdicts?"));
  assert.equal(new URL(`http://localhost${queueRequest}`).searchParams.get("signature"), null);
  assert.equal(harness.api.state().queueSearchWindow, null);

  await harness.api.open(100);
  await harness.settle();
  const investigation = harness.fetchCalls
    .map(({ url }) => url)
    .filter((url) => url.includes("/api/v1/verdicts/100/investigation"))
    .at(-1);
  const params = new URL(`http://localhost${investigation}`).searchParams;
  assert.equal(params.get("signature"), null);
  assert.equal(params.get("search_window"), null);
});

test("a stale queue feedback completion cannot reload a newly opened alert", async () => {
  const harness = runDashboard({
    pathname: "/triage",
    verdicts: [
      { id: 11, verdict: "real", signature: "queue-row", confidence: 0.5, human_verdict: null },
    ],
    defer: (url) => url.includes("/api/v1/feedback/"),
  });
  await harness.settle();

  // Agree from the queue. The POST is held open.
  harness.document.getElementById("verdicts").dispatch("focusin", {
    target: { closest: () => ({ dataset: { idx: "0" } }) },
  });
  harness.dispatchKey("a");
  await harness.settle();
  assert.equal(harness.deferred.length, 1, "the feedback POST should be in flight");

  // The operator moves to another alert and starts writing.
  harness.api.open(22);
  await harness.settle();
  const notes = harness.document.getElementById("detailNotes");
  const sentinel = "sentinel draft that must survive";
  notes.value = sentinel;

  const detail = harness.document.getElementById("detailPageContent");
  const writesBeforeRelease = detail.innerHTMLWrites;
  const fetchesBeforeRelease = harness.fetchCalls.length;

  // The queue-originated POST finally answers.
  harness.releaseDeferred();
  await harness.settle();

  const state = harness.api.state();
  assert.equal(harness.location.pathname, "/triage/22");
  assert.equal(state.currentView, "detail");
  assert.equal(state.activeDetail.id, 22);
  assert.equal(notes.value, sentinel, "the stale completion destroyed the draft");
  assert.equal(
    detail.innerHTMLWrites,
    writesBeforeRelease,
    "the stale completion re-rendered the detail page",
  );
  // No queue reload and no detail reload were triggered by the completion.
  const after = harness.fetchCalls.slice(fetchesBeforeRelease).map(({ url }) => url);
  assert.deepEqual(after, [], `stale completion issued requests: ${after.join(", ")}`);
});

test("a bare triage URL is canonicalized to the Model default", async () => {
  const harness = runDashboard({ pathname: "/triage" });
  await harness.settle();

  assert.ok(
    harness.replacedUrls.some((url) => String(url) === "/triage?model=llm"),
    `expected canonicalization, got ${JSON.stringify(harness.replacedUrls)}`,
  );
  assert.equal(harness.location.search, "?model=llm");
  assert.equal(harness.api.state().currentFilter.model, "llm");
  assert.match(harness.fetchCalls.at(-1).url, /model=llm/);
});

test("opening an alert then going back keeps the queue on Model", async () => {
  const harness = runDashboard({ pathname: "/triage" });
  await harness.settle();

  harness.api.open(5);
  await harness.settle();
  assert.match(String(harness.pushedUrls.at(-1)), /^\/triage\/5\?.*model=llm/);

  // Back to the entry the queue started on.
  harness.goBackTo("/triage?model=llm");
  await harness.settle();
  assert.equal(harness.api.state().currentFilter.model, "llm");
  assert.match(harness.fetchCalls.at(-1).url, /model=llm/);

  // Even a bare entry reaching popstate resolves to Model, not All.
  harness.goBackTo("/triage");
  await harness.settle();
  assert.equal(harness.api.state().currentFilter.model, "llm");
});

test("a bare detail URL canonicalizes and keeps Model neighbours across history", async () => {
  const harness = runDashboard({ pathname: "/triage/5" });
  await harness.settle();

  assert.ok(
    harness.replacedUrls.some((url) => String(url) === "/triage/5?model=llm"),
    `expected canonicalization, got ${JSON.stringify(harness.replacedUrls)}`,
  );
  assert.equal(harness.location.pathname, "/triage/5");
  assert.equal(harness.api.state().activeDetail.id, 5);
  const investigated = harness.fetchCalls
    .map(({ url }) => url)
    .filter((url) => url.includes("/investigation"));
  assert.match(investigated.at(-1), /model=llm/);

  harness.goBackTo("/triage/5?model=llm");
  await harness.settle();
  assert.equal(harness.api.state().currentFilter.model, "llm");
  assert.match(
    harness.fetchCalls.map(({ url }) => url).filter((url) => url.includes("/investigation")).at(-1),
    /model=llm/,
  );
});

test("selecting All writes model=all and omits the API model parameter", async () => {
  const harness = runDashboard({ pathname: "/triage" });
  await harness.settle();

  harness.api.setFilter("model", "");
  harness.api.applyFilters();
  await harness.settle();

  assert.match(String(harness.replacedUrls.at(-1)), /model=all/);
  assert.equal(harness.location.search, "?model=all");
  // All is a URL encoding only; the API has no such filter value.
  const listUrl = harness.fetchCalls
    .map(({ url }) => url)
    .filter((url) => /\/api\/v1\/verdicts\?/.test(url))
    .at(-1);
  assert.doesNotMatch(listUrl, /model=/);
});

test("model=all survives a reload and history navigation", async () => {
  const reloaded = runDashboard({ pathname: "/triage", search: "?model=all" });
  await reloaded.settle();

  assert.equal(reloaded.api.state().currentFilter.model, "");
  // Already explicit, so canonicalization leaves it alone.
  assert.ok(!reloaded.replacedUrls.some((url) => String(url).includes("model=llm")));
  assert.equal(reloaded.location.search, "?model=all");
  const listUrl = reloaded.fetchCalls
    .map(({ url }) => url)
    .filter((url) => /\/api\/v1\/verdicts\?/.test(url))
    .at(-1);
  assert.doesNotMatch(listUrl, /model=/);

  reloaded.goBackTo("/triage?model=all");
  await reloaded.settle();
  assert.equal(reloaded.api.state().currentFilter.model, "");
});

test("other filters survive canonicalization and history navigation", async () => {
  const harness = runDashboard({
    pathname: "/triage",
    search: "?verdict=real&source=wazuh&review=unreviewed&signature=scan",
  });
  await harness.settle();

  const canonical = String(harness.replacedUrls.at(-1));
  for (const expected of [
    "model=llm",
    "verdict=real",
    "source=wazuh",
    "review=unreviewed",
    "signature=scan",
  ]) {
    assert.ok(canonical.includes(expected), `${expected} missing from ${canonical}`);
  }

  harness.goBackTo(canonical);
  await harness.settle();
  const state = harness.api.state();
  assert.deepEqual({ ...state.currentFilter }, {
    verdict: "real",
    signature: "scan",
    model: "llm",
    source: "wazuh",
    review: "unreviewed",
  });
  assert.equal(harness.document.getElementById("sigFilter").value, "scan");
  assert.equal(harness.document.getElementById("sourceFilter").value, "wazuh");
  assert.equal(harness.document.getElementById("reviewFilter").value, "unreviewed");
});

test("canonicalization leaves non-triage routes alone", async () => {
  const harness = runDashboard({ pathname: "/overview" });
  await harness.settle();

  assert.deepEqual(harness.replacedUrls, []);
  assert.equal(harness.location.search, "");
});

// Counts only the queue/detail reads, so health and stats polling never make
// a "nothing reloaded" assertion look false.
function routeFetchUrls(harness) {
  return harness.fetchCalls
    .map(({ url }) => url)
    .filter((url) => url.includes("/api/v1/verdicts"));
}

test("a pending signature debounce cannot remount a detail page", async () => {
  const harness = runDashboard({
    pathname: "/triage",
    verdicts: [
      { id: 7, verdict: "real", signature: "seven", confidence: 0.5, human_verdict: null },
    ],
  });
  await harness.settle();

  // The real input handler schedules the debounced queue reload.
  harness.document.getElementById("sigFilter").dispatch("input", {
    target: { value: "scan" },
  });
  assert.equal(harness.pendingTimers().length, 1, "the debounce should be scheduled");

  // The operator opens an alert before it fires and starts writing.
  harness.api.open(7);
  await harness.settle();
  const notes = harness.document.getElementById("detailNotes");
  const sentinel = "sentinel note the debounce must not destroy";
  notes.value = sentinel;

  const detail = harness.document.getElementById("detailPageContent");
  const writesBefore = detail.innerHTMLWrites;
  const fetchesBefore = routeFetchUrls(harness).length;

  harness.advanceTimers();
  await harness.settle();

  const state = harness.api.state();
  assert.equal(notes.value, sentinel, "the stale debounce destroyed the draft");
  assert.equal(
    detail.innerHTMLWrites,
    writesBefore,
    "the stale debounce remounted the detail page",
  );
  assert.equal(state.currentView, "detail");
  assert.equal(state.activeDetail.id, 7);
  assert.equal(harness.location.pathname, "/triage/7");
  assert.equal(routeFetchUrls(harness).length, fetchesBefore, "a reload was issued");
  assert.equal(harness.document.getElementById("toast").textContent, "");
  // The typed value itself is kept: only the scheduled reload was dropped.
  assert.equal(state.currentFilter.signature, "scan");
});

test("typing a new search retires the prior queue window before detail opens", async () => {
  const harness = runDashboard({
    pathname: "/triage",
    search: "?model=llm&signature=old",
    searchWindow: "window-old",
    verdicts: [
      { id: 7, verdict: "real", signature: "seven", confidence: 0.5, human_verdict: null },
    ],
  });
  await harness.settle();
  assert.equal(harness.api.state().queueSearchWindow, "window-old");

  harness.document.getElementById("sigFilter").dispatch("input", {
    target: { value: "new" },
  });
  assert.equal(harness.api.state().queueSearchWindow, null);

  await harness.api.open(7);
  await harness.settle();
  const investigation = harness.fetchCalls
    .map(({ url }) => url)
    .filter((url) => url.includes("/api/v1/verdicts/7/investigation"))
    .at(-1);
  assert.equal(new URL(`http://localhost${investigation}`).searchParams.get("signature"), "new");
  assert.equal(new URL(`http://localhost${investigation}`).searchParams.get("search_window"), null);
});

test("leaving the queue cancels the pending signature debounce", async () => {
  const harness = runDashboard({ pathname: "/triage" });
  await harness.settle();

  harness.document.getElementById("sigFilter").dispatch("input", {
    target: { value: "scan" },
  });
  assert.equal(harness.pendingTimers().length, 1);

  harness.api.open(7);
  await harness.settle();
  assert.equal(
    harness.pendingTimers().length,
    0,
    "the queue reload was still scheduled after navigating to detail",
  );
});

test("a popstate to a detail route cancels a pending signature debounce", async () => {
  const harness = runDashboard({ pathname: "/triage" });
  await harness.settle();

  harness.document.getElementById("sigFilter").dispatch("input", {
    target: { value: "scan" },
  });
  assert.equal(harness.pendingTimers().length, 1);

  harness.goBackTo("/triage/7?model=llm");
  await harness.settle();
  assert.equal(harness.pendingTimers().length, 0);

  const notes = harness.document.getElementById("detailNotes");
  const sentinel = "written after the back navigation";
  notes.value = sentinel;
  const detail = harness.document.getElementById("detailPageContent");
  const writesBefore = detail.innerHTMLWrites;
  const fetchesBefore = routeFetchUrls(harness).length;

  harness.advanceTimers();
  await harness.settle();

  assert.equal(notes.value, sentinel);
  assert.equal(detail.innerHTMLWrites, writesBefore);
  assert.equal(harness.api.state().activeDetail.id, 7);
  assert.equal(routeFetchUrls(harness).length, fetchesBefore);
});

test("applyFilters is queue-only even if a stale timer survives", async () => {
  const harness = runDashboard({ pathname: "/triage" });
  await harness.settle();

  harness.api.open(7);
  await harness.settle();
  const notes = harness.document.getElementById("detailNotes");
  notes.value = "draft";
  const detail = harness.document.getElementById("detailPageContent");
  const writesBefore = detail.innerHTMLWrites;
  const fetchesBefore = routeFetchUrls(harness).length;

  // Second layer: even invoked directly from the detail view, it must do
  // nothing rather than fall through to load().
  harness.api.applyFilters();
  await harness.settle();

  assert.equal(notes.value, "draft");
  assert.equal(detail.innerHTMLWrites, writesBefore);
  assert.equal(harness.api.state().activeDetail.id, 7);
  assert.equal(routeFetchUrls(harness).length, fetchesBefore);
  assert.equal(harness.document.getElementById("toast").textContent, "");
});

test("signature filtering still reloads the queue exactly once", async () => {
  const harness = runDashboard({ pathname: "/triage" });
  await harness.settle();
  const before = routeFetchUrls(harness).length;

  harness.document.getElementById("sigFilter").dispatch("input", {
    target: { value: "scan" },
  });
  harness.advanceTimers();
  await harness.settle();

  const after = routeFetchUrls(harness);
  assert.equal(after.length, before + 1, "expected exactly one queue reload");
  assert.match(after.at(-1), /signature=scan/);
  assert.equal(harness.api.state().currentFilter.signature, "scan");
  assert.match(String(harness.replacedUrls.at(-1)), /signature=scan/);
});

test("a typed signature is live URL state before the debounce fires", async () => {
  const harness = runDashboard({ pathname: "/triage", search: "?model=llm" });
  await harness.settle();
  const fetchesBefore = routeFetchUrls(harness).length;
  const pushesBefore = harness.pushedUrls.length;

  harness.document.getElementById("sigFilter").dispatch("input", {
    target: { value: "scan" },
  });

  // The queue entry already carries the typed value...
  const queueUrl = String(harness.replacedUrls.at(-1));
  assert.match(queueUrl, /signature=scan/);
  assert.match(queueUrl, /model=llm/);
  assert.match(queueUrl, /^\/triage\?/);
  // ...written with replaceState, and without fetching yet.
  assert.equal(harness.pushedUrls.length, pushesBefore, "typing created a history entry");
  assert.equal(
    routeFetchUrls(harness).length,
    fetchesBefore,
    "typing issued a queue request before the debounce",
  );
  assert.equal(harness.pendingTimers().length, 1);

  // Opening an alert during the debounce carries the signature forward.
  harness.api.open(7);
  await harness.settle();
  const detailUrl = String(harness.pushedUrls.at(-1));
  assert.match(detailUrl, /^\/triage\/7\?/);
  assert.match(detailUrl, /signature=scan/);
  assert.equal(harness.pendingTimers().length, 0, "the obsolete timer was not cancelled");

  // The cancelled debounce must not remount the detail page.
  const notes = harness.document.getElementById("detailNotes");
  const sentinel = "draft written during the debounce";
  notes.value = sentinel;
  const detail = harness.document.getElementById("detailPageContent");
  const writesBefore = detail.innerHTMLWrites;
  harness.advanceTimers();
  await harness.settle();
  assert.equal(notes.value, sentinel);
  assert.equal(detail.innerHTMLWrites, writesBefore);
  assert.equal(harness.api.state().activeDetail.id, 7);

  // Back restores the queue entry exactly as typing left it.
  harness.goBackTo(queueUrl);
  await harness.settle();
  assert.equal(harness.api.state().currentFilter.signature, "scan");
  assert.equal(harness.document.getElementById("sigFilter").value, "scan");
  assert.match(
    routeFetchUrls(harness).at(-1),
    /signature=scan/,
    "the restored queue request lost the typed signature",
  );
});

test("clearing the search removes the signature from the URL immediately", async () => {
  const harness = runDashboard({ pathname: "/triage", search: "?model=llm" });
  await harness.settle();
  const input = harness.document.getElementById("sigFilter");

  input.dispatch("input", { target: { value: "scan" } });
  assert.match(String(harness.replacedUrls.at(-1)), /signature=scan/);

  input.dispatch("input", { target: { value: "" } });
  const cleared = String(harness.replacedUrls.at(-1));
  assert.doesNotMatch(cleared, /signature=/, "the cleared search stayed in the URL");
  assert.match(cleared, /model=llm/, "clearing the search dropped the other filters");
  assert.equal(harness.api.state().currentFilter.signature, "");
});

test("rapid typing writes no history entries and fetches once", async () => {
  const harness = runDashboard({ pathname: "/triage", search: "?model=llm" });
  await harness.settle();
  const fetchesBefore = routeFetchUrls(harness).length;
  const pushesBefore = harness.pushedUrls.length;
  const input = harness.document.getElementById("sigFilter");

  for (const value of ["s", "sc", "sca", "scan"]) {
    input.dispatch("input", { target: { value } });
  }

  assert.equal(harness.pushedUrls.length, pushesBefore, "typing created history entries");
  assert.match(String(harness.replacedUrls.at(-1)), /signature=scan/);
  assert.equal(harness.pendingTimers().length, 1, "earlier timers were not cleared");
  assert.equal(routeFetchUrls(harness).length, fetchesBefore);

  harness.advanceTimers();
  await harness.settle();
  assert.equal(routeFetchUrls(harness).length, fetchesBefore + 1);
  assert.match(routeFetchUrls(harness).at(-1), /signature=scan/);
});

test("rapid typing debounces to a single queue reload", async () => {
  const harness = runDashboard({ pathname: "/triage" });
  await harness.settle();
  const before = routeFetchUrls(harness).length;

  const input = harness.document.getElementById("sigFilter");
  for (const value of ["s", "sc", "sca", "scan"]) {
    input.dispatch("input", { target: { value } });
  }
  assert.equal(harness.pendingTimers().length, 1, "earlier timers were not cleared");

  harness.advanceTimers();
  await harness.settle();
  assert.equal(routeFetchUrls(harness).length, before + 1);
});

test("a failed first Load older returns the queue to live mode", async () => {
  const harness = runDashboard({
    pathname: "/triage",
    fail: (url) => url.includes("cursor="),
  });
  await harness.settle();
  assert.equal(harness.api.state().browsingHistory, false);

  await harness.api.loadOlder();
  await harness.settle();

  const state = harness.api.state();
  assert.equal(state.browsingHistory, false, "history mode stuck after a failure");
  assert.equal(
    harness.document.getElementById("returnLiveButton").classList.contains("hidden"),
    true,
  );
  assert.doesNotMatch(
    harness.document.getElementById("paginationMeta").textContent,
    /browsing history/,
  );

  // Live polling resumes: a tick refetches the queue.
  const before = routeFetchUrls(harness).length;
  harness.tick();
  await harness.settle();
  assert.ok(routeFetchUrls(harness).length > before, "live polling did not resume");
});

test("a failed later Load older stays in history mode", async () => {
  const harness = runDashboard({
    pathname: "/triage",
    // The first historical page succeeds; the second fails.
    fail: (url) => url.includes("cursor=cursor-llm-2"),
  });
  await harness.settle();

  await harness.api.loadOlder();
  await harness.settle();
  assert.equal(harness.api.state().browsingHistory, true);
  assert.equal(harness.api.state().currentVerdicts.length, 2);

  await harness.api.loadOlder();
  await harness.settle();

  const state = harness.api.state();
  assert.equal(state.browsingHistory, true, "history was abandoned on a later failure");
  assert.equal(state.currentVerdicts.length, 2, "loaded historical rows were lost");
  assert.match(
    harness.document.getElementById("verdicts").innerHTML,
    /row-llm-older-1/,
  );
});

test("a superseded Load older failure cannot revert newer queue state", async () => {
  const harness = runDashboard({
    pathname: "/triage",
    defer: (url) => url.includes("cursor="),
  });
  await harness.settle();

  harness.api.loadOlder();
  await harness.settle();
  assert.equal(harness.api.state().browsingHistory, true);

  // A filter change supersedes the pending page and returns to live.
  harness.api.setFilter("model", "prefilter");
  harness.api.applyFilters();
  await harness.settle();
  assert.equal(harness.api.state().browsingHistory, false);

  harness.rejectDeferred();
  await harness.settle();

  const state = harness.api.state();
  assert.equal(state.browsingHistory, false, "a stale failure changed newer state");
  assert.equal(state.currentVerdicts[0].signature, "row-prefilter");
  assert.equal(harness.document.getElementById("toast").textContent, "");
});

test("returning live retires a pending historical page", async () => {
  const harness = runDashboard({
    pathname: "/triage",
    defer: (url) => url.includes("cursor="),
  });
  await harness.settle();

  harness.api.loadOlder();
  await harness.settle();
  assert.equal(harness.api.state().browsingHistory, true);
  assert.equal(harness.document.getElementById("loadOlderButton").disabled, true);
  assert.equal(harness.deferred.length, 1);

  await harness.api.returnToLive();
  await harness.settle();

  let state = harness.api.state();
  assert.equal(state.browsingHistory, false);
  assert.equal(state.currentVerdicts.length, 1, "the live page was not restored");
  assert.equal(harness.document.getElementById("loadOlderButton").disabled, false);
  assert.equal(
    harness.document.getElementById("returnLiveButton").classList.contains("hidden"),
    true,
  );

  // A late response from the retired page owns neither the rows nor the
  // controls of the live queue.
  harness.releaseDeferred();
  await harness.settle();

  state = harness.api.state();
  assert.equal(state.browsingHistory, false);
  assert.equal(state.currentVerdicts.length, 1);
  assert.doesNotMatch(
    harness.document.getElementById("verdicts").innerHTML,
    /older/,
  );
  assert.equal(harness.document.getElementById("loadOlderButton").disabled, false);
});

test("a failed feedback write is reported even after navigating away", async () => {
  const harness = runDashboard({
    pathname: "/triage",
    verdicts: [
      { id: 11, verdict: "real", signature: "one", confidence: 0.5, human_verdict: null },
    ],
    defer: (url) => url.includes("/api/v1/feedback/"),
  });
  await harness.settle();

  harness.document.getElementById("verdicts").dispatch("focusin", {
    target: { closest: () => ({ dataset: { idx: "0" } }) },
  });
  harness.dispatchKey("a");
  await harness.settle();

  harness.api.open(22);
  await harness.settle();
  const notes = harness.document.getElementById("detailNotes");
  const sentinel = "draft on the new alert";
  notes.value = sentinel;
  const detail = harness.document.getElementById("detailPageContent");
  const writesBefore = detail.innerHTMLWrites;

  harness.rejectDeferred();
  await harness.settle();

  const toast = harness.document.getElementById("toast");
  assert.match(toast.textContent, /Alert 11/, "the failure did not name the alert");
  assert.match(toast.textContent, /not saved/i);
  // The new route is untouched.
  assert.equal(notes.value, sentinel);
  assert.equal(detail.innerHTMLWrites, writesBefore);
  assert.equal(harness.api.state().activeDetail.id, 22);
  assert.equal(harness.location.pathname, "/triage/22");
});

test("a review saved from a historical row survives the return to the queue", async () => {
  const harness = runDashboard({ pathname: "/triage" });
  await harness.settle();

  await harness.api.loadOlder();
  await harness.settle();
  assert.equal(harness.api.state().browsingHistory, true);
  const historical = harness.api.state().currentVerdicts.at(-1);
  assert.equal(historical.human_verdict, null);

  harness.api.open(historical.id);
  await harness.settle();
  harness.document.getElementById("detailNotes").value = "kept from the historical page";
  harness.document.getElementById("detailPageContent").dispatch("click", {
    target: {
      closest: (selector) =>
        selector === "[data-detail-feedback]"
          ? { dataset: { detailFeedback: "real" } }
          : null,
    },
  });
  await harness.settle();

  harness.dispatchKey("Escape");
  await harness.settle();

  const state = harness.api.state();
  assert.equal(state.browsingHistory, true, "historical context was discarded");
  assert.equal(state.currentVerdicts.length, 2, "historical rows were dropped");
  const row = state.currentVerdicts.find((entry) => entry.id === historical.id);
  assert.equal(row.human_verdict, "real");
  assert.equal(row.human_notes, "kept from the historical page");

  // The one-key agree action must now refuse to write again.
  const postsBefore = harness.fetchCalls.filter(({ url }) =>
    url.includes("/api/v1/feedback/"),
  ).length;
  const index = state.currentVerdicts.findIndex((entry) => entry.id === historical.id);
  harness.document.getElementById("verdicts").dispatch("focusin", {
    target: { closest: () => ({ dataset: { idx: String(index) } }) },
  });
  harness.dispatchKey("a");
  harness.dispatchKey("u");
  await harness.settle();
  assert.equal(
    harness.fetchCalls.filter(({ url }) => url.includes("/api/v1/feedback/")).length,
    postsBefore,
    "a second feedback write was submitted",
  );
});

test("a pre-commit queue read cannot beat a resolving feedback write", async () => {
  const harness = runDashboard({
    pathname: "/triage",
    defer: (url) => url.includes("/api/v1/feedback/"),
  });
  await harness.settle();
  const target = harness.api.state().currentVerdicts[0];

  harness.api.open(target.id);
  await harness.settle();
  harness.document.getElementById("detailNotes").value = "notes that must survive";
  harness.document.getElementById("detailPageContent").dispatch("click", {
    target: {
      closest: (selector) =>
        selector === "[data-detail-feedback]"
          ? { dataset: { detailFeedback: "real" } }
          : null,
    },
  });
  await harness.settle();
  assert.equal(harness.deferred.length, 1, "the write should still be pending");

  // Back to the queue. This read happens before the write commits, so it
  // returns the row as unreviewed.
  harness.dispatchKey("Escape");
  await harness.settle();
  assert.equal(harness.api.state().currentVerdicts[0].human_verdict, null);

  // Now the write commits.
  harness.releaseDeferred();
  await harness.settle();

  const row = harness.api.state().currentVerdicts.find(
    (entry) => entry.id === target.id,
  );
  assert.equal(row.human_verdict, "real", "the stale pre-commit read won");
  assert.equal(row.human_notes, "notes that must survive");
  // The visible queue must be reconciled too, not just the in-memory array:
  // the rendered row was painted from the pre-commit read.
  assert.match(
    harness.document.getElementById("verdicts").innerHTML,
    /agreed/,
    "the rendered queue still shows the pre-commit state",
  );

  const postsBefore = harness.fetchCalls.filter(({ url }) =>
    url.includes("/api/v1/feedback/"),
  ).length;
  harness.document.getElementById("verdicts").dispatch("focusin", {
    target: { closest: () => ({ dataset: { idx: "0" } }) },
  });
  harness.dispatchKey("a");
  await harness.settle();
  assert.equal(
    harness.fetchCalls.filter(({ url }) => url.includes("/api/v1/feedback/")).length,
    postsBefore,
  );
});

test("reviewing from the historical queue repaints without discarding history", async () => {
  const harness = runDashboard({ pathname: "/triage" });
  await harness.settle();

  await harness.api.loadOlder();
  await harness.settle();
  const loaded = harness.api.state().currentVerdicts;
  assert.equal(loaded.length, 2);
  assert.equal(harness.api.state().browsingHistory, true);

  // Agree on the historical row straight from the queue.
  harness.document.getElementById("verdicts").dispatch("focusin", {
    target: { closest: () => ({ dataset: { idx: "1" } }) },
  });
  harness.dispatchKey("a");
  await harness.settle();

  const state = harness.api.state();
  assert.equal(state.browsingHistory, true, "history was discarded on review");
  assert.equal(state.currentVerdicts.length, 2, "historical pages were dropped");
  assert.equal(state.currentVerdicts[1].human_verdict, "real");
  // Repainted from the patched rows rather than left showing the old state.
  assert.match(
    harness.document.getElementById("verdicts").innerHTML,
    /agreed/,
    "the historical queue was not repainted after the write",
  );
  assert.match(
    harness.document.getElementById("verdicts").innerHTML,
    /row-llm-older-1/,
    "historical rows disappeared from the rendered queue",
  );
});

test("a duplicate feedback submission while one is pending is ignored", async () => {
  const harness = runDashboard({
    pathname: "/triage",
    verdicts: [
      { id: 11, verdict: "real", signature: "one", confidence: 0.5, human_verdict: null },
    ],
    defer: (url) => url.includes("/api/v1/feedback/"),
  });
  await harness.settle();

  harness.document.getElementById("verdicts").dispatch("focusin", {
    target: { closest: () => ({ dataset: { idx: "0" } }) },
  });
  harness.dispatchKey("a");
  await harness.settle();
  harness.dispatchKey("a");
  harness.dispatchKey("u");
  await harness.settle();

  assert.equal(
    harness.fetchCalls.filter(({ url }) => url.includes("/api/v1/feedback/11")).length,
    1,
    "a duplicate write was submitted while the first was pending",
  );

  // Once it settles, the event leaves the pending set.
  harness.releaseDeferred();
  await harness.settle();
  assert.equal(harness.api.state().currentVerdicts[0].human_verdict, "real");
});

test("a feedback completion never remounts a different detail page", async () => {
  const harness = runDashboard({
    pathname: "/triage",
    verdicts: [
      { id: 11, verdict: "real", signature: "one", confidence: 0.5, human_verdict: null },
    ],
    defer: (url) => url.includes("/api/v1/feedback/"),
  });
  await harness.settle();

  harness.api.open(11);
  await harness.settle();
  harness.document.getElementById("detailPageContent").dispatch("click", {
    target: {
      closest: (selector) =>
        selector === "[data-detail-feedback]"
          ? { dataset: { detailFeedback: "real" } }
          : null,
    },
  });
  await harness.settle();

  // Move to a different alert and start a draft there.
  harness.api.open(33);
  await harness.settle();
  const notes = harness.document.getElementById("detailNotes");
  const sentinel = "draft belonging to alert 33";
  notes.value = sentinel;
  const detail = harness.document.getElementById("detailPageContent");
  const writesBefore = detail.innerHTMLWrites;
  const fetchesBefore = routeFetchUrls(harness).length;

  harness.releaseDeferred();
  await harness.settle();

  assert.equal(notes.value, sentinel);
  assert.equal(detail.innerHTMLWrites, writesBefore);
  assert.equal(harness.api.state().activeDetail.id, 33);
  assert.equal(routeFetchUrls(harness).length, fetchesBefore);
});

function clickDetailFeedback(harness, verdict = "real") {
  harness.document.getElementById("detailPageContent").dispatch("click", {
    target: {
      closest: (selector) =>
        selector === "[data-detail-feedback]"
          ? { dataset: { detailFeedback: verdict } }
          : null,
    },
  });
}

function feedbackPosts(harness) {
  return harness.fetchCalls
    .filter(({ url }) => url.includes("/api/v1/feedback/"))
    .map(({ url }) => url);
}

test("controls from the previous alert are retired the moment navigation starts", async () => {
  const harness = runDashboard({
    pathname: "/triage",
    defer: (url) => /\/api\/v1\/verdicts\/8(\/investigation)?(\?|$)/.test(url),
  });
  await harness.settle();

  // Alert 7 is fully rendered and interactive.
  harness.api.open(7);
  await harness.settle();
  assert.equal(harness.api.state().activeDetail.id, 7);
  harness.document.getElementById("detailNotes").value = "notes for seven";

  // Navigate to alert 8; its responses are held open.
  harness.api.open(8);
  await harness.settle();
  assert.equal(harness.location.pathname, "/triage/8");

  const state = harness.api.state();
  assert.equal(state.activeDetail, null, "the previous alert stayed active");
  assert.equal(state.activeInvestigation, null);
  assert.match(
    harness.document.getElementById("detailPageContent").innerHTML,
    /Loading alert detail/,
    "the previous alert's controls are still mounted",
  );
  assert.equal(harness.document.getElementById("previousAlertButton").disabled, true);
  assert.equal(harness.document.getElementById("nextAlertButton").disabled, true);
  assert.equal(harness.document.getElementById("previousAlertButton").dataset.eventId, "");

  // Activating the former feedback control must write nothing at all.
  clickDetailFeedback(harness);
  await harness.settle();
  assert.deepEqual(feedbackPosts(harness), [], "a stale control issued a write");

  // Once alert 8 has rendered, feedback works normally and targets 8.
  harness.releaseDeferred();
  await harness.settle();
  assert.equal(harness.api.state().activeDetail.id, 8);
  clickDetailFeedback(harness);
  await harness.settle();
  assert.deepEqual(feedbackPosts(harness), ["/api/v1/feedback/8"]);
});

test("a detail-to-detail popstate retires the previous alert's controls", async () => {
  const harness = runDashboard({
    pathname: "/triage",
    defer: (url) => /\/api\/v1\/verdicts\/8(\/investigation)?(\?|$)/.test(url),
  });
  await harness.settle();

  harness.api.open(7);
  await harness.settle();
  assert.equal(harness.api.state().activeDetail.id, 7);

  harness.goBackTo("/triage/8?model=llm");
  await harness.settle();

  assert.equal(harness.api.state().activeDetail, null);
  assert.equal(harness.document.getElementById("nextAlertButton").disabled, true);
  clickDetailFeedback(harness);
  await harness.settle();
  assert.deepEqual(feedbackPosts(harness), []);

  harness.releaseDeferred();
  await harness.settle();
  assert.equal(harness.api.state().activeDetail.id, 8);
  clickDetailFeedback(harness);
  await harness.settle();
  assert.deepEqual(feedbackPosts(harness), ["/api/v1/feedback/8"]);
});

test("feedback refuses an id that does not match the routed alert", async () => {
  const harness = runDashboard({ pathname: "/triage" });
  await harness.settle();

  harness.api.open(7);
  await harness.settle();

  // Write-side guard: neither a stale id nor a missing one may be sent.
  await harness.api.feedback(8, "real");
  await harness.api.feedback(undefined, "real");
  await harness.api.feedback(NaN, "real");
  await harness.settle();
  assert.deepEqual(feedbackPosts(harness), []);

  await harness.api.feedback(7, "real");
  await harness.settle();
  assert.deepEqual(feedbackPosts(harness), ["/api/v1/feedback/7"]);
});

test("a keyboard-focused queue card keeps focus across a scheduled refresh", async () => {
  const harness = runDashboard({
    pathname: "/triage",
    verdicts: [
      { id: 22, verdict: "real", signature: "twenty-two", confidence: 0.5 },
      { id: 33, verdict: "real", signature: "thirty-three", confidence: 0.5 },
    ],
  });
  await harness.settle();

  harness.focusCard(22);
  assert.equal(harness.activeEventId(), 22);
  assert.equal(harness.api.state().focusedIndex, 0);

  // A newer alert arrives ahead of it, so its index moves.
  harness.setVerdicts([
    { id: 44, verdict: "real", signature: "forty-four", confidence: 0.5 },
    { id: 22, verdict: "real", signature: "twenty-two", confidence: 0.5 },
    { id: 33, verdict: "real", signature: "thirty-three", confidence: 0.5 },
  ]);
  // Through the real scheduled poll, not a direct render call.
  harness.tick();
  await harness.settle();

  assert.equal(harness.activeEventId(), 22, "focus was lost on refresh");
  assert.equal(harness.api.state().focusedIndex, 1, "focusedIndex did not follow");
  assert.equal(
    harness.document.getElementById("verdicts").cardFor(22).focusOptions?.preventScroll,
    true,
  );

  // Enter must open the alert that is actually focused.
  harness.dispatchKey("Enter");
  await harness.settle();
  assert.match(String(harness.pushedUrls.at(-1)), /^\/triage\/22\?/);
});

// Three unreviewed rows; J moves the logical selection without giving any card
// DOM focus, which is the case the Tab-focus restoration does not cover.
function queueOfThree() {
  return [
    { id: 11, verdict: "real", signature: "eleven", confidence: 0.5, human_verdict: null },
    { id: 22, verdict: "real", signature: "twenty-two", confidence: 0.5, human_verdict: null },
    { id: 33, verdict: "real", signature: "thirty-three", confidence: 0.5, human_verdict: null },
  ];
}

async function selectEvent22WithoutDomFocus(harness) {
  harness.dispatchKey("j");
  await harness.settle();
  assert.equal(harness.api.state().focusedIndex, 1);
  assert.equal(harness.api.state().currentVerdicts[1].id, 22);
  assert.equal(harness.activeEventId(), null, "this case must not use DOM focus");
}

test("a J/K selection follows its alert when a refresh inserts a row", async () => {
  const harness = runDashboard({ pathname: "/triage", verdicts: queueOfThree() });
  await harness.settle();
  await selectEvent22WithoutDomFocus(harness);

  harness.setVerdicts([
    { id: 44, verdict: "real", signature: "forty-four", confidence: 0.5, human_verdict: null },
    ...queueOfThree(),
  ]);
  harness.tick();
  await harness.settle();

  assert.equal(
    harness.api.state().focusedIndex,
    2,
    "the selection did not follow event 22 to its new position",
  );
  assert.equal(harness.api.state().currentVerdicts[2].id, 22);

  harness.dispatchKey("Enter");
  await harness.settle();
  assert.match(String(harness.pushedUrls.at(-1)), /^\/triage\/22\?/);
});

test("A after an inserting refresh writes only to the selected alert", async () => {
  const harness = runDashboard({ pathname: "/triage", verdicts: queueOfThree() });
  await harness.settle();
  await selectEvent22WithoutDomFocus(harness);

  harness.setVerdicts([
    { id: 44, verdict: "real", signature: "forty-four", confidence: 0.5, human_verdict: null },
    ...queueOfThree(),
  ]);
  harness.tick();
  await harness.settle();

  harness.dispatchKey("a");
  await harness.settle();
  assert.deepEqual(feedbackPosts(harness), ["/api/v1/feedback/22"]);
});

test("U after an inserting refresh writes only to the selected alert", async () => {
  const harness = runDashboard({ pathname: "/triage", verdicts: queueOfThree() });
  await harness.settle();
  await selectEvent22WithoutDomFocus(harness);

  harness.setVerdicts([
    { id: 44, verdict: "real", signature: "forty-four", confidence: 0.5, human_verdict: null },
    ...queueOfThree(),
  ]);
  harness.tick();
  await harness.settle();

  harness.dispatchKey("u");
  await harness.settle();
  assert.deepEqual(feedbackPosts(harness), ["/api/v1/feedback/22"]);
});

test("a selection whose alert disappears is not carried onto another one", async () => {
  const harness = runDashboard({ pathname: "/triage", verdicts: queueOfThree() });
  await harness.settle();
  await selectEvent22WithoutDomFocus(harness);

  // Event 22 leaves the results entirely.
  harness.setVerdicts([
    { id: 11, verdict: "real", signature: "eleven", confidence: 0.5, human_verdict: null },
    { id: 33, verdict: "real", signature: "thirty-three", confidence: 0.5, human_verdict: null },
  ]);
  harness.tick();
  await harness.settle();

  const state = harness.api.state();
  assert.ok(!state.currentVerdicts.some((row) => row.id === 22));
  assert.ok(state.focusedIndex < state.currentVerdicts.length, "index left out of range");

  // Whatever is now selected, it must not be treated as event 22.
  harness.dispatchKey("a");
  await harness.settle();
  assert.ok(
    !feedbackPosts(harness).includes("/api/v1/feedback/22"),
    "a write was attributed to the alert that disappeared",
  );

  harness.dispatchKey("Enter");
  await harness.settle();
  assert.doesNotMatch(String(harness.pushedUrls.at(-1)), /^\/triage\/22(\?|$)/);
});

test("a queue refresh does not steal focus from the search field", async () => {
  const harness = runDashboard({
    pathname: "/triage",
    verdicts: [{ id: 22, verdict: "real", signature: "twenty-two", confidence: 0.5 }],
  });
  await harness.settle();

  const search = harness.document.getElementById("sigFilter");
  search.focus();
  assert.equal(harness.document.activeElement, search);

  harness.setVerdicts([
    { id: 44, verdict: "real", signature: "forty-four", confidence: 0.5 },
    { id: 22, verdict: "real", signature: "twenty-two", confidence: 0.5 },
  ]);
  harness.tick();
  await harness.settle();

  assert.equal(
    harness.document.activeElement,
    search,
    "the queue renderer stole focus from the search field",
  );
  assert.equal(harness.activeEventId(), null);
});

test("a refresh that drops the focused alert does not focus another card", async () => {
  const harness = runDashboard({
    pathname: "/triage",
    verdicts: [
      { id: 22, verdict: "real", signature: "twenty-two", confidence: 0.5 },
      { id: 33, verdict: "real", signature: "thirty-three", confidence: 0.5 },
    ],
  });
  await harness.settle();

  const card = harness.focusCard(22);
  assert.equal(harness.activeEventId(), 22);

  harness.setVerdicts([
    { id: 33, verdict: "real", signature: "thirty-three", confidence: 0.5 },
  ]);
  harness.tick();
  await harness.settle();

  // Focus stays on the now-detached card rather than jumping to an unrelated
  // alert; the browser would drop it to the document.
  assert.equal(harness.document.activeElement, card);
  assert.equal(
    harness.document.getElementById("verdicts").cardFor(33).focused,
    false,
    "an unrelated card was focused",
  );
});

test("queue badge counts declare their global 24h scope", () => {
  const html = fs.readFileSync(path.join(STATIC_DIR, "index.html"), "utf8");
  const script = readDashboardScript();

  // The badges come from /api/v1/stats, which is a global 24h rollup, so the
  // page must not let them read as counts of the filtered or paged rows.
  assert.match(html, /aria-describedby="queueScopeNote"/);
  assert.match(html, /id="queueScopeNote"/);
  const note = html.match(
    /id="queueScopeNote"[^>]*>([\s\S]*?)<\/p>/,
  )?.[1];
  assert.ok(note, "queue scope note is missing");
  assert.match(note, /global totals/i);
  assert.match(note, /last 24 hours/i);
  // Must stay true when a Policy, source, or review filter is selected.
  assert.match(note, /Policy, source, and review filters/i);
  assert.match(note, /never change them/i);

  // The sidebar badge carries the same scope for assistive technology.
  assert.match(
    html,
    /id="sidebarQueueCount"[^>]*title="Unreviewed model decisions in the last 24 hours, across all filters"/,
  );
  assert.match(html, /<span class="sr-only">unreviewed model decisions in the last 24 hours, across all filters<\/span>/);

  // The queue meta line separates the page count from the global count.
  assert.match(script, /decisions loaded on this page/);
  assert.match(script, /unreviewed in the last 24h, all filters/);
});

test("the queue search advertises signature, IP, and historical asset lookup", () => {
  const html = fs.readFileSync(path.join(STATIC_DIR, "index.html"), "utf8");

  assert.match(
    html,
    /id="sigFilter"[^>]*placeholder="signature, IP, or asset…"/,
  );
  assert.match(html, /<span class="sr-only">Search alerts by signature, IP address, or historical asset hostname<\/span>/);
  assert.doesNotMatch(html, /placeholder="[^"]*rule id/);
  // The shortcut legend must describe what D now does.
  assert.match(html, /<kbd>D<\/kbd> Review/);
  assert.doesNotMatch(html, /<kbd>D<\/kbd> Correct/);
});

test("the queue reports when search excludes older retained alerts", async () => {
  const harness = runDashboard({
    pathname: "/triage",
    search: "?model=llm&signature=missing",
    searchScope: {
      candidate_limit: 10_000,
      candidates_in_scope: 10_000,
      truncated: true,
    },
  });
  await harness.settle();

  assert.deepEqual(
    harness.api.state().queueSearchScope,
    {
      candidate_limit: 10_000,
      candidates_in_scope: 10_000,
      truncated: true,
    },
  );
  assert.match(
    harness.document.getElementById("queueMeta").textContent,
    /search covers newest 10,000 retained alerts; older alerts not examined/,
  );

  harness.api.setFilter("signature", "");
  harness.api.applyFilters();
  await harness.settle();
  assert.equal(harness.api.state().queueSearchScope, null);
  assert.doesNotMatch(
    harness.document.getElementById("queueMeta").textContent,
    /search covers/,
  );
});

test("overview uses a truthful policy-to-model decision band", () => {
  const staticDir = path.join(
    __dirname,
    "..",
    "triagewall",
    "dashboard",
    "static",
  );
  const html = fs.readFileSync(path.join(staticDir, "index.html"), "utf8");
  const script = fs.readFileSync(path.join(staticDir, "dashboard.js"), "utf8");

  assert.match(html, /id="prefilterRate"/);
  assert.match(html, /id="policyBand"/);
  assert.match(html, /Includes deterministic policy/);
  assert.match(script, /stats\.today_prefilter/);
  assert.match(script, /stats\.today_llm/);
  assert.match(script, /stats\.model_real_count/);
  assert.match(script, /stats\.unreviewed_model_count/);
});

// --- Redacted asset handoffs -------------------------------------------------
// With IP redaction enabled the API returns documented pseudonyms ("ip_" plus
// exactly 32 lowercase hex characters) in src_ip/dest_ip and withholds
// asset_context. A pseudonym is not an address, so an asset candidate seeded
// from one cannot validate. The button must disappear, and because a button is
// only an affordance, the handoff path must refuse independently.

const REDACTED_SOURCE = `ip_${"a".repeat(32)}`;
const REDACTED_DESTINATION = `ip_${"0123456789abcdef".repeat(2)}`;

async function openDetailWith(detailVerdict) {
  const harness = runDashboard({ pathname: "/triage", detailVerdict });
  await harness.settle();
  harness.api.open(7);
  await harness.settle();
  return harness;
}

test("a redacted source pseudonym hides the source asset action", async () => {
  const harness = await openDetailWith({
    src_ip: REDACTED_SOURCE,
    dest_ip: "203.0.113.10",
  });
  const html = harness.document.getElementById("detailPageContent").innerHTML;

  assert.doesNotMatch(html, /data-config-from-alert="asset-source"/);
  assert.match(html, /data-config-from-alert="asset-destination"/);
});

test("a redacted destination pseudonym hides the destination asset action", async () => {
  const harness = await openDetailWith({
    src_ip: "203.0.113.10",
    dest_ip: REDACTED_DESTINATION,
  });
  const html = harness.document.getElementById("detailPageContent").innerHTML;

  assert.doesNotMatch(html, /data-config-from-alert="asset-destination"/);
  assert.match(html, /data-config-from-alert="asset-source"/);
});

test("a real address with no asset context still offers the asset action", async () => {
  const harness = await openDetailWith({
    src_ip: "203.0.113.10",
    dest_ip: "203.0.113.11",
    asset_context: null,
  });
  const html = harness.document.getElementById("detailPageContent").innerHTML;

  // Unknown assets are exactly the ones an operator most wants to add.
  assert.match(html, /data-config-from-alert="asset-source"/);
  assert.match(html, /data-config-from-alert="asset-destination"/);
});

test("prefilter handoff survives IP redaction when its own fields are present", async () => {
  const harness = await openDetailWith({
    src_ip: REDACTED_SOURCE,
    dest_ip: REDACTED_DESTINATION,
    signature_id: 2010935,
    sensor_context: { source: "suricata" },
  });
  const html = harness.document.getElementById("detailPageContent").innerHTML;

  // The prefilter rule is keyed by signature, not by address.
  assert.match(html, /data-config-from-alert="prefilter"/);
  assert.doesNotMatch(html, /data-config-from-alert="asset-source"/);
  assert.doesNotMatch(html, /data-config-from-alert="asset-destination"/);
});

for (const [side, action] of [
  ["source", "asset-source"],
  ["destination", "asset-destination"],
]) {
  test(`a directly invoked ${side} asset handoff on a redacted address is refused`, async () => {
    const harness = await openDetailWith({
      src_ip: REDACTED_SOURCE,
      dest_ip: REDACTED_DESTINATION,
    });
    const pushesBefore = harness.pushedUrls.length;
    const stateBefore = harness.api.state();

    // Stale markup or a direct call must not reach the editor.
    harness.api.configFromAlert(action);
    await harness.settle();

    assert.deepEqual(harness.configEditorCalls, []);
    assert.equal(harness.pushedUrls.length, pushesBefore);
    assert.ok(!harness.pushedUrls.some((url) => String(url).includes("/configuration")));
    assert.ok(!harness.location.pathname.startsWith("/configuration"));
    assert.equal(harness.api.state().activeDetail?.id, stateBefore.activeDetail?.id);
  });
}

test("an unredacted asset handoff still reaches the configuration editor", async () => {
  const harness = await openDetailWith({
    src_ip: "203.0.113.10",
    dest_ip: "203.0.113.11",
  });

  harness.api.configFromAlert("asset-source");
  await harness.settle();

  assert.ok(
    harness.configEditorCalls.some(
      (entry) => entry.call === "seedFromAlert" && entry.action === "asset-source",
    ),
  );
  assert.ok(harness.pushedUrls.some((url) => String(url).includes("/configuration")));
});

test("only the documented pseudonym format counts as redacted", async () => {
  // Arbitrary "ip_" strings are ordinary values and must not be suppressed.
  const harness = await openDetailWith({
    src_ip: "ip_not-a-pseudonym",
    dest_ip: `ip_${"A".repeat(32)}`,
  });
  const html = harness.document.getElementById("detailPageContent").innerHTML;

  assert.match(html, /data-config-from-alert="asset-source"/);
  assert.match(html, /data-config-from-alert="asset-destination"/);
});
