# TriageWall Roadmap

TriageWall started as a way to make a homelab IDS usable again: reduce
thousands of Suricata alerts to the handful worth reviewing. The longer-term
goal is a local-first **homelab security awareness platform** that surfaces
what matters across sensors without requiring the operator to remember to
check several dashboards.

The product strategy remains consistent:

- **Integrate, do not reinvent.** Suricata, Wazuh, Zeek, Pi-hole, OpenVAS, and
  Garak provide detection, collection, scanning, and adversarial probes.
  TriageWall adds local reasoning, prioritization, correlation, and release
  evidence.
- **Keep operational triage independent.** TriageWall Core must remain useful
  without optional evaluation or awareness components.
- **Require human approval for behavior changes.** Automation may test and
  report a prompt, policy, model, or threshold change; it does not silently
  promote, roll back, or tune production behavior.

Release dates below are the existing targets, not commitments. Current status,
prerequisites, and evidence determine delivery order.

---

## Shipped

### v0.1 — May 2026

Initial public release.

- [x] Two-tier classification: tunable prefilter plus a local Ollama model
- [x] Live Suricata `eve.json` ingest with durable checkpoints
- [x] Dashboard with real-time verdicts, trends, health, and feedback
- [x] Demo mode and Docker Compose deployment
- [x] Configurable Ollama backend
- Posted to r/homelab and listed on
  [satta/awesome-suricata](https://github.com/satta/awesome-suricata).

### v0.2-alpha — May 22, 2026

- [x] Foundation-Sec-8B-Instruct as the production model
- [x] Evidence-driven system-prompt revision
- [x] Reproducible benchmark harness and labeled gold set
- Revising the prompt moved Foundation-Sec Q5_K_M from κ=0.210 to κ=0.687
  and from 0% to 83% true-positive recall on that set.

### v0.2 — May 25, 2026

Prompt-injection and operational hardening.

- [x] Per-process canary detection and strict response-schema validation
- [x] Fail-closed field isolation: only typed, allowlisted sensor metadata is
  trusted; unknown and free-text evidence is isolated by default
- [x] SQLite WAL mode, bounded automatic checkpointing, and busy timeouts
- [x] Mounted, validated prefilter configuration

---

## Current and planned

### Post-v0.2 hardening in the current tree

- [x] Durable quarantine for malformed and failed ingest records
- [x] Checkpoint advancement only after a durable process or intentional skip
- [x] Trusted-host validation and complete demo-mode redaction
- [x] Required regression CI, CodeQL, and Dependabot

### v0.2.1 — June 2026

Hardening work retained from the original roadmap.

- Moved: **Garak injection gate** — see
  [Adversarial probing (post-v0.3)](#adversarial-probing-post-v03). It is **not**
  a prerequisite for v0.3, which makes no Garak or adversarial-probe claim.
- [ ] Improve the URL-injection verdict from a conservative `uncertain` result
  to an explicit `real` verdict with the injection attempt identified.
- [ ] Refresh the architecture diagram for Foundation-Sec, scoped prefiltering,
  multi-source isolation, asset context, and the Core/Lab boundary.

### v0.3 — July–August 2026

Multi-sensor Core is implemented and deployed in the maintainer environment.
The operational and release gates below are complete: the gold-set baseline is
calibrated and the calibrated gate passes, and all five required release-evidence
scenarios are recorded in
[docs/release-evidence-v0.3.md](docs/release-evidence-v0.3.md). v0.3 was
[released on August 9, 2026](https://github.com/aaronphifer/triagewall/releases/tag/v0.3).
Adversarial probing is explicitly out of v0.3 scope; see
[Adversarial probing (post-v0.3)](#adversarial-probing-post-v03).

#### Implemented

- [x] **Exact-IP asset inventory enrichment** with validated private mounts,
  trusted prompt context, immutable revisioned snapshots, and API redaction
- [x] **Scoped Suricata prefilter policy** using direction, CIDR, protocol,
  ports, and asset context
- [x] **Multi-source event and persistence contract** with transactional source
  provenance and duplicate protection
- [x] **Optional Wazuh integration** through a read-only local alert volume,
  level-based admission, source-aware isolation, durable checkpoints, and
  compressed-rotation recovery
- [x] **Source-aware dashboard and API** for Suricata and Wazuh verdicts
- [x] **Versioned authenticated API** with scoped keys, bounded pagination,
  runtime-validated response contracts, caching, metrics, and optional keyed IP
  pseudonymization
- [x] **Reliability closeout** for incomplete records, retryable model/database
  failures, UTC timestamps, atomic checkpoints, fail-closed Suricata rotation,
  bounded dashboard queries, startup indexes, explicit WAL policy, and locked
  dashboard dependencies

#### Closeout

- [x] **Retention policy and storage visibility.** Define a safe hot-data
  window, archive or prune workflow, operator controls, and database-size
  reporting. Do not apply an unbounded delete to a live database.
- [x] **Serialized migration phase.** Ensure one startup owner performs schema
  work before Suricata and optional Wazuh ingest begin, avoiding lock races on
  large databases.
- [x] **Release evidence.** Record supported fresh-install, upgrade, rollback,
  Core-only, and Core-plus-Wazuh checks before tagging v0.3. All five are
  recorded in [docs/release-evidence-v0.3.md](docs/release-evidence-v0.3.md),
  collected on the maintainer host against commit `9b95bf00`, together with a
  passing calibrated gold-set gate verified against the real private asset
  inventory. Upgrade and rollback are evidenced across the real release
  boundary — released `v0.2` (`2ec506c9`) → v0.3 candidate and back — using a
  v0.2-origin database, not a transition between runtime-equivalent v0.3
  development commits.
- [x] **Gold-set change-validation implementation.** Fingerprint production
  behavior deterministically, evaluate the real pipeline against human labels,
  validate evidence integrity, and compare both pipeline and model-only metrics.
- [x] **Gold-set calibration.** Approved the complete 266-alert operator
  evaluation as the v0.3 baseline, with fail-closed inventory identity checks,
  zero invalid output, and `0.05` maximum decreases for Cohen's kappa and
  true-positive recall in both metric scopes.

#### Adversarial probing (post-v0.3)

**Maintainer scope decision.** Garak does not block v0.3. Both the initial
full-pipeline Garak gate and its multi-source extension are post-v0.3 work, and
**v0.3 makes no Garak or adversarial-probe claim** — the release-evidence
document records that scenario as `NOT IMPLEMENTED / NOT RUN`. This is a
deliberate scope decision, not a waiver of a check that was attempted.

Nothing here is implemented today: the repository contains no Garak runner,
configuration, or probe set, so there is no Garak result to report. This work is
tracked separately from the deterministic gold-set gate, which is a behaviour
and performance gate over human labels and makes no adversarial claim. The two
fail for different reasons and need different review.

- [ ] **Garak injection gate (full isolated pipeline).** Exercise the complete
  isolated TriageWall pipeline rather than the bare model. A regression is
  blocked and reported for human review. Once implemented it should run
  periodically **and before applicable future releases** — especially any
  release that changes the model, the prompts, field isolation, or the source
  projections.
- [ ] **Extend Garak coverage across the multi-source pipeline.**

  Delivering the two items above requires:
  - a pinned Garak runner and configuration with recorded versions;
  - a harness driving the **full isolated pipeline**, not the bare model;
  - probe coverage of **both** projection surfaces, Suricata and Wazuh, which
    build different prompts from different fields;
  - deterministic gate criteria — which probes block, what attack-success
    threshold fails the build, and how flaky probes are handled;
  - defined failure handling: fail-closed behaviour, reporting, and regression
    triage;
  - CI and release integration, including how a model-dependent suite runs when
    required CI has no GPU or Ollama.

- [ ] Extend the existing canary and prompt-boundary regressions to the Wazuh
  projection path. Deterministic regression coverage, **not** Garak; currently
  Suricata-only.

- [ ] **Tested checkpoint-reconciliation tool and restore runbook.** Suricata
  source/checkpoint disaster recovery is currently **unvalidated**. Restoring a
  backup copies `eve.json`, which allocates a new inode, so a restored
  `position.json` names an identity that no longer exists; copying both files
  together does **not** resolve this. v0.3 fails closed by design. The prior
  release only appears to cope because it restarts the file from byte zero,
  replaying every record — that is not a recovery mechanism and must not be
  documented as one. Deliver:
  - a supported reconciliation step an operator runs **before** starting ingest
    after a restore, with the resulting alert gap explicitly recorded;
  - **bounded replay** or recorded-gap handling, so recovery never means
    re-triaging an entire `eve.json` and never relies on duplicate detection as
    a replay guarantee (flow-less alerts are not covered by it);
  - tests covering restore-then-resume for both sources.

  Direct same-host version switching, where file identity is intact, already
  works and is evidenced in
  [docs/release-evidence-v0.3.md](docs/release-evidence-v0.3.md).

#### Operational usability and provenance

- [ ] **Bounded alert detail.** Show the complete stored evidence projection,
  sensor and agent provenance, asset snapshots, policy outcome, model identity,
  validation result, and related context without scanning unbounded history.
- [ ] **Investigation controls.** Add source, time, IP, subnet, and asset
  filters, then saved views and structured JSON/CSV export.
- [x] **Portable event-bundle v1 Phase 0 contract.** Define and validate a
  sanitized, integrity-protected contract that can reproduce a decision
  without direct access to the production database or sensor logs. Core export
  remains a separate milestone below.
- [ ] **Bounded asynchronous LLM queue.** Decouple checkpointed intake from
  model latency only after overload, retry, ordering, and recovery semantics
  are explicit.

### TriageWall Core and Lab — accepted product direction

TriageWall will mature as one product family with two independently runnable
applications. See
[Core and Lab product boundary](docs/core-lab-product-boundary.md).

- [x] **Product boundary accepted.** Core remains the production-supported
  operational application. Lab is the replay, evaluation, and release-
  validation application.
- [x] **One professional finished product.** There will be one public
  repository, documentation site, issue tracker, and coordinated release
  experience after Lab graduates.
- [ ] **Complete Core provenance and event-bundle v1** before Lab development
  depends on the contract.
- [ ] **Add operator-confirmed sanitized export** from Core. Lab never mounts
  Core's database, sensor logs, inventory, or checkpoints.
- [ ] **Incubate Lab privately** while its interfaces, upload handling, and
  threat model are experimental. Unfinished Lab code does not ship to Core
  users.
- [ ] **Ship a standalone Lab interface** that can evaluate compatible bundles,
  bounded offline Suricata or Wazuh fixtures, and sanitized scenarios without
  running Core.
- [ ] **Prove all three installation modes:** Core only by default, Lab only,
  and an explicitly enabled combined suite.
- [ ] **Graduate Lab into this repository** only after hostile-input,
  separation, CI, upgrade, rollback, backup, removal, and user-documentation
  gates pass. Archive the private incubation repository after import.

### v0.4 — Analyst workbench — August 2026

Turn the alert queue into a source-aware investigation and configuration
workbench without weakening the production boundary.

- [x] **Dashboard UI foundation.** Ship the routed overview, triage,
  behavioural, integrity, and alert-detail surfaces while preserving the
  source-aware API and security contracts.
- [x] **Investigation context and correlation.** Add bounded recurrence,
  related activity, source-specific evidence, and queue-aware navigation as
  detailed below.
- [x] **Versioned operator-configuration foundation.** Separate immutable
  shipped defaults from operator revisions and add drafts, validation, bounded
  impact preview, atomic activation, optimistic locking, last-known-good
  recovery, rollback, and audit history. See
  [Operator configuration foundation](docs/operator-configuration-foundation.md).
  Persistence, authorization, immutable drafts, validation, bounded previews,
  atomic authority cutover, generation-aware last-known-good reload, audited
  rollback, truthful consumer health, and per-verdict bundle provenance are
  delivered alongside the operator editors and release-hardening coverage.
- [x] **Dedicated configuration authorization.** Keep mutation disabled by
  default and require an attributable API key with `config:write`; the
  dashboard feedback cookie is not administrator authentication.
- [x] **Prefilter rule editor.** Draft scoped rules from an alert, preview the
  exact document and bounded historical impact, warn on broad matches, and
  require explicit activation for future events.
- [x] **Private asset-enrichment editor.** Manage exact-IP hostname, role,
  criticality, exposure, and port context while preserving immutable snapshots
  used by historical verdicts.
- [x] **Unified analyst actions.** Connect feedback, related-alert filtering,
  rule drafting, asset editing, and bounded evidence copying from the alert
  workbench.
- [x] **Bounded retained-alert search.** Search by signature, exact IP address,
  or historical asset hostname with a disclosed candidate window, query
  deadline, stable pagination identity, and queue-aware investigation reuse.
- [x] **Guided configuration-key onboarding.** Generate a one-time plaintext
  key and Compose-safe hash-only `config:write` record without external
  dependencies.
- [x] **Release hardening.** Cover authorization, audit, concurrency, atomic
  activation, reload failure, rollback, both sensor paths, browser behaviour,
  field isolation, and canary regressions before tagging v0.4.

#### Analyst investigation context — delivered

The routed alert-detail page is the first functional investigation surface. It
reads only what TriageWall already persists; no schema change, no new index,
and no new sensor field were introduced.

- [x] **Recurrence for the selected alert.** Occurrence count, first and latest
  occurrence, and verdict distribution inside a bounded window.
- [x] **Related activity** by rule, source address, and destination address,
  each stating why it is related.
- [x] **Queue-aware navigation.** The complete queue query string travels
  through the detail page, previous/next, and the back link, and neighbours are
  resolved server-side against every filter the list endpoint supports — so
  previous/next now work on a deep link or refresh, which the client-side
  implementation could not do.
- [x] **Source-aware presentation.** Wazuh rule, agent, manager, location, and
  decoder context is presented separately from the Suricata flow envelope.
  Neither is forced into the other's labels.

**Exact versus navigational.** All correlation views examine at most 2,000 of
the newest events in the requested window, selected through the `processed_at`
index. Recurrence and the same-rule group use equality on
`(source type, signature id)` inside that candidate set. Qualifying by source
type is required for correctness, not neatness — Suricata keeps its SID and
Wazuh keeps `rule.id` in the same column. Their counts are exact only when the
candidate query exhausts the window; otherwise they are partial.

The address groups are navigational aids, not complete correlation. They match
exact `src_ip` or `dest_ip` values inside the same bounded candidate set and
remain non-causal even when the window is exhausted. The API returns
`candidate_limit`, `candidates_examined`, and `truncated`, and the UI labels a
truncated result as partial. Shared addressing is an observation about
addressing; it does not establish a shared cause.

**Known data limitations.** These are shown as "not recorded" rather than
inferred:

- Model latency is not persisted, so no per-decision latency can be displayed.
- There is no per-event integrity attestation. The boundary panel describes
  current classifier posture, not what ran for a historical row.
- Wazuh `manager`, `location`, `decoder`, and `rule.groups` are not columns.
  They are read from the retained sensor record, so demo mode and API
  IP-redaction mode — which withhold that record — show them as unavailable.
- Wazuh rows carry no `flow_id`, `in_iface`, `category`, or `action`.
- The window is capped at 24 hours. A wider window needs a production-shaped
  benchmark against a defined query-time budget first.

**Delivered in later v0.4 slices.** The initial investigation view remained
read-only. Configuration editing subsequently landed through the separate
versioned subsystem described above, with dedicated authorization, previews,
activation, rollback, concurrency controls, and audit evidence rather than
riding on the dashboard feedback boundary.

### v0.5 — Lab to production — Late 2026

Measure candidate behaviour in an isolated Lab, then promote an approved
revision into Core through an explicit audited boundary.

The implementation draft is documented in
[TriageWall Lab design](docs/lab-design.md). Its first controlled experiment
compares Zeek-absent, connection-only, and deeper-evidence conditions to measure
whether a prompt candidate cites supported Zeek facts and improves decisions.

- [ ] Complete the replay provenance needed to reproduce a decision.
- [x] Specify and validate sanitized event-bundle v1 Phase 0 contract.
- [x] Specify and validate candidate, experiment, paired-result, and sanitized
  promotion-report v1 contracts.
- [x] Define the Lab threat model and hostile-upload matrix, including
  executable Phase 0 validator cases and explicit runtime graduation blockers.
- [x] Add the initial balanced 15-case sanitized Zeek calibration corpus with
  condition-specific human verdicts, contribution labels, and fact allowlists.
- [x] Add the first private prompt-only Lab CLI: trusted experiment builder,
  paired local-Ollama runner, strict output validation, immutable private
  per-pair results, and deterministic Zeek evidence-use scoring.
- [x] Add the first standalone authenticated Lab UI foundation: separate
  loopback-default container/profile, immutable bundle/candidate/experiment
  registry, complete-result verification, paired result views, and promotion
  gate views without Core mounts or production authority.
- [x] Add the isolated single-worker execution slice: exact-digest queueing,
  cooperative cancellation, lease-expiry recovery, bounded quota/retention,
  immutable complete runs, and deterministic aggregate promotion reports.
- [ ] Build the isolated Lab runtime for replay, comparison, injection tests,
  richer operational telemetry, audit history, and gold-set evaluation without
  live Core access.
- [ ] Compare baseline and candidate outcomes without collapsing distinct
  safety and performance signals into one score.
- [ ] Require an authenticated operator action to promote a passing candidate;
  Lab never self-promotes.
- [ ] Retain the previous production revision, rollback path, and audit history.
- [ ] Prove Core-only, Lab-only, and combined installation modes.

### Later awareness and vulnerability work — no release commitment

- **Daily digest** of material events, changes, and trends
- **Coverage-gap detection** between known assets and enrolled sensors
- **Cross-sensor narratives** for related IPs, domains, agents, and time windows
- **Assisted prefilter suggestions** requiring explicit human approval
- **Constrained MITRE ATT&CK mapping** backed by controlled references
- Operator-controlled webhooks for selected high-confidence findings
- Ingest Wazuh vulnerability findings and optionally OpenVAS results
- Explain CVEs, prioritize by asset exposure and criticality, and provide
  plain-language remediation

TriageWall reasons on top of mature sensors and scanners; it does not become a
SIEM or vulnerability scanner.

### v1.0 — Early 2027

Package the proven Core pipeline, optional graduated Lab, and awareness layer
into a stable, explainable homelab security product with documented install,
upgrade, rollback, backup, retention, observability, and security guarantees.

---

## Backlog without commitment

- Theme and branding customization
- Additional mobile-responsive dashboard work
- Authenticated multi-user deployments
- Multi-tenant deployments

---

## Design principles

- **Local-first.** No cloud LLMs or product telemetry.
- **Integrate, do not reinvent.** Mature tools provide detection and ground
  truth.
- **License-compatible.** Planned integrations must remain compatible with
  AGPL-3.0.
- **The human stays in the loop.** Test automation removes toil but does not
  make unsupervised production decisions.
- **Fail closed across trust boundaries.** Unknown configuration, bundle
  versions, identity conflicts, and unsafe evidence must stop or remain
  untrusted rather than silently broaden access or suppress detection.
- **Experimental work does not ship as production.** Lab remains privately
  incubated until its graduation gates pass.

---

## Out of scope

- **Auto-blocking or active response.** Use Wazuh Active Response or firewall
  policy. TriageWall is decision support.
- **Cloud LLM integration.** It conflicts with the local-first telemetry
  boundary.
- **Endpoint-agent functionality.** Use Wazuh agents.
- **Building another SIEM or vulnerability scanner.** TriageWall reasons over
  existing sensors and scanners.
- **Unsupervised self-tuning or auto-rollback.** Regressions are blocked and
  reported; a human decides what changes production.
- **Background detection-rule updates.** Updates may be proposed but are never
  silently applied.
- **Lab access to live production state.** Lab does not mount or mutate Core
  data and cannot promote changes automatically.

---

## Contributing

Roadmap items are open to community contributions. Open an issue or Discussion
before starting significant work, and see [CONTRIBUTING.md](CONTRIBUTING.md).
