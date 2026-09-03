# TriageWall Lab contracts v1

Status: Phase 0 contract; no Lab runtime is shipped

Schema: [`schemas/lab-contracts-v1.schema.json`](../schemas/lab-contracts-v1.schema.json)

Reference validators: [`triagewall/lab_contracts.py`](../triagewall/lab_contracts.py)

## Trust boundary

These contracts describe trusted Lab configuration and immutable Lab output.
They are separate from the hostile
[event-bundle v1](event-bundle-v1.md) import boundary.

An uploaded bundle cannot create or select a candidate, experiment, model,
prompt, policy, runner, or inference setting. Candidates are installed through
trusted Lab administration. Experiments are created by an authenticated
operator from installed candidate and imported-bundle identities. Results and
reports are created only by the Lab runner.

Every document rejects unknown fields and versions, duplicate object keys,
non-finite numbers, invalid UTF-8, inconsistent cross-field state, and a
mismatched canonical content digest.

## Candidate

`triagewall.lab-candidate` is an immutable candidate definition. It contains:

- a stable candidate ID, optional parent ID, author, rationale, and expected
  invariant;
- an immutable model name and digest;
- bounded source-specific prompt components;
- source projection, response contract, prefilter, asset-context projection,
  and Zeek-evidence projection revisions;
- bounded inference settings.

Prompt construction is structural rather than a general uploaded template
language. For each source, the runner joins a trusted system prompt, a
classification prefix, the event projection, and—only for a matched Suricata
condition—the matched-Zeek instruction and evidence. Wazuh candidates cannot
define a Zeek instruction.

Each system prompt contains `<CANARY_TOKEN>` exactly once. The runner replaces
that placeholder with a fresh secret value at execution time. Candidate files
therefore remain reproducible without persisting the live canary.

## Experiment

`triagewall.lab-experiment` is an operator-created paired comparison. It
references, but does not embed:

- one baseline candidate;
- one distinct proposed candidate;
- one already validated immutable event bundle.

It records the question, changed component classes, selected evidence
conditions, optional bounded event selection, repetition count, randomized
execution-order seed, and whether human labels are required. The order seed is
reproducibility data; it does not permit a bundle to control execution.

The three v1 evidence conditions are `no_zeek`, `connection_only`, and
`connection_plus_application`. The last remains experimental and must never be
described as historical model-time production evidence.

## Paired result

`triagewall.lab-result` represents one event, evidence condition, and
repetition. It stores both baseline and candidate outcomes and the recorded
execution order. Each outcome contains:

- exact candidate and model identities;
- duration and bounded original model response;
- validation or bounded failure category;
- retained verdict, confidence, and reasoning;
- deterministic evidence-use and safety scoring.

One result document is deliberately one pair rather than one complete
experiment. At the v1 maximum, 1,000 events × three conditions × 20 repetitions
creates 60,000 bounded immutable result objects. This keeps individual writes,
validation, recovery, and private evidence access bounded.

No-Zeek results cannot claim supported Zeek facts. Canary disclosure scoring
must agree with the validation failure category. Before persistence, the runner
replaces a disclosed live canary with `<CANARY_TOKEN>`; the result validator
requires that marker exactly when disclosure is recorded. Model-response
hashes cover the resulting exact UTF-8 response, including invalid output
retained for diagnosis.

## Promotion report

`triagewall.lab-promotion-report` is a sanitized aggregate suitable for human
review. It contains identities, expected and completed result counts, separate
decision, evidence-use, safety/validity, and operational metrics, plus every
required promotion gate.

It contains no raw events, prompts, model responses, asset snapshots, Zeek
records, event IDs, individual result digests, or per-result reasoning. One
aggregate result-set digest ties the summary back to the complete private
evidence without publishing reversible per-result fingerprints. The Lab
verifies that aggregate while generating the report; a public reader cannot
reconstruct its private input list.

Promotion status is derived:

- `incomplete` when result count is short or any gate was not evaluated;
- `blocked` when the result set is complete and at least one gate failed;
- `eligible` only when the result set is complete and every gate passed.

Every report must set `does_not_authorize_production` to `true`. An eligible
report is evidence for a human decision. It cannot write to Core, authorize a
deployment, or replace normal pull-request, CI, review, merge, and deployment
controls.

## Integrity and limits

Each `content_sha256` is the SHA-256 digest of canonical JSON after removing
only that self-naming field. Nested prompt components have their own content
digests. Promotion reports additionally hash the ordered result-digest list.

These hashes detect changed bytes and identities; they are not signatures and
do not authenticate an author.

| Boundary | v1 limit |
|---|---:|
| Any contract document | 8 MiB |
| Prompt component | 64 KiB UTF-8 |
| Model response per outcome | 64 KiB UTF-8 |
| Event selection | 1,000 IDs |
| Repetitions | 20 |
| Evidence conditions | 3 |
| Paired results referenced by one report | 60,000 |
| Verified evidence references or unverified items per outcome | 32 each |
| General free text | 2,000 characters |

## Required gates

V1 reports contain exactly one status for each gate:

- canary disclosure and injected-instruction success;
- unsupported Zeek claims and claims when Zeek was absent;
- invalid or incomplete execution and explicit matched-context assessment;
- missed real alerts and true-positive recall;
- pipeline and model-only Cohen's kappa;
- uncertain-outcome changes;
- material-subset improvement;
- repetition stability (at least two repetitions are required).

Requirements and observed summaries are bounded text so the eventual runner
can record calibrated thresholds without changing the v1 envelope. The Lab
design's hard safety rules remain authoritative.

## First private runner implementation

The [Lab threat model](lab-threat-model.md) and
[hostile-upload matrix](lab-hostile-upload-matrix.md) now define the import and
future runtime security obligations. The initial
[balanced sanitized Zeek scenario set](lab-zeek-scenarios-v1.md) now supplies
condition-specific human fact allowlists. The first Phase 1 CLI now binds these
contracts, streams paired results, validates the configured local model by
name and digest, and persists bounded private result objects. Aggregate report
generation, calibrated gates, retention, cancellation/recovery, and the
standalone application remain separate work.
