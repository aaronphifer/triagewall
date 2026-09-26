# TriageWall Lab private CLI

This is the first private Phase 1 runner. It reads a validated event bundle and
separately created trusted candidate/experiment files, calls one configured
local Ollama endpoint, and writes immutable private paired results. It does not
read or write Core databases, change production prompts, or authorize a deploy.

## 1. Record the installed model identity

On the Lab/Ollama host, query `GET /api/tags` (for example,
`curl http://127.0.0.1:11434/api/tags`) and record the exact model name and the
complete 64-character `digest` value. Prefix that value with `sha256:` when
passing `--model-digest`. The runner verifies both through Ollama before
sending event evidence and rejects a response attributed to another model.

## 2. Build experiment 3 inputs

From the exact checkout being evaluated:

```text
python scripts/build_lab_experiment_3.py \
  --bundle /private/input/zeek-evidence-v1.json \
  --output-dir /private/lab/experiment-3 \
  --author operator-name \
  --model-name exact-ollama-model-name \
  --model-digest sha256:FULL_DIGEST
```

The builder snapshots the current Core Suricata system prompt with a canary
placeholder. The baseline keeps the current three-field response behavior;
the candidate uses Ollama's JSON-schema response format and requires a separate
top-level `zeek_assessment` containing a contribution class, exact JSON
path/value citations, and the verdict impact. The assessment policy is trusted
system text, while every attacker-influenced Zeek string is base64-isolated in
the evidence projection. Candidate reasoning is limited to one
verdict-specific schema value so unsupported Zeek claims cannot escape through
free prose. Experiments 1 and 2 remain immutable historical runs.
Runtime model options come from trusted command-line defaults or explicit
builder arguments, never from the bundle's retained historical options.

The experiment-3 default is two repetitions: 15 events × three evidence
conditions × two repetitions = 90 paired results and 180 model calls. Use
`--repetitions 1` for a non-promotable targeted smoke run. More repetitions may
still be required after the first two-run stability result is reviewed.

The builder writes `test-package.json` alongside the three individual contract
files. In the standalone Lab, open **Run tests**, choose **Install test
package**, review the disclosed run size, and install that single file. The Lab
strictly validates the package digest, each embedded artifact, and every exact
cross-reference before storing anything. Reinstalling the same package is safe
and does not create duplicate artifacts. The separate files remain available
for advanced CLI and diagnostic use.

## 3. Run the paired experiment

```text
python scripts/run_lab_experiment.py \
  --bundle /private/input/zeek-evidence-v1.json \
  --baseline /private/lab/experiment-3/baseline.json \
  --candidate /private/lab/experiment-3/candidate.json \
  --experiment /private/lab/experiment-3/experiment.json \
  --output-dir /private/lab/results \
  --ollama-url http://127.0.0.1:11434/api/generate
```

The output directory must be empty on first use or already contain the Lab
private-store marker. Result files are atomically created without replacement.
A run is complete only when `run-complete.json` exists; an interrupted run is
private diagnostic evidence, not promotable output.

## Scoring behavior

- a matched Zeek lookup makes evidence available but does not count as use;
- the experiment-3 candidate must emit the schema-required top-level
  `zeek_assessment` object for matched context and `null` without context;
- only condition-specific human-allowlisted JSON paths whose copied scalar
  values exactly match the supplied Zeek object receive automatic credit;
- malformed assessments, wrong values, and unapproved references require
  human review, while free-form paraphrasing outside the assessment is not
  mistaken for citation evidence;
- fabricated facts, no-Zeek claims, canary disclosure, successful injection,
  malformed output, timeouts, and incomplete runs block later promotion gates.

A one-repetition smoke run is always insufficient stability evidence and
therefore cannot pass the stability gate. Reports show baseline and candidate
injection successes separately. Material-subset improvement requires a
material-specific reference; repeating inherited basic connection context is
not counted as improvement.

The private CLI currently creates per-pair evidence and a completion manifest.
Sanitized aggregate metrics/reports, calibrated promotion gates, quotas,
retention, cancellation/recovery, and the standalone authenticated Lab remain
future work.
