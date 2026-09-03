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

## 2. Build experiment 2 inputs

From the exact checkout being evaluated:

```text
python scripts/build_lab_experiment_2.py \
  --bundle /private/input/zeek-evidence-v1.json \
  --output-dir /private/lab/experiment-2 \
  --author operator-name \
  --model-name exact-ollama-model-name \
  --model-digest sha256:FULL_DIGEST
```

The builder snapshots the current Core Suricata system prompt with a canary
placeholder. The baseline keeps the current three-field response behavior;
the candidate requires a final structured `Zeek assessment:` containing a
contribution class, exact JSON path/value citations, and the verdict impact.
Runtime model options come from trusted command-line defaults or explicit
builder arguments, never from the bundle's retained historical options.

The default is five repetitions: 15 events × three evidence conditions × five
repetitions = 225 paired results and 450 model calls. Use `--repetitions 1` for
a non-promotable smoke run before spending time on the full calibration run.

## 3. Run the paired experiment

```text
python scripts/run_lab_experiment.py \
  --bundle /private/input/zeek-evidence-v1.json \
  --baseline /private/lab/experiment-2/baseline.json \
  --candidate /private/lab/experiment-2/candidate.json \
  --experiment /private/lab/experiment-2/experiment.json \
  --output-dir /private/lab/results \
  --ollama-url http://127.0.0.1:11434/api/generate
```

The output directory must be empty on first use or already contain the Lab
private-store marker. Result files are atomically created without replacement.
A run is complete only when `run-complete.json` exists; an interrupted run is
private diagnostic evidence, not promotable output.

## Scoring behavior

- a matched Zeek lookup makes evidence available but does not count as use;
- the candidate must emit exactly one structured `Zeek assessment:` marker;
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
