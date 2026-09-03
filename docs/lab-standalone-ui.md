# TriageWall Lab standalone UI

Status: Private incubation worker slice

Production impact: None; the Lab profile is optional and remains separate from
Core.

## What this slice provides

The standalone Lab service exposes a bounded authenticated interface for:

- importing a fully validated event-bundle v1 document into immutable storage;
- installing exact candidate and experiment contracts;
- refusing an experiment until its exact bundle and both candidate digests are
  installed;
- reading only complete private runner output whose manifest, references,
  individual results, result count, and ordered result-set digest agree;
- displaying paired baseline/candidate outcomes and deterministic evidence-use
  signals;
- queueing an exact installed experiment digest for one transactional worker;
- cooperatively canceling a queued or running job without exposing partial evidence;
- recovering an expired worker lease as a failed run instead of silently resuming it;
- generating and displaying a sanitized 13-gate promotion report whose
  references agree with the complete result set;
- enforcing a bounded pending queue, per-job result ceiling, storage quota, and
  scheduled terminal-run retention;
- preserving the statement that Lab evidence cannot authorize or change Core.

The browser never stores the access key. A successful login creates an
authenticated, signed, `HttpOnly`, `SameSite=Strict` session cookie. Every
state-changing request additionally requires the Lab-specific request header.
All data APIs require authentication, including reads.

The web process never contacts Ollama. It can only write a confirmed job that
references an installed experiment by its exact SHA-256 digest. A separate
single-concurrency worker is the only Lab service on the model network. It
revalidates every referenced artifact before execution and verifies the exact
installed model digest through the bounded Ollama adapter.

## Isolated deployment

Generate a Lab access key and configuration values:

```console
python scripts/generate_lab_api_key.py
```

The command creates the private, git-ignored
`triagewall-lab-credentials.txt` file without printing any credential to the
terminal. Save its access key in a password manager, copy the generated hash
and session secret to the private `.env`, then remove the credential file. Add
an attributable operator name alongside those values:

```dotenv
TRIAGEWALL_LAB_OPERATOR=local-operator
TRIAGEWALL_LAB_API_KEY_HASH='pbkdf2_sha256$210000$...'
TRIAGEWALL_LAB_SESSION_SECRET='...'
TRIAGEWALL_LAB_OLLAMA_URL=http://192.168.1.10:11434
```

Start the explicit Lab profile:

```console
docker compose --profile lab up -d lab
```

Open `http://127.0.0.1:8085`. The default published address is loopback. If an
operator deliberately changes `LAB_BIND_ADDRESS`, authentication remains
mandatory; TLS or a protected tunnel is still required before sending the
session cookie over an untrusted network.

The runtime uses its own image entry points, dependency lock, named volume,
temporary filesystems, networks, port, credentials, and processes. It does not
mount Core's database, alert logs, inventory, configuration, checkpoints,
Docker socket, or data volume. The UI joins only an internal UI network; the
worker joins only the dedicated model-egress network. Core services join
neither network, and
the normal Core Compose invocation does not start the Lab profile.

## Worker lifecycle

The UI stores artifacts below the dedicated Lab volume:

- `bundles/`
- `candidates/`
- `experiments/`
- `runs/`
- `reports/`

An authenticated operator reviews the pair and model-call count and explicitly
confirms the experimental run. The queue allows four active jobs by default and
one worker runs only one at a time. Cancellation is checked at paired-result
boundaries so a baseline/candidate comparison is never published half-complete.

The worker streams immutable result files but publishes `run-complete.json`
only after the exact expected ordered set finishes. Results remain hidden until
that manifest validates. It then derives a report from that same ordered set;
the report validator independently proves that a matching complete run exists.
An expired lease is marked `worker_interrupted`; retrying creates a new job and
never appends to the abandoned directory.

Default operational limits are 1,000 paired results per job, four pending jobs,
10 GiB of Lab storage, and 30-day terminal-run retention in batches of ten.
These are trusted deployment settings, not document-controlled options. The
first 15-event experiment produces 45 pairs and 90 model calls at one
repetition, or 225 pairs and 450 calls at five repetitions.

## Deliberate limitations

- No Core exporter and no live Core mount or API handoff.
- No automatic promotion or Core write credential.
- No import/export/deletion audit ledger yet; attributable job history is kept
  in the Lab-owned queue database until retention removes it.
- Retention is local cleanup, not a backup policy; deployment backup, restore,
  upgrade, rollback, and removal proof remain graduation work.
