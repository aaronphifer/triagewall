# TriageWall operations and deployment

This guide contains the detailed installation, migration, storage, retention,
model-selection, tuning, and network-visibility material summarized in the
[project README](../README.md).

## Prerequisites

- **Docker Engine 20.10+** ([install guide](https://docs.docker.com/engine/install/))
- **Docker Compose v2** (the `docker compose` plugin, not deprecated
  `docker-compose` v1)
- **Ollama** on the same host or another reachable private host
- **A compatible model**, with Foundation-Sec-8B Q5_K_M as the production
  default
- **8 GB+ GPU VRAM** recommended for practical residual-alert inference

On Ubuntu, Debian, or Pop!_OS, install the Compose v2 plugin from Docker's
official package repository:

```bash
sudo apt-get install docker-compose-plugin
```

The older `docker-compose` 1.x can fail with `KeyError: 'ContainerConfig'`
against modern Docker Engine. If that error appears, replace it with the v2
plugin.

Pull the default model on the Ollama host:

```bash
ollama pull hf.co/gabriellarson/Foundation-Sec-8B-Instruct-GGUF:Q5_K_M
```

## First deployment

```bash
git clone https://github.com/aaronphifer/triagewall.git
cd triagewall
cp .env.example .env
```

For a safe first look, set `DEMO_MODE=true` and start the base stack:

```bash
docker compose up -d
```

Open `http://localhost:8084`. Demo mode uses bundled fixtures, masks addresses,
and disables feedback and configuration writes.

For production, set `DEMO_MODE=false` and review at least:

- `HOST_DATA_DIR`: persistent SQLite and checkpoint storage
- `HOST_EVE_DIR`: directory containing Suricata `eve.json`
- `OLLAMA_HOST`: private Ollama endpoint
- `OLLAMA_MODEL`: installed model name
- `INTERNAL_SUBNETS`: internal networks used for direction context
- `HOST_ASSET_INVENTORY`: optional private exact-IP inventory
- `HOST_BACKUP_DIR`: backup directory on the intended backup filesystem

Run `docker compose up -d` again after editing `.env`.

## Serialized database startup

Docker Compose runs a one-shot `migrate` service before the dashboard,
Suricata ingest, or optional Wazuh ingest starts. It is the only startup process
that creates tables, adds columns, or builds indexes. Consumers perform a
read-only schema check and fail closed if migration did not complete.

On an existing large database, index work can take several minutes. Do not
interrupt the migration just because output is quiet. Inspect it with:

```bash
docker compose ps -a migrate
docker compose logs migrate
```

A migration failure blocks dependent services rather than allowing them to
race or run against a partial schema. Correct the reported storage, permission,
or database problem, then run `docker compose up -d` again. Direct non-Compose
use must run `python3 triagewall/migrate.py` before either ingest process.

## Private asset inventory

The inventory follows the versioned contract in
[`triagewall/config/assets.example.json`](../triagewall/config/assets.example.json).
Keep populated copies outside Git and mount one with `HOST_ASSET_INVENTORY`.
Missing, malformed, oversized, or ambiguous inventories fail startup.

Direct Python operator tools do not read the Compose mount source
automatically. Set `ASSET_INVENTORY_PATH` to the same host file before gold-set
verification or evaluation. Each asset is limited to 64 IP addresses and 64
exposed ports, and complete two-sided context is bounded so trusted context
cannot exhaust the model prompt budget.

## Configuration workspace

Configuration mutation is disabled by default and requires an attributable
`config:write` key rather than the dashboard feedback cookie:

```bash
python scripts/generate_api_key.py
```

Save the one-time plaintext key. Copy the generated single-quoted
`TRIAGEWALL_API_KEYS` assignment into `.env`, set
`TRIAGEWALL_CONFIG_WRITES_ENABLED=true`, and restart the dashboard with
`docker compose up -d`. Enter the plaintext key at `/configuration`.

Retain existing key records and separate multiple records with commas inside
the same quotes. See [API authentication](api.md#configuring-a-key) and the
[operator configuration lifecycle](operator-configuration-foundation.md).

## Optional Wazuh deployment

The opt-in `docker-compose.wazuh.yml` profile tails a same-host Wazuh manager's
local `alerts.json` through a read-only volume. The base stack has no Wazuh
volume dependency. The recommended level-8 admission gate keeps routine Wazuh
events in Wazuh while sending security-relevant alerts through TriageWall.

Source, event, and agent identity are persisted with each verdict, and the
checkpoint can recover through Wazuh's compressed daily archives. See the
[Wazuh integration guide](wazuh-integration.md) for private environment
settings, startup verification, recovery, and rollback.

## Optional Zeek enrichment

The opt-in `zeek` profile builds a private SQLite context index from JSON Zeek
logs and exposes no network port. Automatic model enrichment remains limited
to an exact `conn.log` match. An explicit operator investigation may then
correlate that connection with allowlisted projections from `dns.log`,
`http.log`, `ssl.log`, `x509.log`, `files.log`, and `notice.log`. HTTP, TLS,
file, and notice evidence use exact Zeek UID/file identifiers. DNS may also use
a recent answer for the same connection origin and responder IP, bounded to a
five-minute lookback. The investigation does not silently rewrite the recorded
verdict. Mount the complete Zeek logs root with
`HOST_ZEEK_LOG_DIR`, keep the `ZEEK_*_PATH` values pointed at the live logs,
and keep `ZEEK_ARCHIVE_ROOT` pointed at the directory containing ZeekControl's
`YYYY-MM-DD` archive directories. Application logs are optional until first
observed. Start it with:

```bash
docker compose --profile zeek up -d
```

Restart recovery supports uncompressed archives plus gzip, bzip2, and xz. It
authenticates the old logical stream with a durable record digest before
resuming a compressed representation; missing, ambiguous, corrupt, symlinked,
unsupported zstd, or over-budget archives stop ingest rather than skipping
evidence. The default recovery scan is bounded to 400 dated directories, 512
matching files, 64 identity candidates, and 512 MiB of decompressed
verification work. Consecutive dated archives must retain ZeekControl's
standard `<type>.HH:MM:SS-HH:MM:SS.log` interval names; an absent interval or an
unverifiable intermediate filename stops handoff before the later archive.
Same-directory restart recovery supports numbered `<type>.log.N` rotations;
arbitrary suffixes are not treated as ordered archives because lexical order
cannot prove that an intermediate log is present. An uninterrupted follower
can still drain an arbitrarily renamed file through its retained descriptor.
The final dated-to-live handoff also requires the live file's modification time
to fall inside the immediately following interval of the same duration. If that
adjacency cannot be established, ingest stops rather than treating a missing
later archive as an empty interval.

Logical records larger than 64 KiB are streamed into digest-only rejection
metadata, with no raw body retained. That streaming work has a 1-MiB per-record
ceiling. Once a record crosses 64 KiB, reaching EOF without a terminator or
crossing the ceiling stops ingest fail-closed without advancing the checkpoint.
This prevents an unchanged oversized partial record from being drained on every
poll while preserving quarantine and forward progress for completed oversized
records within the ceiling.

Each rotation into a successor stores a bounded digest of its initial logical
bytes before committing its zero-offset checkpoint. An empty or incomplete
successor is left pending until at least one complete record (or the full
64-KiB prefix bound) can be authenticated after a restart. A legacy zero-offset
checkpoint without this prefix evidence fails closed instead of trusting a
potentially reused file identity.

The standalone index prunes accepted connections, UID-correlated application
evidence, and rejected-record metadata automatically. Defaults retain seven
days and run a bounded cleanup every 60 seconds (`ZEEK_RETENTION_DAYS`, `ZEEK_PRUNE_INTERVAL`,
`ZEEK_PRUNE_BATCH_SIZE`, and `ZEEK_PRUNE_MAX_ROWS`). Cleanup uses trusted ingest
time, preserves the log checkpoint, reports deleted counts and possible
backlog, and retries at the poll cadence when one run reaches its row budget.
Prune failures stop the writer so uncontrolled growth is visible. Online
cleanup reuses SQLite pages but does not shrink an already enlarged database;
plan offline compaction separately with all writers stopped if space must be
returned to the filesystem.

Automatic Core enrichment gives an eligible `no_match` up to three seconds to
catch the independently polled index, retrying every half second by default
(`ZEEK_CATCHUP_TIMEOUT_SECONDS` and
`ZEEK_CATCHUP_RETRY_INTERVAL_SECONDS`). A match that arrives inside that budget
is included in the single model call. Ambiguous, unavailable, invalid, and
disabled outcomes remain immediate fallbacks, and operator-initiated refreshes
remain one-shot.

## Performance and model selection

Measured production-shaped values are workload- and hardware-dependent:

| Metric | Observed value |
|---|---|
| Source rate | 6,000–13,000 alerts/hour |
| Policy resolution | 99%+ after site tuning |
| Residual-model latency | 7–10 seconds on Foundation-Sec-8B Q5_K_M / RTX 4060 |
| Steady-state lag | Under two minutes with a healthy policy ratio |
| Ingest RAM excluding Ollama | About 17 MB in the measured deployment |

Foundation-Sec-8B-Instruct was benchmarked against a human-labeled gold set.
Full methodology and results are in [the experiment directory](experiments/).

| GPU VRAM | Recommended model | Cohen's kappa | TP recall | Notes |
|---|---|---:|---:|---|
| 8 GB | Foundation-Sec Q4_K_M | 0.574 | 83% | Minimum with headroom |
| 8 GB | **Foundation-Sec Q5_K_M** | **0.687** | **83%** | Production default |
| 10 GB+ | Foundation-Sec Q6_K | 0.734 | 83% | Best measured tier |
| 16 GB+ | Foundation-Sec Q8_0 | Not measured | Not measured | Does not fit the 8 GB test host |

Avoid models that exceed VRAM. Partial CPU offload causes much slower and more
variable inference. After warmup, confirm `ollama ps` reports `100% GPU`. Other
GPU-heavy applications can silently push Ollama into CPU offload.

## Policy tuning

The first days on a network are usually spent identifying repeat noise and
turning it into carefully scoped policy. The configuration workspace can draft
from an alert, validate the exact document, preview bounded historical impact,
and explicitly activate a revision.

Rules can match direction, internal CIDR, Suricata flow direction, protocol,
ports, address ranges, and exact-IP asset fields. Every condition in `match`
must pass; values within one condition are alternatives. Missing or malformed
required context does not suppress the alert—the event continues to normal
model review.

Rules without `match` remain compatible but suppress globally by signature ID.
Migrate them deliberately as reliable context becomes available. Keep reason
strings specific: they are operational documentation for why that behavior is
considered normal on this network.

## Storage visibility and retention

The dashboard reports the SQLite database, WAL, and shared-memory allocation,
plus reusable pages inside the database. Reusable space is not filesystem free
space: with `auto_vacuum=none`, deleted pages are reused but the main file does
not shrink automatically.

Inspect allocation and history bounds without writing:

```bash
docker compose --profile maintenance run --rm maintenance status
```

With Wazuh enabled, include both Compose files and profiles:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.wazuh.yml \
  --profile wazuh \
  --profile maintenance \
  run --rm maintenance status
```

Dry-preview the default 60-day hot-data window:

```bash
docker compose --profile maintenance run --rm maintenance \
  prune --keep-days 60
```

### Automated production cycle

`scripts/retention-cycle.sh` is the recommended production entry point. It:

- prevents overlapping host cycles;
- captures one fixed UTC cutoff for safe resume;
- stops every selected SQLite writer for a bounded backup copy;
- restarts and health-checks monitoring before long integrity verification;
- binds a mode-0600 manifest to the backup and source database;
- applies short, automatically recovered deletion pauses;
- restores every selected service after each pause or ordinary failure; and
- retains the backup, manifest, and JSON results for operator review.

Run it as an SSH-independent transient systemd service. The backup directory
must already exist on the intended backup filesystem, be owned by the account
running the cycle, and not be group- or world-writable:

```bash
sudo systemd-run \
  --unit=triagewall-retention-cycle \
  --collect \
  --property=Type=exec \
  --property=WorkingDirectory=/opt/triagewall \
  /opt/triagewall/scripts/retention-cycle.sh \
  --backup-dir /mnt/triagewall-backups \
  --keep-days 60 \
  --batch-size 500 \
  --wazuh
```

Replace both paths. Omit `--wazuh` when the connector is disabled. A network or
SSH disconnect does not stop the systemd service.

The default is 500 rows per delete transaction. Values from 1 through 10,000
are supported, but benchmark a disposable database copy on the deployment
storage before changing it. Larger batches reduce repeated query work while
increasing WAL use and the rollback unit.

Place large or sustained installations on SSD-class storage and keep verified
backups on a different failure domain.

```bash
systemctl status triagewall-retention-cycle
journalctl -fu triagewall-retention-cycle
```

### Manual split workflow

The maintenance CLI exposes the phases independently:

1. Stop writers, then run `maintenance backup --output PATH
   --confirm-writers-stopped`. Retain `PATH` and `PATH.provenance.json`.
2. Restart writers, then run `maintenance verify-backup --backup PATH
   --manifest PATH`.
3. Stop writers again and run `maintenance prune --apply
   --confirm-writers-stopped --verified-backup-manifest PATH
   --max-runtime-seconds 900`.

Applied prune requires explicit acknowledgement that writers are stopped.
Verification records the backup SHA-256 and integrity result. Authorization
binds deletion to the verified database identity, sequence, backup time, and
feedback state, and refuses to delete eligible rows inserted after the backup.

Human-reviewed verdicts remain protected unless `--include-reviewed` is
supplied. Retain the verified backup. Do not include `VACUUM` in this workflow;
plan it separately with all writers stopped and adequate temporary space.

## Network visibility and limitations

TriageWall only reasons over evidence supplied by its configured sensors. A
typical OPNsense or pfSense Suricata deployment can see traffic crossing the
router, inbound port forwards, and inter-VLAN traffic. It generally cannot see:

- same-segment east-west traffic that never reaches the router;
- Docker bridge traffic that is not mirrored to a monitored interface;
- encrypted DNS sent directly to an unmonitored resolver; or
- activity on interfaces that do not run IDS inspection.

SPAN or mirror ports can expand visibility in larger environments. Optional
Wazuh input adds endpoint-generated evidence to the same workbench, but it does
not turn TriageWall into an endpoint agent or replace either sensor.

TriageWall is decision support. It does not block traffic, change firewall or
sensor rules, invoke Wazuh Active Response, guarantee every threat is detected,
or replace a human analyst.

## Upgrade and rollback discipline

Before upgrading a persistent deployment:

1. Read the target release notes and migration notes.
2. Take and verify a current backup using the maintenance workflow.
3. Record the deployed commit and current service state.
4. Let the one-shot migration complete before starting consumers.
5. Verify health, restart counts, and both source checkpoints after deployment.
6. Retain the prior code revision and verified database backup until the
   observation window closes.

Release-specific proof and declared deviations are recorded under
`docs/release-evidence-v*.md`.
