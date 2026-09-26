# Threat model

This document describes the trust assumptions and known limitations of the
currently shipped **TriageWall Core** application. TriageWall Lab is an
incubating, non-production component with a separate
[Lab threat model](lab-threat-model.md),
[hostile-upload matrix](lab-hostile-upload-matrix.md), and graduation gate; see
also the [Core and Lab product boundary](core-lab-product-boundary.md).

TriageWall targets a single trusted operator running services on a private
homelab network. It is not a multi-tenant or internet-facing application.

## What Core does

Core is a decision-support layer between Suricata and, optionally, Wazuh alert
streams and a human operator. It:

- applies validated deterministic policy to eligible Suricata alerts;
- sends remaining Suricata alerts and admitted Wazuh alerts to a local Ollama
  model through source-specific isolated prompts;
- attaches exact-IP matches from a private trusted asset inventory;
- stores verdicts, source provenance, asset snapshots, failures, checkpoints,
  and operator feedback in local persistent storage;
- serves a local dashboard and JSON API.

Core does not block traffic, change sensor rules, invoke Wazuh Active Response,
or take autonomous action.

## Data flow and trust boundaries

```text
[ Suricata eve.json ] --> [ Suricata adapter ] --+
                                                  |
[ Wazuh alerts.json ] --> [ Wazuh adapter ] -----+--> [ normalized event ]
                                                           |
                                     [ trusted asset and policy config ]
                                                           |
                              Suricata scoped prefilter or local Ollama
                                                           |
                                                        [ SQLite ]
                                                           |
                                                   [ local dashboard ]
```

The important boundaries are:

1. **Sensors to adapters.** Records are untrusted input. Suricata validates its
   required timestamp and rule identity plus every optional flow, IP, port,
   protocol, severity, and bounded rule-text field it consumes. Wazuh validates
   its required timestamp, event identity, rule identity, and level, and
   normalizes valid optional network fields. Free text, unknown fields, agent
   names, descriptions, URLs, hostnames, payloads, TLS/DNS data, and Wazuh
   `data.*` values remain attacker- or environment-controlled evidence.
2. **Operator configuration to Core.** The mounted prefilter and asset
   inventory are trusted operator inputs, but they are still schema-, size-,
   type-, and ambiguity-validated. Invalid configured files fail startup.
3. **Core to Ollama.** Only source identity, typed severity guidance, prompt
   policy, and validated asset context enter trusted system context. Sensor
   evidence stays in the isolated user evidence block. Ollama traffic is
   unencrypted HTTP unless the operator adds a protected transport.
4. **Writers to SQLite.** Verdict, asset snapshots, and source provenance are
   committed together. Retryable model or persistence failures do not advance
   the relevant checkpoint.
5. **Dashboard to operator.** The dashboard validates configured Host values
   and is intended for a trusted private network. The JSON API may require
   API keys (and always requires a credential for writes); the HTML UI uses a
   same-origin write cookie rather than multi-user login.

## Attacker model

The primary adversary can influence sensor evidence by sending crafted network
traffic or generating endpoint activity that appears in Suricata or Wazuh
alerts. Their goals may include:

- prompt injection that forces a benign verdict or attacker-selected output;
- malformed or oversized records that cause gaps, retries, or resource
  exhaustion;
- duplicate or conflicting event identity;
- hostile strings that become HTML, logs, CSV formulas, or model instructions;
- discovery of private asset or agent context through demo responses.

An adversary with code execution on the TriageWall host, control of operator
configuration, control of the trusted network between Core and Ollama, or
control of the sensor ruleset is outside this threat model.

## Defenses

### Prompt and response isolation

Suricata uses a fail-closed typed allowlist: only explicitly trusted structured
sensor fields remain plain; unknown and free-text fields are base64-wrapped with
explicit untrusted-data boundaries. Allowlisted Suricata IP addresses, ports,
protocols, and signature IDs also require valid values before they remain
plain. Wazuh uses a source-specific projection in which free text, descriptions,
agent identity, location, groups, decoder data, `full_log`, and nested `data`
strings are isolated as untrusted evidence.

A per-process canary is included in the system prompt. Raw and decoded model
output is checked for that canary. A leaked canary causes a conservative
security verdict rather than accepting the requested output.

The complete model response must be one JSON object with exactly the expected
keys and valid types. Truncated, salvaged, extra-key, or otherwise malformed
responses fail closed.

### Input and configuration bounds

- Wazuh records are limited to 1 MiB and its model-evidence projection to
  32 KiB. Oversized complete records are hashed, quarantined with bounded
  diagnostics, and checkpointed without reaching Ollama.
- Wazuh descriptions and agent fields have explicit length limits.
- Suricata signature and rule-text fields have explicit length limits; invalid
  rule identity, network tuple, protocol, severity, and flow identity values
  are durably quarantined before model or database use.
- Asset inventory and prefilter files are each limited to 1 MiB and have
  bounded collection and text fields.
- Two-sided trusted asset prompt context is limited to 2 KiB.
- Wazuh source identity, rule fields, IP addresses, ports, protocols, and
  checkpoint documents are validated before use.

### Persistence and recovery

- Incomplete append-in-place records remain uncheckpointed and use the normal
  polling backoff.
- Retryable Ollama and SQLite failures block later records and leave the failed
  record uncheckpointed.
- Intentional skips, duplicates, and durably quarantined malformed input may
  advance the checkpoint.
- Wazuh checkpoints are written atomically and bind to the configured source
  instance. Missing or corrupt required rotation archives fail closed rather
  than silently skipping a gap.
- New Wazuh identities are deduplicated by source type, source instance, and
  source event ID. Instance-less identities use a separate unique constraint.

#### Suricata `eve.json` rotation

The Suricata checkpoint names a specific inode and byte offset. It is never
abandoned merely because the live `eve.json` path now resolves to a different
inode.

- When the checkpointed inode is not the live inode, the rotated archive that
  still owns that inode is drained first. Only affirmative evidence of a
  complete drain — reopening that exact inode and observing a stable EOF —
  allows the checkpoint to move on.
- If the checkpointed inode is no longer present beside `eve.json`, ingest
  fails closed and exits non-zero. A saved offset of `0` is *not* treated as
  proof that the archive was read; it just as plausibly means the whole file
  was still unread.
- A renamed log is not assumed to be immutable. `logrotate` can move the path
  while Suricata still holds the old descriptor and appends more records
  through it, so EOF is confirmed across consecutive observations separated by
  a bounded settle interval. Late appends are drained before the checkpoint
  moves. The wait is bounded and yields to graceful shutdown.
- Rotated-archive discovery is bounded: a single non-recursive scan of the
  `eve.json` directory, restricted to regular files whose names begin with the
  live file's name, rejecting symlinks, directories, devices, sockets and
  FIFOs. Two separate caps apply — one on `eve.json*` siblings and a much
  larger one on total directory entries — so unrelated logs sharing the mount
  cannot consume the archive budget. Exceeding either cap, or failing to read
  the directory at all, fails closed. A partial chain is never returned: it is
  indistinguishable from a complete one, and acting on it would silently skip
  any archive that fell outside the scan.
- Compressed archives (`.gz`, `.bz2`, `.xz`, `.zst`) are recognised as chain
  members — they are evidence that a rotation happened and they hold their slot
  in the ordering — but TriageWall reads `eve.json` as plain JSON-Lines and
  never decompresses them. A compressed file can therefore never become a read
  source or a persisted checkpoint. If the next unread archive is compressed,
  ingest fails closed with the checkpoint left on the preceding file and asks
  the operator to decompress or restore it. It is never skipped.
- Rotation ordering follows the documented schemes — `logrotate` numbering
  (a higher index is older) and Suricata's dated archives — so a second
  rotation that happens while ingest is still catching up drains the displaced
  file before the new live file.
- A file that shrank behind the saved offset, and an inode that changes between
  `stat()` and `open()`, both leave the checkpoint untouched.
- Known limitation: if the rotation chain position cannot be re-established
  after a drain (for example, the archive was compressed and unlinked and no
  recorded successor remains), ingest fails closed and asks an operator to
  resolve the chain rather than guessing which archive comes next.
- A corrupt or unwritable checkpoint and a rotation that cannot be advanced
  safely are one error family (`IngestCheckpointError` subclasses
  `EveCheckpointError`), so both terminate the daemon non-zero through a single
  handler rather than one of them falling into the generic retry path and
  continuing on an in-memory cursor.

### API contract

- Every `/api/v1/*` response is validated against its declared Pydantic model
  at runtime, before the ETag is computed and before any bytes are written.
  Response models forbid undocumented fields, so a stray value fails closed
  instead of leaking into the stable contract. Operator-defined asset-inventory
  contents stay free-form dictionaries by design.
- Verdict, model and timeline-interval filters are typed. An unrecognized value
  returns 422 rather than silently behaving like no filter.
- Free-form inputs are bounded: queue search, cursor length and feedback notes
  each have a documented maximum, so one request cannot make the database or
  the application do unbounded work. Queue search evaluates at most the newest
  10,000 retained alerts, reports when older rows were excluded, and has a
  three-second SQLite progress deadline as a second fail-safe. It includes
  private IP and historical asset fields only when the response disclosure
  policy would show them; demo and IP-redaction modes do not expose a
  membership oracle.

### Operator-facing output

- Dashboard values are HTML-escaped.
- Demo mode masks private network addresses and removes model reasoning, asset
  inventory data, agent identity, event identity, SPC notes, and other private
  context.
- Benchmark CSV output neutralizes formula-capable cells.
- Application logs avoid raw Wazuh alerts and private agent data.

## Known limitations

**Isolation reduces risk; it does not prove model safety.** Encapsulation,
canary detection, and schema validation raise the cost of prompt injection but
do not make an LLM a security boundary. Adversarial regression work remains
required.

**The prefilter deliberately trades coverage for volume.** A matching rule is
auto-classified without Ollama review. Contextual conditions reduce the blast
radius, and missing required context does not match, but legacy global SID
rules remain supported. Operators must review suppressions conservatively.

**False negatives are expected.** The local model is fallible. TriageWall
reduces review volume; it does not replace the underlying sensor or a human
analyst.

**Suricata record size is not globally bounded yet.** Wazuh has record and
projection limits, but an unusually large complete Suricata JSONL record can
still consume memory and model context. Adding a bounded Suricata reader and
prompt projection remains hardening work.

**Ollama transport is unencrypted and unauthenticated by default.** Use
localhost, a tunnel, a private segmented network, or an authenticated proxy
when the network between Core and Ollama is not fully trusted.

**The dashboard UI is not multi-user SSO.** Host validation is not user
authentication. Do not port-forward the dashboard; use a VPN or authenticated
reverse proxy for remote access. The JSON API supports optional API-key auth
(`X-API-Key`, hashed keys, scopes `read` / `feedback:write`) and a same-origin
HttpOnly write cookie for the built-in UI. Writes always require a credential.
Unauthenticated reads remain available only when
`TRIAGEWALL_API_ALLOW_UNAUTHENTICATED_READS=true` (default). See
[docs/api.md](api.md).

**Not every write credential identifies a user.** An API key names a caller;
the dashboard write cookie does not. It is same-origin CSRF resistance for the
trusted built-in interface — it establishes that a write came from a page
TriageWall served, not who sent it, and any browser that can load the dashboard
receives one. `TRIAGEWALL_DASHBOARD_COOKIE_SECURE=true` keeps it off plaintext
transports, but the trusted-LAN boundary is what actually protects it.

**API IP redaction is pseudonymization, not anonymization.**
`TRIAGEWALL_API_REDACT_IPS=true` replaces addresses with
`HMAC-SHA256(TRIAGEWALL_API_IP_HASH_SECRET, domain || address)`. An unkeyed
digest would be reversible by exhaustive search over the address space, so
enabling redaction without a valid secret fails startup. Because the mapping is
deterministic within a deployment — which is what makes correlation useful — an
attacker who learns the secret can still re-identify addresses, and one who can
observe traffic can confirm a guessed address. When this mode is enabled, API
verdict rows also withhold free-form reasoning, operator notes, raw sensor
records, and asset snapshots because those channels can repeat or add cleartext
addresses outside the structured endpoint fields. Demo-mode masking is
separate and unaffected.

**Retention remains an operator-controlled maintenance action.** The bounded,
backup-first host runner restores monitoring between short deletion pauses and
fails closed when its safety evidence is missing. It does not choose a site's
retention window, delete reviewed verdicts by default, shrink the database
file, or replace off-host backup policy. High-volume installations should use
SSD-class active storage and keep verified backups on a separate failure
domain.

**Startup serialization depends on the Compose boundary.** The one-shot
`migrate` service is the sole schema owner and all shipped consumers wait for
its successful completion. Directly launching an ingest script outside
Compose requires the operator to run `triagewall/migrate.py` first; consumers
then verify the schema read-only and fail closed rather than repairing it.

## Assumptions

- The TriageWall host and operator-controlled configuration are trusted.
- Suricata and Wazuh remain the authoritative detection and alert stores.
- The network between Core components and Ollama is private and trusted unless
  the operator adds transport protection.
- Core is not exposed directly to the public internet.
- There is one trusted operator and no multi-user authorization model.

## Example and demo data

Tracked fixtures and experiment material are intended to be synthetic or
sanitized. Demo API responses apply additional redaction at runtime. Do not
commit production alerts, private inventories, checkpoints, packet captures,
or populated databases.

## Reporting

Report security issues according to [SECURITY.md](../SECURITY.md). Prompt-
injection bypasses, checkpoint gaps, identity collisions, cross-source context
leaks, and unsafe configuration behavior are all in scope.
