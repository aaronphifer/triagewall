# TriageWall HTTP API

Stable contract for clients that consume TriageWall outside the built-in
dashboard (kiosks, scrapers, automations). The dashboard process serves both
the HTML UI and this JSON API.

**Deprecation:** unversioned `/api/*` aliases and the stats field `real_` are
scheduled for removal on **2026-12-31**. Prefer `/api/v1/*` and the field
`real`.

## Authentication

| Concern | Mechanism |
|---------|-----------|
| Header | `X-API-Key: <plaintext>` |
| Storage | Keys are configured as **PBKDF2-HMAC-SHA256** digests only
  (`TRIAGEWALL_API_KEYS`). Plaintext keys are never stored or logged. |
| Scopes | `read`, `feedback:write`, `config:write` |
| Reads | Allowed without a key when `TRIAGEWALL_API_ALLOW_UNAUTHENTICATED_READS=true` (**default**). Set to `false` to require a key with `read` (or `feedback:write`) for read endpoints and `/metrics`. |
| Feedback writes | **Always** require a credential: an API key with `feedback:write`, or the same-origin dashboard write cookie. |
| Configuration | Every configuration endpoint requires an attributable API key with `config:write`; anonymous reads, `read`, `feedback:write`, the dashboard cookie, and demo mode never grant access. Draft mutations also require `TRIAGEWALL_CONFIG_WRITES_ENABLED=true`. |
| Dashboard cookie | Serving `GET /` sets HttpOnly `SameSite=Strict` cookie `tw_dash_write` derived from `TRIAGEWALL_DASHBOARD_WRITE_SECRET`. The built-in UI does not need JS changes. External clients must use `X-API-Key`. |
| Health | `GET /api/v1/health` is always unauthenticated and omits storage metrics. |

### The dashboard write cookie is not user authentication

API keys identify a caller. The dashboard write cookie does not. It is
**same-origin CSRF resistance for the trusted built-in interface**: it proves a
write came from a page TriageWall itself served, not that a particular user is
signed in. Every browser that can load the dashboard receives one.

That is deliberate — TriageWall targets a single trusted operator on a private
network — but it means the cookie is not a substitute for network controls.
**Remote access still requires a VPN or an authenticated reverse proxy.** There
is no multi-user login or SSO.

Cookie attributes: `HttpOnly`, `SameSite=Strict`, `Path=/`, and `Secure` when
`TRIAGEWALL_DASHBOARD_COOKIE_SECURE=true`. Enable that whenever the dashboard
is reached over HTTPS so the browser will not send it over plaintext.

### Configuring a key

```bash
# Run this in a private terminal from the repository root. The plaintext key
# is printed once; the generated .env value contains only its PBKDF2 hash.
python scripts/generate_api_key.py
```

The default creates an attributable `config-admin` record carrying only
`config:write`. Use `--name` and repeat `--scope` to generate a different
least-privilege record. The command prints both the record to append when
`TRIAGEWALL_API_KEYS` already exists and a complete Compose-safe assignment for
a new installation. Keep the assignment single-quoted: the quotes prevent
Compose from treating the PBKDF2 `$` separators as variable interpolation.

```env
TRIAGEWALL_API_KEYS='config-admin:pbkdf2_sha256$210000$<salt>$<digest>:config:write'
TRIAGEWALL_DASHBOARD_WRITE_SECRET=<long-random-string>
TRIAGEWALL_API_ALLOW_UNAUTHENTICATED_READS=true
TRIAGEWALL_CONFIG_WRITES_ENABLED=true
```

Restart the dashboard after changing `.env`, open `/configuration`, and enter
the one-time plaintext key. The browser keeps it only in the current page's
memory and clears it on reload or disconnect. Set
`TRIAGEWALL_CONFIG_WRITES_ENABLED=false` again whenever configuration mutation
should be administratively disabled; configuration access still requires the
attributable key.

### Recommended production settings

The compatibility defaults favour a first-run experience on a trusted LAN. For
anything beyond that, set all of:

```env
TRIAGEWALL_API_ALLOW_UNAUTHENTICATED_READS=false
TRIAGEWALL_API_REDACT_IPS=true
TRIAGEWALL_API_IP_HASH_SECRET=<persistent-random-secret>
TRIAGEWALL_DASHBOARD_WRITE_SECRET=<persistent-random-secret>
TRIAGEWALL_DASHBOARD_COOKIE_SECURE=true
```

The two secrets must be different from each other, and both must be persistent —
regenerating them invalidates open dashboard sessions and changes every IP
pseudonym.

## IP exposure

Responses may include internal `src_ip` / `dest_ip` values and SPC `ip` fields.
Default: **no redaction** (`TRIAGEWALL_API_REDACT_IPS=false`) so on-LAN
operators see real addresses.

Set `TRIAGEWALL_API_REDACT_IPS=true` to replace them with a **keyed
pseudonym**:

- Construction: `HMAC-SHA256(secret, "triagewall/api/ip-pseudonym/v1" || 0x00 ||
  address)`, rendered as `ip_` followed by the leading 32 hex characters.
- The secret comes from `TRIAGEWALL_API_IP_HASH_SECRET` (minimum 32
  characters). It is never logged and never appears in any error message.
- It **must differ** from `TRIAGEWALL_DASHBOARD_WRITE_SECRET`; reusing one
  secret for both means disclosing either compromises both.
- **Startup fails** if redaction is enabled without a valid secret. An unsalted
  digest of an IP address is not redaction — the address space is small enough
  to enumerate offline — so TriageWall refuses to imply protection it is not
  providing.
- Pseudonyms are deterministic within a deployment, so correlation across
  responses still works. Changing the secret changes every pseudonym.
- Verdict `reasoning`, operator `human_notes`, retained `raw_alert`, and both
  `asset_context` snapshots are omitted while redaction is enabled. Those are
  free-form channels that can repeat endpoint addresses or contain additional
  inventory addresses; withholding them keeps the boundary fail-closed rather
  than implying that changing only `src_ip` / `dest_ip` sanitized the row.

Demo mode continues to apply its stricter masking independently of this
setting.

## Endpoints

### `GET /api/v1/health`

Liveness only. No auth. Returns `{status, last_alert_age_seconds, generated_at}`.
HTTP 503 when the newest alert is older than `STALE_THRESHOLD_SECONDS`.

```bash
curl -sS -H 'Host: localhost' http://127.0.0.1:8084/api/v1/health
```

### `GET /api/v1/stats`

Summary counters for the rolling 24h window plus lifetime total. Includes
canonical `real` and deprecated `real_`. The model-only queue fields
`model_real_count`, `model_fp_count`, `model_uncertain_count`, and
`unreviewed_model_count` exclude deterministic prefilter decisions so the
operator queue can display source-of-truth totals rather than counts from only
the currently loaded page.

```bash
curl -sS -H 'Host: localhost' -H "X-API-Key: $KEY" \
  http://127.0.0.1:8084/api/v1/stats
```

### `GET /api/v1/verdicts`

Verdict rows only (no stats).

| Param | Type | Bound |
|-------|------|-------|
| `verdict` | enum | `real` \| `false_positive` \| `uncertain` |
| `model` | enum | `llm` \| `prefilter` |
| `source` | enum | `suricata` \| `wazuh` |
| `review` | enum | `unreviewed` \| `agreed` \| `corrected` |
| `signature` | string | ≤ 200 characters; signature substring, exact source/destination IP, or historical asset-hostname substring |
| `limit` | integer | 1–500, default 100 |
| `cursor` | opaque string | ≤ 512 characters |

Filter values are typed: an unrecognized `verdict`, `model`, `source`, or `review` returns **422**
rather than silently behaving like no filter. Values over a documented bound
also return 422.

The `signature` parameter name is retained for existing API clients and saved
dashboard URLs, but the workbench treats it as its bounded search term. Address
matches are exact after IPv4/IPv6 normalization. Asset names come from the
immutable source or destination snapshot stored with each verdict, so changing
the current inventory never rewrites historical search results. IP and asset
matching are disabled in demo mode and whenever
`TRIAGEWALL_API_REDACT_IPS=true`; a disclosure policy that withholds those
values must not expose them through a search-result membership oracle.
Surrounding whitespace is ignored; a whitespace-only value is the same as
omitting `signature` and does not activate a bounded search window.

Search evaluates every documented predicate inside the newest 10,000 retained
alerts. This fixed candidate window prevents an absent leading-wildcard term
from scanning the complete retained database. `search_scope` reports
`candidate_limit`, `candidates_in_scope`, and `truncated`; when `truncated` is
true, older retained alerts were not examined. The dashboard displays that
boundary rather than implying a complete-history result. A three-second SQLite
progress deadline additionally interrupts an unexpectedly slow search with
**503**; ordinary unsearched queue reads are not subject to that deadline.

Response: `{generated_at, mode, verdicts, next_cursor, search_scope,
search_window}`. Pass `next_cursor` as `cursor` for the next page. Cursor is opaque over
`(processed_at, id)`. A search cursor also carries the complete initial window:
its insertion watermark, newest candidate ceiling, oldest candidate floor, and
disclosed scope. Those indexable boundaries let later pages seek directly into
the original candidate range, so work does not grow with alerts inserted after
page one. New alerts are excluded; retention can remove initial candidates but
cannot pull an older alert into their place. Starting a fresh search observes
the current live queue.
`search_window` is a separate opaque identity returned on every searched page,
including a one-page result with no `next_cursor`. Pass it to investigation when
Previous/Next must remain inside the exact queue window the analyst loaded.

Each verdict includes nullable `zeek_context` provenance. Queue rows contain
only the eligibility reason, lookup status, source, match strategy, counts,
truncation flag, and recording time; their `context` member is always `null`.
This keeps list response cost bounded independently of the retained evidence
size. A missing `zeek_context` means enrichment was not evaluated, normally
because it was disabled or the row predates the integration.

```bash
curl -sS -H 'Host: localhost' -H "X-API-Key: $KEY" \
  'http://127.0.0.1:8084/api/v1/verdicts?limit=50&model=llm'
```

### `GET /api/v1/verdicts/{event_id}`

One complete decision for the routed alert-detail view. Response:
`{generated_at, mode, verdict}`. Unlike the bounded list endpoint, the detail
row includes the stored `raw_alert` sensor record when local-mode disclosure
policy permits it. Demo mode and API IP-redaction mode continue to omit that
field. IP-redaction mode also omits reasoning, operator notes, and asset
snapshots as described under **IP exposure**.

For a matched Zeek enrichment, the detail row's `zeek_context.context` contains
the bounded connection JSON used as untrusted model evidence. Other lookup
statuses carry provenance but no context. Demo and API IP-redaction modes omit
the entire Zeek object because free-form Zeek records can repeat endpoint
addresses that cannot be pseudonymized safely by rewriting two fields.

```bash
curl -sS -H 'Host: localhost' -H "X-API-Key: $KEY" \
  http://127.0.0.1:8084/api/v1/verdicts/1
```

### `GET /api/v1/verdicts/{event_id}/zeek-context`

Repeat the same exact, bounded tuple lookup against the current local Zeek
index at operator request, then correlate the single matched Zeek connection
with bounded, allowlisted DNS, HTTP, TLS/certificate, file, and notice records.
Application records use exact Zeek identifiers. DNS may additionally match a
recent answer for the same origin host and responder IP within five minutes.
Response:
`{generated_at, mode, event_id, stored, live}`. `stored` is the immutable
enrichment used for the verdict; `live` is the new lookup result. This endpoint
does not widen the automatic ±5-second window. Missing application-log groups
remain explicitly absent; the endpoint never infers them from connection
metadata. The stored verdict and its original connection-only model evidence
remain immutable.

The alert must have recorded eligible Zeek provenance. Rows that were not
evaluated or were ineligible return **409**. A disabled dashboard provider
returns **503**; demo mode and `TRIAGEWALL_API_REDACT_IPS=true` return **403**.
The route uses the normal read policy and is always served with `no-store`.

```bash
curl -sS -H 'Host: localhost' -H "X-API-Key: $KEY" \
  http://127.0.0.1:8084/api/v1/verdicts/1/zeek-context
```

### `GET /api/v1/verdicts/{event_id}/investigation`

Bounded recurrence, related activity, and queue-aware neighbours for one alert.
Additive: it does not change `/api/v1/verdicts` or
`/api/v1/verdicts/{event_id}`.

| Param | Type | Bound |
|-------|------|-------|
| `hours` | integer | 1–24, default 24 |
| `verdict` | enum | `real` \| `false_positive` \| `uncertain` |
| `model` | enum | `llm` \| `prefilter` |
| `source` | enum | `suricata` \| `wazuh` |
| `review` | enum | `unreviewed` \| `agreed` \| `corrected` |
| `signature` | string | ≤ 200 characters; the same queue search used by `/api/v1/verdicts` |
| `search_window` | opaque string | ≤ 512 characters; optional identity returned by the searched queue |

The filter parameters are the ones `/api/v1/verdicts` accepts, and they apply
only to `neighbors`, so previous/next stay inside the queue the analyst was
working from. An unknown event id returns **404**; unrecognized filter values
and an out-of-bound `hours` return **422**.

When `signature` search is active, pass the queue response's `search_window` to
preserve its immutable candidate boundary while opening alert details. Without
that optional context (for example, on a direct link), investigation captures a
fresh window and returns its opaque identity as top-level `search_window` for
subsequent detail navigation. `neighbors.search_scope` reports the window used;
previous and next never escape it. A `search_window` without `signature`, or a
malformed value, returns **422**. The same three-second progress deadline
applies to the search-aware neighbor query.

Response: `{generated_at, mode, event_id, window_hours, window_start,
recurrence, related, neighbors, search_window}`.

**`recurrence`** counts events sharing this alert's `(source type, signature
id)` inside the bounded candidate set. The source qualifier is load-bearing:
Suricata stores its SID in `signature_id` while Wazuh stores `rule.id` there,
so an unqualified group would merge two unrelated rules that happen to share an
integer. Rows predating source provenance are counted as Suricata. A row with
no `signature_id` has no group and reports `available: false`. `exact`,
`truncated`, `candidate_limit`, and `candidates_examined` state whether the
count covers the whole window or only its newest candidates.

**`related`** is a list of groups, each carrying `relationship`, a human
`label`, a `reason` explaining the link, and the honest scope of the query
behind it:

| Group | `exact` | Scope |
|-------|---------|-------|
| `same_rule` | conditional | Exact equality on `(source type, signature id)` inside the bounded candidate set. |
| `same_source_ip` | `false` | Exact `src_ip` equality, matched inside a bounded candidate set. |
| `same_destination_ip` | `false` | Exact `dest_ip` equality, matched inside a bounded candidate set. |

All correlation views examine at most `candidate_limit` (2000) of the newest
events in the window, selected through the `processed_at` index.
`candidates_examined` reports how many were read. `truncated: true` means an
additional row proved that older events in the window were not examined, so
recurrence counts and every related group are partial. When the candidate query
exhausts the window, recurrence and `same_rule` report `exact: true`; address
groups remain non-causal bounded matches. Each group returns at most 10 alerts.

An address match is a shared-addressing observation, not a causal finding.

**`neighbors`** is `{previous, next, filters}` in the queue's own order
(`processed_at DESC NULLS LAST, id DESC`). `previous` is the newer neighbour and
`next` the older one; either is `null` at a queue edge or when the filters
exclude every candidate. `filters` echoes what the neighbours were resolved
against.

Addresses inside `related` follow the same disclosure policy as verdict rows:
demo mode masks them, and API IP-redaction mode pseudonymizes them.

```bash
curl -sS -H 'Host: localhost' -H "X-API-Key: $KEY" \
  'http://127.0.0.1:8084/api/v1/verdicts/1/investigation?hours=24&model=llm'
```

### `POST /api/v1/feedback/{event_id}`

Body: `{"human_verdict":"real"|"false_positive"|"uncertain","notes":""}`.
`notes` is limited to 2000 characters; unknown body fields are rejected.
Requires `feedback:write` (or dashboard cookie). Disabled in demo mode.

```bash
curl -sS -X POST -H 'Host: localhost' -H "X-API-Key: $KEY" \
  -H 'Content-Type: application/json' \
  -d '{"human_verdict":"false_positive"}' \
  http://127.0.0.1:8084/api/v1/feedback/1
```

### Operator configuration

Configuration documents may contain private asset inventory and suppression
policy, so every endpoint below requires an `X-API-Key` carrying
`config:write`. That requirement is independent of ordinary API read settings.
Demo mode rejects configuration access even when such a key is supplied.

The dashboard exposes these operations at `/configuration`. Its administrator
key exists only in the current page's memory, is cleared from the password
field after connection, and is sent only in `X-API-Key`; navigation, URLs,
request bodies, logs, persistent browser storage, and the database never carry
it. Disconnecting or reloading the page discards the key. The editor follows
the API lifecycle explicitly: edit a structured candidate, inspect its exact
canonical JSON, create an immutable draft, validate it, run a bounded preview,
then confirm activation. Broad prefilter rules and candidates based on an older
shipped baseline require their specific acknowledgement before activation or
rollback.

`GET /api/v1/config` returns the active revision metadata for both kinds,
bundle generation, compatibility mode, revision counts, and per-consumer
reload health. Health includes each consumer's desired and loaded generation,
loaded revision pair, status age, and a bounded generic error. A missing Wazuh
row means the optional Wazuh ingest has not started; it is not synthesized as
healthy. `GET /api/v1/config/{kind}` returns the active canonical document for
`prefilter_policy` or `asset_inventory`. `GET /api/v1/config/{kind}/revisions`
lists newest-first revision metadata without documents; it accepts `state`,
`limit` (1–100), and an opaque `cursor`. The per-revision endpoint,
`GET /api/v1/config/{kind}/revisions/{id}`, retrieves one immutable document.

Draft mutation is disabled unless:

```env
TRIAGEWALL_CONFIG_WRITES_ENABLED=true
```

Enabling this without at least one configured `config:write` key fails process
startup. Draft creation requires the current active revision and generation:

```bash
curl -sS -X POST -H 'Host: localhost' -H "X-API-Key: $CONFIG_KEY" \
  -H 'X-Request-ID: change-2026-08-15-01' \
  -H 'Content-Type: application/json' \
  -d '{"document":{"version":1,"internal_cidrs":[],"auto_false_positive":[]},"parent_revision_id":1,"expected_generation":1,"note":"candidate"}' \
  http://127.0.0.1:8084/api/v1/config/prefilter_policy/drafts
```

Revision content is unique per kind, so an identical resubmission cannot create
a second row. When the existing revision is still an unactivated candidate off
the very parent named in the request, creation returns that revision with
`"resumed": true` and `200` instead of `201`, which lets an operator who lost
editor state resume it. That covers a `draft`, a `validated` revision, and a
draft that validation normalized; resubmitting the canonical form of a
normalized candidate returns the same submitted handle, found by exact pointer
match rather than by scanning recent history, so ordinary activation and
rollback churn against the same parent cannot bury it. `validated_revision_id`
names the validated result when there already is one, so a resumed candidate
continues at preview. Any other existing state, and any candidate raised against
a different parent, stay a `409`.

`POST /api/v1/config/{kind}/drafts/{id}/validate` applies the production
validator. An invalid candidate becomes an immutable `rejected` revision with
a structured validation result. When normalization changes the effective
document, validation preserves the submitted draft and creates a canonical
`validated` child, or reuses the existing revision that already holds that exact
canonical content. Because content and digests are immutable, a reused revision
keeps its own lineage and state; the response reports the submitted draft's
`candidate_parent_revision_id`, and preview and activation are addressed by the
submitted draft id, which carries that parent relationship forward. Neither
operation activates configuration or changes the bundle generation.

`POST /api/v1/config/{kind}/drafts/{id}/preview` accepts
`expected_generation`, a capped time window, and a candidate limit up to
2,000. It refuses a candidate whose parent is no longer active before sampling
anything. It compares only the newest eligible events, reports the examined count
and whether the sample was truncated, never calls Ollama, and never changes
verdicts or checkpoints. The sample is bounded by rows and by aggregate alert
bytes, and reaching the byte budget is reported as truncation with a warning.
That budget is enforced from the alert size recorded beside each record at
ingestion, so an oversized body is never read. A record retained before those
sizes existed has no trusted length, so the sample stops there and reports it
rather than reading an unmeasured body.
Events retained before sensor context existed are included; only records
positively identified as another sensor are excluded from a prefilter preview.
Prefilter previews report suppression deltas, bounded event/signature examples,
unmatched rules, and unscoped-rule warnings. Asset previews report exact-IP
match and context changes with bounded examples in `summary.counts`, and report
suppression separately in `summary.suppression`: an inventory edit also moves
deterministic verdicts when the active policy scopes rules by `source_asset` or
`destination_asset`, so the active policy is evaluated against both inventories
for each eligible Suricata record in the same bounded sample. A policy with no
asset-scoped rule cannot move a decision, so that analysis is complete without
reading any alert body. `summary.suppression.complete` is false when truncation
or an unreadable record left an asset-scoped rule unevaluated.

`POST /api/v1/config/{kind}/drafts/{id}/activate` requires the current
`expected_generation`. Prefilter candidates containing signature-only rules
also require `acknowledge_broad_rules=true`. While asset-scoped prefilter rules
are active, an asset inventory activates only on evidence of a preview that
actually evaluated them at this generation, or on an explicit
`acknowledge_incomplete_asset_preview=true`; a rollback has no preview of its
own and always requires that acknowledgement. An enrichment-only summary is
never presented as the whole change. Activation revalidates stored
content under `BEGIN IMMEDIATE`, checks the draft parent is still active, moves
the old and new revision states, updates both previous-bundle pointers, and
increments generation in one transaction. While the deployment remains in
`legacy` authority mode, the first successful activation atomically changes
authority to `database`; both ingest processes observe the new complete bundle
between records. A candidate based on an older packaged prefilter baseline also
requires `acknowledge_shipped_base_change=true`.

`POST /api/v1/config/{kind}/revisions/{id}/rollback` reactivates a previously
active superseded revision through the same validation, acknowledgement,
optimistic-generation, transaction, audit, and runtime-reload path. Rollback
creates a new bundle generation; it never rewrites revision content or restores
files. A superseded draft that validation normalized was never active and is
refused with `409`; the editor does not offer it as a rollback target.

Refused mutations are themselves evidence. A stale generation, a parent that is
no longer active, a missing acknowledgement, and a refused rollback each append
one bounded, attributable audit record naming the reason, which survives the
rollback of the refused change. These records never contain document content,
notes, or credentials.

`GET /api/v1/config/audit` returns newest-first audit records with `limit`
(1–100, default 50), optional `kind`, and an opaque `cursor`. Audit details are
bounded lifecycle metadata and never contain configuration documents or API
keys. All configuration responses use `Cache-Control: private, no-store` and
emit no ETag.

New verdict rows also store `config_generation`, `prefilter_revision`, and
`asset_revision`. Both ingest adapters load both documents as one immutable
bundle. While authority remains `legacy`, each consumer start mirrors the
mounted documents into the durable bundle through the same serialized,
fail-closed transaction the one-shot bootstrap uses, then publishes exactly what
it mirrored. Every authoritative read happens inside that transaction, so two
consumers starting at once cannot commit mount snapshots out of order. When a
peer has already mirrored a newer generation, the other consumer adopts those
durable documents rather than classifying on its obsolete start-time snapshot,
and records one bounded audit event naming the adopted generation, so both
consumers converge on one immutable bundle. In `database` mode, no file is read
at all, so a missing or malformed mount, or a host with no packaged default,
cannot block a start from a valid durable bundle. Startup fails closed without a
valid complete bundle; a later reload failure retains the last-known-good bundle,
reports degraded health, records bounded audit evidence, and retries with
bounded backoff.

### `GET /api/v1/timeline`

Hourly buckets. Query: `hours` (1–168, default 24), `interval` (typed enum;
`1h` is the only accepted value in v1 — anything else is a 422). Response wraps
buckets with `generated_at`, `hours`, and `interval`.

```bash
curl -sS -H 'Host: localhost' -H "X-API-Key: $KEY" \
  'http://127.0.0.1:8084/api/v1/timeline?hours=24&interval=1h'
```

### `GET /api/v1/spc-anomalies`

Recent SPC anomalies plus `count_24h` when the table exists.

```bash
curl -sS -H 'Host: localhost' -H "X-API-Key: $KEY" \
  http://127.0.0.1:8084/api/v1/spc-anomalies
```

### `GET /metrics`

Prometheus text exposition. Auth follows the unauthenticated-reads toggle.

```bash
curl -sS -H 'Host: localhost' -H "X-API-Key: $KEY" \
  http://127.0.0.1:8084/metrics
```

## Response contract enforcement

Every `/api/v1/*` response is validated against its declared Pydantic model
**at runtime**, before the ETag is computed and before anything is written to
the wire. The response models use `extra="forbid"`, so an undocumented field or
a wrong type is a server-side failure (HTTP 500) rather than something that
silently leaks into the stable contract.

One deliberate exception: the `asset_context.source` and
`asset_context.destination` objects stay free-form dictionaries. Their contents
come from the operator's own asset inventory, so TriageWall does not invent a
schema for fields it does not define.

## Caching

Read endpoints that are safe to poll emit `Cache-Control: private, max-age=…`
and a weak `ETag`. The ETag is derived from the **validated** representation,
so it always matches the bytes actually served. Send `If-None-Match` to receive
HTTP 304 when unchanged. Stats/timeline/SPC results also use short in-process
TTL caches. Payloads include `generated_at` (UTC).

The verdict and configuration endpoints are the exception. `GET /api/v1/verdicts`,
`GET /api/v1/verdicts/{event_id}` and
`GET /api/v1/verdicts/{event_id}/investigation` emit
`Cache-Control: private, no-store` and **no** `ETag`, and never answer 304.
The `/api/v1/config*` family uses the same no-store policy because its private
documents and lifecycle state must not be retained by intermediaries.
Saving operator feedback rewrites the underlying row, so a stored or
revalidated copy would report a reviewed alert as unreviewed. Stats, timeline,
SPC and health keep their existing caching, as does the deprecated
`GET /api/verdicts` alias, whose shape and headers are frozen until removal.

## Deprecated aliases

| Alias | Behavior |
|-------|----------|
| `GET /api/health` | Like v1 health **plus** `storage` metrics (dashboard UI depends on this). |
| `GET /api/verdicts` | Combined `{mode, stats, verdicts}` without cursor pagination. |
| `GET /api/timeline` | Bare JSON array of buckets (24h / 1h). |
| `GET /api/spc-anomalies` | Same data as v1 (includes `generated_at`). |
| `POST /api/feedback/{id}` | Same as v1 write path (auth required). |

The aliases keep their historical behaviour until removal: their shapes are
frozen, and unrecognized filter values are still ignored rather than rejected.
New clients should use `/api/v1/*`, where those values are 422s.

`GET /api/verdicts` keeps that frozen `{mode, stats, verdicts}` shape, its
lenient filter vocabulary, and its lack of cursor fields, but its `signature`
search does the same bounded work as v1: the term is capped at 200 characters,
matching is limited to the newest 10,000 retained candidates, and the query-time
budget applies. An over-long term returns 422 and an exhausted budget returns
503. The alias remains **signature-only** — it does not search source or
destination addresses or historical asset hostnames, which stay a v1 addition.
Requests without a `signature`, or with a whitespace-only one, remain ordinary
unsearched reads outside that deadline.

Removal target: **2026-12-31**.
