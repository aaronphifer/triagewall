# Event-bundle v1 contract

Status: Phase 0 contract; exporter and Lab importer are not yet wired

Schema: [`schemas/event-bundle-v1.schema.json`](../schemas/event-bundle-v1.schema.json)

Reference validator: [`triagewall/event_bundle.py`](../triagewall/event_bundle.py)

## Purpose and authority

Event-bundle v1 is the only planned data handoff from TriageWall Core to the
private TriageWall Lab. Core creates and redacts a bundle at an operator's
explicit request. Lab treats the resulting file as hostile input, validates the
entire file, and publishes it to immutable local storage only after validation
succeeds.

The bundle records historical inputs and outcomes. It never selects a Lab
model, model host, prompt, policy, candidate, filesystem path, network
destination, or runtime option. Those choices come only from trusted Lab
configuration. In particular, `model.inference_options_json` is provenance;
an importer must not pass uploaded options directly to a model runtime.

## Encoding

One bundle is one uncompressed UTF-8 JSON document without a byte-order mark.
Archives, compression, JSON Lines, multipart documents, and trailing companion
files are not v1.

The identity fields are exact:

- `schema` is `triagewall.event-bundle`;
- `version` is the integer `1`;
- unknown fields and unknown versions fail closed;
- duplicate object keys, non-finite numbers, invalid UTF-8, and noncanonical
  embedded JSON fail closed.

JSON Schema defines the portable static shape. The reference validator is
normative for byte limits, canonicalization, component hashes, bundle hashes,
event counts, feedback-manifest consistency, prefilter-revision consistency,
and Zeek status/eligibility invariants that JSON Schema cannot fully express.

## Envelope

| Area | Meaning |
|---|---|
| Bundle identity | Stable bundle ID, canonical creation time, Core version, and immutable exporter revision |
| Redaction | Named policy, policy revision, exact transformations, and whether operator feedback was deliberately included |
| Revisions | Prompt, response contract, evidence projection, prefilter policy, and asset inventory identities used historically |
| Model | Historical model name, immutable digest when available, and canonical inference-option provenance |
| Events | One to 1,000 bounded, independently identified replay records |
| Integrity | Component hashes plus one canonical digest covering the complete envelope and event array |

Every event contains:

- a strict normalized `SensorEvent` projection for Suricata or Wazuh;
- bounded source and agent provenance;
- the exact bounded source-specific text supplied at the model boundary;
- the trusted historical asset-context snapshot as canonical JSON;
- the prefilter outcome and immutable policy revision;
- automatic model-time Zeek provenance and, when deliberately exported, a
  separate operator-time Zeek layer;
- the original bounded model response, including invalid text when validation
  rejected it, plus the validation result and retained final verdict;
- optional human verdict and condition-specific Zeek contribution/fact labels,
  plus optional deliberately included operator feedback.

The source event is a normalized field set rather than an unrestricted raw
sensor record. `model_projection.content` preserves the exact bounded source
projection needed for replay. This avoids turning a portable bundle into a raw
log export.

## Zeek evidence layers

`zeek.automatic` records what the automatic classification path could use.
`zeek.operator`, when non-null, records a later explicit deep lookup. A Lab
runner may create an experimental deeper-evidence condition from the operator
layer, but it must never relabel that evidence as model-time production input.

Each layer records eligibility, lookup status, source instance, match strategy,
record and candidate counts, truncation, and an optional canonical context
object. A `matched` layer requires context, at least one record, and exactly one
candidate. Ambiguous and nonmatched results cannot carry automatic model
context.

The reference validator also restricts context field names to the production
Zeek projection plus the legacy Lab SSL/X.509 aliases. This prevents an
uploaded bundle from moving instruction-like text into an object key. At the
model boundary, every Zeek string value is base64-isolated regardless of its
field name; no UID, service, protocol, address, timestamp, or application value
is trusted merely because it occupies an expected path.

Automatic eligibility is recomputed from the normalized event and prefilter
outcome. Wazuh events are `unsupported_source`; prefilter-resolved Suricata
events are `prefilter_resolved`; incomplete or unsupported flows retain the
corresponding deterministic reason. Ineligible events must have a `disabled`
automatic lookup.

## Canonical JSON and integrity

Canonical JSON uses sorted object keys, no insignificant whitespace, ASCII
escaping, and finite JSON numbers. Embedded inference options, asset context,
and Zeek context must already use this representation.

Text components are hashed over their exact UTF-8 bytes:

```text
sha256:<64 lowercase hexadecimal characters>
```

`content_sha256` covers the canonical JSON representation of the complete
top-level document after removing only the `content_sha256` member. It therefore
covers the manifest, redaction claims, revision identities, model provenance,
event order, labels, feedback, and all component hashes without creating a
self-referential digest.

The digest detects accidental or unauthenticated modification; it is not a
signature and does not prove who created a bundle. File origin and operator
authorization remain separate concerns.

## Limits

| Limit | v1 value |
|---|---:|
| Raw or canonical bundle | 64 MiB |
| Events per bundle | 1,000 |
| Model projection per event | 64 KiB UTF-8 |
| Asset or Zeek evidence layer | 64 KiB UTF-8 |
| Original model response | 64 KiB UTF-8 |
| Inference-option provenance | 8 KiB UTF-8 |
| General free-text field | 2,000 characters |
| Allowed Zeek facts per label | 32 |

When labels are present, `condition_labels` contains exact entries for
`no_zeek`, `connection_only`, and `connection_plus_application`. The no-Zeek
entry is always `unavailable` with an empty fact list. A matched automatic or
operator layer requires a non-unavailable contribution and at least one
allowed fact; a nonmatched or absent layer requires `unavailable` and no facts.
This prevents one event-wide label from incorrectly treating connection-only
and deeper application evidence as equivalent ground truth.

JSON Schema character limits are a portable first check. The reference
validator additionally enforces UTF-8 byte limits before an object crosses the
import boundary.

## Redaction and exclusions

The redaction manifest uses enumerated transformations rather than free-form
claims. Its operator-feedback marker must agree with both the boolean manifest
field and the actual event contents.

Bundles never contain:

- the live prompt-injection canary;
- API keys, cookies, credentials, or authentication headers;
- Core database pages, checkpoints, or unrestricted raw sensor logs;
- host filesystem paths, Docker socket information, or runtime mounts;
- a model endpoint, callback, redirect, or other uploaded network control;
- an uploaded prompt, candidate, or executable policy.

Evidence text may naturally describe paths, URLs, hosts, or commands observed
by a sensor. Lab must keep all such strings inside the untrusted evidence
boundary and must never interpret them as configuration.

## Versioning

V1 fields cannot change meaning. Adding, removing, or changing a field requires
a new bundle version because v1 rejects unknown fields. A Lab importer may
support multiple explicit versions, but it must never guess a version or
downgrade an unknown document.

The sanitized
[`suricata-zeek-correlative.json`](../tests/fixtures/event_bundle_v1/suricata-zeek-correlative.json)
fixture is the first cross-implementation conformance example. It uses IANA
documentation address ranges and contains no production event or asset data.

## Next contract work

This slice intentionally does not export production data or run a model. The
candidate/experiment/result/report contracts, the
[Lab threat model](lab-threat-model.md), and the
[hostile-upload matrix](lab-hostile-upload-matrix.md) are now defined. The
initial [sanitized Zeek scenario set](lab-zeek-scenarios-v1.md) supplies
condition-specific human labels and fact allowlists. The remaining Phase 0
sequence is:

1. review and freeze all Phase 0 contracts, scenarios, and security inputs;
2. implement the explicit Core exporter and private Lab importer only after
   that review.
