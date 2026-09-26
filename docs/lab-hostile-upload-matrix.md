# TriageWall Lab hostile-upload matrix

Status: Phase 0 executable contract matrix plus Phase 1 runtime requirements

Threat model: [TriageWall Lab threat model](lab-threat-model.md)

V1 accepts one uncompressed UTF-8 JSON event-bundle. The matrix treats every
byte and every nested evidence value as hostile even when a file appears to
have been exported by Core. `Enforced` means the Phase 0 reference validator
and an executable test exist. `Deferred` means the control belongs to the
future importer, runner, storage, API, or exporter and must block graduation;
it is not claimed as implemented.

## Byte, parser, and envelope boundary

| ID | Hostile case | Required result | Status | Test or required evidence |
|---|---|---|---|---|
| HU-001 | Empty input | Reject before parsing | Enforced | `HostileEventBundleMatrixTests.test_transport_rejects_empty_archive_trailing_and_non_object_inputs` |
| HU-002 | Raw payload exceeds 64 MiB, including invalid UTF-8 bytes | Reject on byte count before decode/JSON work | Enforced | `EventBundleV1Tests.test_raw_payload_limit_is_checked_before_json_decode`; `HostileEventBundleMatrixTests.test_raw_byte_limit_precedes_utf8_and_json_work` |
| HU-003 | UTF-8 BOM or invalid UTF-8 | Reject; never use replacement decoding | Enforced | `EventBundleV1Tests.test_utf8_bom_and_invalid_utf8_are_rejected` |
| HU-004 | Archive signature, compression, multipart data, trailing JSON, scalar, or array | Reject as non-v1 strict JSON object; never extract | Enforced | `HostileEventBundleMatrixTests.test_transport_rejects_empty_archive_trailing_and_non_object_inputs` |
| HU-005 | Duplicate object keys at any depth | Reject before semantic validation | Enforced | `EventBundleV1Tests.test_duplicate_json_keys_are_rejected_before_validation` |
| HU-006 | `NaN`, positive/negative infinity, or non-finite nested number | Reject before semantic validation | Enforced | `EventBundleV1Tests.test_nonfinite_json_numbers_are_rejected` |
| HU-007 | Excessive JSON nesting or recursion failure | Convert to a bounded contract error; do not crash the process | Enforced | `EventBundleV1Tests.test_embedded_json_recursion_failure_is_a_contract_error`; loader recursion handling in `triagewall/event_bundle.py` |
| HU-008 | Wrong schema/version, missing field, unknown field, or JSON type confusion such as boolean-for-integer | Reject closed and fail version/type checks | Enforced | `EventBundleV1Tests.test_unknown_fields_fail_closed`; `HostileEventBundleMatrixTests.test_schema_version_missing_field_and_type_confusion_fail_closed` |
| HU-009 | Decoded/canonical document expands beyond the raw limit | Reject before publication | Enforced | Canonical-size check in `triagewall/event_bundle.py`; maximum-event and component tests below |

## Integrity, identity, and cross-field state

| ID | Hostile case | Required result | Status | Test or required evidence |
|---|---|---|---|---|
| HU-010 | Top-level digest changed or stale after any field mutation | Reject | Enforced | `EventBundleV1Tests.test_bundle_content_digest_covers_manifest_and_events` |
| HU-011 | Projection, asset, Zeek, inference-option, or model-response content does not match its component digest | Reject | Enforced | `EventBundleV1Tests.test_embedded_json_must_be_canonical_and_hash_matched`; `HostileEventBundleMatrixTests.test_historical_response_hash_and_state_cannot_be_rewritten` |
| HU-012 | Embedded JSON is noncanonical, has duplicate keys, is non-object, or exceeds its byte limit | Reject | Enforced | `EventBundleV1Tests.test_embedded_json_must_be_canonical_and_hash_matched`; strict embedded loader tests |
| HU-013 | Multibyte text is within a character count but exceeds a UTF-8 byte limit | Reject on encoded byte length | Enforced | `HostileEventBundleMatrixTests.test_unicode_projection_limit_is_measured_in_utf8_bytes` |
| HU-014 | Event manifest count differs from array length, event array is empty/oversized, or event IDs repeat | Reject | Enforced | `HostileEventBundleMatrixTests.test_duplicate_event_identity_and_manifest_count_are_rejected` |
| HU-015 | Bundle, source, match, or event identifier contains slash, backslash, traversal, whitespace, or shell syntax | Reject as an unsafe identifier; never derive a path from it | Enforced | `HostileEventBundleMatrixTests.test_identifiers_cannot_smuggle_paths` |
| HU-016 | Prefilter event revision differs from the bundle revision | Reject | Enforced | `EventBundleV1Tests.test_prefilter_revision_must_match_bundle_revision` |
| HU-017 | Historical model identity differs from the bundle provenance, or prefilter/model validation state is contradictory | Reject | Enforced | `EventBundleV1Tests.test_historical_model_identity_must_match_bundle`; `HostileEventBundleMatrixTests.test_historical_response_hash_and_state_cannot_be_rewritten` |
| HU-018 | Feedback manifest/marker disagrees with actual feedback presence | Reject | Enforced | `EventBundleV1Tests.test_feedback_manifest_must_match_event_contents` |
| HU-019 | Redaction markers are missing, duplicated, contradictory, or unknown | Reject | Enforced | `EventBundleV1Tests.test_redaction_transformations_are_complete_and_exclusive` |
| HU-020 | Redaction manifest is internally valid but free text still contains a private value or secret | Future exporter must detect/preview; importer must not claim that hashes prove redaction | Deferred | Core exporter field-aware redaction corpus, operator preview, and secret-seed tests required |
| HU-021 | A fully forged document has self-consistent hashes and plausible provenance | Treat provenance/origin as unauthenticated claims | Deferred | Import UI must show origin status; decide signature or authenticated handoff before automatic transfer |

## Capability and evidence isolation

| ID | Hostile case | Required result | Status | Test or required evidence |
|---|---|---|---|---|
| HU-022 | Upload adds `filesystem_path`, model host, callback, candidate, prompt, policy, or runtime-option selector | Reject as unknown fields | Enforced | `HostileEventBundleMatrixTests.test_uploaded_capability_selectors_are_not_contract_fields` |
| HU-023 | Evidence text contains a path, URL, command, prompt injection, or setting-like text | Preserve only as bounded evidence; never interpret it as configuration | Contract and private runner enforced | `HostileEventBundleMatrixTests.test_path_url_and_instruction_strings_remain_untrusted_evidence`; `LabRunnerTests.test_paired_run_uses_only_candidate_options_and_scores_explicit_fact` |
| HU-024 | Uploaded historical `inference_options_json` is malformed, noncanonical, or hash-mismatched | Reject | Enforced | `HostileEventBundleMatrixTests.test_inference_provenance_cannot_supply_noncanonical_options` |
| HU-025 | Uploaded historical inference options are valid and attacker-chosen | Retain only as provenance; execute the trusted candidate settings | Enforced in private runner | `LabRunnerTests.test_paired_run_uses_only_candidate_options_and_scores_explicit_fact`; `LabRunnerTests.test_experiment_builder_snapshots_core_prompt_and_uses_trusted_options` |
| HU-026 | Wazuh, prefilter-resolved, missing-endpoint, unsupported-protocol, or missing-port event claims automatic Zeek eligibility | Recompute eligibility from normalized fields and reject disagreement | Enforced | `HostileEventBundleMatrixTests.test_automatic_eligibility_is_recomputed_for_every_ineligible_class` |
| HU-027 | Matched lookup has no context, zero/multiple candidates, or no records | Reject | Enforced | `EventBundleV1Tests.test_matched_zeek_requires_exactly_one_candidate_and_context` |
| HU-028 | Ambiguous/nonmatched lookup carries attacker-selected context, records, candidates, or truncation state | Reject | Enforced | `HostileEventBundleMatrixTests.test_ambiguous_lookup_cannot_carry_attacker_selected_context` |
| HU-029 | Ineligible event carries an operator Zeek layer, or an operator layer claims noneligible state | Reject | Enforced | Cross-field checks in `triagewall/event_bundle.py`; eligibility matrix tests |
| HU-030 | Prefilter-resolved event reintroduces model output or Zeek work | Reject contradictory state | Enforced | `HostileEventBundleMatrixTests.test_prefilter_resolved_event_cannot_reintroduce_model_or_zeek_work` |
| HU-031 | Bundle evidence instructs the model to ignore policy, reveal the canary, cross source boundaries, or fabricate Zeek use | Bound and isolate evidence; flag disclosure/instruction following/unsupported facts; block promotion | Private runner/scorer partial; live corpus run and report gates deferred | Fresh canary and injection scoring tests in `LabRunnerTests` and `LabEvidenceScoringTests`; all-condition live execution remains required |
| HU-032 | No-Zeek condition induces Zeek claims | Score as unsupported and block promotion | Enforced in private runner/scorer | `LabRunnerTests.test_no_zeek_condition_omits_context_and_catches_false_claim`; `LabEvidenceScoringTests.test_no_zeek_negative_control_distinguishes_absence_from_claim` |

## File staging, storage, execution, and output

| ID | Hostile case | Required result | Status | Test or required evidence |
|---|---|---|---|---|
| HU-033 | Operator-selected upload path is a symlink, directory, device, socket, reparse point, or changes during validation | Refuse unsafe type; validate private staged bytes; publish only that identity | Private CLI partial; staging/TOCTOU/reparse coverage deferred | CLI rejects symlinks and non-regular inputs; platform-specific replacement tests remain required |
| HU-034 | Two imports race on the same ID/digest or one fails mid-publication | One immutable object or a safe duplicate result; no partial visible object | Private result publication partial; import store deferred | Same-directory atomic no-replace result publication and completion manifest in `scripts/run_lab_experiment.py`; crash/restart tests remain required |
| HU-035 | Import error contains raw evidence, path secrets, credentials, or a large parser message | Return bounded structured diagnostics without private bytes | Deferred | Log/error snapshot tests with sentinel secrets and 64 MiB inputs |
| HU-036 | Many valid uploads consume disk indefinitely | Enforce per-object/total quotas and bounded retention without touching Core storage | Deferred | Quota boundary, concurrent import, prune, low-disk, and recovery tests |
| HU-037 | Experiment requests maximum events × conditions × repetitions or many concurrent runs | Bound queue, concurrency, model calls, wall time, cancellation, and result storage | Private CLI partial | Results stream without eager accumulation and each call has a total deadline; queue, cancellation, run deadline, quota, and restart tests remain required |
| HU-038 | Ollama endpoint redirects or uploaded content resembles a destination/model selector | Use one trusted configured destination and model digest; reject redirects | Enforced in private CLI | Literal loopback/RFC1918/ULA destination allowlist, redirect rejection, `/api/tags` digest preflight, response-model binding, and mock adapter tests in `LabRunnerTests` |
| HU-039 | Model output is malformed, truncated, oversized, slow, canary-bearing, or contains injected instructions | Fail/score conservatively, redact live canary before persistence, never count as valid completion | Private CLI partial; live injection and cancellation deferred | `LabRunnerTests.test_malformed_model_output_matrix_fails_closed`, canary/timeout tests, exact byte caps, and total transport deadline; live all-condition injection execution remains required |
| HU-040 | Private event IDs, evidence, prompts, model responses, reasoning, or per-result digests enter a shareable report | Reject export and fail closed | Report envelope enforced; generator deferred | Closed report contract tests plus generator sentinel-leak tests across JSON, logs, UI, metrics, and downloaded files |
| HU-041 | Incomplete/unsafe report claims `eligible` or sets production authority | Derive `incomplete`/`blocked`; require `does_not_authorize_production=true` | Enforced contract | `LabContractsV1Tests` promotion-status, gate, and no-authority tests |
| HU-042 | Unauthenticated LAN user imports, runs, reads, exports, or deletes | Default loopback; require reviewed authentication and write protections before LAN | Deferred | Bind-address startup tests; read/write/export/delete authorization matrix; CSRF/origin tests for browser UI |
| HU-043 | Lab container can read Core state, use Docker, or reach a production write surface | Deny by construction in every installation mode | Deferred | Compose/container inspection plus runtime negative-access tests for Core-only, Lab-only, and combined deployments |

## Exit criteria

Phase 0 is complete when all `Enforced` rows pass in the full repository suite,
the threat model and matrix are reviewed, and every deferred item has an owner
in the implementation sequence. `Partial` and deferred rows remain graduation
blockers; they must never be converted to `Enforced` based only on
documentation.

The initial [balanced sanitized Zeek scenario set](lab-zeek-scenarios-v1.md)
now supplies the human verdicts, condition-specific contribution labels, and
exact fact lists needed to execute HU-031 and HU-032 in the private runner.
