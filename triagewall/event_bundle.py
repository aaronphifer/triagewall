"""Strict, bounded contract for the Core-to-Lab event-bundle v1 boundary."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
from copy import deepcopy
from typing import Any

try:
    from .time_utils import format_utc_timestamp
except ImportError:  # Direct script-style imports used by container entrypoints.
    from time_utils import format_utc_timestamp


EVENT_BUNDLE_SCHEMA = "triagewall.event-bundle"
EVENT_BUNDLE_VERSION = 1
MAX_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_EVENTS = 1_000
MAX_PROJECTION_BYTES = 64 * 1024
MAX_EVIDENCE_BYTES = 64 * 1024
MAX_MODEL_RESPONSE_BYTES = 64 * 1024
MAX_OPTIONS_BYTES = 8 * 1024
MAX_FREE_TEXT_CHARS = 2_000
MAX_ALLOWED_ZEEK_FACTS = 32
MAX_EMBEDDED_JSON_DEPTH = 64

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}$")
_PROTOCOL_RE = re.compile(r"^[A-Z][A-Z0-9._-]{0,31}$")

_TOP_FIELDS = {
    "schema",
    "version",
    "bundle_id",
    "created_at",
    "core_version",
    "exporter_revision",
    "event_count",
    "content_sha256",
    "redaction",
    "revisions",
    "model",
    "events",
}
_REDACTION_FIELDS = {
    "policy",
    "policy_revision",
    "transformations",
    "operator_feedback_included",
}
_REVISION_FIELDS = {
    "prompt_template",
    "response_contract",
    "evidence_projection",
    "prefilter_policy",
    "asset_inventory",
}
_MODEL_FIELDS = {
    "name",
    "digest",
    "inference_options_json",
    "inference_options_sha256",
}
_EVENT_FIELDS = {
    "event_id",
    "sensor_event",
    "provenance",
    "model_projection",
    "asset_context",
    "prefilter",
    "zeek",
    "historical_result",
    "labels",
    "operator_feedback",
}
_SENSOR_FIELDS = {
    "schema_version",
    "source",
    "timestamp",
    "signature_id",
    "signature",
    "flow_id",
    "src_ip",
    "src_port",
    "dest_ip",
    "dest_port",
    "proto",
    "in_iface",
    "pkt_src",
    "category",
    "severity",
    "action",
}
_PROVENANCE_FIELDS = {
    "source_instance",
    "source_event_id",
    "agent_id",
    "agent_name",
}
_TEXT_BLOB_FIELDS = {"format", "content", "sha256"}
_PREFILTER_FIELDS = {"outcome", "verdict", "reason", "policy_revision"}
_ZEEK_FIELDS = {"automatic", "operator"}
_ZEEK_LAYER_FIELDS = {
    "lookup_status",
    "eligibility_reason",
    "source_instance",
    "match_strategy",
    "record_count",
    "candidate_count",
    "truncated",
    "context_json",
    "context_sha256",
}
_HISTORICAL_FIELDS = {
    "model_response",
    "model_response_sha256",
    "validation_status",
    "validation_reason",
    "final_verdict",
    "confidence",
    "reasoning",
    "model_used",
}
_LABEL_FIELDS = {
    "human_verdict",
    "condition_labels",
    "notes",
}
_CONDITION_LABELS_FIELDS = {
    "no_zeek",
    "connection_only",
    "connection_plus_application",
}
_CONDITION_LABEL_FIELDS = {"zeek_contribution", "allowed_zeek_facts"}
_FEEDBACK_FIELDS = {"decision", "note", "reviewed_at"}

_REDACTION_TRANSFORMATIONS = {
    "agent_identifiers_pseudonymized",
    "operator_feedback_excluded",
    "operator_feedback_included",
    "private_addresses_preserved",
    "private_addresses_pseudonymized",
    "raw_sensor_event_excluded",
    "sensor_instance_pseudonymized",
}
_ZEEK_STATUSES = {
    "disabled",
    "matched",
    "no_match",
    "ambiguous",
    "unavailable",
    "invalid_response",
}
_ZEEK_ELIGIBILITY = {
    "eligible",
    "prefilter_resolved",
    "unsupported_source",
    "missing_endpoint",
    "unsupported_protocol",
    "missing_port",
}
_VERDICTS = {"real", "false_positive", "uncertain"}


class EventBundleError(ValueError):
    """Raised when an event bundle violates the public v1 contract."""


def canonical_json(value: Any) -> str:
    """Return the sole canonical JSON representation used by this contract."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def sha256_text(value: str) -> str:
    """Hash exact UTF-8 text with the contract's prefixed digest form."""

    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def bundle_content_digest(document: dict[str, Any]) -> str:
    """Hash canonical bundle content while excluding its self-naming digest."""

    unsigned = deepcopy(document)
    unsigned.pop("content_sha256", None)
    return sha256_text(canonical_json(unsigned))


def _fail(location: str, message: str) -> None:
    raise EventBundleError(f"{location} {message}")


def _object(value: Any, fields: set[str], location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(location, "must be an object")
    missing = fields - set(value)
    unknown = set(value) - fields
    if missing:
        _fail(location, f"is missing fields: {', '.join(sorted(missing))}")
    if unknown:
        _fail(location, f"contains unknown fields: {', '.join(sorted(unknown))}")
    return value


def _text(
    value: Any,
    location: str,
    *,
    maximum: int = MAX_FREE_TEXT_CHARS,
    nullable: bool = False,
    nonempty: bool = True,
) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str):
        _fail(location, "must be a string")
    if nonempty and not value.strip():
        _fail(location, "must not be empty")
    if len(value) > maximum:
        _fail(location, f"must be at most {maximum} characters")
    return value


def _safe_id(value: Any, location: str, *, nullable: bool = False) -> str | None:
    text = _text(value, location, maximum=128, nullable=nullable)
    if text is not None and _SAFE_ID_RE.fullmatch(text) is None:
        _fail(location, "must be a safe identifier")
    return text


def _digest(value: Any, location: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        _fail(location, "must be a lowercase prefixed SHA-256 digest")
    return value


def _integer(
    value: Any,
    location: str,
    *,
    minimum: int,
    maximum: int,
    nullable: bool = False,
) -> int | None:
    if nullable and value is None:
        return None
    if type(value) is not int or not minimum <= value <= maximum:
        _fail(location, f"must be an integer from {minimum} to {maximum}")
    return value


def _number(value: Any, location: str, *, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _fail(location, "must be numeric")
    number = float(value)
    if not math.isfinite(number) or not minimum <= number <= maximum:
        _fail(location, f"must be finite and from {minimum:g} to {maximum:g}")
    return number


def _timestamp(value: Any, location: str) -> str:
    text = _text(value, location, maximum=64)
    try:
        canonical = format_utc_timestamp(text)
    except (TypeError, ValueError) as exc:
        raise EventBundleError(f"{location} must be an ISO-8601 timestamp") from exc
    if canonical != text:
        _fail(location, "must use canonical UTC form")
    return text


def _optional_ip(value: Any, location: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        _fail(location, "must be an IP address string or null")
    try:
        canonical = str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise EventBundleError(f"{location} must be an IP address or null") from exc
    if canonical != value:
        _fail(location, "must use canonical IP-address form")
    return value


def _enum(value: Any, choices: set[str], location: str, *, nullable: bool = False):
    if nullable and value is None:
        return None
    if not isinstance(value, str) or value not in choices:
        _fail(location, f"must be one of: {', '.join(sorted(choices))}")
    return value


def _load_embedded_json(value: Any, location: str, *, maximum_bytes: int) -> dict:
    text = _text(value, location, maximum=maximum_bytes)
    if len(text.encode("utf-8")) > maximum_bytes:
        _fail(location, f"exceeds the {maximum_bytes}-byte limit")
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except EventBundleError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise EventBundleError(f"{location} must contain strict JSON") from exc
    if not isinstance(parsed, dict):
        _fail(location, "must contain a JSON object")
    _enforce_embedded_json_depth(parsed, location)
    try:
        rendered = canonical_json(parsed)
    except (RecursionError, ValueError) as exc:
        raise EventBundleError(f"{location} must contain bounded strict JSON") from exc
    if rendered != text:
        _fail(location, "must contain canonical JSON")
    return parsed


def _enforce_embedded_json_depth(value: Any, location: str) -> None:
    """Reject deeply nested JSON without relying on interpreter recursion limits."""

    pending: list[tuple[Any, int]] = [(value, 0)]
    while pending:
        current, parent_depth = pending.pop()
        if not isinstance(current, (dict, list)):
            continue
        depth = parent_depth + 1
        if depth > MAX_EMBEDDED_JSON_DEPTH:
            raise EventBundleError(
                f"{location} must contain strict JSON with at most "
                f"{MAX_EMBEDDED_JSON_DEPTH} nested containers"
            )
        children = current.values() if isinstance(current, dict) else current
        pending.extend((child, depth) for child in children)


def _verify_text_hash(value: str | None, digest: str | None, location: str) -> None:
    if (value is None) != (digest is None):
        _fail(location, "content and digest must either both be null or both be set")
    if value is not None and sha256_text(value) != digest:
        _fail(location, "does not match its digest")


def _validate_text_blob(
    value: Any,
    location: str,
    *,
    expected_format: str,
    maximum_bytes: int,
    json_object: bool,
) -> None:
    blob = _object(value, _TEXT_BLOB_FIELDS, location)
    if blob["format"] != expected_format:
        _fail(f"{location}.format", f"must be {expected_format}")
    content = _text(blob["content"], f"{location}.content", maximum=maximum_bytes)
    if len(content.encode("utf-8")) > maximum_bytes:
        _fail(f"{location}.content", f"exceeds the {maximum_bytes}-byte limit")
    if json_object:
        _load_embedded_json(
            content,
            f"{location}.content",
            maximum_bytes=maximum_bytes,
        )
    digest = _digest(blob["sha256"], f"{location}.sha256")
    _verify_text_hash(content, digest, location)


def _validate_sensor_event(value: Any, location: str) -> None:
    event = _object(value, _SENSOR_FIELDS, location)
    if event["schema_version"] != 1:
        _fail(f"{location}.schema_version", "must be 1")
    _enum(event["source"], {"suricata", "wazuh"}, f"{location}.source")
    _timestamp(event["timestamp"], f"{location}.timestamp")
    _integer(
        event["signature_id"],
        f"{location}.signature_id",
        minimum=1,
        maximum=2**63 - 1,
    )
    _text(event["signature"], f"{location}.signature")
    _integer(event["flow_id"], f"{location}.flow_id", minimum=1, maximum=2**63 - 1, nullable=True)
    _optional_ip(event["src_ip"], f"{location}.src_ip")
    _integer(event["src_port"], f"{location}.src_port", minimum=0, maximum=65535, nullable=True)
    _optional_ip(event["dest_ip"], f"{location}.dest_ip")
    _integer(event["dest_port"], f"{location}.dest_port", minimum=0, maximum=65535, nullable=True)
    proto = _text(event["proto"], f"{location}.proto", maximum=32, nullable=True)
    if proto is not None and _PROTOCOL_RE.fullmatch(proto) is None:
        _fail(f"{location}.proto", "must be a canonical uppercase protocol identifier")
    for name in ("in_iface", "pkt_src", "category", "action"):
        _text(event[name], f"{location}.{name}", nullable=True)
    _integer(
        event["severity"],
        f"{location}.severity",
        minimum=1,
        maximum=255,
        nullable=True,
    )


def _validate_provenance(value: Any, location: str) -> None:
    provenance = _object(value, _PROVENANCE_FIELDS, location)
    _safe_id(provenance["source_instance"], f"{location}.source_instance")
    for name in ("source_event_id", "agent_id", "agent_name"):
        _text(provenance[name], f"{location}.{name}", nullable=True)


def _validate_prefilter(value: Any, location: str) -> None:
    prefilter = _object(value, _PREFILTER_FIELDS, location)
    outcome = _enum(prefilter["outcome"], {"model", "resolved"}, f"{location}.outcome")
    verdict = _enum(prefilter["verdict"], {"false_positive"}, f"{location}.verdict", nullable=True)
    reason = _text(prefilter["reason"], f"{location}.reason", nullable=True)
    _digest(prefilter["policy_revision"], f"{location}.policy_revision")
    if outcome == "model" and (verdict is not None or reason is not None):
        _fail(location, "model outcomes cannot carry a prefilter verdict or reason")
    if outcome == "resolved" and (verdict != "false_positive" or reason is None):
        _fail(location, "resolved outcomes require a false_positive verdict and reason")


def _validate_zeek_layer(value: Any, location: str) -> None:
    layer = _object(value, _ZEEK_LAYER_FIELDS, location)
    status = _enum(layer["lookup_status"], _ZEEK_STATUSES, f"{location}.lookup_status")
    _enum(layer["eligibility_reason"], _ZEEK_ELIGIBILITY, f"{location}.eligibility_reason")
    _safe_id(layer["source_instance"], f"{location}.source_instance", nullable=True)
    _safe_id(layer["match_strategy"], f"{location}.match_strategy", nullable=True)
    records = _integer(
        layer["record_count"],
        f"{location}.record_count",
        minimum=0,
        maximum=32,
    )
    candidates = _integer(
        layer["candidate_count"],
        f"{location}.candidate_count",
        minimum=0,
        maximum=33,
    )
    if type(layer["truncated"]) is not bool:
        _fail(f"{location}.truncated", "must be a boolean")
    context = layer["context_json"]
    digest = _digest(
        layer["context_sha256"],
        f"{location}.context_sha256",
        nullable=True,
    )
    if context is not None:
        _load_embedded_json(
            context,
            f"{location}.context_json",
            maximum_bytes=MAX_EVIDENCE_BYTES,
        )
    _verify_text_hash(context, digest, location)
    if status == "matched":
        if context is None or records < 1 or candidates != 1:
            _fail(location, "matched lookups require context, records, and exactly one candidate")
    elif status == "ambiguous":
        if context is not None or records != 0 or candidates < 2:
            _fail(location, "ambiguous lookups require multiple candidates and no context")
    elif context is not None or records != 0 or candidates != 0 or layer["truncated"]:
        _fail(
            location,
            "non-matched lookups cannot carry context, records, candidates, "
            "or truncation",
        )


def _validate_zeek(value: Any, location: str) -> None:
    zeek = _object(value, _ZEEK_FIELDS, location)
    _validate_zeek_layer(zeek["automatic"], f"{location}.automatic")
    if zeek["operator"] is not None:
        _validate_zeek_layer(zeek["operator"], f"{location}.operator")


def _validate_historical_result(value: Any, location: str, prefilter_outcome: str) -> None:
    result = _object(value, _HISTORICAL_FIELDS, location)
    response = _text(
        result["model_response"],
        f"{location}.model_response",
        maximum=MAX_MODEL_RESPONSE_BYTES,
        nullable=True,
        nonempty=False,
    )
    if response is not None and len(response.encode("utf-8")) > MAX_MODEL_RESPONSE_BYTES:
        _fail(f"{location}.model_response", f"exceeds the {MAX_MODEL_RESPONSE_BYTES}-byte limit")
    response_digest = _digest(
        result["model_response_sha256"],
        f"{location}.model_response_sha256",
        nullable=True,
    )
    _verify_text_hash(response, response_digest, location)
    validation = _enum(
        result["validation_status"],
        {"accepted", "rejected", "not_applicable"},
        f"{location}.validation_status",
    )
    reason = _text(result["validation_reason"], f"{location}.validation_reason", nullable=True)
    _enum(result["final_verdict"], _VERDICTS, f"{location}.final_verdict")
    _number(result["confidence"], f"{location}.confidence", minimum=0, maximum=1)
    _text(result["reasoning"], f"{location}.reasoning")
    _text(result["model_used"], f"{location}.model_used", maximum=256)
    if validation == "accepted" and (response is None or not response.strip()):
        _fail(location, "accepted model results require the original response")
    if validation == "rejected" and reason is None:
        _fail(location, "rejected model results require a validation reason")
    if validation == "not_applicable" and (
        prefilter_outcome != "resolved" or response is not None
    ):
        _fail(location, "not_applicable validation is reserved for prefilter-resolved events")
    if prefilter_outcome == "model" and validation == "not_applicable":
        _fail(location, "model outcomes require accepted or rejected validation")


def _validate_condition_label(value: Any, location: str) -> dict[str, Any]:
    label = _object(value, _CONDITION_LABEL_FIELDS, location)
    contribution = _enum(
        label["zeek_contribution"],
        {
            "material",
            "corroborative",
            "conflicting",
            "uninformative",
            "unavailable",
        },
        f"{location}.zeek_contribution",
    )
    facts = label["allowed_zeek_facts"]
    if not isinstance(facts, list) or len(facts) > MAX_ALLOWED_ZEEK_FACTS:
        _fail(
            f"{location}.allowed_zeek_facts",
            f"must be an array of at most {MAX_ALLOWED_ZEEK_FACTS} strings",
        )
    seen: set[str] = set()
    for index, fact in enumerate(facts):
        fact = _text(fact, f"{location}.allowed_zeek_facts[{index}]")
        if fact in seen:
            _fail(f"{location}.allowed_zeek_facts", "must not contain duplicates")
        seen.add(fact)
    if contribution == "unavailable" and facts:
        _fail(f"{location}.allowed_zeek_facts", "must be empty when Zeek is unavailable")
    if contribution != "unavailable" and not facts:
        _fail(
            f"{location}.allowed_zeek_facts",
            "must contain at least one fact when Zeek evidence is available",
        )
    return label


def _validate_labels(value: Any, location: str) -> dict[str, Any]:
    labels = _object(value, _LABEL_FIELDS, location)
    _enum(labels["human_verdict"], _VERDICTS, f"{location}.human_verdict")
    condition_labels = _object(
        labels["condition_labels"],
        _CONDITION_LABELS_FIELDS,
        f"{location}.condition_labels",
    )
    for condition in sorted(_CONDITION_LABELS_FIELDS):
        _validate_condition_label(
            condition_labels[condition],
            f"{location}.condition_labels.{condition}",
        )
    if condition_labels["no_zeek"]["zeek_contribution"] != "unavailable":
        _fail(
            f"{location}.condition_labels.no_zeek.zeek_contribution",
            "must be unavailable",
        )
    _text(labels["notes"], f"{location}.notes", nullable=True)
    return labels


def _validate_feedback(value: Any, location: str) -> None:
    feedback = _object(value, _FEEDBACK_FIELDS, location)
    _enum(
        feedback["decision"],
        {"agree", "real", "false_positive", "uncertain"},
        f"{location}.decision",
    )
    _text(feedback["note"], f"{location}.note", nullable=True)
    _timestamp(feedback["reviewed_at"], f"{location}.reviewed_at")


def _validate_event(value: Any, index: int) -> str:
    location = f"events[{index}]"
    event = _object(value, _EVENT_FIELDS, location)
    event_id = _safe_id(event["event_id"], f"{location}.event_id")
    _validate_sensor_event(event["sensor_event"], f"{location}.sensor_event")
    _validate_provenance(event["provenance"], f"{location}.provenance")
    _validate_text_blob(
        event["model_projection"],
        f"{location}.model_projection",
        expected_format="text/plain",
        maximum_bytes=MAX_PROJECTION_BYTES,
        json_object=False,
    )
    _validate_text_blob(
        event["asset_context"],
        f"{location}.asset_context",
        expected_format="triagewall.asset-context.v1+json",
        maximum_bytes=MAX_EVIDENCE_BYTES,
        json_object=True,
    )
    _validate_prefilter(event["prefilter"], f"{location}.prefilter")
    _validate_zeek(event["zeek"], f"{location}.zeek")
    _validate_historical_result(
        event["historical_result"],
        f"{location}.historical_result",
        event["prefilter"]["outcome"],
    )
    labels = None
    if event["labels"] is not None:
        labels = _validate_labels(event["labels"], f"{location}.labels")
    if event["operator_feedback"] is not None:
        _validate_feedback(event["operator_feedback"], f"{location}.operator_feedback")

    sensor = event["sensor_event"]
    prefilter_outcome = event["prefilter"]["outcome"]
    automatic = event["zeek"]["automatic"]
    if sensor["source"] != "suricata":
        expected_eligibility = "unsupported_source"
    elif prefilter_outcome == "resolved":
        expected_eligibility = "prefilter_resolved"
    elif sensor["src_ip"] is None or sensor["dest_ip"] is None:
        expected_eligibility = "missing_endpoint"
    elif sensor["proto"] not in {"TCP", "UDP"}:
        expected_eligibility = "unsupported_protocol"
    elif sensor["src_port"] is None or sensor["dest_port"] is None:
        expected_eligibility = "missing_port"
    else:
        expected_eligibility = "eligible"
    if automatic["eligibility_reason"] != expected_eligibility:
        _fail(
            f"{location}.zeek.automatic.eligibility_reason",
            f"must be {expected_eligibility} for the normalized event",
        )
    if expected_eligibility != "eligible" and automatic["lookup_status"] != "disabled":
        _fail(
            f"{location}.zeek.automatic.lookup_status",
            "must be disabled when the event is ineligible",
        )
    if event["zeek"]["operator"] is not None and expected_eligibility != "eligible":
        _fail(f"{location}.zeek.operator", "requires an eligible Suricata flow")
    if (
        event["zeek"]["operator"] is not None
        and event["zeek"]["operator"]["eligibility_reason"] != "eligible"
    ):
        _fail(f"{location}.zeek.operator.eligibility_reason", "must be eligible")
    if labels is not None:
        condition_layers = {
            "connection_only": automatic,
            "connection_plus_application": event["zeek"]["operator"],
        }
        for condition, layer in condition_layers.items():
            contribution = labels["condition_labels"][condition]["zeek_contribution"]
            matched = layer is not None and layer["lookup_status"] == "matched"
            if matched and contribution == "unavailable":
                _fail(
                    f"{location}.labels.condition_labels.{condition}.zeek_contribution",
                    "must describe the matched Zeek evidence",
                )
            if not matched and contribution != "unavailable":
                _fail(
                    f"{location}.labels.condition_labels.{condition}.zeek_contribution",
                    "must be unavailable when the Zeek layer is not matched",
                )
    return event_id


def validate_event_bundle(document: Any) -> dict[str, Any]:
    """Validate one already-decoded v1 bundle and return it unchanged."""

    bundle = _object(document, _TOP_FIELDS, "bundle")
    if bundle["schema"] != EVENT_BUNDLE_SCHEMA:
        _fail("bundle.schema", f"must be {EVENT_BUNDLE_SCHEMA}")
    if bundle["version"] != EVENT_BUNDLE_VERSION:
        _fail("bundle.version", f"must be {EVENT_BUNDLE_VERSION}")
    _safe_id(bundle["bundle_id"], "bundle.bundle_id")
    _timestamp(bundle["created_at"], "bundle.created_at")
    _safe_id(bundle["core_version"], "bundle.core_version")
    _digest(bundle["exporter_revision"], "bundle.exporter_revision")
    count = _integer(bundle["event_count"], "bundle.event_count", minimum=1, maximum=MAX_EVENTS)
    _digest(bundle["content_sha256"], "bundle.content_sha256")

    redaction = _object(bundle["redaction"], _REDACTION_FIELDS, "bundle.redaction")
    _safe_id(redaction["policy"], "bundle.redaction.policy")
    _digest(redaction["policy_revision"], "bundle.redaction.policy_revision")
    transformations = redaction["transformations"]
    if not isinstance(transformations, list) or not transformations:
        _fail("bundle.redaction.transformations", "must be a non-empty array")
    if len(transformations) != len(set(transformations)):
        _fail("bundle.redaction.transformations", "must not contain duplicates")
    for index, item in enumerate(transformations):
        _enum(item, _REDACTION_TRANSFORMATIONS, f"bundle.redaction.transformations[{index}]")
    if type(redaction["operator_feedback_included"]) is not bool:
        _fail("bundle.redaction.operator_feedback_included", "must be a boolean")
    expected_feedback_marker = (
        "operator_feedback_included" if redaction["operator_feedback_included"]
        else "operator_feedback_excluded"
    )
    if expected_feedback_marker not in transformations:
        _fail("bundle.redaction", "feedback inclusion must match its transformation marker")
    feedback_markers = {
        "operator_feedback_included",
        "operator_feedback_excluded",
    }
    if len(feedback_markers.intersection(transformations)) != 1:
        _fail("bundle.redaction", "must contain exactly one feedback transformation")
    address_markers = {
        "private_addresses_preserved",
        "private_addresses_pseudonymized",
    }
    if len(address_markers.intersection(transformations)) != 1:
        _fail("bundle.redaction", "must contain exactly one private-address transformation")
    for required_marker in (
        "raw_sensor_event_excluded",
        "sensor_instance_pseudonymized",
    ):
        if required_marker not in transformations:
            _fail("bundle.redaction", f"must include {required_marker}")

    revisions = _object(bundle["revisions"], _REVISION_FIELDS, "bundle.revisions")
    for name in sorted(_REVISION_FIELDS):
        _digest(revisions[name], f"bundle.revisions.{name}")

    model = _object(bundle["model"], _MODEL_FIELDS, "bundle.model")
    _text(model["name"], "bundle.model.name", maximum=256)
    _digest(model["digest"], "bundle.model.digest", nullable=True)
    options = _load_embedded_json(
        model["inference_options_json"],
        "bundle.model.inference_options_json",
        maximum_bytes=MAX_OPTIONS_BYTES,
    )
    del options
    options_digest = _digest(
        model["inference_options_sha256"],
        "bundle.model.inference_options_sha256",
    )
    _verify_text_hash(model["inference_options_json"], options_digest, "bundle.model")

    events = bundle["events"]
    if not isinstance(events, list) or not 1 <= len(events) <= MAX_EVENTS:
        _fail("bundle.events", f"must contain from 1 to {MAX_EVENTS} events")
    if count != len(events):
        _fail("bundle.event_count", "does not match the events array")
    event_ids: set[str] = set()
    feedback_present = False
    for index, event in enumerate(events):
        event_id = _validate_event(event, index)
        if event_id in event_ids:
            _fail("bundle.events", f"contains duplicate event_id {event_id}")
        event_ids.add(event_id)
        feedback_present = feedback_present or event["operator_feedback"] is not None
        if event["prefilter"]["policy_revision"] != revisions["prefilter_policy"]:
            _fail(
                f"bundle.events[{index}].prefilter.policy_revision",
                "must match bundle.revisions.prefilter_policy",
            )
        historical = event["historical_result"]
        if event["prefilter"]["outcome"] == "model":
            if historical["model_used"] != model["name"]:
                _fail(
                    f"bundle.events[{index}].historical_result.model_used",
                    "must match bundle.model.name",
                )
        elif (
            historical["model_used"] != "prefilter"
            or historical["final_verdict"] != "false_positive"
        ):
            _fail(
                f"bundle.events[{index}].historical_result",
                "prefilter-resolved events require the prefilter model and verdict",
            )
    if feedback_present != redaction["operator_feedback_included"]:
        _fail("bundle.redaction.operator_feedback_included", "does not match event contents")

    rendered_size = len(canonical_json(bundle).encode("utf-8"))
    if rendered_size > MAX_BUNDLE_BYTES:
        _fail("bundle", f"exceeds the {MAX_BUNDLE_BYTES}-byte canonical limit")
    if bundle_content_digest(bundle) != bundle["content_sha256"]:
        _fail("bundle.content_sha256", "does not match canonical bundle content")
    return bundle


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EventBundleError(f"JSON contains duplicate object key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise EventBundleError(f"JSON contains non-finite number: {value}")


def load_event_bundle_bytes(payload: bytes) -> dict[str, Any]:
    """Decode and validate a bounded, uncompressed UTF-8 JSON bundle."""

    if not isinstance(payload, bytes):
        raise TypeError("event bundle payload must be bytes")
    if not payload:
        raise EventBundleError("event bundle payload must not be empty")
    if len(payload) > MAX_BUNDLE_BYTES:
        raise EventBundleError(
            f"event bundle payload exceeds the {MAX_BUNDLE_BYTES}-byte limit"
        )
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EventBundleError("event bundle must be valid UTF-8") from exc
    if text.startswith("\ufeff"):
        raise EventBundleError("event bundle must not contain a UTF-8 BOM")
    try:
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except EventBundleError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise EventBundleError("event bundle must contain strict JSON") from exc
    return validate_event_bundle(document)
