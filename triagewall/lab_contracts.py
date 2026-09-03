"""Strict Phase 0 contracts for trusted TriageWall Lab experiment state."""

from __future__ import annotations

import json
import math
import re
from typing import Any, Callable

from .event_bundle import canonical_json, sha256_text
from .time_utils import format_utc_timestamp


CANDIDATE_SCHEMA = "triagewall.lab-candidate"
EXPERIMENT_SCHEMA = "triagewall.lab-experiment"
RESULT_SCHEMA = "triagewall.lab-result"
PROMOTION_REPORT_SCHEMA = "triagewall.lab-promotion-report"
LAB_CONTRACT_VERSION = 1

MAX_LAB_CONTRACT_BYTES = 8 * 1024 * 1024
MAX_PROMPT_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
MAX_FREE_TEXT_CHARS = 2_000
MAX_EVENT_SELECTION = 1_000
MAX_REPETITIONS = 20
MAX_FACTS = 32
MAX_RESULT_DIGESTS = MAX_EVENT_SELECTION * 3 * MAX_REPETITIONS
CANARY_PLACEHOLDER = "<CANARY_TOKEN>"

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}$")
_VERDICTS = {"real", "false_positive", "uncertain"}
_CONDITIONS = {"no_zeek", "connection_only", "connection_plus_application"}
_CHANGED_COMPONENTS = {
    "model",
    "prompt",
    "evidence_projection",
    "response_contract",
    "prefilter_policy",
}
_GATE_IDS = {
    "canary_disclosure",
    "injected_instruction_followed",
    "unsupported_zeek_claims",
    "zeek_claim_when_absent",
    "invalid_or_incomplete",
    "explicit_matched_assessment",
    "missed_real",
    "true_positive_recall",
    "kappa_pipeline",
    "kappa_model_only",
    "uncertain_outcomes",
    "material_subset_improvement",
    "repetition_stability",
}
REQUIRED_GATE_IDS = frozenset(_GATE_IDS)

_CANDIDATE_FIELDS = {
    "schema",
    "version",
    "candidate_id",
    "created_at",
    "author",
    "parent_candidate_id",
    "rationale",
    "expected_invariant",
    "model",
    "prompt_templates",
    "revisions",
    "inference",
    "content_sha256",
}
_MODEL_FIELDS = {"name", "digest"}
_PROMPT_TEMPLATES_FIELDS = {"suricata", "wazuh"}
_PROMPT_FIELDS = {
    "system_prompt",
    "classification_prefix",
    "matched_zeek_instruction",
    "content_sha256",
}
_CANDIDATE_REVISIONS_FIELDS = {
    "source_projection",
    "response_contract",
    "prefilter_policy",
    "asset_context_projection",
    "zeek_evidence_projection",
}
_INFERENCE_FIELDS = {"temperature", "num_predict", "num_ctx", "seed"}

_EXPERIMENT_FIELDS = {
    "schema",
    "version",
    "experiment_id",
    "created_at",
    "question",
    "baseline_candidate",
    "candidate",
    "bundle",
    "changed_components",
    "evidence_conditions",
    "event_ids",
    "repetitions",
    "execution_order_seed",
    "labels_required",
    "content_sha256",
}
_REFERENCE_FIELDS = {"id", "sha256"}

_RESULT_FIELDS = {
    "schema",
    "version",
    "result_id",
    "experiment",
    "bundle",
    "event_id",
    "evidence_condition",
    "repetition",
    "execution_order",
    "started_at",
    "completed_at",
    "runner_sha256",
    "baseline",
    "candidate",
    "content_sha256",
}
_OUTCOME_FIELDS = {
    "candidate_id",
    "candidate_sha256",
    "model_name",
    "model_digest",
    "duration_ms",
    "model_response",
    "model_response_sha256",
    "validation_status",
    "failure_category",
    "verdict",
    "confidence",
    "reasoning",
    "score",
}
_SCORE_FIELDS = {
    "explicit_zeek_assessment",
    "supported_facts",
    "unsupported_claims",
    "claims_zeek_when_absent",
    "injected_instruction_followed",
    "canary_disclosed",
    "human_review_required",
}

_REPORT_FIELDS = {
    "schema",
    "version",
    "report_id",
    "created_at",
    "experiment",
    "bundle",
    "baseline_candidate",
    "candidate",
    "runner_sha256",
    "expected_result_count",
    "completed_result_count",
    "result_set_sha256",
    "metrics",
    "gates",
    "promotion_status",
    "does_not_authorize_production",
    "content_sha256",
}
_METRICS_FIELDS = {
    "decision_quality",
    "evidence_use",
    "safety_validity",
    "operational_cost",
}
_DECISION_QUALITY_FIELDS = {"labeled_events", "baseline", "candidate"}
_DECISION_METRIC_FIELDS = {
    "accuracy",
    "cohens_kappa_pipeline",
    "cohens_kappa_model_only",
    "true_positive_recall_pipeline",
    "true_positive_recall_model_only",
    "false_positive_rate",
    "uncertain_rate",
}
_EVIDENCE_METRIC_FIELDS = {
    "matched_results",
    "baseline_explicit_assessment_rate",
    "candidate_explicit_assessment_rate",
    "baseline_supported_fact_rate",
    "candidate_supported_fact_rate",
    "baseline_unsupported_claims",
    "candidate_unsupported_claims",
    "baseline_absent_zeek_claims",
    "candidate_absent_zeek_claims",
    "material_subset_improvement",
}
_SAFETY_METRIC_FIELDS = {
    "baseline_invalid_results",
    "candidate_invalid_results",
    "baseline_canary_disclosures",
    "candidate_canary_disclosures",
    "baseline_injection_successes",
    "candidate_injection_successes",
    "incomplete_results",
}
_OPERATIONAL_METRIC_FIELDS = {
    "baseline_latency_p50_ms",
    "baseline_latency_p95_ms",
    "candidate_latency_p50_ms",
    "candidate_latency_p95_ms",
    "baseline_stability_rate",
    "candidate_stability_rate",
}
_GATE_FIELDS = {"gate_id", "status", "observed", "requirement"}


class LabContractError(ValueError):
    """Raised when trusted Lab state violates its immutable contract."""


def _fail(location: str, message: str) -> None:
    raise LabContractError(f"{location} {message}")


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
    allow_empty: bool = False,
) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str):
        _fail(location, "must be a string")
    if not allow_empty and not value.strip():
        _fail(location, "must not be empty")
    if len(value) > maximum:
        _fail(location, f"must be at most {maximum} characters")
    return value


def _bounded_text_bytes(
    value: Any,
    location: str,
    maximum: int,
    *,
    nullable: bool = False,
    allow_empty: bool = False,
) -> str | None:
    text = _text(
        value,
        location,
        maximum=maximum,
        nullable=nullable,
        allow_empty=allow_empty,
    )
    if text is not None and len(text.encode("utf-8")) > maximum:
        _fail(location, f"exceeds the {maximum}-byte limit")
    return text


def _identifier(value: Any, location: str, *, nullable: bool = False) -> str | None:
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


def _timestamp(value: Any, location: str) -> str:
    text = _text(value, location, maximum=64)
    try:
        canonical = format_utc_timestamp(text)
    except (TypeError, ValueError) as exc:
        raise LabContractError(f"{location} must be an ISO-8601 timestamp") from exc
    if canonical != text:
        _fail(location, "must use canonical UTC form")
    return text


def _integer(
    value: Any,
    location: str,
    minimum: int,
    maximum: int,
    *,
    nullable: bool = False,
) -> int | None:
    if nullable and value is None:
        return None
    if type(value) is not int or not minimum <= value <= maximum:
        _fail(location, f"must be an integer from {minimum} to {maximum}")
    return value


def _number(
    value: Any,
    location: str,
    minimum: float,
    maximum: float,
    *,
    nullable: bool = False,
) -> float | None:
    if nullable and value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _fail(location, "must be numeric")
    number = float(value)
    if not math.isfinite(number) or not minimum <= number <= maximum:
        _fail(location, f"must be finite and from {minimum:g} to {maximum:g}")
    return number


def _enum(
    value: Any,
    choices: set[str],
    location: str,
    *,
    nullable: bool = False,
) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or value not in choices:
        _fail(location, f"must be one of: {', '.join(sorted(choices))}")
    return value


def _boolean(value: Any, location: str) -> bool:
    if type(value) is not bool:
        _fail(location, "must be a boolean")
    return value


def _unique_enum_array(
    value: Any,
    choices: set[str],
    location: str,
) -> list[str]:
    if not isinstance(value, list) or not value:
        _fail(location, "must be a non-empty array")
    if len(value) != len(set(value)):
        _fail(location, "must not contain duplicates")
    for index, item in enumerate(value):
        _enum(item, choices, f"{location}[{index}]")
    return value


def _validate_reference(value: Any, location: str) -> dict[str, Any]:
    reference = _object(value, _REFERENCE_FIELDS, location)
    _identifier(reference["id"], f"{location}.id")
    _digest(reference["sha256"], f"{location}.sha256")
    return reference


def content_digest(document: dict[str, Any]) -> str:
    """Digest canonical content while omitting only its self-naming field."""

    unsigned = dict(document)
    unsigned.pop("content_sha256", None)
    return sha256_text(canonical_json(unsigned))


def result_set_digest(result_digests: list[str]) -> str:
    """Digest the ordered immutable result identity list used by a report."""

    return sha256_text(canonical_json(result_digests))


def _verify_content_digest(document: dict[str, Any], location: str) -> None:
    _digest(document["content_sha256"], f"{location}.content_sha256")
    if content_digest(document) != document["content_sha256"]:
        _fail(f"{location}.content_sha256", "does not match canonical content")


def _validate_document_size(document: dict[str, Any], location: str) -> None:
    try:
        size = len(canonical_json(document).encode("utf-8"))
    except (RecursionError, ValueError) as exc:
        raise LabContractError(f"{location} must contain bounded strict JSON") from exc
    if size > MAX_LAB_CONTRACT_BYTES:
        _fail(location, f"exceeds the {MAX_LAB_CONTRACT_BYTES}-byte limit")


def _validate_model(value: Any, location: str) -> None:
    model = _object(value, _MODEL_FIELDS, location)
    _text(model["name"], f"{location}.name", maximum=256)
    _digest(model["digest"], f"{location}.digest")


def _validate_prompt(value: Any, location: str, source: str) -> None:
    prompt = _object(value, _PROMPT_FIELDS, location)
    system_prompt = _bounded_text_bytes(
        prompt["system_prompt"],
        f"{location}.system_prompt",
        MAX_PROMPT_BYTES,
    )
    _bounded_text_bytes(
        prompt["classification_prefix"],
        f"{location}.classification_prefix",
        MAX_PROMPT_BYTES,
    )
    zeek_instruction = _bounded_text_bytes(
        prompt["matched_zeek_instruction"],
        f"{location}.matched_zeek_instruction",
        MAX_PROMPT_BYTES,
        nullable=True,
    )
    if system_prompt.count(CANARY_PLACEHOLDER) != 1:
        _fail(
            f"{location}.system_prompt",
            f"must contain {CANARY_PLACEHOLDER} exactly once",
        )
    if source == "wazuh" and zeek_instruction is not None:
        _fail(f"{location}.matched_zeek_instruction", "must be null for Wazuh")
    _verify_content_digest(prompt, location)


def validate_candidate(document: Any) -> dict[str, Any]:
    """Validate one trusted immutable candidate definition."""

    candidate = _object(document, _CANDIDATE_FIELDS, "candidate")
    if candidate["schema"] != CANDIDATE_SCHEMA:
        _fail("candidate.schema", f"must be {CANDIDATE_SCHEMA}")
    if candidate["version"] != LAB_CONTRACT_VERSION:
        _fail("candidate.version", f"must be {LAB_CONTRACT_VERSION}")
    candidate_id = _identifier(candidate["candidate_id"], "candidate.candidate_id")
    parent_id = _identifier(
        candidate["parent_candidate_id"],
        "candidate.parent_candidate_id",
        nullable=True,
    )
    if parent_id == candidate_id:
        _fail("candidate.parent_candidate_id", "must differ from candidate_id")
    _timestamp(candidate["created_at"], "candidate.created_at")
    _text(candidate["author"], "candidate.author", maximum=256)
    _text(candidate["rationale"], "candidate.rationale")
    _text(candidate["expected_invariant"], "candidate.expected_invariant")
    _validate_model(candidate["model"], "candidate.model")

    prompts = _object(
        candidate["prompt_templates"],
        _PROMPT_TEMPLATES_FIELDS,
        "candidate.prompt_templates",
    )
    if prompts["suricata"] is None and prompts["wazuh"] is None:
        _fail("candidate.prompt_templates", "must configure at least one source")
    for source in ("suricata", "wazuh"):
        if prompts[source] is not None:
            _validate_prompt(
                prompts[source],
                f"candidate.prompt_templates.{source}",
                source,
            )

    revisions = _object(
        candidate["revisions"],
        _CANDIDATE_REVISIONS_FIELDS,
        "candidate.revisions",
    )
    for name in sorted(_CANDIDATE_REVISIONS_FIELDS):
        _digest(revisions[name], f"candidate.revisions.{name}")

    inference = _object(candidate["inference"], _INFERENCE_FIELDS, "candidate.inference")
    _number(inference["temperature"], "candidate.inference.temperature", 0, 2)
    _integer(inference["num_predict"], "candidate.inference.num_predict", 1, 16_384)
    _integer(inference["num_ctx"], "candidate.inference.num_ctx", 256, 1_048_576)
    _integer(
        inference["seed"],
        "candidate.inference.seed",
        0,
        2**63 - 1,
        nullable=True,
    )
    _verify_content_digest(candidate, "candidate")
    _validate_document_size(candidate, "candidate")
    return candidate


def validate_experiment(document: Any) -> dict[str, Any]:
    """Validate one operator-created paired experiment definition."""

    experiment = _object(document, _EXPERIMENT_FIELDS, "experiment")
    if experiment["schema"] != EXPERIMENT_SCHEMA:
        _fail("experiment.schema", f"must be {EXPERIMENT_SCHEMA}")
    if experiment["version"] != LAB_CONTRACT_VERSION:
        _fail("experiment.version", f"must be {LAB_CONTRACT_VERSION}")
    _identifier(experiment["experiment_id"], "experiment.experiment_id")
    _timestamp(experiment["created_at"], "experiment.created_at")
    _text(experiment["question"], "experiment.question")
    baseline = _validate_reference(
        experiment["baseline_candidate"],
        "experiment.baseline_candidate",
    )
    candidate = _validate_reference(
        experiment["candidate"],
        "experiment.candidate",
    )
    _validate_reference(experiment["bundle"], "experiment.bundle")
    if baseline == candidate or baseline["id"] == candidate["id"]:
        _fail("experiment.candidate", "must differ from the baseline candidate")
    _unique_enum_array(
        experiment["changed_components"],
        _CHANGED_COMPONENTS,
        "experiment.changed_components",
    )
    _unique_enum_array(
        experiment["evidence_conditions"],
        _CONDITIONS,
        "experiment.evidence_conditions",
    )
    event_ids = experiment["event_ids"]
    if event_ids is not None:
        if (
            not isinstance(event_ids, list)
            or not 1 <= len(event_ids) <= MAX_EVENT_SELECTION
        ):
            _fail(
                "experiment.event_ids",
                f"must be null or contain 1 to {MAX_EVENT_SELECTION} event IDs",
            )
        seen: set[str] = set()
        for index, event_id in enumerate(event_ids):
            event_id = _identifier(event_id, f"experiment.event_ids[{index}]")
            if event_id in seen:
                _fail("experiment.event_ids", "must not contain duplicates")
            seen.add(event_id)
    _integer(
        experiment["repetitions"],
        "experiment.repetitions",
        1,
        MAX_REPETITIONS,
    )
    _integer(
        experiment["execution_order_seed"],
        "experiment.execution_order_seed",
        0,
        2**63 - 1,
    )
    _boolean(experiment["labels_required"], "experiment.labels_required")
    _verify_content_digest(experiment, "experiment")
    _validate_document_size(experiment, "experiment")
    return experiment


def _validate_fact_array(value: Any, location: str) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_FACTS:
        _fail(location, f"must be an array of at most {MAX_FACTS} strings")
    seen: set[str] = set()
    for index, item in enumerate(value):
        item = _text(item, f"{location}[{index}]")
        if item in seen:
            _fail(location, "must not contain duplicates")
        seen.add(item)
    return value


def _validate_score(value: Any, location: str, condition: str) -> None:
    score = _object(value, _SCORE_FIELDS, location)
    _boolean(score["explicit_zeek_assessment"], f"{location}.explicit_zeek_assessment")
    facts = _validate_fact_array(score["supported_facts"], f"{location}.supported_facts")
    _validate_fact_array(score["unsupported_claims"], f"{location}.unsupported_claims")
    for name in (
        "claims_zeek_when_absent",
        "injected_instruction_followed",
        "canary_disclosed",
        "human_review_required",
    ):
        _boolean(score[name], f"{location}.{name}")
    if condition == "no_zeek" and facts:
        _fail(f"{location}.supported_facts", "must be empty in the no-Zeek condition")
    if condition != "no_zeek" and score["claims_zeek_when_absent"]:
        _fail(
            f"{location}.claims_zeek_when_absent",
            "can be true only in the no-Zeek condition",
        )


def _validate_outcome(value: Any, location: str, condition: str) -> dict[str, Any]:
    outcome = _object(value, _OUTCOME_FIELDS, location)
    _identifier(outcome["candidate_id"], f"{location}.candidate_id")
    _digest(outcome["candidate_sha256"], f"{location}.candidate_sha256")
    _text(outcome["model_name"], f"{location}.model_name", maximum=256)
    _digest(outcome["model_digest"], f"{location}.model_digest")
    _integer(outcome["duration_ms"], f"{location}.duration_ms", 0, 3_600_000)
    response = _bounded_text_bytes(
        outcome["model_response"],
        f"{location}.model_response",
        MAX_RESPONSE_BYTES,
        nullable=True,
        allow_empty=True,
    )
    response_digest = _digest(
        outcome["model_response_sha256"],
        f"{location}.model_response_sha256",
        nullable=True,
    )
    if (response is None) != (response_digest is None):
        _fail(location, "model response and digest must both be null or both be set")
    if response is not None and sha256_text(response) != response_digest:
        _fail(f"{location}.model_response_sha256", "does not match the response")
    validation = _enum(
        outcome["validation_status"],
        {"accepted", "rejected", "timeout", "error"},
        f"{location}.validation_status",
    )
    failure = _enum(
        outcome["failure_category"],
        {
            "transport",
            "timeout",
            "invalid_envelope",
            "invalid_json",
            "invalid_schema",
            "canary_disclosure",
            "runner_error",
        },
        f"{location}.failure_category",
        nullable=True,
    )
    if validation == "accepted" and (
        response is None or not response.strip() or failure is not None
    ):
        _fail(location, "accepted outcomes require a response and no failure")
    if validation != "accepted" and failure is None:
        _fail(location, "non-accepted outcomes require a failure category")
    _enum(outcome["verdict"], _VERDICTS, f"{location}.verdict")
    _number(outcome["confidence"], f"{location}.confidence", 0, 1)
    _text(outcome["reasoning"], f"{location}.reasoning")
    _validate_score(outcome["score"], f"{location}.score", condition)
    if outcome["score"]["canary_disclosed"] != (failure == "canary_disclosure"):
        _fail(location, "canary score must match the canary failure category")
    carries_redacted_canary = (
        response is not None and CANARY_PLACEHOLDER in response
    )
    if carries_redacted_canary != outcome["score"]["canary_disclosed"]:
        _fail(
            location,
            "a disclosed runtime canary must be replaced by its placeholder",
        )
    return outcome


def validate_result(document: Any) -> dict[str, Any]:
    """Validate one immutable paired-trial result."""

    result = _object(document, _RESULT_FIELDS, "result")
    if result["schema"] != RESULT_SCHEMA:
        _fail("result.schema", f"must be {RESULT_SCHEMA}")
    if result["version"] != LAB_CONTRACT_VERSION:
        _fail("result.version", f"must be {LAB_CONTRACT_VERSION}")
    _identifier(result["result_id"], "result.result_id")
    _validate_reference(result["experiment"], "result.experiment")
    _validate_reference(result["bundle"], "result.bundle")
    _identifier(result["event_id"], "result.event_id")
    condition = _enum(
        result["evidence_condition"],
        _CONDITIONS,
        "result.evidence_condition",
    )
    _integer(result["repetition"], "result.repetition", 1, MAX_REPETITIONS)
    order = _enum(
        result["execution_order"],
        {"baseline_first", "candidate_first"},
        "result.execution_order",
    )
    del order
    started = _timestamp(result["started_at"], "result.started_at")
    completed = _timestamp(result["completed_at"], "result.completed_at")
    if completed < started:
        _fail("result.completed_at", "must not precede started_at")
    _digest(result["runner_sha256"], "result.runner_sha256")
    baseline = _validate_outcome(result["baseline"], "result.baseline", condition)
    candidate = _validate_outcome(result["candidate"], "result.candidate", condition)
    if baseline["candidate_id"] == candidate["candidate_id"]:
        _fail("result.candidate.candidate_id", "must differ from the baseline")
    _verify_content_digest(result, "result")
    _validate_document_size(result, "result")
    return result


def _validate_decision_metrics(value: Any, location: str) -> None:
    metrics = _object(value, _DECISION_METRIC_FIELDS, location)
    for name in sorted(_DECISION_METRIC_FIELDS):
        minimum = -1 if "kappa" in name else 0
        _number(metrics[name], f"{location}.{name}", minimum, 1, nullable=True)


def _validate_metrics(value: Any, location: str) -> None:
    metrics = _object(value, _METRICS_FIELDS, location)
    decision = _object(
        metrics["decision_quality"],
        _DECISION_QUALITY_FIELDS,
        f"{location}.decision_quality",
    )
    _integer(
        decision["labeled_events"],
        f"{location}.decision_quality.labeled_events",
        0,
        MAX_EVENT_SELECTION,
    )
    _validate_decision_metrics(
        decision["baseline"],
        f"{location}.decision_quality.baseline",
    )
    _validate_decision_metrics(
        decision["candidate"],
        f"{location}.decision_quality.candidate",
    )

    evidence = _object(
        metrics["evidence_use"],
        _EVIDENCE_METRIC_FIELDS,
        f"{location}.evidence_use",
    )
    _integer(
        evidence["matched_results"],
        f"{location}.evidence_use.matched_results",
        0,
        MAX_RESULT_DIGESTS,
    )
    for name in (
        "baseline_explicit_assessment_rate",
        "candidate_explicit_assessment_rate",
        "baseline_supported_fact_rate",
        "candidate_supported_fact_rate",
    ):
        _number(evidence[name], f"{location}.evidence_use.{name}", 0, 1, nullable=True)
    for name in (
        "baseline_unsupported_claims",
        "candidate_unsupported_claims",
        "baseline_absent_zeek_claims",
        "candidate_absent_zeek_claims",
    ):
        _integer(
            evidence[name],
            f"{location}.evidence_use.{name}",
            0,
            MAX_RESULT_DIGESTS * MAX_FACTS,
        )
    _number(
        evidence["material_subset_improvement"],
        f"{location}.evidence_use.material_subset_improvement",
        -1,
        1,
        nullable=True,
    )

    safety = _object(
        metrics["safety_validity"],
        _SAFETY_METRIC_FIELDS,
        f"{location}.safety_validity",
    )
    for name in sorted(_SAFETY_METRIC_FIELDS):
        _integer(
            safety[name],
            f"{location}.safety_validity.{name}",
            0,
            MAX_RESULT_DIGESTS,
        )

    operational = _object(
        metrics["operational_cost"],
        _OPERATIONAL_METRIC_FIELDS,
        f"{location}.operational_cost",
    )
    for name in (
        "baseline_latency_p50_ms",
        "baseline_latency_p95_ms",
        "candidate_latency_p50_ms",
        "candidate_latency_p95_ms",
    ):
        _number(
            operational[name],
            f"{location}.operational_cost.{name}",
            0,
            3_600_000,
            nullable=True,
        )
    for name in ("baseline_stability_rate", "candidate_stability_rate"):
        _number(
            operational[name],
            f"{location}.operational_cost.{name}",
            0,
            1,
            nullable=True,
        )


def validate_promotion_report(document: Any) -> dict[str, Any]:
    """Validate a sanitized report that carries no production authority."""

    report = _object(document, _REPORT_FIELDS, "report")
    if report["schema"] != PROMOTION_REPORT_SCHEMA:
        _fail("report.schema", f"must be {PROMOTION_REPORT_SCHEMA}")
    if report["version"] != LAB_CONTRACT_VERSION:
        _fail("report.version", f"must be {LAB_CONTRACT_VERSION}")
    _identifier(report["report_id"], "report.report_id")
    _timestamp(report["created_at"], "report.created_at")
    _validate_reference(report["experiment"], "report.experiment")
    _validate_reference(report["bundle"], "report.bundle")
    baseline = _validate_reference(
        report["baseline_candidate"],
        "report.baseline_candidate",
    )
    candidate = _validate_reference(report["candidate"], "report.candidate")
    if baseline["id"] == candidate["id"]:
        _fail("report.candidate", "must differ from baseline_candidate")
    _digest(report["runner_sha256"], "report.runner_sha256")
    expected = _integer(
        report["expected_result_count"],
        "report.expected_result_count",
        1,
        MAX_RESULT_DIGESTS,
    )
    completed = _integer(
        report["completed_result_count"],
        "report.completed_result_count",
        0,
        MAX_RESULT_DIGESTS,
    )
    _digest(report["result_set_sha256"], "report.result_set_sha256")
    _validate_metrics(report["metrics"], "report.metrics")

    gates = report["gates"]
    if not isinstance(gates, list) or len(gates) != len(_GATE_IDS):
        _fail("report.gates", f"must contain exactly {len(_GATE_IDS)} gates")
    gate_statuses: dict[str, str] = {}
    for index, value in enumerate(gates):
        location = f"report.gates[{index}]"
        gate = _object(value, _GATE_FIELDS, location)
        gate_id = _enum(gate["gate_id"], _GATE_IDS, f"{location}.gate_id")
        if gate_id in gate_statuses:
            _fail("report.gates", f"contains duplicate gate {gate_id}")
        gate_statuses[gate_id] = _enum(
            gate["status"],
            {"pass", "fail", "not_evaluated"},
            f"{location}.status",
        )
        _text(gate["observed"], f"{location}.observed")
        _text(gate["requirement"], f"{location}.requirement")
    if set(gate_statuses) != _GATE_IDS:
        _fail("report.gates", "must contain every required gate exactly once")

    status = _enum(
        report["promotion_status"],
        {"eligible", "blocked", "incomplete"},
        "report.promotion_status",
    )
    if report["does_not_authorize_production"] is not True:
        _fail("report.does_not_authorize_production", "must be true")
    complete = completed == expected
    any_failed = "fail" in gate_statuses.values()
    any_not_evaluated = "not_evaluated" in gate_statuses.values()
    expected_status = (
        "incomplete"
        if not complete or any_not_evaluated
        else "blocked" if any_failed else "eligible"
    )
    if status != expected_status:
        _fail("report.promotion_status", f"must be {expected_status}")
    _verify_content_digest(report, "report")
    _validate_document_size(report, "report")
    return report


_VALIDATORS: dict[str, Callable[[Any], dict[str, Any]]] = {
    CANDIDATE_SCHEMA: validate_candidate,
    EXPERIMENT_SCHEMA: validate_experiment,
    RESULT_SCHEMA: validate_result,
    PROMOTION_REPORT_SCHEMA: validate_promotion_report,
}


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LabContractError(f"JSON contains duplicate object key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise LabContractError(f"JSON contains non-finite number: {value}")


def load_lab_contract_bytes(
    payload: bytes,
    *,
    expected_schema: str | None = None,
) -> dict[str, Any]:
    """Decode and dispatch one bounded strict UTF-8 Lab contract document."""

    if not isinstance(payload, bytes):
        raise TypeError("Lab contract payload must be bytes")
    if not payload:
        raise LabContractError("Lab contract payload must not be empty")
    if len(payload) > MAX_LAB_CONTRACT_BYTES:
        raise LabContractError(
            f"Lab contract exceeds the {MAX_LAB_CONTRACT_BYTES}-byte limit"
        )
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LabContractError("Lab contract must be valid UTF-8") from exc
    if text.startswith("\ufeff"):
        raise LabContractError("Lab contract must not contain a UTF-8 BOM")
    try:
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except LabContractError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise LabContractError("Lab contract must contain strict JSON") from exc
    if not isinstance(document, dict):
        raise LabContractError("Lab contract must contain a JSON object")
    schema = document.get("schema")
    if expected_schema is not None and schema != expected_schema:
        raise LabContractError(f"Lab contract schema must be {expected_schema}")
    validator = _VALIDATORS.get(schema)
    if validator is None:
        raise LabContractError("Lab contract schema is unknown")
    return validator(document)
