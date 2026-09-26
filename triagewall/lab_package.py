"""Single-file installation package for a complete TriageWall Lab test."""

from __future__ import annotations

import json
from typing import Any

from triagewall.event_bundle import (
    MAX_BUNDLE_BYTES,
    canonical_json,
    load_event_bundle_bytes,
)
from triagewall.lab_contracts import (
    CANDIDATE_SCHEMA,
    EXPERIMENT_SCHEMA,
    LAB_CONTRACT_VERSION,
    MAX_LAB_CONTRACT_BYTES,
    content_digest,
    load_lab_contract_bytes,
)


TEST_PACKAGE_SCHEMA = "triagewall.lab-test-package"
TEST_PACKAGE_VERSION = 1
MAX_TEST_PACKAGE_BYTES = (
    MAX_BUNDLE_BYTES + (3 * MAX_LAB_CONTRACT_BYTES) + (1024 * 1024)
)
_PACKAGE_FIELDS = {
    "schema",
    "version",
    "bundle",
    "baseline_candidate",
    "candidate",
    "experiment",
    "content_sha256",
}


class LabTestPackageError(ValueError):
    """Raised when a one-file Lab test package is invalid."""


def _strict_object(payload: bytes) -> dict[str, Any]:
    if not isinstance(payload, bytes):
        raise TypeError("Lab test package payload must be bytes")
    if not payload:
        raise LabTestPackageError("Lab test package must not be empty")
    if len(payload) > MAX_TEST_PACKAGE_BYTES:
        raise LabTestPackageError("Lab test package exceeds its size limit")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LabTestPackageError("Lab test package must be valid UTF-8") from exc
    if text.startswith("\ufeff"):
        raise LabTestPackageError("Lab test package must not contain a UTF-8 BOM")

    def pairs(items):
        value = {}
        for name, item in items:
            if name in value:
                raise LabTestPackageError(
                    f"Lab test package contains duplicate object key: {name}"
                )
            value[name] = item
        return value

    def reject_constant(value):
        raise LabTestPackageError(
            f"Lab test package contains non-finite number: {value}"
        )

    try:
        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_constant=reject_constant,
        )
    except LabTestPackageError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise LabTestPackageError("Lab test package must contain strict JSON") from exc
    if not isinstance(value, dict):
        raise LabTestPackageError("Lab test package must contain a JSON object")
    return value


def _validated_nested_document(
    value: Any,
    *,
    name: str,
    expected_schema: str | None,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise LabTestPackageError(f"Lab test package {name} must be an object")
    payload = canonical_json(value).encode("utf-8")
    try:
        if expected_schema is None:
            return load_event_bundle_bytes(payload)
        return load_lab_contract_bytes(payload, expected_schema=expected_schema)
    except (TypeError, ValueError) as exc:
        raise LabTestPackageError(
            f"Lab test package {name} is invalid: {exc}"
        ) from exc


def validate_test_package(document: dict[str, Any]) -> dict[str, Any]:
    """Validate every embedded artifact and all experiment references."""

    missing = _PACKAGE_FIELDS - set(document)
    unknown = set(document) - _PACKAGE_FIELDS
    if missing:
        raise LabTestPackageError(
            f"Lab test package is missing fields: {', '.join(sorted(missing))}"
        )
    if unknown:
        raise LabTestPackageError(
            f"Lab test package contains unknown fields: {', '.join(sorted(unknown))}"
        )
    if document["schema"] != TEST_PACKAGE_SCHEMA:
        raise LabTestPackageError(
            f"Lab test package schema must be {TEST_PACKAGE_SCHEMA}"
        )
    if document["version"] != TEST_PACKAGE_VERSION:
        raise LabTestPackageError(
            f"Lab test package version must be {TEST_PACKAGE_VERSION}"
        )
    if content_digest(document) != document["content_sha256"]:
        raise LabTestPackageError(
            "Lab test package content_sha256 does not match canonical content"
        )

    bundle = _validated_nested_document(
        document["bundle"], name="bundle", expected_schema=None
    )
    baseline = _validated_nested_document(
        document["baseline_candidate"],
        name="baseline_candidate",
        expected_schema=CANDIDATE_SCHEMA,
    )
    candidate = _validated_nested_document(
        document["candidate"],
        name="candidate",
        expected_schema=CANDIDATE_SCHEMA,
    )
    experiment = _validated_nested_document(
        document["experiment"],
        name="experiment",
        expected_schema=EXPERIMENT_SCHEMA,
    )
    expected = {
        "bundle": {
            "id": bundle["bundle_id"],
            "sha256": bundle["content_sha256"],
        },
        "baseline_candidate": {
            "id": baseline["candidate_id"],
            "sha256": baseline["content_sha256"],
        },
        "candidate": {
            "id": candidate["candidate_id"],
            "sha256": candidate["content_sha256"],
        },
    }
    for name, reference in expected.items():
        if experiment[name] != reference:
            raise LabTestPackageError(
                f"Lab test package experiment {name} reference does not match its embedded artifact"
            )
    return {
        **document,
        "bundle": bundle,
        "baseline_candidate": baseline,
        "candidate": candidate,
        "experiment": experiment,
    }


def load_test_package_bytes(payload: bytes) -> dict[str, Any]:
    """Decode and validate one bounded, strict, single-file Lab test package."""

    return validate_test_package(_strict_object(payload))


def build_test_package(
    bundle: dict[str, Any],
    baseline_candidate: dict[str, Any],
    candidate: dict[str, Any],
    experiment: dict[str, Any],
) -> dict[str, Any]:
    """Build and self-name a package from already-created Lab artifacts."""

    document = {
        "schema": TEST_PACKAGE_SCHEMA,
        "version": LAB_CONTRACT_VERSION,
        "bundle": bundle,
        "baseline_candidate": baseline_candidate,
        "candidate": candidate,
        "experiment": experiment,
        "content_sha256": "sha256:" + ("0" * 64),
    }
    document["content_sha256"] = content_digest(document)
    return validate_test_package(document)
