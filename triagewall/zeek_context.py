"""Bounded contracts for optional Zeek alert enrichment.

Zeek is evidence for a Suricata decision, not a verdict source.  This module
contains only source-neutral request/result contracts and deterministic
eligibility checks.  Live log access and persistence are intentionally kept
out of this first integration seam.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

try:
    from .sensor_event import MAX_SQLITE_INTEGER, SensorEvent
    from .time_utils import format_utc_timestamp
except ImportError:  # Direct script-style imports used by container entrypoints.
    from sensor_event import MAX_SQLITE_INTEGER, SensorEvent
    from time_utils import format_utc_timestamp


ZEEK_CONTEXT_SCHEMA_VERSION = 1

# Defaults keep the automatic lookup close to the Suricata alert.  Providers
# must also enforce the hard caps; callers cannot widen a request beyond them.
DEFAULT_WINDOW_BEFORE_SECONDS = 5.0
DEFAULT_WINDOW_AFTER_SECONDS = 5.0
DEFAULT_MAX_RECORDS = 8
DEFAULT_MAX_CONTEXT_BYTES = 16 * 1024

MAX_WINDOW_SECONDS = 5 * 60.0
MAX_RECORDS = 32
MAX_CANDIDATES = MAX_RECORDS + 1
MAX_CONTEXT_BYTES = 64 * 1024
MAX_PROVENANCE_TEXT_CHARS = 128

SUPPORTED_PROTOCOLS = frozenset({"TCP", "UDP"})


class ZeekContextContractError(ValueError):
    """A Zeek request or result violates the bounded integration contract."""


class ZeekEligibilityReason(str, Enum):
    """Why an already-normalized sensor event is or is not eligible."""

    ELIGIBLE = "eligible"
    PREFILTER_RESOLVED = "prefilter_resolved"
    UNSUPPORTED_SOURCE = "unsupported_source"
    MISSING_ENDPOINT = "missing_endpoint"
    UNSUPPORTED_PROTOCOL = "unsupported_protocol"
    MISSING_PORT = "missing_port"


class ZeekLookupStatus(str, Enum):
    """Outcome of one bounded provider lookup."""

    DISABLED = "disabled"
    MATCHED = "matched"
    NO_MATCH = "no_match"
    AMBIGUOUS = "ambiguous"
    UNAVAILABLE = "unavailable"
    INVALID_RESPONSE = "invalid_response"


@dataclass(frozen=True)
class ZeekLookupRequest:
    """A validated TCP/UDP tuple and the hard bounds for one lookup."""

    alert_timestamp: str
    src_ip: str
    src_port: int
    dest_ip: str
    dest_port: int
    proto: str
    suricata_flow_id: int | None = None
    window_before_seconds: float = DEFAULT_WINDOW_BEFORE_SECONDS
    window_after_seconds: float = DEFAULT_WINDOW_AFTER_SECONDS
    max_records: int = DEFAULT_MAX_RECORDS
    max_context_bytes: int = DEFAULT_MAX_CONTEXT_BYTES

    def __post_init__(self) -> None:
        try:
            canonical_timestamp = format_utc_timestamp(self.alert_timestamp)
        except (TypeError, ValueError) as exc:
            raise ZeekContextContractError(
                "Zeek lookup alert_timestamp must be a valid ISO-8601 value"
            ) from exc
        object.__setattr__(self, "alert_timestamp", canonical_timestamp)
        for label, value in (("src_ip", self.src_ip), ("dest_ip", self.dest_ip)):
            if not isinstance(value, str):
                raise ZeekContextContractError(
                    f"Zeek lookup {label} must be an IP address string"
                )
            try:
                canonical_ip = str(ipaddress.ip_address(value.strip()))
            except ValueError as exc:
                raise ZeekContextContractError(
                    f"Zeek lookup {label} must be a valid IP address"
                ) from exc
            object.__setattr__(self, label, canonical_ip)
        if not isinstance(self.proto, str):
            raise ZeekContextContractError("Zeek lookup protocol must be TCP or UDP")
        canonical_proto = self.proto.strip().upper()
        if canonical_proto not in SUPPORTED_PROTOCOLS:
            raise ZeekContextContractError("Zeek lookup protocol must be TCP or UDP")
        object.__setattr__(self, "proto", canonical_proto)
        for label, value in (("src_port", self.src_port), ("dest_port", self.dest_port)):
            if type(value) is not int or not 0 <= value <= 65535:
                raise ZeekContextContractError(
                    f"Zeek lookup {label} must be an integer from 0 to 65535"
                )
        if self.suricata_flow_id is not None and (
            type(self.suricata_flow_id) is not int
            or not 1 <= self.suricata_flow_id <= MAX_SQLITE_INTEGER
        ):
            raise ZeekContextContractError(
                "suricata_flow_id must be a positive SQLite integer when present"
            )
        for label, value in (
            ("window_before_seconds", self.window_before_seconds),
            ("window_after_seconds", self.window_after_seconds),
        ):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ZeekContextContractError(f"{label} must be numeric")
            if not 0 <= float(value) <= MAX_WINDOW_SECONDS:
                raise ZeekContextContractError(
                    f"{label} must be between 0 and {MAX_WINDOW_SECONDS:g}"
                )
        if (
            type(self.max_records) is not int
            or not 1 <= self.max_records <= MAX_RECORDS
        ):
            raise ZeekContextContractError(
                f"max_records must be between 1 and {MAX_RECORDS}"
            )
        if (
            type(self.max_context_bytes) is not int
            or not 1 <= self.max_context_bytes <= MAX_CONTEXT_BYTES
        ):
            raise ZeekContextContractError(
                f"max_context_bytes must be between 1 and {MAX_CONTEXT_BYTES}"
            )


@dataclass(frozen=True)
class ZeekEligibility:
    """Eligibility is decided before, and independently from, a Zeek match."""

    reason: ZeekEligibilityReason
    request: ZeekLookupRequest | None = None

    @property
    def eligible(self) -> bool:
        return self.reason is ZeekEligibilityReason.ELIGIBLE

    def __post_init__(self) -> None:
        if not isinstance(self.reason, ZeekEligibilityReason):
            raise ZeekContextContractError("eligibility reason must be recognized")
        if self.eligible != (self.request is not None):
            raise ZeekContextContractError(
                "eligible decisions require a request and skipped decisions forbid one"
            )


@dataclass(frozen=True)
class ZeekLookupResult:
    """Exact bounded provider result suitable for later provenance storage."""

    status: ZeekLookupStatus
    context_json: str | None = None
    source_instance: str | None = None
    match_strategy: str | None = None
    record_count: int = 0
    candidate_count: int = 0
    truncated: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.status, ZeekLookupStatus):
            raise ZeekContextContractError("lookup status must be recognized")
        if type(self.truncated) is not bool:
            raise ZeekContextContractError("truncated must be a boolean")
        if (
            type(self.record_count) is not int
            or not 0 <= self.record_count <= MAX_RECORDS
        ):
            raise ZeekContextContractError(
                f"record_count must be between 0 and {MAX_RECORDS}"
            )
        if (
            type(self.candidate_count) is not int
            or not 0 <= self.candidate_count <= MAX_CANDIDATES
        ):
            raise ZeekContextContractError(
                f"candidate_count must be between 0 and {MAX_CANDIDATES}"
            )
        if self.context_json is not None:
            if not isinstance(self.context_json, str):
                raise ZeekContextContractError("context_json must be a string")
            if len(self.context_json.encode("utf-8")) > MAX_CONTEXT_BYTES:
                raise ZeekContextContractError(
                    f"context_json exceeds the {MAX_CONTEXT_BYTES}-byte hard limit"
                )
            try:
                parsed = json.loads(self.context_json)
            except json.JSONDecodeError as exc:
                raise ZeekContextContractError("context_json must be valid JSON") from exc
            if not isinstance(parsed, dict):
                raise ZeekContextContractError("context_json must contain a JSON object")
        for label, value in (
            ("source_instance", self.source_instance),
            ("match_strategy", self.match_strategy),
        ):
            if value is not None and (
                not isinstance(value, str)
                or not value.strip()
                or len(value) > MAX_PROVENANCE_TEXT_CHARS
            ):
                raise ZeekContextContractError(
                    f"{label} must be non-empty and at most "
                    f"{MAX_PROVENANCE_TEXT_CHARS} characters"
                )

        carries_context = self.context_json is not None
        if self.status is ZeekLookupStatus.MATCHED:
            if (
                not carries_context
                or self.record_count < 1
                or self.candidate_count != 1
            ):
                raise ZeekContextContractError(
                    "matched results require context and exactly one candidate"
                )
        elif self.status is ZeekLookupStatus.AMBIGUOUS:
            if carries_context or self.record_count != 0 or self.candidate_count < 2:
                raise ZeekContextContractError(
                    "ambiguous results require multiple candidates and no context"
                )
        elif (
            carries_context
            or self.record_count != 0
            or self.candidate_count != 0
            or self.truncated
        ):
            raise ZeekContextContractError(
                "non-matched results cannot carry automatic model context"
            )


@dataclass(frozen=True)
class ZeekEnrichmentOutcome:
    """Auditable policy and lookup outcome for one Suricata alert."""

    eligibility: ZeekEligibility
    lookup: ZeekLookupResult

    def __post_init__(self) -> None:
        if not isinstance(self.eligibility, ZeekEligibility):
            raise ZeekContextContractError("enrichment eligibility must be recognized")
        if not isinstance(self.lookup, ZeekLookupResult):
            raise ZeekContextContractError("enrichment lookup must be recognized")
        if (
            not self.eligibility.eligible
            and self.lookup.status is not ZeekLookupStatus.DISABLED
        ):
            raise ZeekContextContractError(
                "ineligible enrichment outcomes must use the disabled lookup status"
            )


class ZeekContextProvider(Protocol):
    """Interface implemented later by the local Zeek context client."""

    def lookup(self, request: ZeekLookupRequest) -> ZeekLookupResult:
        """Return one bounded result without mutating TriageWall state."""


class DisabledZeekContextProvider:
    """Default provider preserving the Core-only v0.4 behavior."""

    def lookup(self, request: ZeekLookupRequest) -> ZeekLookupResult:
        del request
        return ZeekLookupResult(status=ZeekLookupStatus.DISABLED)


def evaluate_zeek_eligibility(event: SensorEvent) -> ZeekEligibility:
    """Build a bounded request for one model-bound, normalized Suricata event."""

    if event.sensor.source != "suricata":
        return ZeekEligibility(ZeekEligibilityReason.UNSUPPORTED_SOURCE)
    if event.src_ip is None or event.dest_ip is None:
        return ZeekEligibility(ZeekEligibilityReason.MISSING_ENDPOINT)
    if event.proto not in SUPPORTED_PROTOCOLS:
        return ZeekEligibility(ZeekEligibilityReason.UNSUPPORTED_PROTOCOL)
    if event.src_port is None or event.dest_port is None:
        return ZeekEligibility(ZeekEligibilityReason.MISSING_PORT)

    return ZeekEligibility(
        ZeekEligibilityReason.ELIGIBLE,
        ZeekLookupRequest(
            alert_timestamp=event.timestamp,
            src_ip=event.src_ip,
            src_port=event.src_port,
            dest_ip=event.dest_ip,
            dest_port=event.dest_port,
            proto=event.proto,
            suricata_flow_id=event.flow_id,
        ),
    )
