"""Fail-closed prompt isolation for attacker-controlled Zeek string values."""

from __future__ import annotations

import base64
import json
from typing import Any


class ZeekIsolationError(ValueError):
    """Raised when a Zeek context cannot be projected without ambiguity."""


_ALLOWED_KEYS = {
    "actions", "answers", "application_evidence_truncated", "cert_chain_fuids",
    "certificate.curve", "certificate.issuer", "certificate.key_alg",
    "certificate.key_length", "certificate.key_type",
    "certificate.not_valid_after", "certificate.not_valid_before",
    "certificate.serial", "certificate.sig_alg", "certificate.subject",
    "certificate.version", "certificates", "cipher", "client_cert_chain_fuids",
    "conn_state", "conn_uids", "connections", "correlation", "curve",
    "direction", "dns", "dst", "duration", "end_ts", "established", "files",
    "filename", "fuid", "host", "http", "id", "id.orig_h", "id.orig_p",
    "id.resp_h", "id.resp_p", "is_orig", "issuer", "md5", "method",
    "mime_type", "missed_bytes", "missing_bytes", "msg", "next_protocol",
    "note", "notices", "orig_bytes", "orig_pkts", "overflow_bytes", "p",
    "proto", "qtype_name", "query", "rcode_name", "referrer", "rejected",
    "resp_bytes", "resp_mime_types", "resp_pkts", "request_body_len", "resumed",
    "response_body_len", "san.dns", "san.email", "san.ip", "san.uri",
    "schema_version", "seen_bytes", "server_name", "service", "sha1", "sha256",
    "source", "src", "ssl", "status_code", "status_msg", "sub", "subject",
    "timedout", "tls", "total_bytes", "ts", "uid", "uri", "user_agent",
    "version", "x509",
}


def _strict_object(context_json: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ZeekIsolationError("Zeek context contained a duplicate key")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ZeekIsolationError(f"Zeek context contained non-finite JSON: {value}")

    try:
        value = json.loads(
            context_json,
            object_pairs_hook=pairs,
            parse_constant=reject_constant,
        )
    except (json.JSONDecodeError, RecursionError, TypeError) as exc:
        raise ZeekIsolationError("Zeek context was not strict JSON") from exc
    if not isinstance(value, dict):
        raise ZeekIsolationError("Zeek context must contain an object")
    return value


def _wrap(path: str, value: str) -> str:
    encoded = base64.b64encode(value.encode("utf-8", "surrogatepass")).decode("ascii")
    return (
        f"=== UNTRUSTED ZEEK FIELD [{path}] (base64) ===\n"
        f"{encoded}\n"
        "=== END UNTRUSTED ZEEK FIELD ==="
    )


def _isolate(value: Any, path: str, depth: int) -> Any:
    if depth > 32:
        raise ZeekIsolationError("Zeek context nesting exceeded its limit")
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if not isinstance(key, str) or key not in _ALLOWED_KEYS:
                raise ZeekIsolationError("Zeek context contained an unknown field name")
            item_path = f"{path}.{key}" if path else key
            result[key] = _isolate(item, item_path, depth + 1)
        return result
    if isinstance(value, list):
        return [
            _isolate(item, f"{path}.{index}" if path else str(index), depth + 1)
            for index, item in enumerate(value)
        ]
    if isinstance(value, str):
        return _wrap(path, value)
    if value is None or type(value) in {bool, int, float, str}:
        return value
    raise ZeekIsolationError("Zeek context contained an unsupported value")


def format_zeek_context_for_llm(context_json: str) -> str:
    """Render recognized Zeek JSON while base64-isolating every string value."""

    if not isinstance(context_json, str):
        raise ZeekIsolationError("Zeek context must be text")
    isolated = _isolate(_strict_object(context_json), "", 0)
    return json.dumps(isolated, indent=2, ensure_ascii=True)


def validate_zeek_context_json(context_json: str) -> None:
    """Reject context fields outside the production and legacy Lab projection."""

    if not isinstance(context_json, str):
        raise ZeekIsolationError("Zeek context must be text")
    _isolate(_strict_object(context_json), "", 0)
