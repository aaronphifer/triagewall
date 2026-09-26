"""Standalone, bounded SQLite index for Zeek connection and application context.

The index is deliberately separate from TriageWall's verdict database.  It
accepts complete JSON-Lines records, stores a strict allowlisted projection,
and commits each record (or bounded failure metadata) atomically with a
compare-and-swap byte checkpoint.  A later service can therefore follow log
rotation without letting stale readers skip or replay data silently.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
import sqlite3
import time
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

try:
    from .database import connect_database
    from .sensor_event import MAX_SQLITE_INTEGER
    from .time_utils import format_utc_timestamp, parse_utc_timestamp
    from .zeek_context import (
        DEFAULT_WINDOW_AFTER_SECONDS,
        DEFAULT_WINDOW_BEFORE_SECONDS,
        MAX_CANDIDATES,
        ZEEK_CONTEXT_SCHEMA_VERSION,
        ZeekLookupRequest,
        ZeekLookupResult,
        ZeekLookupStatus,
    )
except ImportError:  # Direct script-style imports used by container entrypoints.
    from database import connect_database
    from sensor_event import MAX_SQLITE_INTEGER
    from time_utils import format_utc_timestamp, parse_utc_timestamp
    from zeek_context import (
        DEFAULT_WINDOW_AFTER_SECONDS,
        DEFAULT_WINDOW_BEFORE_SECONDS,
        MAX_CANDIDATES,
        ZEEK_CONTEXT_SCHEMA_VERSION,
        ZeekLookupRequest,
        ZeekLookupResult,
        ZeekLookupStatus,
    )


MAX_CONN_RECORD_BYTES = 64 * 1024
MAX_UID_CHARS = 128
MAX_SOURCE_INSTANCE_CHARS = 128
MAX_LOG_NAME_CHARS = 32
MAX_OPTIONAL_TEXT_CHARS = 128
MAX_EVIDENCE_TEXT_CHARS = 2_048
MAX_EVIDENCE_LIST_ITEMS = 16
MAX_EVIDENCE_RECORDS = 24
DNS_CORRELATION_LOOKBACK_SECONDS = 5 * 60
MAX_FAILURE_ERROR_CHARS = 256
MAX_CONNECTION_DURATION_SECONDS = 7 * 24 * 60 * 60
DEFAULT_PRUNE_BATCH_SIZE = 1_000
MAX_PRUNE_BATCH_SIZE = 10_000
DEFAULT_PRUNE_MAX_ROWS = 10_000
MAX_PRUNE_ROWS = 100_000

UID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
SAFE_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,127}$")
PRINTABLE_TEXT_RE = re.compile(r"^[\x20-\x7e]+$")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SUPPORTED_EVIDENCE_LOGS = frozenset(
    {"dns", "http", "ssl", "x509", "files", "notice"}
)


SCHEMA_STATEMENTS = (
    """CREATE TABLE IF NOT EXISTS zeek_connections (
           source_instance TEXT NOT NULL,
           uid TEXT NOT NULL,
           ts REAL NOT NULL,
           end_ts REAL NOT NULL,
           orig_h TEXT NOT NULL,
           orig_p INTEGER NOT NULL,
           resp_h TEXT NOT NULL,
           resp_p INTEGER NOT NULL,
           proto TEXT NOT NULL CHECK (proto IN ('TCP', 'UDP')),
           service TEXT,
           duration REAL,
           orig_bytes INTEGER,
           resp_bytes INTEGER,
           conn_state TEXT,
           missed_bytes INTEGER,
           orig_pkts INTEGER,
           resp_pkts INTEGER,
           indexed_at REAL NOT NULL,
           PRIMARY KEY (source_instance, uid)
       ) WITHOUT ROWID""",
    """CREATE INDEX IF NOT EXISTS idx_zeek_conn_tuple_time
       ON zeek_connections (
           source_instance, proto,
           orig_h, orig_p, resp_h, resp_p,
           ts, end_ts
       )""",
    """CREATE INDEX IF NOT EXISTS idx_zeek_conn_end
       ON zeek_connections (end_ts, source_instance, uid)""",
    """CREATE INDEX IF NOT EXISTS idx_zeek_conn_indexed
       ON zeek_connections (indexed_at, source_instance, uid)""",
    """CREATE TABLE IF NOT EXISTS zeek_log_checkpoints (
           source_instance TEXT NOT NULL,
           log_name TEXT NOT NULL,
           device INTEGER NOT NULL,
           inode INTEGER NOT NULL,
           offset INTEGER NOT NULL CHECK (offset >= 0),
           file_size INTEGER NOT NULL CHECK (file_size >= offset),
           record_bytes INTEGER,
           record_sha256 TEXT,
           prefix_bytes INTEGER,
           prefix_sha256 TEXT,
           updated_at REAL NOT NULL,
           PRIMARY KEY (source_instance, log_name)
       ) WITHOUT ROWID""",
    """CREATE TABLE IF NOT EXISTS zeek_ingest_failures (
           id INTEGER PRIMARY KEY,
           source_instance TEXT NOT NULL,
           log_name TEXT NOT NULL,
           device INTEGER NOT NULL,
           inode INTEGER NOT NULL,
           record_end_offset INTEGER NOT NULL,
           record_sha256 TEXT NOT NULL,
           error_code TEXT NOT NULL,
           error TEXT NOT NULL,
           recorded_at REAL NOT NULL
       )""",
    """CREATE INDEX IF NOT EXISTS idx_zeek_failures_recorded
       ON zeek_ingest_failures (recorded_at, id)""",
    """CREATE TABLE IF NOT EXISTS zeek_evidence (
           source_instance TEXT NOT NULL,
           log_name TEXT NOT NULL,
           record_sha256 TEXT NOT NULL,
           ts REAL NOT NULL,
           context_json TEXT NOT NULL,
           indexed_at REAL NOT NULL,
           PRIMARY KEY (source_instance, log_name, record_sha256)
       ) WITHOUT ROWID""",
    """CREATE INDEX IF NOT EXISTS idx_zeek_evidence_indexed
       ON zeek_evidence (indexed_at, source_instance, log_name, record_sha256)""",
    """CREATE TABLE IF NOT EXISTS zeek_evidence_links (
           source_instance TEXT NOT NULL,
           log_name TEXT NOT NULL,
           record_sha256 TEXT NOT NULL,
           link_type TEXT NOT NULL CHECK (
               link_type IN ('uid', 'fuid', 'answer_ip', 'orig_h')
           ),
           link_value TEXT NOT NULL,
           ts REAL NOT NULL,
           PRIMARY KEY (
               source_instance, log_name, record_sha256,
               link_type, link_value
           )
       ) WITHOUT ROWID""",
    """CREATE INDEX IF NOT EXISTS idx_zeek_evidence_link_lookup
       ON zeek_evidence_links (
           source_instance, link_type, link_value,
           ts, log_name, record_sha256
       )""",
)


class ZeekConnValidationError(ValueError):
    """A complete conn.log record cannot enter the bounded index."""


class ZeekIncompleteRecordError(ValueError):
    """A line lacks its terminator and must remain uncheckpointed."""


class ZeekCheckpointConflict(RuntimeError):
    """The durable log cursor changed since a reader last observed it."""


@dataclass(frozen=True)
class ZeekConnection:
    source_instance: str
    uid: str
    ts: float
    end_ts: float
    orig_h: str
    orig_p: int
    resp_h: str
    resp_p: int
    proto: str
    service: str | None = None
    duration: float | None = None
    orig_bytes: int | None = None
    resp_bytes: int | None = None
    conn_state: str | None = None
    missed_bytes: int | None = None
    orig_pkts: int | None = None
    resp_pkts: int | None = None


@dataclass(frozen=True)
class ZeekEvidence:
    source_instance: str
    log_name: str
    ts: float
    context_json: str
    links: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class ZeekLogCheckpoint:
    source_instance: str
    log_name: str
    device: int
    inode: int
    offset: int
    file_size: int
    record_bytes: int | None = None
    record_sha256: str | None = None
    prefix_bytes: int | None = None
    prefix_sha256: str | None = None

    def __post_init__(self) -> None:
        _validate_safe_name(
            self.source_instance,
            "source_instance",
            MAX_SOURCE_INSTANCE_CHARS,
        )
        _validate_safe_name(self.log_name, "log_name", MAX_LOG_NAME_CHARS)
        for label, value in (("device", self.device), ("inode", self.inode)):
            if type(value) is not int or not 0 <= value <= MAX_SQLITE_INTEGER:
                raise ZeekConnValidationError(
                    f"checkpoint {label} must be a non-negative SQLite integer"
                )
        if (
            type(self.offset) is not int
            or not 0 <= self.offset <= MAX_SQLITE_INTEGER
        ):
            raise ZeekConnValidationError(
                "checkpoint offset must be a non-negative SQLite integer"
            )
        if (
            type(self.file_size) is not int
            or not self.offset <= self.file_size <= MAX_SQLITE_INTEGER
        ):
            raise ZeekConnValidationError(
                "checkpoint file_size must be a SQLite integer at least as large as offset"
            )
        if (self.record_bytes is None) != (self.record_sha256 is None):
            raise ZeekConnValidationError(
                "checkpoint record anchor requires both length and digest"
            )
        if self.record_bytes is not None:
            if (
                type(self.record_bytes) is not int
                or not 1 <= self.record_bytes <= self.offset
            ):
                raise ZeekConnValidationError(
                    "checkpoint record_bytes must be positive and no larger than offset"
                )
            if (
                not isinstance(self.record_sha256, str)
                or SHA256_RE.fullmatch(self.record_sha256) is None
            ):
                raise ZeekConnValidationError(
                    "checkpoint record_sha256 must be a sha256 digest"
                )
        if (self.prefix_bytes is None) != (self.prefix_sha256 is None):
            raise ZeekConnValidationError(
                "checkpoint prefix anchor requires both length and digest"
            )
        if self.record_bytes is not None and self.prefix_bytes is not None:
            raise ZeekConnValidationError(
                "checkpoint cannot contain record and prefix anchors together"
            )
        if self.prefix_bytes is not None:
            if (
                self.offset != 0
                or type(self.prefix_bytes) is not int
                or not 1 <= self.prefix_bytes <= self.file_size
            ):
                raise ZeekConnValidationError(
                    "checkpoint prefix_bytes requires an offset-zero non-empty file"
                )
            if (
                not isinstance(self.prefix_sha256, str)
                or SHA256_RE.fullmatch(self.prefix_sha256) is None
            ):
                raise ZeekConnValidationError(
                    "checkpoint prefix_sha256 must be a sha256 digest"
                )


@dataclass(frozen=True)
class IndexedLineResult:
    indexed: bool
    duplicate: bool = False
    failure_code: str | None = None


@dataclass(frozen=True)
class ZeekPruneResult:
    connections: int
    evidence: int
    failures: int


def _validate_safe_name(value: Any, label: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or SAFE_NAME_RE.fullmatch(value.strip()) is None
    ):
        raise ZeekConnValidationError(
            f"{label} must be a safe identifier of at most {maximum} characters"
        )
    return value.strip()


def _required_number(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ZeekConnValidationError(f"{label} must be numeric")
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise ZeekConnValidationError(f"{label} must be finite and non-negative")
    return number


def _zeek_timestamp(value: Any) -> float:
    timestamp = _required_number(value, "ts")
    try:
        datetime.fromtimestamp(timestamp, timezone.utc)
    except (OSError, OverflowError, ValueError) as exc:
        raise ZeekConnValidationError("ts is outside the supported time range") from exc
    return timestamp


def _optional_number(
    value: Any,
    label: str,
    *,
    maximum: float | None = None,
) -> float | None:
    if value is None:
        return None
    number = _required_number(value, label)
    if maximum is not None and number > maximum:
        raise ZeekConnValidationError(f"{label} exceeds the supported maximum")
    return number


def _required_port(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= 65535:
        raise ZeekConnValidationError(
            f"{label} must be an integer from 0 to 65535"
        )
    return value


def _optional_counter(value: Any, label: str) -> int | None:
    if value is None:
        return None
    if type(value) is not int or not 0 <= value <= MAX_SQLITE_INTEGER:
        raise ZeekConnValidationError(
            f"{label} must be a non-negative SQLite integer"
        )
    return value


def _required_ip(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ZeekConnValidationError(f"{label} must be an IP address string")
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ZeekConnValidationError(f"{label} must be a valid IP address") from exc


def _optional_text(value: Any, label: str) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_OPTIONAL_TEXT_CHARS
        or PRINTABLE_TEXT_RE.fullmatch(value) is None
    ):
        raise ZeekConnValidationError(
            f"{label} must contain at most {MAX_OPTIONAL_TEXT_CHARS} printable characters"
        )
    return value


def normalize_conn_record(
    record: Mapping[str, Any],
    source_instance: str,
) -> ZeekConnection:
    """Validate and project one decoded Zeek conn.log JSON object."""

    if not isinstance(record, Mapping):
        raise ZeekConnValidationError("conn.log record must be a JSON object")
    source_instance = _validate_safe_name(
        source_instance,
        "source_instance",
        MAX_SOURCE_INSTANCE_CHARS,
    )
    uid = record.get("uid")
    if not isinstance(uid, str) or UID_RE.fullmatch(uid) is None:
        raise ZeekConnValidationError(
            f"uid must be a safe identifier of at most {MAX_UID_CHARS} characters"
        )
    ts = _zeek_timestamp(record.get("ts"))
    duration = _optional_number(
        record.get("duration"),
        "duration",
        maximum=MAX_CONNECTION_DURATION_SECONDS,
    )
    proto_value = record.get("proto")
    if not isinstance(proto_value, str):
        raise ZeekConnValidationError("proto must be tcp or udp")
    proto = proto_value.strip().upper()
    if proto not in {"TCP", "UDP"}:
        raise ZeekConnValidationError("proto must be tcp or udp")

    end_ts = ts + (duration or 0.0)
    try:
        datetime.fromtimestamp(end_ts, timezone.utc)
    except (OSError, OverflowError, ValueError) as exc:
        raise ZeekConnValidationError(
            "connection end time is outside the supported range"
        ) from exc

    return ZeekConnection(
        source_instance=source_instance,
        uid=uid,
        ts=ts,
        end_ts=end_ts,
        orig_h=_required_ip(record.get("id.orig_h"), "id.orig_h"),
        orig_p=_required_port(record.get("id.orig_p"), "id.orig_p"),
        resp_h=_required_ip(record.get("id.resp_h"), "id.resp_h"),
        resp_p=_required_port(record.get("id.resp_p"), "id.resp_p"),
        proto=proto,
        service=_optional_text(record.get("service"), "service"),
        duration=duration,
        orig_bytes=_optional_counter(record.get("orig_bytes"), "orig_bytes"),
        resp_bytes=_optional_counter(record.get("resp_bytes"), "resp_bytes"),
        conn_state=_optional_text(record.get("conn_state"), "conn_state"),
        missed_bytes=_optional_counter(
            record.get("missed_bytes"),
            "missed_bytes",
        ),
        orig_pkts=_optional_counter(record.get("orig_pkts"), "orig_pkts"),
        resp_pkts=_optional_counter(record.get("resp_pkts"), "resp_pkts"),
    )


def _optional_evidence_text(
    value: Any,
    label: str,
    *,
    maximum: int = MAX_EVIDENCE_TEXT_CHARS,
) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ZeekConnValidationError(
            f"{label} must be non-empty text of at most {maximum} characters"
        )
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ZeekConnValidationError(f"{label} contains control characters")
    return value


def _optional_evidence_bool(value: Any, label: str) -> bool | None:
    if value is None:
        return None
    if type(value) is not bool:
        raise ZeekConnValidationError(f"{label} must be a boolean")
    return value


def _optional_evidence_integer(
    value: Any,
    label: str,
    *,
    maximum: int = MAX_SQLITE_INTEGER,
) -> int | None:
    if value is None:
        return None
    if type(value) is not int or not 0 <= value <= maximum:
        raise ZeekConnValidationError(
            f"{label} must be an integer from 0 to {maximum}"
        )
    return value


def _optional_evidence_list(
    value: Any,
    label: str,
    *,
    identifiers: bool = False,
) -> list[str] | None:
    if value is None:
        return None
    if not isinstance(value, list) or len(value) > MAX_EVIDENCE_LIST_ITEMS:
        raise ZeekConnValidationError(
            f"{label} must be a list of at most {MAX_EVIDENCE_LIST_ITEMS} values"
        )
    result = []
    for index, item in enumerate(value):
        text = _optional_evidence_text(
            item,
            f"{label}[{index}]",
            maximum=MAX_UID_CHARS if identifiers else MAX_EVIDENCE_TEXT_CHARS,
        )
        if text is None:
            raise ZeekConnValidationError(f"{label}[{index}] cannot be null")
        if identifiers and UID_RE.fullmatch(text) is None:
            raise ZeekConnValidationError(
                f"{label}[{index}] must be a safe Zeek identifier"
            )
        if text not in result:
            result.append(text)
    return result


def _evidence_uid(value: Any, label: str, *, required: bool) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str) or UID_RE.fullmatch(value) is None:
        raise ZeekConnValidationError(
            f"{label} must be a safe identifier of at most {MAX_UID_CHARS} characters"
        )
    return value


def _copy_evidence_text(record: Mapping[str, Any], output: dict, *names: str) -> None:
    for name in names:
        value = _optional_evidence_text(record.get(name), name)
        if value is not None:
            output[name] = value


def _copy_evidence_integers(
    record: Mapping[str, Any],
    output: dict,
    *names: str,
) -> None:
    for name in names:
        value = _optional_evidence_integer(record.get(name), name)
        if value is not None:
            output[name] = value


def _copy_evidence_bools(record: Mapping[str, Any], output: dict, *names: str) -> None:
    for name in names:
        value = _optional_evidence_bool(record.get(name), name)
        if value is not None:
            output[name] = value


def _copy_evidence_lists(record: Mapping[str, Any], output: dict, *names: str) -> None:
    for name in names:
        value = _optional_evidence_list(record.get(name), name)
        if value is not None:
            output[name] = value


def normalize_evidence_record(
    record: Mapping[str, Any],
    source_instance: str,
    log_name: str,
) -> ZeekEvidence:
    """Project one supported application log into bounded, UID-linked evidence."""

    if not isinstance(record, Mapping):
        raise ZeekConnValidationError(f"{log_name}.log record must be a JSON object")
    source_instance = _validate_safe_name(
        source_instance,
        "source_instance",
        MAX_SOURCE_INSTANCE_CHARS,
    )
    if log_name not in SUPPORTED_EVIDENCE_LOGS:
        raise ZeekConnValidationError(f"unsupported Zeek evidence log: {log_name}")
    ts = _zeek_timestamp(record.get("ts"))
    output: dict[str, Any] = {
        "ts": format_utc_timestamp(datetime.fromtimestamp(ts, timezone.utc))
    }
    links: list[tuple[str, str]] = []

    if log_name in {"dns", "http", "ssl"}:
        uid = _evidence_uid(record.get("uid"), "uid", required=True)
        output["uid"] = uid
        links.append(("uid", uid))
    elif log_name == "files":
        fuid = _evidence_uid(record.get("fuid"), "fuid", required=True)
        output["fuid"] = fuid
        links.append(("fuid", fuid))
        conn_uids = _optional_evidence_list(
            record.get("conn_uids"),
            "conn_uids",
            identifiers=True,
        ) or []
        if conn_uids:
            output["conn_uids"] = conn_uids
            links.extend(("uid", uid) for uid in conn_uids)
    elif log_name == "x509":
        fuid = _evidence_uid(record.get("id"), "id", required=True)
        output["id"] = fuid
        links.append(("fuid", fuid))
    else:
        uid = _evidence_uid(record.get("uid"), "uid", required=False)
        fuid = _evidence_uid(record.get("fuid"), "fuid", required=False)
        if uid is not None:
            output["uid"] = uid
            links.append(("uid", uid))
        if fuid is not None:
            output["fuid"] = fuid
            links.append(("fuid", fuid))

    if log_name == "dns":
        _copy_evidence_text(record, output, "query", "qtype_name", "rcode_name")
        origin = record.get("id.orig_h")
        if origin is not None:
            canonical_origin = _required_ip(origin, "id.orig_h")
            output["id.orig_h"] = canonical_origin
            links.append(("orig_h", canonical_origin))
        answers = _optional_evidence_list(record.get("answers"), "answers")
        if answers is not None:
            output["answers"] = answers
            for answer in answers:
                try:
                    canonical_answer = str(ipaddress.ip_address(answer))
                except ValueError:
                    continue
                links.append(("answer_ip", canonical_answer))
        _copy_evidence_bools(record, output, "rejected")
    elif log_name == "http":
        _copy_evidence_text(
            record,
            output,
            "method",
            "host",
            "uri",
            "referrer",
            "user_agent",
            "status_msg",
        )
        _copy_evidence_integers(
            record,
            output,
            "status_code",
            "request_body_len",
            "response_body_len",
        )
        _copy_evidence_lists(record, output, "resp_mime_types")
    elif log_name == "ssl":
        _copy_evidence_text(
            record,
            output,
            "version",
            "cipher",
            "curve",
            "server_name",
            "next_protocol",
        )
        _copy_evidence_bools(record, output, "established", "resumed")
        for name in ("cert_chain_fuids", "client_cert_chain_fuids"):
            values = _optional_evidence_list(
                record.get(name),
                name,
                identifiers=True,
            )
            if values is not None:
                output[name] = values
                links.extend(("fuid", value) for value in values)
    elif log_name == "x509":
        _copy_evidence_text(
            record,
            output,
            "certificate.serial",
            "certificate.subject",
            "certificate.issuer",
            "certificate.key_alg",
            "certificate.sig_alg",
            "certificate.key_type",
            "certificate.curve",
        )
        _copy_evidence_integers(
            record,
            output,
            "certificate.version",
            "certificate.key_length",
        )
        _copy_evidence_lists(
            record,
            output,
            "san.dns",
            "san.ip",
            "san.email",
            "san.uri",
        )
        for name in ("certificate.not_valid_before", "certificate.not_valid_after"):
            value = record.get(name)
            if value is not None:
                epoch = _zeek_timestamp(value)
                output[name] = format_utc_timestamp(
                    datetime.fromtimestamp(epoch, timezone.utc)
                )
    elif log_name == "files":
        _copy_evidence_text(
            record,
            output,
            "source",
            "mime_type",
            "filename",
            "md5",
            "sha1",
            "sha256",
        )
        _copy_evidence_integers(
            record,
            output,
            "seen_bytes",
            "total_bytes",
            "missing_bytes",
            "overflow_bytes",
        )
        _copy_evidence_bools(record, output, "is_orig", "timedout")
    else:
        _copy_evidence_text(record, output, "note", "msg", "sub", "src", "dst")
        _copy_evidence_integers(record, output, "p")
        _copy_evidence_lists(record, output, "actions")

    context_json = json.dumps(
        output,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    if len(context_json.encode("utf-8")) > MAX_CONN_RECORD_BYTES:
        raise ZeekConnValidationError("normalized Zeek evidence exceeds its byte limit")
    return ZeekEvidence(
        source_instance=source_instance,
        log_name=log_name,
        ts=ts,
        context_json=context_json,
        links=tuple(dict.fromkeys(links)),
    )


def ensure_zeek_index(conn: sqlite3.Connection) -> None:
    """Create the standalone index schema idempotently."""

    try:
        conn.execute("BEGIN IMMEDIATE")
        # The checkpoint table predates its archive-recovery anchor columns.
        # Create it first, then migrate existing v0.5 indexes before replaying
        # the complete idempotent schema.
        conn.execute(SCHEMA_STATEMENTS[4])
        checkpoint_columns = {
            str(row[1])
            for row in conn.execute("PRAGMA table_info(zeek_log_checkpoints)")
        }
        if "record_bytes" not in checkpoint_columns:
            conn.execute(
                "ALTER TABLE zeek_log_checkpoints ADD COLUMN record_bytes INTEGER"
            )
        if "record_sha256" not in checkpoint_columns:
            conn.execute(
                "ALTER TABLE zeek_log_checkpoints ADD COLUMN record_sha256 TEXT"
            )
        if "prefix_bytes" not in checkpoint_columns:
            conn.execute(
                "ALTER TABLE zeek_log_checkpoints ADD COLUMN prefix_bytes INTEGER"
            )
        if "prefix_sha256" not in checkpoint_columns:
            conn.execute(
                "ALTER TABLE zeek_log_checkpoints ADD COLUMN prefix_sha256 TEXT"
            )
        for statement in SCHEMA_STATEMENTS:
            conn.execute(statement)
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def connect_zeek_index(path: str | Path) -> sqlite3.Connection:
    """Open and initialize a dedicated Zeek context database."""

    conn = connect_database(path)
    try:
        ensure_zeek_index(conn)
        return conn
    except Exception:
        conn.close()
        raise


def load_checkpoint(
    conn: sqlite3.Connection,
    source_instance: str,
    log_name: str = "conn",
) -> ZeekLogCheckpoint | None:
    """Return one durable index cursor without inventing a missing position."""

    source_instance = _validate_safe_name(
        source_instance,
        "source_instance",
        MAX_SOURCE_INSTANCE_CHARS,
    )
    log_name = _validate_safe_name(log_name, "log_name", MAX_LOG_NAME_CHARS)
    row = conn.execute(
        """SELECT device, inode, offset, file_size,
                  record_bytes, record_sha256, prefix_bytes, prefix_sha256
           FROM zeek_log_checkpoints
           WHERE source_instance = ? AND log_name = ?""",
        (source_instance, log_name),
    ).fetchone()
    if row is None:
        return None
    return ZeekLogCheckpoint(
        source_instance=source_instance,
        log_name=log_name,
        device=int(row[0]),
        inode=int(row[1]),
        offset=int(row[2]),
        file_size=int(row[3]),
        record_bytes=None if row[4] is None else int(row[4]),
        record_sha256=None if row[5] is None else str(row[5]),
        prefix_bytes=None if row[6] is None else int(row[6]),
        prefix_sha256=None if row[7] is None else str(row[7]),
    )


def _validate_checkpoint_transition(
    current: ZeekLogCheckpoint | None,
    expected: ZeekLogCheckpoint | None,
    next_checkpoint: ZeekLogCheckpoint,
    record_bytes: int,
) -> None:
    if current != expected:
        raise ZeekCheckpointConflict(
            "Zeek log checkpoint changed while the record was being processed"
        )
    if expected is not None and (
        expected.source_instance != next_checkpoint.source_instance
        or expected.log_name != next_checkpoint.log_name
    ):
        raise ZeekCheckpointConflict(
            "Zeek checkpoint identity cannot change source or log name"
        )
    if expected is None:
        if next_checkpoint.offset != record_bytes:
            raise ZeekCheckpointConflict(
                "the first Zeek checkpoint must equal the complete record length"
            )
        return
    same_file = (
        expected.device == next_checkpoint.device
        and expected.inode == next_checkpoint.inode
    )
    expected_offset = expected.offset + record_bytes if same_file else record_bytes
    if next_checkpoint.offset != expected_offset:
        raise ZeekCheckpointConflict(
            "Zeek checkpoint must advance by exactly one complete record"
        )
    if same_file and next_checkpoint.file_size < expected.file_size:
        raise ZeekCheckpointConflict(
            "Zeek checkpoint file size cannot shrink within the same identity"
        )


def _decode_complete_line(raw_line: bytes | str) -> tuple[bytes, str]:
    if isinstance(raw_line, str):
        raw = raw_line.encode("utf-8")
    elif isinstance(raw_line, bytes):
        raw = raw_line
    else:
        raise TypeError("raw_line must be bytes or text")
    if not raw.endswith((b"\n", b"\r")):
        raise ZeekIncompleteRecordError(
            "Zeek JSON-Lines record is incomplete and cannot be checkpointed"
        )
    if len(raw) > MAX_CONN_RECORD_BYTES:
        raise ZeekConnValidationError(
            f"conn.log record exceeds the {MAX_CONN_RECORD_BYTES}-byte limit"
        )
    try:
        text = raw.rstrip(b"\r\n").decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ZeekConnValidationError("conn.log record is not valid UTF-8") from exc
    return raw, text


def _parse_complete_conn_line(
    raw_line: bytes | str,
    source_instance: str,
) -> tuple[bytes, ZeekConnection | None]:
    raw, text = _decode_complete_line(raw_line)
    if not text.strip():
        return raw, None

    def reject_duplicate_keys(pairs):
        decoded = {}
        for key, value in pairs:
            if key in decoded:
                raise ZeekConnValidationError(
                    f"conn.log record contains duplicate key {key!r}"
                )
            decoded[key] = value
        return decoded

    try:
        decoded = json.loads(text, object_pairs_hook=reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise ZeekConnValidationError("conn.log record is not valid JSON") from exc
    return raw, normalize_conn_record(decoded, source_instance)


def _parse_complete_evidence_line(
    raw_line: bytes | str,
    source_instance: str,
    log_name: str,
) -> tuple[bytes, ZeekEvidence | None]:
    raw, text = _decode_complete_line(raw_line)
    if not text.strip():
        return raw, None

    def reject_duplicate_keys(pairs):
        decoded = {}
        for key, value in pairs:
            if key in decoded:
                raise ZeekConnValidationError(
                    f"{log_name}.log record contains duplicate key {key!r}"
                )
            decoded[key] = value
        return decoded

    try:
        decoded = json.loads(text, object_pairs_hook=reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise ZeekConnValidationError(
            f"{log_name}.log record is not valid JSON"
        ) from exc
    return raw, normalize_evidence_record(decoded, source_instance, log_name)


def _insert_connection(
    conn: sqlite3.Connection,
    record: ZeekConnection,
    indexed_at: float,
) -> str:
    cursor = conn.execute(
        """INSERT OR IGNORE INTO zeek_connections (
               source_instance, uid, ts, end_ts,
               orig_h, orig_p, resp_h, resp_p, proto,
               service, duration, orig_bytes, resp_bytes, conn_state,
               missed_bytes, orig_pkts, resp_pkts, indexed_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            record.source_instance,
            record.uid,
            record.ts,
            record.end_ts,
            record.orig_h,
            record.orig_p,
            record.resp_h,
            record.resp_p,
            record.proto,
            record.service,
            record.duration,
            record.orig_bytes,
            record.resp_bytes,
            record.conn_state,
            record.missed_bytes,
            record.orig_pkts,
            record.resp_pkts,
            indexed_at,
        ),
    )
    if cursor.rowcount == 1:
        return "inserted"
    stored = conn.execute(
        """SELECT ts, end_ts, orig_h, orig_p, resp_h, resp_p, proto,
                  service, duration, orig_bytes, resp_bytes, conn_state,
                  missed_bytes, orig_pkts, resp_pkts
           FROM zeek_connections
           WHERE source_instance = ? AND uid = ?""",
        (record.source_instance, record.uid),
    ).fetchone()
    expected = (
        record.ts,
        record.end_ts,
        record.orig_h,
        record.orig_p,
        record.resp_h,
        record.resp_p,
        record.proto,
        record.service,
        record.duration,
        record.orig_bytes,
        record.resp_bytes,
        record.conn_state,
        record.missed_bytes,
        record.orig_pkts,
        record.resp_pkts,
    )
    return "duplicate" if stored == expected else "uid_conflict"


def _insert_evidence(
    conn: sqlite3.Connection,
    record: ZeekEvidence,
    record_sha256: str,
    indexed_at: float,
) -> str:
    cursor = conn.execute(
        """INSERT OR IGNORE INTO zeek_evidence (
               source_instance, log_name, record_sha256,
               ts, context_json, indexed_at
           ) VALUES (?, ?, ?, ?, ?, ?)""",
        (
            record.source_instance,
            record.log_name,
            record_sha256,
            record.ts,
            record.context_json,
            indexed_at,
        ),
    )
    if cursor.rowcount != 1:
        stored = conn.execute(
            """SELECT ts, context_json
               FROM zeek_evidence
               WHERE source_instance = ? AND log_name = ?
                 AND record_sha256 = ?""",
            (record.source_instance, record.log_name, record_sha256),
        ).fetchone()
        if stored != (record.ts, record.context_json):
            return "digest_conflict"
        return "duplicate"
    for link_type, link_value in record.links:
        conn.execute(
            """INSERT INTO zeek_evidence_links (
                   source_instance, log_name, record_sha256,
                   link_type, link_value, ts
               ) VALUES (?, ?, ?, ?, ?, ?)""",
            (
                record.source_instance,
                record.log_name,
                record_sha256,
                link_type,
                link_value,
                record.ts,
            ),
        )
    return "inserted"


def _store_failure_digest(
    conn: sqlite3.Connection,
    checkpoint: ZeekLogCheckpoint,
    record_sha256: str,
    error_code: str,
    error: str,
    recorded_at: float,
) -> None:
    conn.execute(
        """INSERT INTO zeek_ingest_failures (
               source_instance, log_name, device, inode, record_end_offset,
               record_sha256, error_code, error, recorded_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            checkpoint.source_instance,
            checkpoint.log_name,
            checkpoint.device,
            checkpoint.inode,
            checkpoint.offset,
            record_sha256,
            error_code,
            error[:MAX_FAILURE_ERROR_CHARS],
            recorded_at,
        ),
    )


def _store_checkpoint(
    conn: sqlite3.Connection,
    checkpoint: ZeekLogCheckpoint,
    updated_at: float,
) -> None:
    conn.execute(
        """INSERT INTO zeek_log_checkpoints (
               source_instance, log_name, device, inode,
               offset, file_size, record_bytes, record_sha256,
               prefix_bytes, prefix_sha256, updated_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(source_instance, log_name) DO UPDATE SET
               device = excluded.device,
               inode = excluded.inode,
               offset = excluded.offset,
               file_size = excluded.file_size,
               record_bytes = excluded.record_bytes,
               record_sha256 = excluded.record_sha256,
               prefix_bytes = excluded.prefix_bytes,
               prefix_sha256 = excluded.prefix_sha256,
               updated_at = excluded.updated_at""",
        (
            checkpoint.source_instance,
            checkpoint.log_name,
            checkpoint.device,
            checkpoint.inode,
            checkpoint.offset,
            checkpoint.file_size,
            checkpoint.record_bytes,
            checkpoint.record_sha256,
            checkpoint.prefix_bytes,
            checkpoint.prefix_sha256,
            updated_at,
        ),
    )


def index_conn_line(
    conn: sqlite3.Connection,
    raw_line: bytes | str,
    next_checkpoint: ZeekLogCheckpoint,
    *,
    expected_checkpoint: ZeekLogCheckpoint | None,
    clock: Callable[[], float] = time.time,
) -> IndexedLineResult:
    """Atomically index one complete line and advance an exact durable cursor."""

    if next_checkpoint.log_name != "conn":
        raise ZeekConnValidationError(
            "conn.log records require the 'conn' checkpoint name"
        )
    raw = raw_line.encode("utf-8") if isinstance(raw_line, str) else raw_line
    record = None
    failure_code = None
    failure_message = None
    try:
        raw, record = _parse_complete_conn_line(
            raw_line,
            next_checkpoint.source_instance,
        )
    except ZeekIncompleteRecordError:
        raise
    except ZeekConnValidationError as exc:
        if not isinstance(raw, bytes):
            raise TypeError("raw_line must be bytes or text") from exc
        failure_code = "invalid_record"
        failure_message = str(exc)

    observed_at = _epoch_timestamp(clock())
    try:
        conn.execute("BEGIN IMMEDIATE")
        current = load_checkpoint(
            conn,
            next_checkpoint.source_instance,
            next_checkpoint.log_name,
        )
        _validate_checkpoint_transition(
            current,
            expected_checkpoint,
            next_checkpoint,
            len(raw),
        )
        inserted = False
        duplicate = False
        if record is not None:
            insert_outcome = _insert_connection(conn, record, observed_at)
            inserted = insert_outcome == "inserted"
            duplicate = insert_outcome == "duplicate"
            if insert_outcome == "uid_conflict":
                failure_code = "uid_conflict"
                failure_message = (
                    "Zeek uid already exists with different normalized content"
                )
        if failure_code is not None:
            _store_failure_digest(
                conn,
                next_checkpoint,
                "sha256:" + hashlib.sha256(raw).hexdigest(),
                failure_code,
                failure_message or failure_code,
                observed_at,
            )
        stored_checkpoint = replace(
            next_checkpoint,
            record_bytes=len(raw),
            record_sha256="sha256:" + hashlib.sha256(raw).hexdigest(),
        )
        _store_checkpoint(conn, stored_checkpoint, observed_at)
        conn.commit()
        return IndexedLineResult(
            indexed=inserted,
            duplicate=duplicate,
            failure_code=failure_code,
        )
    except Exception:
        conn.rollback()
        raise


def index_evidence_line(
    conn: sqlite3.Connection,
    raw_line: bytes | str,
    next_checkpoint: ZeekLogCheckpoint,
    *,
    expected_checkpoint: ZeekLogCheckpoint | None,
    clock: Callable[[], float] = time.time,
) -> IndexedLineResult:
    """Atomically index one supported application-log record and its cursor."""

    log_name = next_checkpoint.log_name
    if log_name not in SUPPORTED_EVIDENCE_LOGS:
        raise ZeekConnValidationError(f"unsupported Zeek evidence log: {log_name}")
    raw = raw_line.encode("utf-8") if isinstance(raw_line, str) else raw_line
    record = None
    failure_code = None
    failure_message = None
    try:
        raw, record = _parse_complete_evidence_line(
            raw_line,
            next_checkpoint.source_instance,
            log_name,
        )
    except ZeekIncompleteRecordError:
        raise
    except ZeekConnValidationError as exc:
        if not isinstance(raw, bytes):
            raise TypeError("raw_line must be bytes or text") from exc
        failure_code = "invalid_record"
        failure_message = str(exc)

    observed_at = _epoch_timestamp(clock())
    record_sha256 = "sha256:" + hashlib.sha256(raw).hexdigest()
    try:
        conn.execute("BEGIN IMMEDIATE")
        current = load_checkpoint(
            conn,
            next_checkpoint.source_instance,
            log_name,
        )
        _validate_checkpoint_transition(
            current,
            expected_checkpoint,
            next_checkpoint,
            len(raw),
        )
        inserted = False
        duplicate = False
        if record is not None and record.links:
            insert_outcome = _insert_evidence(
                conn,
                record,
                record_sha256,
                observed_at,
            )
            inserted = insert_outcome == "inserted"
            duplicate = insert_outcome == "duplicate"
            if insert_outcome == "digest_conflict":
                failure_code = "digest_conflict"
                failure_message = (
                    "Zeek evidence digest exists with different normalized content"
                )
        if failure_code is not None:
            _store_failure_digest(
                conn,
                next_checkpoint,
                record_sha256,
                failure_code,
                failure_message or failure_code,
                observed_at,
            )
        stored_checkpoint = replace(
            next_checkpoint,
            record_bytes=len(raw),
            record_sha256=record_sha256,
        )
        _store_checkpoint(conn, stored_checkpoint, observed_at)
        conn.commit()
        return IndexedLineResult(
            indexed=inserted,
            duplicate=duplicate,
            failure_code=failure_code,
        )
    except Exception:
        conn.rollback()
        raise


def index_conn_failure(
    conn: sqlite3.Connection,
    next_checkpoint: ZeekLogCheckpoint,
    *,
    expected_checkpoint: ZeekLogCheckpoint | None,
    record_bytes: int,
    record_sha256: str,
    error_code: str,
    error: str,
    clock: Callable[[], float] = time.time,
) -> IndexedLineResult:
    """Atomically checkpoint bounded metadata for a complete rejected line."""

    if next_checkpoint.log_name not in ({"conn"} | SUPPORTED_EVIDENCE_LOGS):
        raise ZeekConnValidationError(
            "Zeek failures require a supported checkpoint name"
        )
    if (
        type(record_bytes) is not int
        or not 1 <= record_bytes <= MAX_SQLITE_INTEGER
    ):
        raise ZeekConnValidationError(
            "record_bytes must be a positive SQLite integer"
        )
    if not isinstance(record_sha256, str) or SHA256_RE.fullmatch(
        record_sha256
    ) is None:
        raise ZeekConnValidationError("record_sha256 must be a sha256 digest")
    error_code = _validate_safe_name(error_code, "error_code", 64)
    if (
        not isinstance(error, str)
        or not error
        or len(error) > MAX_FAILURE_ERROR_CHARS
        or PRINTABLE_TEXT_RE.fullmatch(error) is None
    ):
        raise ZeekConnValidationError(
            f"error must contain at most {MAX_FAILURE_ERROR_CHARS} printable characters"
        )

    observed_at = _epoch_timestamp(clock())
    try:
        conn.execute("BEGIN IMMEDIATE")
        current = load_checkpoint(
            conn,
            next_checkpoint.source_instance,
            next_checkpoint.log_name,
        )
        _validate_checkpoint_transition(
            current,
            expected_checkpoint,
            next_checkpoint,
            record_bytes,
        )
        _store_failure_digest(
            conn,
            next_checkpoint,
            record_sha256,
            error_code,
            error,
            observed_at,
        )
        stored_checkpoint = replace(
            next_checkpoint,
            record_bytes=record_bytes,
            record_sha256=record_sha256,
        )
        _store_checkpoint(conn, stored_checkpoint, observed_at)
        conn.commit()
        return IndexedLineResult(indexed=False, failure_code=error_code)
    except Exception:
        conn.rollback()
        raise


def rotate_checkpoint(
    conn: sqlite3.Connection,
    next_checkpoint: ZeekLogCheckpoint,
    *,
    expected_checkpoint: ZeekLogCheckpoint,
    allow_reused_identity: bool = False,
    clock: Callable[[], float] = time.time,
) -> None:
    """Persist a proven, fully drained handoff to a successor at byte zero."""

    if next_checkpoint.log_name not in ({"conn"} | SUPPORTED_EVIDENCE_LOGS):
        raise ZeekConnValidationError(
            "Zeek rotation requires a supported checkpoint name"
        )
    if (
        next_checkpoint.source_instance != expected_checkpoint.source_instance
        or next_checkpoint.log_name != expected_checkpoint.log_name
    ):
        raise ZeekCheckpointConflict(
            "Zeek rotation cannot change source or log name"
        )
    if next_checkpoint.offset != 0:
        raise ZeekCheckpointConflict(
            "a rotated Zeek successor must begin at byte zero"
        )
    if (
        next_checkpoint.prefix_bytes is None
        or next_checkpoint.prefix_sha256 is None
    ):
        raise ZeekCheckpointConflict(
            "a rotated Zeek successor requires a durable prefix anchor"
        )
    if (
        next_checkpoint.device == expected_checkpoint.device
        and next_checkpoint.inode == expected_checkpoint.inode
        and not allow_reused_identity
    ):
        raise ZeekCheckpointConflict(
            "Zeek rotation requires a different file identity"
        )
    if expected_checkpoint.offset != expected_checkpoint.file_size:
        raise ZeekCheckpointConflict(
            "the checkpointed Zeek file is not proven fully drained"
        )

    observed_at = _epoch_timestamp(clock())
    try:
        conn.execute("BEGIN IMMEDIATE")
        current = load_checkpoint(
            conn,
            expected_checkpoint.source_instance,
            expected_checkpoint.log_name,
        )
        if current != expected_checkpoint:
            raise ZeekCheckpointConflict(
                "Zeek log checkpoint changed during rotation"
            )
        _store_checkpoint(conn, next_checkpoint, observed_at)
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def _epoch_timestamp(value: str | datetime | int | float) -> float:
    if isinstance(value, bool):
        raise ValueError("timestamp must not be boolean")
    if isinstance(value, (int, float)):
        epoch = float(value)
        if not math.isfinite(epoch) or epoch < 0:
            raise ValueError("epoch timestamp must be finite and non-negative")
        return epoch
    return parse_utc_timestamp(value).timestamp()


def _connection_context(row: tuple[Any, ...], request: ZeekLookupRequest) -> dict:
    (
        uid,
        ts,
        end_ts,
        orig_h,
        orig_p,
        resp_h,
        resp_p,
        proto,
        service,
        duration,
        orig_bytes,
        resp_bytes,
        conn_state,
        missed_bytes,
        orig_pkts,
        resp_pkts,
    ) = row
    direction = (
        "same_as_alert"
        if orig_h == request.src_ip
        and orig_p == request.src_port
        and resp_h == request.dest_ip
        and resp_p == request.dest_port
        else "reversed_from_alert"
    )
    context = {
        "schema_version": ZEEK_CONTEXT_SCHEMA_VERSION,
        "connections": [
            {
                "uid": uid,
                "ts": format_utc_timestamp(
                    datetime.fromtimestamp(ts, timezone.utc)
                ),
                "end_ts": format_utc_timestamp(
                    datetime.fromtimestamp(end_ts, timezone.utc)
                ),
                "id.orig_h": orig_h,
                "id.orig_p": orig_p,
                "id.resp_h": resp_h,
                "id.resp_p": resp_p,
                "proto": proto,
                "service": service,
                "duration": duration,
                "orig_bytes": orig_bytes,
                "resp_bytes": resp_bytes,
                "conn_state": conn_state,
                "missed_bytes": missed_bytes,
                "orig_pkts": orig_pkts,
                "resp_pkts": resp_pkts,
                "direction": direction,
            }
        ],
    }
    return context


_EVIDENCE_CONTEXT_KEYS = {
    "dns": "dns",
    "http": "http",
    "ssl": "tls",
    "x509": "certificates",
    "files": "files",
    "notice": "notices",
}


def _linked_application_evidence(
    conn: sqlite3.Connection,
    source_instance: str,
    uid: str,
    start_ts: float,
    end_ts: float,
    origin_host: str,
    responder_host: str,
) -> tuple[list[tuple[str, dict]], bool]:
    direct = conn.execute(
        """SELECT e.log_name, e.record_sha256, e.context_json, e.ts
           FROM zeek_evidence_links AS link
           JOIN zeek_evidence AS e
             ON e.source_instance = link.source_instance
            AND e.log_name = link.log_name
            AND e.record_sha256 = link.record_sha256
           WHERE link.source_instance = ?
             AND link.link_type = 'uid'
             AND link.link_value = ?
             AND link.ts BETWEEN ? AND ?
           ORDER BY link.ts, link.log_name, link.record_sha256
           LIMIT ?""",
        (
            source_instance,
            uid,
            start_ts - DEFAULT_WINDOW_BEFORE_SECONDS,
            end_ts + DEFAULT_WINDOW_AFTER_SECONDS,
            MAX_EVIDENCE_RECORDS + 1,
        ),
    ).fetchall()
    fuid_rows = conn.execute(
        """SELECT DISTINCT fuid.link_value
           FROM zeek_evidence_links AS uid
           JOIN zeek_evidence_links AS fuid
             ON fuid.source_instance = uid.source_instance
            AND fuid.log_name = uid.log_name
            AND fuid.record_sha256 = uid.record_sha256
           WHERE uid.source_instance = ?
             AND uid.link_type = 'uid'
             AND uid.link_value = ?
             AND uid.ts BETWEEN ? AND ?
             AND fuid.link_type = 'fuid'
           ORDER BY fuid.link_value
           LIMIT ?""",
        (
            source_instance,
            uid,
            start_ts - DEFAULT_WINDOW_BEFORE_SECONDS,
            end_ts + DEFAULT_WINDOW_AFTER_SECONDS,
            MAX_EVIDENCE_LIST_ITEMS + 1,
        ),
    ).fetchall()
    truncated = (
        len(direct) > MAX_EVIDENCE_RECORDS
        or len(fuid_rows) > MAX_EVIDENCE_LIST_ITEMS
    )
    rows = [(*row, "same_connection_uid") for row in direct[:MAX_EVIDENCE_RECORDS]]
    remaining = MAX_EVIDENCE_RECORDS - len(rows)
    fuids = [str(row[0]) for row in fuid_rows[:MAX_EVIDENCE_LIST_ITEMS]]
    if remaining > 0 and fuids:
        placeholders = ",".join("?" for _value in fuids)
        linked = conn.execute(
            f"""SELECT DISTINCT e.log_name, e.record_sha256,
                               e.context_json, e.ts
                   FROM zeek_evidence_links AS link
                   JOIN zeek_evidence AS e
                     ON e.source_instance = link.source_instance
                    AND e.log_name = link.log_name
                    AND e.record_sha256 = link.record_sha256
                   WHERE link.source_instance = ?
                     AND link.link_type = 'fuid'
                     AND link.link_value IN ({placeholders})
                     AND link.ts BETWEEN ? AND ?
                   ORDER BY e.ts, e.log_name, e.record_sha256
                   LIMIT ?""",
            (
                source_instance,
                *fuids,
                start_ts - DEFAULT_WINDOW_BEFORE_SECONDS,
                end_ts + DEFAULT_WINDOW_AFTER_SECONDS,
                remaining + 1,
            ),
        ).fetchall()
        if len(linked) > remaining:
            truncated = True
        rows.extend((*row, "shared_file_id") for row in linked[:remaining])
        remaining = MAX_EVIDENCE_RECORDS - len(rows)

    if remaining > 0:
        dns_rows = conn.execute(
            """SELECT e.log_name, e.record_sha256, e.context_json, e.ts
               FROM zeek_evidence_links AS answer
               JOIN zeek_evidence_links AS origin
                 ON origin.source_instance = answer.source_instance
                AND origin.log_name = answer.log_name
                AND origin.record_sha256 = answer.record_sha256
               JOIN zeek_evidence AS e
                 ON e.source_instance = answer.source_instance
                AND e.log_name = answer.log_name
                AND e.record_sha256 = answer.record_sha256
               WHERE answer.source_instance = ?
                 AND answer.link_type = 'answer_ip'
                 AND answer.link_value = ?
                 AND answer.ts BETWEEN ? AND ?
                 AND origin.link_type = 'orig_h'
                 AND origin.link_value = ?
               ORDER BY answer.ts DESC, answer.log_name, answer.record_sha256
               LIMIT ?""",
            (
                source_instance,
                responder_host,
                start_ts - DNS_CORRELATION_LOOKBACK_SECONDS,
                end_ts + DEFAULT_WINDOW_AFTER_SECONDS,
                origin_host,
                remaining + 1,
            ),
        ).fetchall()
        if len(dns_rows) > remaining:
            truncated = True
        rows.extend(
            (*row, "recent_dns_answer_for_responder")
            for row in dns_rows[:remaining]
        )
    if len(rows) >= MAX_EVIDENCE_RECORDS:
        truncated = True

    seen = set()
    evidence = []
    for log_name, digest, context_json, _ts, correlation in rows:
        identity = (str(log_name), str(digest))
        if identity in seen:
            continue
        seen.add(identity)
        parsed = json.loads(context_json)
        if not isinstance(parsed, dict):
            raise ZeekConnValidationError(
                "stored Zeek evidence context must be an object"
            )
        parsed["correlation"] = correlation
        evidence.append((_EVIDENCE_CONTEXT_KEYS[str(log_name)], parsed))
    return evidence, truncated


def _serialize_context(
    base: dict,
    evidence: list[tuple[str, dict]],
    *,
    max_bytes: int,
    already_truncated: bool,
) -> tuple[str | None, bool]:
    def encode(value: dict) -> str:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    encoded = encode(base)
    if len(encoded.encode("utf-8")) > max_bytes:
        return None, False
    truncated = already_truncated
    for group, record in evidence:
        base.setdefault(group, []).append(record)
        candidate = encode(base)
        if len(candidate.encode("utf-8")) <= max_bytes:
            encoded = candidate
            continue
        base[group].pop()
        if not base[group]:
            del base[group]
        truncated = True
    if truncated:
        base["application_evidence_truncated"] = True
        candidate = encode(base)
        if len(candidate.encode("utf-8")) <= max_bytes:
            encoded = candidate
        else:
            del base["application_evidence_truncated"]
    return encoded, truncated


def lookup_connection(
    conn: sqlite3.Connection,
    request: ZeekLookupRequest,
    source_instance: str,
    *,
    include_application: bool = False,
) -> ZeekLookupResult:
    """Correlate one exact tuple against connection intervals without guessing."""

    source_instance = _validate_safe_name(
        source_instance,
        "source_instance",
        MAX_SOURCE_INSTANCE_CHARS,
    )
    alert_epoch = _epoch_timestamp(request.alert_timestamp)
    orientations = [
        (
            request.src_ip,
            request.src_port,
            request.dest_ip,
            request.dest_port,
        ),
        (
            request.dest_ip,
            request.dest_port,
            request.src_ip,
            request.src_port,
        ),
    ]
    if orientations[0] == orientations[1]:
        orientations.pop()
    by_uid = {}
    for orig_h, orig_p, resp_h, resp_p in orientations:
        orientation_rows = conn.execute(
            """SELECT uid, ts, end_ts, orig_h, orig_p, resp_h, resp_p, proto,
                      service, duration, orig_bytes, resp_bytes, conn_state,
                      missed_bytes, orig_pkts, resp_pkts
               FROM zeek_connections INDEXED BY idx_zeek_conn_tuple_time
               WHERE source_instance = ?
                 AND proto = ?
                 AND orig_h = ?
                 AND orig_p = ?
                 AND resp_h = ?
                 AND resp_p = ?
                 AND ts <= ?
                 AND end_ts >= ?
               ORDER BY ts DESC, uid
               LIMIT ?""",
            (
                source_instance,
                request.proto,
                orig_h,
                orig_p,
                resp_h,
                resp_p,
                alert_epoch + request.window_after_seconds,
                alert_epoch - request.window_before_seconds,
                request.max_records + 1,
            ),
        ).fetchall()
        for row in orientation_rows:
            by_uid.setdefault(str(row[0]), row)
    rows = sorted(
        by_uid.values(),
        key=lambda row: (-float(row[1]), str(row[0])),
    )[: request.max_records + 1]

    if not rows:
        return ZeekLookupResult(
            status=ZeekLookupStatus.NO_MATCH,
            source_instance=source_instance,
            match_strategy="exact_tuple_interval",
        )
    if len(rows) > 1:
        return ZeekLookupResult(
            status=ZeekLookupStatus.AMBIGUOUS,
            source_instance=source_instance,
            match_strategy="exact_tuple_interval",
            candidate_count=min(len(rows), MAX_CANDIDATES),
            truncated=len(rows) > request.max_records,
        )

    context = _connection_context(rows[0], request)
    evidence = []
    evidence_truncated = False
    match_strategy = "exact_tuple_interval"
    if include_application:
        evidence, evidence_truncated = _linked_application_evidence(
            conn,
            source_instance,
            str(rows[0][0]),
            float(rows[0][1]),
            float(rows[0][2]),
            str(rows[0][3]),
            str(rows[0][5]),
        )
        match_strategy = "exact_tuple_interval_linked_evidence"
    context_json, serialized_truncated = _serialize_context(
        context,
        evidence,
        max_bytes=request.max_context_bytes,
        already_truncated=evidence_truncated,
    )
    if context_json is None:
        return ZeekLookupResult(
            status=ZeekLookupStatus.INVALID_RESPONSE,
            source_instance=source_instance,
            match_strategy=match_strategy,
        )
    return ZeekLookupResult(
        status=ZeekLookupStatus.MATCHED,
        context_json=context_json,
        source_instance=source_instance,
        match_strategy=match_strategy,
        record_count=1,
        candidate_count=1,
        truncated=serialized_truncated,
    )


def prune_index(
    conn: sqlite3.Connection,
    cutoff: str | datetime | int | float,
    *,
    batch_size: int = DEFAULT_PRUNE_BATCH_SIZE,
    max_rows: int = DEFAULT_PRUNE_MAX_ROWS,
) -> ZeekPruneResult:
    """Bound deletion work for expired connections, evidence, and failures."""

    if type(batch_size) is not int or not 1 <= batch_size <= MAX_PRUNE_BATCH_SIZE:
        raise ValueError(
            f"batch_size must be between 1 and {MAX_PRUNE_BATCH_SIZE}"
        )
    if type(max_rows) is not int or not 1 <= max_rows <= MAX_PRUNE_ROWS:
        raise ValueError(f"max_rows must be between 1 and {MAX_PRUNE_ROWS}")
    cutoff_epoch = _epoch_timestamp(cutoff)

    totals = {"connections": 0, "evidence": 0, "failures": 0}
    targets = ("connections", "evidence", "failures")

    def delete_batch(key: str, limit: int) -> int:
        try:
            conn.execute("BEGIN IMMEDIATE")
            if key == "connections":
                conn.execute(
                    """DELETE FROM zeek_connections
                       WHERE (source_instance, uid) IN (
                           SELECT source_instance, uid
                           FROM zeek_connections
                           WHERE indexed_at < ?
                           ORDER BY indexed_at, source_instance, uid
                           LIMIT ?
                       )""",
                    (cutoff_epoch, limit),
                )
            elif key == "evidence":
                selection = """SELECT source_instance, log_name, record_sha256
                               FROM zeek_evidence
                               WHERE indexed_at < ?
                               ORDER BY indexed_at, source_instance,
                                        log_name, record_sha256
                               LIMIT ?"""
                conn.execute(
                    f"""DELETE FROM zeek_evidence_links
                        WHERE (source_instance, log_name, record_sha256) IN (
                            {selection}
                        )""",
                    (cutoff_epoch, limit),
                )
                conn.execute(
                    f"""DELETE FROM zeek_evidence
                        WHERE (source_instance, log_name, record_sha256) IN (
                            {selection}
                        )""",
                    (cutoff_epoch, limit),
                )
            else:
                conn.execute(
                    """DELETE FROM zeek_ingest_failures
                       WHERE id IN (
                           SELECT id
                           FROM zeek_ingest_failures
                           WHERE recorded_at < ?
                           ORDER BY recorded_at, id
                           LIMIT ?
                       )""",
                    (cutoff_epoch, limit),
                )
            deleted = int(conn.execute("SELECT changes()").fetchone()[0])
            conn.commit()
            return deleted
        except Exception:
            conn.rollback()
            raise

    # Reserve a share for every retained data class so no one traffic shape can
    # indefinitely starve another. Reuse sparse-table capacity afterward.
    base_quota, remainder = divmod(max_rows, len(targets))
    quotas = {
        key: base_quota + int(index < remainder)
        for index, key in enumerate(targets)
    }
    for key in targets:
        remaining_quota = quotas[key]
        while remaining_quota > 0:
            current_batch = min(batch_size, remaining_quota)
            deleted = delete_batch(key, current_batch)
            totals[key] += deleted
            remaining_quota -= deleted
            if deleted < current_batch:
                break

    total_deleted = sum(totals.values())
    for key in targets:
        while total_deleted < max_rows:
            current_batch = min(batch_size, max_rows - total_deleted)
            deleted = delete_batch(key, current_batch)
            totals[key] += deleted
            total_deleted += deleted
            if deleted < current_batch:
                break

    return ZeekPruneResult(
        connections=totals["connections"],
        evidence=totals["evidence"],
        failures=totals["failures"],
    )
