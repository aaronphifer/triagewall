"""Shared dashboard API query helpers used by v1 and legacy aliases."""

from __future__ import annotations

import base64
import ipaddress
import json
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Callable, Iterator

from fastapi import HTTPException

from triagewall.dashboard.api.pseudonym import (
    IpPseudonymConfigError,
    pseudonymize_ip,
)
from triagewall.dashboard.stats import get_dashboard_stats
from triagewall.storage import get_storage_metrics
from triagewall.time_utils import (
    format_utc_timestamp,
    parse_utc_timestamp,
    utc_now,
    utc_now_iso,
)

STATS_TTL = 30.0
TIMELINE_TTL = 60.0
SPC_TTL = 30.0
MAX_TIMELINE_HOURS = 168
MAX_VERDICT_LIMIT = 500
DEFAULT_VERDICT_LIMIT = 100

# Bounds on free-form input. These exist so one request cannot make the
# database or the application do unbounded work: a long LIKE pattern is scanned
# against every candidate row, and an oversized cursor or note is stored and
# echoed back. The values are generous for real use and documented in
# docs/api.md.
MAX_SIGNATURE_SEARCH_LENGTH = 200
MAX_CURSOR_LENGTH = 512
MAX_FEEDBACK_NOTES_LENGTH = 2_000

# Queue text/IP/asset search is deliberately scoped to the newest retained
# events. A leading-wildcard signature match cannot use a conventional index;
# letting a zero-match term traverse a multi-million-row table made an
# interactive request run for more than 16 minutes on the production-shaped
# database. Candidate ids come from the covering processed_at index, then every
# documented predicate is evaluated inside this fixed window. The API reports
# the window and whether older rows were excluded.
MAX_QUEUE_SEARCH_CANDIDATE_ROWS = 10_000

# The candidate bound is the primary work limit. The progress handler is a
# second, wall-clock fail-safe for unexpectedly slow storage or a future query
# plan regression. It is installed only around queue-search SQL and is always
# removed before the connection returns to its caller.
QUEUE_SEARCH_TIMEOUT_SECONDS = 3.0
QUEUE_SEARCH_PROGRESS_OPCODES = 1_000
SQLITE_MAX_INTEGER = (1 << 63) - 1


@dataclass(frozen=True)
class QueueSearchWindow:
    """Complete immutable state for one paged queue-search candidate set."""

    max_event_id: int
    ceiling_processed_at: str | None
    ceiling_event_id: int | None
    floor_processed_at: str | None
    floor_event_id: int | None
    candidate_limit: int
    candidates_in_scope: int
    truncated: bool

    def scope(self) -> dict[str, Any]:
        return {
            "candidate_limit": self.candidate_limit,
            "candidates_in_scope": self.candidates_in_scope,
            "truncated": self.truncated,
        }

# Investigation bounds.
#
# The window is capped at 24 hours rather than the 168 the timeline allows.
# src_ip and dest_ip are not indexed, so address correlation cannot be an index
# seek; it is a bounded scan, and a wider window would widen that scan without
# a production-shaped benchmark proving a query-time budget is still met.
#
# MAX_RELATED_CANDIDATE_ROWS is the second half of that bound. Every correlation
# view -- recurrence, same-rule activity and address matches -- examines at most
# this many of the newest rows in the window, selected through
# idx_triage_processed. Anything older inside the window is not examined, and
# the response says so via candidate_limit/truncated rather than implying the
# result is complete correlation across the whole window.
DEFAULT_INVESTIGATION_WINDOW_HOURS = 24
MAX_INVESTIGATION_WINDOW_HOURS = 24
MAX_RELATED_ALERTS = 10
MAX_RELATED_CANDIDATE_ROWS = 2_000

_stats_cache: dict[str, Any] = {"data": None, "ts": 0.0, "generated_at": None}
_timeline_cache: dict[str, Any] = {"data": None, "ts": 0.0, "key": None}
_spc_cache: dict[str, Any] = {"data": None, "ts": 0.0}


def reset_caches() -> None:
    """Clear TTL caches (tests)."""
    _stats_cache.update(data=None, ts=0.0, generated_at=None)
    _timeline_cache.update(data=None, ts=0.0, key=None)
    _spc_cache.update(data=None, ts=0.0)


def hash_ip(ip: str | None, secret: bytes | None = None) -> str | None:
    """Pseudonymize one IP address for API output.

    Keyed with HMAC-SHA256: an unsalted digest of an IP address is reversible
    by exhaustive search, so it never provided the redaction it implied. The
    secret is validated at startup, which is why it is required here.
    """
    if not ip:
        return ip
    if not secret:
        raise IpPseudonymConfigError(
            "IP redaction is enabled but no pseudonymization secret is loaded"
        )
    return pseudonymize_ip(ip, secret)


def encode_cursor(
    processed_at: str | None,
    event_id: int,
    *,
    search_window: QueueSearchWindow | None = None,
) -> str:
    cursor_payload: dict[str, Any] = {"p": processed_at, "i": event_id}
    if search_window is not None:
        cursor_payload.update(_search_window_payload(search_window))
    payload = json.dumps(cursor_payload, separators=(",", ":"))
    return base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")


def _search_window_payload(search_window: QueueSearchWindow) -> dict[str, Any]:
    return {
        "s": search_window.max_event_id,
        "c": {
            "p": search_window.ceiling_processed_at,
            "i": search_window.ceiling_event_id,
        },
        "f": {
            "p": search_window.floor_processed_at,
            "i": search_window.floor_event_id,
        },
        "l": search_window.candidate_limit,
        "n": search_window.candidates_in_scope,
        "t": search_window.truncated,
    }


def encode_search_window(search_window: QueueSearchWindow) -> str:
    """Encode queue-search identity independently from page position."""
    payload = {"v": 2, **_search_window_payload(search_window)}
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _cursor_integer(
    value: Any,
    *,
    minimum: int = 1,
    maximum: int = SQLITE_MAX_INTEGER,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("invalid cursor integer")
    if value < minimum or value > maximum:
        raise ValueError("cursor integer outside SQLite range")
    return value


def _decode_opaque_payload(value: str) -> dict[str, Any]:
    padding = "=" * (-len(value) % 4)
    raw = base64.urlsafe_b64decode(value + padding)
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("invalid opaque payload")
    return payload


def _search_window_from_payload(payload: dict[str, Any]) -> QueueSearchWindow:
    max_event_id = _cursor_integer(payload["s"], minimum=0)
    ceiling = payload["c"]
    if not isinstance(ceiling, dict) or set(ceiling) != {"p", "i"}:
        raise ValueError("invalid search ceiling")
    ceiling_processed_at = ceiling["p"]
    if ceiling_processed_at is not None and not isinstance(
        ceiling_processed_at, str
    ):
        raise ValueError("invalid search ceiling timestamp")
    raw_ceiling_event_id = ceiling["i"]
    ceiling_event_id = None
    if raw_ceiling_event_id is not None:
        ceiling_event_id = _cursor_integer(
            raw_ceiling_event_id,
            maximum=max_event_id,
        )
    floor = payload["f"]
    if not isinstance(floor, dict) or set(floor) != {"p", "i"}:
        raise ValueError("invalid search floor")
    floor_processed_at = floor["p"]
    if floor_processed_at is not None and not isinstance(floor_processed_at, str):
        raise ValueError("invalid search floor timestamp")
    raw_floor_event_id = floor["i"]
    floor_event_id = None
    if raw_floor_event_id is not None:
        floor_event_id = _cursor_integer(
            raw_floor_event_id,
            maximum=max_event_id,
        )
    candidate_limit = _cursor_integer(
        payload["l"],
        maximum=MAX_QUEUE_SEARCH_CANDIDATE_ROWS,
    )
    candidates_in_scope = _cursor_integer(
        payload["n"],
        minimum=0,
        maximum=candidate_limit,
    )
    truncated = payload["t"]
    if not isinstance(truncated, bool):
        raise ValueError("invalid search truncation state")
    if truncated and candidates_in_scope != candidate_limit:
        raise ValueError("invalid truncated search scope")
    empty = candidates_in_scope == 0
    if (ceiling_event_id is None) != empty or (floor_event_id is None) != empty:
        raise ValueError("search boundaries do not match candidate scope")
    if empty:
        if ceiling_processed_at is not None or floor_processed_at is not None:
            raise ValueError("empty search window has timestamp boundaries")
    elif ceiling_processed_at is None:
        if floor_processed_at is not None or ceiling_event_id < floor_event_id:
            raise ValueError("invalid null-timestamp search boundaries")
    elif floor_processed_at is not None and (
        ceiling_processed_at,
        ceiling_event_id,
    ) < (
        floor_processed_at,
        floor_event_id,
    ):
        raise ValueError("search ceiling precedes floor")
    return QueueSearchWindow(
        max_event_id=max_event_id,
        ceiling_processed_at=ceiling_processed_at,
        ceiling_event_id=ceiling_event_id,
        floor_processed_at=floor_processed_at,
        floor_event_id=floor_event_id,
        candidate_limit=candidate_limit,
        candidates_in_scope=candidates_in_scope,
        truncated=truncated,
    )


def decode_search_window(value: str) -> QueueSearchWindow:
    """Decode and validate search identity supplied to investigation."""
    try:
        payload = _decode_opaque_payload(value)
        if (
            set(payload) != {"v", "s", "c", "f", "l", "n", "t"}
            or type(payload["v"]) is not int
            or payload["v"] != 2
        ):
            raise ValueError("invalid search window payload")
        return _search_window_from_payload(payload)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, OSError) as exc:
        raise HTTPException(status_code=422, detail="invalid search window") from exc


def decode_cursor(
    cursor: str,
) -> tuple[str | None, int, QueueSearchWindow | None]:
    try:
        payload = _decode_opaque_payload(cursor)
        event_id = _cursor_integer(payload["i"])
        processed_at = payload.get("p")
        if processed_at is not None and not isinstance(processed_at, str):
            raise ValueError("invalid processed_at")
        search_keys = {"s", "c", "f", "l", "n", "t"}
        present_search_keys = search_keys.intersection(payload)
        search_window = None
        if present_search_keys:
            if present_search_keys != search_keys:
                raise ValueError("incomplete search boundary")
            search_window = _search_window_from_payload(payload)
            if event_id > search_window.max_event_id:
                raise ValueError("cursor lies beyond search watermark")
        return processed_at, event_id, search_window
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, OSError) as exc:
        raise HTTPException(status_code=422, detail="invalid cursor") from exc


def build_verdict_filters(
    verdict: str | None,
    signature: str | None,
    model: str | None,
    source: str | None = None,
    review: str | None = None,
    *,
    include_private_search: bool = True,
) -> tuple[list[str], list[Any]]:
    where: list[str] = []
    params: list[Any] = []
    if verdict in ("real", "false_positive", "uncertain"):
        where.append("events.verdict = ?")
        params.append(verdict)
    term = _normalized_queue_search(signature)
    if term:
        # ``signature`` is retained as the public parameter name for existing
        # clients and bookmarked queue URLs, but the workbench search now also
        # resolves exact source/destination addresses and immutable asset
        # hostnames. Private fields participate only when the response policy
        # would reveal them; demo and IP-redacted callers must not gain a
        # membership oracle through an otherwise empty result set.
        clauses = ["events.signature LIKE ?"]
        search_params: list[Any] = [f"%{term}%"]
        normalized_ip = None
        if include_private_search:
            try:
                normalized_ip = str(ipaddress.ip_address(term))
            except ValueError:
                normalized_ip = None
            if normalized_ip is not None:
                clauses.extend(("events.src_ip = ?", "events.dest_ip = ?"))
                search_params.extend((normalized_ip, normalized_ip))
        if include_private_search:
            # Snapshot JSON is immutable and validated when written, but
            # json_valid keeps a damaged historical row from aborting the
            # whole queue. Evaluate the snapshots already referenced by each
            # candidate event; independent snapshot subqueries would scan the
            # complete retained snapshot history for an absent term.
            clauses.extend(
                (
                    """CASE WHEN json_valid(src_snapshot.asset_json)
                            THEN json_extract(
                                src_snapshot.asset_json, '$.hostname'
                            )
                       END LIKE ?""",
                    """CASE WHEN json_valid(dest_snapshot.asset_json)
                            THEN json_extract(
                                dest_snapshot.asset_json, '$.hostname'
                            )
                       END LIKE ?""",
                )
            )
            hostname_pattern = f"%{term}%"
            search_params.extend((hostname_pattern, hostname_pattern))
        where.append("(" + " OR ".join(clauses) + ")")
        params.extend(search_params)
    if model == "llm":
        where.append("events.model_used != 'prefilter'")
    elif model == "prefilter":
        where.append("events.model_used = 'prefilter'")
    if source == "suricata":
        # Rows created before source provenance was introduced are Suricata
        # rows: Wazuh support and sensor_event_context shipped together.
        where.append("(sensor.source_type = 'suricata' OR sensor.source_type IS NULL)")
    elif source == "wazuh":
        where.append("sensor.source_type = 'wazuh'")
    if review == "unreviewed":
        where.append("events.human_verdict IS NULL")
    elif review == "agreed":
        where.append("events.human_verdict IS NOT NULL AND events.agreed = 1")
    elif review == "corrected":
        where.append("events.human_verdict IS NOT NULL AND events.agreed = 0")
    return where, params


def _normalized_queue_search(signature: str | None) -> str:
    """Return the effective queue term; whitespace alone means no search."""
    return signature.strip() if signature else ""


_QUEUE_SEARCH_ORDER = (
    "search_events.processed_at DESC NULLS LAST, search_events.id DESC"
)


def _queue_search_max_id(conn: sqlite3.Connection) -> int:
    """Return the insertion watermark that freezes one search's candidates."""
    row = conn.execute("SELECT MAX(id) AS max_id FROM triage_events").fetchone()
    value = row["max_id"] if isinstance(row, sqlite3.Row) else row[0]
    return int(value) if value is not None else 0


def _new_queue_search_window(
    conn: sqlite3.Connection,
) -> QueueSearchWindow:
    """Capture one immutable, retention-safe queue-search candidate window."""
    max_event_id = _queue_search_max_id(conn)
    candidate_limit = MAX_QUEUE_SEARCH_CANDIDATE_ROWS
    rows = conn.execute(
        f"""SELECT search_events.processed_at, search_events.id
            FROM triage_events AS search_events INDEXED BY idx_triage_processed
            WHERE search_events.id <= ?
            ORDER BY {_QUEUE_SEARCH_ORDER}
            LIMIT ?""",
        (max_event_id, candidate_limit + 1),
    ).fetchall()
    truncated = len(rows) > candidate_limit
    candidates = rows[:candidate_limit]
    ceiling_processed_at = None
    ceiling_event_id = None
    floor_processed_at = None
    floor_event_id = None
    if candidates:
        ceiling = candidates[0]
        ceiling_processed_at = ceiling["processed_at"] if isinstance(
            ceiling, sqlite3.Row
        ) else ceiling[0]
        ceiling_event_id = int(
            ceiling["id"] if isinstance(ceiling, sqlite3.Row) else ceiling[1]
        )
        floor = candidates[-1]
        floor_processed_at = floor["processed_at"] if isinstance(
            floor, sqlite3.Row
        ) else floor[0]
        floor_event_id = int(
            floor["id"] if isinstance(floor, sqlite3.Row) else floor[1]
        )
    return QueueSearchWindow(
        max_event_id=max_event_id,
        ceiling_processed_at=ceiling_processed_at,
        ceiling_event_id=ceiling_event_id,
        floor_processed_at=floor_processed_at,
        floor_event_id=floor_event_id,
        candidate_limit=candidate_limit,
        candidates_in_scope=len(candidates),
        truncated=truncated,
    )


def _queue_search_candidate_query(
    window: QueueSearchWindow,
) -> tuple[str, list[Any]]:
    """Build the candidate-id query for one captured search window."""
    clauses = ["search_events.id <= ?"]
    params: list[Any] = [window.max_event_id]
    if window.ceiling_event_id is None:
        clauses.append("0")
    elif window.ceiling_processed_at is None:
        clauses.extend(
            (
                "search_events.processed_at IS NULL",
                "search_events.id <= ?",
                "search_events.id >= ?",
            )
        )
        params.extend((window.ceiling_event_id, window.floor_event_id))
    elif window.floor_processed_at is None:
        clauses.append(
            """(
                (
                    search_events.processed_at IS NOT NULL
                    AND (search_events.processed_at, search_events.id) <= (?, ?)
                )
                OR (
                    search_events.processed_at IS NULL
                    AND search_events.id >= ?
                )
            )"""
        )
        params.extend(
            (
                window.ceiling_processed_at,
                window.ceiling_event_id,
                window.floor_event_id,
            )
        )
    else:
        clauses.extend(
            (
                "(search_events.processed_at, search_events.id) <= (?, ?)",
                "(search_events.processed_at, search_events.id) >= (?, ?)",
            )
        )
        params.extend(
            (
                window.ceiling_processed_at,
                window.ceiling_event_id,
                window.floor_processed_at,
                window.floor_event_id,
            )
        )
    params.append(window.candidate_limit)
    return (
        f"""SELECT search_events.id
            FROM triage_events AS search_events INDEXED BY idx_triage_processed
            WHERE {" AND ".join(clauses)}
            ORDER BY {_QUEUE_SEARCH_ORDER}
            LIMIT ?""",
        params,
    )


def _apply_queue_search_bound(
    where: list[str],
    params: list[Any],
    *,
    window: QueueSearchWindow,
) -> None:
    """Restrict filters to one fixed newest-event candidate window."""
    candidate_sql, candidate_params = _queue_search_candidate_query(window)
    where.insert(0, f"events.id IN ({candidate_sql})")
    params[0:0] = candidate_params


@contextmanager
def _queue_search_budget(
    conn: sqlite3.Connection,
    *,
    enabled: bool,
) -> Iterator[None]:
    """Interrupt queue-search SQL that exceeds its wall-clock budget."""
    if not enabled:
        yield
        return

    deadline = time.monotonic() + QUEUE_SEARCH_TIMEOUT_SECONDS

    def over_budget() -> int:
        return int(time.monotonic() >= deadline)

    conn.set_progress_handler(
        over_budget,
        max(1, int(QUEUE_SEARCH_PROGRESS_OPCODES)),
    )
    try:
        yield
    except sqlite3.OperationalError as exc:
        if "interrupted" not in str(exc).lower():
            raise
        raise HTTPException(
            status_code=503,
            detail=(
                "search exceeded its query-time budget; "
                "narrow the filters and retry"
            ),
        ) from exc
    finally:
        conn.set_progress_handler(None, 0)


_VERDICT_SELECT = """
SELECT events.id, events.timestamp, events.src_ip, events.src_port,
       events.dest_ip, events.dest_port, events.proto,
       events.signature_id, events.signature, events.category,
       events.severity, events.verdict, events.confidence,
       events.reasoning, events.model_used, events.processed_at,
       events.human_verdict, events.human_notes, events.agreed,
       events.reviewed_at,
       src_snapshot.asset_json AS src_asset_json,
       dest_snapshot.asset_json AS dest_asset_json,
       sensor.source_type AS sensor_source,
       sensor.source_instance AS sensor_instance,
       sensor.source_event_id AS sensor_event_id,
       sensor.agent_id AS sensor_agent_id,
       sensor.agent_name AS sensor_agent_name,
       zeek.eligibility_reason AS zeek_eligibility_reason,
       zeek.lookup_status AS zeek_lookup_status,
       zeek.source_instance AS zeek_source_instance,
       zeek.match_strategy AS zeek_match_strategy,
       zeek.record_count AS zeek_record_count,
       zeek.candidate_count AS zeek_candidate_count,
       zeek.truncated AS zeek_truncated,
       zeek.recorded_at AS zeek_recorded_at
FROM triage_events AS events
LEFT JOIN asset_snapshots AS src_snapshot
  ON src_snapshot.id = events.src_asset_snapshot_id
LEFT JOIN asset_snapshots AS dest_snapshot
  ON dest_snapshot.id = events.dest_asset_snapshot_id
LEFT JOIN sensor_event_context AS sensor
  ON sensor.triage_event_id = events.id
LEFT JOIN zeek_alert_enrichment AS zeek
  ON zeek.triage_event_id = events.id
"""

_VERDICT_DETAIL_SELECT = _VERDICT_SELECT.replace(
    "events.reasoning, events.model_used, events.processed_at,",
    "events.reasoning, events.raw_alert, events.model_used, events.processed_at,",
).replace(
    "zeek.recorded_at AS zeek_recorded_at",
    "zeek.recorded_at AS zeek_recorded_at, zeek.context_json AS zeek_context_json",
)


def fetch_verdicts(
    conn: sqlite3.Connection,
    *,
    verdict: str | None = None,
    signature: str | None = None,
    model: str | None = None,
    source: str | None = None,
    review: str | None = None,
    include_private_search: bool = True,
    bounded_search: bool = True,
    limit: int = DEFAULT_VERDICT_LIMIT,
    cursor: str | None = None,
) -> tuple[list[sqlite3.Row], str | None, dict[str, Any] | None, str | None]:
    """Return rows, pagination, bounded-search scope, and search identity."""
    if limit < 1 or limit > MAX_VERDICT_LIMIT:
        raise HTTPException(
            status_code=422,
            detail=f"limit must be between 1 and {MAX_VERDICT_LIMIT}",
        )
    where, params = build_verdict_filters(
        verdict,
        signature,
        model,
        source,
        review,
        include_private_search=include_private_search,
    )
    search_enabled = bool(_normalized_queue_search(signature)) and bounded_search
    cursor_position = None
    cursor_search_window = None
    if cursor:
        processed_at, event_id, cursor_search_window = decode_cursor(cursor)
        cursor_position = (processed_at, event_id)
    search_window = None
    if search_enabled:
        if cursor_position is not None:
            if cursor_search_window is None:
                raise HTTPException(status_code=422, detail="invalid search cursor")
            search_window = cursor_search_window
        else:
            search_window = _new_queue_search_window(conn)
        _apply_queue_search_bound(
            where,
            params,
            window=search_window,
        )
    if cursor_position is not None:
        processed_at, event_id = cursor_position
        where.append(
            """(
                (
                    ? IS NOT NULL
                    AND (
                        events.processed_at < ?
                        OR (events.processed_at = ? AND events.id < ?)
                        OR events.processed_at IS NULL
                    )
                )
                OR (
                    ? IS NULL
                    AND events.processed_at IS NULL
                    AND events.id < ?
                )
            )"""
        )
        params.extend(
            [
                processed_at,
                processed_at,
                processed_at,
                event_id,
                processed_at,
                event_id,
            ]
        )
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    search_scope = None
    with _queue_search_budget(conn, enabled=search_enabled):
        if search_enabled:
            search_scope = search_window.scope()
        rows = conn.execute(
            f"""{_VERDICT_SELECT}
                {where_sql}
                ORDER BY events.processed_at DESC NULLS LAST, events.id DESC
                LIMIT ?""",
            params + [limit + 1],
        ).fetchall()
    next_cursor = None
    if len(rows) > limit:
        rows = rows[:limit]
        last = rows[-1]
        next_cursor = encode_cursor(
            last["processed_at"],
            int(last["id"]),
            search_window=search_window,
        )
    elif rows:
        # Exact page with no more rows.
        next_cursor = None
    encoded_search_window = (
        encode_search_window(search_window) if search_window is not None else None
    )
    return list(rows), next_cursor, search_scope, encoded_search_window


def fetch_verdict(conn: sqlite3.Connection, event_id: int) -> sqlite3.Row | None:
    """Return one complete decision, including its original sensor record."""
    return conn.execute(
        f"""{_VERDICT_DETAIL_SELECT}
            WHERE events.id = ?""",
        (event_id,),
    ).fetchone()


# --- Investigation context -------------------------------------------------
#
# Provenance is normalized the same way build_verdict_filters treats it: rows
# written before sensor_event_context existed are Suricata rows. Qualifying by
# source type is not cosmetic. Suricata stores its SID in signature_id while
# Wazuh stores rule.id there, so an unqualified group would silently merge two
# unrelated rules that happen to share an integer.
_SOURCE_TYPE_EXPR = "COALESCE(sensor.source_type, 'suricata')"

# The newest candidates in the window, ordered by the indexed column so
# idx_triage_processed drives the range. All correlation happens over this one
# bounded set; no investigation query scans a high-volume 24-hour window end to
# end or builds a new production index during deployment.
_RELATED_CANDIDATES_SQL = f"""
SELECT events.id, events.timestamp, events.processed_at,
       events.signature_id, events.signature, events.verdict,
       events.confidence, events.src_ip, events.dest_ip,
       {_SOURCE_TYPE_EXPR} AS source_type
FROM triage_events AS events
LEFT JOIN sensor_event_context AS sensor
  ON sensor.triage_event_id = events.id
WHERE events.processed_at IS NOT NULL
  AND events.processed_at >= ?
ORDER BY events.processed_at DESC, events.id DESC
LIMIT ?
"""

_NEIGHBOR_SELECT = f"""
SELECT events.id, events.signature, events.verdict, events.processed_at,
       {_SOURCE_TYPE_EXPR} AS source_type
FROM triage_events AS events
LEFT JOIN asset_snapshots AS src_snapshot
  ON src_snapshot.id = events.src_asset_snapshot_id
LEFT JOIN asset_snapshots AS dest_snapshot
  ON dest_snapshot.id = events.dest_asset_snapshot_id
LEFT JOIN sensor_event_context AS sensor
  ON sensor.triage_event_id = events.id
"""

RELATIONSHIP_LABELS = {
    "same_rule": (
        "Same rule",
        "Same source type and signature id as this alert among the examined "
        "candidates. The scope below states whether the whole window was read.",
    ),
    "same_source_ip": (
        "Same source address",
        "Recorded src_ip is identical to this alert's src_ip. Shared "
        "addressing only; it does not establish a shared cause.",
    ),
    "same_destination_ip": (
        "Same destination address",
        "Recorded dest_ip is identical to this alert's dest_ip. Shared "
        "addressing only; it does not establish a shared cause.",
    ),
}


def _apply_ip_policy(
    value: str | None,
    *,
    mode: str,
    mask_ip_fn: Callable,
    redact_ips: bool,
    ip_secret: bytes | None,
) -> str | None:
    """Apply the same address-disclosure policy the verdict rows use."""
    if not value:
        return value
    if mode == "demo":
        return mask_ip_fn(value)
    if redact_ips:
        return hash_ip(value, ip_secret)
    return value


def _normalize_timestamp(value: str | None) -> str | None:
    """Re-canonicalize a stored timestamp, matching app.row_to_dict."""
    if not value:
        return None
    try:
        return format_utc_timestamp(value)
    except (TypeError, ValueError):
        return None


def _related_row_to_dict(
    row: sqlite3.Row,
    relationship: str,
    *,
    mode: str,
    mask_ip_fn: Callable,
    redact_ips: bool,
    ip_secret: bytes | None,
) -> dict[str, Any]:
    return {
        "id": int(row["id"]),
        "timestamp": _normalize_timestamp(row["timestamp"]),
        "processed_at": _normalize_timestamp(row["processed_at"]),
        "signature_id": row["signature_id"],
        "signature": row["signature"],
        "verdict": row["verdict"],
        "confidence": row["confidence"],
        "src_ip": _apply_ip_policy(
            row["src_ip"],
            mode=mode,
            mask_ip_fn=mask_ip_fn,
            redact_ips=redact_ips,
            ip_secret=ip_secret,
        ),
        "dest_ip": _apply_ip_policy(
            row["dest_ip"],
            mode=mode,
            mask_ip_fn=mask_ip_fn,
            redact_ips=redact_ips,
            ip_secret=ip_secret,
        ),
        "source_type": row["source_type"],
        "relationship": relationship,
    }


def _neighbor_row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return {
        "id": int(row["id"]),
        "signature": row["signature"],
        "verdict": row["verdict"],
        "processed_at": _normalize_timestamp(row["processed_at"]),
        "source_type": row["source_type"],
    }


def _fetch_neighbors(
    conn: sqlite3.Connection,
    *,
    anchor_id: int,
    anchor_processed_at: str | None,
    where: list[str],
    params: list[Any],
) -> tuple[sqlite3.Row | None, sqlite3.Row | None]:
    """Return the (previous, next) rows around an anchor in queue order.

    Queue order is ``processed_at DESC NULLS LAST, id DESC``. "Next" is the row
    immediately after the anchor in that order (older); "previous" is the row
    immediately before it (newer). Filters are the caller's, so navigation stays
    inside whatever queue the analyst was looking at.
    """

    def run(extra_clauses: list[str], extra_params: list[Any], order: str):
        clauses = where + extra_clauses
        where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        return conn.execute(
            f"""{_NEIGHBOR_SELECT}
                {where_sql}
                ORDER BY {order}
                LIMIT 1""",
            params + extra_params,
        ).fetchone()

    if anchor_processed_at is None:
        # Unprocessed rows sort last, ordered by descending id.
        next_row = run(
            ["events.processed_at IS NULL", "events.id < ?"],
            [anchor_id],
            "events.id DESC",
        )
        previous_row = run(
            ["events.processed_at IS NULL", "events.id > ?"],
            [anchor_id],
            "events.id ASC",
        )
        if previous_row is None:
            # Nothing unprocessed above it, so the neighbour is the oldest
            # processed row.
            previous_row = run(
                ["events.processed_at IS NOT NULL"],
                [],
                "events.processed_at ASC, events.id ASC",
            )
        return previous_row, next_row

    # Keep the timestamp tie and the adjacent timestamp as separate seeks.
    # Combining them with OR makes SQLite walk and order every row on the
    # newer side of an old alert before LIMIT 1 can apply. That was more than
    # five seconds on a production database even though each seek is instant.
    next_row = run(
        ["events.processed_at = ?", "events.id < ?"],
        [anchor_processed_at, anchor_id],
        "events.id DESC",
    )
    if next_row is None:
        next_row = run(
            ["events.processed_at < ?"],
            [anchor_processed_at],
            "events.processed_at DESC, events.id DESC",
        )
    if next_row is None:
        next_row = run(
            ["events.processed_at IS NULL"],
            [],
            "events.id DESC",
        )

    previous_row = run(
        ["events.processed_at = ?", "events.id > ?"],
        [anchor_processed_at, anchor_id],
        "events.id ASC",
    )
    if previous_row is None:
        previous_row = run(
            ["events.processed_at > ?"],
            [anchor_processed_at],
            "events.processed_at ASC, events.id ASC",
        )
    return previous_row, next_row


def fetch_investigation(
    conn: sqlite3.Connection,
    event_id: int,
    *,
    hours: int = DEFAULT_INVESTIGATION_WINDOW_HOURS,
    mode: str = "local",
    mask_ip_fn: Callable = lambda value: value,
    redact_ips: bool = False,
    ip_secret: bytes | None = None,
    verdict: str | None = None,
    signature: str | None = None,
    model: str | None = None,
    source: str | None = None,
    review: str | None = None,
    include_private_search: bool = True,
    search_window: QueueSearchWindow | None = None,
) -> dict[str, Any] | None:
    """Return bounded recurrence, related activity and queue neighbours.

    Returns ``None`` when the anchor event does not exist, so the caller can
    answer 404 the same way the detail route does.
    """
    if hours < 1 or hours > MAX_INVESTIGATION_WINDOW_HOURS:
        raise HTTPException(
            status_code=422,
            detail=f"hours must be between 1 and {MAX_INVESTIGATION_WINDOW_HOURS}",
        )

    anchor = conn.execute(
        f"""SELECT events.id, events.processed_at, events.signature_id,
                   events.src_ip, events.dest_ip,
                   {_SOURCE_TYPE_EXPR} AS source_type
            FROM triage_events AS events
            LEFT JOIN sensor_event_context AS sensor
              ON sensor.triage_event_id = events.id
            WHERE events.id = ?""",
        (event_id,),
    ).fetchone()
    if anchor is None:
        return None

    window_start = format_utc_timestamp(utc_now() - timedelta(hours=hours))
    source_type = anchor["source_type"]
    signature_id = anchor["signature_id"]

    ip_policy = {
        "mode": mode,
        "mask_ip_fn": mask_ip_fn,
        "redact_ips": redact_ips,
        "ip_secret": ip_secret,
    }

    # Fetch one bounded candidate set for every correlation view. Over-fetch by
    # one row: exactly reaching the budget does not prove that anything was
    # omitted, while the extra row does.
    candidate_limit = MAX_RELATED_CANDIDATE_ROWS
    candidates: list[sqlite3.Row] = []
    candidates_truncated = False
    if signature_id is not None or anchor["src_ip"] or anchor["dest_ip"]:
        candidates = conn.execute(
            _RELATED_CANDIDATES_SQL,
            (window_start, candidate_limit + 1),
        ).fetchall()
        candidates_truncated = len(candidates) > candidate_limit
        if candidates_truncated:
            candidates = candidates[:candidate_limit]

    # Recurrence. A row without a signature_id has no group to belong to;
    # correlating on NULL would join every other signature-less row. Counts are
    # exact only when the candidate query proves it exhausted the whole window.
    if signature_id is None:
        recurrence = {
            "available": False,
            "signature_id": None,
            "source_type": source_type,
            "occurrences": 0,
            "first_seen": None,
            "last_seen": None,
            "real_count": 0,
            "false_positive_count": 0,
            "uncertain_count": 0,
            "unclassified_count": 0,
            "exact": False,
            "truncated": False,
            "candidate_limit": None,
            "candidates_examined": 0,
        }
    else:
        recurrence_rows = [
            candidate
            for candidate in candidates
            if candidate["signature_id"] == signature_id
            and candidate["source_type"] == source_type
        ]
        processed_values = [
            candidate["processed_at"]
            for candidate in recurrence_rows
            if candidate["processed_at"]
        ]
        recurrence = {
            "available": True,
            "signature_id": int(signature_id),
            "source_type": source_type,
            "occurrences": len(recurrence_rows),
            "first_seen": _normalize_timestamp(min(processed_values, default=None)),
            "last_seen": _normalize_timestamp(max(processed_values, default=None)),
            "real_count": sum(row["verdict"] == "real" for row in recurrence_rows),
            "false_positive_count": sum(
                row["verdict"] == "false_positive" for row in recurrence_rows
            ),
            "uncertain_count": sum(
                row["verdict"] == "uncertain" for row in recurrence_rows
            ),
            "unclassified_count": sum(
                row["verdict"] is None for row in recurrence_rows
            ),
            "exact": not candidates_truncated,
            "truncated": candidates_truncated,
            "candidate_limit": candidate_limit,
            "candidates_examined": len(candidates),
        }

    groups: list[dict[str, Any]] = []

    # Same rule uses the same bounded candidates as recurrence. This keeps one
    # frequent SID from monopolizing the dashboard and gives both panels the
    # same honest completeness boundary.
    rule_alerts: list[dict[str, Any]] = []
    if signature_id is not None:
        rule_rows = [
            candidate
            for candidate in candidates
            if int(candidate["id"]) != event_id
            and candidate["signature_id"] == signature_id
            and candidate["source_type"] == source_type
        ][:MAX_RELATED_ALERTS]
        rule_alerts = [
            _related_row_to_dict(r, "same_rule", **ip_policy) for r in rule_rows
        ]
    label, reason = RELATIONSHIP_LABELS["same_rule"]
    groups.append(
        {
            "relationship": "same_rule",
            "label": label,
            "reason": reason,
            "exact": signature_id is not None and not candidates_truncated,
            "truncated": signature_id is not None and candidates_truncated,
            "candidate_limit": candidate_limit if signature_id is not None else None,
            "candidates_examined": len(candidates) if signature_id is not None else 0,
            "alerts": rule_alerts,
        }
    )

    # Address groups are matched in application code over the same candidates.
    for relationship, column, anchor_value in (
        ("same_source_ip", "src_ip", anchor["src_ip"]),
        ("same_destination_ip", "dest_ip", anchor["dest_ip"]),
    ):
        label, reason = RELATIONSHIP_LABELS[relationship]
        alerts: list[dict[str, Any]] = []
        if anchor_value:
            for candidate in candidates:
                if len(alerts) >= MAX_RELATED_ALERTS:
                    break
                if int(candidate["id"]) == event_id:
                    continue
                if candidate[column] != anchor_value:
                    continue
                alerts.append(
                    _related_row_to_dict(candidate, relationship, **ip_policy)
                )
        groups.append(
            {
                "relationship": relationship,
                "label": label,
                "reason": reason,
                "exact": False,
                "truncated": bool(anchor_value) and candidates_truncated,
                "candidate_limit": candidate_limit,
                "candidates_examined": len(candidates) if anchor_value else 0,
                "alerts": alerts,
            }
        )

    effective_signature = _normalized_queue_search(signature)
    where, params = build_verdict_filters(
        verdict,
        effective_signature,
        model,
        source,
        review,
        include_private_search=include_private_search,
    )
    search_enabled = bool(effective_signature)
    if search_window is not None and not search_enabled:
        raise HTTPException(status_code=422, detail="search window requires search")
    if search_enabled:
        if search_window is None:
            search_window = _new_queue_search_window(conn)
        _apply_queue_search_bound(
            where,
            params,
            window=search_window,
        )
    search_scope = None
    with _queue_search_budget(conn, enabled=search_enabled):
        if search_enabled:
            search_scope = search_window.scope()
        previous_row, next_row = _fetch_neighbors(
            conn,
            anchor_id=int(anchor["id"]),
            anchor_processed_at=anchor["processed_at"],
            where=list(where),
            params=list(params),
        )
    encoded_search_window = (
        encode_search_window(search_window) if search_window is not None else None
    )

    return {
        "generated_at": utc_now_iso(),
        "event_id": int(anchor["id"]),
        "window_hours": hours,
        "window_start": window_start,
        "recurrence": recurrence,
        "related": groups,
        "search_window": encoded_search_window,
        "neighbors": {
            "previous": _neighbor_row_to_dict(previous_row),
            "next": _neighbor_row_to_dict(next_row),
            "filters": {
                "verdict": verdict,
                "signature": effective_signature or None,
                "model": model,
                "source": source,
                "review": review,
            },
            "search_scope": search_scope,
        },
    }


def get_cached_stats(
    db_factory: Callable[..., Any],
) -> tuple[dict[str, int], str]:
    now = time.time()
    if (
        _stats_cache["data"] is not None
        and (now - _stats_cache["ts"]) < STATS_TTL
    ):
        return _stats_cache["data"], _stats_cache["generated_at"]
    with db_factory(readonly=True) as conn:
        stats = get_dashboard_stats(conn)
    generated_at = utc_now_iso()
    _stats_cache["data"] = stats
    _stats_cache["ts"] = now
    _stats_cache["generated_at"] = generated_at
    return stats, generated_at


def get_timeline(
    db_factory: Callable[..., Any],
    *,
    hours: int = 24,
    interval: str = "1h",
) -> tuple[list[dict[str, Any]], str]:
    if hours < 1 or hours > MAX_TIMELINE_HOURS:
        raise HTTPException(
            status_code=422,
            detail=f"hours must be between 1 and {MAX_TIMELINE_HOURS}",
        )
    if interval != "1h":
        raise HTTPException(
            status_code=422,
            detail="interval must be 1h",
        )
    cache_key = (hours, interval)
    now = time.time()
    if (
        _timeline_cache["data"] is not None
        and _timeline_cache["key"] == cache_key
        and (now - _timeline_cache["ts"]) < TIMELINE_TTL
    ):
        return _timeline_cache["data"]["buckets"], _timeline_cache["data"][
            "generated_at"
        ]

    cutoff = format_utc_timestamp(utc_now() - timedelta(hours=hours))
    with db_factory(readonly=True) as conn:
        rows = conn.execute(
            """
            SELECT
                strftime('%Y-%m-%dT%H:00:00.000000Z', processed_at) AS hour_bucket,
                COUNT(*) AS total_alerts,
                COALESCE(SUM(model_used = 'prefilter'), 0) AS prefiltered_count,
                COALESCE(SUM(verdict = 'real'), 0) AS real_count
            FROM triage_events
            WHERE processed_at >= ?
            GROUP BY hour_bucket
            ORDER BY hour_bucket ASC
            """,
            (cutoff,),
        ).fetchall()

    out: list[dict[str, Any]] = []
    for row in rows:
        total = int(row["total_alerts"] or 0)
        pre = int(row["prefiltered_count"] or 0)
        real = int(row["real_count"] or 0)
        pct = (pre / total * 100.0) if total else 0.0
        out.append(
            {
                "timestamp": row["hour_bucket"] or "",
                "total_alerts": total,
                "prefiltered_count": pre,
                "prefilter_percentage": pct,
                "real_count": real,
            }
        )
        if len(out) >= MAX_TIMELINE_HOURS:
            break

    generated_at = utc_now_iso()
    payload = {"buckets": out, "generated_at": generated_at}
    _timeline_cache["data"] = payload
    _timeline_cache["ts"] = now
    _timeline_cache["key"] = cache_key
    return out, generated_at


def get_spc_anomalies(
    db_factory: Callable[..., Any],
    *,
    mode: str,
    mask_ip_fn: Callable[[str | None], str | None],
    redact_ips: bool,
    ip_secret: bytes | None = None,
) -> tuple[dict[str, Any], str]:
    now = time.time()
    if _spc_cache["data"] is not None and (now - _spc_cache["ts"]) < SPC_TTL:
        return _spc_cache["data"]["payload"], _spc_cache["data"]["generated_at"]

    out: dict[str, Any] = {"anomalies": [], "available": True}
    with db_factory(readonly=True) as conn:
        exists = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='spc_anomalies'"
        ).fetchone()
        if not exists:
            out["available"] = False
            generated_at = utc_now_iso()
            _spc_cache["data"] = {"payload": out, "generated_at": generated_at}
            _spc_cache["ts"] = now
            return out, generated_at

        rows = conn.execute(
            """
            SELECT detected_at, feature, ip, signature_id, z, note
            FROM spc_anomalies
            ORDER BY id DESC
            LIMIT 50
            """
        ).fetchall()
        cutoff = format_utc_timestamp(utc_now() - timedelta(hours=24))
        last24 = conn.execute(
            "SELECT COUNT(*) FROM spc_anomalies WHERE detected_at >= ?",
            (cutoff,),
        ).fetchone()[0]

    for row in rows:
        try:
            ts = format_utc_timestamp(row["detected_at"])
        except (TypeError, ValueError):
            ts = None
        ip_value = mask_ip_fn(row["ip"]) if mode == "demo" else row["ip"]
        if redact_ips and mode != "demo":
            ip_value = hash_ip(ip_value, ip_secret)
        out["anomalies"].append(
            {
                "detected_at": ts,
                "feature": row["feature"],
                "ip": ip_value,
                "signature_id": row["signature_id"],
                "z": row["z"],
                "note": None if mode == "demo" else row["note"],
            }
        )
    out["count_24h"] = int(last24 or 0)
    generated_at = utc_now_iso()
    _spc_cache["data"] = {"payload": out, "generated_at": generated_at}
    _spc_cache["ts"] = now
    return out, generated_at


def compute_health(
    db_factory: Callable[..., Any],
    db_path: Any,
    *,
    stale_threshold_seconds: int,
    include_storage: bool,
) -> tuple[dict[str, Any], int]:
    last_processed_at = None
    storage = None
    with db_factory(readonly=True) as conn:
        try:
            row = conn.execute(
                "SELECT MAX(processed_at) AS last_processed_at FROM triage_events"
            ).fetchone()
            if row:
                last_processed_at = row["last_processed_at"]
            if include_storage:
                storage = get_storage_metrics(conn, db_path)
        except sqlite3.OperationalError:
            last_processed_at = None

    age_seconds = 10**9
    if last_processed_at:
        try:
            dt = parse_utc_timestamp(str(last_processed_at))
            age_seconds = int((utc_now() - dt).total_seconds())
        except Exception:
            age_seconds = 10**9

    payload: dict[str, Any] = {
        "last_alert_age_seconds": max(0, age_seconds),
        "generated_at": utc_now_iso(),
    }
    if include_storage:
        payload["storage"] = storage
    status_code = 200
    if age_seconds > stale_threshold_seconds:
        payload["status"] = "stale"
        status_code = 503
    else:
        payload["status"] = "ok"
    return payload, status_code


def submit_feedback(
    db_factory: Callable[..., Any],
    *,
    mode: str,
    event_id: int,
    human_verdict: str,
    notes: str,
) -> dict[str, Any]:
    if mode == "demo":
        raise HTTPException(403, "Feedback disabled in demo mode")
    if human_verdict not in ("real", "false_positive", "uncertain"):
        raise HTTPException(
            400,
            "human_verdict must be real | false_positive | uncertain",
        )
    with db_factory() as conn:
        row = conn.execute(
            "SELECT verdict FROM triage_events WHERE id = ?",
            (event_id,),
        ).fetchone()
        if not row:
            raise HTTPException(404, "event not found")
        agreed = 1 if row["verdict"] == human_verdict else 0
        conn.execute(
            """UPDATE triage_events
               SET human_verdict = ?, human_notes = ?, agreed = ?, reviewed_at = ?
               WHERE id = ?""",
            (human_verdict, notes, agreed, utc_now_iso(), event_id),
        )
        conn.commit()
    return {"ok": True, "agreed": bool(agreed)}
