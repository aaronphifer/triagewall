#!/usr/bin/env python3
"""
Live ingest daemon: tails OPNsense eve.json, triages alerts in real time.

Reads new lines from the synced eve.json, filters to alert events,
sends each to the triage function, writes verdict to triage.db.

Run:
    python3 src/ingest.py

Stop with Ctrl-C or systemd.
"""
from __future__ import annotations

import os
import re
import sys
import spc
import stat
import time
import json
import sqlite3
import signal
import logging
import random
from dataclasses import dataclass
from pathlib import Path
from asset_inventory import configured_inventory_path
from config_bootstrap import packaged_prefilter_path
from database import connect_database
from environment import parse_boolean
from migrations import verify_db_initialized
from operator_config import (
    ConfigurationBundleOwner,
    OperatorConfigError,
    synchronize_legacy_configuration,
)
from time_utils import format_utc_timestamp, utc_now_iso

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_dotenv(override: bool = False) -> None:
    """Minimal `.env` loader (stdlib-only; matches docker-compose interpolation locally)."""
    env_path = _REPO_ROOT / ".env"
    if not env_path.exists():
        return
    try:
        for raw_line in env_path.read_text().splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if not key:
                continue
            if not override and key in os.environ:
                continue
            os.environ[key] = val
    except OSError:
        return


_load_dotenv(override=False)

# Reuse the existing triage code
sys.path.insert(0, str(Path(__file__).parent))
from triage import (
    MODEL,
    PREFILTER_CONFIG_PATH,
    call_ollama,
    classify_suricata,
    get_asset_context,
    insert_triage_row,
    set_configuration_bundle_owner,
    validate_zeek_catchup_settings,
)
from sensor_event import (
    SuricataValidationError,
    normalize_suricata_event,
    suricata_classification_alert,
)
from zeek_provider import SQLiteZeekContextProvider

# --- Config ---
DEMO_MODE = parse_boolean(
    os.environ.get("DEMO_MODE", "false"),
    "DEMO_MODE",
)
EVE_PATH = Path(os.environ.get("EVE_PATH", "/var/log/suricata/eve.json"))
POSITION_PATH = Path(os.environ.get("POSITION_PATH", "/var/lib/triagewall/position.json"))
DB_PATH = Path(
    os.environ.get("DB_PATH")
    or os.environ.get("TRIAGE_DB")
    or str(_REPO_ROOT / "triage.db")
)
ZEEK_ENRICHMENT_ENABLED = parse_boolean(
    os.environ.get("ZEEK_ENRICHMENT_ENABLED", "false"),
    "ZEEK_ENRICHMENT_ENABLED",
)
ZEEK_INDEX_PATH = Path(
    os.environ.get(
        "ZEEK_INDEX_PATH",
        "/var/lib/triagewall/zeek-context.db",
    )
)
ZEEK_SOURCE_ID = os.environ.get("ZEEK_SOURCE_ID", "zeek-local")
try:
    (
        ZEEK_CATCHUP_TIMEOUT_SECONDS,
        ZEEK_CATCHUP_RETRY_INTERVAL_SECONDS,
    ) = validate_zeek_catchup_settings(
        float(os.environ.get("ZEEK_CATCHUP_TIMEOUT_SECONDS", "3")),
        float(os.environ.get("ZEEK_CATCHUP_RETRY_INTERVAL_SECONDS", "0.5")),
    )
except ValueError as exc:
    raise RuntimeError(f"invalid Zeek catch-up configuration: {exc}") from exc
ZEEK_CONTEXT_PROVIDER = (
    SQLiteZeekContextProvider(ZEEK_INDEX_PATH, ZEEK_SOURCE_ID)
    if ZEEK_ENRICHMENT_ENABLED
    else None
)
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "10"))  # seconds
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")

# --- Rotation handling ---
# Rotated eve.json archives are written beside the live file, inside the single
# directory the deployment mounts as HOST_EVE_DIR. Discovery stays deliberately
# bounded: one directory, never recursive, never through a symlink, regular
# files only, and a hard cap on how many entries we are willing to examine.
#
# The two caps are separate on purpose. HOST_EVE_DIR is usually the whole
# Suricata log directory, so unrelated files (fast.log, stats.log, other
# daemons' logs) must not consume the archive budget -- counting them was what
# let a truncated scan hide an intermediate archive and skip its alerts. Only
# eve.json* siblings count against MAX_ROTATION_SCAN_ENTRIES; the much larger
# MAX_ROTATION_DIR_ENTRIES bounds a pathological directory. Exceeding either is
# a hard failure, never a partial chain: an incomplete chain cannot be told
# apart from a complete one by its callers.
MAX_ROTATION_SCAN_ENTRIES = 512
MAX_ROTATION_DIR_ENTRIES = 100_000
COMPRESSED_ROTATION_SUFFIXES = (".gz", ".bz2", ".xz", ".zst")
_NUMBERED_ROTATION_RE = re.compile(r"^\.(\d+)$")

# A renamed eve.json is NOT immutable. logrotate (and Suricata's own rotation)
# can move the path while the writer still holds the old descriptor open and
# appends more records through it. Treating the first EOF as "fully drained"
# silently loses those records, so an inode is only abandoned after consecutive
# unchanged EOF observations spaced by a bounded settle interval.
EOF_STABLE_OBSERVATIONS = max(
    2, int(os.environ.get("EVE_EOF_STABLE_OBSERVATIONS", "2"))
)
EOF_SETTLE_INTERVAL = float(os.environ.get("EVE_EOF_SETTLE_SECONDS", "1.0"))

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("ingest")


@dataclass(frozen=True)
class LineResult:
    """Outcome of processing one complete input record."""

    processed: bool
    checkpoint: bool

    def __bool__(self):
        """Preserve the historical truthy result for successfully triaged alerts."""
        return self.processed


PROCESSED_LINE = LineResult(processed=True, checkpoint=True)
CHECKPOINT_LINE = LineResult(processed=False, checkpoint=True)
RETRY_LINE = LineResult(processed=False, checkpoint=False)


class EveCheckpointError(RuntimeError):
    """Suricata checkpoint is corrupt, unwritable, or otherwise unusable."""


class IngestCheckpointError(EveCheckpointError):
    """Suricata ingest cannot safely advance the durable checkpoint.

    A subclass so that one ``except EveCheckpointError`` guard fails closed on
    the whole family: a checkpoint that cannot be read or written, and a
    rotation chain that cannot be followed without risking an alert gap.
    """


# Graceful shutdown
_stop = False
RUNTIME_CONFIG_OWNER = None

CONFIG_RELOAD_INTERVAL_SECONDS = float(
    os.environ.get("TRIAGEWALL_CONFIG_RELOAD_INTERVAL_SECONDS", "5")
)
if not 1 <= CONFIG_RELOAD_INTERVAL_SECONDS <= 300:
    raise RuntimeError(
        "TRIAGEWALL_CONFIG_RELOAD_INTERVAL_SECONDS must be from 1 to 300"
    )


def start_configuration_owner(
    conn,
    *,
    consumer,
    db_path=None,
    reload_interval_seconds=None,
):
    """Synchronize legacy mounts, then publish one verified immutable bundle.

    The one-shot bootstrap container runs before the first consumer start, but
    it does not rerun when a single consumer restarts, so a valid host-side edit
    to a mounted document would otherwise leave the durable active revision
    stale and fail this consumer's start closed on every restart. Mirroring the
    mounts here -- through the same serialized, fail-closed transaction -- keeps
    the durable record truthful for every consumer start, and publishing the
    exact objects that synchronization validated means one read of each mount
    backs both the durable revision and the runtime bundle. Under `database`
    authority no file is read at all: recording a changed packaged default
    belongs to the one-shot bootstrap, and a consumer must be able to start from
    a valid durable bundle on a host that installs no packaged default.
    """
    snapshot = synchronize_legacy_configuration(
        db_path or DB_PATH,
        packaged_prefilter_path=packaged_prefilter_path(),
        legacy_prefilter_path=PREFILTER_CONFIG_PATH,
        asset_inventory_path=configured_inventory_path(),
        discover_shipped_baseline=False,
    )
    log.info(
        "Configuration authority: mode=%s generation=%s",
        snapshot.mode,
        snapshot.generation,
    )
    owner = ConfigurationBundleOwner(
        consumer=consumer,
        legacy_prefilter_policy=snapshot.prefilter_policy,
        legacy_asset_inventory=snapshot.asset_inventory,
        reload_interval_seconds=(
            reload_interval_seconds
            if reload_interval_seconds is not None
            else CONFIG_RELOAD_INTERVAL_SECONDS
        ),
    )
    owner.start(conn)
    return owner


def _handle_signal(signum, frame):
    global _stop
    _stop = True
    log.info(f"Received signal {signum}, shutting down...")

signal.signal(signal.SIGTERM, _handle_signal)
signal.signal(signal.SIGINT, _handle_signal)


def _empty_position():
    return {"offset": 0, "inode": None, "size": 0}


def _validate_position(state):
    """Reject checkpoints that cannot be trusted as a durable read cursor."""
    if not isinstance(state, dict) or set(state) != {"offset", "inode", "size"}:
        raise EveCheckpointError("Suricata checkpoint has an invalid schema")
    for field in ("offset", "size"):
        value = state[field]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise EveCheckpointError(
                f"Suricata checkpoint {field} must be a non-negative integer"
            )
    inode = state["inode"]
    if inode is not None and (
        isinstance(inode, bool) or not isinstance(inode, int)
    ):
        raise EveCheckpointError("Suricata checkpoint inode is invalid")
    return state


def load_position():
    """Return the durable read cursor, or an empty cursor on first run.

    A corrupt or schema-invalid checkpoint fails closed. Silently rewinding to
    offset 0 would re-ingest already-triaged alerts: flow-less Suricata alerts
    are not covered by ``is_duplicate``, so a rewind creates duplicate
    ``triage_events`` rows. Wazuh ingest already fails closed for the same
    reason.
    """
    if not POSITION_PATH.exists():
        return _empty_position()
    try:
        state = json.loads(POSITION_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EveCheckpointError(
            "could not read Suricata checkpoint"
        ) from exc
    return _validate_position(state)


def save_position(state):
    """Atomically replace the Suricata checkpoint.

    A plain ``write_text`` truncates the existing file first. A crash in the
    middle leaves a partial JSON document; the previous loader treated that as
    "start fresh" and rewound to offset 0. Write to a temp file, fsync, then
    ``os.replace`` so readers either see the old complete checkpoint or the
    new one — never a torn file.
    """
    validated = _validate_position(state)
    temporary = POSITION_PATH.with_name(
        f".{POSITION_PATH.name}.{os.getpid()}.tmp"
    )
    try:
        try:
            POSITION_PATH.parent.mkdir(parents=True, exist_ok=True)
            with open(temporary, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(
                    validated, handle, sort_keys=True, separators=(",", ":")
                )
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, POSITION_PATH)
        except OSError as exc:
            raise EveCheckpointError(
                "could not write Suricata checkpoint"
            ) from exc
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _rotation_sort_key(name: str, live_name: str):
    """Order eve.json siblings oldest-first using documented rotation schemes.

    logrotate numbers archives so that a *higher* index is older
    (``eve.json.2`` predates ``eve.json.1``). Suricata's own dated archives
    (``eve.json-20260806``) sort oldest-first lexicographically. The live file
    is always the newest member of the chain.
    """
    if name == live_name:
        return (2, 0, "")
    suffix = name[len(live_name):]
    for compressed in COMPRESSED_ROTATION_SUFFIXES:
        if suffix.endswith(compressed):
            suffix = suffix[: -len(compressed)]
            break
    numbered = _NUMBERED_ROTATION_RE.match(suffix)
    if numbered:
        return (0, -int(numbered.group(1)), "")
    return (1, 0, suffix)


def _is_compressed_archive(name: str) -> bool:
    """Whether ``name`` is a compressed rotation archive.

    Compressed archives stay in the chain: they are evidence that a rotation
    happened and they hold their slot in the ordering. They are simply not
    readable as JSON-Lines, so they may never become a read source or a
    persisted checkpoint.
    """
    return name.endswith(COMPRESSED_ROTATION_SUFFIXES)


def _compressed_archive_message(path: Path, inode: int) -> str:
    return (
        f"the next unread eve.json archive is {path} (inode {inode}), which is "
        "compressed. Triagewall reads eve.json as plain JSON-Lines and will "
        "not decompress it, and it will not skip it either: the alerts inside "
        "have not been triaged. The checkpoint has been left on the file "
        "before it. Recovery: decompress the archive in place beside "
        f"{EVE_PATH} (for example `gunzip {path}`), or restore an "
        "uncompressed copy under the same name, then restart ingest. If that "
        "archive is genuinely unrecoverable, an operator must decide and "
        f"record the resulting alert gap before editing {POSITION_PATH}."
    )


def _scan_eve_chain(live_path: Path) -> list[tuple[str, Path, os.stat_result]]:
    """Return the bounded, oldest-first rotation chain beside ``live_path``.

    Only plausible rotated siblings are considered: entries in the eve.json
    directory whose name starts with the live file's name. Symlinks,
    directories, devices, sockets and FIFOs are rejected outright, and the scan
    never recurses.

    The chain this returns is always complete. Callers use it to decide which
    archive comes next, and a partial chain is indistinguishable from a
    complete one: if an intermediate archive is missing from it, successor
    selection happily skips to the live file and that archive's alerts are
    never triaged. So an incomplete scan raises ``IngestCheckpointError``
    instead of returning what it managed to see.
    """
    directory = live_path.parent
    prefix = live_path.name
    chain: list[tuple[str, Path, os.stat_result]] = []
    examined = 0
    matched = 0
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                examined += 1
                if examined > MAX_ROTATION_DIR_ENTRIES:
                    raise IngestCheckpointError(
                        f"{directory} holds more than "
                        f"{MAX_ROTATION_DIR_ENTRIES} entries, so Triagewall "
                        "cannot enumerate the eve.json rotation chain without "
                        "an unbounded scan. It will not advance the checkpoint "
                        "on a chain it could not fully see. Recovery: mount a "
                        "directory that contains only the Suricata logs as "
                        "HOST_EVE_DIR, or reduce the number of files in it."
                    )
                if not entry.name.startswith(prefix):
                    # Unrelated logs in HOST_EVE_DIR must not consume the
                    # archive budget; only the directory-wide cap bounds them.
                    continue
                matched += 1
                if matched > MAX_ROTATION_SCAN_ENTRIES:
                    raise IngestCheckpointError(
                        f"more than {MAX_ROTATION_SCAN_ENTRIES} files in "
                        f"{directory} look like rotated eve.json archives, so "
                        "the rotation chain cannot be enumerated within its "
                        "safety bound. Triagewall will not guess which archive "
                        "follows the checkpoint and risk skipping alerts. "
                        "Recovery: archive or remove the drained rotations, "
                        "leaving only the ones ingest has not read yet."
                    )
                try:
                    if entry.is_symlink():
                        # Never follow a symlink out of the eve.json directory.
                        continue
                    # DirEntry.stat(follow_symlinks=False) reports st_ino == 0 on
                    # Windows, so stat the (already proven non-symlink) path.
                    entry_stat = os.stat(entry.path)
                except OSError:
                    continue
                if not stat.S_ISREG(entry_stat.st_mode):
                    continue
                chain.append((entry.name, Path(entry.path), entry_stat))
    except OSError as exc:
        # An unreadable log directory is not evidence that no archive is
        # pending. Returning an empty chain here would let a caller conclude
        # the checkpointed inode is gone, or that the live file is the next
        # thing to read.
        raise IngestCheckpointError(
            f"could not scan {directory} for rotated eve.json archives: {exc}. "
            "Triagewall cannot confirm which archive follows the checkpoint, "
            "so it will not advance it. Recovery: restore read access to the "
            "directory and restart ingest."
        ) from exc
    chain.sort(key=lambda item: _rotation_sort_key(item[0], prefix))
    return chain


def _chain_index_of_inode(
    chain: list[tuple[str, Path, os.stat_result]], inode: int
) -> int | None:
    for index, (_name, _path, entry_stat) in enumerate(chain):
        if entry_stat.st_ino == inode:
            return index
    return None


def _successor_in_chain(
    live_path: Path, inode: int
) -> tuple[Path, os.stat_result] | None:
    """Return the archive that directly follows ``inode`` in the rotation chain."""
    chain = _scan_eve_chain(live_path)
    index = _chain_index_of_inode(chain, inode)
    if index is None or index + 1 >= len(chain):
        return None
    _name, path, entry_stat = chain[index + 1]
    return path, entry_stat


@dataclass(frozen=True)
class EveSource:
    """The file that currently owns the durable checkpoint."""

    path: Path
    stat: os.stat_result
    # True when this is a rotated archive rather than the live eve.json.
    draining: bool
    # Chain successor recorded *before* draining, so the chain position survives
    # logrotate compressing (and unlinking) this archive while we read it.
    successor_hint: tuple[Path, int] | None


def _resolve_checkpoint_source(
    state: dict, live_stat: os.stat_result
) -> EveSource | None:
    """Choose the file that still owns the durable checkpoint.

    Suricata/logrotate renames ``eve.json`` and creates a new live file. While
    a checkpoint still points at the previous inode, that archive must be
    drained before the live path is followed. Returns ``None`` when the
    filesystem is mid-rename and the caller should simply re-resolve.
    """
    live_inode = live_stat.st_ino
    checkpoint_inode = state.get("inode")
    offset = int(state.get("offset") or 0)

    if checkpoint_inode is None:
        # First run: adopt the live file and read it from the saved offset.
        if live_stat.st_size < offset:
            raise IngestCheckpointError(_shrank_message(EVE_PATH, live_stat, offset))
        return EveSource(EVE_PATH, live_stat, draining=False, successor_hint=None)

    if checkpoint_inode == live_inode:
        if live_stat.st_size < offset:
            raise IngestCheckpointError(_shrank_message(EVE_PATH, live_stat, offset))
        return EveSource(EVE_PATH, live_stat, draining=False, successor_hint=None)

    chain = _scan_eve_chain(EVE_PATH)
    index = _chain_index_of_inode(chain, checkpoint_inode)
    if index is None:
        # The checkpointed inode is gone. A zero offset is NOT evidence that the
        # archive was drained -- it just as plausibly means the whole file was
        # still unread -- so fail closed either way.
        raise IngestCheckpointError(_missing_inode_message(checkpoint_inode, offset))

    name, rotated_path, rotated_stat = chain[index]
    if name == EVE_PATH.name:
        # The live path was replaced between the stat above and this scan.
        return None

    if _is_compressed_archive(name):
        # The checkpoint names an archive that has since been compressed in
        # place (same inode, new name). It cannot be read as JSON-Lines and
        # its unread records must not be skipped.
        raise IngestCheckpointError(
            _compressed_archive_message(rotated_path, checkpoint_inode)
        )

    if rotated_stat.st_size < offset:
        raise IngestCheckpointError(
            _shrank_message(rotated_path, rotated_stat, offset)
        )

    successor_hint = None
    if index + 1 < len(chain):
        _next_name, next_path, next_stat = chain[index + 1]
        successor_hint = (next_path, next_stat.st_ino)

    log.info(
        "eve.json rotated; draining unread records from %s (inode %s, offset %s) "
        "before following the live file",
        rotated_path,
        checkpoint_inode,
        offset,
    )
    return EveSource(
        rotated_path, rotated_stat, draining=True, successor_hint=successor_hint
    )


def _shrank_message(path: Path, path_stat: os.stat_result, offset: int) -> str:
    return (
        f"{path} shrank behind the durable checkpoint "
        f"(size {path_stat.st_size} < offset {offset}); refusing to skip unread "
        "alerts. Recovery: restore the file that produced this checkpoint, or "
        "have an operator record the resulting alert gap before the checkpoint "
        "is changed."
    )


def _missing_inode_message(inode: int, offset: int) -> str:
    return (
        f"the eve.json checkpoint points at inode {inode} (offset {offset}) but no "
        f"regular file with that inode remains in {EVE_PATH.parent}. Triagewall "
        "has no evidence that the previous file was fully drained -- an offset of "
        "0 can equally mean the entire archive was still unread -- so it will not "
        "skip ahead to the current eve.json. Recovery: restore the rotated archive "
        f"for inode {inode} into {EVE_PATH.parent} (for example from the logrotate "
        "archive or a backup) and restart ingest, which resumes at offset "
        f"{offset}. If that log is genuinely unrecoverable, an operator must "
        "decide and record the resulting alert gap before replacing "
        f"{POSITION_PATH}."
    )


def _await_stable_eof(handle) -> bool:
    """Return True once this descriptor has held EOF across bounded rechecks.

    A renamed eve.json is not immutable: logrotate can move the path while
    Suricata still holds the old descriptor and appends more records through it.
    Treating the first EOF as "drained" loses those records, so require
    consecutive unchanged observations, spaced by a bounded settle interval,
    before any caller is allowed to leave this inode. Returns False when more
    bytes appeared (keep draining) or when shutdown was requested.
    """
    position = handle.tell()
    observations = 0
    while observations < EOF_STABLE_OBSERVATIONS:
        try:
            size = os.fstat(handle.fileno()).st_size
        except OSError as exc:
            log.warning("Could not re-stat the open eve.json descriptor: %s", exc)
            # Back off so a persistently failing descriptor cannot spin the
            # caller's EOF retry loop.
            time.sleep(EOF_SETTLE_INTERVAL)
            return False
        if size > position:
            # A late append landed after we first saw EOF.
            return False
        observations += 1
        if observations >= EOF_STABLE_OBSERVATIONS:
            break
        time.sleep(EOF_SETTLE_INTERVAL)
        if _stop:
            # Graceful shutdown: leave the checkpoint on this inode so the next
            # start resumes the drain instead of skipping ahead.
            return False
    return True


def _line_is_complete(line):
    """A JSON-Lines record is complete only after its newline is present."""
    return bool(line) and line.endswith(("\n", "\r"))


def _line_is_complete_or_wait(line):
    """Return whether a record is complete, backing off before retrying if not."""
    if _line_is_complete(line):
        return True
    log.debug("Waiting for newline to complete eve.json record")
    time.sleep(POLL_INTERVAL)
    return False


def quarantine_line(conn, line, error, source_type="suricata"):
    """Durably retain an unprocessable complete record before checkpointing."""
    conn.rollback()
    conn.execute(
        """INSERT INTO ingest_failures
           (source_type, raw_line, error, failed_at) VALUES (?, ?, ?, ?)""",
        (
            source_type,
            line.rstrip("\r\n"),
            str(error)[:1000],
            utc_now_iso(),
        ),
    )
    conn.commit()
    log.error(f"Quarantined unprocessable {source_type} record: {error}")


def is_duplicate(conn, alert):
    """Check if we've already triaged this alert (flow_id + sig_id + timestamp)."""
    flow_id = alert.get("flow_id")
    sig_id = alert.get("alert", {}).get("signature_id")
    raw_ts = alert.get("timestamp")
    if not (flow_id and sig_id and raw_ts):
        return False
    canonical_ts = format_utc_timestamp(raw_ts)
    row = conn.execute(
        """SELECT 1 FROM triage_events
           WHERE flow_id = ? AND signature_id = ? AND timestamp IN (?, ?)
           LIMIT 1""",
        (flow_id, sig_id, raw_ts, canonical_ts),
    ).fetchone()
    return row is not None


def insert_with_retry(
    conn,
    event,
    verdict,
    asset_context=None,
    config_bundle=None,
    zeek_enrichment=None,
    max_retries=3,
    base_backoff_ms=100,
):
    """
    Insert a triage row with simple exponential backoff on SQLite 'database is locked' errors.
    Returns True on success, False if we give up after max_retries.
    """
    for attempt in range(max_retries):
        try:
            insert_triage_row(
                conn,
                event,
                verdict,
                asset_context=asset_context,
                config_bundle=config_bundle,
                zeek_enrichment=zeek_enrichment,
            )
            conn.commit()
            return True
        except sqlite3.OperationalError as e:
            conn.rollback()
            if "locked" in str(e).lower():
                if attempt < max_retries - 1:
                    sleep_time = (base_backoff_ms * (2**attempt)) / 1000.0
                    logging.warning(
                        f"Database locked, retrying in {sleep_time}s (attempt {attempt + 1}/{max_retries})"
                    )
                    time.sleep(sleep_time)
                else:
                    event_reference = (
                        event.get("flow_id")
                        if isinstance(event, dict)
                        else event.sensor.event_id
                    )
                    logging.error(
                        f"Failed to insert alert after {max_retries} attempts; "
                        f"will retry without checkpointing event: {event_reference}"
                    )
                    return False
            else:
                raise


def process_line(conn, line):
    """Parse one line and return whether it was processed and may be checkpointed."""
    if RUNTIME_CONFIG_OWNER is not None:
        RUNTIME_CONFIG_OWNER.maybe_reload(conn)
    raw_line = line.rstrip("\r\n")
    line = raw_line.strip()
    if not line:
        return CHECKPOINT_LINE
    try:
        event = json.loads(line)
    except json.JSONDecodeError as e:
        quarantine_line(conn, raw_line, f"invalid JSON: {e}")
        return CHECKPOINT_LINE

    if not isinstance(event, dict):
        quarantine_line(conn, raw_line, "top-level JSON value must be an object")
        return CHECKPOINT_LINE

    if event.get("event_type") != "alert":
        return CHECKPOINT_LINE

    if not isinstance(event.get("alert"), dict):
        quarantine_line(conn, raw_line, "alert event metadata must be an object")
        return CHECKPOINT_LINE

    try:
        format_utc_timestamp(event.get("timestamp"))
    except (TypeError, ValueError) as e:
        quarantine_line(conn, raw_line, f"invalid alert timestamp: {e}")
        return CHECKPOINT_LINE

    try:
        normalized_event = normalize_suricata_event(event)
    except SuricataValidationError as e:
        quarantine_line(conn, raw_line, f"invalid alert data: {e}")
        return CHECKPOINT_LINE

    classification_event = suricata_classification_alert(normalized_event)

    if is_duplicate(conn, event):
        log.debug(f"Skipping duplicate alert flow_id={event.get('flow_id')}")
        return CHECKPOINT_LINE

    sig = normalized_event.signature
    try:
        asset_context = get_asset_context(classification_event)
        call_kwargs = {"asset_context": asset_context}
        zeek_enrichment = None
        if ZEEK_ENRICHMENT_ENABLED:
            call_kwargs.update(
                normalized_event=normalized_event,
                zeek_context_provider=ZEEK_CONTEXT_PROVIDER,
            )
            classification = classify_suricata(
                classification_event,
                **call_kwargs,
                zeek_catchup_timeout_seconds=ZEEK_CATCHUP_TIMEOUT_SECONDS,
                zeek_catchup_retry_interval_seconds=(
                    ZEEK_CATCHUP_RETRY_INTERVAL_SECONDS
                ),
            )
            verdict = classification.verdict
            zeek_enrichment = classification.zeek_enrichment
        else:
            verdict = call_ollama(classification_event, **call_kwargs)
        insert_kwargs = {"asset_context": asset_context}
        if zeek_enrichment is not None:
            insert_kwargs["zeek_enrichment"] = zeek_enrichment
        if RUNTIME_CONFIG_OWNER is not None:
            insert_kwargs["config_bundle"] = RUNTIME_CONFIG_OWNER.bundle
        if not insert_with_retry(
            conn,
            normalized_event,
            verdict,
            **insert_kwargs,
        ):
            log.error(
                f"Failed to persist alert ({sig}); retrying without advancing checkpoint"
            )
            return RETRY_LINE
        # SPC behavioral baselining — independent observer, never fatal
        try:
            spc.observe(conn, classification_event)
            conn.commit()
        except Exception as e:
            log.warning(f"SPC observe failed (non-fatal): {type(e).__name__}: {e}")
        log.info(
            f"[{verdict['verdict']:>15}] {verdict['confidence']:.2f}  {sig[:80]}"
        )
        return PROCESSED_LINE
    except sqlite3.IntegrityError as e:
        conn.rollback()
        quarantine_line(
            conn,
            raw_line,
            f"invalid alert data: {type(e).__name__}: {e}",
        )
        return CHECKPOINT_LINE
    except Exception as e:
        conn.rollback()
        log.error(
            f"Failed to triage alert ({sig}): {type(e).__name__}: {e}; "
            "retrying without advancing checkpoint"
        )
        return RETRY_LINE


def demo_loop():
    global RUNTIME_CONFIG_OWNER
    fixtures_path = Path(__file__).parent.parent / "tests" / "fixtures" / "diverse_alerts.json"
    if not fixtures_path.exists():
        log.error(f"Demo fixtures not found at {fixtures_path}")
        sys.exit(1)

    try:
        with open(fixtures_path, "r") as f:
            demo_lines = [line.strip() for line in f if line.strip()]
    except Exception as e:
        log.error(f"Failed to load demo fixtures: {type(e).__name__}: {e}")
        sys.exit(1)

    if not demo_lines:
        log.error("Demo fixtures file is empty (expected JSON-Lines).")
        sys.exit(1)

    verify_db_initialized(DB_PATH)

    log.info(f"Demo fixtures loaded: {len(demo_lines)} alerts")
    conn = connect_database(DB_PATH)

    try:
        try:
            RUNTIME_CONFIG_OWNER = start_configuration_owner(
                conn,
                consumer="suricata",
            )
        except OperatorConfigError as exc:
            log.critical(f"Ingest configuration startup failed: {exc}")
            sys.exit(1)
        set_configuration_bundle_owner(RUNTIME_CONFIG_OWNER)
        while not _stop:
            for line in demo_lines:
                if _stop:
                    break
                process_line(conn, line)
                time.sleep(random.uniform(2, 8))
    finally:
        set_configuration_bundle_owner(None)
        RUNTIME_CONFIG_OWNER = None
        conn.close()


def tail_file():
    """Main loop: poll the file, process new lines."""
    global RUNTIME_CONFIG_OWNER
    if EVE_PATH.is_dir():
        log.error(f"{EVE_PATH} is a directory, not a file.")
        log.error("Either:")
        log.error("  1. Set DEMO_MODE=true in .env to test without real Suricata data")
        log.error("  2. Set HOST_EVE_PATH in .env to your actual eve.json file path")
        log.error("  3. Make sure the file exists on the host before starting the container")
        sys.exit(1)

    verify_db_initialized(DB_PATH)

    log.info(f"Starting ingest daemon")
    log.info(f"  eve.json: {EVE_PATH}")
    log.info(f"  database: {DB_PATH}")
    log.info(f"  model:    {MODEL}")
    log.info(f"  poll:     every {POLL_INTERVAL}s")

    state = load_position()
    conn = connect_database(DB_PATH)
    last_line_seen_ts = time.time()
    last_stall_warning_ts = 0.0

    def eve_disk_stat():
        try:
            return os.stat(EVE_PATH)
        except FileNotFoundError:
            return None

    try:
        try:
            RUNTIME_CONFIG_OWNER = start_configuration_owner(
                conn,
                consumer="suricata",
            )
        except OperatorConfigError as exc:
            log.critical(f"Ingest configuration startup failed: {exc}")
            sys.exit(1)
        set_configuration_bundle_owner(RUNTIME_CONFIG_OWNER)
        while not _stop:
            try:
                # Warn if we haven't seen new eve.json lines recently (rate-limited).
                now = time.time()
                gap = now - last_line_seen_ts
                if gap > 300 and (now - last_stall_warning_ts) > 300:
                    mins = gap / 60.0
                    log.warning(
                        f"Ingestion stalled. No new lines seen in eve.json for {mins:.1f} minutes."
                    )
                    last_stall_warning_ts = now

                disk_stat = eve_disk_stat()
                if disk_stat is None:
                    log.warning(f"{EVE_PATH} doesn't exist yet, waiting...")
                    time.sleep(POLL_INTERVAL)
                    continue

                source = _resolve_checkpoint_source(state, disk_stat)
                if source is None:
                    # Mid-rename race; re-resolve without touching the checkpoint.
                    time.sleep(POLL_INTERVAL)
                    continue

                read_path = source.path
                current_inode = source.stat.st_ino
                current_size = source.stat.st_size

                # A rotated archive must be reopened and confirmed at a stable EOF
                # before its checkpoint may move, so the idle shortcut below only
                # applies while we are following the live file.
                if not source.draining and current_size == state["offset"]:
                    # Nothing new
                    time.sleep(POLL_INTERVAL)
                    continue

                # Read new content using readline() so f.tell() works inside the loop.
                # Track the inode of the *open file descriptor* via os.fstat() so we can
                # detect rotation even when the path is recreated with a new inode while
                # we're still reading the old file.
                f = open(read_path, "r")
                try:
                    open_inode = os.fstat(f.fileno()).st_ino
                    # Stat/open race: the path we chose may have been replaced before open.
                    if open_inode != current_inode:
                        log.info(
                            "%s changed identity between stat and open (expected inode "
                            "%s, opened %s); retrying without advancing the durable "
                            "checkpoint",
                            read_path,
                            current_inode,
                            open_inode,
                        )
                        time.sleep(POLL_INTERVAL)
                        continue
                    f.seek(state["offset"])
                    if f.tell() != state["offset"]:
                        raise IngestCheckpointError(
                            f"failed to seek {read_path} to durable offset {state['offset']}"
                        )
                    new_lines = 0
                    processed = 0
                    while not _stop:
                        line = f.readline()
                        if not line:
                            # EOF. Never abandon this descriptor on a single
                            # observation: a renamed eve.json can still receive
                            # appends from the writer holding the old descriptor.
                            if not _await_stable_eof(f):
                                if _stop:
                                    break
                                # Late append: keep draining this inode.
                                continue

                            live = eve_disk_stat()
                            if live is None:
                                # Mid-rename: the live path is momentarily absent.
                                time.sleep(POLL_INTERVAL)
                                break

                            if not source.draining and live.st_ino == open_inode:
                                # Still the live file; just waiting for more data.
                                break

                            # This descriptor held a stable EOF, so every complete
                            # record on this inode is durably processed or
                            # quarantined. Only now may the checkpoint leave it.
                            successor = _successor_in_chain(EVE_PATH, open_inode)
                            if successor is None and source.successor_hint is not None:
                                # logrotate may have compressed (and unlinked) the
                                # archive we just drained. Fall back to the chain
                                # position recorded before the drain started.
                                hint_path, hint_inode = source.successor_hint
                                try:
                                    hint_stat = os.stat(hint_path)
                                except OSError:
                                    hint_stat = None
                                if hint_stat is not None and hint_stat.st_ino == hint_inode:
                                    successor = (hint_path, hint_stat)
                            if successor is None:
                                raise IngestCheckpointError(
                                    f"drained eve.json inode {open_inode} but its "
                                    f"position in the rotation chain under "
                                    f"{EVE_PATH.parent} can no longer be determined, "
                                    "so the next archive to read is unknown. "
                                    "Triagewall will not guess and risk skipping "
                                    "alerts. Recovery: stop the rotation tooling, "
                                    "confirm which archive follows inode "
                                    f"{open_inode}, and have an operator set "
                                    f"{POSITION_PATH} to that file's inode with "
                                    "offset 0."
                                )
                            next_path, next_stat = successor
                            if _is_compressed_archive(next_path.name):
                                # Fail closed *before* save_position(). Parking
                                # the durable checkpoint on a compressed inode
                                # would make every later poll open gzip bytes
                                # as UTF-8 text, and the resulting
                                # UnicodeDecodeError is not a checkpoint error,
                                # so the generic retry path would spin forever
                                # with the checkpoint already moved -- and a
                                # restart would reproduce it.
                                raise IngestCheckpointError(
                                    _compressed_archive_message(
                                        next_path, next_stat.st_ino
                                    )
                                )
                            log.info(
                                "Drained eve.json inode %s (%s); following %s "
                                "(inode %s) from offset 0",
                                open_inode,
                                read_path,
                                next_path,
                                next_stat.st_ino,
                            )
                            state["offset"] = 0
                            state["inode"] = next_stat.st_ino
                            state["size"] = next_stat.st_size
                            save_position(state)
                            break

                        if not _line_is_complete_or_wait(line):
                            # An append-in-place writer may expose a partial JSON
                            # record at EOF. Leave the checkpoint unchanged so the
                            # completed record is reread on the next poll.
                            break

                        last_line_seen_ts = time.time()
                        result = process_line(conn, line)
                        if not result.checkpoint:
                            # Retryable processing failures must block later records
                            # from moving the durable checkpoint past this alert.
                            time.sleep(POLL_INTERVAL)
                            break

                        new_lines += 1
                        if result:
                            processed += 1

                        state["offset"] = f.tell()
                        state["inode"] = open_inode
                        state["size"] = current_size
                        save_position(state)
                finally:
                    try:
                        f.close()
                    except Exception:
                        pass

                if new_lines:
                    log.info(
                        f"Read {new_lines} new lines, triaged {processed} alerts "
                        f"(offset now {state['offset']})"
                    )

            except EveCheckpointError as exc:
                # Fail closed on the whole checkpoint-error family. This single
                # guard covers both a corrupt or unwritable checkpoint and a
                # rotation the daemon cannot advance across safely, because
                # IngestCheckpointError subclasses EveCheckpointError.
                # Continuing with an in-memory cursor ahead of a durable
                # checkpoint would skip or duplicate alerts across a restart.
                log.critical(
                    "Suricata ingest stopped to prevent an alert gap: %s", exc
                )
                raise
            except Exception as e:
                log.error(f"Loop error: {type(e).__name__}: {e}")
                time.sleep(POLL_INTERVAL)
    finally:
        set_configuration_bundle_owner(None)
        RUNTIME_CONFIG_OWNER = None
        conn.close()
        log.info("Ingest daemon stopped cleanly")


def main() -> int:
    try:
        if DEMO_MODE:
            log.info("Running in DEMO MODE using local fixtures...")
            demo_loop()
        else:
            tail_file()
    except EveCheckpointError as exc:
        # One handler for the whole checkpoint-error family: a corrupt or
        # unwritable checkpoint and a rotation that cannot be advanced safely
        # both terminate here, non-zero, rather than skipping alerts.
        # IngestCheckpointError subclasses EveCheckpointError, so listing the
        # subclass separately would be dead code and could drift apart.
        log.critical("Suricata ingest stopped to avoid skipping alerts: %s", exc)
        return 1
    except (OSError, RuntimeError, sqlite3.Error) as exc:
        log.critical("Suricata ingest failed: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
