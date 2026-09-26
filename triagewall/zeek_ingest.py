#!/usr/bin/env python3
"""Private service indexing Zeek connections and UID-linked evidence."""

from __future__ import annotations

import logging
import os
import signal
import sqlite3
import sys
import time
from dataclasses import dataclass
from pathlib import Path

try:
    from .zeek_follower import (
        MAX_RECORDS_PER_POLL,
        ZeekFollower,
        ZeekFollowerError,
    )
    from .zeek_index import (
        MAX_PRUNE_BATCH_SIZE,
        MAX_PRUNE_ROWS,
        ZeekCheckpointConflict,
        ZeekConnValidationError,
        connect_zeek_index,
        load_checkpoint,
        prune_index,
    )
except ImportError:  # Direct execution in the ingest container.
    from zeek_follower import (
        MAX_RECORDS_PER_POLL,
        ZeekFollower,
        ZeekFollowerError,
    )
    from zeek_index import (
        MAX_PRUNE_BATCH_SIZE,
        MAX_PRUNE_ROWS,
        ZeekCheckpointConflict,
        ZeekConnValidationError,
        connect_zeek_index,
        load_checkpoint,
        prune_index,
    )


log = logging.getLogger("zeek_ingest")
_stop = False


@dataclass(frozen=True)
class ZeekIngestSettings:
    conn_path: Path
    index_path: Path
    source_instance: str
    poll_interval_seconds: float
    max_records_per_poll: int
    eof_stable_observations: int
    archive_root: Path = Path("/var/log/zeek")
    retention_seconds: float = 7 * 24 * 60 * 60
    prune_interval_seconds: float = 60.0
    prune_batch_size: int = 1_000
    prune_max_rows: int = 10_000
    evidence_paths: tuple[tuple[str, Path], ...] = ()


def settings_from_environment() -> ZeekIngestSettings:
    poll_interval = float(os.environ.get("ZEEK_POLL_INTERVAL", "2"))
    if not 0.1 <= poll_interval <= 300:
        raise RuntimeError("ZEEK_POLL_INTERVAL must be from 0.1 to 300 seconds")
    max_records = int(os.environ.get("ZEEK_MAX_RECORDS_PER_POLL", "1000"))
    if not 1 <= max_records <= MAX_RECORDS_PER_POLL:
        raise RuntimeError(
            f"ZEEK_MAX_RECORDS_PER_POLL must be from 1 to {MAX_RECORDS_PER_POLL}"
        )
    stable_observations = int(
        os.environ.get("ZEEK_EOF_STABLE_OBSERVATIONS", "2")
    )
    if stable_observations < 2:
        raise RuntimeError("ZEEK_EOF_STABLE_OBSERVATIONS must be at least 2")
    retention_days = float(os.environ.get("ZEEK_RETENTION_DAYS", "7"))
    if not 1 <= retention_days <= 3_650:
        raise RuntimeError("ZEEK_RETENTION_DAYS must be from 1 to 3650")
    prune_interval = float(os.environ.get("ZEEK_PRUNE_INTERVAL", "60"))
    if not 1 <= prune_interval <= 86_400:
        raise RuntimeError("ZEEK_PRUNE_INTERVAL must be from 1 to 86400 seconds")
    prune_batch_size = int(os.environ.get("ZEEK_PRUNE_BATCH_SIZE", "1000"))
    if not 1 <= prune_batch_size <= MAX_PRUNE_BATCH_SIZE:
        raise RuntimeError(
            f"ZEEK_PRUNE_BATCH_SIZE must be from 1 to {MAX_PRUNE_BATCH_SIZE}"
        )
    prune_max_rows = int(os.environ.get("ZEEK_PRUNE_MAX_ROWS", "10000"))
    if not 3 <= prune_max_rows <= MAX_PRUNE_ROWS:
        raise RuntimeError(
            f"ZEEK_PRUNE_MAX_ROWS must be from 3 to {MAX_PRUNE_ROWS}"
        )
    return ZeekIngestSettings(
        conn_path=Path(
            os.environ.get("ZEEK_CONN_PATH", "/var/log/zeek/current/conn.log")
        ),
        index_path=Path(
            os.environ.get(
                "ZEEK_INDEX_PATH",
                "/var/lib/triagewall/zeek-context.db",
            )
        ),
        source_instance=os.environ.get("ZEEK_SOURCE_ID", "zeek-local"),
        poll_interval_seconds=poll_interval,
        max_records_per_poll=max_records,
        eof_stable_observations=stable_observations,
        archive_root=Path(os.environ.get("ZEEK_ARCHIVE_ROOT", "/var/log/zeek")),
        retention_seconds=retention_days * 24 * 60 * 60,
        prune_interval_seconds=prune_interval,
        prune_batch_size=prune_batch_size,
        prune_max_rows=prune_max_rows,
        evidence_paths=tuple(
            (
                log_name,
                Path(
                    os.environ.get(
                        f"ZEEK_{log_name.upper()}_PATH",
                        f"/var/log/zeek/current/{log_name}.log",
                    )
                ),
            )
            for log_name in ("dns", "http", "ssl", "x509", "files", "notice")
        ),
    )


def _handle_signal(signum, _frame) -> None:
    global _stop
    _stop = True
    log.info("Received signal %s, stopping Zeek ingest", signum)


def tail_zeek(settings: ZeekIngestSettings | None = None) -> int:
    """Run the local follower until stopped or a gap risk is detected."""

    global _stop
    _stop = False
    try:
        settings = settings or settings_from_environment()
        if not 3 <= settings.prune_max_rows <= MAX_PRUNE_ROWS:
            raise ValueError(
                f"prune_max_rows must be from 3 to {MAX_PRUNE_ROWS}"
            )
        follower = ZeekFollower(
            settings.conn_path,
            settings.source_instance,
            max_records_per_poll=settings.max_records_per_poll,
            eof_stable_observations=settings.eof_stable_observations,
            archive_root=settings.archive_root,
        )
        followers = [("conn", settings.conn_path, follower, True)]
        followers.extend(
            (
                log_name,
                path,
                ZeekFollower(
                    path,
                    settings.source_instance,
                    max_records_per_poll=settings.max_records_per_poll,
                    eof_stable_observations=settings.eof_stable_observations,
                    archive_root=settings.archive_root,
                    log_name=log_name,
                ),
                False,
            )
            for log_name, path in settings.evidence_paths
        )
        conn = connect_zeek_index(settings.index_path)
    except (OSError, RuntimeError, ValueError, sqlite3.Error) as exc:
        log.critical("Zeek ingest startup failed: %s", exc)
        return 1

    log.info("Starting Zeek log ingest")
    log.info("  source:   %s", settings.source_instance)
    log.info("  conn.log: %s", settings.conn_path)
    for log_name, path in settings.evidence_paths:
        log.info("  %-8s %s (optional until first observed)", f"{log_name}.log:", path)
    log.info("  index:    %s", settings.index_path)
    log.info("  archive:  %s", settings.archive_root)
    log.info(
        "  retention: %.2f days, prune every %.1fs (batch=%s max=%s)",
        settings.retention_seconds / (24 * 60 * 60),
        settings.prune_interval_seconds,
        settings.prune_batch_size,
        settings.prune_max_rows,
    )
    next_prune_at = 0.0
    next_follower = 0
    try:
        while not _stop:
            try:
                monotonic_now = time.monotonic()
                if monotonic_now >= next_prune_at:
                    cutoff = time.time() - settings.retention_seconds
                    pruned = prune_index(
                        conn,
                        cutoff,
                        batch_size=settings.prune_batch_size,
                        max_rows=settings.prune_max_rows,
                    )
                    pruned_total = (
                        pruned.connections + pruned.evidence + pruned.failures
                    )
                    backlog_possible = pruned_total >= settings.prune_max_rows
                    log.info(
                        "Zeek retention pruned connections=%s evidence=%s failures=%s "
                        "backlog_possible=%s",
                        pruned.connections,
                        pruned.evidence,
                        pruned.failures,
                        backlog_possible,
                    )
                    next_prune_at = monotonic_now + (
                        settings.poll_interval_seconds
                        if backlog_possible
                        else settings.prune_interval_seconds
                    )
                remaining = settings.max_records_per_poll
                ordered = followers[next_follower:] + followers[:next_follower]
                for log_name, path, current_follower, required in ordered:
                    if remaining <= 0:
                        break
                    if not required:
                        checkpoint = load_checkpoint(
                            conn,
                            settings.source_instance,
                            log_name,
                        )
                        try:
                            path.lstat()
                            present = True
                        except FileNotFoundError:
                            present = False
                        if not present and checkpoint is None:
                            continue
                    result = current_follower.poll(
                        conn,
                        record_limit=remaining,
                    )
                    remaining -= result.scanned
                    if result.scanned or result.rotated:
                        log.info(
                            "Zeek %s.log batch scanned=%s indexed=%s failures=%s rotated=%s",
                            log_name,
                            result.scanned,
                            result.indexed,
                            result.failures,
                            result.rotated,
                        )
                next_follower = (next_follower + 1) % len(followers)
            except (
                ZeekCheckpointConflict,
                ZeekConnValidationError,
                ZeekFollowerError,
                OSError,
                sqlite3.Error,
            ) as exc:
                log.critical(
                    "Zeek ingest stopped to prevent a context gap: %s",
                    exc,
                )
                return 1
            time.sleep(settings.poll_interval_seconds)
    finally:
        for _log_name, _path, current_follower, _required in followers:
            current_follower.close()
        conn.close()
    log.info("Zeek ingest stopped cleanly")
    return 0


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)
    return tail_zeek()


if __name__ == "__main__":
    sys.exit(main())
