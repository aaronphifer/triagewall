"""Transactional single-worker job queue for the standalone Lab."""

from __future__ import annotations

import re
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from triagewall.time_utils import format_utc_timestamp


_JOB_ID_RE = re.compile(r"^job-[0-9a-f]{32}$")
TERMINAL_STATES = frozenset({"completed", "failed", "canceled"})


class LabJobError(ValueError):
    """Raised when a requested job transition is invalid or over quota."""


def _utc_now() -> str:
    return format_utc_timestamp(datetime.now(timezone.utc))


class LabJobRepository:
    def __init__(self, path: Path, *, max_pending_jobs: int = 4) -> None:
        self.path = path
        self.max_pending_jobs = max_pending_jobs

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with closing(self._connect()) as connection, connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS lab_jobs (
                    job_id TEXT PRIMARY KEY,
                    experiment_id TEXT NOT NULL,
                    experiment_sha256 TEXT NOT NULL,
                    state TEXT NOT NULL CHECK (
                        state IN ('queued', 'running', 'completed', 'failed', 'canceled')
                    ),
                    requested_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK (
                        cancel_requested IN (0, 1)
                    ),
                    worker_id TEXT,
                    lease_expires_at REAL,
                    run_name TEXT,
                    result_count INTEGER NOT NULL DEFAULT 0,
                    report_digest TEXT,
                    failure_code TEXT,
                    failure_detail TEXT
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_lab_jobs_state_created "
                "ON lab_jobs(state, created_at, job_id)"
            )

    @staticmethod
    def _summary(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["job_id"],
            "experiment_id": row["experiment_id"],
            "experiment_digest": row["experiment_sha256"],
            "state": row["state"],
            "requested_by": row["requested_by"],
            "created_at": row["created_at"],
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
            "cancel_requested": bool(row["cancel_requested"]),
            "result_count": row["result_count"],
            "report_digest": row["report_digest"],
            "failure_code": row["failure_code"],
            "failure_detail": row["failure_detail"],
        }

    def enqueue(self, *, experiment: dict[str, str], requested_by: str) -> dict[str, Any]:
        now = _utc_now()
        job_id = "job-" + uuid.uuid4().hex
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            pending = connection.execute(
                "SELECT COUNT(*) FROM lab_jobs WHERE state IN ('queued', 'running')"
            ).fetchone()[0]
            if pending >= self.max_pending_jobs:
                raise LabJobError("Lab pending-job limit reached")
            duplicate = connection.execute(
                "SELECT 1 FROM lab_jobs WHERE experiment_sha256 = ? "
                "AND state IN ('queued', 'running') LIMIT 1",
                (experiment["sha256"],),
            ).fetchone()
            if duplicate is not None:
                raise LabJobError("this exact experiment is already queued or running")
            connection.execute(
                """
                INSERT INTO lab_jobs (
                    job_id, experiment_id, experiment_sha256, state,
                    requested_by, created_at
                ) VALUES (?, ?, ?, 'queued', ?, ?)
                """,
                (job_id, experiment["id"], experiment["sha256"], requested_by, now),
            )
            row = connection.execute(
                "SELECT * FROM lab_jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
        return self._summary(row)

    def list_jobs(self, *, limit: int = 100) -> list[dict[str, Any]]:
        bounded = min(max(limit, 1), 500)
        with closing(self._connect()) as connection, connection:
            rows = connection.execute(
                "SELECT * FROM lab_jobs ORDER BY created_at DESC, job_id DESC LIMIT ?",
                (bounded,),
            ).fetchall()
        return [self._summary(row) for row in rows]

    def get(self, job_id: str) -> dict[str, Any] | None:
        if _JOB_ID_RE.fullmatch(job_id) is None:
            return None
        with closing(self._connect()) as connection, connection:
            row = connection.execute(
                "SELECT * FROM lab_jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
        return self._summary(row) if row is not None else None

    def cancel(self, job_id: str) -> dict[str, Any]:
        if _JOB_ID_RE.fullmatch(job_id) is None:
            raise LabJobError("unknown Lab job")
        now = _utc_now()
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM lab_jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
            if row is None:
                raise LabJobError("unknown Lab job")
            if row["state"] in TERMINAL_STATES:
                raise LabJobError("Lab job is already finished")
            if row["state"] == "queued":
                connection.execute(
                    "UPDATE lab_jobs SET state = 'canceled', cancel_requested = 1, "
                    "completed_at = ? WHERE job_id = ? AND state = 'queued'",
                    (now, job_id),
                )
            else:
                connection.execute(
                    "UPDATE lab_jobs SET cancel_requested = 1 "
                    "WHERE job_id = ? AND state = 'running'",
                    (job_id,),
                )
            updated = connection.execute(
                "SELECT * FROM lab_jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
        return self._summary(updated)

    def claim_next(
        self,
        *,
        worker_id: str,
        now_epoch: float,
        lease_seconds: float,
    ) -> dict[str, Any] | None:
        if not worker_id or len(worker_id) > 128:
            raise LabJobError("worker identity is invalid")
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                UPDATE lab_jobs
                SET state = 'failed', completed_at = ?, failure_code = 'worker_interrupted',
                    failure_detail = 'Worker lease expired before the run completed.',
                    worker_id = NULL, lease_expires_at = NULL
                WHERE state = 'running' AND lease_expires_at < ?
                """,
                (_utc_now(), now_epoch),
            )
            running = connection.execute(
                "SELECT 1 FROM lab_jobs WHERE state = 'running' LIMIT 1"
            ).fetchone()
            if running is not None:
                return None
            row = connection.execute(
                "SELECT * FROM lab_jobs WHERE state = 'queued' "
                "ORDER BY created_at, job_id LIMIT 1"
            ).fetchone()
            if row is None:
                return None
            run_name = row["job_id"]
            changed = connection.execute(
                """
                UPDATE lab_jobs
                SET state = 'running', started_at = ?, worker_id = ?,
                    lease_expires_at = ?, run_name = ?
                WHERE job_id = ? AND state = 'queued'
                """,
                (
                    _utc_now(),
                    worker_id,
                    now_epoch + lease_seconds,
                    run_name,
                    row["job_id"],
                ),
            ).rowcount
            if changed != 1:
                return None
            claimed = connection.execute(
                "SELECT * FROM lab_jobs WHERE job_id = ?", (row["job_id"],)
            ).fetchone()
        return self._summary(claimed)

    def heartbeat(
        self,
        job_id: str,
        *,
        worker_id: str,
        now_epoch: float,
        lease_seconds: float,
        result_count: int,
    ) -> bool:
        with closing(self._connect()) as connection, connection:
            changed = connection.execute(
                """
                UPDATE lab_jobs SET lease_expires_at = ?, result_count = ?
                WHERE job_id = ? AND state = 'running' AND worker_id = ?
                """,
                (now_epoch + lease_seconds, result_count, job_id, worker_id),
            ).rowcount
        return changed == 1

    def cancellation_requested(self, job_id: str, *, worker_id: str) -> bool:
        with closing(self._connect()) as connection, connection:
            row = connection.execute(
                "SELECT cancel_requested FROM lab_jobs "
                "WHERE job_id = ? AND state = 'running' AND worker_id = ?",
                (job_id, worker_id),
            ).fetchone()
        return row is None or bool(row[0])

    def _finish(
        self,
        job_id: str,
        *,
        worker_id: str,
        state: str,
        result_count: int,
        report_digest: str | None = None,
        failure_code: str | None = None,
        failure_detail: str | None = None,
    ) -> None:
        if state not in TERMINAL_STATES:
            raise LabJobError("invalid terminal state")
        with closing(self._connect()) as connection, connection:
            changed = connection.execute(
                """
                UPDATE lab_jobs SET state = ?, completed_at = ?, result_count = ?,
                    report_digest = ?, failure_code = ?, failure_detail = ?,
                    worker_id = NULL, lease_expires_at = NULL
                WHERE job_id = ? AND state = 'running' AND worker_id = ?
                """,
                (
                    state,
                    _utc_now(),
                    result_count,
                    report_digest,
                    failure_code,
                    failure_detail[:300] if failure_detail else None,
                    job_id,
                    worker_id,
                ),
            ).rowcount
        if changed != 1:
            raise LabJobError("worker no longer owns the Lab job")

    def complete(
        self,
        job_id: str,
        *,
        worker_id: str,
        result_count: int,
        report_digest: str,
    ) -> None:
        self._finish(
            job_id,
            worker_id=worker_id,
            state="completed",
            result_count=result_count,
            report_digest=report_digest,
        )

    def fail(
        self,
        job_id: str,
        *,
        worker_id: str,
        result_count: int,
        failure_code: str,
        failure_detail: str,
    ) -> None:
        self._finish(
            job_id,
            worker_id=worker_id,
            state="failed",
            result_count=result_count,
            failure_code=failure_code,
            failure_detail=failure_detail,
        )

    def finish_canceled(
        self,
        job_id: str,
        *,
        worker_id: str,
        result_count: int,
    ) -> None:
        self._finish(
            job_id,
            worker_id=worker_id,
            state="canceled",
            result_count=result_count,
        )

    def terminal_before(self, completed_before: str, *, limit: int = 10) -> list[dict[str, Any]]:
        with closing(self._connect()) as connection, connection:
            rows = connection.execute(
                """
                SELECT * FROM lab_jobs
                WHERE state IN ('completed', 'failed', 'canceled')
                  AND completed_at < ?
                ORDER BY completed_at, job_id LIMIT ?
                """,
                (completed_before, min(max(limit, 1), 100)),
            ).fetchall()
        return [dict(row) for row in rows]

    def delete_terminal(self, job_id: str) -> bool:
        with closing(self._connect()) as connection, connection:
            changed = connection.execute(
                "DELETE FROM lab_jobs WHERE job_id = ? "
                "AND state IN ('completed', 'failed', 'canceled')",
                (job_id,),
            ).rowcount
        return changed == 1
