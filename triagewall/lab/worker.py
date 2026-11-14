"""Dedicated, bounded model worker for standalone TriageWall Lab jobs."""

from __future__ import annotations

import logging
import os
import signal
import stat
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from triagewall.event_bundle import canonical_json
from triagewall.lab.jobs import LabJobError, LabJobRepository
from triagewall.lab.store import LabStore, LabStoreError
from triagewall.lab_contracts import PROMOTION_REPORT_SCHEMA, result_set_digest
from triagewall.lab_reporting import build_promotion_report
from triagewall.lab_runner import ModelTransport, OllamaTransport, run_experiment
from triagewall.time_utils import format_utc_timestamp


LOGGER = logging.getLogger(__name__)


def _env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _env_float(name: str, default: float, *, minimum: float, maximum: float) -> float:
    raw = os.environ.get(name, str(default))
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be numeric") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


@dataclass(frozen=True)
class LabWorkerSettings:
    data_root: Path
    ollama_url: str
    request_timeout_seconds: float = 300.0
    poll_interval_seconds: float = 2.0
    max_results_per_job: int = 1_000
    storage_quota_bytes: int = 10 * 1024 * 1024 * 1024
    retention_days: int = 30
    retention_batch_size: int = 10

    @classmethod
    def from_env(cls) -> "LabWorkerSettings":
        return cls(
            data_root=Path(
                os.environ.get("TRIAGEWALL_LAB_DATA_DIR", "/var/lib/triagewall-lab")
            ),
            ollama_url=os.environ.get(
                "TRIAGEWALL_LAB_OLLAMA_URL", "http://127.0.0.1:11434"
            ).strip(),
            request_timeout_seconds=_env_float(
                "TRIAGEWALL_LAB_REQUEST_TIMEOUT_SECONDS", 300, minimum=1, maximum=3600
            ),
            poll_interval_seconds=_env_float(
                "TRIAGEWALL_LAB_POLL_INTERVAL_SECONDS", 2, minimum=0.1, maximum=60
            ),
            max_results_per_job=_env_int(
                "TRIAGEWALL_LAB_MAX_RESULTS_PER_JOB", 1_000, minimum=1, maximum=60_000
            ),
            storage_quota_bytes=_env_int(
                "TRIAGEWALL_LAB_STORAGE_QUOTA_BYTES",
                10 * 1024 * 1024 * 1024,
                minimum=64 * 1024 * 1024,
                maximum=10 * 1024 * 1024 * 1024 * 1024,
            ),
            retention_days=_env_int(
                "TRIAGEWALL_LAB_RETENTION_DAYS", 30, minimum=1, maximum=3650
            ),
            retention_batch_size=_env_int(
                "TRIAGEWALL_LAB_RETENTION_BATCH_SIZE", 10, minimum=1, maximum=100
            ),
        )


class LabWorker:
    def __init__(
        self,
        settings: LabWorkerSettings,
        *,
        transport_factory: Callable[[str], ModelTransport] = OllamaTransport,
        epoch: Callable[[], float] = time.time,
    ) -> None:
        self.settings = settings
        self.store = LabStore(
            settings.data_root, quota_bytes=settings.storage_quota_bytes
        )
        self.jobs = LabJobRepository(settings.data_root / "lab-jobs.db")
        self.transport_factory = transport_factory
        self.epoch = epoch
        self.worker_id = "worker-" + uuid.uuid4().hex
        # Covers model verification plus one complete atomic paired comparison.
        self.lease_seconds = max(300.0, settings.request_timeout_seconds * 6 + 60)

    def initialize(self) -> None:
        self.store.initialize()
        self.jobs.initialize()

    def run_once(self) -> bool:
        job = self.jobs.claim_next(
            worker_id=self.worker_id,
            now_epoch=self.epoch(),
            lease_seconds=self.lease_seconds,
        )
        if job is None:
            return False
        self._execute(job)
        return True

    def _execute(self, job: dict) -> None:
        count = 0
        try:
            experiment = self.store.load_document(
                "experiments", job["experiment_digest"]
            )
            if experiment["experiment_id"] != job["experiment_id"]:
                raise LabStoreError("queued experiment identity does not match its digest")
            bundle = self.store.load_document("bundles", experiment["bundle"]["sha256"])
            baseline = self.store.load_document(
                "candidates", experiment["baseline_candidate"]["sha256"]
            )
            candidate = self.store.load_document(
                "candidates", experiment["candidate"]["sha256"]
            )
            selected_count = len(experiment["event_ids"] or bundle["events"])
            expected = (
                selected_count
                * len(experiment["evidence_conditions"])
                * experiment["repetitions"]
            )
            if expected > self.settings.max_results_per_job:
                raise LabStoreError("experiment exceeds the configured result limit")
            run_dir = self.store.create_run_directory(job["id"])
            results = []
            transport = self.transport_factory(self.settings.ollama_url)
            for result in run_experiment(
                bundle=bundle,
                baseline=baseline,
                candidate=candidate,
                experiment=experiment,
                transport=transport,
                timeout=self.settings.request_timeout_seconds,
            ):
                if self.jobs.cancellation_requested(
                    job["id"], worker_id=self.worker_id
                ):
                    self.jobs.finish_canceled(
                        job["id"], worker_id=self.worker_id, result_count=count
                    )
                    return
                self.store.publish_result(run_dir, result)
                results.append(result)
                count += 1
                if not self.jobs.heartbeat(
                    job["id"],
                    worker_id=self.worker_id,
                    now_epoch=self.epoch(),
                    lease_seconds=self.lease_seconds,
                    result_count=count,
                ):
                    raise LabJobError("worker no longer owns the Lab job")
            if self.jobs.cancellation_requested(job["id"], worker_id=self.worker_id):
                self.jobs.finish_canceled(
                    job["id"], worker_id=self.worker_id, result_count=count
                )
                return
            manifest = {
                "schema": "triagewall.lab-private-run-completion",
                "version": 1,
                "experiment": {
                    "id": experiment["experiment_id"],
                    "sha256": experiment["content_sha256"],
                },
                "bundle": dict(experiment["bundle"]),
                "paired_result_count": len(results),
                "nonaccepted_outcome_count": sum(
                    result[side]["validation_status"] != "accepted"
                    for result in results
                    for side in ("baseline", "candidate")
                ),
                "result_set_sha256": result_set_digest(
                    [result["content_sha256"] for result in results]
                ),
            }
            self.store.publish_manifest(run_dir, manifest)
            report = build_promotion_report(
                bundle=bundle, experiment=experiment, results=results
            )
            stored = self.store.import_contract(
                PROMOTION_REPORT_SCHEMA,
                (canonical_json(report) + "\n").encode("utf-8"),
            )
            self.jobs.complete(
                job["id"],
                worker_id=self.worker_id,
                result_count=count,
                report_digest=stored["digest"],
            )
        except LabJobError:
            # A lost lease must never let a stale worker mutate current job state.
            LOGGER.warning("Lab worker lost ownership of job %s", job["id"])
        except Exception as exc:
            LOGGER.warning("Lab job %s failed: %s", job["id"], type(exc).__name__)
            try:
                self.jobs.fail(
                    job["id"],
                    worker_id=self.worker_id,
                    result_count=count,
                    failure_code="execution_failed",
                    failure_detail="The bounded Lab run failed; inspect worker logs for the error class.",
                )
            except LabJobError:
                LOGGER.warning("Lab worker could not publish failure for job %s", job["id"])

    def prune_terminal_runs(self) -> int:
        cutoff = format_utc_timestamp(
            datetime.now(timezone.utc) - timedelta(days=self.settings.retention_days)
        )
        removed = 0
        runs_root = (self.store.root / "runs").resolve()
        for job in self.jobs.terminal_before(
            cutoff, limit=self.settings.retention_batch_size
        ):
            run_dir = runs_root / job["run_name"] if job["run_name"] else None
            if run_dir is not None and run_dir.parent == runs_root and run_dir.exists():
                metadata = run_dir.lstat()
                if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                    continue
                safe = True
                children = list(run_dir.iterdir())
                for child in children:
                    mode = child.lstat().st_mode
                    if not stat.S_ISREG(mode) or stat.S_ISLNK(mode):
                        safe = False
                        break
                if not safe:
                    continue
                for child in children:
                    child.unlink()
                run_dir.rmdir()
            report_digest = job["report_digest"]
            if report_digest:
                report_path = self.store._artifact_path("reports", report_digest)
                if report_path.exists():
                    mode = report_path.lstat().st_mode
                    if not stat.S_ISREG(mode) or stat.S_ISLNK(mode):
                        continue
                    report_path.unlink()
            if self.jobs.delete_terminal(job["job_id"]):
                removed += 1
        return removed


def main() -> int:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    worker = LabWorker(LabWorkerSettings.from_env())
    worker.initialize()
    stopping = False

    def stop(_signum, _frame) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    last_prune = 0.0
    while not stopping:
        worked = worker.run_once()
        now = time.monotonic()
        if now - last_prune >= 60:
            worker.prune_terminal_runs()
            last_prune = now
        if not worked:
            time.sleep(worker.settings.poll_interval_seconds)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
