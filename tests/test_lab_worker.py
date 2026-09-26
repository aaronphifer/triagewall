import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace

from scripts.build_lab_experiment_2 import build_documents
from triagewall.event_bundle import canonical_json, load_event_bundle_bytes
from triagewall.lab.worker import LabWorker, LabWorkerSettings


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "lab_scenarios" / "zeek-evidence-v1.json"


class FakeTransport:
    def verify_model(self, name, digest, timeout):
        del name, digest, timeout

    def generate(self, payload, timeout):
        del timeout
        return {
            "model": payload["model"],
            "response": json.dumps({
                "verdict": "real",
                "confidence": 0.8,
                "reasoning": "The Suricata evidence remains suspicious.",
            }),
        }


class CancelingTransport(FakeTransport):
    def __init__(self, cancel):
        self.calls = 0
        self.cancel = cancel

    def generate(self, payload, timeout):
        self.calls += 1
        response = super().generate(payload, timeout)
        if self.calls == 2:
            self.cancel()
        return response


class LabWorkerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle_bytes = FIXTURE.read_bytes()
        cls.bundle = load_event_bundle_bytes(cls.bundle_bytes)
        args = SimpleNamespace(
            temperature=0.2, num_predict=512, num_ctx=4096, model_seed=None,
            repetitions=1, execution_order_seed=42,
            baseline_id="worker-baseline", candidate_id="worker-candidate",
            experiment_id="worker-experiment", author="worker-test",
            model_name="fixture-model", model_digest="sha256:" + "a" * 64,
        )
        cls.baseline, cls.candidate, cls.experiment = build_documents(args, cls.bundle)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.settings = LabWorkerSettings(
            data_root=Path(self.temp.name), ollama_url="http://127.0.0.1:11434",
            request_timeout_seconds=1, max_results_per_job=1000,
            storage_quota_bytes=64 * 1024 * 1024,
        )

    def tearDown(self):
        self.temp.cleanup()

    def make_worker(self, factory=lambda _url: FakeTransport()):
        worker = LabWorker(self.settings, transport_factory=factory)
        worker.initialize()
        worker.store.import_bundle(self.bundle_bytes)
        for document in (self.baseline, self.candidate):
            worker.store.import_contract(
                "triagewall.lab-candidate",
                (canonical_json(document) + "\n").encode(),
            )
        worker.store.import_contract(
            "triagewall.lab-experiment",
            (canonical_json(self.experiment) + "\n").encode(),
        )
        return worker

    def enqueue(self, worker):
        return worker.jobs.enqueue(
            experiment={
                "id": self.experiment["experiment_id"],
                "sha256": self.experiment["content_sha256"],
            },
            requested_by="worker-test",
        )

    def test_complete_job_publishes_manifest_results_and_aggregate_report(self):
        worker = self.make_worker()
        job = self.enqueue(worker)
        self.assertTrue(worker.run_once())
        finished = worker.jobs.get(job["id"])
        self.assertEqual(finished["state"], "completed")
        self.assertEqual(finished["result_count"], 45)
        self.assertTrue(finished["report_digest"].startswith("sha256:"))
        self.assertEqual(len(worker.store.list_results(limit=100)), 45)
        reports = worker.store.list_reports()
        self.assertEqual(len(reports), 1)
        self.assertTrue(reports[0]["does_not_authorize_production"])

    def test_cooperative_cancel_leaves_partial_run_hidden(self):
        holder = {}

        def factory(_url):
            return CancelingTransport(lambda: holder["worker"].jobs.cancel(holder["job"]["id"]))

        worker = self.make_worker(factory)
        job = self.enqueue(worker)
        holder.update(worker=worker, job=job)
        worker.run_once()
        finished = worker.jobs.get(job["id"])
        self.assertEqual(finished["state"], "canceled")
        self.assertEqual(worker.store.list_results(), [])
        self.assertEqual(worker.store.list_reports(), [])

    def test_result_limit_fails_job_without_publishing_partial_evidence(self):
        limited = LabWorkerSettings(
            data_root=Path(self.temp.name), ollama_url="http://127.0.0.1:11434",
            request_timeout_seconds=1, max_results_per_job=1,
            storage_quota_bytes=64 * 1024 * 1024,
        )
        self.settings = limited
        worker = self.make_worker()
        job = self.enqueue(worker)
        worker.run_once()
        finished = worker.jobs.get(job["id"])
        self.assertEqual(finished["state"], "failed")
        self.assertEqual(finished["failure_code"], "execution_failed")
        self.assertEqual(worker.store.list_results(), [])

    def test_retention_removes_only_safe_old_terminal_run_directories(self):
        worker = self.make_worker()
        job = self.enqueue(worker)
        worker.jobs.claim_next(
            worker_id=worker.worker_id, now_epoch=100, lease_seconds=30
        )
        run_dir = worker.store.create_run_directory(job["id"])
        (run_dir / "partial.json").write_text("{}", encoding="utf-8")
        worker.jobs.fail(
            job["id"], worker_id=worker.worker_id, result_count=0,
            failure_code="test", failure_detail="test",
        )
        with closing(sqlite3.connect(worker.jobs.path)) as connection, connection:
            connection.execute(
                "UPDATE lab_jobs SET completed_at = ? WHERE job_id = ?",
                ("2000-01-01T00:00:00.000000Z", job["id"]),
            )
        self.assertEqual(worker.prune_terminal_runs(), 1)
        self.assertFalse(run_dir.exists())
        self.assertIsNone(worker.jobs.get(job["id"]))

        unsafe = self.enqueue(worker)
        worker.jobs.claim_next(
            worker_id=worker.worker_id, now_epoch=200, lease_seconds=30
        )
        unsafe_dir = worker.store.create_run_directory(unsafe["id"])
        (unsafe_dir / "nested").mkdir()
        worker.jobs.fail(
            unsafe["id"], worker_id=worker.worker_id, result_count=0,
            failure_code="test", failure_detail="test",
        )
        with closing(sqlite3.connect(worker.jobs.path)) as connection, connection:
            connection.execute(
                "UPDATE lab_jobs SET completed_at = ? WHERE job_id = ?",
                ("2000-01-01T00:00:00.000000Z", unsafe["id"]),
            )
        self.assertEqual(worker.prune_terminal_runs(), 0)
        self.assertTrue(unsafe_dir.exists())
        self.assertIsNotNone(worker.jobs.get(unsafe["id"]))


if __name__ == "__main__":
    unittest.main()
