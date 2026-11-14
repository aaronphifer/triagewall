import tempfile
import unittest
from pathlib import Path

from triagewall.lab.jobs import LabJobError, LabJobRepository


EXPERIMENT = {"id": "experiment-one", "sha256": "sha256:" + "a" * 64}


class LabJobRepositoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.repo = LabJobRepository(Path(self.temp.name) / "jobs.db", max_pending_jobs=2)
        self.repo.initialize()

    def tearDown(self):
        self.temp.cleanup()

    def test_queue_is_bounded_and_rejects_duplicate_active_digest(self):
        first = self.repo.enqueue(experiment=EXPERIMENT, requested_by="operator")
        self.assertEqual(first["state"], "queued")
        with self.assertRaisesRegex(LabJobError, "already queued"):
            self.repo.enqueue(experiment=EXPERIMENT, requested_by="operator")
        self.repo.enqueue(
            experiment={"id": "experiment-two", "sha256": "sha256:" + "b" * 64},
            requested_by="operator",
        )
        with self.assertRaisesRegex(LabJobError, "pending-job limit"):
            self.repo.enqueue(
                experiment={"id": "experiment-three", "sha256": "sha256:" + "c" * 64},
                requested_by="operator",
            )

    def test_single_claim_lease_heartbeat_and_owner_compare_and_swap(self):
        queued = self.repo.enqueue(experiment=EXPERIMENT, requested_by="operator")
        claimed = self.repo.claim_next(worker_id="worker-a", now_epoch=100, lease_seconds=30)
        self.assertEqual(claimed["id"], queued["id"])
        self.assertIsNone(
            self.repo.claim_next(worker_id="worker-b", now_epoch=101, lease_seconds=30)
        )
        self.assertTrue(
            self.repo.heartbeat(
                queued["id"], worker_id="worker-a", now_epoch=110,
                lease_seconds=30, result_count=3,
            )
        )
        with self.assertRaisesRegex(LabJobError, "no longer owns"):
            self.repo.complete(
                queued["id"], worker_id="worker-b", result_count=3,
                report_digest="sha256:" + "d" * 64,
            )

    def test_cancel_queued_is_terminal_and_running_is_cooperative(self):
        queued = self.repo.enqueue(experiment=EXPERIMENT, requested_by="operator")
        canceled = self.repo.cancel(queued["id"])
        self.assertEqual(canceled["state"], "canceled")
        second = self.repo.enqueue(experiment=EXPERIMENT, requested_by="operator")
        self.repo.claim_next(worker_id="worker-a", now_epoch=100, lease_seconds=30)
        requested = self.repo.cancel(second["id"])
        self.assertEqual(requested["state"], "running")
        self.assertTrue(requested["cancel_requested"])
        self.assertTrue(
            self.repo.cancellation_requested(second["id"], worker_id="worker-a")
        )
        self.repo.finish_canceled(second["id"], worker_id="worker-a", result_count=1)
        self.assertEqual(self.repo.get(second["id"])["state"], "canceled")

    def test_expired_worker_is_failed_before_next_job_is_claimed(self):
        first = self.repo.enqueue(experiment=EXPERIMENT, requested_by="operator")
        self.repo.claim_next(worker_id="worker-a", now_epoch=100, lease_seconds=10)
        second = self.repo.enqueue(
            experiment={"id": "experiment-two", "sha256": "sha256:" + "b" * 64},
            requested_by="operator",
        )
        claimed = self.repo.claim_next(worker_id="worker-b", now_epoch=111, lease_seconds=10)
        self.assertEqual(claimed["id"], second["id"])
        recovered = self.repo.get(first["id"])
        self.assertEqual(recovered["state"], "failed")
        self.assertEqual(recovered["failure_code"], "worker_interrupted")

    def test_terminal_retention_delete_is_state_guarded(self):
        queued = self.repo.enqueue(experiment=EXPERIMENT, requested_by="operator")
        self.assertFalse(self.repo.delete_terminal(queued["id"]))
        self.repo.cancel(queued["id"])
        rows = self.repo.terminal_before("9999-12-31T23:59:59.999999Z", limit=10)
        self.assertEqual([row["job_id"] for row in rows], [queued["id"]])
        self.assertTrue(self.repo.delete_terminal(queued["id"]))
        self.assertIsNone(self.repo.get(queued["id"]))


if __name__ == "__main__":
    unittest.main()
