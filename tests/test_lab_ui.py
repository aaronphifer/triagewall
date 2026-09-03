"""Standalone Lab UI authentication, storage, and isolation regressions."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from fastapi.testclient import TestClient
import yaml


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "lab_scenarios" / "zeek-evidence-v1.json"
PLAINTEXT_KEY = "lab-test-access-key-with-enough-entropy"

# The production module deliberately fails closed without credentials. Supply a
# valid throwaway configuration before importing its app factory.
os.environ.setdefault("TRIAGEWALL_LAB_OPERATOR", "module-test-operator")
os.environ.setdefault(
    "TRIAGEWALL_LAB_API_KEY_HASH",
    "pbkdf2_sha256$100000$30313233343536373839616263646566$"
    "98d0049ec8c3d667a86c11e6d0f9a16ee98868d66dc8e2355f32d5e810d8d7fe",
)
os.environ.setdefault("TRIAGEWALL_LAB_SESSION_SECRET", "module-test-secret-" * 3)

from scripts.build_lab_experiment_2 import build_documents
from triagewall.event_bundle import canonical_json, load_event_bundle_bytes
from triagewall.lab.app import create_app
from triagewall.lab.auth import LabAuthSettings, hash_lab_api_key
from triagewall.lab.store import COMPLETE_MANIFEST
from triagewall.lab_contracts import REQUIRED_GATE_IDS, content_digest, result_set_digest
from triagewall.lab_runner import run_experiment


class FakeTransport:
    def verify_model(self, name, digest, timeout):
        del name, digest, timeout

    def generate(self, payload, timeout):
        del timeout
        return {
            "model": payload["model"],
            "response": json.dumps(
                {
                    "verdict": "real",
                    "confidence": 0.8,
                    "reasoning": "The alert remains suspicious based on Suricata evidence.",
                }
            ),
        }


class LabUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle_bytes = FIXTURE.read_bytes()
        cls.bundle = load_event_bundle_bytes(cls.bundle_bytes)
        args = SimpleNamespace(
            temperature=0.2,
            num_predict=512,
            num_ctx=4096,
            model_seed=None,
            repetitions=1,
            execution_order_seed=42,
            baseline_id="ui-test-baseline",
            candidate_id="ui-test-candidate",
            experiment_id="ui-test-experiment",
            author="ui-test-operator",
            model_name="fixture-model",
            model_digest="sha256:" + "a" * 64,
        )
        cls.baseline, cls.candidate, cls.experiment = build_documents(args, cls.bundle)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        settings = LabAuthSettings(
            operator_name="ui-test-operator",
            api_key_hash=hash_lab_api_key(
                PLAINTEXT_KEY,
                iterations=100_000,
                salt=b"0123456789abcdef",
            ),
            session_secret="test-session-secret-" * 3,
        )
        self.app = create_app(
            auth_settings=settings,
            data_root=Path(self.temp.name),
            trusted_hosts=frozenset({"localhost", "testserver"}),
        )
        self.client_context = TestClient(self.app)
        self.client = self.client_context.__enter__()

    def tearDown(self):
        self.client_context.__exit__(None, None, None)
        self.temp.cleanup()

    def login(self):
        response = self.client.post("/api/v1/session", json={"api_key": PLAINTEXT_KEY})
        self.assertEqual(response.status_code, 200, response.text)
        return response

    def import_contract(self, kind, document):
        return self.client.post(
            f"/api/v1/{kind}",
            content=(canonical_json(document) + "\n").encode(),
            headers={
                "content-type": "application/json",
                "X-TriageWall-Lab-Request": "1",
            },
        )

    def install_inputs(self):
        self.login()
        headers = {"X-TriageWall-Lab-Request": "1", "content-type": "application/json"}
        self.assertEqual(
            self.client.post("/api/v1/bundles", content=self.bundle_bytes, headers=headers).status_code,
            200,
        )
        for document in (self.baseline, self.candidate):
            self.assertEqual(self.import_contract("candidates", document).status_code, 200)
        self.assertEqual(self.import_contract("experiments", self.experiment).status_code, 200)

    def publish_complete_run(self):
        results = list(
            run_experiment(
                bundle=self.bundle,
                baseline=self.baseline,
                candidate=self.candidate,
                experiment=self.experiment,
                transport=FakeTransport(),
                timeout=1,
            )
        )
        run_dir = Path(self.temp.name) / "runs" / "ui-test-run"
        run_dir.mkdir()
        for result in results:
            (run_dir / f"{result['result_id']}.json").write_text(
                canonical_json(result) + "\n",
                encoding="utf-8",
            )
        manifest = {
            "schema": "triagewall.lab-private-run-completion",
            "version": 1,
            "experiment": {
                "id": self.experiment["experiment_id"],
                "sha256": self.experiment["content_sha256"],
            },
            "bundle": dict(self.experiment["bundle"]),
            "paired_result_count": len(results),
            "nonaccepted_outcome_count": 0,
            "result_set_sha256": result_set_digest(
                [result["content_sha256"] for result in results]
            ),
        }
        (run_dir / COMPLETE_MANIFEST).write_text(
            json.dumps(manifest),
            encoding="utf-8",
        )
        return results, manifest

    def test_all_lab_data_apis_require_login_and_wrong_key_is_rejected(self):
        for path in ("status", "bundles", "candidates", "experiments", "jobs", "results", "reports"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(f"/api/v1/{path}").status_code, 401)
        self.assertEqual(
            self.client.post("/api/v1/session", json={"api_key": "wrong"}).status_code,
            401,
        )

    def test_login_uses_httponly_strict_cookie_and_security_headers(self):
        response = self.login()
        cookie = response.headers["set-cookie"].lower()
        self.assertIn("httponly", cookie)
        self.assertIn("samesite=strict", cookie)
        page = self.client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertEqual(page.headers["x-frame-options"], "DENY")
        self.assertIn("frame-ancestors 'none'", page.headers["content-security-policy"])
        self.assertEqual(page.headers["cache-control"], "no-store")

    def test_logout_revokes_the_server_side_session(self):
        response = self.login()
        stolen = response.cookies.get("tw_lab_session")
        logged_out = self.client.delete(
            "/api/v1/session",
            headers={"X-TriageWall-Lab-Request": "1"},
        )
        self.assertEqual(logged_out.status_code, 200)
        self.client.cookies.set("tw_lab_session", stolen)
        self.assertEqual(self.client.get("/api/v1/status").status_code, 401)

    def test_login_throttles_repeated_failures_and_rejects_duplicate_fields(self):
        duplicate = self.client.post(
            "/api/v1/session",
            content=b'{"api_key":"first","api_key":"second"}',
            headers={"content-type": "application/json"},
        )
        self.assertEqual(duplicate.status_code, 401)
        for _ in range(4):
            self.assertEqual(
                self.client.post("/api/v1/session", json={"api_key": "wrong"}).status_code,
                401,
            )
        limited = self.client.post("/api/v1/session", json={"api_key": PLAINTEXT_KEY})
        self.assertEqual(limited.status_code, 429)
        self.assertEqual(limited.headers["retry-after"], "60")

    def test_mutations_require_csrf_header_and_never_overwrite_artifacts(self):
        self.login()
        denied = self.client.post(
            "/api/v1/bundles",
            content=self.bundle_bytes,
            headers={"content-type": "application/json"},
        )
        self.assertEqual(denied.status_code, 403)
        headers = {"X-TriageWall-Lab-Request": "1", "content-type": "application/json"}
        first = self.client.post("/api/v1/bundles", content=self.bundle_bytes, headers=headers)
        second = self.client.post("/api/v1/bundles", content=self.bundle_bytes, headers=headers)
        self.assertTrue(first.json()["created"])
        self.assertFalse(second.json()["created"])
        self.assertEqual(len(list((Path(self.temp.name) / "bundles").glob("*.json"))), 1)

    def test_experiment_fails_closed_until_exact_references_are_installed(self):
        self.login()
        missing = self.import_contract("experiments", self.experiment)
        self.assertEqual(missing.status_code, 422)
        self.assertIn("bundle is not installed", missing.json()["detail"])
        self.install_inputs()
        items = self.client.get("/api/v1/experiments").json()["items"]
        self.assertEqual(items[0]["id"], "ui-test-experiment")
        self.assertEqual(items[0]["completed_runs"], 0)

    def test_run_queue_requires_exact_digest_confirmation_and_supports_cancel(self):
        self.install_inputs()
        digest = self.experiment["content_sha256"][7:]
        headers = {"X-TriageWall-Lab-Request": "1", "content-type": "application/json"}
        denied = self.client.post(
            f"/api/v1/experiments/{digest}/runs",
            json={"confirm_experimental": True},
        )
        self.assertEqual(denied.status_code, 403)
        malformed = self.client.post(
            f"/api/v1/experiments/{digest}/runs",
            content=b'{"confirm_experimental":true,"extra":true}', headers=headers,
        )
        self.assertEqual(malformed.status_code, 422)
        queued = self.client.post(
            f"/api/v1/experiments/{digest}/runs",
            json={"confirm_experimental": True}, headers=headers,
        )
        self.assertEqual(queued.status_code, 202, queued.text)
        self.assertEqual(queued.json()["experiment_digest"], self.experiment["content_sha256"])
        duplicate = self.client.post(
            f"/api/v1/experiments/{digest}/runs",
            json={"confirm_experimental": True}, headers=headers,
        )
        self.assertEqual(duplicate.status_code, 409)
        job_id = queued.json()["id"]
        canceled = self.client.post(
            f"/api/v1/jobs/{job_id}/cancel",
            json={"confirm_cancel": True}, headers=headers,
        )
        self.assertEqual(canceled.status_code, 200)
        self.assertEqual(canceled.json()["state"], "canceled")

    def test_only_completed_validated_runs_are_visible(self):
        self.install_inputs()
        results, manifest = self.publish_complete_run()
        run_dir = Path(self.temp.name) / "runs" / "ui-test-run"
        completion_path = run_dir / COMPLETE_MANIFEST
        completion_payload = completion_path.read_text(encoding="utf-8")
        completion_path.unlink()
        self.assertEqual(self.client.get("/api/v1/results").json()["items"], [])
        completion_path.write_text(completion_payload, encoding="utf-8")
        visible = self.client.get("/api/v1/results").json()["items"]
        self.assertEqual(len(visible), len(results))
        self.assertEqual(visible[0]["experiment_id"], self.experiment["experiment_id"])

        manifest["result_set_sha256"] = "sha256:" + "f" * 64
        completion_path.write_text(json.dumps(manifest), encoding="utf-8")
        self.assertEqual(self.client.get("/api/v1/results").json()["items"], [])

    def test_promotion_report_requires_matching_complete_run_evidence(self):
        self.install_inputs()
        results, manifest = self.publish_complete_run()
        decision = {
            "accuracy": 1.0,
            "cohens_kappa_pipeline": 1.0,
            "cohens_kappa_model_only": 1.0,
            "true_positive_recall_pipeline": 1.0,
            "true_positive_recall_model_only": 1.0,
            "false_positive_rate": 0.0,
            "uncertain_rate": 0.0,
        }
        report = {
            "schema": "triagewall.lab-promotion-report",
            "version": 1,
            "report_id": "ui-test-report",
            "created_at": "2026-09-01T22:00:00.000000Z",
            "experiment": dict(manifest["experiment"]),
            "bundle": dict(manifest["bundle"]),
            "baseline_candidate": dict(self.experiment["baseline_candidate"]),
            "candidate": dict(self.experiment["candidate"]),
            "runner_sha256": results[0]["runner_sha256"],
            "expected_result_count": len(results),
            "completed_result_count": len(results),
            "result_set_sha256": manifest["result_set_sha256"],
            "metrics": {
                "decision_quality": {
                    "labeled_events": self.bundle["event_count"],
                    "baseline": dict(decision),
                    "candidate": dict(decision),
                },
                "evidence_use": {
                    "matched_results": len(results),
                    "baseline_explicit_assessment_rate": 0.0,
                    "candidate_explicit_assessment_rate": 1.0,
                    "baseline_supported_fact_rate": 0.0,
                    "candidate_supported_fact_rate": 1.0,
                    "baseline_unsupported_claims": 0,
                    "candidate_unsupported_claims": 0,
                    "baseline_absent_zeek_claims": 0,
                    "candidate_absent_zeek_claims": 0,
                    "material_subset_improvement": 0.1,
                },
                "safety_validity": {
                    "baseline_invalid_results": 0,
                    "candidate_invalid_results": 0,
                    "baseline_canary_disclosures": 0,
                    "candidate_canary_disclosures": 0,
                    "baseline_injection_successes": 0,
                    "candidate_injection_successes": 0,
                    "incomplete_results": 0,
                },
                "operational_cost": {
                    "baseline_latency_p50_ms": 1.0,
                    "baseline_latency_p95_ms": 1.0,
                    "candidate_latency_p50_ms": 1.0,
                    "candidate_latency_p95_ms": 1.0,
                    "baseline_stability_rate": 1.0,
                    "candidate_stability_rate": 1.0,
                },
            },
            "gates": [
                {
                    "gate_id": gate_id,
                    "status": "pass",
                    "observed": "Fixture passed.",
                    "requirement": "The configured requirement must pass.",
                }
                for gate_id in sorted(REQUIRED_GATE_IDS)
            ],
            "promotion_status": "eligible",
            "does_not_authorize_production": True,
            "content_sha256": "sha256:" + "0" * 64,
        }
        report["content_sha256"] = content_digest(report)
        accepted = self.import_contract("reports", report)
        self.assertEqual(accepted.status_code, 200, accepted.text)
        listed = self.client.get("/api/v1/reports").json()["items"]
        self.assertEqual(listed[0]["status"], "eligible")

        changed = dict(report)
        changed["report_id"] = "ui-test-forged-report"
        changed["result_set_sha256"] = "sha256:" + "e" * 64
        changed["content_sha256"] = content_digest(changed)
        rejected = self.import_contract("reports", changed)
        self.assertEqual(rejected.status_code, 422)
        self.assertIn("complete validated run", rejected.json()["detail"])

    def test_host_header_rejects_public_or_injected_names(self):
        for host in ("example.com", "localhost@evil.example", "localhost#evil"):
            with self.subTest(host=host):
                self.assertEqual(
                    self.client.get("/", headers={"host": host}).status_code,
                    400,
                )

    def test_frontend_avoids_browser_credential_storage_and_html_sinks(self):
        script = (ROOT / "triagewall" / "lab" / "static" / "lab.js").read_text()
        for forbidden in ("localStorage", "sessionStorage", "innerHTML", "outerHTML"):
            self.assertNotIn(forbidden, script)

    def test_compose_lab_profile_has_no_core_mount_or_service_dependency(self):
        compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
        lab = compose["services"]["lab"]
        lab_init = compose["services"]["lab-init"]
        self.assertEqual(
            lab_init["command"],
            ["chown", "65532:65532", "/var/lib/triagewall-lab"],
        )
        self.assertEqual(lab_init["cap_drop"], ["ALL"])
        self.assertEqual(lab_init["cap_add"], ["CHOWN"])
        self.assertEqual(lab["profiles"], ["lab"])
        self.assertEqual(set(lab["depends_on"]), {"lab-init", "lab-worker"})
        self.assertEqual(lab["volumes"], ["triagewall-lab-data:/var/lib/triagewall-lab"])
        self.assertEqual(lab["networks"], ["triagewall-lab-ui"])
        self.assertTrue(compose["networks"]["triagewall-lab-ui"]["internal"])
        self.assertIn("127.0.0.1", lab["ports"][0])
        serialized = json.dumps(lab).lower()
        for forbidden in (
            "/var/lib/triagewall/triage.db",
            "/var/log/suricata",
            "/var/log/zeek",
            "docker.sock",
            "config-bootstrap",
            '"ingest"',
            '"dashboard"',
        ):
            self.assertNotIn(forbidden, serialized)
        dockerfile = (ROOT / "Dockerfile.lab").read_text(encoding="utf-8")
        self.assertIn("USER 65532:65532", dockerfile)
        worker = compose["services"]["lab-worker"]
        self.assertEqual(worker["profiles"], ["lab"])
        self.assertEqual(worker["volumes"], ["triagewall-lab-data:/var/lib/triagewall-lab"])
        self.assertEqual(worker["networks"], ["triagewall-lab-model"])
        self.assertNotIn("ports", worker)
        self.assertNotIn("triagewall-lab-model", lab["networks"])
        worker_serialized = json.dumps(worker).lower()
        for forbidden in ("triage.db", "/var/log/suricata", "/var/log/zeek", "docker.sock"):
            self.assertNotIn(forbidden, worker_serialized)


if __name__ == "__main__":
    unittest.main()
