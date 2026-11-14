import json
from copy import deepcopy
import unittest
from pathlib import Path
from types import SimpleNamespace

from scripts.build_lab_experiment_2 import build_documents
from triagewall.event_bundle import canonical_json, load_event_bundle_bytes
from triagewall.lab_contracts import REQUIRED_GATE_IDS
from triagewall.lab_reporting import LabReportingError, build_promotion_report
from triagewall.lab_runner import run_experiment


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
                "verdict": "real", "confidence": 0.8,
                "reasoning": "The alert remains suspicious from Suricata evidence.",
            }),
        }


class LabReportingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle = load_event_bundle_bytes(FIXTURE.read_bytes())
        args = SimpleNamespace(
            temperature=0.2, num_predict=512, num_ctx=4096, model_seed=None,
            repetitions=1, execution_order_seed=42,
            baseline_id="report-baseline", candidate_id="report-candidate",
            experiment_id="report-experiment", author="report-test",
            model_name="fixture-model", model_digest="sha256:" + "a" * 64,
        )
        cls.baseline, cls.candidate, cls.experiment = build_documents(args, cls.bundle)
        cls.results = list(run_experiment(
            bundle=cls.bundle, baseline=cls.baseline, candidate=cls.candidate,
            experiment=cls.experiment, transport=FakeTransport(), timeout=1,
        ))

    def test_report_is_deterministic_sanitized_and_evaluates_every_gate(self):
        created = "2026-09-01T22:00:00.000000Z"
        first = build_promotion_report(
            bundle=self.bundle, experiment=self.experiment,
            results=self.results, created_at=created,
        )
        second = build_promotion_report(
            bundle=self.bundle, experiment=self.experiment,
            results=self.results, created_at=created,
        )
        self.assertEqual(first, second)
        self.assertEqual({gate["gate_id"] for gate in first["gates"]}, REQUIRED_GATE_IDS)
        self.assertEqual(first["promotion_status"], "blocked")
        self.assertTrue(first["does_not_authorize_production"])
        encoded = canonical_json(first)
        for forbidden in ("model_response", '"reasoning"', "raw_event"):
            self.assertNotIn(forbidden, encoded)

    def test_report_rejects_missing_reordered_or_misbound_results(self):
        cases = [self.results[:-1], list(reversed(self.results))]
        for results in cases:
            with self.subTest(length=len(results)):
                with self.assertRaisesRegex(LabReportingError, "incomplete or not in"):
                    build_promotion_report(
                        bundle=self.bundle, experiment=self.experiment, results=results
                    )
        changed = [dict(result) for result in self.results]
        changed[0] = {**changed[0], "bundle": {"id": "wrong", "sha256": "sha256:" + "f" * 64}}
        with self.assertRaisesRegex(LabReportingError, "references"):
            build_promotion_report(
                bundle=self.bundle, experiment=self.experiment, results=changed
            )

    def test_single_repetition_is_insufficient_stability_evidence(self):
        report = build_promotion_report(
            bundle=self.bundle,
            experiment=self.experiment,
            results=self.results,
            created_at="2026-09-01T22:00:00.000000Z",
        )

        operational = report["metrics"]["operational_cost"]
        self.assertIsNone(operational["baseline_stability_rate"])
        self.assertIsNone(operational["candidate_stability_rate"])
        gate = next(
            gate for gate in report["gates"]
            if gate["gate_id"] == "repetition_stability"
        )
        self.assertEqual(gate["status"], "fail")
        self.assertIn("insufficient", gate["observed"].lower())

    def test_injection_gate_reports_baseline_and_candidate_separately(self):
        results = deepcopy(self.results)
        results[0]["baseline"]["score"]["injected_instruction_followed"] = True
        results[0]["candidate"]["score"]["injected_instruction_followed"] = True
        report = build_promotion_report(
            bundle=self.bundle,
            experiment=self.experiment,
            results=results,
            created_at="2026-09-01T22:00:00.000000Z",
        )

        gate = next(
            gate for gate in report["gates"]
            if gate["gate_id"] == "injected_instruction_followed"
        )
        self.assertEqual(gate["status"], "fail")
        self.assertIn("Baseline injection successes: 1", gate["observed"])
        self.assertIn("candidate injection successes: 1", gate["observed"])

    def test_material_improvement_requires_material_specific_references(self):
        results = deepcopy(self.results)
        events = {event["event_id"]: event for event in self.bundle["events"]}
        changed = 0
        for result in results:
            if result["evidence_condition"] != "connection_plus_application":
                continue
            labels = events[result["event_id"]]["labels"]["condition_labels"]
            if (
                labels["connection_plus_application"]["zeek_contribution"] == "material"
                and labels["connection_only"]["zeek_contribution"] != "material"
            ):
                result["candidate"]["score"]["supported_facts"] = [
                    labels["connection_only"]["allowed_zeek_facts"][0]
                ]
                changed += 1
        self.assertGreater(changed, 0)

        report = build_promotion_report(
            bundle=self.bundle,
            experiment=self.experiment,
            results=results,
            created_at="2026-09-01T22:00:00.000000Z",
        )

        self.assertEqual(
            report["metrics"]["evidence_use"]["material_subset_improvement"],
            0.0,
        )


if __name__ == "__main__":
    unittest.main()
