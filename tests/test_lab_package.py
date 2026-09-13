"""Strict one-file Lab test-package contract regressions."""

from __future__ import annotations

import argparse
from pathlib import Path
import unittest
from unittest.mock import patch

from scripts.build_lab_experiment_3 import build_documents
from triagewall import event_bundle, lab_package
from triagewall.event_bundle import canonical_json


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "lab_scenarios" / "zeek-evidence-v1.json"


class LabTestPackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle = event_bundle.load_event_bundle_bytes(FIXTURE.read_bytes())
        args = argparse.Namespace(
            author="package-test",
            model_name="fixture-model",
            model_digest="sha256:" + "8" * 64,
            baseline_id="package-baseline",
            candidate_id="package-candidate",
            experiment_id="package-experiment",
            temperature=0.2,
            num_predict=512,
            num_ctx=4096,
            model_seed=7,
            repetitions=2,
            execution_order_seed=42,
        )
        cls.baseline, cls.candidate, cls.experiment = build_documents(
            args, cls.bundle
        )
        cls.package = lab_package.build_test_package(
            cls.bundle, cls.baseline, cls.candidate, cls.experiment
        )
        cls.payload = (canonical_json(cls.package) + "\n").encode("utf-8")

    def test_round_trip_preserves_validated_embedded_artifacts(self):
        loaded = lab_package.load_test_package_bytes(self.payload)
        self.assertEqual(loaded, self.package)
        self.assertEqual(
            loaded["experiment"]["candidate"]["sha256"],
            loaded["candidate"]["content_sha256"],
        )

    def test_duplicate_object_key_is_rejected_at_any_depth(self):
        payload = self.payload.replace(
            b'"schema":',
            b'"schema":"attacker-controlled","schema":',
            1,
        )
        with self.assertRaisesRegex(
            lab_package.LabTestPackageError,
            "duplicate object key: schema",
        ):
            lab_package.load_test_package_bytes(payload)

    def test_changed_package_digest_and_unknown_field_are_rejected(self):
        changed = dict(self.package)
        changed["content_sha256"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(
            lab_package.LabTestPackageError,
            "content_sha256 does not match",
        ):
            lab_package.load_test_package_bytes(canonical_json(changed).encode())

        unknown = dict(self.package)
        unknown["extra"] = True
        with self.assertRaisesRegex(
            lab_package.LabTestPackageError,
            "contains unknown fields: extra",
        ):
            lab_package.load_test_package_bytes(canonical_json(unknown).encode())

    def test_package_byte_limit_is_enforced_before_decoding(self):
        with patch.object(lab_package, "MAX_TEST_PACKAGE_BYTES", len(self.payload) - 1):
            with self.assertRaisesRegex(
                lab_package.LabTestPackageError,
                "exceeds its size limit",
            ):
                lab_package.load_test_package_bytes(self.payload)


if __name__ == "__main__":
    unittest.main()
