from copy import deepcopy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from triagewall import event_bundle


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = (
    ROOT
    / "tests"
    / "fixtures"
    / "event_bundle_v1"
    / "suricata-zeek-correlative.json"
)
SCHEMA = ROOT / "schemas" / "event-bundle-v1.schema.json"


def fixture_document():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def resign(document):
    document["content_sha256"] = event_bundle.bundle_content_digest(document)
    return document


class EventBundleV1Tests(unittest.TestCase):
    def test_sanitized_zeek_fixture_is_valid(self):
        document = event_bundle.load_event_bundle_bytes(FIXTURE.read_bytes())

        self.assertEqual(document["schema"], event_bundle.EVENT_BUNDLE_SCHEMA)
        self.assertEqual(document["version"], event_bundle.EVENT_BUNDLE_VERSION)
        self.assertEqual(
            document["events"][0]["labels"]["condition_labels"]
            ["connection_only"]["zeek_contribution"],
            "corroborative",
        )

    def test_bundle_content_digest_covers_manifest_and_events(self):
        document = fixture_document()
        expected = document["content_sha256"]

        document["events"][0]["labels"]["notes"] = "Changed after export."

        self.assertNotEqual(event_bundle.bundle_content_digest(document), expected)
        with self.assertRaisesRegex(event_bundle.EventBundleError, "content_sha256"):
            event_bundle.validate_event_bundle(document)

    def test_unknown_fields_fail_closed(self):
        document = fixture_document()
        document["model_host"] = "http://attacker.invalid"

        with self.assertRaisesRegex(event_bundle.EventBundleError, "unknown fields"):
            event_bundle.validate_event_bundle(document)

    def test_duplicate_json_keys_are_rejected_before_validation(self):
        with self.assertRaisesRegex(event_bundle.EventBundleError, "duplicate object key"):
            event_bundle.load_event_bundle_bytes(b'{"schema":"one","schema":"two"}')

    def test_nonfinite_json_numbers_are_rejected(self):
        with self.assertRaisesRegex(event_bundle.EventBundleError, "non-finite"):
            event_bundle.load_event_bundle_bytes(b'{"confidence":NaN}')

    def test_utf8_bom_and_invalid_utf8_are_rejected(self):
        for payload, message in (
            (b"\xef\xbb\xbf{}", "BOM"),
            (b"\xff", "UTF-8"),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(event_bundle.EventBundleError, message):
                    event_bundle.load_event_bundle_bytes(payload)

    def test_raw_payload_limit_is_checked_before_json_decode(self):
        with patch.object(event_bundle, "MAX_BUNDLE_BYTES", 16):
            with self.assertRaisesRegex(event_bundle.EventBundleError, "byte limit"):
                event_bundle.load_event_bundle_bytes(b"x" * 17)

    def test_embedded_json_must_be_canonical_and_hash_matched(self):
        noncanonical = fixture_document()
        value = '{"source": null, "destination": null}'
        blob = noncanonical["events"][0]["asset_context"]
        blob["content"] = value
        blob["sha256"] = event_bundle.sha256_text(value)
        resign(noncanonical)

        with self.assertRaisesRegex(event_bundle.EventBundleError, "canonical JSON"):
            event_bundle.validate_event_bundle(noncanonical)

        mismatched = fixture_document()
        mismatched["events"][0]["model_projection"]["content"] += "\nextra"
        resign(mismatched)
        with self.assertRaisesRegex(event_bundle.EventBundleError, "does not match its digest"):
            event_bundle.validate_event_bundle(mismatched)

    def test_rejected_original_model_output_may_be_invalid_json(self):
        document = fixture_document()
        historical = document["events"][0]["historical_result"]
        historical["model_response"] = '{"verdict":"real"'
        historical["model_response_sha256"] = event_bundle.sha256_text(
            historical["model_response"]
        )
        historical["validation_status"] = "rejected"
        historical["validation_reason"] = "Failed to parse complete model JSON output."
        historical["final_verdict"] = "uncertain"
        historical["confidence"] = 0.0
        resign(document)

        self.assertIs(event_bundle.validate_event_bundle(document), document)

    def test_matched_zeek_requires_exactly_one_candidate_and_context(self):
        for mutation, message in (
            ({"candidate_count": 2}, "exactly one candidate"),
            ({"context_json": None, "context_sha256": None}, "require context"),
        ):
            document = fixture_document()
            document["events"][0]["zeek"]["automatic"].update(mutation)
            resign(document)
            with self.subTest(mutation=mutation):
                with self.assertRaisesRegex(event_bundle.EventBundleError, message):
                    event_bundle.validate_event_bundle(document)

    def test_ineligible_wazuh_event_cannot_claim_matched_zeek(self):
        document = fixture_document()
        document["events"][0]["sensor_event"]["source"] = "wazuh"
        resign(document)

        with self.assertRaisesRegex(event_bundle.EventBundleError, "unsupported_source"):
            event_bundle.validate_event_bundle(document)

    def test_prefilter_revision_must_match_bundle_revision(self):
        document = fixture_document()
        document["events"][0]["prefilter"]["policy_revision"] = (
            "sha256:" + "9" * 64
        )
        resign(document)

        with self.assertRaisesRegex(event_bundle.EventBundleError, "must match"):
            event_bundle.validate_event_bundle(document)

    def test_feedback_manifest_must_match_event_contents(self):
        document = fixture_document()
        document["redaction"]["operator_feedback_included"] = True
        transformations = document["redaction"]["transformations"]
        transformations.remove("operator_feedback_excluded")
        transformations.append("operator_feedback_included")
        resign(document)

        with self.assertRaisesRegex(event_bundle.EventBundleError, "event contents"):
            event_bundle.validate_event_bundle(document)

    def test_redaction_transformations_are_complete_and_exclusive(self):
        cases = (
            ("raw_sensor_event_excluded", "must include"),
            ("sensor_instance_pseudonymized", "must include"),
            ("private_addresses_preserved", "private-address"),
        )
        for removed, message in cases:
            document = fixture_document()
            document["redaction"]["transformations"].remove(removed)
            resign(document)
            with self.subTest(removed=removed):
                with self.assertRaisesRegex(event_bundle.EventBundleError, message):
                    event_bundle.validate_event_bundle(document)

        document = fixture_document()
        document["redaction"]["transformations"].append(
            "private_addresses_pseudonymized"
        )
        resign(document)
        with self.assertRaisesRegex(event_bundle.EventBundleError, "private-address"):
            event_bundle.validate_event_bundle(document)

    def test_historical_model_identity_must_match_bundle(self):
        document = fixture_document()
        document["events"][0]["historical_result"]["model_used"] = "other-model"
        resign(document)

        with self.assertRaisesRegex(event_bundle.EventBundleError, "bundle.model.name"):
            event_bundle.validate_event_bundle(document)

    def test_labels_are_condition_specific_and_match_available_layers(self):
        document = fixture_document()
        connection = document["events"][0]["labels"]["condition_labels"]
        connection["connection_only"] = {
            "zeek_contribution": "unavailable",
            "allowed_zeek_facts": [],
        }
        resign(document)
        with self.assertRaisesRegex(event_bundle.EventBundleError, "matched Zeek evidence"):
            event_bundle.validate_event_bundle(document)

        document = fixture_document()
        application = document["events"][0]["labels"]["condition_labels"]
        application["connection_plus_application"] = {
            "zeek_contribution": "material",
            "allowed_zeek_facts": ["Zeek observed a fixture HTTP request."],
        }
        resign(document)
        with self.assertRaisesRegex(event_bundle.EventBundleError, "must be unavailable"):
            event_bundle.validate_event_bundle(document)

        document = fixture_document()
        no_zeek = document["events"][0]["labels"]["condition_labels"]["no_zeek"]
        no_zeek["zeek_contribution"] = "corroborative"
        no_zeek["allowed_zeek_facts"] = ["An impossible no-Zeek fact."]
        resign(document)
        with self.assertRaisesRegex(event_bundle.EventBundleError, "must be unavailable"):
            event_bundle.validate_event_bundle(document)

    def test_embedded_json_recursion_failure_is_a_contract_error(self):
        document = fixture_document()
        nested = "{" + '"x":{' * 1200 + '"end":true' + "}" * 1201
        blob = document["events"][0]["asset_context"]
        blob["content"] = nested
        blob["sha256"] = event_bundle.sha256_text(nested)
        resign(document)

        with self.assertRaisesRegex(event_bundle.EventBundleError, "strict JSON"):
            event_bundle.validate_event_bundle(document)

    def test_embedded_json_depth_limit_is_explicit_and_inclusive(self):
        accepted = fixture_document()
        within_limit = '{"x":' * event_bundle.MAX_EMBEDDED_JSON_DEPTH + "true" + (
            "}" * event_bundle.MAX_EMBEDDED_JSON_DEPTH
        )
        blob = accepted["events"][0]["asset_context"]
        blob["content"] = within_limit
        blob["sha256"] = event_bundle.sha256_text(within_limit)
        resign(accepted)
        self.assertIs(event_bundle.validate_event_bundle(accepted), accepted)

        rejected = fixture_document()
        over_limit = (
            '{"x":' * (event_bundle.MAX_EMBEDDED_JSON_DEPTH + 1)
            + "true"
            + "}" * (event_bundle.MAX_EMBEDDED_JSON_DEPTH + 1)
        )
        blob = rejected["events"][0]["asset_context"]
        blob["content"] = over_limit
        blob["sha256"] = event_bundle.sha256_text(over_limit)
        resign(rejected)
        with self.assertRaisesRegex(
            event_bundle.EventBundleError,
            f"at most {event_bundle.MAX_EMBEDDED_JSON_DEPTH} nested containers",
        ):
            event_bundle.validate_event_bundle(rejected)

    def test_schema_objects_are_closed_and_require_every_declared_field(self):
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))

        def visit(value, location="$"):
            if isinstance(value, dict):
                if value.get("type") == "object":
                    self.assertIs(
                        value.get("additionalProperties"),
                        False,
                        f"{location} must reject unknown fields",
                    )
                    self.assertEqual(
                        set(value.get("required", [])),
                        set(value.get("properties", {})),
                        f"{location} must require every declared field",
                    )
                for key, item in value.items():
                    visit(item, f"{location}.{key}")
            elif isinstance(value, list):
                for index, item in enumerate(value):
                    visit(item, f"{location}[{index}]")

        visit(schema)

    def test_schema_limits_and_identity_match_runtime_contract(self):
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))

        self.assertEqual(
            schema["properties"]["schema"]["const"],
            event_bundle.EVENT_BUNDLE_SCHEMA,
        )
        self.assertEqual(
            schema["properties"]["version"]["const"],
            event_bundle.EVENT_BUNDLE_VERSION,
        )
        self.assertEqual(
            schema["properties"]["events"]["maxItems"],
            event_bundle.MAX_EVENTS,
        )
        self.assertEqual(
            schema["$defs"]["modelProjection"]["properties"]["content"]["maxLength"],
            event_bundle.MAX_PROJECTION_BYTES,
        )


if __name__ == "__main__":
    unittest.main()
