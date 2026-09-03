from collections import Counter
import ipaddress
import json
from pathlib import Path
import re
import unittest

from scripts.build_lab_zeek_scenarios import INJECTION_MARKER, render_fixture_bytes
from triagewall import event_bundle


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "lab_scenarios" / "zeek-evidence-v1.json"
DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)


def load_fixture():
    return event_bundle.load_event_bundle_bytes(FIXTURE.read_bytes())


class LabZeekScenarioTests(unittest.TestCase):
    def test_checked_fixture_is_deterministic_and_contract_valid(self):
        self.assertEqual(FIXTURE.read_bytes(), render_fixture_bytes())
        document = load_fixture()
        self.assertEqual(document["event_count"], 15)
        self.assertEqual(len(document["events"]), 15)

    def test_human_verdicts_and_application_contributions_are_balanced(self):
        document = load_fixture()
        verdicts = Counter(event["labels"]["human_verdict"] for event in document["events"])
        contributions = Counter(
            event["labels"]["condition_labels"]["connection_plus_application"]
            ["zeek_contribution"]
            for event in document["events"]
        )

        self.assertEqual(
            verdicts,
            Counter({"real": 5, "false_positive": 5, "uncertain": 5}),
        )
        self.assertEqual(
            contributions,
            Counter(
                {
                    "material": 3,
                    "corroborative": 3,
                    "conflicting": 3,
                    "uninformative": 3,
                    "unavailable": 3,
                }
            ),
        )

    def test_no_zeek_ground_truth_never_contains_zeek_facts(self):
        for event in load_fixture()["events"]:
            label = event["labels"]["condition_labels"]["no_zeek"]
            self.assertEqual(label["zeek_contribution"], "unavailable")
            self.assertEqual(label["allowed_zeek_facts"], [])

    def test_connection_states_lookup_failures_and_truncation_are_covered(self):
        document = load_fixture()
        states = set()
        statuses = set()
        truncated = False
        directions = set()
        for event in document["events"]:
            layer = event["zeek"]["automatic"]
            statuses.add(layer["lookup_status"])
            truncated = truncated or layer["truncated"]
            if layer["context_json"] is not None:
                context = json.loads(layer["context_json"])
                for connection in context["connections"]:
                    states.add(connection["conn_state"])
                    directions.add(connection["direction"])

        self.assertTrue({"SF", "S0", "REJ", "RSTO"}.issubset(states))
        self.assertTrue({"matched", "no_match", "unavailable", "ambiguous"}.issubset(statuses))
        self.assertTrue(truncated)
        self.assertEqual(directions, {"same_as_alert", "reverse_of_alert"})

    def test_deeper_evidence_covers_supported_application_record_classes(self):
        record_classes = set()
        for event in load_fixture()["events"]:
            operator = event["zeek"]["operator"]
            context_json = operator["context_json"]
            if context_json is not None:
                context = json.loads(context_json)
                application_classes = set(context) - {"connections", "schema_version"}
                record_classes.update(application_classes)
                with self.subTest(event=event["event_id"]):
                    self.assertTrue(application_classes)
                    self.assertTrue(
                        any(context[name] for name in application_classes),
                        "a matched deeper-evidence condition needs an application record",
                    )

        self.assertTrue(
            {"dns", "http", "ssl", "x509", "files", "notices"}.issubset(
                record_classes
            )
        )

    def test_injection_sentinel_covers_every_retained_application_string_class(self):
        document = load_fixture()
        event = next(
            event
            for event in document["events"]
            if "injection-strings-uninformative" in event["event_id"]
        )
        context = json.loads(event["zeek"]["operator"]["context_json"])
        expected_paths = (
            ("dns", 0, "answers", 0),
            ("dns", 0, "query"),
            ("dns", 0, "qtype_name"),
            ("http", 0, "host"),
            ("http", 0, "method"),
            ("http", 0, "uri"),
            ("http", 0, "user_agent"),
            ("ssl", 0, "server_name"),
            ("ssl", 0, "version"),
            ("x509", 0, "issuer"),
            ("x509", 0, "subject"),
            ("files", 0, "filename"),
            ("files", 0, "mime_type"),
            ("notices", 0, "msg"),
            ("notices", 0, "note"),
            ("notices", 0, "sub"),
        )
        for path in expected_paths:
            value = context
            for component in path:
                value = value[component]
            with self.subTest(path=path):
                self.assertEqual(value, INJECTION_MARKER)

    def test_evidence_reference_allowlists_are_unique_grounded_non_tuple_paths(self):
        for event in load_fixture()["events"]:
            labels = event["labels"]["condition_labels"]
            for condition, layer_name in (
                ("connection_only", "automatic"),
                ("connection_plus_application", "operator"),
            ):
                facts = labels[condition]["allowed_zeek_facts"]
                self.assertEqual(len(facts), len(set(facts)))
                context_json = event["zeek"][layer_name]["context_json"]
                if context_json is None:
                    self.assertEqual(facts, [])
                    continue
                context = json.loads(context_json)
                for fact in facts:
                    with self.subTest(event=event["event_id"], condition=condition, fact=fact):
                        self.assertNotIn(fact, {
                            "$.connections[0].id.orig_h",
                            "$.connections[0].id.orig_p",
                            "$.connections[0].id.resp_h",
                            "$.connections[0].id.resp_p",
                        })
                        value = context
                        for name, index in re.findall(
                            r"(?:^|\.)([A-Za-z_][A-Za-z0-9_]*)|\[(\d+)\]",
                            fact,
                        ):
                            value = value[int(index)] if index else value[name]
                        self.assertNotIsInstance(value, (dict, list))

    def test_fixture_addresses_are_reserved_documentation_addresses(self):
        document = load_fixture()
        observed = []
        for event in document["events"]:
            sensor = event["sensor_event"]
            observed.extend((sensor["src_ip"], sensor["dest_ip"]))
            asset_context = json.loads(event["asset_context"]["content"])
            for side in ("source", "destination"):
                if asset_context[side] is not None:
                    observed.extend(asset_context[side]["ips"])
            for layer_name in ("automatic", "operator"):
                context_json = event["zeek"][layer_name]["context_json"]
                if context_json is None:
                    continue
                for connection in json.loads(context_json)["connections"]:
                    observed.extend((connection["id.orig_h"], connection["id.resp_h"]))

        for value in observed:
            address = ipaddress.ip_address(value)
            with self.subTest(address=value):
                self.assertTrue(any(address in network for network in DOCUMENTATION_NETWORKS))


if __name__ == "__main__":
    unittest.main()
