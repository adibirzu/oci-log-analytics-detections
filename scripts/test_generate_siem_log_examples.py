#!/usr/bin/env python3
"""Contract tests for the customer-facing OCI SIEM sample catalog."""

import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from generate_siem_log_examples import (
    build_catalog,
    check_catalog,
    render_detection_jsonl,
    render_raw_jsonl,
    validate_catalog,
)
from query_artifacts import is_generated_query_artifact, is_saved_search_query_file


RAW_SAMPLE_IDS = {
    "oci_audit",
    "vcn_flow",
    "load_balancer_access",
    "waf",
    "network_firewall_threat",
    "api_gateway_access",
    "functions_invoke",
    "cloud_guard_raw",
    "object_storage_access",
    "custom_application",
}

DETECTION_IDS = {
    "oci_console_brute_force",
    "oci_iam_rapid_changes",
    "oci_privilege_escalation_chain",
    "oci_resource_destruction_spike",
    "cloud_identity_token_abuse",
    "waf_multi_attack_scoring",
    "waf_attack_frequency",
    "web_application_brute_force",
    "c2_flow_connections",
    "web_to_cloud_attack_timeline",
}


class TestSiemLogExamples(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = build_catalog(generated_at="2026-06-29T00:00:00Z")

    def test_catalog_has_versioned_contract_and_expected_inventory(self):
        self.assertEqual(self.catalog["schema_version"], "1.0.0")
        self.assertEqual(
            {sample["id"] for sample in self.catalog["raw_log_samples"]},
            RAW_SAMPLE_IDS,
        )
        self.assertEqual(
            {sample["id"] for sample in self.catalog["detection_samples"]},
            DETECTION_IDS,
        )

    def test_output_is_registered_as_generated_metadata(self):
        self.assertTrue(is_generated_query_artifact("queries/siem_log_examples.json"))
        self.assertFalse(is_saved_search_query_file("queries/siem_log_examples.json"))

    def test_raw_samples_have_official_provenance_and_no_tenant_values(self):
        serialized = json.dumps(self.catalog["raw_log_samples"])

        for sample in self.catalog["raw_log_samples"]:
            self.assertTrue(sample["official_doc_url"].startswith("https://docs.oracle.com/"))
            self.assertIn(sample["repository_coverage"], {"envelope", "payload", "custom", "gap"})
            self.assertIsInstance(sample["event"], dict)

        self.assertNotRegex(serialized, r"ocid1\.[a-z]+\.oc1")
        self.assertNotRegex(serialized, r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
        self.assertNotRegex(serialized, r"\b(?:10\.42|10\.0\.10|130\.61|161\.153|144\.24|129\.153|141\.147)\.")

    def test_canonical_envelopes_keep_service_specific_shapes(self):
        by_id = {sample["id"]: sample["event"] for sample in self.catalog["raw_log_samples"]}

        self.assertEqual(by_id["oci_audit"]["cloudEventsVersion"], "0.1")
        self.assertIn("identity", by_id["oci_audit"]["data"])
        self.assertEqual(by_id["vcn_flow"]["specversion"], "1.0")
        self.assertIn("sourceAddress", by_id["vcn_flow"]["data"])
        self.assertIn("request", by_id["waf"]["data"])
        self.assertIn("firewall-id", by_id["network_firewall_threat"]["data"])
        self.assertIn("functionId", by_id["functions_invoke"]["data"])
        cloud_guard_message = by_id["cloud_guard_raw"]["data"]["message"]
        self.assertIn("logContent", cloud_guard_message)
        self.assertIn("result", cloud_guard_message["logContent"]["data"])
        self.assertIn("regionId", cloud_guard_message)
        object_storage_data = by_id["object_storage_access"]["data"]
        self.assertIn("requestAction", object_storage_data)
        self.assertIn("namespaceName", object_storage_data)
        self.assertIn("credentials", object_storage_data)

    def test_detection_examples_are_backed_by_deployable_repo_queries(self):
        for detection in self.catalog["detection_samples"]:
            self.assertTrue(detection["eligible"])
            self.assertIn(detection["severity"], {"high", "critical"})
            self.assertTrue(detection["query_file"].startswith("queries/"))
            self.assertTrue(detection["metric_name"])
            self.assertLessEqual(len(detection["dimensions"]), 3)

    def test_native_alarm_examples_match_monitoring_message_contract(self):
        required = {
            "dedupeKey",
            "title",
            "body",
            "type",
            "severity",
            "timestampEpochMillis",
            "timestamp",
            "alarmMetaData",
            "version",
        }
        for detection in self.catalog["detection_samples"]:
            alarm = detection["native_alarm"]
            self.assertTrue(required.issubset(alarm))
            self.assertEqual(alarm["alarmMetaData"][0]["namespace"], "oci_logging_analytics")
            self.assertEqual(alarm["alarmMetaData"][0]["status"], "FIRING")

    def test_normalized_detection_examples_have_stable_v1_shape(self):
        required = {
            "schema_version",
            "event_id",
            "event_type",
            "detected_at",
            "rule",
            "severity",
            "source",
            "window",
            "matched_count",
            "entities",
            "mitre",
            "evidence",
            "oci_context",
        }
        for detection in self.catalog["detection_samples"]:
            normalized = detection["normalized_detection"]
            self.assertEqual(set(normalized), required)
            self.assertEqual(normalized["schema_version"], "1.0.0")
            self.assertEqual(normalized["event_type"], "oci.logan.detection")
            self.assertNotRegex(json.dumps(normalized), r"ocid1\.[a-z]+\.oc1")

    def test_catalog_validator_and_jsonl_exports(self):
        self.assertEqual(validate_catalog(self.catalog), [])

        raw_lines = render_raw_jsonl(self.catalog).strip().splitlines()
        detection_lines = render_detection_jsonl(self.catalog).strip().splitlines()
        self.assertEqual(len(raw_lines), 10)
        self.assertEqual(len(detection_lines), 10)
        self.assertTrue(all(isinstance(json.loads(line), dict) for line in raw_lines))
        self.assertTrue(all(isinstance(json.loads(line), dict) for line in detection_lines))

    def test_check_catalog_detects_drift_without_rewriting_artifact(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "siem_log_examples.json"
            output_path.write_text(json.dumps(self.catalog, indent=2) + "\n", encoding="utf-8")
            original = output_path.read_text(encoding="utf-8")

            self.assertEqual(check_catalog(output_path), [])
            self.assertEqual(output_path.read_text(encoding="utf-8"), original)

            drifted = dict(self.catalog)
            drifted["raw_log_samples"] = self.catalog["raw_log_samples"][:-1]
            output_path.write_text(json.dumps(drifted, indent=2) + "\n", encoding="utf-8")
            self.assertEqual(check_catalog(output_path), ["generated artifact is out of date"])


if __name__ == "__main__":
    unittest.main()
