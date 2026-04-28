#!/usr/bin/env python3
"""Tests for scheduled-search detection rule spec generation."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from detection_rule_creator import build_detection_rule_spec, classify_query


class TestDetectionRuleCreator(unittest.TestCase):
    """Validate scheduled-search eligibility heuristics."""

    def test_classify_query_accepts_simple_stats_query(self):
        result = classify_query(
            "'Log Source' = 'SOC Application Logs' | stats count as ErrorCount by 'Service Name', 'URI Path'"
        )

        self.assertTrue(result["eligible"])
        self.assertEqual(result["metric_name"], "ErrorCount")
        self.assertEqual(result["dimensions"], ["Service Name", "URI Path"])

    def test_classify_query_rejects_dashboard_only_commands(self):
        result = classify_query(
            "'Log Source' = 'SOC Multicloud Health Logs' | geostats count by 'Latitude', 'Longitude'",
            visualization_type="map",
        )

        self.assertFalse(result["eligible"])
        self.assertTrue(any("visualization" in reason or "unsupported" in reason for reason in result["reasons"]))

    def test_build_detection_rule_spec_carries_metadata(self):
        payload = {
            "title": "Application Error Rate by Service",
            "query": "'Log Source' = 'SOC Application Logs' | stats count as ErrorCount by 'Service Name'",
            "level": "high",
            "dashboard": {"visualizationType": "bar"},
        }

        spec = build_detection_rule_spec("queries/apps/app_error_rate_by_service.json", payload)

        self.assertEqual(spec["title"], payload["title"])
        self.assertTrue(spec["eligible"])
        self.assertEqual(spec["metric_name"], "ErrorCount")
        self.assertEqual(spec["dimensions"], ["Service Name"])
        self.assertEqual(spec["severity"], "high")

    def test_classify_query_rejects_live_incompatible_windows_extractions(self):
        result = classify_query(
            "'Log Source' = 'Windows Security Events' | eval Account = regexextract('Original Log Content', 'TargetUserName:([^;]+)') | stats count as Failures by Account"
        )

        self.assertFalse(result["eligible"])
        self.assertTrue(any("regexextract" in reason for reason in result["reasons"]))

    def test_classify_query_rejects_unmapped_windows_process_field(self):
        result = classify_query(
            "'Log Source' = 'Windows Security Events' and 'New Process Name' like '*\\\\powershell.exe' | stats count as Detections by Entity"
        )

        self.assertFalse(result["eligible"])
        self.assertTrue(any("New Process Name" in reason for reason in result["reasons"]))

    def test_classify_query_rejects_fusion_dependent_correlation(self):
        result = classify_query(
            "'Log Source' = 'OCI Audit Logs' or 'Log Source' = 'Fusion Apps: ESS Audit Logs' | stats count as TotalEvents by actor"
        )

        self.assertFalse(result["eligible"])
        self.assertTrue(any("Fusion Apps" in reason for reason in result["reasons"]))


if __name__ == "__main__":
    unittest.main()
