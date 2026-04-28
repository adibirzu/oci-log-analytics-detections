#!/usr/bin/env python3
"""Tests for live OCI query audit helpers."""

import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from query_audit import execute_query, load_specs


class TestQueryAudit(unittest.TestCase):
    """Validate query-audit behavior without hitting OCI."""

    @staticmethod
    def load_query_payload(relative_path: str) -> dict:
        project_dir = Path(__file__).resolve().parent.parent
        with (project_dir / relative_path).open() as handle:
            return json.load(handle)

    def test_load_specs_can_filter_to_detection_rule_eligible_queries(self):
        all_specs = load_specs(False)
        eligible_specs = load_specs(True)

        self.assertGreater(len(all_specs), 0)
        self.assertGreater(len(eligible_specs), 0)
        self.assertLessEqual(len(eligible_specs), len(all_specs))
        self.assertTrue(all(spec["eligible"] for spec in eligible_specs))

    def test_execute_query_returns_error_metadata_instead_of_raising(self):
        class StubClient:
            def query(self, namespace_name, query_details):
                raise RuntimeError("parse failure")

        result = execute_query(StubClient(), "demo-ns", "'Log Source' = 'OCI Audit Logs'", "7d")

        self.assertFalse(result["ok"])
        self.assertEqual(result["rows"], 0)
        self.assertEqual(result["error"], "parse failure")

    @patch("query_audit.oci.log_analytics.models.QueryDetails", autospec=True)
    @patch("query_audit.oci.log_analytics.models.TimeRange", autospec=True)
    def test_execute_query_returns_row_count_for_success(self, mock_time_range, mock_query_details):
        class StubResponse:
            data = type("Data", (), {"items": [{"row": 1}, {"row": 2}, {"row": 3}]})()

        class StubClient:
            def query(self, namespace_name, query_details):
                return StubResponse()

        result = execute_query(StubClient(), "demo-ns", "'Log Source' = 'OCI Audit Logs'", "7d")

        self.assertTrue(result["ok"])
        self.assertFalse(result["empty"])
        self.assertEqual(result["rows"], 3)

    def test_live_eligible_windows_queries_use_string_event_ids(self):
        query_files = [
            "queries/bluelight_screen_capture.json",
            "queries/cmd_suspicious_child_process.json",
            "queries/mimikatz_command_indicators.json",
            "queries/powershell_suspicious_commands.json",
            "queries/hunting/bluelight_apt37_kill_chain.json",
        ]

        for query_file in query_files:
            payload = self.load_query_payload(query_file)
            self.assertNotRegex(payload["query"], r"'Event ID'\s*=\s*\d+", query_file)
            self.assertRegex(payload["query"], r"'Event ID'\s*=\s*'\d+'", query_file)

    def test_sysmon_hunting_queries_use_runtime_mapped_host_fields(self):
        expectations = {
            "queries/bluelight_onedrive_exfiltration.json": "'Host Name'",
            "queries/hunting/dns_exfiltration_entropy.json": "'Host Name (Server)'",
            "queries/hunting/network_c2_beaconing.json": "'Host Name (Server)'",
        }

        for query_file, host_field in expectations.items():
            payload = self.load_query_payload(query_file)
            self.assertIn(host_field, payload["query"], query_file)

    def test_dns_entropy_query_covers_soc_and_native_sysmon_sources(self):
        payload = self.load_query_payload("queries/hunting/dns_exfiltration_entropy.json")

        self.assertIn("'Log Source' = 'SOC Windows Sysmon Logs'", payload["query"])
        self.assertIn("'Log Source' = 'Windows Sysmon Operational Logs'", payload["query"])

    def test_rare_process_hunting_queries_scale_for_weekly_demo_window(self):
        expectations = {
            "queries/hunting/linux_rare_process.json": "where executions < 100",
            "queries/hunting/windows_rare_process.json": "where executions < 80",
        }

        for query_file, clause in expectations.items():
            payload = self.load_query_payload(query_file)
            self.assertIn(clause, payload["query"], query_file)

    def test_windows_security_command_queries_use_command_line_dimension(self):
        expectations = {
            "queries/cmd_suspicious_child_process.json": "'Command Line'",
            "queries/powershell_suspicious_commands.json": "'Command Line'",
        }

        for query_file, command_field in expectations.items():
            payload = self.load_query_payload(query_file)
            self.assertIn(command_field, payload["query"], query_file)
            self.assertNotIn("by Entity", payload["query"], query_file)
            self.assertNotIn("'Process Name' like '*\\\\", payload["query"], query_file)

    def test_dns_entropy_query_uses_demo_realistic_label_threshold(self):
        payload = self.load_query_payload("queries/hunting/dns_exfiltration_entropy.json")

        self.assertIn("domain_length > 14", payload["query"])

    def test_scanner_stacking_query_tolerates_small_rotating_source_ip_sets(self):
        payload = self.load_query_payload("queries/hunting/web_scanner_tool_stacking.json")

        self.assertIn("requests > 50", payload["query"])
        self.assertIn("source_ips < 5", payload["query"])


if __name__ == "__main__":
    unittest.main()
