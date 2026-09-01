#!/usr/bin/env python3
"""Tests for read-only threat-hunting live preflight."""

import os
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from preflight_threat_hunting_demo import (
    DEFAULT_REQUIRED_DASHBOARDS,
    build_preflight_report,
    live_command_plan,
    parse_args,
    write_report,
)


class TestPreflightThreatHuntingDemo(unittest.TestCase):
    """Validate read-only demo preflight behavior."""

    def test_preflight_report_is_read_only_and_sanitized(self):
        args = Namespace(
            days=21,
            minimum_events=1,
            dashboard_name=list(DEFAULT_REQUIRED_DASHBOARDS),
            readiness_json="docs/health/threat-hunting-demo-readiness.json",
            json="docs/health/threat-hunting-live-preflight.json",
            strict_env=False,
        )

        report = build_preflight_report(args, env={})

        self.assertTrue(report["local_only"])
        self.assertFalse(report["live_oci_mutation_performed"])
        self.assertIn(report["status"], {"PASS", "WARN", "FAIL"})
        rendered = "\n".join(report["live_command_plan"])
        self.assertIn("<OCI_PROFILE>", rendered)
        self.assertIn("<OCI_COMPARTMENT_OCID>", rendered)
        self.assertNotIn("ocid1.", rendered)

    def test_live_command_plan_uses_placeholders_and_requested_days(self):
        commands = live_command_plan(14, "docs/health/custom-readiness.json")
        rendered = "\n".join(commands)

        self.assertIn("--query-lookback 14d", rendered)
        self.assertIn("--lookback 14d", rendered)
        self.assertIn("--report-json docs/health/custom-readiness.json", rendered)
        self.assertIn("<OCI_PROFILE>", rendered)

    def test_preflight_uses_requested_readiness_path(self):
        args = Namespace(
            days=21,
            minimum_events=1,
            dashboard_name=[],
            readiness_json="docs/health/custom-readiness.json",
            json="docs/health/threat-hunting-live-preflight.json",
            strict_env=False,
        )

        report = build_preflight_report(args, env={})
        file_checks = [check["path"] for check in report["checks"] if check["name"].startswith("file:")]

        self.assertIn("docs/health/custom-readiness.json", file_checks)

    def test_write_report_supports_opt_out(self):
        with patch("preflight_threat_hunting_demo.Path.write_text") as mock_write:
            write_report({"status": "PASS"}, None)

        mock_write.assert_not_called()

    def test_write_report_writes_requested_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "preflight.json"
            write_report({"status": "PASS"}, str(path))

            self.assertTrue(path.exists())
            self.assertIn('"status": "PASS"', path.read_text())

    def test_parse_args_defaults_to_core_dashboards(self):
        with patch("preflight_threat_hunting_demo.sys.argv", ["preflight_threat_hunting_demo.py", "--no-report"]):
            args = parse_args()

        self.assertIsNone(args.json)
        self.assertEqual(args.dashboard_name, DEFAULT_REQUIRED_DASHBOARDS)


if __name__ == "__main__":
    unittest.main()
