#!/usr/bin/env python3
"""Tests for reusable threat-hunting demo preparation."""

import os
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from prepare_threat_hunting_demo import (
    DEFAULT_TH_DASHBOARDS,
    PROJECT_DIR,
    build_commands,
    build_readiness_report,
    format_command,
    parse_args,
    run_commands,
    write_readiness_report,
)


class TestPrepareThreatHuntingDemo(unittest.TestCase):
    """Validate the local-first threat-hunting demo workflow."""

    def test_build_commands_prepares_local_demo_without_live_mutations(self):
        commands = build_commands(
            Namespace(
                days=7,
                geo_interval=15,
                dashboard_name=list(DEFAULT_TH_DASHBOARDS),
                skip_octo_apm=False,
                strict=False,
            )
        )
        flattened = [" ".join(command) for command in commands]

        self.assertIn("generate_dashboard_data.py", flattened[0])
        self.assertIn("--days 7", flattened[0])
        self.assertIn("--validate", flattened[0])
        self.assertTrue(any("octo_apm_workshop.py" in command for command in flattened))
        self.assertTrue(any("generate_catalog.py" in command for command in flattened))
        self.assertTrue(any("deploy_dashboard.py --export-inventory" in command for command in flattened))
        self.assertTrue(any("detection_rule_creator.py --write-default" in command for command in flattened))
        self.assertEqual(
            sum("deploy_dashboard.py --dry-run --dashboard-name" in command for command in flattened),
            len(DEFAULT_TH_DASHBOARDS),
        )
        self.assertFalse(any("ingest_test_data.py" in command for command in flattened))
        self.assertFalse(any("--cleanup" in command for command in flattened))
        self.assertFalse(any("--validate " in command and "deploy_dashboard.py" in command for command in flattened))

    def test_build_commands_strict_adds_expensive_gates(self):
        commands = build_commands(
            Namespace(
                days=14,
                geo_interval=30,
                dashboard_name=["SOC: 2025-2026 Threat Hunting Dashboard"],
                skip_octo_apm=True,
                strict=True,
            )
        )
        flattened = [" ".join(command) for command in commands]

        self.assertFalse(any("octo_apm_workshop.py" in command for command in flattened))
        self.assertTrue(any("query_performance_audit.py --strict" in command for command in flattened))
        self.assertTrue(any("parse_validate_all_queries.py" in command for command in flattened))
        self.assertTrue(any("pytest -q" in command for command in flattened))

    def test_format_command_uses_portable_repo_relative_paths(self):
        command = [
            sys.executable,
            str(Path(PROJECT_DIR) / "scripts" / "deploy_dashboard.py"),
            "--dry-run",
            "--dashboard-name",
            "SOC: 2025-2026 Threat Hunting Dashboard",
        ]

        formatted = format_command(command)

        self.assertTrue(formatted.startswith("python3 scripts/deploy_dashboard.py"))
        self.assertNotIn(str(PROJECT_DIR), formatted)
        self.assertIn("'SOC: 2025-2026 Threat Hunting Dashboard'", formatted)

    def test_build_readiness_report_summarizes_local_artifacts(self):
        args = Namespace(
            days=7,
            geo_interval=15,
            dashboard_name=["SOC: 2025-2026 Threat Hunting Dashboard"],
            skip_octo_apm=False,
            strict=True,
            report_json="docs/health/threat-hunting-demo-readiness.json",
        )
        report = build_readiness_report(args, [[sys.executable, "scripts/generate_catalog.py"]])

        self.assertEqual(report["evidence_class"], "locally_verified")
        self.assertTrue(report["local_only"])
        self.assertFalse(report["live_oci_mutation_performed"])
        self.assertEqual(report["days"], 7)
        self.assertGreaterEqual(report["synthetic_logs"]["total_events"], 0)
        self.assertEqual(report["synthetic_logs"]["path"], "test_data/manifest.json")
        self.assertEqual(report["catalog"]["path"], "queries/catalog.json")
        self.assertEqual(report["dashboards"]["path"], "queries/dashboard_inventory.json")
        self.assertEqual(
            report["dashboards"]["requested_dashboards"][0]["name"],
            "SOC: 2025-2026 Threat Hunting Dashboard",
        )
        self.assertIn("explicit approval", report["operator_boundary"])
        self.assertEqual(report["commands"], ["python3 scripts/generate_catalog.py"])

    def test_write_readiness_report_supports_opt_out(self):
        args = Namespace(
            days=7,
            geo_interval=15,
            dashboard_name=list(DEFAULT_TH_DASHBOARDS),
            skip_octo_apm=False,
            strict=False,
            report_json=None,
        )
        with patch("prepare_threat_hunting_demo.Path.write_text") as mock_write:
            write_readiness_report(args, [])

        mock_write.assert_not_called()

    def test_write_readiness_report_writes_requested_path(self):
        args = Namespace(
            days=7,
            geo_interval=15,
            dashboard_name=list(DEFAULT_TH_DASHBOARDS),
            skip_octo_apm=False,
            strict=False,
            report_json=None,
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "th-demo.json"
            args.report_json = str(report_path)

            write_readiness_report(args, [])

            self.assertTrue(report_path.exists())
            self.assertIn('"local_only": true', report_path.read_text())

    def test_parse_args_no_report_disables_report(self):
        with patch("prepare_threat_hunting_demo.sys.argv", ["prepare_threat_hunting_demo.py", "--no-report"]):
            args = parse_args()

        self.assertIsNone(args.report_json)

    @patch("prepare_threat_hunting_demo.subprocess.run")
    def test_run_commands_executes_from_project_root(self, mock_run):
        commands = [
            [sys.executable, str(Path(PROJECT_DIR) / "scripts" / "generate_dashboard_data.py"), "--days", "7"],
            [sys.executable, str(Path(PROJECT_DIR) / "scripts" / "deploy_dashboard.py"), "--dry-run"],
        ]

        run_commands(commands)

        self.assertEqual(mock_run.call_count, 2)
        for call in mock_run.call_args_list:
            self.assertEqual(call.kwargs["check"], True)
            self.assertEqual(Path(call.kwargs["cwd"]), Path(PROJECT_DIR))


if __name__ == "__main__":
    unittest.main()
