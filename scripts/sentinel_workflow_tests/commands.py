"""Command, status, HTML report, and triage tests for Sentinel workflow."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinel_conversion_workflow import (  # noqa: E402
    build_convert_command,
    build_parser,
    build_status,
    build_triage,
    load_promoted_query_counts,
    load_sentinel_dashboard_counts,
    main,
    render_report_html,
    resolve_top,
    write_report_html,
)


class TestSentinelConversionWorkflowCommands(unittest.TestCase):
    """Validate wrapper commands and static report rendering."""

    def test_resolve_top_accepts_all_from_candidates_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            candidates = Path(tmpdir) / "sentinel_candidates.json"
            candidates.write_text(json.dumps({"candidates": [{}, {}, {}]}), encoding="utf-8")

            self.assertEqual(resolve_top("all", candidates), 3)
            self.assertEqual(resolve_top("25", candidates), 25)

    def test_build_convert_command_uses_safe_modes(self):
        local = build_convert_command(
            mode="local",
            top=100,
            timeout=20,
            lookback="24h",
            report_path=Path("/tmp/local.json"),
            no_sync=True,
        )
        promote = build_convert_command(
            mode="promote",
            top=4452,
            timeout=20,
            lookback="24h",
            report_path=Path("queries/sentinel_conversion_report.json"),
            no_sync=True,
        )

        self.assertIn("--validate-local", local)
        self.assertNotIn("--write-working", local)
        self.assertIn("--validate-live", promote)
        self.assertIn("--write-working", promote)
        self.assertIn("--clean-output", promote)
        self.assertIn("--no-sync", promote)

    def test_build_convert_command_can_pass_progress_options(self):
        command = build_convert_command(
            mode="local",
            top=10,
            timeout=20,
            lookback="24h",
            report_path=Path("/tmp/local.json"),
            no_sync=True,
            progress_interval=5,
            progress_every=2,
        )

        self.assertIn("--progress-interval", command)
        self.assertIn("5", command)
        self.assertIn("--progress-every", command)
        self.assertIn("2", command)

    def test_parser_exposes_synthetic_plan_command(self):
        args = build_parser().parse_args([
            "synthetic-plan",
            "--top",
            "5",
            "--synthetic-plan",
            "/tmp/sentinel_synthetic_plan.json",
            "--synthetic-data-dir",
            "/tmp/sentinel_synthetic",
        ])

        self.assertEqual(args.command, "synthetic-plan")
        self.assertEqual(args.top, "5")
        self.assertEqual(args.synthetic_plan, "/tmp/sentinel_synthetic_plan.json")
        self.assertEqual(args.synthetic_data_dir, "/tmp/sentinel_synthetic")

    def test_load_promoted_query_counts_reads_generated_surface(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sentinel_dir = Path(tmpdir) / "sentinel"
            sentinel_dir.mkdir()
            (sentinel_dir / "identity.json").write_text(json.dumps({
                "sentinel_category": "identity",
                "level": "high",
                "live_validation_status": "passed",
                "sentinel_tables": ["SigninLogs"],
            }), encoding="utf-8")
            (sentinel_dir / "endpoint.json").write_text(json.dumps({
                "sentinel_category": "endpoint",
                "level": "medium",
                "live_validation_status": "passed",
                "sentinel_tables": ["DeviceProcessEvents"],
            }), encoding="utf-8")

            counts = load_promoted_query_counts(sentinel_dir)

            self.assertEqual(counts["files"], 2)
            self.assertEqual(counts["categories"], {"identity": 1, "endpoint": 1})
            self.assertEqual(counts["live_status"], {"passed": 2})
            self.assertEqual(counts["source_tables"]["SigninLogs"], 1)

    def test_dashboard_counts_include_only_sentinel_dashboards(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            inventory = Path(tmpdir) / "dashboard_inventory.json"
            inventory.write_text(json.dumps({
                "dashboards": [
                    {"name": "SOC Overview Dashboard", "widget_count": 14},
                    {
                        "name": "SOC: Microsoft Sentinel Identity Converted Detections",
                        "widget_count": 24,
                    },
                ]
            }), encoding="utf-8")

            self.assertEqual(
                load_sentinel_dashboard_counts(inventory),
                {"SOC: Microsoft Sentinel Identity Converted Detections": 24},
            )

    def test_build_status_reports_ok_for_consistent_artifacts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            report_path = root / "report.json"
            sentinel_dir = root / "sentinel"
            inventory_path = root / "dashboard_inventory.json"
            sentinel_dir.mkdir()
            report_path.write_text(json.dumps({
                "summary": {
                    "promoted_count": 1,
                    "live_validation_passed": 1,
                    "live_validation_failed": 0,
                }
            }), encoding="utf-8")
            (sentinel_dir / "one.json").write_text(json.dumps({
                "sentinel_category": "identity",
                "level": "medium",
                "live_validation_status": "passed",
            }), encoding="utf-8")
            inventory_path.write_text(json.dumps({
                "dashboards": [{
                    "name": "SOC: Microsoft Sentinel Identity Converted Detections",
                    "widget_count": 1,
                }]
            }), encoding="utf-8")

            status = build_status(
                report_path=report_path,
                sentinel_dir=sentinel_dir,
                dashboard_inventory=inventory_path,
            )

            self.assertEqual(status["status"], "ok")
            self.assertTrue(all(status["checks"].values()))

    def test_build_status_detects_count_mismatch(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            report_path = root / "report.json"
            sentinel_dir = root / "sentinel"
            sentinel_dir.mkdir()
            report_path.write_text(json.dumps({
                "summary": {
                    "promoted_count": 2,
                    "live_validation_passed": 2,
                    "live_validation_failed": 0,
                }
            }), encoding="utf-8")
            (sentinel_dir / "one.json").write_text(json.dumps({
                "sentinel_category": "identity",
                "level": "medium",
                "live_validation_status": "passed",
            }), encoding="utf-8")

            status = build_status(
                report_path=report_path,
                sentinel_dir=sentinel_dir,
                dashboard_inventory=root / "missing_inventory.json",
            )

            self.assertEqual(status["status"], "attention")
            self.assertFalse(status["checks"]["promoted_count_matches_files"])
            self.assertFalse(status["checks"]["sentinel_dashboards_present"])

    def test_render_report_html_escapes_failure_content(self):
        report = {
            "source": {"repository": "https://example.invalid/repo"},
            "summary": {
                "total_candidates": 10,
                "attempted_candidates": 10,
                "promoted_count": 7,
                "live_validation_passed": 7,
                "live_validation_failed": 1,
                "ranking": "quality-first",
            },
            "unsupported_features": {"unsupported KQL operator: join": 3},
            "attempted": [{
                "title": "<script>alert(1)</script>",
                "source_path": "Rules/example.yaml",
                "live_validation_status": "failed",
                "live_validation_error": "{'opc-request-id': 'ABC/DEF', 'message': 'Invalid <field>'}",
            }],
        }

        html_text = render_report_html(
            report,
            sentinel_counts={
                "files": 7,
                "categories": {"endpoint": 5, "identity": 2},
                "levels": {"high": 1, "medium": 6},
                "live_status": {"passed": 7},
            },
            dashboard_counts={"SOC: Microsoft Sentinel Endpoint Converted Detections": 24},
            generated_at=datetime(2026, 5, 13, tzinfo=timezone.utc),
        )

        self.assertIn("Sentinel to Logan QL Conversion", html_text)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html_text)
        self.assertIn("Invalid &lt;field&gt;", html_text)
        self.assertIn("status= code= message=Invalid", html_text)
        self.assertNotIn("opc-request-id", html_text)
        self.assertNotIn("ABC/DEF", html_text)
        self.assertIn("SOC: Microsoft Sentinel Endpoint Converted Detections", html_text)
        self.assertIn("promote --top all --timeout 20", html_text)
        self.assertIn("sentinel_conversion_workflow.py triage", html_text)
        self.assertIn("next-queries --limit 10", html_text)
        self.assertIn("status --json --strict", html_text)

    def test_write_report_html_creates_static_page(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            report_path = root / "report.json"
            output_path = root / "sentinel_converter.html"
            sentinel_dir = root / "sentinel"
            sentinel_dir.mkdir()
            report_path.write_text(json.dumps({
                "source": {},
                "summary": {
                    "total_candidates": 1,
                    "attempted_candidates": 1,
                    "promoted_count": 1,
                    "live_validation_passed": 1,
                    "live_validation_failed": 0,
                },
                "unsupported_features": {},
                "attempted": [],
            }), encoding="utf-8")
            (sentinel_dir / "one.json").write_text(json.dumps({
                "sentinel_category": "network",
                "level": "low",
                "live_validation_status": "passed",
            }), encoding="utf-8")

            written = write_report_html(
                report_path=report_path,
                output_path=output_path,
                sentinel_dir=sentinel_dir,
                dashboard_inventory=root / "missing_inventory.json",
            )

            self.assertEqual(written, output_path)
            self.assertIn("Promoted files", output_path.read_text(encoding="utf-8"))

    def test_build_triage_summarizes_skips_and_live_failures(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "report.json"
            report_path.write_text(json.dumps({
                "summary": {
                    "attempted_candidates": 4,
                    "promoted_count": 1,
                    "skipped_count": 3,
                    "live_validation_failed": 1,
                },
                "unsupported_features": {
                    "unsupported KQL operator: join": 2,
                    "unsupported Sentinel table: ExampleTable": 1,
                },
                "attempted": [
                    {
                        "title": "Skipped field",
                        "skip_reasons": ["unsupported Sentinel field mapping: FieldA"],
                        "local_validation_errors": [],
                        "live_validation_status": "not_run",
                        "live_validation_error": "",
                    },
                    {
                        "title": "Skipped table",
                        "skip_reasons": ["unsupported Sentinel table: ExampleTable"],
                        "local_validation_errors": ["unsupported OCI field reference: FieldB"],
                        "live_validation_status": "not_run",
                        "live_validation_error": "",
                    },
                    {
                        "title": "Live failed",
                        "source_path": "Rules/live.yaml",
                        "skip_reasons": ["live OCI validation failed"],
                        "local_validation_errors": [],
                        "live_validation_status": "failed",
                        "live_validation_error": "{'opc-request-id': 'ABC/DEF', 'message': 'Invalid <field>'}",
                    },
                ],
            }), encoding="utf-8")

            triage = build_triage(report_path=report_path, limit=2)

            self.assertEqual(triage["top_skip_reasons"][0]["count"], 1)
            self.assertEqual(triage["top_local_validation_errors"][0]["reason"], "unsupported OCI field reference: FieldB")
            self.assertEqual(triage["top_unsupported_features"][0]["reason"], "unsupported KQL operator: join")
            self.assertEqual(triage["live_failure_examples"][0]["title"], "Live failed")
            self.assertIn("Invalid <field>", triage["live_failure_examples"][0]["error"])
            self.assertNotIn("opc-request-id", triage["live_failure_examples"][0]["error"])
            self.assertTrue(any("unsupported field-mapping" in action for action in triage["next_actions"]))
            self.assertTrue(any("unsupported table" in action for action in triage["next_actions"]))

    def test_triage_json_command_outputs_machine_readable_summary(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "report.json"
            report_path.write_text(json.dumps({
                "summary": {
                    "attempted_candidates": 1,
                    "promoted_count": 0,
                    "skipped_count": 1,
                    "live_validation_failed": 0,
                },
                "unsupported_features": {},
                "attempted": [{
                    "title": "Skipped",
                    "skip_reasons": ["unsupported KQL operator: join"],
                    "local_validation_errors": [],
                    "live_validation_status": "not_run",
                    "live_validation_error": "",
                }],
            }), encoding="utf-8")

            output = StringIO()
            with redirect_stdout(output):
                exit_code = main([
                    "triage",
                    "--report", str(report_path),
                    "--json",
                    "--limit", "1",
                ])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.getvalue())
            self.assertEqual(payload["summary"]["attempted_candidates"], 1)
            self.assertEqual(payload["top_skip_reasons"][0]["reason"], "unsupported KQL operator: join")
