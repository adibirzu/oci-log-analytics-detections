"""Backlog and strict status tests for Sentinel workflow."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinel_conversion_workflow import build_next_query_backlog, main  # noqa: E402


class TestSentinelConversionWorkflowBacklogStatus(unittest.TestCase):
    """Validate backlog prioritization and strict status command behavior."""

    def test_build_next_query_backlog_prioritizes_actionable_candidates(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "report.json"
            report_path.write_text(json.dumps({
                "summary": {
                    "attempted_candidates": 6,
                    "promoted_count": 1,
                    "skipped_count": 5,
                    "live_validation_failed": 2,
                },
                "attempted": [
                    {
                        "title": "Promoted",
                        "sentinel_id": "promoted",
                        "quality_score": 999,
                        "conversion_status": "promoted",
                        "skip_reasons": [],
                        "local_validation_errors": [],
                        "live_validation_status": "passed",
                        "live_validation_error": "",
                    },
                    {
                        "title": "Field Mapping",
                        "sentinel_id": "field",
                        "quality_score": 200,
                        "source_path": "Rules/field.yaml",
                        "source_url": "https://example.invalid/field",
                        "conversion_status": "skipped",
                        "skip_reasons": ["unsupported Sentinel field mapping: FieldA"],
                        "local_validation_errors": [],
                        "live_validation_status": "not_run",
                        "live_validation_error": "",
                    },
                    {
                        "title": "Live Failed",
                        "sentinel_id": "live",
                        "quality_score": 10,
                        "source_path": "Rules/live.yaml",
                        "source_url": "https://example.invalid/live",
                        "conversion_status": "skipped",
                        "skip_reasons": ["live OCI validation failed"],
                        "local_validation_errors": [],
                        "live_validation_status": "failed",
                        "live_validation_error": "{'opc-request-id': 'ABC/DEF', 'message': 'Invalid <field>'}",
                    },
                    {
                        "title": "Live Environment",
                        "sentinel_id": "env",
                        "quality_score": 5,
                        "source_path": "Rules/env.yaml",
                        "source_url": "https://example.invalid/env",
                        "conversion_status": "skipped",
                        "skip_reasons": ["live OCI validation failed"],
                        "local_validation_errors": [],
                        "live_validation_status": "failed",
                        "live_validation_error": "{'status': 401, 'code': 'NotAuthenticated', 'message': 'clock skew'}",
                    },
                    {
                        "title": "Live Throttled",
                        "sentinel_id": "throttled",
                        "quality_score": 70,
                        "source_path": "Rules/throttled.yaml",
                        "source_url": "https://example.invalid/throttled",
                        "conversion_status": "skipped",
                        "skip_reasons": ["live OCI validation failed"],
                        "local_validation_errors": [],
                        "live_validation_status": "failed",
                        "live_validation_error": "{'status': 429, 'code': 'TooManyRequests', 'message': 'RequestThrottled'}",
                    },
                    {
                        "title": "KQL Join",
                        "sentinel_id": "join",
                        "quality_score": 300,
                        "source_path": "Rules/join.yaml",
                        "source_url": "https://example.invalid/join",
                        "conversion_status": "skipped",
                        "skip_reasons": ["unsupported KQL operator: join"],
                        "local_validation_errors": [],
                        "live_validation_status": "not_run",
                        "live_validation_error": "",
                    },
                    {
                        "title": "Local Error",
                        "sentinel_id": "local",
                        "quality_score": 50,
                        "source_path": "Rules/local.yaml",
                        "source_url": "https://example.invalid/local",
                        "conversion_status": "skipped",
                        "skip_reasons": [],
                        "local_validation_errors": ["unsupported OCI field reference: FieldB"],
                        "live_validation_status": "not_run",
                        "live_validation_error": "",
                    },
                ],
            }), encoding="utf-8")

            backlog = build_next_query_backlog(report_path=report_path, limit=10)

            self.assertEqual(backlog["candidate_count"], 6)
            self.assertEqual([item["work_type"] for item in backlog["candidates"]], [
                "live_environment",
                "live_environment",
                "live_validation",
                "local_validation",
                "field_mapping",
                "kql_support",
            ])
            self.assertEqual(backlog["candidates"][0]["title"], "Live Throttled")
            self.assertEqual(backlog["candidates"][1]["title"], "Live Environment")
            self.assertEqual(backlog["candidates"][2]["title"], "Live Failed")
            self.assertIn("Invalid <field>", backlog["candidates"][2]["reason"])
            self.assertNotIn("opc-request-id", backlog["candidates"][2]["reason"])

    def test_build_next_query_backlog_supports_foundational_strategy(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "report.json"
            attempted = [
                {
                    "title": "Live Environment",
                    "sentinel_id": "env",
                    "quality_score": 10,
                    "conversion_status": "skipped",
                    "skip_reasons": ["live OCI validation failed"],
                    "local_validation_errors": [],
                    "live_validation_status": "failed",
                    "live_validation_error": "{'status': 401, 'code': 'NotAuthenticated', 'message': 'clock skew'}",
                },
                {
                    "title": "Live Validation",
                    "sentinel_id": "live",
                    "quality_score": 20,
                    "conversion_status": "skipped",
                    "skip_reasons": ["live OCI validation failed"],
                    "local_validation_errors": [],
                    "live_validation_status": "failed",
                    "live_validation_error": "{'message': 'Invalid query'}",
                },
                {
                    "title": "Local Validation",
                    "sentinel_id": "local",
                    "quality_score": 30,
                    "conversion_status": "skipped",
                    "skip_reasons": [],
                    "local_validation_errors": ["unsupported OCI field reference: FieldB"],
                    "live_validation_status": "not_run",
                    "live_validation_error": "",
                },
                {
                    "title": "Field Mapping",
                    "sentinel_id": "field",
                    "quality_score": 40,
                    "conversion_status": "skipped",
                    "skip_reasons": ["unsupported Sentinel field mapping: FieldA"],
                    "local_validation_errors": [],
                    "live_validation_status": "not_run",
                    "live_validation_error": "",
                },
                {
                    "title": "Table Mapping",
                    "sentinel_id": "table",
                    "quality_score": 50,
                    "conversion_status": "skipped",
                    "skip_reasons": ["unsupported Sentinel table: ExampleTable"],
                    "local_validation_errors": [],
                    "live_validation_status": "not_run",
                    "live_validation_error": "",
                },
                {
                    "title": "KQL Support",
                    "sentinel_id": "kql",
                    "quality_score": 60,
                    "conversion_status": "skipped",
                    "skip_reasons": ["unsupported KQL operator: join"],
                    "local_validation_errors": [],
                    "live_validation_status": "not_run",
                    "live_validation_error": "",
                },
                {
                    "title": "Unsupported",
                    "sentinel_id": "unsupported",
                    "quality_score": 70,
                    "conversion_status": "skipped",
                    "skip_reasons": ["missing required product connector"],
                    "local_validation_errors": [],
                    "live_validation_status": "not_run",
                    "live_validation_error": "",
                },
            ]
            report_path.write_text(json.dumps({
                "summary": {"attempted_candidates": len(attempted)},
                "attempted": attempted,
            }), encoding="utf-8")

            foundational = build_next_query_backlog(
                report_path=report_path,
                strategy="foundational",
                limit=10,
            )
            default = build_next_query_backlog(
                report_path=report_path,
                strategy="default",
                limit=10,
            )

            self.assertEqual(foundational["strategy"], "foundational")
            self.assertEqual([item["work_type"] for item in foundational["candidates"]], [
                "field_mapping",
                "table_mapping",
                "kql_support",
                "local_validation",
                "live_validation",
                "live_environment",
                "unsupported",
            ])
            self.assertEqual(default["strategy"], "default")
            self.assertEqual([item["work_type"] for item in default["candidates"]], [
                "live_environment",
                "live_validation",
                "local_validation",
                "field_mapping",
                "table_mapping",
                "kql_support",
                "unsupported",
            ])

    def test_next_query_backlog_includes_oci_gap_for_mapping_candidates(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "report.json"
            report_path.write_text(json.dumps({
                "summary": {"attempted_candidates": 3},
                "attempted": [
                    {
                        "title": "Field Mapping",
                        "sentinel_id": "field",
                        "quality_score": 100,
                        "conversion_status": "skipped",
                        "skip_reasons": ["unsupported Sentinel field mapping: AccountUPN"],
                        "local_validation_errors": [],
                        "live_validation_status": "not_run",
                        "live_validation_error": "",
                    },
                    {
                        "title": "Table Mapping",
                        "sentinel_id": "table",
                        "quality_score": 90,
                        "conversion_status": "skipped",
                        "skip_reasons": ["unsupported Sentinel table: TheomAlerts_CL"],
                        "local_validation_errors": [],
                        "live_validation_status": "not_run",
                        "live_validation_error": "",
                    },
                    {
                        "title": "KQL Support",
                        "sentinel_id": "kql",
                        "quality_score": 80,
                        "conversion_status": "skipped",
                        "skip_reasons": ["unsupported KQL operator: join"],
                        "local_validation_errors": [],
                        "live_validation_status": "not_run",
                        "live_validation_error": "",
                    },
                ],
            }), encoding="utf-8")

            backlog = build_next_query_backlog(
                report_path=report_path,
                strategy="foundational",
                limit=10,
            )
            field_candidate = backlog["candidates"][0]
            table_candidate = backlog["candidates"][1]
            kql_candidate = backlog["candidates"][2]

            expected_steps = [
                "confirm OCI source",
                "define parser or parser mapping",
                "define fields and aliases",
                "ingest representative sample logs",
                "validate in CAP tenancy",
                "update field dictionary",
                "add allow-list mapping",
                "add converter tests",
            ]
            self.assertEqual(field_candidate["oci_gap"], {
                "gap_type": "field_mapping",
                "blocked_on": "AccountUPN",
                "oci_steps": expected_steps,
            })
            self.assertEqual(table_candidate["oci_gap"], {
                "gap_type": "table_mapping",
                "blocked_on": "TheomAlerts_CL",
                "oci_steps": expected_steps,
            })
            self.assertNotIn("oci_gap", kql_candidate)

    def test_next_queries_json_command_filters_by_work_type(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "report.json"
            report_path.write_text(json.dumps({
                "summary": {"attempted_candidates": 2},
                "attempted": [
                    {
                        "title": "Field Mapping",
                        "sentinel_id": "field",
                        "quality_score": 100,
                        "conversion_status": "skipped",
                        "skip_reasons": ["unsupported Sentinel field mapping: FieldA"],
                        "local_validation_errors": [],
                        "live_validation_status": "not_run",
                        "live_validation_error": "",
                    },
                    {
                        "title": "Table Mapping",
                        "sentinel_id": "table",
                        "quality_score": 200,
                        "conversion_status": "skipped",
                        "skip_reasons": ["unsupported Sentinel table: ExampleTable"],
                        "local_validation_errors": [],
                        "live_validation_status": "not_run",
                        "live_validation_error": "",
                    },
                ],
            }), encoding="utf-8")

            output = StringIO()
            with redirect_stdout(output):
                exit_code = main([
                    "next-queries",
                    "--report", str(report_path),
                    "--json",
                    "--work-type", "table_mapping",
                    "--strategy", "foundational",
                    "--limit", "5",
                ])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.getvalue())
            self.assertEqual(payload["work_type"], "table_mapping")
            self.assertEqual(payload["strategy"], "foundational")
            self.assertEqual(payload["candidate_count"], 1)
            self.assertEqual(payload["candidates"][0]["title"], "Table Mapping")

    def test_status_strict_returns_nonzero_for_attention(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            report_path = root / "report.json"
            sentinel_dir = root / "sentinel"
            inventory_path = root / "dashboard_inventory.json"
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
            inventory_path.write_text(json.dumps({"dashboards": []}), encoding="utf-8")

            with redirect_stdout(StringIO()):
                exit_code = main([
                    "status",
                    "--report", str(report_path),
                    "--sentinel-dir", str(sentinel_dir),
                    "--dashboard-inventory", str(inventory_path),
                    "--strict",
                ])

            self.assertEqual(exit_code, 1)

    def test_status_strict_returns_zero_for_ok(self):
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

            with redirect_stdout(StringIO()):
                exit_code = main([
                    "status",
                    "--report", str(report_path),
                    "--sentinel-dir", str(sentinel_dir),
                    "--dashboard-inventory", str(inventory_path),
                    "--strict",
                ])

            self.assertEqual(exit_code, 0)
