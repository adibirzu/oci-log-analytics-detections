#!/usr/bin/env python3
"""Smoke tests for dashboard wiring and visualization metadata."""

import json
import io
import os
import re
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from deploy_dashboard import (
    DASHBOARDS,
    SUPPORTED_VISUALIZATION_TYPES,
    build_dashboard_inventory,
    build_dashboard_json,
    build_saved_search_json,
    load_sentinel_dashboard_groups,
    resolve_widget_ui_config,
    select_dashboards,
    validate_dashboard_inventory,
    validate_inventory_queries_in_oci,
)
from oci_config import QUERIES_DIR


class DashboardContractCasesC:



    def test_dashboard_inventory_exports_source_references(self):
        inventory = build_dashboard_inventory(generated_at="2026-04-28T00:00:00+00:00")
        flf_dashboard = next(
            dashboard for dashboard in inventory["dashboards"]
            if dashboard["name"] == "SOC: FreeLabFriday Threat Hunting Dashboard"
        )

        for widget in flf_dashboard["widgets"]:
            references = widget.get("references", [])
            self.assertTrue(references, widget["query_file"])
            self.assertTrue(
                references[0]["url"].startswith(
                    "https://github.com/blackhillsinfosec/FreeLabFriday_Labs"
                ),
                widget["query_file"],
            )

    def test_dashboard_inventory_validates_every_query_reference(self):
        inventory = build_dashboard_inventory(generated_at="2026-04-28T00:00:00+00:00")

        errors = validate_dashboard_inventory(inventory)

        self.assertEqual(errors, [])

    def test_dashboard_inventory_rejects_generated_support_artifact_reference(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            queries_dir = Path(tmpdir)
            (queries_dir / "sentinel_synthetic_plan.json").write_text(
                json.dumps({
                    "summary": {"synthetic_ready": 1},
                    "candidates": [{"title": "support artifact"}],
                }),
                encoding="utf-8",
            )
            inventory = {
                "summary": {"total_dashboards": 1, "total_widgets": 1},
                "dashboards": [
                    {
                        "name": "Test Dashboard",
                        "widget_count": 1,
                        "widgets": [
                            {
                                "title": "Bad Widget",
                                "query_file": "sentinel_synthetic_plan.json",
                            }
                        ],
                    }
                ],
            }

            errors = validate_dashboard_inventory(inventory, queries_dir=str(queries_dir))

            self.assertTrue(
                any(
                    "sentinel_synthetic_plan.json" in error
                    and "generated support artifact" in error
                    for error in errors
                ),
                errors,
            )

    def test_dashboard_inventory_validation_catches_query_metadata_drift(self):
        inventory = build_dashboard_inventory(generated_at="2026-04-28T00:00:00+00:00")
        inventory["dashboards"][0]["widgets"][0]["query_title"] = "Wrong title"

        errors = validate_dashboard_inventory(inventory)

        self.assertTrue(any("query_title mismatch" in error for error in errors))

    def test_dashboard_inventory_validation_catches_layout_drift(self):
        inventory = build_dashboard_inventory(generated_at="2026-04-28T00:00:00+00:00")
        inventory["dashboards"][0]["widgets"][0]["layout"] = {"width": 6, "height": 5}

        errors = validate_dashboard_inventory(inventory)

        self.assertTrue(any("layout mismatch" in error for error in errors))

    def test_dashboard_inventory_validation_catches_visualization_drift(self):
        inventory = build_dashboard_inventory(generated_at="2026-04-28T00:00:00+00:00")
        inventory["dashboards"][0]["widgets"][0]["visualization_type"] = "bar"

        errors = validate_dashboard_inventory(inventory)

        self.assertTrue(any("visualization_type mismatch" in error for error in errors))

    def test_live_validation_progress_reports_status_and_redacts_sensitive_details(self):
        inventory = {
            "dashboards": [
                {
                    "widgets": [
                        {"query_file": "apps/one.json"},
                        {"query_file": "apps/two.json"},
                    ]
                }
            ]
        }
        validation_results = [
            {"query_file": "apps/one.json", "ok": True, "rows": 2, "empty": False},
            {
                "query_file": "apps/two.json",
                "ok": False,
                "rows": 0,
                "empty": False,
                "error": self.synthetic_validation_error,
            },
        ]
        output = io.StringIO()

        with patch("deploy_dashboard.resolve_validation_namespace", return_value="redacted-namespace"), \
             patch("deploy_dashboard.get_la_client", return_value=object()), \
             patch("deploy_dashboard.load_query_info", return_value={"query": "'Log Source' = 'SOC Application Logs'"}), \
             patch("deploy_dashboard.validate_query_in_oci", side_effect=validation_results):
            with redirect_stdout(output):
                results = validate_inventory_queries_in_oci(
                    inventory,
                    progress=True,
                    progress_interval=1,
                    isolated=False,
                )

        rendered = output.getvalue()
        self.assertEqual(results, validation_results)
        self.assertIn("[001/002] apps/one.json status=passed rows=2", rendered)
        self.assertIn("[002/002] apps/two.json status=failed rows=0", rendered)
        self.assertNotIn("ocid1.", rendered)
        self.assertNotIn("abc123", rendered)
        self.assertNotIn("203.0.113.44", rendered)
        self.assertNotIn("DEFAULT", rendered)
        self.assertNotIn("captenancy", rendered)

    def test_sentinel_dashboard_loader_selects_diverse_live_passed_widgets(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            queries_dir = Path(tmpdir)
            sentinel_dir = queries_dir / "sentinel"
            sentinel_dir.mkdir(parents=True)

            def write_sentinel(filename, **overrides):
                payload = {
                    "title": filename.replace(".json", ""),
                    "query": "'Log Source' = 'SOC Windows Sysmon Logs' | stats count as Count",
                    "level": "high",
                    "source_type": "microsoft_sentinel",
                    "conversion_status": "promoted",
                    "live_validation_status": "passed",
                    "sentinel_category": "endpoint",
                    "sentinel_tables": ["DeviceProcessEvents"],
                    "mitre_attack": {"techniques": ["T1059"]},
                    "required_data_connectors": [
                        {"connector_id": "MicrosoftThreatProtection", "data_types": ["DeviceProcessEvents"]}
                    ],
                    "dashboard": {"visualizationType": "summary_table"},
                }
                payload.update(overrides)
                (sentinel_dir / filename).write_text(json.dumps(payload), encoding="utf-8")

            for index in range(4):
                write_sentinel(f"aaa_process_{index}.json")
            write_sentinel(
                "zzz_security_event.json",
                level="medium",
                sentinel_tables=["SecurityEvent"],
                mitre_attack={"techniques": ["T1078"]},
                required_data_connectors=[{"connector_id": "SecurityEvents", "data_types": ["SecurityEvent"]}],
            )
            write_sentinel(
                "zzz_network_event.json",
                level="low",
                sentinel_tables=["DeviceNetworkEvents"],
                mitre_attack={"techniques": ["T1041"]},
                required_data_connectors=[{"connector_id": "MicrosoftThreatProtection", "data_types": ["DeviceNetworkEvents"]}],
            )
            write_sentinel("not_promoted.json", conversion_status="skipped")
            write_sentinel("not_live_passed.json", live_validation_status="failed")
            write_sentinel("unsupported_pattern.json", query="'Log Source' = 'x' and Properties like '*bad*'")

            dashboards = load_sentinel_dashboard_groups(queries_dir=str(queries_dir), max_widgets=4)

            widgets = dashboards["SOC: Microsoft Sentinel Endpoint Converted Detections"]["widgets"]
            selected_files = {Path(widget["query_file"]).name for widget in widgets}
            self.assertEqual(len(widgets), 4)
            self.assertTrue({"zzz_security_event.json", "zzz_network_event.json"} & selected_files)
            self.assertFalse({"not_promoted.json", "not_live_passed.json", "unsupported_pattern.json"} & selected_files)

            selected_tables = set()
            for filename in selected_files:
                payload = json.loads((sentinel_dir / filename).read_text(encoding="utf-8"))
                selected_tables.update(payload["sentinel_tables"])
            self.assertGreaterEqual(len(selected_tables), 2)


if __name__ == "__main__":
    unittest.main()
