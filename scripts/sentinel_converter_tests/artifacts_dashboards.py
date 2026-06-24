#!/usr/bin/env python3
"""Tests for Microsoft Sentinel KQL intake and conversion."""

import json
import os
import sys
import tempfile
import unittest
from io import StringIO
from pathlib import Path

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from convert_sentinel_kql import (  # noqa: E402
    _write_query_payload,
    classify_unsupported_kql,
    convert_candidate,
    convert_candidates,
    convert_kql_to_logan,
    load_mapping_config,
    rank_candidates,
    select_top_candidates,
    validate_logan_query_local,
)
from deploy_dashboard import load_sentinel_dashboard_groups  # noqa: E402
from generate_catalog import generate_json_catalog, get_inventory_counts, load_query_surfaces  # noqa: E402
from query_artifacts import is_saved_search_query_file  # noqa: E402
from sync_sentinel_kql import normalize_sentinel_rule  # noqa: E402

class TestSentinelArtifactsAndDashboards(unittest.TestCase):
    """Validate catalog/report/dashboard integration contracts."""

    def test_sentinel_report_is_not_a_saved_search_query_file(self):
        self.assertFalse(is_saved_search_query_file("sentinel_conversion_report.json"))
        self.assertFalse(is_saved_search_query_file("sentinel_feed_dependencies.json"))

    def test_catalog_includes_sentinel_surface(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir)
            queries_dir = project_dir / "queries"
            sentinel_dir = queries_dir / "sentinel"
            apps_dir = queries_dir / "apps"
            hunting_dir = queries_dir / "hunting"
            rules_dir = project_dir / "rules" / "cloud"
            sentinel_dir.mkdir(parents=True)
            apps_dir.mkdir()
            hunting_dir.mkdir()
            rules_dir.mkdir(parents=True)

            (sentinel_dir / "failed_signin.json").write_text(json.dumps({
                "title": "Failed sign-in burst",
                "description": "Converted from Microsoft Sentinel.",
                "query": "'Log Source' = 'Azure Entra ID Sign-in Logs' | stats count as Count",
                "level": "high",
                "source_type": "microsoft_sentinel",
                "sentinel_id": "rule-001",
                "sentinel_source_path": "Detections/SigninLogs/failed_signin.yaml",
                "conversion_status": "promoted",
                "live_validation_status": "passed",
                "logsource": {"product": "microsoft_sentinel", "service": "identity"},
                "mitre_attack": {"tactics": ["initial_access"], "techniques": ["T1078"]},
                "references": [{"name": "Microsoft Sentinel", "url": "https://github.com/Azure/Azure-Sentinel"}],
            }))

            detections, app_queries, hunting = load_query_surfaces(queries_dir, apps_dir, hunting_dir)
            inventory = get_inventory_counts(project_dir, queries_dir, apps_dir, hunting_dir)
            catalog = generate_json_catalog(detections, app_queries, hunting, inventory=inventory)

            self.assertEqual(catalog["total_sentinel_queries"], 1)
            self.assertEqual(catalog["inventory"]["generated_sentinel_queries"], 1)
            self.assertEqual(catalog["sentinel_queries"][0]["sentinel_id"], "rule-001")
            self.assertEqual(catalog["sentinel_queries"][0]["conversion_status"], "promoted")

    def test_sentinel_dashboard_loader_requires_live_validation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            queries_dir = Path(tmpdir)
            sentinel_dir = queries_dir / "sentinel"
            sentinel_dir.mkdir(parents=True)

            base_payload = {
                "title": "Failed sign-in burst",
                "description": "Converted from Microsoft Sentinel.",
                "query": "'Log Source' = 'Azure Entra ID Sign-in Logs' | stats count as Count by 'User Name'",
                "level": "high",
                "source_type": "microsoft_sentinel",
                "sentinel_id": "rule-001",
                "conversion_status": "promoted",
                "sentinel_category": "identity",
                "live_validation_status": "passed",
                "dashboard": {"visualizationType": "summary_table"},
            }
            (sentinel_dir / "failed_signin.json").write_text(json.dumps(base_payload))
            skipped = {**base_payload, "sentinel_id": "rule-002", "live_validation_status": "not_run"}
            (sentinel_dir / "not_live_validated.json").write_text(json.dumps(skipped))

            dashboards = load_sentinel_dashboard_groups(queries_dir=str(queries_dir))

            identity = dashboards["SOC: Microsoft Sentinel Identity Converted Detections"]
            self.assertEqual(identity["widgets"], [
                {
                    "title": "Sentinel: Failed sign-in burst",
                    "query_file": "sentinel/failed_signin.json",
                    "visualization_type": "summary_table",
                }
            ])

    def test_sentinel_writer_avoids_title_collisions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            base_payload = {
                "title": "Duplicate Sentinel Title",
                "query": "'Log Source' = 'SOC Windows Sysmon Logs'",
                "sentinel_id": "rule-one",
            }
            first = _write_query_payload(output_dir, base_payload)
            second = _write_query_payload(output_dir, {**base_payload, "sentinel_id": "rule-two"})

            self.assertNotEqual(first, second)
            self.assertEqual(len(list(output_dir.glob("*.json"))), 2)
