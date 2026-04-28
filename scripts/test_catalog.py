#!/usr/bin/env python3
"""Unit tests for the catalog generator."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from generate_catalog import generate_json_catalog, get_inventory_counts, load_query_surfaces


class TestCatalogSurfaces(unittest.TestCase):
    """Validate multi-surface catalog generation."""

    def test_catalog_includes_apps_and_inventory_split(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir)
            queries_dir = project_dir / "queries"
            apps_dir = queries_dir / "apps"
            hunting_dir = queries_dir / "hunting"
            rules_dir = project_dir / "rules" / "web" / "browser_attacks"

            apps_dir.mkdir(parents=True, exist_ok=True)
            hunting_dir.mkdir(parents=True, exist_ok=True)
            rules_dir.mkdir(parents=True, exist_ok=True)

            (queries_dir / "base_detection.json").write_text(json.dumps({
                "title": "Base Detection",
                "query": "'Log Source' = 'OCI Audit Logs'",
                "sigma_id": "sigma-base-001",
                "level": "high",
                "logsource": {"product": "oci", "service": "audit"},
                "mitre_attack": {"tactics": ["initial_access"], "techniques": ["T1078"]},
            }))
            (apps_dir / "apm_browser.json").write_text(json.dumps({
                "title": "Browser Detection",
                "query": "'Log Source' = 'SOC Application Logs'",
                "sigma_id": "sigma-browser-001",
                "level": "medium",
                "logsource": {"product": "oci", "service": "apm"},
                "mitre_attack": {"tactics": ["execution"], "techniques": ["T1059.007"]},
            }))
            (apps_dir / "app_health.json").write_text(json.dumps({
                "title": "Curated App Health",
                "query": "'Log Source' = 'SOC Application Logs'",
                "level": "informational",
                "logsource": {"product": "oci", "service": "apm"},
                "mitre_attack": {"tactics": [], "techniques": []},
            }))
            (hunting_dir / "hunt.json").write_text(json.dumps({
                "title": "Threat Hunt",
                "query": "'Log Source' = 'OCI Audit Logs' | stats count",
                "level": "high",
                "mitre_attack": {"tactics": ["discovery"], "techniques": ["T1087.001"]},
            }))

            (rules_dir / "apm_browser.yaml").write_text(
                "title: Browser Detection\n"
                "id: sigma-browser-001\n"
                "logsource:\n"
                "  product: oci\n"
                "  service: apm\n"
                "detection:\n"
                "  selection:\n"
                "    HttpUrl|contains: test\n"
                "  condition: selection\n"
            )

            detections, app_queries, hunting = load_query_surfaces(queries_dir, apps_dir, hunting_dir)
            inventory = get_inventory_counts(project_dir, queries_dir, apps_dir, hunting_dir)
            catalog = generate_json_catalog(detections, app_queries, hunting, inventory=inventory)

            self.assertEqual(len(detections), 1)
            self.assertEqual(len(app_queries), 2)
            self.assertEqual(len(hunting), 1)
            self.assertEqual(catalog["total_rules"], 1)
            self.assertEqual(catalog["total_app_queries"], 2)
            self.assertEqual(catalog["total_hunting"], 1)
            self.assertEqual(catalog["inventory"]["source_derived_app_queries"], 1)
            self.assertEqual(catalog["inventory"]["curated_app_queries"], 1)
            self.assertEqual(catalog["inventory"]["generated_sigma_queries"], 2)
            self.assertEqual(len(catalog["app_queries"]), 2)
            self.assertIn("T1059.007", catalog["all_mitre_techniques"])
            self.assertIn("T1087.001", catalog["all_mitre_techniques"])


if __name__ == "__main__":
    unittest.main()
