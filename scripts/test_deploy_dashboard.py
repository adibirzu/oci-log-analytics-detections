#!/usr/bin/env python3
"""Smoke tests for dashboard wiring and visualization metadata."""

import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from deploy_dashboard import (
    DASHBOARDS,
    SUPPORTED_VISUALIZATION_TYPES,
    build_dashboard_json,
    resolve_widget_ui_config,
)
from oci_config import QUERIES_DIR


class TestDashboardContract(unittest.TestCase):
    """Validate dashboard widgets and saved-search visualization metadata."""

    def test_dashboard_widgets_reference_existing_query_files(self):
        for dashboard_name, config in DASHBOARDS.items():
            self.assertGreater(len(config["widgets"]), 0, dashboard_name)
            for widget in config["widgets"]:
                query_path = Path(QUERIES_DIR) / widget["query_file"]
                self.assertTrue(query_path.exists(), f"{dashboard_name}: missing {widget['query_file']}")

    def test_query_visualization_metadata_is_supported(self):
        for config in DASHBOARDS.values():
            for widget in config["widgets"]:
                query_path = Path(QUERIES_DIR) / widget["query_file"]
                with query_path.open() as f:
                    payload = json.load(f)

                dashboard_meta = payload.get("dashboard", {})
                visualization_type = dashboard_meta.get("visualizationType")
                if visualization_type:
                    self.assertIn(visualization_type, SUPPORTED_VISUALIZATION_TYPES, query_path.name)

                ask_ai_prompts = dashboard_meta.get("ask_ai_prompts", [])
                self.assertIsInstance(ask_ai_prompts, list, query_path.name)
                for prompt in ask_ai_prompts:
                    self.assertIsInstance(prompt, str, query_path.name)
                    self.assertTrue(prompt.strip(), query_path.name)

    def test_resolve_widget_ui_config_uses_query_dashboard_metadata(self):
        widget = {"title": "Geo map"}
        query_info = {
            "query": "'Log Source' = 'SOC Multicloud Health Logs' | stats count",
            "dashboard": {
                "visualizationType": "map",
                "ask_ai_prompts": ["Summarize the current cloud health posture."],
                "timeSelection": {"timePeriod": "l24h"},
            },
        }

        ui_config = resolve_widget_ui_config(widget, query_info)

        self.assertEqual(ui_config["visualizationType"], "map")
        self.assertEqual(ui_config["timeSelection"], {"timePeriod": "l24h"})
        self.assertEqual(ui_config["queryString"], query_info["query"])

    def test_build_dashboard_json_promotes_ask_ai_prompts_to_tags(self):
        widget = {"title": "Geo map", "query_file": "hunting/multicloud_geo_health_regional_map.json"}
        query_info = {
            "query": "'Log Source' = 'SOC Multicloud Health Logs' | stats count",
            "dashboard": {
                "visualizationType": "map",
                "ask_ai_prompts": ["Summarize the health posture."],
            },
            "tags": ["operations.health"],
        }

        dashboard = build_dashboard_json(
            dashboard_id="soc-test",
            name="Test Dashboard",
            description="test",
            widgets=[widget],
            widget_queries=[query_info],
        )

        saved_search = dashboard["savedSearches"][0]
        self.assertEqual(saved_search["uiConfig"]["visualizationType"], "map")
        self.assertIn("ask_ai_prompts", saved_search["freeformTags"])


if __name__ == "__main__":
    unittest.main()
