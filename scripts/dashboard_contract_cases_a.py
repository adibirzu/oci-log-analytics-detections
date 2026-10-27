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


UNSUPPORTED_DASHBOARD_QUERY_PATTERNS = (
    "regexextract(",
    "countif(",
    "case(",
    " REGEX MATCH ",
    "TicketEncryptionType",
    "PrivilegeList",
    "Properties like",
    "'Request Action Type'",
    "'Target Server Name'",
)


class DashboardContractCasesA:
    """Validate dashboard widgets and saved-search visualization metadata."""

    def test_dashboard_widgets_reference_existing_query_files(self):
        for dashboard_name, config in DASHBOARDS.items():
            self.assertGreater(len(config["widgets"]), 0, dashboard_name)
            for widget in config["widgets"]:
                query_path = Path(QUERIES_DIR) / widget["query_file"]
                self.assertTrue(query_path.exists(), f"{dashboard_name}: missing {widget['query_file']}")

    def test_dashboards_stay_under_oci_widget_limit(self):
        for dashboard_name, config in DASHBOARDS.items():
            self.assertLessEqual(
                len(config["widgets"]),
                30,
                f"{dashboard_name} has too many widgets for a focused SOC dashboard",
            )

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

    def test_dashboard_queries_avoid_unsupported_live_validation_patterns(self):
        for dashboard_name, config in DASHBOARDS.items():
            for widget in config["widgets"]:
                query_path = Path(QUERIES_DIR) / widget["query_file"]
                with query_path.open() as f:
                    payload = json.load(f)

                query = payload["query"]
                for pattern in UNSUPPORTED_DASHBOARD_QUERY_PATTERNS:
                    self.assertNotIn(
                        pattern,
                        query,
                        f"{dashboard_name}: {widget['query_file']} contains {pattern}",
                    )

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

    def test_resolve_widget_ui_config_defaults_to_demo_ready_time_window(self):
        widget = {"title": "Default time widget"}
        query_info = {"query": "'Log Source' = 'SOC Windows Sysmon Logs' | stats count"}

        ui_config = resolve_widget_ui_config(widget, query_info)

        self.assertEqual(ui_config["timeSelection"], {"timePeriod": "l21d"})

    def test_build_saved_search_json_defaults_to_demo_ready_time_window(self):
        saved_search = build_saved_search_json(
            search_id="default-time",
            title="Default Time",
            query="'Log Source' = 'SOC Windows Sysmon Logs' | stats count",
        )

        self.assertEqual(saved_search["uiConfig"]["timeSelection"], {"timePeriod": "l21d"})

    def test_build_dashboard_json_time_parameter_matches_widget_default(self):
        widget = {"title": "Default Time", "query_file": "default_time.json"}
        query_info = {"query": "'Log Source' = 'SOC Windows Sysmon Logs' | stats count"}

        dashboard = build_dashboard_json(
            dashboard_id="soc-default-time",
            name="Default Time Dashboard",
            description="test",
            widgets=[widget],
            widget_queries=[query_info],
        )

        time_parameter = next(
            parameter for parameter in dashboard["parametersConfig"]
            if parameter["paramName"] == "time"
        )
        saved_search = dashboard["savedSearches"][0]
        self.assertEqual(time_parameter["defaultValue"], "l21d")
        self.assertEqual(saved_search["uiConfig"]["timeSelection"], {"timePeriod": "l21d"})

    def test_build_dashboard_json_saved_search_ids_unique_per_deploy(self):
        # Saved-search IDs must carry the dashboard's per-deploy suffix so OCI's
        # soft-delete cannot resurrect a stale same-named saved search after a
        # --cleanup run. Two deploys (different dashboard_id) must yield different
        # saved-search IDs, and every tile reference must match a saved search.
        widget = {"title": "Reverse Shell", "query_file": "linux_reverse_shell_detected.json"}
        query_info = {"query": "'Log Source' = 'SOC Linux Syslog Logs' | stats count"}

        first = build_dashboard_json(
            dashboard_id="soc-overview-1111111111",
            name="SOC Overview", description="test",
            widgets=[widget], widget_queries=[query_info],
        )
        second = build_dashboard_json(
            dashboard_id="soc-overview-2222222222",
            name="SOC Overview", description="test",
            widgets=[widget], widget_queries=[query_info],
        )

        first_id = first["savedSearches"][0]["id"]
        second_id = second["savedSearches"][0]["id"]
        self.assertTrue(first_id.endswith("-1111111111"), first_id)
        self.assertTrue(second_id.endswith("-2222222222"), second_id)
        self.assertNotEqual(first_id, second_id)
        # Tile reference stays consistent with the embedded saved search.
        self.assertEqual(first["tiles"][0]["savedSearchId"], first_id)
        self.assertEqual(second["tiles"][0]["savedSearchId"], second_id)

    def test_build_dashboard_json_layout_prevents_tile_overlap(self):
        for dashboard_name, config in DASHBOARDS.items():
            widget_queries = []
            for widget in config["widgets"]:
                with (Path(QUERIES_DIR) / widget["query_file"]).open() as f:
                    widget_queries.append(json.load(f))

            dashboard = build_dashboard_json(
                dashboard_id=f"layout-{dashboard_name}",
                name=dashboard_name,
                description=config["description"],
                widgets=config["widgets"],
                widget_queries=widget_queries,
            )

            tiles = dashboard["tiles"]
            for left_index, left in enumerate(tiles):
                for right in tiles[left_index + 1:]:
                    separated = (
                        left["column"] + left["width"] <= right["column"]
                        or right["column"] + right["width"] <= left["column"]
                        or left["row"] + left["height"] <= right["row"]
                        or right["row"] + right["height"] <= left["row"]
                    )
                    self.assertTrue(
                        separated,
                        f"{dashboard_name}: {left['displayName']} overlaps {right['displayName']}",
                    )

    def test_table_widgets_get_full_width_layout(self):
        widgets = [
            {"title": "Wide Table 1", "query_file": "wide_table_1.json"},
            {"title": "Wide Table 2", "query_file": "wide_table_2.json"},
        ]
        query_info = {
            "query": "'Log Source' = 'SOC Application Logs' | stats count by 'Trace ID', 'Span Name'",
            "dashboard": {"visualizationType": "table"},
        }

        dashboard = build_dashboard_json(
            dashboard_id="wide-table-layout",
            name="Wide Table Layout",
            description="test",
            widgets=widgets,
            widget_queries=[query_info, query_info],
        )

        first, second = dashboard["tiles"]
        self.assertEqual(first["width"], 12)
        self.assertEqual(second["width"], 12)
        self.assertGreaterEqual(second["row"], first["row"] + first["height"])

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

    def test_select_dashboards_filters_by_display_name(self):
        selected = select_dashboards(["C2 & Beaconing Detection"])

        self.assertEqual(list(selected), ["C2 & Beaconing Detection"])
        self.assertEqual(len(selected["C2 & Beaconing Detection"]["widgets"]), 10)

    def test_dashboard_inventory_exports_query_metadata(self):
        inventory = build_dashboard_inventory(generated_at="2026-04-28T00:00:00+00:00")

        self.assertEqual(inventory["summary"]["total_dashboards"], len(DASHBOARDS))
        self.assertEqual(
            inventory["summary"]["total_widgets"],
            sum(len(config["widgets"]) for config in DASHBOARDS.values()),
        )
        self.assertIn("visualization_types", inventory["summary"])

        browser_dashboard = next(
            dashboard for dashboard in inventory["dashboards"]
            if dashboard["name"] == "SOC: Browser Attack Detection Dashboard"
        )
        total_attacks = next(
            widget for widget in browser_dashboard["widgets"]
            if widget["query_file"] == "apps/apm_total_attacks_kpi.json"
        )

        self.assertEqual(total_attacks["query_title"], "APM: Total Browser Attacks (24h)")
        self.assertEqual(total_attacks["visualization_type"], "tile")
        self.assertEqual(total_attacks["level"], "informational")
        self.assertIn("apm", total_attacks["tags"])

    def test_web_to_cloud_dashboard_covers_investigation_drilldown_widgets(self):
        dashboard = DASHBOARDS["SOC: Web-to-Cloud Threat Hunting Dashboard"]
        expected_query_files = {
            "hunting/web_to_cloud_attack_timeline.json",
            "hunting/web_to_cloud_entry_point.json",
            "hunting/web_to_cloud_compromised_machines.json",
            "hunting/web_to_cloud_compromised_identity.json",
            "hunting/web_to_cloud_vcn_egress.json",
            "hunting/web_to_cloud_firewall_c2.json",
            "hunting/web_to_cloud_cloud_abuse.json",
            "hunting/web_to_cloud_exfiltration.json",
            "hunting/web_to_cloud_attack_path_link.json",
            "hunting/web_to_cloud_mitre_sunburst.json",
        }
        actual_query_files = {widget["query_file"] for widget in dashboard["widgets"]}

        self.assertEqual(expected_query_files, actual_query_files)
        self.assertIn("entry point", dashboard["description"].lower())
        self.assertIn("exfiltration", dashboard["description"].lower())

        visualization_types = {}
        for query_file in expected_query_files:
            query_path = Path(QUERIES_DIR) / query_file
            with query_path.open() as f:
                payload = json.load(f)
            visualization_types[query_file] = payload.get("dashboard", {}).get("visualizationType")
            self.assertTrue(payload.get("dashboard", {}).get("ask_ai_prompts"), query_file)

        self.assertEqual(visualization_types["hunting/web_to_cloud_attack_path_link.json"], "link")
        # MITRE rollup renders as summary_table: a stats query under a sunburst viz
        # triggers OCI's records-companion "| fields Time" append and errors at render.
        self.assertEqual(visualization_types["hunting/web_to_cloud_mitre_sunburst.json"], "summary_table")
        self.assertIn("summary_table", set(visualization_types.values()))

    def test_c2_dashboard_covers_legacy_widgets_with_drilldowns(self):
        dashboard = DASHBOARDS["C2 & Beaconing Detection"]
        expected_query_files = {
            "hunting/c2_top_dns_domains.json",
            "hunting/c2_beacon_activity_timeline.json",
            "hunting/c2_dns_beacon_queries_kpi.json",
            "hunting/c2_destination_ips.json",
            "hunting/c2_communication_topology.json",
            "hunting/c2_dns_beacon_sources.json",
            "hunting/c2_unique_domains_kpi.json",
            "hunting/c2_flow_connections_kpi.json",
            "hunting/c2_https_beaconing.json",
            "hunting/c2_affected_hosts_kpi.json",
        }
        actual_query_files = {widget["query_file"] for widget in dashboard["widgets"]}

        self.assertEqual(expected_query_files, actual_query_files)
        self.assertIn("command-and-control", dashboard["description"].lower())

        visualization_types = {}
        for query_file in expected_query_files:
            query_path = Path(QUERIES_DIR) / query_file
            with query_path.open() as f:
                payload = json.load(f)
            visualization_types[query_file] = payload.get("dashboard", {}).get("visualizationType")
            self.assertEqual(payload.get("dashboard", {}).get("timeSelection"), {"timePeriod": "l21d"})
            self.assertTrue(payload.get("dashboard", {}).get("ask_ai_prompts"), query_file)

        self.assertEqual(visualization_types["hunting/c2_communication_topology.json"], "link")
        self.assertEqual(visualization_types["hunting/c2_beacon_activity_timeline.json"], "line")
        self.assertEqual(visualization_types["hunting/c2_dns_beacon_queries_kpi.json"], "tile")
        self.assertIn("summary_table", set(visualization_types.values()))
