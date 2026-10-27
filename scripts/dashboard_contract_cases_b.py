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


class DashboardContractCasesB:



    def test_octo_apm_dashboard_covers_logs_spans_and_metrics(self):
        dashboard = DASHBOARDS["OCI-DEMO: Octo APM Demo Dashboard"]
        expected_query_files = {
            "apps/apm_octo_red_metrics.json",
            "apps/apm_octo_request_timeline.json",
            "apps/apm_octo_span_latency_hotspots.json",
            "apps/apm_octo_trace_logs_correlation.json",
            "apps/apm_octo_trace_investigation_tiles.json",
            "apps/apm_octo_span_link.json",
            "apps/apm_octo_error_logs.json",
            "apps/apm_octo_metric_samples.json",
            "apps/apm_octo_db_spans.json",
            "apps/apm_octo_java_sidecar_errors.json",
            "apps/apm_octo_api_gateway_edge.json",
            "apps/apm_octo_attack_timeline.json",
            "apps/apm_octo_attack_path_link.json",
            "apps/apm_octo_attack_trace_correlation.json",
            "apps/apm_octo_payment_threats.json",
            "apps/apm_octo_osquery_findings.json",
            "apps/apm_octo_compromised_vm_pivots.json",
        }
        actual_query_files = {widget["query_file"] for widget in dashboard["widgets"]}
        widgets_by_query_file = {widget["query_file"]: widget for widget in dashboard["widgets"]}

        self.assertEqual(expected_query_files, actual_query_files)
        self.assertIn("octo-apm-demo", dashboard["description"])

        visualization_types = set()
        for query_file in expected_query_files:
            query_path = Path(QUERIES_DIR) / query_file
            with query_path.open() as f:
                payload = json.load(f)

            query = payload["query"]
            visualization_types.add(payload.get("dashboard", {}).get("visualizationType"))
            self.assertIn("'Log Source' = 'SOC Application Logs'", query)
            self.assertIn("'Service Namespace' = 'octo'", query)
            self.assertTrue(payload.get("dashboard", {}).get("ask_ai_prompts"), query_file)
            self.assertEqual(
                resolve_widget_ui_config(widgets_by_query_file[query_file], payload)["timeSelection"],
                {"timePeriod": "l21d"},
                query_file,
            )

        self.assertIn("link", visualization_types)
        self.assertIn("line", visualization_types)
        self.assertIn("summary_table", visualization_types)

        attack_queries = {
            "apps/apm_octo_attack_timeline.json",
            "apps/apm_octo_attack_path_link.json",
            "apps/apm_octo_attack_trace_correlation.json",
            "apps/apm_octo_payment_threats.json",
            "apps/apm_octo_osquery_findings.json",
            "apps/apm_octo_compromised_vm_pivots.json",
        }
        for query_file in attack_queries:
            with (Path(QUERIES_DIR) / query_file).open() as f:
                payload = json.load(f)
            query = payload["query"]
            self.assertIn("'Attack ID'", query)
            self.assertTrue(
                any(token in query for token in (
                    "'Payment Redirect URL'",
                    "'Payment Interception'",
                    "'Compromised VM'",
                    "'OSQuery Finding'",
                    "'Attack Stage'",
                )),
                query_file,
            )

    def test_link_tile_layout_metadata_is_well_formed(self):
        expected_tile_layout_queries = {
            "apps/apm_octo_span_link.json",
            "apps/apm_octo_attack_path_link.json",
            "apps/apm_octo_trace_investigation_tiles.json",
            "apps/apm_trace_correlation_link.json",
            "hunting/bluelight_attack_path_link.json",
            "hunting/c2_communication_topology.json",
            "hunting/flf_port_knocking_sequence.json",
            "hunting/melts_attack_path_link.json",
            "hunting/web_to_cloud_attack_path_link.json",
        }
        tiled_queries = set()

        for config in DASHBOARDS.values():
            for widget in config["widgets"]:
                query_file = widget["query_file"]
                query_path = Path(QUERIES_DIR) / query_file
                with query_path.open() as f:
                    payload = json.load(f)

                dashboard_meta = payload.get("dashboard", {})
                options = dashboard_meta.get("visualizationOptions", {})
                tile_layout_xml = options.get("tileLayoutXml")
                if not tile_layout_xml:
                    continue

                tiled_queries.add(query_file)
                self.assertEqual(dashboard_meta.get("visualizationType"), "link", query_file)
                self.assertIn("Tiles", options.get("dashboardOptions", []), query_file)
                self.assertIn("Main Table", options.get("dashboardOptions", []), query_file)

                root = ET.fromstring(tile_layout_xml)
                self.assertEqual(root.tag, "summary", query_file)
                tile_fields = {
                    tile.attrib["field"]
                    for tile in root.iter("tile")
                    if tile.attrib.get("field")
                }
                self.assertGreater(len(tile_fields), 0, query_file)
                for field in tile_fields:
                    self.assertIn(f" as {field}", payload["query"], query_file)

        self.assertTrue(expected_tile_layout_queries.issubset(tiled_queries))

    def test_melts_dashboard_covers_weekly_melts_workflow(self):
        dashboard = DASHBOARDS["SOC: 2025-2026 Threat Hunting Dashboard"]
        expected_query_files = {
            "hunting/melts_datasource_coverage_kpi.json",
            "hunting/melts_attack_signal_overview.json",
            "hunting/melts_attack_timeline.json",
            "hunting/melts_attack_path_link.json",
            "hunting/melts_last_week_risk_exposure.json",
            "hunting/melts_apm_log_trace_correlation.json",
            "hunting/clickfix_clipboard_powershell_execution.json",
            "hunting/clickfix_lolbin_payload_execution.json",
            "hunting/crashfix_python_rat_activity.json",
            "hunting/sharepoint_toolshell_exploitation.json",
            "hunting/sharepoint_toolshell_webshell_post_exploit.json",
            "hunting/rmm_post_compromise_activity.json",
            "hunting/cloud_identity_aitm_token_abuse.json",
            "hunting/cloud_identity_control_plane_takeover.json",
            "hunting/cloud_control_plane_discovery_burst.json",
            "hunting/cloud_secret_and_object_collection.json",
            "hunting/exfiltration_after_initial_access_2025_2026.json",
            "hunting/compromised_machines_and_data_2025_2026.json",
        }
        actual_query_files = {widget["query_file"] for widget in dashboard["widgets"]}

        self.assertEqual(expected_query_files, actual_query_files)
        self.assertIn("MELTS", dashboard["description"])

        weekly_queries = {
            "hunting/melts_datasource_coverage_kpi.json": "tile",
            "hunting/melts_last_week_risk_exposure.json": "summary_table",
            "hunting/melts_apm_log_trace_correlation.json": "summary_table",
        }
        for query_file, visualization_type in weekly_queries.items():
            with (Path(QUERIES_DIR) / query_file).open() as f:
                payload = json.load(f)
            self.assertEqual(payload["dashboard"]["visualizationType"], visualization_type)
            self.assertEqual(payload["dashboard"]["timeSelection"], {"timePeriod": "l7d"})
            self.assertTrue(payload["dashboard"]["ask_ai_prompts"], query_file)

        with (Path(QUERIES_DIR) / "hunting/melts_attack_path_link.json").open() as f:
            link_payload = json.load(f)
        options = link_payload["dashboard"]["visualizationOptions"]
        self.assertIn("Tiles", options["dashboardOptions"])
        self.assertIn("Main Table", options["dashboardOptions"])
        self.assertIn("show(id=containment-pivots", options["tileLayoutXml"])
        self.assertIn(" as Stages", link_payload["query"])

    def test_link_commands_stay_within_oci_field_limit(self):
        """OCI Log Analytics link commands used by dashboards support up to four fields."""
        for config in DASHBOARDS.values():
            for widget in config["widgets"]:
                query_file = widget["query_file"]
                with (Path(QUERIES_DIR) / query_file).open() as f:
                    payload = json.load(f)

                for command in payload["query"].split("|"):
                    command = command.strip()
                    if not command.lower().startswith("link "):
                        continue
                    link_fields = re.findall(r"'([^']+)'", command)
                    self.assertLessEqual(
                        len(link_fields),
                        4,
                        f"{query_file} link command exceeds OCI Log Analytics four-field LINK limit",
                    )

    def test_freelabfriday_dashboard_carries_source_references(self):
        dashboard = DASHBOARDS["SOC: FreeLabFriday Threat Hunting Dashboard"]
        expected_query_files = {
            "hunting/flf_dns_c2_pattern_analysis.json",
            "hunting/flf_bits_exfiltration.json",
            "hunting/flf_cloud_service_exfiltration.json",
            "hunting/flf_domain_fronting_cdn_c2.json",
            "hunting/flf_vsagent_http_beaconing.json",
            "hunting/flf_credential_stuffing_pattern.json",
            "hunting/flf_new_user_persistence.json",
            "hunting/flf_port_knocking_sequence.json",
        }
        actual_query_files = {widget["query_file"] for widget in dashboard["widgets"]}

        self.assertEqual(expected_query_files, actual_query_files)
        self.assertIn("FreeLabFriday", dashboard["description"])

        visualization_types = {}
        for query_file in expected_query_files:
            query_path = Path(QUERIES_DIR) / query_file
            with query_path.open() as f:
                payload = json.load(f)

            references = payload.get("references", [])
            visualization_types[query_file] = payload.get("dashboard", {}).get("visualizationType")

            self.assertTrue(references, query_file)
            self.assertTrue(payload.get("dashboard", {}).get("ask_ai_prompts"), query_file)
            for reference in references:
                self.assertTrue(
                    reference.get("url", "").startswith(
                        "https://github.com/blackhillsinfosec/FreeLabFriday_Labs"
                    ),
                    query_file,
                )

        self.assertEqual(visualization_types["hunting/flf_vsagent_http_beaconing.json"], "line")
        self.assertEqual(visualization_types["hunting/flf_port_knocking_sequence.json"], "link")
        self.assertIn("summary_table", set(visualization_types.values()))

    def test_2025_2026_dashboard_covers_modern_attack_drilldowns(self):
        dashboard = DASHBOARDS["SOC: 2025-2026 Threat Hunting Dashboard"]
        expected_query_files = {
            "hunting/melts_datasource_coverage_kpi.json",
            "hunting/melts_attack_signal_overview.json",
            "hunting/melts_attack_timeline.json",
            "hunting/melts_attack_path_link.json",
            "hunting/melts_last_week_risk_exposure.json",
            "hunting/melts_apm_log_trace_correlation.json",
            "hunting/clickfix_clipboard_powershell_execution.json",
            "hunting/clickfix_lolbin_payload_execution.json",
            "hunting/crashfix_python_rat_activity.json",
            "hunting/sharepoint_toolshell_exploitation.json",
            "hunting/sharepoint_toolshell_webshell_post_exploit.json",
            "hunting/rmm_post_compromise_activity.json",
            "hunting/cloud_identity_aitm_token_abuse.json",
            "hunting/cloud_identity_control_plane_takeover.json",
            "hunting/cloud_control_plane_discovery_burst.json",
            "hunting/cloud_secret_and_object_collection.json",
            "hunting/exfiltration_after_initial_access_2025_2026.json",
            "hunting/compromised_machines_and_data_2025_2026.json",
        }
        actual_query_files = {widget["query_file"] for widget in dashboard["widgets"]}

        self.assertEqual(expected_query_files, actual_query_files)
        self.assertLessEqual(len(dashboard["widgets"]), 30)
        self.assertIn("MELTS", dashboard["description"])

        advanced_types = set()
        source_backed_queries = set()
        for query_file in expected_query_files:
            query_path = Path(QUERIES_DIR) / query_file
            with query_path.open() as f:
                payload = json.load(f)

            advanced_types.add(payload.get("dashboard", {}).get("visualizationType"))
            expected_time = (
                {"timePeriod": "l7d"}
                if query_file in {
                    "hunting/melts_datasource_coverage_kpi.json",
                    "hunting/melts_last_week_risk_exposure.json",
                    "hunting/melts_apm_log_trace_correlation.json",
                }
                else {"timePeriod": "l21d"}
            )
            self.assertEqual(payload.get("dashboard", {}).get("timeSelection"), expected_time)
            self.assertTrue(payload.get("dashboard", {}).get("ask_ai_prompts"), query_file)
            if payload.get("references"):
                source_backed_queries.add(query_file)

        self.assertIn("link", advanced_types)
        self.assertIn("line", advanced_types)
        self.assertIn("summary_table", advanced_types)
        self.assertTrue(source_backed_queries)
