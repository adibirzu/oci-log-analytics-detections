#!/usr/bin/env python3.11
"""Unit and contract tests for the 7-Day Multi-Pillar Threat Hunting Storyline,
2026 Threat Report YAML packs, and Storyline Hunting Queries.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from generate_synthetic_2026_campaign import (  # noqa: E402
    SEVEN_DAY_KILL_CHAIN_DAYS,
    generate_7day_storyline_bundle,
    generate_campaign_bundle,
)
from hunting_bundle import build_bundle, validate_bundle  # noqa: E402


class TestSevenDayStorylineAndPacks(unittest.TestCase):
    def test_seven_day_storyline_spans_seven_distinct_dates_and_all_pillars(self):
        story = generate_7day_storyline_bundle(
            seed="20260901",
            mask_mode="off",
            reference_time="2026-10-20T21:00:00Z",
        )
        self.assertEqual(story["schema"], "oci-demo.seven-day-storyline-2026/v1")
        self.assertEqual(len(story["distinct_dates"]), 7)
        self.assertEqual(story["storyline_counts"]["distinct_dates"], 7)
        self.assertEqual(story["storyline_counts"]["background_logs"], 35)
        self.assertGreaterEqual(story["storyline_counts"]["attack_logs"], 20)
        self.assertEqual(story["storyline_counts"]["metrics"], 7)
        self.assertEqual(story["storyline_counts"]["apm_traces"], 6)
        self.assertEqual(story["storyline_counts"]["langfuse_traces"], 1)
        self.assertEqual(story["storyline_counts"]["datasafe_events"], 1)
        self.assertGreaterEqual(story["storyline_counts"]["multicloud_logs"], 16)
        self.assertGreaterEqual(story["storyline_counts"]["ac_hunter_telemetry"], 35)
        self.assertGreaterEqual(story["storyline_counts"]["multicloud_metrics"], 8)
        clouds = {row["Cloud Provider"] for row in story["multicloud_logs"]}
        self.assertEqual(clouds, {"AWS", "Azure", "GCP", "OCI"})
        ac_modules = {row["ac_hunter_module"] for row in story["ac_hunter_telemetry"]}
        self.assertEqual(
            ac_modules,
            {
                "c2_beaconing_rita",
                "long_connections",
                "dns_beaconing_fqdn_entropy",
                "client_signatures_ja3",
                "composite_threat_score",
            },
        )

        # Verify background tasks cover all 5 operational task types across 7 days
        bg_tasks = {row["service_task"] for row in story["background_logs"]}
        self.assertEqual(
            bg_tasks,
            {
                "automated_db_backup",
                "oke_kubelet_heartbeat",
                "crm_shop_order_sync",
                "devops_build_pipeline",
                "iam_token_refresh",
            },
        )

        # Verify all 7 days of the perpetrator kill chain are present
        attack_days = {row["day"] for row in story["attack_logs"]}
        self.assertEqual(attack_days, {1, 2, 3, 4, 5, 6, 7})

        # Verify Langfuse AI Agent MELTS reasoning trace includes all 5 tool spans
        lf_trace = story["langfuse_traces"][0]
        span_names = [s["name"] for s in lf_trace["spans"]]
        self.assertEqual(
            span_names,
            [
                "logan.execute_query",
                "apm.query_traces",
                "monitoring.summarize_metrics",
                "datasafe.audit_events",
                "caldera.operation_correlation",
            ],
        )

    def test_campaign_bundle_preserves_prd024_counts_and_embeds_storyline(self):
        bundle = generate_campaign_bundle(seed="20260901", mask_mode="partial")
        self.assertEqual(
            bundle["counts"],
            {
                "peak_hunts": 4,
                "logs": 5,
                "metrics": 6,
                "apm_traces": 2,
                "datasafe_events": 1,
            },
        )
        self.assertIn("storyline_7day", bundle)
        self.assertEqual(bundle["storyline_7day"]["storyline_counts"]["distinct_dates"], 7)

    def test_all_2026_threat_report_packs_parse_and_have_queries(self):
        packs_dir = ROOT / "packs" / "2026_threat_reports"
        pack_files = sorted(packs_dir.glob("*.yaml"))
        self.assertGreaterEqual(len(pack_files), 4)
        for pack_file in pack_files:
            payload = yaml.safe_load(pack_file.read_text(encoding="utf-8"))
            self.assertIsInstance(payload, dict, pack_file.name)
            self.assertIn("pack_id", payload, pack_file.name)
            items = (
                payload.get("detections")
                or payload.get("campaigns")
                or payload.get("hunts")
                or payload.get("days")
                or []
            )
            self.assertGreater(len(items), 0, pack_file.name)
            for item in items:
                query = item.get("log_analytics_query") or (item.get("execute") or {}).get("log_analytics_query")
                self.assertTrue(query and "'Log Source'" in query, f"Missing query in {pack_file.name}")

    def test_storyline_hunting_queries_are_ready_in_hunting_bundle(self):
        bundle = build_bundle(ROOT)
        self.assertEqual(validate_bundle(bundle), [])
        by_path = {q["source_path"]: q for q in bundle["queries"]}
        for day_meta in SEVEN_DAY_KILL_CHAIN_DAYS:
            q_path = day_meta["query_file"]
            self.assertIn(q_path, by_path, f"{q_path} missing from hunting bundle")
            record = by_path[q_path]
            self.assertEqual(
                record["field_contract"]["status"],
                "ready",
                f"{q_path} blocked: {record['field_contract']['reasons']}",
            )
            self.assertIn("storyline_7day_caldera_goad", record["pack_ids"])

    def test_forge_detection_catalog_bundles_all_1400_rules_and_packs(self):
        catalog_path = ROOT / "queries" / "forge_detection_catalog.json"
        self.assertTrue(catalog_path.is_file(), "forge_detection_catalog.json missing")
        payload = json.loads(catalog_path.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema_version"], "1.0.0")
        self.assertGreaterEqual(payload["total_items"], 1400)
        self.assertEqual(len(payload["items"]), payload["total_items"])
        surfaces = set(payload["surface_counts"].keys())
        self.assertEqual(
            surfaces,
            {"workbench_example", "threat_report_2026", "hunting", "application", "detection"},
        )
        ids = {item["id"] for item in payload["items"]}
        self.assertIn("STORYLINE-DAY-01", ids)
        self.assertIn("STORYLINE-DAY-07", ids)
        self.assertIn("hunting/storyline_day1_waf_apigw_vcn_recon_sweep", ids)
        self.assertIn("hunting/ac_hunter_01_c2_beaconing_rita_score", ids)
        self.assertIn("hunting/ac_hunter_08_multicloud_cross_csp_correlation", ids)

    def test_ac_hunter_network_hunting_pack_and_dashboard_are_valid_and_ready(self):
        pack_dir = ROOT / "packs" / "ac_hunter_network_hunting"
        manifest_path = pack_dir / "manifest.json"
        self.assertTrue(manifest_path.is_file(), "packs/ac_hunter_network_hunting/manifest.json missing")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["pack_id"], "ac_hunter_network_hunting")
        self.assertEqual(len(manifest["capabilities_replicated"]), 8)

        bundle = build_bundle(ROOT)
        by_path = {q["source_path"]: q for q in bundle["queries"]}
        for cap in manifest["capabilities_replicated"]:
            q_rel = cap["query_file"]
            pack_q = pack_dir / Path(q_rel).name
            queries_hunt_q = ROOT / "queries" / q_rel
            self.assertTrue(pack_q.is_file(), f"Missing {pack_q}")
            self.assertTrue(queries_hunt_q.is_file(), f"Missing {queries_hunt_q}")
            self.assertIn(q_rel, by_path)
            self.assertEqual(by_path[q_rel]["field_contract"]["status"], "ready")
            self.assertIn("ac_hunter_network_hunting", by_path[q_rel]["pack_ids"])

        dash_path = ROOT / "dashboards" / "ac_hunter_and_multicloud_logan_dashboard.json"
        self.assertTrue(dash_path.is_file(), "dashboards/ac_hunter_and_multicloud_logan_dashboard.json missing")
        dash = json.loads(dash_path.read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(dash["tiles"]), 12)
        self.assertEqual(len(dash["tiles"]), len(dash["savedSearches"]))


if __name__ == "__main__":
    unittest.main()
