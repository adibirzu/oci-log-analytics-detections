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

class TestSentinelYamlNormalization(unittest.TestCase):
    """Validate official Sentinel YAML metadata normalization."""

    def test_normalize_analytics_rule_metadata(self):
        payload = {
            "id": "sentinel-rule-001",
            "name": "Suspicious sign-in",
            "description": "Detects suspicious Entra ID sign-ins.",
            "severity": "High",
            "requiredDataConnectors": [
                {"connectorId": "AzureActiveDirectory", "dataTypes": ["SigninLogs"]}
            ],
            "tactics": ["InitialAccess"],
            "relevantTechniques": ["T1078"],
            "query": "SigninLogs | where ResultType != 0",
        }

        normalized = normalize_sentinel_rule(
            Path("Detections/SigninLogs/suspicious_signin.yaml"),
            payload,
            repo_root=Path("."),
            commit="abc123",
        )

        self.assertEqual(normalized["sentinel_id"], "sentinel-rule-001")
        self.assertEqual(normalized["kind"], "analytics_rule")
        self.assertEqual(normalized["severity"], "high")
        self.assertEqual(normalized["required_data_connectors"][0]["connector_id"], "AzureActiveDirectory")
        self.assertEqual(normalized["mitre_attack"]["techniques"], ["T1078"])
        self.assertTrue(normalized["source_url"].endswith("/abc123/Detections/SigninLogs/suspicious_signin.yaml"))
        self.assertEqual(normalized["attribution"]["source"], "Microsoft Sentinel")

    def test_normalize_hunting_query_without_id_gets_stable_id(self):
        payload = {
            "name": "Rare process",
            "description": "Finds rare endpoint process starts.",
            "query": "DeviceProcessEvents | take 10",
        }

        normalized = normalize_sentinel_rule(
            Path("Hunting Queries/Windows/RareProcess.yaml"),
            payload,
            repo_root=Path("."),
            commit="main",
        )

        self.assertEqual(normalized["kind"], "hunting_query")
        self.assertTrue(normalized["sentinel_id"].startswith("sentinel-"))
