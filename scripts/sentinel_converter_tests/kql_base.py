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

class SentinelKqlConversionBase(unittest.TestCase):
    """Validate deterministic KQL subset conversion."""

    def setUp(self):
        self.mapping = load_mapping_config()

    def _candidate(self, **overrides):
        candidate = {
            "sentinel_id": "rule-001",
            "title": "Failed sign-in burst",
            "description": "Detects failed sign-ins with repeated source IPs.",
            "severity": "high",
            "query": (
                "SigninLogs\n"
                "| where TimeGenerated > ago(1d)\n"
                "| where Result != \"Success\" and UserPrincipalName has \"admin\" "
                "and IPAddress in (\"10.0.0.1\", \"10.0.0.2\")\n"
                "| summarize Failures=count(), Users=dcount(UserPrincipalName) "
                "by UserPrincipalName, IPAddress\n"
                "| sort by Failures desc\n"
                "| take 10"
            ),
            "required_data_connectors": [
                {"connector_id": "AzureActiveDirectory", "data_types": ["SigninLogs"]}
            ],
            "mitre_attack": {"tactics": ["initial_access"], "techniques": ["T1078"]},
            "source_path": "Detections/SigninLogs/failed_signins.yaml",
            "source_url": "https://github.com/Azure/Azure-Sentinel/blob/main/Detections/SigninLogs/failed_signins.yaml",
            "attribution": {"source": "Microsoft Sentinel"},
            "kind": "analytics_rule",
        }
        return {**candidate, **overrides}
