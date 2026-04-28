#!/usr/bin/env python3
"""Prevent application/browser queries from drifting back to unsupported fields."""

import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from oci_config import APPS_DIR, PROJECT_DIR


LEGACY_QUERY_TOKENS = [
    "service.name",
    "security.attack.",
    "security.source_ip",
    "security.username",
    "security.waf.score",
    "http.url.path",
    "http.response_time_ms",
    "http.status_code",
    "performance.slow_request",
    "orders.sync.",
    "trace_id",
    "db.target",
    "HTTP URL",
    "HTTP Status Code",
    " is not null",
    "avg('Response Time Ms')",
    "max('Response Time Ms')",
    "sum('Orders Sync",
]


class TestAppQueryContract(unittest.TestCase):
    """Validate the public app/browser query contract."""

    def test_queries_use_supported_soc_application_schema(self):
        query_files = sorted(Path(APPS_DIR).glob("*.json"))
        query_files.append(Path(PROJECT_DIR) / "queries" / "hunting" / "browser_attack_frequency_analysis.json")

        self.assertGreater(len(query_files), 0)

        for path in query_files:
            with path.open() as f:
                payload = json.load(f)
            query = payload["query"]

            self.assertIn("SOC Application Logs", query, path.name)
            self.assertNotIn("enterprise-crm-portal'", query, path.name)
            self.assertNotIn("octo-drone-shop'", query, path.name)

            for token in LEGACY_QUERY_TOKENS:
                self.assertNotIn(token, query, f"{path.name} still uses legacy token: {token}")

            if "| stats " in query and " by " in query:
                stats_section = query.split("| stats ", 1)[1].split("|", 1)[0]
                if " by " in stats_section:
                    by_clause = stats_section.split(" by ", 1)[1]
                    group_fields = [field.strip() for field in by_clause.split(",") if field.strip()]
                    self.assertLessEqual(
                        len(group_fields),
                        4,
                        f"{path.name} exceeds OCI Log Analytics four-field STATS limit",
                    )


if __name__ == "__main__":
    unittest.main()
