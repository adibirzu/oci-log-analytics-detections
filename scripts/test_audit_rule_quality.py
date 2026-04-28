#!/usr/bin/env python3
"""Unit tests for the rule quality audit helpers."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from audit_rule_quality import load_all_queries, load_all_rules


class TestAuditRuleQuality(unittest.TestCase):
    """Validate quality-audit loading behavior."""

    def test_load_all_rules_reports_invalid_yaml(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            rules_dir = Path(tmpdir)
            (rules_dir / "good.yaml").write_text(
                "title: Good Rule\n"
                "id: good-001\n"
                "logsource:\n"
                "  product: oci\n"
                "  service: audit\n"
                "detection:\n"
                "  selection:\n"
                "    event_type: test\n"
                "  condition: selection\n"
            )
            (rules_dir / "bad.yaml").write_text("title: Broken Rule\nauthor: Team: Example\n")

            rules, errors = load_all_rules(rules_dir)

            self.assertEqual(len(rules), 1)
            self.assertEqual(len(errors), 1)
            self.assertIn("Invalid YAML", errors[0]["issue"])
            self.assertEqual(errors[0]["severity"], "critical")

    def test_load_all_queries_walks_subdirs_and_filters_curated(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            queries_dir = Path(tmpdir)
            apps_dir = queries_dir / "apps"
            apps_dir.mkdir(parents=True, exist_ok=True)

            (queries_dir / "base.json").write_text(json.dumps({
                "title": "Base Rule",
                "query": "'Log Source' = 'OCI Audit Logs'",
                "sigma_id": "base-001",
            }))
            (apps_dir / "browser.json").write_text(json.dumps({
                "title": "Browser Rule",
                "query": "'Log Source' = 'SOC Application Logs'",
                "sigma_id": "browser-001",
            }))
            (apps_dir / "curated.json").write_text(json.dumps({
                "title": "Curated App Query",
                "query": "'Log Source' = 'SOC Application Logs'",
            }))

            queries = load_all_queries(queries_dir)
            files = {q["_file"] for q in queries}

            self.assertEqual(len(queries), 2)
            self.assertIn("base.json", files)
            self.assertIn("apps/browser.json", files)
            self.assertNotIn("apps/curated.json", files)


if __name__ == "__main__":
    unittest.main()
