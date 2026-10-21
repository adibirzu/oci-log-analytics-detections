#!/usr/bin/env python3
"""Validation tests for the 20 migrated Splunk and Elastic queries."""

import json
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = PROJECT_ROOT / "queries" / "migrated_siem_20_queries.json"


class MigratedSiemQueriesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = json.loads(CATALOG_PATH.read_text())

    def test_catalog_structure_and_counts(self):
        self.assertEqual(self.catalog["schema_version"], "1.0.0")
        queries = self.catalog["queries"]
        self.assertEqual(len(queries), 20)
        splunk_queries = [q for q in queries if q["family"] == "splunk"]
        elastic_queries = [q for q in queries if q["family"] == "elastic"]
        self.assertEqual(len(splunk_queries), 10)
        self.assertEqual(len(elastic_queries), 10)

    def test_query_attributes_and_syntax(self):
        valid_log_sources = {
            "SOC Application Logs",
            "Windows Security Events",
            "Windows Sysmon Events",
        }
        for q in self.catalog["queries"]:
            self.assertTrue(q["id"].startswith(("MIG-SPL-", "MIG-ELS-")), f"Invalid ID in {q['id']}")
            self.assertTrue(q["title"])
            self.assertTrue(q["source_query"])
            self.assertTrue(q["converted_logan_ql"])
            self.assertIn(q["log_source"], valid_log_sources)
            self.assertTrue(q["mitre_technique"].startswith("T"))
            self.assertIn(q["severity"], {"low", "medium", "high", "critical"})

            # Basic OCL syntax integrity
            converted = q["converted_logan_ql"]
            self.assertIn("'Log Source' =", converted)
            self.assertEqual(converted.count("'") % 2, 0, f"Unbalanced single quotes in {q['id']}: {converted}")
            if "|" in converted:
                pipe_commands = [seg.strip().split()[0] for seg in converted.split("|")[1:]]
                valid_pipe_commands = {"stats", "sort", "head", "where", "eval", "top", "fields"}
                for cmd in pipe_commands:
                    self.assertIn(cmd, valid_pipe_commands, f"Unknown pipe command {cmd} in {q['id']}")


if __name__ == "__main__":
    unittest.main()
