#!/usr/bin/env python3
"""Tests for the static OCI Log Analytics query performance audit."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from query_performance_audit import analyze_query, build_report, load_query_artifacts


class TestQueryPerformanceAudit(unittest.TestCase):
    def test_detects_filter_after_sort_as_strict_error(self):
        result = analyze_query(
            {
                "file": "queries/example.json",
                "title": "Example",
                "query": "'Log Source' = 'X' | stats count as Hits by User | sort -Hits | where Hits > 5",
            }
        )

        self.assertIn("filter_after_sort", {item["code"] for item in result["findings"]})
        self.assertEqual(
            [item["severity"] for item in result["findings"] if item["code"] == "filter_after_sort"],
            ["error"],
        )

    def test_filter_before_sort_is_not_flagged(self):
        result = analyze_query(
            {
                "file": "queries/example.json",
                "title": "Example",
                "query": "'Log Source' = 'X' | stats count as Hits by User | where Hits > 5 | sort -Hits",
            }
        )

        self.assertNotIn("filter_after_sort", {item["code"] for item in result["findings"]})

    def test_rejects_sql_style_like_wildcards(self):
        result = analyze_query(
            {
                "file": "queries/example.json",
                "title": "Example",
                "query": "'Log Source' = 'X' and 'Command Line' like '%powershell%'",
            }
        )

        self.assertIn("invalid_like_wildcard", {item["code"] for item in result["findings"]})

    def test_counts_scan_bound_predicates_without_failing_them(self):
        result = analyze_query(
            {
                "file": "queries/example.json",
                "title": "Example",
                "query": "'Log Source' = 'X' and (msg like '*one*' or 'Command Line' like '*two*')",
            }
        )

        self.assertEqual(result["metrics"]["leading_wildcard_predicates"], 2)
        self.assertEqual(result["metrics"]["raw_content_scans"], 1)
        self.assertNotIn("error", {item["severity"] for item in result["findings"]})

    def test_loader_ignores_non_query_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "query.json").write_text(
                json.dumps({"title": "One", "query": "'Log Source' = 'X'"}),
                encoding="utf-8",
            )
            (root / "catalog.json").write_text(json.dumps({"items": []}), encoding="utf-8")

            artifacts = load_query_artifacts(root)

        self.assertEqual(len(artifacts), 1)
        self.assertEqual(artifacts[0]["title"], "One")

    def test_repo_has_no_filter_after_sort_errors(self):
        report = build_report()

        self.assertEqual(report["summary"]["strict_errors"], 0)


if __name__ == "__main__":
    unittest.main()
