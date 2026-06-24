#!/usr/bin/env python3
"""Tests for offline Sentinel promotion drift detection."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sentinel_drift_check import (  # noqa: E402
    build_drift_report,
    parser_schema_hash,
    write_parser_schema_hashes,
)


class TestSentinelDriftCheck(unittest.TestCase):
    def write_json(self, path: Path, payload: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    def fixture_tree(self):
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        sentinel_dir = root / "sentinel"
        dictionary = root / "dictionary.json"
        report = root / "report.json"
        self.write_json(dictionary, {"fields": [{"display_name": "User"}], "approved_builtins": ["Log Source"]})
        current_hash = parser_schema_hash(dictionary)
        self.write_json(sentinel_dir / "one.json", {
            "title": "One",
            "query": "'Log Source' = 'SOC Windows Sysmon Logs'",
            "sentinel_id": "one",
            "live_validation_status": "passed",
            "parser_schema_hash": current_hash,
        })
        self.write_json(report, {
            "summary": {"promoted_count": 1, "live_validation_passed": 1},
            "attempted": [{"output_file": "sentinel/one.json", "live_validation_status": "passed"}],
        })
        return temp, sentinel_dir, dictionary, report

    def test_clean_tree_has_no_drift(self):
        temp, sentinel_dir, dictionary, report = self.fixture_tree()
        self.addCleanup(temp.cleanup)

        drift = build_drift_report(
            sentinel_dir=sentinel_dir,
            dictionary_path=dictionary,
            report_path=report,
        )

        self.assertEqual(drift["summary"]["error_count"], 0)
        self.assertEqual(drift["drift"], [])

    def test_missing_parser_hash_is_error(self):
        temp, sentinel_dir, dictionary, report = self.fixture_tree()
        self.addCleanup(temp.cleanup)
        payload = json.loads((sentinel_dir / "one.json").read_text(encoding="utf-8"))
        del payload["parser_schema_hash"]
        self.write_json(sentinel_dir / "one.json", payload)

        drift = build_drift_report(
            sentinel_dir=sentinel_dir,
            dictionary_path=dictionary,
            report_path=report,
        )

        self.assertEqual(drift["summary"]["error_count"], 1)
        self.assertEqual(drift["drift"][0]["type"], "missing_parser_schema_hash")

    def test_write_parser_schema_hashes_repairs_missing_hash(self):
        temp, sentinel_dir, dictionary, report = self.fixture_tree()
        self.addCleanup(temp.cleanup)
        payload = json.loads((sentinel_dir / "one.json").read_text(encoding="utf-8"))
        del payload["parser_schema_hash"]
        self.write_json(sentinel_dir / "one.json", payload)

        self.assertEqual(write_parser_schema_hashes(sentinel_dir=sentinel_dir, dictionary_path=dictionary), 1)
        drift = build_drift_report(
            sentinel_dir=sentinel_dir,
            dictionary_path=dictionary,
            report_path=report,
        )

        self.assertEqual(drift["summary"]["error_count"], 0)

    def test_baseline_query_hash_change_is_error(self):
        temp, sentinel_dir, dictionary, report = self.fixture_tree()
        self.addCleanup(temp.cleanup)
        baseline = Path(temp.name) / "baseline.json"
        self.write_json(baseline, {
            "current": [{
                "path": "sentinel/one.json",
                "live_validation_status": "passed",
                "query_hash": "old",
            }]
        })

        drift = build_drift_report(
            sentinel_dir=sentinel_dir,
            dictionary_path=dictionary,
            report_path=report,
            baseline_path=baseline,
        )

        self.assertEqual(drift["summary"]["error_count"], 1)
        self.assertEqual(drift["drift"][0]["type"], "baseline_query_hash_changed")

    def test_require_synthetic_hits_flags_missing_promoted_evidence(self):
        temp, sentinel_dir, dictionary, report = self.fixture_tree()
        self.addCleanup(temp.cleanup)
        live_results = Path(temp.name) / "live_results.json"
        self.write_json(live_results, {"results": []})

        drift = build_drift_report(
            sentinel_dir=sentinel_dir,
            dictionary_path=dictionary,
            report_path=report,
            synthetic_live_results_path=live_results,
            require_synthetic_hits=True,
        )

        self.assertEqual(drift["summary"]["synthetic_live_hit_count"], 0)
        self.assertEqual(drift["summary"]["promoted_without_synthetic_hit"], 1)
        self.assertEqual(drift["drift"][0]["type"], "missing_synthetic_live_hit")

    def test_synthetic_hit_gaps_include_plan_status(self):
        temp, sentinel_dir, dictionary, report = self.fixture_tree()
        self.addCleanup(temp.cleanup)
        live_results = Path(temp.name) / "live_results.json"
        synthetic_plan = Path(temp.name) / "plan.json"
        self.write_json(live_results, {"results": []})
        self.write_json(synthetic_plan, {
            "candidates": [{
                "sentinel_id": "one",
                "status": "synthetic_ready",
                "selected_source": "SOC Windows Sysmon Logs",
                "required_fields": ["User"],
            }]
        })

        drift = build_drift_report(
            sentinel_dir=sentinel_dir,
            dictionary_path=dictionary,
            report_path=report,
            synthetic_live_results_path=live_results,
            synthetic_plan_path=synthetic_plan,
        )

        self.assertEqual(drift["summary"]["error_count"], 0)
        self.assertEqual(len(drift["synthetic_hit_gaps"]), 1)
        self.assertEqual(drift["synthetic_hit_gaps"][0]["synthetic_plan_status"], "synthetic_ready")
        self.assertEqual(drift["synthetic_hit_gaps"][0]["selected_source"], "SOC Windows Sysmon Logs")


if __name__ == "__main__":
    unittest.main()
