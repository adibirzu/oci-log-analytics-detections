#!/usr/bin/env python3
"""Tests for Sentinel live-validation cache-key generation."""

import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sentinel_conversion_workflow import build_live_cache_key, main  # noqa: E402


class TestSentinelLiveCacheKey(unittest.TestCase):
    def test_live_cache_key_is_deterministic_and_input_sensitive(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            candidates = root / "sentinel_candidates.json"
            report = root / "sentinel_conversion_report.json"
            dictionary = root / "dictionary.json"
            mappings = root / "mapping"
            mappings.mkdir()
            candidates.write_text(json.dumps({"candidates": [{"id": "one"}]}), encoding="utf-8")
            report.write_text(json.dumps({"summary": {"promoted_count": 1}}), encoding="utf-8")
            dictionary.write_text(json.dumps({"fields": ["Command Line"]}), encoding="utf-8")
            (mappings / "fields.yaml").write_text("CommandLine: Command Line\n", encoding="utf-8")

            first = build_live_cache_key(
                lookback="24h",
                profile="azure_as_is",
                candidates_file=candidates,
                report_path=report,
                field_dictionary_path=dictionary,
                mapping_root=mappings,
            )
            second = build_live_cache_key(
                lookback="24h",
                profile="azure_as_is",
                candidates_file=candidates,
                report_path=report,
                field_dictionary_path=dictionary,
                mapping_root=mappings,
            )
            report.write_text(json.dumps({"summary": {"promoted_count": 2}}), encoding="utf-8")
            changed = build_live_cache_key(
                lookback="24h",
                profile="azure_as_is",
                candidates_file=candidates,
                report_path=report,
                field_dictionary_path=dictionary,
                mapping_root=mappings,
            )

        self.assertEqual(first, second)
        self.assertNotEqual(first, changed)
        self.assertRegex(first, r"^sentinel-live-[0-9a-f]{32}$")

    def test_live_cache_key_command_outputs_json(self):
        buffer = StringIO()
        with redirect_stdout(buffer):
            exit_code = main([
                "live-cache-key",
                "--lookback",
                "48h",
                "--profile",
                "azure_as_is",
                "--json",
            ])

        payload = json.loads(buffer.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["lookback"], "48h")
        self.assertEqual(payload["profile"], "azure_as_is")
        self.assertRegex(payload["cache_key"], r"^sentinel-live-[0-9a-f]{32}$")


if __name__ == "__main__":
    unittest.main()
