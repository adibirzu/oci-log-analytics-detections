"""Deterministic provenance and conversion-report regression tests."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from convert_sentinel_kql import convert_candidates, load_mapping_config
from sentinel_conversion_workflow import build_convert_command, main
from sentinel_converter_reporting import (
    build_conversion_report,
    compute_conversion_provenance_hash,
)
from sentinel_workflow.html_report import write_report_html


class TestSentinelConversionProvenance(unittest.TestCase):
    """Verify deterministic provenance hashes and conversion report output."""

    @staticmethod
    def _sample_candidates() -> list[dict]:
        return [
            {
                "sentinel_id": "det-001",
                "title": "Failed sign-in burst",
                "description": "Detects repeated sign-in failures.",
                "severity": "high",
                "kind": "analytics_rule",
                "source_path": "Detections/SigninLogs/failed_signin.yaml",
                "source_url": "https://example.invalid/failed_signin.yaml",
                "query": (
                    "SigninLogs | where TimeGenerated > ago(1h) "
                    "| where ResultType != '0' "
                    "| summarize Failures = count() by UserPrincipalName, IPAddress"
                ),
                "mitre_attack": {"tactics": ["credential_access"], "techniques": ["T1110"]},
                "required_data_connectors": ["AzureActiveDirectory"],
            },
            {
                "sentinel_id": "det-002",
                "title": "Unsupported table candidate",
                "description": "Uses an unmapped Sentinel table.",
                "severity": "medium",
                "kind": "analytics_rule",
                "source_path": "Detections/Custom/unsupported.yaml",
                "source_url": "https://example.invalid/unsupported.yaml",
                "query": "UnmappedExampleTable_CL | where FieldA == 'x'",
                "mitre_attack": {"tactics": [], "techniques": []},
            },
        ]

    def test_repeated_conversions_produce_identical_provenance_hashes(self):
        mapping = load_mapping_config()
        candidates = self._sample_candidates()
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            report_a = root / "report_a.json"
            report_b = root / "report_b.json"

            first = convert_candidates(
                candidates=candidates,
                mapping=mapping,
                top=2,
                validate_live=False,
                write_working=False,
                report_path=report_a,
                progress_interval=-1,
                workers=1,
            )
            second = convert_candidates(
                candidates=candidates,
                mapping=mapping,
                top=2,
                validate_live=False,
                write_working=False,
                report_path=report_b,
                progress_interval=-1,
                workers=2,
            )

            self.assertIn("provenance_sha256", first)
            self.assertRegex(first["provenance_sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(first["provenance_sha256"], second["provenance_sha256"])
            self.assertEqual(
                first["provenance"]["provenance_sha256"],
                first["provenance_sha256"],
            )
            self.assertEqual(
                compute_conversion_provenance_hash(first),
                first["provenance_sha256"],
            )

    def test_source_date_epoch_and_generated_at_produce_byte_identical_reports(self):
        mapping = load_mapping_config()
        candidates = self._sample_candidates()
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            report_a = root / "report_a.json"
            report_b = root / "report_b.json"

            convert_candidates(
                candidates=candidates,
                mapping=mapping,
                top=2,
                validate_live=False,
                write_working=False,
                report_path=report_a,
                progress_interval=-1,
                workers=1,
                generated_at="2026-06-01T00:00:00+00:00",
            )

            prior = os.environ.get("SOURCE_DATE_EPOCH")
            os.environ["SOURCE_DATE_EPOCH"] = "1780272000"
            try:
                convert_candidates(
                    candidates=candidates,
                    mapping=mapping,
                    top=2,
                    validate_live=False,
                    write_working=False,
                    report_path=report_b,
                    progress_interval=-1,
                    workers=2,
                )
            finally:
                if prior is None:
                    os.environ.pop("SOURCE_DATE_EPOCH", None)
                else:
                    os.environ["SOURCE_DATE_EPOCH"] = prior

            self.assertEqual(report_a.read_bytes(), report_b.read_bytes())

    def test_build_convert_command_forwards_generated_at(self):
        command = build_convert_command(
            mode="local",
            top=5,
            timeout=20,
            lookback="24h",
            report_path=Path("/tmp/local.json"),
            no_sync=True,
            generated_at="2026-06-01T00:00:00+00:00",
        )
        self.assertIn("--generated-at", command)
        self.assertIn("2026-06-01T00:00:00+00:00", command)

    def test_workflow_provenance_command_verifies_and_detects_tampering(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "report.json"
            report = build_conversion_report(
                candidates=[],
                attempted=[],
                results=[],
                source={"name": "Microsoft Sentinel"},
                validate_live=False,
                generated_at="2026-06-01T00:00:00+00:00",
            )
            report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

            stdout = StringIO()
            with redirect_stdout(stdout):
                exit_code = main(["provenance", "--report", str(report_path), "--json"])
            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["provenance_sha256"], report["provenance_sha256"])
            self.assertTrue(payload["verified"])

            tampered = dict(report)
            tampered["summary"] = {**report["summary"], "promoted_count": 999}
            report_path.write_text(json.dumps(tampered, indent=2) + "\n", encoding="utf-8")
            with redirect_stdout(StringIO()):
                tamper_code = main(["provenance", "--report", str(report_path), "--json"])
            self.assertEqual(tamper_code, 1)

    def test_workflow_provenance_command_rejects_missing_and_contradictory_digests(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "report.json"
            base_report = build_conversion_report(
                candidates=[],
                attempted=[],
                results=[],
                source={"name": "Microsoft Sentinel"},
                validate_live=False,
                generated_at="2026-06-01T00:00:00+00:00",
            )
            expected_hash = base_report["provenance_sha256"]

            # Historical report with no embedded provenance fields still hashes, but fails verification
            historical = {
                k: v for k, v in base_report.items() if k not in {"provenance", "provenance_sha256"}
            }
            report_path.write_text(json.dumps(historical, indent=2) + "\n", encoding="utf-8")
            stdout = StringIO()
            with redirect_stdout(stdout):
                missing_code = main(["provenance", "--report", str(report_path), "--json"])
            self.assertEqual(missing_code, 1)
            missing_payload = json.loads(stdout.getvalue())
            self.assertEqual(missing_payload["provenance_sha256"], expected_hash)
            self.assertIsNone(missing_payload["recorded_provenance_sha256"])
            self.assertFalse(missing_payload["verified"])

            # Empty recorded digest must also fail verification
            empty_digest = {**historical, "provenance_sha256": ""}
            report_path.write_text(json.dumps(empty_digest, indent=2) + "\n", encoding="utf-8")
            stdout = StringIO()
            with redirect_stdout(stdout):
                empty_code = main(["provenance", "--report", str(report_path), "--json"])
            self.assertEqual(empty_code, 1)
            self.assertFalse(json.loads(stdout.getvalue())["verified"])

            # Contradictory nested digest with matching top-level digest must fail
            contradictory_nested = {
                **base_report,
                "provenance": {**base_report["provenance"], "provenance_sha256": "0" * 64},
            }
            report_path.write_text(
                json.dumps(contradictory_nested, indent=2) + "\n", encoding="utf-8"
            )
            stdout = StringIO()
            with redirect_stdout(stdout):
                nested_mismatch_code = main(["provenance", "--report", str(report_path), "--json"])
            self.assertEqual(nested_mismatch_code, 1)
            self.assertFalse(json.loads(stdout.getvalue())["verified"])

            # Contradictory top-level digest with matching nested digest must fail
            contradictory_top = {
                **base_report,
                "provenance_sha256": "f" * 64,
            }
            report_path.write_text(
                json.dumps(contradictory_top, indent=2) + "\n", encoding="utf-8"
            )
            stdout = StringIO()
            with redirect_stdout(stdout):
                top_mismatch_code = main(["provenance", "--report", str(report_path), "--json"])
            self.assertEqual(top_mismatch_code, 1)
            self.assertFalse(json.loads(stdout.getvalue())["verified"])

    def test_write_report_html_uses_report_generated_at_deterministically(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            report_path = root / "report.json"
            html_a = root / "a.html"
            html_b = root / "b.html"
            sentinel_dir = root / "sentinel"
            sentinel_dir.mkdir()
            report = build_conversion_report(
                candidates=[],
                attempted=[],
                results=[],
                source={"repository": "https://example.invalid/repo"},
                validate_live=False,
                generated_at="2026-06-01T00:00:00+00:00",
            )
            report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

            write_report_html(
                report_path=report_path,
                output_path=html_a,
                sentinel_dir=sentinel_dir,
                dashboard_inventory=root / "missing.json",
            )
            write_report_html(
                report_path=report_path,
                output_path=html_b,
                sentinel_dir=sentinel_dir,
                dashboard_inventory=root / "missing.json",
            )
            self.assertEqual(html_a.read_bytes(), html_b.read_bytes())
            self.assertIn("2026-06-01T00:00:00+00:00", html_a.read_text(encoding="utf-8"))
