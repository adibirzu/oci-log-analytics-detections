#!/usr/bin/env python3
"""Tests for inventory drift reconciliation behavior."""

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import release_checklist
from check_inventory_drift import DriftRule, check
from release_checklist import build_steps


class TestInventoryDrift(unittest.TestCase):
    """Validate drift checks without reading repository docs or catalogs."""

    @staticmethod
    def sources(**inventory_overrides):
        inventory = {
            "source_yaml_rules": 454,
            "total_query_artifacts": 1001,
            "art_percent": 87.4,
        }
        inventory.update(inventory_overrides)
        return {
            "catalog": {
                "inventory": inventory,
                "stig_controls": ["V-1", "V-2"],
                "rules": [{"stig_ids": ["V-1"]}, {"stig_ids": []}],
            },
            "dashboard": {
                "summary": {
                    "total_dashboards": 27,
                    "total_widgets": 450,
                    "advanced_visualization_widgets": 91,
                }
            },
            "sentinel": {
                "summary": {
                    "live_validation_passed": 421,
                    "live_validation_failed": 53,
                }
            },
        }

    def run_check(self, text, rules):
        with tempfile.TemporaryDirectory() as temp_dir:
            doc = Path(temp_dir) / "README.md"
            doc.write_text(text, encoding="utf-8")
            materialized = [
                DriftRule(
                    label=rule.label,
                    file=doc,
                    pattern=rule.pattern,
                    canonical=rule.canonical,
                    notes=rule.notes,
                )
                for rule in rules
            ]
            with patch("check_inventory_drift.DRIFT_RULES", materialized):
                return check(self.sources())

    def test_matching_integer_count_has_no_drift(self):
        rules = [
            DriftRule(
                label="source rules",
                file=Path("unused"),
                pattern=re.compile(r"Source rules: (\d+)", re.M),
                canonical=lambda s: s["catalog"]["inventory"]["source_yaml_rules"],
            )
        ]

        self.assertEqual(self.run_check("Source rules: 454\n", rules), [])

    def test_comma_formatted_count_matches_integer_canonical(self):
        rules = [
            DriftRule(
                label="total items",
                file=Path("unused"),
                pattern=re.compile(r"Total items: ([\d,]+)", re.M),
                canonical=lambda s: s["catalog"]["inventory"]["total_query_artifacts"],
            )
        ]

        self.assertEqual(self.run_check("Total items: 1,001\n", rules), [])

    def test_missing_regex_match_returns_missing_record(self):
        rules = [
            DriftRule(
                label="missing source rules",
                file=Path("unused"),
                pattern=re.compile(r"Source rules: (\d+)", re.M),
                canonical=lambda s: s["catalog"]["inventory"]["source_yaml_rules"],
            )
        ]

        drift = self.run_check("No count here\n", rules)

        self.assertEqual(len(drift), 1)
        self.assertEqual(drift[0]["status"], "MISSING")
        self.assertEqual(drift[0]["label"], "missing source rules")

    def test_mismatched_integer_returns_drift_record(self):
        rules = [
            DriftRule(
                label="source rules",
                file=Path("unused"),
                pattern=re.compile(r"Source rules: (\d+)", re.M),
                canonical=lambda s: s["catalog"]["inventory"]["source_yaml_rules"],
            )
        ]

        drift = self.run_check("Source rules: 450\n", rules)

        self.assertEqual(len(drift), 1)
        self.assertEqual(drift[0]["status"], "DRIFT")
        self.assertEqual(drift[0]["published"], 450)
        self.assertEqual(drift[0]["canonical"], 454)
        self.assertEqual(drift[0]["delta"], 4)

    def test_float_canonical_uses_tolerance(self):
        rules = [
            DriftRule(
                label="art percent",
                file=Path("unused"),
                pattern=re.compile(r"ART: (\d+(?:\.\d+)?)%", re.M),
                canonical=lambda s: s["catalog"]["inventory"]["art_percent"],
            )
        ]

        self.assertEqual(self.run_check("ART: 87.36%\n", rules), [])
        drift = self.run_check("ART: 87.3%\n", rules)
        self.assertEqual(len(drift), 1)
        self.assertEqual(drift[0]["status"], "DRIFT")


class TestReleaseChecklistOrdering(unittest.TestCase):
    """Validate local release gates refresh generated inputs before drift check."""

    @staticmethod
    def step_index(steps, name):
        names = [step[0] for step in steps]
        return names.index(name)

    def test_inventory_drift_runs_after_generated_inputs(self):
        steps = build_steps(False, False, "21d", 60)
        drift_idx = self.step_index(steps, "inventory drift check")

        self.assertLess(self.step_index(steps, "field dictionary validation"), drift_idx)
        self.assertLess(self.step_index(steps, "detection rule spec export"), drift_idx)
        self.assertLess(self.step_index(steps, "catalog generation"), drift_idx)
        self.assertLess(self.step_index(steps, "dashboard inventory export"), drift_idx)

        drift_command = steps[drift_idx][1]
        self.assertTrue(any(str(part).endswith("check_inventory_drift.py") for part in drift_command))

    def test_default_local_gates_cover_phase_four_artifact_contract(self):
        steps = build_steps(False, False, "21d", 60)
        names = [step[0] for step in steps]

        expected = [
            "synthetic log contract validation",
            "field dictionary validation",
            "sentinel feed dependency bundle",
            "detection rule spec export",
            "catalog generation",
            "dashboard inventory export",
            "octo apm workshop bundle validation",
            "sentinel strict status",
            "sentinel drift check",
            "dashboard dry run",
            "inventory drift check",
            "sensitive value scan",
            "compileall scripts",
            "pytest",
        ]
        for name in expected:
            self.assertIn(name, names)
        self.assertNotIn("sentinel synthetic-hit drift check", names)

        self.assertLess(self.step_index(steps, "dashboard inventory export"), self.step_index(steps, "dashboard dry run"))
        self.assertLess(self.step_index(steps, "sentinel strict status"), self.step_index(steps, "sentinel drift check"))
        self.assertLess(self.step_index(steps, "sentinel drift check"), self.step_index(steps, "dashboard dry run"))
        self.assertLess(self.step_index(steps, "inventory drift check"), self.step_index(steps, "sensitive value scan"))
        self.assertLess(self.step_index(steps, "sensitive value scan"), self.step_index(steps, "pytest"))

    def test_sentinel_synthetic_hit_gate_is_explicit_opt_in(self):
        local_steps = build_steps(False, False, "21d", 60)
        self.assertNotIn("sentinel synthetic-hit drift check", [step[0] for step in local_steps])

        strict_steps = build_steps(False, False, "21d", 60, True)
        strict_idx = self.step_index(strict_steps, "sentinel synthetic-hit drift check")

        self.assertLess(self.step_index(strict_steps, "sentinel drift check"), strict_idx)
        self.assertLess(strict_idx, self.step_index(strict_steps, "dashboard dry run"))
        self.assertIn("--require-synthetic-hits", strict_steps[strict_idx][1])

    def test_pytest_is_the_release_test_command(self):
        steps = build_steps(False, False, "21d", 60)
        pytest_step = steps[self.step_index(steps, "pytest")]

        self.assertEqual(pytest_step[1][1:], ["-m", "pytest", "-q"])

    def test_tests_can_be_skipped_without_removing_syntax_gate(self):
        steps = build_steps(False, True, "21d", 60)
        names = [step[0] for step in steps]

        self.assertIn("sensitive value scan", names)
        self.assertIn("compileall scripts", names)
        self.assertNotIn("pytest", names)

    def test_sensitive_scan_runs_before_compile_and_live_gates(self):
        local_steps = build_steps(False, False, "21d", 60)
        scanner_idx = self.step_index(local_steps, "sensitive value scan")

        self.assertLess(self.step_index(local_steps, "inventory drift check"), scanner_idx)
        self.assertLess(scanner_idx, self.step_index(local_steps, "compileall scripts"))
        self.assertTrue(any(str(part).endswith("scan_sensitive_values.py") for part in local_steps[scanner_idx][1]))

        live_steps = build_steps(True, False, "21d", 60)
        self.assertLess(self.step_index(live_steps, "sensitive value scan"), self.step_index(live_steps, "live profile dashboard verification"))

    def test_dashboard_dry_run_skips_live_validation(self):
        steps = build_steps(False, False, "21d", 60)
        dry_run_step = steps[self.step_index(steps, "dashboard dry run")]

        self.assertIn("--dry-run", dry_run_step[1])
        self.assertIn("--skip-live-validation", dry_run_step[1])

    def test_live_dashboard_verification_only_runs_when_requested(self):
        local_steps = build_steps(False, False, "21d", 60)
        local_commands = " ".join(str(part) for _, command, _ in local_steps for part in command)
        self.assertNotIn("verify_deployed_dashboards.py", local_commands)

        live_steps = build_steps(True, False, "21d", 60)
        self.assertEqual(live_steps[-1][0], "live profile dashboard verification")
        live_commands = " ".join(str(part) for _, command, _ in live_steps for part in command)
        self.assertIn("verify_deployed_dashboards.py", live_commands)

    def test_splunk_parallel_stage_covers_only_offline_release_contracts(self):
        stage_steps = release_checklist.build_splunk_parallel_offline_steps()
        names = [step[0] for step in stage_steps]

        self.assertEqual(
            names,
            [
                "registry drift validation",
                "schema validation",
                "local exporter success",
                "local exporter duplicate",
                "local exporter failure",
                "local exporter replay",
                "diagram validation",
                "documentation validation",
                "terraform format validation",
                "terraform static validation",
            ],
        )
        commands = [step[1] for step in stage_steps]
        self.assertIn("--check", commands[0])
        self.assertEqual(commands[2][-2:], ["--scenario", "success"])
        self.assertEqual(commands[3][-2:], ["--scenario", "duplicate-invocation"])
        self.assertEqual(commands[4][-2:], ["--scenario", "500"])
        self.assertEqual(
            commands[5][-3:],
            ["--scenario", "approved-replay", "--approve-replay"],
        )
        self.assertIn("scripts/test_splunk_diagrams.py", commands[6])
        self.assertIn("scripts/test_splunk_documentation.py", commands[7])
        self.assertEqual(commands[8][1:], ["fmt", "-check", "-recursive", "stack"])
        self.assertEqual(
            commands[9][1:],
            ["-chdir=stack", "validate", "-no-color"],
        )

        allowed_executables = {sys.executable, "terraform"}
        self.assertTrue(all(command[0] in allowed_executables for command in commands))
        forbidden_arguments = {
            "--include-live",
            "plan",
            "apply",
            "oci",
            "curl",
            "wget",
        }
        self.assertFalse(
            forbidden_arguments.intersection(
                argument.lower()
                for command in commands
                for argument in command
            )
        )

        release_steps = build_steps(False, False, "21d", 60)
        release_names = [step[0] for step in release_steps]
        self.assertIn("splunk parallel offline release", release_names)


class TestReleaseChecklistEvidence(unittest.TestCase):
    """Validate release evidence shape and fail-fast behavior."""

    def test_splunk_parallel_offline_stage_returns_classified_structured_evidence(self):
        result = subprocess.run(
            [
                sys.executable,
                str(Path(release_checklist.__file__).resolve()),
                "--splunk-parallel-offline-stage",
            ],
            cwd=Path(release_checklist.__file__).resolve().parents[1],
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(result.stdout)
        self.assertEqual(evidence["schema_version"], "oci.logan.splunk.local-release.v1")
        self.assertEqual(evidence["status"], "PASS")
        self.assertTrue(evidence["offline"])
        self.assertEqual(evidence["external_calls"], [])
        self.assertEqual(evidence["evidence_class"], "locally_verified")
        self.assertEqual(evidence["provider_validation"], "not_run")
        self.assertFalse(evidence["provider_verified"])
        self.assertEqual(
            evidence["scenario_counts"],
            {
                "requested": 4,
                "passed": 4,
                "success": 1,
                "duplicate": 1,
                "failure": 1,
                "replay": 1,
            },
        )
        self.assertEqual(evidence["gate_counts"], {"total": 10, "passed": 10, "failed": 0})
        self.assertTrue(all(gate["ok"] for gate in evidence["gates"]))
        self.assertIn("queries/splunk_detection_registry.json", evidence["artifact_hashes"])
        self.assertIn("schemas/splunk_evidence_event.schema.json", evidence["artifact_hashes"])
        self.assertNotIn("generated_at", evidence)
        self.assertNotRegex(result.stdout, r"(?i)ocid1\.|authorization: splunk")

    def test_run_step_output_tail_is_bounded(self):
        result = release_checklist._run_step(
            "bounded output",
            [sys.executable, "-c", "print('x' * 7000)"],
            timeout=30,
        )

        self.assertTrue(result["ok"])
        self.assertLessEqual(len(result["output_tail"]), 6000)
        self.assertEqual(
            {"name", "command", "started_at", "exit_code", "ok", "output_tail"},
            set(result),
        )

    def test_run_step_output_tail_is_redacted(self):
        fixture_ocid = "ocid1.tenancy.oc1..aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"  # scanner-fixture
        result = release_checklist._run_step(
            "redacted output",
            [sys.executable, "-c", f"print('{fixture_ocid}')"],
            timeout=30,
        )

        self.assertTrue(result["ok"])
        self.assertNotIn(fixture_ocid, result["output_tail"])
        self.assertIn("<redacted:ocid>", result["output_tail"])

    def test_failed_step_stops_later_steps_and_writes_fail_evidence(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "release.json"
            steps = [
                ("first gate", [sys.executable, "-c", "raise SystemExit(2)"], 30),
                ("second gate", [sys.executable, "-c", "raise SystemExit(0)"], 30),
            ]
            first_result = {
                "name": "first gate",
                "command": steps[0][1],
                "started_at": "2026-05-15T00:00:00+00:00",
                "exit_code": 2,
                "ok": False,
                "output_tail": "redacted failure",
            }

            with patch.object(sys, "argv", ["release_checklist.py", "--report", str(report_path)]):
                with patch("release_checklist.build_steps", return_value=steps):
                    with patch("release_checklist._run_step", return_value=first_result) as run_step:
                        exit_code = release_checklist.main()

            self.assertEqual(exit_code, 1)
            self.assertEqual(run_step.call_count, 1)
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["version"], "1.0")
            self.assertIn("generated_at", report)
            self.assertFalse(report["include_live"])
            self.assertEqual(report["overall_status"], "FAIL")
            self.assertEqual(len(report["steps"]), 1)
            self.assertEqual(
                {"name", "command", "started_at", "exit_code", "ok", "output_tail"},
                set(report["steps"][0]),
            )


if __name__ == "__main__":
    unittest.main()
