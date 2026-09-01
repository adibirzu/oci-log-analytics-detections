#!/usr/bin/env python3
"""Public contract tests for the Windows access-monitoring fast track."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.windows_eventlog_synthetic import generate_all
from scripts.windows_access_onboarding import (
    build_alert_plan,
    build_association_template,
    evaluate_access_alerts,
    render_cli_bundle,
)
from scripts.dashboards.catalog import DASHBOARDS
from scripts.detection_rule_creator import build_detection_rule_spec


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "windows_access_onboarding.py"


class TestWindowsAccessOnboarding(unittest.TestCase):
    def test_plan_exposes_native_sources_fields_events_and_alerts(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "plan", "--json"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        plan = json.loads(result.stdout)

        self.assertEqual(
            {source["display_name"] for source in plan["continuous_collection"]["sources"]},
            {
                "Windows Security Events",
                "Windows System Events",
                "Windows Application Events",
            },
        )
        self.assertTrue(
            {"Event ID", "Logon Type", "Source Address", "Target User Name"}.issubset(
                plan["required_fields"]
            )
        )
        self.assertEqual(
            set(plan["event_ids"]),
            {"4624", "4625", "4634", "4648", "4672", "4720", "4726", "4732", "4733", "4776"},
        )
        self.assertEqual(len(plan["alert_searches"]), 5)
        self.assertTrue(all(item["query_file"].startswith("queries/hunting/") for item in plan["alert_searches"]))

    def test_synthetic_pack_covers_requested_channels_and_event_ids(self):
        datasets = generate_all()

        self.assertIn("windows_event_application.jsonl", datasets)
        security_ids = {
            str(record["Event ID"])
            for record in datasets["windows_event_security.jsonl"]
        }
        self.assertTrue(
            {"4624", "4625", "4634", "4648", "4672", "4720", "4726", "4732", "4733", "4776"}.issubset(
                security_ids
            )
        )

    def test_local_e2e_triggers_every_access_alert(self):
        security_events = generate_all()["windows_event_security.jsonl"]

        report = evaluate_access_alerts(
            security_events,
            business_start_hour=8,
            business_end_hour=18,
        )

        self.assertEqual(report["status"], "passed")
        self.assertEqual(
            set(report["triggered_alerts"]),
            {item["id"] for item in json.loads(
                subprocess.run(
                    [sys.executable, str(SCRIPT), "plan", "--json"],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=True,
                ).stdout
            )["alert_searches"]},
        )
        self.assertEqual(report["evidence"]["failed-logon-burst"][0]["count"], 11)

    def test_alert_searches_are_dashboard_and_schedule_ready(self):
        plan = json.loads(
            subprocess.run(
                [sys.executable, str(SCRIPT), "plan", "--json"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=True,
            ).stdout
        )

        for alert in plan["alert_searches"]:
            path = ROOT / alert["query_file"]
            self.assertTrue(path.exists(), path)
            payload = json.loads(path.read_text())
            self.assertIn("dashboard", payload)
            self.assertEqual(payload["detection_rule"]["schedule"], "5m")
            spec = build_detection_rule_spec(alert["query_file"], payload)
            self.assertTrue(spec["eligible"], spec["reasons"])

        dashboard = DASHBOARDS["SOC: Windows Access Monitoring"]
        self.assertGreaterEqual(len(dashboard["widgets"]), 5)
        self.assertEqual(
            {widget["query_file"] for widget in dashboard["widgets"]},
            {Path(item["query_file"]).relative_to("queries").as_posix() for item in plan["alert_searches"]},
        )

    def test_synthetic_application_source_and_access_fields_are_defined(self):
        from scripts.logsources.application_sources import APP_FIELD_MAPPINGS, APP_SOURCE_DISPLAY
        from scripts.logsources.endpoint_sources import WINSEC_FIELD_MAPPINGS

        security_fields = {field for field, _path, _sequence in WINSEC_FIELD_MAPPINGS}
        application_fields = {field for field, _path, _sequence in APP_FIELD_MAPPINGS}

        self.assertEqual(APP_SOURCE_DISPLAY, "SOC Application Logs")
        self.assertIn("Target User Name", security_fields)
        self.assertTrue({"Application Name", "Host Name"}.issubset(application_fields))
        application_record = generate_all()["windows_event_application.jsonl"][0]
        self.assertEqual(application_record["serviceName"], "synthetic-app.exe")
        self.assertEqual(application_record["hostname"], "WS01.synthetic.example")

    def test_windows_access_source_setup_has_a_narrow_dry_run(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "setup_log_sources.py"), "--windows-access-only", "--dry-run"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Windows Event Security Logs", result.stdout)
        self.assertIn("Windows Event System Logs", result.stdout)
        self.assertIn("Application-channel fixtures are validated locally", result.stdout)
        self.assertNotIn("SOC Cloud Guard Logs", result.stdout)

    def test_windows_agent_helper_exposes_safe_plan_without_installing(self):
        helper = ROOT / "scripts" / "windows" / "management_agent_access_setup.ps1"
        result = subprocess.run(
            ["pwsh", "-NoProfile", "-File", str(helper), "-Mode", "Plan"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["mode"], "Plan")
        self.assertEqual(payload["channels"], ["Security", "System", "Application"])
        self.assertIn("Service.plugin.logan.download=true", payload["required_response_file_setting"])
        self.assertEqual(payload["minimum_free_disk_mb"], 300)
        self.assertEqual(payload["minimum_java_8_update"], 281)
        self.assertTrue(payload["wmic_required"])
        self.assertEqual(
            payload["required_https_endpoints"],
            [
                "loganalytics.<region>.oci.oraclecloud.com:443",
                "telemetry-ingestion.<region>.oraclecloud.com:443",
            ],
        )
        self.assertIn("installer.bat", payload["installation_command"])
        self.assertFalse(payload["mutated_host"])

    def test_association_template_uses_only_native_windows_sources(self):
        template = build_association_template(
            agent_id="<MANAGEMENT_AGENT_OCID>",
            entity_id="<WINDOWS_ENTITY_OCID>",
            log_group_id="<LOG_GROUP_OCID>",
        )

        self.assertEqual(template["evidence_class"], "code-backed")
        self.assertFalse(template["applied"])
        self.assertEqual(len(template["items"]), 3)
        self.assertEqual(
            {item["sourceName"] for item in template["items"]},
            {
                "MsftWinEventSecurityLogSource",
                "MsftWinEventSystemLogSource",
                "MsftWinEventApplicationLogSource",
            },
        )
        for item in template["items"]:
            self.assertEqual(item["agentId"], "<MANAGEMENT_AGENT_OCID>")
            self.assertEqual(item["entityId"], "<WINDOWS_ENTITY_OCID>")
            self.assertEqual(item["logGroupId"], "<LOG_GROUP_OCID>")

    def test_alert_plan_is_review_only_and_uses_valid_custom_namespace(self):
        plan = build_alert_plan(
            log_analytics_compartment_id="<LA_COMPARTMENT_OCID>",
            metric_compartment_id="<METRIC_COMPARTMENT_OCID>",
            alarm_compartment_id="<ALARM_COMPARTMENT_OCID>",
            notification_topic_id="<NOTIFICATION_TOPIC_OCID>",
        )

        self.assertEqual(plan["evidence_class"], "code-backed")
        self.assertFalse(plan["applied"])
        self.assertEqual(len(plan["scheduled_tasks"]), 5)
        self.assertEqual(len(plan["alarms"]), 5)
        self.assertFalse(plan["metric_namespace"].startswith(("oci_", "oracle_")))

        for task in plan["scheduled_tasks"]:
            self.assertEqual(task["taskType"], "SAVED_SEARCH")
            self.assertEqual(task["action"]["type"], "STREAM")
            self.assertEqual(task["action"]["savedSearchDuration"], "PT5M")
            self.assertEqual(task["schedules"][0]["recurringInterval"], "PT5M")
            self.assertLessEqual(len(task["dimensions"]), 3)
            self.assertTrue(task["action"]["savedSearchId"].startswith("<"))

        for alarm in plan["alarms"]:
            self.assertFalse(alarm["isEnabled"])
            self.assertEqual(alarm["destinations"], ["<NOTIFICATION_TOPIC_OCID>"])
            self.assertRegex(alarm["query"], r"^[A-Za-z][A-Za-z0-9]*\[5m\]\.sum\(\) > 0$")

    def test_cli_bundle_renders_apply_ready_files_with_saved_search_gates(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            report = render_cli_bundle(
                output_dir=Path(temporary_directory),
                namespace_name="<LA_NAMESPACE>",
                log_analytics_compartment_id="<LA_COMPARTMENT_OCID>",
                metric_compartment_id="<METRIC_COMPARTMENT_OCID>",
                alarm_compartment_id="<ALARM_COMPARTMENT_OCID>",
                notification_topic_id="<NOTIFICATION_TOPIC_OCID>",
                agent_id="<MANAGEMENT_AGENT_OCID>",
                entity_id="<WINDOWS_ENTITY_OCID>",
                log_group_id="<LOG_GROUP_OCID>",
            )

            self.assertFalse(report["applied"])
            self.assertEqual(report["file_count"], 12)
            bundle_dir = Path(temporary_directory)
            association = json.loads((bundle_dir / "association.json").read_text())
            self.assertEqual(association["namespaceName"], "<LA_NAMESPACE>")
            self.assertEqual(len(association["items"]), 3)

            task_files = sorted(bundle_dir.glob("scheduled-task-*.json"))
            alarm_files = sorted(bundle_dir.glob("alarm-*.json"))
            self.assertEqual(len(task_files), 5)
            self.assertEqual(len(alarm_files), 5)
            self.assertTrue(json.loads(task_files[0].read_text())["action"]["savedSearchId"].startswith("<"))
            self.assertFalse(json.loads(alarm_files[0].read_text())["isEnabled"])

            manifest = json.loads((bundle_dir / "manifest.json").read_text())
            self.assertEqual(manifest["apply_sequence"][0]["file"], "association.json")
            self.assertIn("replace_saved_search_placeholders", manifest["blocking_gates"])

    def test_manual_scripted_and_diagram_runbooks_are_linked_and_complete(self):
        overview = (ROOT / "docs" / "WINDOWS_ACCESS_FAST_ONBOARDING.md").read_text()
        manual = (ROOT / "docs" / "WINDOWS_ACCESS_MANUAL_RUNBOOK.md").read_text()
        scripted = (ROOT / "docs" / "WINDOWS_ACCESS_SCRIPTED_RUNBOOK.md").read_text()
        diagrams = (ROOT / "docs" / "WINDOWS_ACCESS_WORKFLOW_DIAGRAMS.md").read_text()

        self.assertIn("WINDOWS_ACCESS_MANUAL_RUNBOOK.md", overview)
        self.assertIn("WINDOWS_ACCESS_SCRIPTED_RUNBOOK.md", overview)
        self.assertIn("WINDOWS_ACCESS_WORKFLOW_DIAGRAMS.md", overview)
        self.assertIn("management_agent_access_setup.ps1", overview)
        self.assertGreaterEqual(overview.count("```mermaid"), 2)

        for required in (
            r"installer.bat C:\secure\input.rsp",
            "Host (Windows)",
            "MsftWinEventSecurityLogSource",
            "logan_windows_access",
            "Create disabled alarm canaries",
        ):
            self.assertIn(required, manual)

        for required in (
            "management_agent_access_setup.ps1",
            "render-cli-bundle",
            "association.json",
            "scheduled-task-failed-logon-burst.json",
            "alarm-failed-logon-burst.json",
        ):
            self.assertIn(required, scripted)

        self.assertEqual(diagrams.count("```mermaid"), 5)
        self.assertNotRegex(diagrams, r"(?i)\bclick\s+")

    def test_windows_runbook_local_links_resolve(self):
        paths = [
            ROOT / "README.md",
            ROOT / "docs" / "README.md",
            ROOT / "docs" / "FAST_ONBOARDING_TRACK.md",
            ROOT / "docs" / "WINDOWS_ACCESS_FAST_ONBOARDING.md",
            ROOT / "docs" / "WINDOWS_ACCESS_MANUAL_RUNBOOK.md",
            ROOT / "docs" / "WINDOWS_ACCESS_SCRIPTED_RUNBOOK.md",
            ROOT / "docs" / "WINDOWS_ACCESS_WORKFLOW_DIAGRAMS.md",
        ]
        missing = []
        for path in paths:
            for target in re.findall(r"(?<!!)\[[^\]]+\]\(([^)]+)\)", path.read_text()):
                target = target.strip()
                if target.startswith(("http://", "https://", "#", "mailto:")):
                    continue
                local_target = target.split("#", 1)[0]
                if local_target and not (path.parent / local_target).resolve().exists():
                    missing.append(f"{path.relative_to(ROOT)} -> {target}")

        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
