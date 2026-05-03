#!/usr/bin/env python3
"""Regression tests for expanding synthetic attack datasets across days."""

import os
import random
import sys
import unittest
from collections import defaultdict
from datetime import timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from generate_test_logs import (
    expand_events_over_days,
    generate_linux_secure,
    generate_oci_audit_events,
    generate_sysmon_network_events,
    generate_sysmon_operational,
    generate_waf_events,
    generate_windows_event_security,
    generate_windows_events,
    shift_event_window,
)


class TestGenerateTestLogs(unittest.TestCase):
    """Ensure the demo datasets can be extended to a full-week window."""

    def test_shift_event_window_recursively_updates_timestamps(self):
        payload = {
            "timestamp": "2026-04-20T10:15:30.000Z",
            "nested": {
                "eventTime": "2026-04-20T10:16:30.000Z",
                "note": "not-a-timestamp",
            },
            "items": [
                {"Timestamp": "2026-04-20T10:17:30.000Z"},
                "still-not-a-timestamp",
            ],
        }

        shifted = shift_event_window(payload, timedelta(days=2))

        self.assertEqual(shifted["timestamp"], "2026-04-22T10:15:30.000Z")
        self.assertEqual(shifted["nested"]["eventTime"], "2026-04-22T10:16:30.000Z")
        self.assertEqual(shifted["items"][0]["Timestamp"], "2026-04-22T10:17:30.000Z")
        self.assertEqual(shifted["nested"]["note"], "not-a-timestamp")

    def test_expand_events_over_days_repeats_scenarios_per_day(self):
        events = [
            {"timestamp": "2026-04-20T10:15:30.000Z", "value": 1},
            {"timestamp": "2026-04-20T11:15:30.000Z", "value": 2},
        ]

        expanded = expand_events_over_days(events, 3)

        self.assertEqual(len(expanded), 6)
        self.assertEqual(expanded[0]["timestamp"], "2026-04-18T10:15:30.000Z")
        self.assertEqual(expanded[2]["timestamp"], "2026-04-19T10:15:30.000Z")
        self.assertEqual(expanded[4]["timestamp"], "2026-04-20T10:15:30.000Z")

    def test_windows_security_process_creation_events_include_detection_commandlines(self):
        random.seed(7)
        events = generate_windows_event_security()

        process_events = [
            event for event in events
            if str(event.get("Event ID") or event.get("EventID")) == "4688"
        ]
        command_lines = " ".join(
            (event.get("Command Line") or event.get("CommandLine") or "")
            for event in process_events
        )

        self.assertTrue(process_events)
        self.assertIn("whoami /all", command_lines)
        self.assertIn("Invoke-WebRequest", command_lines)
        self.assertIn("sekurlsa::logonpasswords", command_lines)

    def test_oci_audit_events_include_dashboard_status_labels_and_policy_keywords(self):
        random.seed(17)
        events = generate_oci_audit_events()

        console_successes = [
            event for event in events
            if event.get("eventType") == "com.oraclecloud.consolesignon.login"
            and event.get("Status") == "Success"
            and event.get("data", {}).get("response", {}).get("status") == "200"
        ]
        admin_policy_events = [
            event for event in events
            if event.get("eventType") == "com.oraclecloud.identitycontrolplane.createpolicy"
            and "manage all-resources" in event.get("data", {}).get("resourceName", "")
        ]

        self.assertGreaterEqual(len(console_successes), 8)
        self.assertGreaterEqual(len(admin_policy_events), 3)

    def test_linux_secure_events_mirror_messages_to_command_line_fields(self):
        random.seed(19)
        events = generate_linux_secure()

        crontab_events = [
            event for event in events
            if event.get("Process") == "crontab"
            and any(pattern in event.get("Command Line", "") for pattern in ("crontab -e", "/tmp/", "/dev/shm/"))
        ]

        self.assertTrue(crontab_events)
        for event in crontab_events:
            self.assertEqual(event["msg"], event["CommandLine"])
            self.assertEqual(event["msg"], event["Command Line"])

    def test_windows_events_include_rare_process_hunting_tail(self):
        random.seed(23)
        events = generate_windows_events()

        command_lines = {
            event.get("Command Line") or event.get("CommandLine")
            for event in events
            if str(event.get("Event ID") or event.get("EventID")) == "1"
        }

        self.assertIn("rare_recon.exe -enum users", command_lines)
        self.assertIn("anomaly_dropper.exe stage", command_lines)

    def test_sysmon_operational_includes_named_pipe_iocs(self):
        random.seed(29)
        events = generate_sysmon_operational()

        pipe_names = {
            event.get("Pipe Name") or event.get("PipeName")
            for event in events
            if str(event.get("Event ID") or event.get("EventID")) == "17"
        }

        self.assertIn(r"\\.\pipe\PSEXESVC", pipe_names)
        self.assertIn(r"\\.\pipe\MSSE-1234-server", pipe_names)
        self.assertIn(r"\\.\pipe\mimikatz_lsass", pipe_names)

    def test_sysmon_network_includes_dns_tunnel_processes(self):
        random.seed(31)
        events = generate_sysmon_network_events()

        dns_processes = {
            event.get("Process Name") or event.get("Image")
            for event in events
            if str(event.get("Destination Port") or event.get("DestinationPort")) == "53"
            and str(event.get("Initiated")).lower() == "true"
        }

        self.assertIn(r"C:\Tools\iodine.exe", dns_processes)
        self.assertIn(r"C:\Tools\dnscat2.exe", dns_processes)
        self.assertIn(r"C:\Tools\dns2tcp.exe", dns_processes)

    def test_waf_events_include_cors_and_allowed_sqli_cases(self):
        random.seed(37)
        events = generate_waf_events()

        cors_blocks = [
            event for event in events
            if event.get("action") == "BLOCK"
            and "Origin:" in event.get("requestHeaders", "")
        ]
        allowed_sqli = [
            event for event in events
            if event.get("action") == "DETECT"
            and event.get("responseCode") == "200"
            and any(token in event.get("requestUrl", "") for token in ("UNION SELECT", "sleep(5)", "'--"))
        ]

        self.assertGreaterEqual(len(cors_blocks), 5)
        self.assertGreaterEqual(len(allowed_sqli), 3)

    def test_sysmon_operational_includes_screen_capture_burst(self):
        random.seed(11)
        events = generate_sysmon_operational()

        buckets = defaultdict(int)
        for event in events:
            if str(event.get("Event ID") or event.get("EventID")) != "11":
                continue
            target_filename = event.get("Target Filename", "")
            if not target_filename.lower().endswith(".jpg"):
                continue
            minute_bucket = (event.get("TimeCreated") or "")[:16]
            buckets[(minute_bucket, event.get("Process Name"))] += 1

        self.assertTrue(buckets)
        self.assertGreaterEqual(max(buckets.values()), 4)

    def test_bluelight_kill_chain_has_multi_stage_host_coverage(self):
        random.seed(13)
        stage_hits = defaultdict(set)
        datasets = (
            generate_windows_events()
            + generate_sysmon_operational()
            + generate_sysmon_network_events()
        )

        for event in datasets:
            host = event.get("Host Name (Server)") or event.get("Computer")
            event_id = str(event.get("Event ID") or event.get("EventID"))
            process_name = (event.get("Process Name") or event.get("Image") or "").lower()
            parent_name = (event.get("Parent Process Name") or event.get("ParentImage") or "").lower()
            target_process = (event.get("Target Process") or event.get("TargetImage") or "").lower()
            source_process = (event.get("Source Process") or event.get("SourceImage") or "").lower()
            destination = (event.get("Destination Hostname") or event.get("DestinationHostname") or "").lower()
            command_line = (event.get("Command Line") or event.get("CommandLine") or "").lower()

            if event_id == "1" and "iexplore.exe" in parent_name and any(
                binary in process_name for binary in ("cmd.exe", "powershell.exe", "wscript.exe")
            ):
                stage_hits[host].add("initial_access")
            if event_id == "3" and "graph.microsoft.com" in destination and not any(
                allowed in process_name for allowed in ("onedrive.exe", "teams.exe", "outlook.exe")
            ):
                stage_hits[host].add("graph_c2")
            if event_id == "10" and any(browser in target_process for browser in ("chrome.exe", "firefox.exe")) and not any(
                browser in source_process for browser in ("chrome.exe", "firefox.exe")
            ):
                stage_hits[host].add("credential_access")
            if "win32_computersystem" in command_line or "win32_operatingsystem" in command_line:
                stage_hits[host].add("discovery")
            if "frombase64string" in command_line or "-bxor" in command_line:
                stage_hits[host].add("obfuscation")

        self.assertTrue(
            any(len(stages) >= 3 for stages in stage_hits.values()),
            stage_hits,
        )


if __name__ == "__main__":
    unittest.main()
