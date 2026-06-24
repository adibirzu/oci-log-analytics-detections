"""Shared constants and helpers for the testlogs package.

Auto-extracted from generate_test_logs.py — behavior-preserving. All module-level
constants and the cross-source helper functions used by the per-source builders
live here so each ``testlogs.<source>`` module can ``from testlogs.common import *``.
"""
import json
import ntpath
import os
import random
import re
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from oci_config import COMPARTMENT_ID

# This module lives at scripts/testlogs/common.py, so the repo root is three
# parents up. (Before the T1 split these constants lived in
# scripts/generate_test_logs.py at two parents up; the extra package directory
# adds one level.) OUTPUT_DIR must equal oci_config.TEST_DATA_DIR (<repo>/test_data)
# or the generated corpus lands in the wrong place and the ingest-manifest
# contract test fails on a fresh checkout.
PROJECT_DIR = Path(__file__).resolve().parent.parent.parent
OUTPUT_DIR = PROJECT_DIR / 'test_data'
QUERIES_DIR = PROJECT_DIR / 'queries'
OCI_USERS = [
    ("<DEMO_USER_ADMIN_OCID>", "admin@corp.example.com", "natv"),
    ("<DEMO_USER_SRE_LEAD_OCID>", "sre-lead@corp.example.com", "natv"),
    ("<DEMO_USER_DEVOPS_OCID>", "dev-ops@corp.example.com", "federation"),
    ("<DEMO_USER_ROGUE_ADMIN_OCID>", "rogue-admin@corp.example.com", "natv"),
    ("<DEMO_USER_COMPROMISED_SERVICE_OCID>", "compromised-svc@corp.example.com", "natv"),
]
SUSPICIOUS_IPS = ["45.33.32.156", "185.220.101.1", "91.92.109.18", "194.5.249.7"]
CORPORATE_IPS = ["10.0.0.5", "10.0.1.10", "172.16.0.50", "192.168.1.100"]
LINUX_HOSTS = ["web-prod-01", "app-prod-02", "db-prod-01", "bastion-01", "k8s-worker-03"]
LINUX_USERS = ["root", "admin", "deploy", "www-data", "svc-app"]
WINDOWS_HOSTS = ["DC01.corp.local", "SRV01.corp.local", "WS01.corp.local"]
WINDOWS_USERS = ["CORP\\admin", "CORP\\analyst", "NT AUTHORITY\\SYSTEM"]
BASE_TIME = datetime.now(timezone.utc) - timedelta(hours=24)
ISO_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")
WEB_TO_CLOUD_TRACE_ID = "trace_w2c_entry_001"
WEB_TO_CLOUD_ATTACKER_IP = "185.220.101.1"
WEB_TO_CLOUD_ATTACKER_UA = "Mozilla/5.0 (compatible; Nuclei - Open-source project)"
WEB_TO_CLOUD_COMPROMISED_HOST = "app-prod-02"
WEB_TO_CLOUD_COMPROMISED_PRIVATE_IP = "10.0.1.50"
WEB_TO_CLOUD_WINDOWS_HOST = "SRV01.sevenkingdoms.local"
WEB_TO_CLOUD_WINDOWS_PRIVATE_IP = "10.0.1.66"
WEB_TO_CLOUD_C2_IP = "198.51.100.77"
WEB_TO_CLOUD_C2_HOST = "updates.cdn-check.example"
WEB_TO_CLOUD_COMPROMISED_USER = "compromised-svc@corp.example.com"
WEB_TO_CLOUD_BUCKET = "prod-customer-backups"
WEB_TO_CLOUD_EXFIL_OBJECT = "customer-export-2026-05.csv"
WEB_TO_CLOUD_REQUEST_URL = (
    "/crm/profile/avatar?url=http://169.254.169.254/opc/v2/instance/"
)
CLICKFIX_TRACE_ID = "trace_clickfix_2026_001"
CLICKFIX_COMPROMISED_HOST = "WS02.sevenkingdoms.local"
CLICKFIX_COMPROMISED_PRIVATE_IP = "10.0.2.71"
CLICKFIX_C2_IP = "203.0.113.200"
CLICKFIX_C2_HOST = "captcha-verify.example"
TOOL_SHELL_TRACE_ID = "trace_toolshell_sp_001"
TOOL_SHELL_ATTACKER_IP = "198.51.100.44"
TOOL_SHELL_HOST = "sharepoint-prod-01"
TOOL_SHELL_BACKEND = "10.0.4.15"
RMM_TRACE_ID = "trace_rmm_2025_001"
AITM_TRACE_ID = "trace_aitm_token_2026_001"
THREAT_ACTORS = ["joffrey", "littlefinger", "arya", "daenerys", "sql_svc", "svc-devops"]
THREAT_ACTOR_EMAILS = [
    "joffrey.baratheon@sevenkingdoms.local",
    "arya.stark@sevenkingdoms.local",
]
SEVEN_KINGDOMS_HOSTS = [
    "DC01.sevenkingdoms.local", "SRV01.sevenkingdoms.local",
    "WS01.sevenkingdoms.local", "WS02.sevenkingdoms.local",
    "DB01.sevenkingdoms.local",
]
SEVEN_KINGDOMS_LINUX = [
    "web01.sevenkingdoms.local", "app01.sevenkingdoms.local",
    "db01.sevenkingdoms.local", "bastion.sevenkingdoms.local",
    "k8s-node01.sevenkingdoms.local",
]
ATTACKER_IPS = ["185.220.101.1", "91.92.109.18", "45.33.32.156", "194.5.249.7",
                "23.129.64.100", "51.15.43.205", "178.128.23.9"]
ATTACKER_UAS = ["sqlmap/1.7", "Nikto/2.1.6", "Mozilla/5.0 (compatible; Hydra/9.0)",
                "python-requests/2.28.0", "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
                "Gobuster/3.6", "OWASP ZAP/2.14.0"]
WAF_HOST = "sevenkingdoms.example.com"


def ts(offset_minutes=0):
    """Generate ISO8601 timestamp with optional offset."""
    t = BASE_TIME + timedelta(minutes=offset_minutes, seconds=random.randint(0, 59))
    return t.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def iso_to_epoch_seconds(value):
    """Convert a generated UTC ISO8601 timestamp to epoch seconds."""
    return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())


def windows_guid():
    """Generate a Windows-style GUID string with braces."""
    return "{" + str(uuid.uuid4()).upper() + "}"


def shift_iso8601_utc(value, delta):
    """Shift a ``...Z`` UTC timestamp string by ``delta`` if it matches ISO8601."""
    if not isinstance(value, str) or not ISO_UTC_RE.match(value):
        return value

    shifted = datetime.fromisoformat(value.replace("Z", "+00:00")) + delta
    return shifted.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def shift_event_window(payload, delta):
    """Recursively shift UTC timestamp strings in a JSON-like payload."""
    if isinstance(payload, dict):
        return {key: shift_event_window(value, delta) for key, value in payload.items()}
    if isinstance(payload, list):
        return [shift_event_window(item, delta) for item in payload]
    return shift_iso8601_utc(payload, delta)


def expand_events_over_days(events, days):
    """Replicate a scenario set across trailing daily windows ending on the base day."""
    if days <= 1:
        return list(events)

    expanded = []
    for day in range(days - 1, -1, -1):
        delta = timedelta(days=-day)
        for event in events:
            expanded.append(shift_event_window(event, delta))
    return expanded


def write_jsonl(filepath, events):
    """Write events as NDJSON (one JSON object per line)."""
    with open(filepath, 'w') as f:
        for event in events:
            f.write(json.dumps(event, default=str) + "\n")
    return len(events)


def add_windows_event_envelope(event, *, channel, provider, provider_guid="",
                               event_data_fields=None):
    """Attach a Windows Event XML-shaped envelope translated to JSON.

    The envelope mirrors the official ``Event/System/EventData`` structure while
    preserving the top-level parser aliases used by the OCI Log Analytics JSON
    parsers.
    """
    event_id = str(event.get("EventID") or event.get("Event ID") or "")
    event_time = event.get("TimeCreated") or event.get("UtcTime") or event.get("time") or ts(0)
    computer = event.get("Computer") or event.get("Host Name (Server)") or event.get("Host Name") or "windows.synthetic.example"
    provider_entry = {"Name": provider}
    if provider_guid:
        provider_entry["Guid"] = provider_guid

    fields = event_data_fields or []
    event_data = [
        {"Name": field, "#text": str(event[field])}
        for field in fields
        if event.get(field) not in ("", None)
    ]

    event["Event"] = {
        "System": {
            "Provider": provider_entry,
            "EventID": event_id,
            "Version": "0",
            "Level": "0",
            "Task": "0",
            "Opcode": "0",
            "Keywords": "0x8020000000000000",
            "TimeCreated": {"SystemTime": event_time},
            "EventRecordID": str(event.get("Event Record ID") or event.get("EventRecordID") or random.randint(1000, 999999)),
            "Correlation": {},
            "Execution": {
                "ProcessID": str(event.get("Process ID") or event.get("ProcessId") or 704),
                "ThreadID": str(event.get("ThreadID") or 1140),
            },
            "Channel": channel,
            "Computer": computer,
            "Security": {"UserID": "S-1-5-18"},
        },
        "EventData": {"Data": event_data},
    }
    event.setdefault("RenderedDescription", event.get("msg", ""))


__all__ = ['AITM_TRACE_ID', 'ATTACKER_IPS', 'ATTACKER_UAS', 'BASE_TIME', 'CLICKFIX_C2_HOST', 'CLICKFIX_C2_IP', 'CLICKFIX_COMPROMISED_HOST', 'CLICKFIX_COMPROMISED_PRIVATE_IP', 'CLICKFIX_TRACE_ID', 'COMPARTMENT_ID', 'CORPORATE_IPS', 'ISO_UTC_RE', 'LINUX_HOSTS', 'LINUX_USERS', 'OCI_USERS', 'OUTPUT_DIR', 'PROJECT_DIR', 'QUERIES_DIR', 'RMM_TRACE_ID', 'SEVEN_KINGDOMS_HOSTS', 'SEVEN_KINGDOMS_LINUX', 'SUSPICIOUS_IPS', 'THREAT_ACTORS', 'THREAT_ACTOR_EMAILS', 'TOOL_SHELL_ATTACKER_IP', 'TOOL_SHELL_BACKEND', 'TOOL_SHELL_HOST', 'TOOL_SHELL_TRACE_ID', 'WAF_HOST', 'WEB_TO_CLOUD_ATTACKER_IP', 'WEB_TO_CLOUD_ATTACKER_UA', 'WEB_TO_CLOUD_BUCKET', 'WEB_TO_CLOUD_C2_HOST', 'WEB_TO_CLOUD_C2_IP', 'WEB_TO_CLOUD_COMPROMISED_HOST', 'WEB_TO_CLOUD_COMPROMISED_PRIVATE_IP', 'WEB_TO_CLOUD_COMPROMISED_USER', 'WEB_TO_CLOUD_EXFIL_OBJECT', 'WEB_TO_CLOUD_REQUEST_URL', 'WEB_TO_CLOUD_TRACE_ID', 'WEB_TO_CLOUD_WINDOWS_HOST', 'WEB_TO_CLOUD_WINDOWS_PRIVATE_IP', 'WINDOWS_HOSTS', 'WINDOWS_USERS', 'add_windows_event_envelope', 'expand_events_over_days', 'iso_to_epoch_seconds', 'shift_event_window', 'shift_iso8601_utc', 'ts', 'windows_guid', 'write_jsonl']
