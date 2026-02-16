"""
Create custom OCI Log Analytics fields, parsers, and log sources for SOC detections.

This script sets up the Log Analytics content required for detection rules to work:
  - Custom fields (Command Line, Process Name, Problem Name, etc.)
  - JSON parsers that map NDJSON test data fields to OCI LA fields
  - SOC custom log sources that reference those parsers (only when needed)

Log sources created:
  - SOC Linux Syslog Logs       (parses linux_syslog.jsonl)
  - SOC Windows Sysmon Logs     (parses windows_sysmon.jsonl)
  - SOC Cloud Guard Logs        (parses cloud_guard.jsonl)

Native OCI sources are preferred when available (for example `OCI Cloud Guard Problems`
or `Windows Sysmon Events`). SOC custom sources are created only when an equivalent
native source is not present.

Prerequisites:
  1. OCI CLI configured (~/.oci/config)
  2. Log Analytics service enabled in the tenancy

Usage:
  python3 scripts/setup_log_sources.py          # Create all content
  python3 scripts/setup_log_sources.py --dry-run # Print plan only
"""

import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from oci_config import (
    TENANCY_ID, COMPARTMENT_ID,
    get_la_client, get_namespace, validate_oci_setup,
    list_available_log_sources,
)

import oci
from oci.log_analytics.models import (
    LogAnalyticsField,
    LogAnalyticsParserField,
    UpsertLogAnalyticsFieldDetails,
    UpsertLogAnalyticsParserDetails,
)


# ─── Field Definitions ──────────────────────────────────────────

CUSTOM_FIELDS = [
    "Command Line",
    "Process Name",
    "Parent Process Name",
    "Parent Command Line",
    "Original File Name",
    "Event ID",
    "Host Name",
    "Problem Name",
    "Problem ID",
    "Risk Level",
    "Risk Score",
    "Lifecycle State",
    "Detector Rule ID",
    "Resource Type",
    "Resource ID",
    "Resource Name",
    "Region",
    "Utc Time",
    "Process Guid",
    "Parent Process Guid",
    "Parent Process ID",
    "Current Directory",
    "Company",
    "Product",
    "Description",
    "Logon Guid",
    "Facility",
    "Severity Level",
    "Process ID",
    # Additional fields for multicloudoperations widget compatibility
    "Host Name (Server)",
    "Source Address",
    "Logon Type",
    "Endpoint OS",
    "Source Process",
    "Target Process",
    "Destination Hostname",
    "Destination IP",
    "Destination Port",
    "Query Name",
    "Query Results",
    "Pipe Name",
    "Target Filename",
    "Granted Access",
    "Source IP",
    "Auth Method",
    "Session Type",
    "Service Name",
    "Process",
]


# ─── Linux Syslog Parser ────────────────────────────────────────

LINUX_PARSER_NAME = "socLinuxSyslogJsonParser"
LINUX_PARSER_DISPLAY = "SOC Linux Syslog JSON Parser"
LINUX_PARSER_DESC = (
    "Parses Linux syslog/auth JSON events for SOC detection rules. "
    "Maps msg, Process, Hostname, PID, Facility, Severity fields."
)
LINUX_FIELD_MAPPINGS = [
    # (display_name_or_builtin, json_path, sequence)
    ("msg",              "$.msg",        1),
    ("time",             "$.Timestamp",  2),
    ("Process Name",     "$.Process",    3),
    ("Host Name",        "$.Hostname",   4),
    ("Process ID",       "$.PID",        5),
    ("Facility",         "$.Facility",   6),
    ("Severity Level",   "$.Severity",   7),
    ("User",             "$.User",       8),
    ("Source IP",        "$.SourceIP",   9),
    ("Auth Method",      "$.AuthMethod", 10),
    ("Session Type",     "$.SessionType", 11),
]
LINUX_EXAMPLE = {
    "Timestamp": "2026-02-10T10:30:00.000Z",
    "Hostname": "web-prod-01",
    "Process": "sshd",
    "PID": 12345,
    "Facility": "auth",
    "Severity": "info",
    "User": "admin",
    "SourceIP": "45.33.32.156",
    "AuthMethod": "password",
    "SessionType": "ssh",
    "msg": "Failed password for admin from 45.33.32.156 port 54321 ssh2",
}

LINUX_SOURCE_INTERNAL = "socLinuxSyslogSource"
LINUX_SOURCE_DISPLAY = "SOC Linux Syslog Logs"
LINUX_SOURCE_DESC = (
    "Linux syslog and auth log events in JSON format for SOC detection rules."
)


# ─── Windows Sysmon Parser ──────────────────────────────────────

WINDOWS_PARSER_NAME = "socWindowsSysmonJsonParser"
WINDOWS_PARSER_DISPLAY = "SOC Windows Sysmon JSON Parser"
WINDOWS_PARSER_DESC = (
    "Parses Windows Sysmon JSON events for SOC detection rules. "
    "Maps core Sysmon Event 1 process fields and parent context."
)
WINDOWS_FIELD_MAPPINGS = [
    ("msg",                  "$.CommandLine",       1),
    ("time",                 "$.TimeCreated",       2),
    ("Utc Time",             "$.UtcTime",           3),
    ("Event ID",             "$.EventID",           4),
    ("Process ID",           "$.ProcessId",         5),
    ("Process Name",         "$.Image",             6),
    ("Command Line",         "$.CommandLine",       7),
    ("Current Directory",    "$.CurrentDirectory",  8),
    ("Parent Process Name",  "$.ParentImage",       9),
    ("Parent Command Line",  "$.ParentCommandLine", 10),
    ("Parent Process ID",    "$.ParentProcessId",   11),
    ("Original File Name",   "$.OriginalFileName",  12),
    ("Hashes",               "$.Hashes",            13),
    ("Logon ID",             "$.LogonId",           14),
    ("Logon Guid",           "$.LogonGuid",         15),
    ("Integrity Level",      "$.IntegrityLevel",    16),
    ("Process Guid",         "$.ProcessGuid",       17),
    ("Parent Process Guid",  "$.ParentProcessGuid", 18),
    ("Company",              "$.Company",           19),
    ("Product",              "$.Product",           20),
    ("Description",          "$.Description",       21),
    ("Host Name",            "$.Computer",          22),
    ("User",                 "$.User",              23),
    ("Channel",              "$.Channel",           24),
    ("Provider",             "$.Provider",          25),
]
WINDOWS_EXAMPLE = {
    "EventID": 1,
    "TimeCreated": "2026-02-10T10:30:00.000Z",
    "UtcTime": "2026-02-10T10:30:00.000Z",
    "Computer": "WS01.corp.local",
    "Channel": "Microsoft-Windows-Sysmon/Operational",
    "Provider": "Microsoft-Windows-Sysmon",
    "User": "CORP\\admin",
    "ProcessId": 2048,
    "ProcessGuid": "{AABBCCDD-1111-2222-3333-444455556666}",
    "Image": "C:\\Windows\\System32\\powershell.exe",
    "CommandLine": "powershell.exe -enc SQBFAFgA",
    "CurrentDirectory": "C:\\Windows\\System32\\",
    "Hashes": "SHA1=E4A1...,MD5=11AA...,SHA256=2F9D...",
    "LogonGuid": "{12345678-1111-2222-3333-ABCDEF123456}",
    "LogonId": "0x3e7",
    "IntegrityLevel": "High",
    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
    "ParentCommandLine": "cmd.exe /c powershell.exe -enc SQBFAFgA",
    "ParentProcessGuid": "{FFEEDDCC-AAAA-BBBB-CCCC-DDDDEEEEFFFF}",
    "ParentProcessId": 1024,
    "OriginalFileName": "powershell.exe",
    "Company": "Microsoft Corporation",
    "Product": "Microsoft Windows Operating System",
    "Description": "Windows PowerShell",
}

WINDOWS_SOURCE_INTERNAL = "socWindowsSysmonSource"
WINDOWS_SOURCE_DISPLAY = "SOC Windows Sysmon Logs"
WINDOWS_SOURCE_DESC = (
    "Windows Sysmon process creation events in JSON format for SOC detection rules."
)


# ─── Cloud Guard Parser ─────────────────────────────────────────

CG_PARSER_NAME = "socCloudGuardJsonParser"
CG_PARSER_DISPLAY = "SOC Cloud Guard JSON Parser"
CG_PARSER_DESC = (
    "Parses OCI Cloud Guard problem events (ProblemSummary-style JSON) for SOC detections."
)
CG_FIELD_MAPPINGS = [
    ("msg",              "$.problemName",        1),
    ("time",             "$.timeFirstDetected",  2),
    ("Problem Name",     "$.problemName",        3),
    ("Problem ID",       "$.id",                 4),
    ("Risk Level",       "$.riskLevel",          5),
    ("Risk Score",       "$.riskScore",          6),
    ("Resource Type",    "$.resourceType",       7),
    ("Resource ID",      "$.resourceId",         8),
    ("Resource Name",    "$.resourceName",       9),
    ("Host Name",        "$.resourceName",       10),
    ("Detector ID",      "$.detectorId",         11),
    ("Detector Rule ID", "$.detectorRuleId",     12),
    ("Region",           "$.region",             13),
    ("Lifecycle State",  "$.lifecycleState",     14),
]
CG_EXAMPLE = {
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "compartmentId": COMPARTMENT_ID,
    "problemName": "BUCKET_IS_PUBLIC_READ",
    "resourceType": "Bucket",
    "resourceId": "ocid1.bucket.oc1..aaaaaaaaexample",
    "resourceName": "test-bucket-42",
    "riskLevel": "HIGH",
    "riskScore": 83,
    "detectorId": "ACTIVITY_DETECTOR",
    "detectorRuleId": "ocid1.cloudguarddetectorrecipe.oc1..aaaaaaaaexample",
    "region": "us-phoenix-1",
    "timeFirstDetected": "2026-02-10T10:30:00.000Z",
    "timeLastDetected": "2026-02-10T10:30:01.000Z",
    "lifecycleState": "ACTIVE",
}

CG_SOURCE_INTERNAL = "socCloudGuardSource"
CG_SOURCE_DISPLAY = "SOC Cloud Guard Logs"
CG_SOURCE_DESC = (
    "OCI Cloud Guard problem detection events in JSON format for SOC detection rules."
)


# ─── Windows Event Security Parser (multicloudoperations compat) ─

WINSEC_PARSER_NAME = "socWinEventSecurityJsonParser"
WINSEC_PARSER_DISPLAY = "SOC Windows Event Security JSON Parser"
WINSEC_PARSER_DESC = (
    "Parses Windows Security Event Log JSON for multicloudoperations widgets. "
    "Maps Event ID, User, Host Name (Server), Source Address, Logon Type."
)
WINSEC_FIELD_MAPPINGS = [
    ("msg",                  "$.msg",              1),
    ("time",                 "$.TimeCreated",      2),
    ("Event ID",             "$.EventID",          3),
    ("User",                 "$.User",             4),
    ("Host Name (Server)",   "$.Computer",         5),
    ("Source Address",       "$.SourceAddress",     6),
    ("Logon Type",           "$.LogonType",        7),
    ("Process Name",         "$.ProcessName",      8),
    ("Host Name",            "$.Computer",         9),
    ("Process",              "$.ProcessName",     10),
]
WINSEC_EXAMPLE = {
    "EventID": "4625",
    "TimeCreated": "2026-02-11T10:30:00.000Z",
    "Computer": "DC01.sevenkingdoms.local",
    "Channel": "Security",
    "Provider": "Microsoft-Windows-Security-Auditing",
    "User": "joffrey",
    "SourceAddress": "192.168.1.50",
    "LogonType": "10",
    "ProcessName": "C:\\Windows\\System32\\svchost.exe",
    "msg": "An account failed to log on.",
}

WINSEC_SOURCE_INTERNAL = "socWinEventSecuritySource"
WINSEC_SOURCE_DISPLAY = "Windows Event Security Logs"
WINSEC_SOURCE_DESC = (
    "Windows Security Event Log events in JSON format for SOC and multicloud widgets."
)


# ─── Windows Event System Parser (multicloudoperations compat) ───

WINSYS_PARSER_NAME = "socWinEventSystemJsonParser"
WINSYS_PARSER_DISPLAY = "SOC Windows Event System JSON Parser"
WINSYS_PARSER_DESC = (
    "Parses Windows System Event Log JSON for multicloudoperations widgets. "
    "Maps Event ID, Host Name (Server), Service Name."
)
WINSYS_FIELD_MAPPINGS = [
    ("msg",                  "$.msg",              1),
    ("time",                 "$.TimeCreated",      2),
    ("Event ID",             "$.EventID",          3),
    ("Host Name (Server)",   "$.Computer",         4),
    ("Host Name",            "$.Computer",         5),
    ("Service Name",         "$.ServiceName",      6),
    ("User",                 "$.User",             7),
]
WINSYS_EXAMPLE = {
    "EventID": "7045",
    "TimeCreated": "2026-02-11T10:30:00.000Z",
    "Computer": "SRV01.sevenkingdoms.local",
    "Channel": "System",
    "Provider": "Service Control Manager",
    "ServiceName": "backdoor_svc",
    "User": "SYSTEM",
    "msg": "A service was installed in the system.",
}

WINSYS_SOURCE_INTERNAL = "socWinEventSystemSource"
WINSYS_SOURCE_DISPLAY = "Windows Event System Logs"
WINSYS_SOURCE_DESC = (
    "Windows System Event Log events in JSON format for SOC and multicloud widgets."
)


# ─── Linux Secure Parser (multicloudoperations compat) ───────────

LINSEC_PARSER_NAME = "socLinuxSecureJsonParser"
LINSEC_PARSER_DISPLAY = "SOC Linux Secure JSON Parser"
LINSEC_PARSER_DESC = (
    "Parses Linux auth/secure log JSON for multicloudoperations widgets. "
    "Maps Process, User, Source IP, Host Name (Server), Auth Method."
)
LINSEC_FIELD_MAPPINGS = [
    ("msg",                  "$.msg",              1),
    ("time",                 "$.Timestamp",        2),
    ("Process",              "$.Process",          3),
    ("Process Name",         "$.Process",          4),
    ("User",                 "$.User",             5),
    ("Host Name (Server)",   "$.Hostname",         6),
    ("Host Name",            "$.Hostname",         7),
    ("Source Address",       "$.SourceIP",         8),
    ("Source IP",            "$.SourceIP",         9),
    ("Auth Method",          "$.AuthMethod",      10),
    ("Process ID",           "$.PID",             11),
    ("Facility",             "$.Facility",        12),
    ("Severity Level",       "$.Severity",        13),
    ("Endpoint OS",          "$.EndpointOS",      14),
]
LINSEC_EXAMPLE = {
    "EndpointOS": "Linux",
    "Timestamp": "2026-02-11T10:30:00.000Z",
    "Hostname": "web-prod-01",
    "Process": "sshd",
    "PID": 12345,
    "Facility": "auth",
    "Severity": "info",
    "msg": "Failed password for admin from 45.33.32.156 port 54321 ssh2",
    "SourceIP": "45.33.32.156",
    "User": "admin",
    "AuthMethod": "password",
    "SessionType": "ssh",
}

LINSEC_SOURCE_INTERNAL = "socLinuxSecureSource"
LINSEC_SOURCE_DISPLAY = "Linux Secure Logs"
LINSEC_SOURCE_DESC = (
    "Linux auth/secure log events in JSON format for SOC and multicloud widgets."
)


# ─── Windows Sysmon Operational Parser (multicloudoperations) ────

SYSMON_PARSER_NAME = "socSysmonOperationalJsonParser"
SYSMON_PARSER_DISPLAY = "SOC Sysmon Operational JSON Parser"
SYSMON_PARSER_DESC = (
    "Parses Windows Sysmon Operational JSON for multicloudoperations widgets. "
    "Maps Sysmon fields: SourceImage, TargetImage, DestinationIp, QueryName."
)
SYSMON_FIELD_MAPPINGS = [
    ("msg",                  "$.msg",                  1),
    ("time",                 "$.TimeCreated",           2),
    ("Event ID",             "$.EventID",               3),
    ("Host Name (Server)",   "$.Computer",              4),
    ("Host Name",            "$.Computer",              5),
    ("User",                 "$.User",                  6),
    ("Source Process",       "$.SourceImage",           7),
    ("Target Process",       "$.TargetImage",           8),
    ("Endpoint OS",          "$.EndpointOS",            9),
    ("Destination Hostname", "$.DestinationHostname",  10),
    ("Destination IP",       "$.DestinationIp",        11),
    ("Destination Port",     "$.DestinationPort",      12),
    ("Query Name",           "$.QueryName",            13),
    ("Query Results",        "$.QueryResults",         14),
    ("Pipe Name",            "$.PipeName",             15),
    ("Target Filename",      "$.TargetFilename",       16),
    ("Granted Access",       "$.GrantedAccess",        17),
    ("Process Name",         "$.SourceImage",          18),
    ("Command Line",         "$.CommandLine",          19),
]
SYSMON_EXAMPLE = {
    "EndpointOS": "Windows",
    "EventID": 1,
    "TimeCreated": "2026-02-11T10:30:00.000Z",
    "Computer": "WS01.sevenkingdoms.local",
    "Channel": "Microsoft-Windows-Sysmon/Operational",
    "Provider": "Microsoft-Windows-Sysmon",
    "User": "joffrey",
    "SourceImage": "C:\\Windows\\System32\\cmd.exe",
    "TargetImage": "C:\\Windows\\System32\\lsass.exe",
    "CommandLine": "cmd.exe /c whoami",
    "DestinationHostname": "evil-c2.duckdns.org",
    "DestinationIp": "185.215.113.206",
    "DestinationPort": 443,
    "QueryName": "evil-c2.duckdns.org",
    "QueryResults": "185.215.113.206",
    "PipeName": "",
    "TargetFilename": "",
    "GrantedAccess": "0x1010",
    "msg": "Process Create: cmd.exe /c whoami",
}

SYSMON_SOURCE_INTERNAL = "socSysmonOperationalSource"
SYSMON_SOURCE_DISPLAY = "Windows Sysmon Operational Logs"
SYSMON_SOURCE_DESC = (
    "Windows Sysmon operational events in JSON format for SOC and multicloud widgets."
)

# Native source alternatives used to avoid creating unnecessary SOC sources.
# If a SOC source already exists, it is still retained/updated for compatibility.
NATIVE_SOURCE_ALTERNATIVES = {
    CG_SOURCE_DISPLAY: ["OCI Cloud Guard Problems", "OCI Cloud Guard Logs"],
    WINDOWS_SOURCE_DISPLAY: ["Windows Sysmon Events", "Windows Sysmon Operational Logs"],
    LINUX_SOURCE_DISPLAY: [],
    WINSEC_SOURCE_DISPLAY: [],
    WINSYS_SOURCE_DISPLAY: [],
    LINSEC_SOURCE_DISPLAY: [],
    SYSMON_SOURCE_DISPLAY: [],
}


# ─── Helper Functions ────────────────────────────────────────────

def build_existing_field_map(client, namespace):
    """Fetch all existing fields and return display_name -> internal_name map."""
    result = {}
    page = None
    while True:
        kwargs = {"limit": 1000}
        if page:
            kwargs["page"] = page
        resp = client.list_fields(namespace, **kwargs)
        for f in resp.data.items:
            if f.display_name:
                result[f.display_name] = f.name
        page = resp.headers.get("opc-next-page")
        if not page:
            break
    return result


def create_fields(client, namespace, field_display_names):
    """Create or upsert custom fields. Returns display_name -> internal_name map."""
    existing = build_existing_field_map(client, namespace)
    field_map = {}

    for display_name in field_display_names:
        if display_name in existing:
            field_map[display_name] = existing[display_name]
            print(f"  Field EXISTS {existing[display_name]:20s} -> {display_name}")
            continue

        details = UpsertLogAnalyticsFieldDetails()
        details.display_name = display_name
        details.data_type = "String"
        details.is_multi_valued = False
        try:
            resp = client.upsert_field(namespace, details)
            field_map[display_name] = resp.data.name
            print(f"  Field OK     {resp.data.name:20s} -> {display_name}")
        except oci.exceptions.ServiceError as exc:
            print(f"  Field ERR    {display_name}: {exc.message}")

    return field_map


def create_parser(client, namespace, parser_name, display_name, description,
                  field_mappings, field_map, example_log):
    """Create or upsert a JSON parser with field mappings."""
    parser_field_maps = []
    for name_or_display, json_path, seq in field_mappings:
        internal = field_map.get(name_or_display, name_or_display)
        parser_field_maps.append(
            LogAnalyticsParserField(
                field=LogAnalyticsField(name=internal),
                parser_field_name=internal,
                parser_field_sequence=seq,
                storage_field_name=internal,
                structured_column_info=json_path,
            )
        )

    example_content = json.dumps(example_log, indent=2)

    parser_details = UpsertLogAnalyticsParserDetails(
        name=parser_name,
        display_name=display_name,
        description=description,
        type="JSON",
        language="en_US",
        encoding="UTF-8",
        is_default=True,
        is_single_line_content=False,
        is_system=False,
        header_content="$:0",
        content=example_content,
        example_content=example_content,
        field_maps=parser_field_maps,
    )

    etag = None
    try:
        existing = client.get_parser(namespace, parser_name)
        etag = existing.headers.get("etag")
    except oci.exceptions.ServiceError:
        pass

    kwargs = {"if_match": etag} if etag else {}
    result = client.upsert_parser(namespace, parser_details, **kwargs)
    print(f"  Parser OK: {result.data.name} ({len(result.data.field_maps)} field maps)")


def create_source(client, namespace, compartment_id, source_internal_name,
                  source_display_name, source_description, parser_name):
    """Create a Log Analytics source referencing a parser (via OCI CLI)."""
    try:
        existing = client.list_sources(
            namespace, compartment_id,
            name=source_display_name, is_system="ALL",
        )
        if existing.data.items:
            src = existing.data.items[0]
            print(f"  Source EXISTS: {src.name} (display={src.display_name})")
            return
    except Exception:
        pass

    parsers_json = json.dumps([{"name": parser_name, "isDefault": True}])
    entity_types_json = json.dumps(
        [{"entityType": "oci_generic_resource",
          "entityTypeCategory": "Undefined",
          "entityTypeDisplayName": "OCI Generic Resource"}]
    )

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as pf:
        pf.write(parsers_json)
        parsers_path = pf.name
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as ef:
        ef.write(entity_types_json)
        entity_path = ef.name

    try:
        cmd = [
            "oci", "log-analytics", "source", "upsert-source",
            "--namespace-name", namespace,
            "--name", source_internal_name,
            "--display-name", source_display_name,
            "--description", source_description,
            "--type-name", "os_file",
            "--is-system", "false",
            "--is-for-cloud", "false",
            "--parsers", f"file://{parsers_path}",
            "--entity-types", f"file://{entity_path}",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"  Source OK: {source_display_name}")
        else:
            stderr = result.stderr.strip()
            if "already exists" in stderr.lower():
                print(f"  Source EXISTS: {source_display_name}")
            else:
                print(f"  Source WARN: {stderr[:300]}")
    finally:
        os.unlink(parsers_path)
        os.unlink(entity_path)


def should_skip_custom_source_creation(available_sources, source_display_name):
    """Return (bool, reason) when a custom source should not be created."""
    if source_display_name in available_sources:
        return False, ""

    alternatives = NATIVE_SOURCE_ALTERNATIVES.get(source_display_name, [])
    for native_name in alternatives:
        if native_name in available_sources:
            return True, f"native source '{native_name}' already exists"
    return False, ""


# ─── Main ────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Set up custom OCI LA log sources for SOC detections")
    parser.add_argument("--dry-run", action="store_true", help="Print plan without executing")
    parser.add_argument("--validate", action="store_true", help="Run pre-flight validation checks")
    args = parser.parse_args()

    if args.validate:
        ok = validate_oci_setup(['ocid', 'cli', 'namespace', 'compartment'])
        sys.exit(0 if ok else 1)

    if args.dry_run:
        print("DRY RUN - would create:")
        print(f"  {len(CUSTOM_FIELDS)} custom fields")
        print(f"  7 JSON parsers")
        print(f"  up to 7 log sources (SOC sources skipped when native equivalent exists):")
        print(f"    - {LINUX_SOURCE_DISPLAY} ({LINUX_SOURCE_INTERNAL})")
        print(f"    - {WINDOWS_SOURCE_DISPLAY} ({WINDOWS_SOURCE_INTERNAL})")
        print(f"    - {CG_SOURCE_DISPLAY} ({CG_SOURCE_INTERNAL})")
        print(f"    - {WINSEC_SOURCE_DISPLAY} ({WINSEC_SOURCE_INTERNAL})")
        print(f"    - {WINSYS_SOURCE_DISPLAY} ({WINSYS_SOURCE_INTERNAL})")
        print(f"    - {LINSEC_SOURCE_DISPLAY} ({LINSEC_SOURCE_INTERNAL})")
        print(f"    - {SYSMON_SOURCE_DISPLAY} ({SYSMON_SOURCE_INTERNAL})")
        return

    la_client = get_la_client()

    # Get namespace
    namespace = get_namespace(la_client)
    print(f"Compartment: {COMPARTMENT_ID}")
    available_sources = list_available_log_sources(la_client, namespace, COMPARTMENT_ID)
    print(f"Discovered {len(available_sources)} existing log sources")

    # Step 1: Create custom fields
    print("\n" + "=" * 60)
    print("STEP 1: CREATE CUSTOM FIELDS")
    print("=" * 60)
    field_map = create_fields(la_client, namespace, CUSTOM_FIELDS)

    # Also load ALL existing fields (including built-in) for parser creation
    all_fields = build_existing_field_map(la_client, namespace)
    field_map.update(all_fields)
    print(f"\n  Total fields available for parser mapping: {len(field_map)}")

    # Step 2: Create parsers
    print("\n" + "=" * 60)
    print("STEP 2: CREATE JSON PARSERS")
    print("=" * 60)

    print("\n--- Linux Syslog Parser ---")
    create_parser(la_client, namespace,
                  LINUX_PARSER_NAME, LINUX_PARSER_DISPLAY, LINUX_PARSER_DESC,
                  LINUX_FIELD_MAPPINGS, field_map, LINUX_EXAMPLE)

    print("\n--- Windows Sysmon Parser ---")
    create_parser(la_client, namespace,
                  WINDOWS_PARSER_NAME, WINDOWS_PARSER_DISPLAY, WINDOWS_PARSER_DESC,
                  WINDOWS_FIELD_MAPPINGS, field_map, WINDOWS_EXAMPLE)

    print("\n--- Cloud Guard Parser ---")
    create_parser(la_client, namespace,
                  CG_PARSER_NAME, CG_PARSER_DISPLAY, CG_PARSER_DESC,
                  CG_FIELD_MAPPINGS, field_map, CG_EXAMPLE)

    print("\n--- Windows Event Security Parser ---")
    create_parser(la_client, namespace,
                  WINSEC_PARSER_NAME, WINSEC_PARSER_DISPLAY, WINSEC_PARSER_DESC,
                  WINSEC_FIELD_MAPPINGS, field_map, WINSEC_EXAMPLE)

    print("\n--- Windows Event System Parser ---")
    create_parser(la_client, namespace,
                  WINSYS_PARSER_NAME, WINSYS_PARSER_DISPLAY, WINSYS_PARSER_DESC,
                  WINSYS_FIELD_MAPPINGS, field_map, WINSYS_EXAMPLE)

    print("\n--- Linux Secure Parser ---")
    create_parser(la_client, namespace,
                  LINSEC_PARSER_NAME, LINSEC_PARSER_DISPLAY, LINSEC_PARSER_DESC,
                  LINSEC_FIELD_MAPPINGS, field_map, LINSEC_EXAMPLE)

    print("\n--- Sysmon Operational Parser ---")
    create_parser(la_client, namespace,
                  SYSMON_PARSER_NAME, SYSMON_PARSER_DISPLAY, SYSMON_PARSER_DESC,
                  SYSMON_FIELD_MAPPINGS, field_map, SYSMON_EXAMPLE)

    # Step 3: Create log sources
    print("\n" + "=" * 60)
    print("STEP 3: CREATE LOG SOURCES")
    print("=" * 60)

    def create_source_if_needed(source_internal, source_display, source_desc, parser_name):
        skip, reason = should_skip_custom_source_creation(available_sources, source_display)
        if skip:
            print(f"  Source SKIP: {source_display} ({reason})")
            return
        create_source(
            la_client, namespace, COMPARTMENT_ID,
            source_internal, source_display, source_desc, parser_name
        )
        available_sources.add(source_display)

    print("\n--- Linux Source ---")
    create_source_if_needed(
        LINUX_SOURCE_INTERNAL, LINUX_SOURCE_DISPLAY, LINUX_SOURCE_DESC, LINUX_PARSER_NAME
    )

    print("\n--- Windows Sysmon Source ---")
    create_source_if_needed(
        WINDOWS_SOURCE_INTERNAL, WINDOWS_SOURCE_DISPLAY, WINDOWS_SOURCE_DESC, WINDOWS_PARSER_NAME
    )

    print("\n--- Cloud Guard Source ---")
    create_source_if_needed(
        CG_SOURCE_INTERNAL, CG_SOURCE_DISPLAY, CG_SOURCE_DESC, CG_PARSER_NAME
    )

    print("\n--- Windows Event Security Source ---")
    create_source_if_needed(
        WINSEC_SOURCE_INTERNAL, WINSEC_SOURCE_DISPLAY, WINSEC_SOURCE_DESC, WINSEC_PARSER_NAME
    )

    print("\n--- Windows Event System Source ---")
    create_source_if_needed(
        WINSYS_SOURCE_INTERNAL, WINSYS_SOURCE_DISPLAY, WINSYS_SOURCE_DESC, WINSYS_PARSER_NAME
    )

    print("\n--- Linux Secure Source ---")
    create_source_if_needed(
        LINSEC_SOURCE_INTERNAL, LINSEC_SOURCE_DISPLAY, LINSEC_SOURCE_DESC, LINSEC_PARSER_NAME
    )

    print("\n--- Sysmon Operational Source ---")
    create_source_if_needed(
        SYSMON_SOURCE_INTERNAL, SYSMON_SOURCE_DISPLAY, SYSMON_SOURCE_DESC, SYSMON_PARSER_NAME
    )

    print("\n" + "=" * 60)
    print("SETUP COMPLETE")
    print("=" * 60)
    print(f"\nConfigured log sources/parsers:")
    print(f"  - {LINUX_SOURCE_DISPLAY}")
    print(f"  - {WINDOWS_SOURCE_DISPLAY}")
    print(f"  - {CG_SOURCE_DISPLAY}")
    print(f"  - {WINSEC_SOURCE_DISPLAY}")
    print(f"  - {WINSYS_SOURCE_DISPLAY}")
    print(f"  - {LINSEC_SOURCE_DISPLAY}")
    print(f"  - {SYSMON_SOURCE_DISPLAY}")
    print(f"  - OCI Audit Logs (built-in)")
    print(f"  - OCI Cloud Guard Problems (native, preferred when available)")
    print(f"  - Windows Sysmon Events (native, preferred when available)")
    print(f"\nNext: python3 scripts/convert_sigma.py")


if __name__ == "__main__":
    main()
