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
  - SOC Application Logs        (parses application_logs.jsonl)

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
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from oci_config import (
    TENANCY_ID, COMPARTMENT_ID, OCI_PROFILE,
    get_la_client, get_namespace, validate_oci_setup,
    list_available_log_sources,
    resolve_compartment_id,
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
    "Logon ID",
    "Logon Guid",
    "Integrity Level",
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
    "Target Object",
    "Granted Access",
    "Source IP",
    "Source Port",
    "Auth Method",
    "Session Type",
    "Service Name",
    "Process",
    "Service",
    "Severity",
    "Original Log Content",
    # Windows Security advanced auth fields (Kerberos / privilege / explicit-creds events)
    # Required by detections: golden_ticket_*, kerberoasting_*, pass-the-ticket_*,
    # privilege_escalation_sensitive_privileges_assigned_to_non-admin, dcsync_*
    "Subject User Name",
    "Target User Name",
    "Target Domain Name",
    "Ticket Encryption Type",
    "Ticket Options",
    "Privilege List",
    "Target Server Name",
    "Service Information",
    "Object Server",
    "Object Type",
    "Properties",
    # Sysmon Network / MITRE fields
    "Account Name",
    "RuleName",
    "Technique Name",
    "Technique ID",
    "Protocol",
    "Initiated",
    "Event Channel",
    # Sysmon process / Cloud Guard fields
    "Hashes",
    "Detector ID",
    # WAF / Web Application fields
    "Action",
    "HTTP Method",
    "HTTP Request Method",
    "Request URL",
    "URI Path",
    "Query String",
    "Client IP",
    "Country Code",
    "User Agent",
    "Response Code",
    "Rule Type",
    "Rule Key",
    "Rule Action",
    "WAF Action",
    "Request Body",
    "Content Type",
    "Referrer",
    "Request Headers",
    "WAF Policy",
    "Threat Feeds",
    "Fingerprint",
    "Response Headers",
    "WAF Score",
    # Load Balancer fields
    "Backend Address",
    "Backend Status Code",
    "Bytes Received",
    "Bytes Sent",
    "Request Processing Time",
    "Load Balancer Name",
    "Listener Name",
    "Backend Name",
    # Web Application fields
    "Application Name",
    "Attack Type",
    "Attack Payload",
    "Vulnerability ID",
    "Session ID",
    "OWASP Category",
    "Request ID",
    "Trace ID",
    "Trace Parent",
    "Span Name",
    "Span Attributes",
    "Span ID",
    "Parent Span ID",
    "Span Kind",
    "APM Domain",
    "Service Namespace",
    "Service Version",
    "Service Instance ID",
    "Deployment Environment",
    "App Name",
    "App Brand",
    "App Runtime",
    "App Service",
    "Workflow ID",
    "Workflow Step",
    "Correlation ID",
    "Run ID",
    "Metric Name",
    "Metric Value",
    "Metric Unit",
    "DB Target",
    "DB Statement",
    "DB Elapsed ms",
    "DB Connection Name",
    "DB OCID",
    "Error Type",
    "Slow Request",
    "URL Path",
    "HTTP Status Code",
    "Java APM Path",
    "Java APM Status Code",
    "Java APM Latency ms",
    "Java APM Error Type",
    "Attack ID",
    "Attack Stage",
    "Attack Entry Point",
    "LOTL Binary",
    "Security Severity",
    "MITRE Tactic",
    "MITRE Technique ID",
    "MITRE Technique",
    "Server Address",
    "Network Protocol",
    "OSQuery Query",
    "OSQuery Finding",
    "OSQuery SQL",
    "OSQuery Result Count",
    "Instance OCID",
    "Host Role",
    "Compromised VM",
    "Process Name",
    "Process Command Line",
    "File Path",
    "Payment Provider",
    "Payment Status",
    "Payment Gateway Request ID",
    "Payment Network",
    "Payment Wallet Token Hash",
    "Payment Risk Score",
    "Payment Card Last4",
    "Order ID",
    "Source Order ID",
    "Gateway",
    "Provider",
    "Version",
    "Step Id",
    "Process Phase",
    "Event Status",
    "Elapsed Time (Gateway)",
    "Request Type",
    "Authorization Scheme",
    "Method",
    "ORDER_AMOUNT",
    "BillingCurrency",
    "Gateway ID",
    "Transaction ID",
    "Result",
    "Security Result",
    "Program",
    "Flow Code",
    "Flow",
    "Downstream Component",
    "Payment Interception",
    "Payment Redirect",
    "Payment Redirect URL",
    "HTTP Redirect Location",
    "Network Bytes Out",
    "User ID (hashed)",
    "Business ID",
    "API Gateway Name",
    "API Gateway Scope",
    "API Gateway Deployment ID",
    "API Gateway Route",
    "API Gateway Route ID",
    "API Gateway Route Family",
    "API Gateway Request ID",
    "API Gateway Action",
    "API Gateway Policy Decision",
    "API Gateway Latency ms",
    "API Gateway Rate Limit",
    "API Gateway Rate Remaining",
    "API Gateway Threat Signal",
    "Chaos Injected",
    "Chaos Scenario",
    "Chaos TTL Seconds",
    "Chaos Target",
    "Orders Sync Created",
    "Orders Sync Updated",
    "Orders Sync Failed",
    "Orders Sync Source",
    # Multicloud Health / Geographic fields
    "Cloud Provider",
    "Region Display",
    "Country",
    "Latitude",
    "Longitude",
    "Instance ID",
    "Instance Role",
    "Tier",
    "Operating System",
    "Instance Type",
    "Status",
    "Status Code",
    "CPU Percent",
    "Memory Percent",
    "Disk Percent",
    "Network In Mbps",
    "Network Out Mbps",
    "Uptime Hours",
    "Open Connections",
    "Response Time Ms",
    "Heartbeat Sequence",
    "IP Address",
    # OCI network telemetry fields
    "Flow ID",
    "Packets",
    "Network Action",
    "Log Type",
    "Firewall Rule",
    "Threat Name",
    "Threat Category",
    "Direction",
]


FIELD_DATA_TYPE_OVERRIDES = {
    "HTTP Status Code": "LONG",
    "Java APM Status Code": "LONG",
    "Java APM Latency ms": "LONG",
    "DB Elapsed ms": "LONG",
    "Destination Port": "LONG",
    "OSQuery Result Count": "LONG",
    "Payment Risk Score": "LONG",
    "Elapsed Time (Gateway)": "FLOAT",
    "ORDER_AMOUNT": "FLOAT",
    "Network Bytes Out": "LONG",
    "API Gateway Latency ms": "LONG",
    "API Gateway Rate Limit": "LONG",
    "API Gateway Rate Remaining": "LONG",
    "Chaos TTL Seconds": "LONG",
}


# Existing OCI fields with different display names can be useful, but parser
# mappings cannot safely substitute them unless saved searches are also updated
# to the reused display name. Keep these as audit-only rewrite candidates.
FIELD_REWRITE_REUSE_CANDIDATES = {
    "Service Name": ("Service",),
    "Severity Level": ("Severity",),
    "Host Name": ("Host Name (Server)",),
    "HTTP Request Method": ("HTTP Method",),
    "Response Code": ("HTTP Status Code", "Status Code"),
    "URL Path": ("URI Path",),
    "Source IP": ("Source Address",),
    "Process Command Line": ("Command Line",),
}

RESERVED_PARSER_FIELD_DISPLAY_NAMES = {
    "Original Log Content",
}


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
    ("Command Line",     "$.CommandLine", 12),
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
    ("Source Process",       "$.SourceImage",       26),
    ("Target Process",       "$.TargetImage",       27),
    ("Target Filename",      "$.TargetFilename",    28),
    ("Target Object",        "$.TargetObject",      29),
    ("Granted Access",       "$.GrantedAccess",     30),
    ("Pipe Name",            "$.PipeName",          31),
    ("Destination Hostname", "$.DestinationHostname", 32),
    ("Destination IP",       "$.DestinationIp",     33),
    ("Destination Port",     "$.DestinationPort",   34),
    ("Host Name (Server)",   "$.Computer",          35),
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
    ("msg",                     "$.msg",                    1),
    ("time",                    "$.TimeCreated",            2),
    ("Event ID",                "$.EventID",                3),
    ("User",                    "$.User",                   4),
    ("Host Name (Server)",      "$.Computer",               5),
    ("Source Address",          "$.SourceAddress",          6),
    ("Logon Type",              "$.LogonType",              7),
    ("Process Name",            "$.ProcessName",            8),
    ("Command Line",            "$.CommandLine",            9),
    ("Host Name",               "$.Computer",              10),
    ("Process",                 "$.ProcessName",           11),
    # Advanced auth/Kerberos/privilege fields. Synthetic generators emit
    # these as top-level JSON keys so detections for events 4648/4672/4768/
    # 4769/4770 (kerberoasting, golden ticket, pass-the-ticket, sensitive
    # privilege use) have searchable columns.
    ("Subject User Name",       "$.SubjectUserName",       12),
    ("Target User Name",        "$.TargetUserName",        13),
    ("Target Domain Name",      "$.TargetDomainName",      14),
    ("Ticket Encryption Type",  "$.TicketEncryptionType",  15),
    ("Ticket Options",          "$.TicketOptions",         16),
    ("Privilege List",          "$.PrivilegeList",         17),
    ("Target Server Name",      "$.TargetServerName",      18),
    ("Service Information",     "$.ServiceInformation",    19),
    ("Service Name",            "$.ServiceName",           20),
    # DCSync (event 4662): Properties holds the AD attribute GUIDs being replicated.
    ("Object Server",           "$.ObjectServer",          21),
    ("Object Type",             "$.ObjectType",            22),
    ("Properties",              "$.Properties",            23),
]
WINSEC_EXAMPLE = {
    "EventID": "4769",
    "TimeCreated": "2026-02-11T10:30:00.000Z",
    "Computer": "DC01.sevenkingdoms.local",
    "Channel": "Security",
    "Provider": "Microsoft-Windows-Security-Auditing",
    "User": "joffrey",
    "SubjectUserName": "joffrey",
    "TargetUserName": "MSSQLSvc/sql01.sevenkingdoms.local",
    "TargetDomainName": "SEVENKINGDOMS",
    "ServiceName": "MSSQLSvc",
    "TicketEncryptionType": "0x17",
    "TicketOptions": "0x40810000",
    "PrivilegeList": "SeSecurityPrivilege",
    "TargetServerName": "sql01.sevenkingdoms.local",
    "ServiceInformation": "MSSQLSvc/sql01.sevenkingdoms.local",
    "SourceAddress": "192.168.1.50",
    "LogonType": "3",
    "ProcessName": "C:\\Windows\\System32\\lsass.exe",
    "CommandLine": "",
    "msg": "A Kerberos service ticket was requested.",
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
    ("Command Line",         "$.CommandLine",     15),
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
    ("Target Object",        "$.TargetObject",         20),
    ("Parent Process Name",  "$.ParentImage",          21),
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


# ─── Sysmon Network Connection Parser (Event ID 3) ───────────

SYSNET_PARSER_NAME = "socSysmonNetworkJsonParser"
SYSNET_PARSER_DISPLAY = "SOC Sysmon Network JSON Parser"
SYSNET_PARSER_DESC = (
    "Parses Windows Sysmon Event ID 3 (network connection) JSON. "
    "Maps Protocol, SourceIp, SourcePort, DestinationIp, DestinationPort, Image."
)
SYSNET_FIELD_MAPPINGS = [
    ("msg",                  "$.msg",               1),
    ("time",                 "$.@timestamp",         2),
    ("Event ID",             "$.EventID",            3),
    ("Host Name",            "$.Computer",           4),
    ("Process Name",         "$.Image",              5),
    ("Protocol",             "$.Protocol",           6),
    ("Destination IP",       "$.DestinationIp",      7),
    ("Destination Port",     "$.DestinationPort",    8),
    ("Source IP",            "$.SourceIp",           9),
    ("Source Port",          "$.SourcePort",        10),
    ("Initiated",            "$.Initiated",         11),
    ("Destination Hostname", "$.DestinationHostname", 12),
    ("User",                 "$.User",              13),
    ("Source Process",       "$.Image",             14),
    ("RuleName",             "$.RuleName",          15),
    ("Technique Name",       "$.TechniqueName",     16),
    ("Technique ID",         "$.TechniqueId",       17),
    ("Account Name",         "$.AccountName",       18),
    ("Event Channel",        "$.Channel",           19),
]
SYSNET_EXAMPLE = {
    "@timestamp": "2026-02-11T10:30:00.000Z",
    "EventID": 3,
    "Computer": "WS01.corp.local",
    "Channel": "Microsoft-Windows-Sysmon/Operational",
    "User": "CORP\\admin",
    "Image": "C:\\Windows\\System32\\cmd.exe",
    "Protocol": "tcp",
    "DestinationIp": "185.220.101.1",
    "DestinationPort": 443,
    "DestinationHostname": "evil-c2.example.com",
    "SourceIp": "10.0.1.50",
    "SourcePort": 54321,
    "Initiated": "true",
    "RuleName": "technique_id=T1071,technique_name=Application Layer Protocol",
    "TechniqueName": "Application Layer Protocol",
    "TechniqueId": "T1071",
    "AccountName": "admin",
    "msg": "Network connection detected: cmd.exe -> 185.220.101.1:443",
}

SYSNET_SOURCE_INTERNAL = "socSysmonNetworkSource"
SYSNET_SOURCE_DISPLAY = "SOC Sysmon Network Logs"
SYSNET_SOURCE_DESC = (
    "Windows Sysmon Event ID 3 (network connection) events in JSON format for SOC network detections."
)


# ─── OCI WAF Security Log Parser ──────────────────────────────

WAF_PARSER_NAME = "socWafSecurityJsonParser"
WAF_PARSER_DISPLAY = "SOC WAF Security JSON Parser"
WAF_PARSER_DESC = (
    "Parses OCI WAF security event JSON for OWASP attack detection. "
    "Maps action, request URL, HTTP method, client IP, user agent, rule details."
)
WAF_FIELD_MAPPINGS = [
    ("msg",                  "$.msg",                1),
    ("time",                 "$.timeCreated",        2),
    ("Action",               "$.action",             3),
    ("HTTP Method",          "$.httpMethod",         4),
    ("Request URL",          "$.requestUrl",         5),
    ("URI Path",             "$.requestUrl",         6),
    ("Query String",         "$.queryString",        7),
    ("Client IP",            "$.clientAddress",      8),
    ("Country Code",         "$.countryCode",        9),
    ("User Agent",           "$.userAgent",         10),
    ("Response Code",        "$.responseCode",      11),
    ("Rule Type",            "$.type",              12),
    ("Rule Key",             "$.protectionRuleKey", 13),
    ("Rule Action",          "$.protectionRuleAction", 14),
    ("Request Body",         "$.bodyData",          15),
    ("Content Type",         "$.contentType",       16),
    ("Referrer",             "$.referer",           17),
    ("Request Headers",      "$.requestHeaders",    18),
    ("WAF Policy",           "$.wafPolicy",         19),
    ("Fingerprint",          "$.fingerprint",       20),
    ("Host Name",            "$.hostname",          21),
    ("Trace ID",             "$.traceId",           22),
    ("Service Name",         "$.wafPolicy",         23),
    ("WAF Action",           "$.action",            24),
]
WAF_EXAMPLE = {
    "timeCreated": "2026-02-15T14:30:00.000Z",
    "action": "BLOCK",
    "httpMethod": "GET",
    "requestUrl": "/vulnerable/search?q=1' OR '1'='1",
    "queryString": "q=1' OR '1'='1",
    "clientAddress": "185.220.101.1",
    "countryCode": "RU",
    "userAgent": "sqlmap/1.7",
    "responseCode": "403",
    "type": "PROTECTION_RULES",
    "protectionRuleKey": "941100",
    "protectionRuleAction": "BLOCK",
    "bodyData": "",
    "contentType": "text/html",
    "referer": "",
    "requestHeaders": "Host: sevenkingdoms.example.com",
    "wafPolicy": "seven-kingdoms-portal-waf",
    "fingerprint": "abc123def456",
    "hostname": "sevenkingdoms.example.com",
    "msg": "WAF BLOCK: SQL Injection attempt in /vulnerable/search",
}

WAF_SOURCE_INTERNAL = "socWafSecuritySource"
WAF_SOURCE_DISPLAY = "SOC WAF Security Logs"
WAF_SOURCE_DESC = (
    "OCI WAF security events in JSON format for OWASP attack detection and threat hunting."
)


# ─── OCI Load Balancer Access Log Parser ──────────────────────

LB_PARSER_NAME = "socLbAccessJsonParser"
LB_PARSER_DISPLAY = "SOC Load Balancer Access JSON Parser"
LB_PARSER_DESC = (
    "Parses OCI Load Balancer access log JSON for web traffic analysis. "
    "Maps HTTP method, request URL, status code, client IP, user agent, timing."
)
LB_FIELD_MAPPINGS = [
    ("msg",                      "$.msg",                     1),
    ("time",                     "$.timeCreated",             2),
    ("HTTP Method",              "$.httpMethod",              3),
    ("Request URL",              "$.requestUrl",              4),
    ("URI Path",                 "$.uriPath",                 5),
    ("Query String",             "$.queryString",             6),
    ("Client IP",                "$.clientAddress",           7),
    ("User Agent",               "$.userAgent",               8),
    ("Response Code",            "$.statusCode",              9),
    ("Backend Status Code",      "$.backendStatusCode",      10),
    ("Backend Address",          "$.backendAddress",         11),
    ("Bytes Received",           "$.bytesReceived",          12),
    ("Bytes Sent",               "$.bytesSent",              13),
    ("Request Processing Time",  "$.requestProcessingTime",  14),
    ("Host Name",                "$.hostname",               15),
    ("Load Balancer Name",       "$.lbName",                 16),
    ("Listener Name",            "$.listenerName",           17),
    ("Content Type",             "$.contentType",            18),
    ("Referrer",                 "$.referer",                19),
    ("Trace ID",                 "$.traceId",                20),
]
LB_EXAMPLE = {
    "timeCreated": "2026-02-15T14:30:00.000Z",
    "httpMethod": "POST",
    "requestUrl": "/vulnerable/login",
    "uriPath": "/vulnerable/login",
    "queryString": "",
    "clientAddress": "45.33.32.156",
    "userAgent": "Mozilla/5.0 (compatible; Hydra/9.0)",
    "statusCode": "401",
    "backendStatusCode": "401",
    "backendAddress": "10.0.1.50:9010",
    "bytesReceived": "1024",
    "bytesSent": "256",
    "requestProcessingTime": "15",
    "hostname": "sevenkingdoms.example.com",
    "lbName": "seven-kingdoms-portal-lb",
    "listenerName": "http-listener",
    "contentType": "application/x-www-form-urlencoded",
    "referer": "https://sevenkingdoms.example.com/vulnerable/login",
    "traceId": "trace_demo_lb_001",
    "msg": "POST /vulnerable/login 401 - Hydra/9.0",
}

LB_SOURCE_INTERNAL = "socLbAccessSource"
LB_SOURCE_DISPLAY = "SOC Load Balancer Access Logs"
LB_SOURCE_DESC = (
    "OCI Load Balancer access log events in JSON format for web traffic analysis and threat detection."
)


# ─── Web Application Log Parser ───────────────────────────────

WEBAPP_PARSER_NAME = "socWebAppJsonParser"
WEBAPP_PARSER_DISPLAY = "SOC Web Application JSON Parser"
WEBAPP_PARSER_DESC = (
    "Parses web application security events (Seven Kingdoms Portal) for attack detection. "
    "Maps attack type, OWASP category, request details, and vulnerability context."
)
WEBAPP_FIELD_MAPPINGS = [
    ("msg",                  "$.msg",                1),
    ("time",                 "$.timestamp",          2),
    ("HTTP Method",          "$.httpMethod",         3),
    ("Request URL",          "$.requestUrl",         4),
    ("URI Path",             "$.uriPath",            5),
    ("Query String",         "$.queryString",        6),
    ("Client IP",            "$.clientAddress",      7),
    ("User Agent",           "$.userAgent",          8),
    ("Response Code",        "$.statusCode",         9),
    ("Attack Type",          "$.attackType",        10),
    ("Attack Payload",       "$.attackPayload",     11),
    ("OWASP Category",       "$.owaspCategory",     12),
    ("Vulnerability ID",     "$.vulnerabilityId",   13),
    ("Session ID",           "$.sessionId",         14),
    ("Application Name",     "$.appName",           15),
    ("Request ID",           "$.requestId",         16),
    ("Host Name",            "$.hostname",          17),
    ("Request Body",         "$.requestBody",       18),
    ("Content Type",         "$.contentType",       19),
    ("User",                 "$.user",              20),
    ("Trace ID",             "$.traceId",           21),
]
WEBAPP_EXAMPLE = {
    "timestamp": "2026-02-15T14:30:00.000Z",
    "httpMethod": "POST",
    "requestUrl": "/vulnerable/api/users/1",
    "uriPath": "/vulnerable/api/users/1",
    "queryString": "",
    "clientAddress": "91.92.109.18",
    "userAgent": "python-requests/2.28.0",
    "statusCode": "200",
    "attackType": "IDOR",
    "attackPayload": "id=1",
    "owaspCategory": "A01:2021-Broken Access Control",
    "vulnerabilityId": "CVE-2024-DEMO-001",
    "sessionId": "sess_abc123def456",
    "appName": "seven-kingdoms-portal",
    "requestId": "req_789xyz",
    "hostname": "sevenkingdoms.example.com",
    "requestBody": "{\"id\": 1, \"role\": \"admin\"}",
    "contentType": "application/json",
    "user": "anonymous",
    "traceId": "trace_demo_webapp_001",
    "msg": "IDOR: Unauthorized access to user profile id=1",
}

WEBAPP_SOURCE_INTERNAL = "socWebAppSource"
WEBAPP_SOURCE_DISPLAY = "SOC Web Application Logs"
WEBAPP_SOURCE_DESC = (
    "Web application security events from Seven Kingdoms Portal for OWASP attack detection."
)


# ─── Application Telemetry Parser ─────────────────────────────

APP_PARSER_NAME = "socApplicationJsonParser"
APP_PARSER_DISPLAY = "SOC Application JSON Parser"
APP_PARSER_DESC = (
    "Parses application and browser telemetry JSON for the Application 360 and "
    "browser attack dashboards. Maps service name, request metadata, trace IDs, "
    "security attack context, and browser span attributes."
)
APP_FIELD_MAPPINGS = [
    ("msg",                  "$.message",            1),
    ("time",                 "$.timestamp",          2),
    ("Service Name",         "$.serviceName",        3),
    ("Application Name",     "$.serviceName",        4),
    ("Trace ID",             "$.traceId",            5),
    ("HTTP Method",          "$.httpMethod",         6),
    ("Request URL",          "$.requestUrl",         7),
    ("URI Path",             "$.uriPath",            8),
    ("Query String",         "$.queryString",        9),
    ("Response Code",        "$.statusCode",        10),
    ("Response Time Ms",     "$.responseTimeMs",    11),
    ("Client IP",            "$.clientAddress",     12),
    ("User Agent",           "$.userAgent",         13),
    ("User",                 "$.user",              14),
    ("Session ID",           "$.sessionId",         15),
    ("Request ID",           "$.requestId",         16),
    ("Content Type",         "$.contentType",       17),
    ("Referrer",             "$.referrer",          18),
    ("Response Headers",     "$.responseHeaders",   19),
    ("Span Name",            "$.spanName",          20),
    ("Span Attributes",      "$.spanAttributes",    21),
    ("Span ID",              "$.spanId",            22),
    ("Parent Span ID",       "$.parentSpanId",      23),
    ("Span Kind",            "$.spanKind",          24),
    ("APM Domain",           "$.apmDomain",         25),
    ("Metric Name",          "$.metricName",        26),
    ("Metric Value",         "$.metricValue",       27),
    ("Metric Unit",          "$.metricUnit",        28),
    ("Attack Type",          "$.securityAttackType", 29),
    ("Risk Level",           "$.securityAttackSeverity", 30),
    ("WAF Score",            "$.wafScore",          31),
    ("DB Target",            "$.dbTarget",          32),
    ("Error Type",           "$.errorType",         33),
    ("Slow Request",         "$.slowRequest",       34),
    ("Orders Sync Created",  "$.ordersSyncCreated", 35),
    ("Orders Sync Updated",  "$.ordersSyncUpdated", 36),
    ("Orders Sync Failed",   "$.ordersSyncFailed",  37),
    ("Orders Sync Source",   "$.ordersSyncSource",  38),
    ("Severity Level",       "$.level",             39),
    ("Host Name",            "$.hostname",          40),
    # Octo APM Demo / OTel-style structured logs. These duplicate some
    # display fields intentionally so existing synthetic logs and real app
    # logs resolve to the same dashboard-facing field names.
    ("Service Name",         "$.service.name",      41),
    ("Service Namespace",    "$.service.namespace", 42),
    ("Service Version",      "$.service.version",   43),
    ("Service Instance ID",  "$.service.instance.id", 44),
    ("Deployment Environment", "$.deployment.environment", 45),
    ("Application Name",     "$.app.name",          46),
    ("App Name",             "$.app.name",          47),
    ("App Brand",            "$.app.brand",         48),
    ("App Runtime",          "$.app.runtime",       49),
    ("App Service",          "$.app.service",       50),
    ("Trace ID",             "$.trace_id",          51),
    ("Trace ID",             "$.oracleApmTraceId",  52),
    ("Span ID",              "$.span_id",           53),
    ("Span ID",              "$.oracleApmSpanId",   54),
    ("Trace Parent",         "$.traceparent",       55),
    ("HTTP Method",          "$.http.method",       56),
    ("HTTP Method",          "$.http.request.method", 57),
    ("Request URL",          "$.http.url.path",     58),
    ("URI Path",             "$.http.url.path",     59),
    ("URL Path",             "$.http.url.path",     60),
    ("Response Code",        "$.http.status_code",  61),
    ("Response Code",        "$.http.response.status_code", 62),
    ("HTTP Status Code",     "$.http.status_code",  63),
    ("HTTP Status Code",     "$.http.response.status_code", 64),
    ("Response Time Ms",     "$.http.response_time_ms", 65),
    ("Client IP",            "$.http.client_ip",    66),
    ("Client IP",            "$.client.address",    67),
    ("User Agent",           "$.user_agent.original", 68),
    ("User Agent",           "$.http.user_agent",   69),
    ("Request ID",           "$.request_id",        70),
    ("Workflow ID",          "$.workflow_id",       71),
    ("Workflow Step",        "$.workflow_step",     72),
    ("Correlation ID",       "$.correlation.id",    73),
    ("Run ID",               "$.run_id",            74),
    ("DB Target",            "$.db.target",         75),
    ("DB Statement",         "$.db.statement",      76),
    ("DB Elapsed ms",        "$.db.elapsed_ms",     77),
    ("DB Connection Name",   "$.db.connection_name", 78),
    ("DB OCID",              "$.db.ocid",           79),
    ("Slow Request",         "$.performance.slow_request", 80),
    ("Host Name",            "$.host.name",         81),
    ("Java APM Path",        "$.java_apm.path",     82),
    ("Java APM Status Code", "$.java_apm.status_code", 83),
    ("Java APM Latency ms",  "$.java_apm.latency_ms", 84),
    ("Java APM Error Type",  "$.java_apm.error_type", 85),
    ("Attack ID",           "$.security.attack.id", 86),
    ("Attack Stage",        "$.security.attack.stage", 87),
    ("Attack Type",         "$.security.attack.type", 88),
    ("Attack Entry Point",  "$.attack.entry_point", 89),
    ("Attack Payload",      "$.security.attack.payload", 90),
    ("LOTL Binary",         "$.attack.lotl_binary", 91),
    ("Security Severity",   "$.security.severity", 92),
    ("MITRE Tactic",        "$.mitre.tactic", 93),
    ("MITRE Technique ID",  "$.mitre.technique_id", 94),
    ("MITRE Technique",     "$.mitre.technique", 95),
    ("Source IP",           "$.source.ip", 96),
    ("Server Address",      "$.server.address", 97),
    ("Destination IP",      "$.destination.ip", 98),
    ("Destination Port",    "$.destination.port", 99),
    ("Network Protocol",    "$.network.protocol.name", 100),
    ("OSQuery Query",       "$.osquery.query", 101),
    ("OSQuery Finding",     "$.osquery.finding", 102),
    ("OSQuery SQL",         "$.osquery.sql", 103),
    ("OSQuery Result Count", "$.osquery.result_count", 104),
    ("Instance OCID",       "$.cloud.instance.id", 105),
    ("Host Role",           "$.host.role", 106),
    ("Compromised VM",      "$.vm.compromised", 107),
    ("Process Name",        "$.process.name", 108),
    ("Process Command Line", "$.process.command_line", 109),
    ("File Path",           "$.file.path", 110),
    ("Payment Provider",    "$.payment.provider", 111),
    ("Payment Status",      "$.payment.status", 112),
    ("Payment Risk Score",  "$.payment.risk_score", 113),
    ("Payment Network",     "$.payment.card_brand", 114),
    ("Payment Card Last4",  "$.payment.card_last4", 115),
    ("Payment Interception", "$.payment.interception.detected", 116),
    ("Payment Redirect",    "$.payment.redirect.detected", 117),
    ("Payment Redirect URL", "$.payment.redirect.url", 118),
    ("HTTP Redirect Location", "$.http.redirect.location", 119),
    ("Network Bytes Out",   "$.network.bytes_out", 120),
    ("WAF Action",          "$.wafAction", 121),
    ("WAF Action",          "$.waf.action", 122),
    ("Severity",            "$.level", 123),
    ("Severity",            "$.severity", 124),
    # Keep $.message on the built-in msg field only. Mapping it to
    # "Original Log Content" resolves to reserved field mbody and OCI rejects
    # that mapping for custom parsers.
    ("Service",             "$.service.name", 125),
    ("Service",             "$.serviceName", 126),
    ("HTTP Request Method", "$.http.request.method", 127),
    ("HTTP Request Method", "$.http.method", 128),
    ("User ID (hashed)",    "$.user_id_hash", 129),
    ("Business ID",         "$.business_id", 130),
    ("API Gateway Name",    "$.oci.api_gateway.name", 131),
    ("API Gateway Scope",   "$.oci.api_gateway.scope", 132),
    ("API Gateway Deployment ID", "$.oci.api_gateway.deployment_id", 133),
    ("API Gateway Route",   "$.oci.api_gateway.route", 134),
    ("API Gateway Route ID", "$.oci.api_gateway.route_id", 135),
    ("API Gateway Route Family", "$.oci.api_gateway.route_family", 136),
    ("API Gateway Request ID", "$.oci.api_gateway.request_id", 137),
    ("API Gateway Action",  "$.oci.api_gateway.action", 138),
    ("API Gateway Policy Decision", "$.oci.api_gateway.policy.decision", 139),
    ("API Gateway Latency ms", "$.oci.api_gateway.latency_ms", 140),
    ("API Gateway Rate Limit", "$.oci.api_gateway.rate_limit.limit", 141),
    ("API Gateway Rate Remaining", "$.oci.api_gateway.rate_limit.remaining", 142),
    ("API Gateway Threat Signal", "$.oci.api_gateway.threat_signal", 143),
    ("Chaos Injected",      "$.chaos.injected", 144),
    ("Chaos Scenario",      "$.chaos.scenario", 145),
    ("Chaos TTL Seconds",   "$.chaos.ttl_seconds", 146),
    ("Chaos Target",        "$.chaos.target", 147),
    # OKE app stdout and Java gateway records use both OTel semantic keys and
    # Log Analytics-friendly aliases. Map both into the reusable SOC fields.
    ("Service Name",         "$.service_name", 148),
    ("Service Namespace",    "$.service_namespace", 149),
    ("Service Instance ID",  "$.service_instance_id", 150),
    ("Deployment Environment", "$.deployment_environment", 151),
    ("Trace ID",             "$.traceId", 152),
    ("Span ID",              "$.spanId", 153),
    ("Request ID",           "$.request_id", 154),
    ("URL Path",             "$.url_path", 155),
    ("HTTP Status Code",     "$.http_status_code", 156),
    ("Order ID",             "$.orders.order_id", 157),
    ("Order ID",             "$.orders.id", 158),
    ("Order ID",             "$.order_id", 159),
    ("Source Order ID",      "$.source_order_id", 160),
    ("Payment Gateway Request ID", "$.payment.gateway.request_id", 161),
    ("Payment Gateway Request ID", "$.payment_gateway_request_id", 162),
    ("Payment Provider",     "$.payment.provider", 163),
    ("Payment Provider",     "$.payment_provider", 164),
    ("Payment Status",       "$.payment.status", 165),
    ("Payment Status",       "$.payment_status", 166),
    ("Payment Network",      "$.payment.network", 167),
    ("Payment Network",      "$.payment_network", 168),
    ("Payment Wallet Token Hash", "$.payment.wallet_token_hash", 169),
    ("Payment Wallet Token Hash", "$.payment.wallet.token_hash", 170),
    ("Payment Wallet Token Hash", "$.payment_wallet_token_hash", 171),
    ("Payment Risk Score",   "$.payment.risk_score", 172),
    ("Payment Risk Score",   "$.payment_risk_score", 173),
    ("Payment Network",      "$.payment.card_brand", 174),
    ("Payment Network",      "$.payment.card.brand", 175),
    ("Payment Card Last4",   "$.payment.card_last4", 176),
    ("Payment Card Last4",   "$.payment.card.last4", 177),
    ("Gateway",              "$.payment.gateway.name", 178),
    ("Gateway",              "$.payment_gateway_name", 179),
    ("Provider",             "$.payment.gateway.provider", 180),
    ("Provider",             "$.payment_gateway_provider", 181),
    ("Version",              "$.payment.gateway.version", 182),
    ("Version",              "$.payment_gateway_version", 183),
    ("Step Id",              "$.payment.gateway.step", 184),
    ("Step Id",              "$.payment_gateway_step", 185),
    ("Process Phase",        "$.payment.gateway.phase", 186),
    ("Process Phase",        "$.payment_gateway_phase", 187),
    ("Event Status",         "$.payment.gateway.step_status", 188),
    ("Event Status",         "$.payment_gateway_step_status", 189),
    ("Elapsed Time (Gateway)", "$.payment.gateway.step_latency_ms", 190),
    ("Elapsed Time (Gateway)", "$.payment_gateway_step_latency_ms", 191),
    ("Request Type",         "$.payment.gateway.request_shape", 192),
    ("Authorization Scheme", "$.payment.gateway.authorization_type", 193),
    ("Method",               "$.payment.method", 194),
    ("Method",               "$.payment_method", 195),
    ("ORDER_AMOUNT",         "$.payment.amount_minor_units", 196),
    ("ORDER_AMOUNT",         "$.payment_amount_minor_units", 197),
    ("BillingCurrency",      "$.payment.currency", 198),
    ("BillingCurrency",      "$.payment_currency", 199),
    ("Response Code",        "$.payment.processor.response_code", 200),
    ("Response Code",        "$.payment_processor_response_code", 201),
    ("Gateway ID",           "$.payment.processor.gateway_code", 202),
    ("Gateway ID",           "$.payment_processor_gateway_code", 203),
    ("Transaction ID",       "$.payment.network.transaction_id", 204),
    ("Transaction ID",       "$.payment_network_transaction_id", 205),
    ("Result",               "$.payment.card.avs.result", 206),
    ("Result",               "$.payment_card_avs_result", 207),
    ("Security Result",      "$.payment.card.cvv.result", 208),
    ("Security Result",      "$.payment_card_cvv_result", 209),
    ("Program",              "$.payment.3ds.program", 210),
    ("Program",              "$.payment_3ds_program", 211),
    ("Flow Code",            "$.payment.3ds.eci", 212),
    ("Flow Code",            "$.payment_3ds_eci", 213),
    ("Flow",                 "$.payment.3ds.flow", 214),
    ("Flow",                 "$.payment_3ds_flow", 215),
    ("Java APM Path",        "$.java_apm_path", 216),
    ("Java APM Status Code", "$.java_apm_status_code", 217),
    ("Java APM Latency ms",  "$.java_apm_latency_ms", 218),
    ("Java APM Error Type",  "$.java_apm_error_type", 219),
    ("Downstream Component", "$.java_apm.service.name", 220),
    ("Downstream Component", "$.payment.processor.name", 221),
    ("Downstream Component", "$.java_apm_service_name", 222),
    ("Downstream Component", "$.payment_processor_name", 223),
]
OCTO_APM_FIELD_DISPLAY_NAMES = (
    "Service",
    "Severity",
    "APM Domain",
    "Service Namespace",
    "Service Version",
    "Service Instance ID",
    "Deployment Environment",
    "App Name",
    "App Brand",
    "App Runtime",
    "App Service",
    "Trace ID",
    "Trace Parent",
    "Span ID",
    "Parent Span ID",
    "Span Name",
    "Span Attributes",
    "Span Kind",
    "Workflow ID",
    "Workflow Step",
    "Correlation ID",
    "Run ID",
    "Request ID",
    "URL Path",
    "HTTP Status Code",
    "HTTP Request Method",
    "Response Time Ms",
    "Metric Name",
    "Metric Value",
    "Metric Unit",
    "DB Target",
    "DB Statement",
    "DB Elapsed ms",
    "DB Connection Name",
    "DB OCID",
    "Error Type",
    "Slow Request",
    "Java APM Path",
    "Java APM Status Code",
    "Java APM Latency ms",
    "Java APM Error Type",
    "Attack ID",
    "Attack Stage",
    "Attack Type",
    "Attack Entry Point",
    "Attack Payload",
    "LOTL Binary",
    "Security Severity",
    "MITRE Tactic",
    "MITRE Technique ID",
    "MITRE Technique",
    "Source IP",
    "Server Address",
    "Destination IP",
    "Destination Port",
    "Network Protocol",
    "OSQuery Query",
    "OSQuery Finding",
    "OSQuery SQL",
    "OSQuery Result Count",
    "Instance OCID",
    "Host Role",
    "Compromised VM",
    "Process Name",
    "Process Command Line",
    "File Path",
    "Payment Provider",
    "Payment Status",
    "Payment Risk Score",
    "Payment Card Last4",
    "Payment Interception",
    "Payment Redirect",
    "Payment Redirect URL",
    "HTTP Redirect Location",
    "Network Bytes Out",
    "User ID (hashed)",
    "Business ID",
    "API Gateway Name",
    "API Gateway Scope",
    "API Gateway Deployment ID",
    "API Gateway Route",
    "API Gateway Route ID",
    "API Gateway Route Family",
    "API Gateway Request ID",
    "API Gateway Action",
    "API Gateway Policy Decision",
    "API Gateway Latency ms",
    "API Gateway Rate Limit",
    "API Gateway Rate Remaining",
    "API Gateway Threat Signal",
    "WAF Action",
    "Chaos Injected",
    "Chaos Scenario",
    "Chaos TTL Seconds",
    "Chaos Target",
)

OCTO_APM_WORKSHOP_FIELD_DISPLAY_NAMES = (
    "Service Name",
    "Service Namespace",
    "Severity Level",
    "Trace ID",
    "Span ID",
    "Parent Span ID",
    "Span Name",
    "Span Attributes",
    "Span Kind",
    "APM Domain",
    "Request ID",
    "Workflow ID",
    "Workflow Step",
    "Run ID",
    "Response Code",
    "Metric Name",
    "Metric Value",
    "Metric Unit",
    "DB Target",
    "DB Statement",
    "DB Elapsed ms",
    "DB Connection Name",
    "Error Type",
    "Java APM Path",
    "Java APM Latency ms",
    "Java APM Error Type",
    "Attack ID",
    "Attack Stage",
    "Security Severity",
    "MITRE Tactic",
    "MITRE Technique ID",
    "Destination IP",
    "Destination Port",
    "OSQuery Query",
    "OSQuery Finding",
    "OSQuery SQL",
    "Instance OCID",
    "Host Name",
    "Host Role",
    "Compromised VM",
    "Process Command Line",
    "Order ID",
    "Source Order ID",
    "Payment Gateway Request ID",
    "Payment Provider",
    "Payment Status",
    "Payment Network",
    "Payment Wallet Token Hash",
    "Payment Risk Score",
    "Payment Card Last4",
    "Gateway",
    "Provider",
    "Version",
    "Step Id",
    "Process Phase",
    "Event Status",
    "Elapsed Time (Gateway)",
    "Request Type",
    "Authorization Scheme",
    "Method",
    "ORDER_AMOUNT",
    "BillingCurrency",
    "Gateway ID",
    "Transaction ID",
    "Result",
    "Security Result",
    "Program",
    "Flow Code",
    "Flow",
    "Downstream Component",
    "Payment Interception",
    "Payment Redirect",
    "Payment Redirect URL",
    "HTTP Redirect Location",
    "API Gateway Request ID",
    "API Gateway Action",
    "API Gateway Policy Decision",
    "API Gateway Route",
    "API Gateway Threat Signal",
)
APP_EXAMPLE = {
    "timestamp": "2026-03-18T09:07:04.446Z",
    "serviceName": "enterprise-crm-portal",
    "service.name": "enterprise-crm-portal",
    "service.namespace": "octo",
    "service.version": "1.1.0",
    "service.instance.id": "crm-portal-01",
    "deployment.environment": "production",
    "app.name": "enterprise-crm-portal",
    "app.brand": "OCTO CRM APM",
    "app.runtime": "python",
    "app.service": "enterprise-crm-portal",
    "traceId": "trace_demo_cross_service_001",
    "trace_id": "trace_demo_cross_service_001",
    "span_id": "span_demo_root_001",
    "oracleApmTraceId": "trace_demo_cross_service_001",
    "oracleApmSpanId": "span_demo_root_001",
    "traceparent": "00-trace_demo_cross_service_001-span_demo_root_001-01",
    "httpMethod": "GET",
    "http.method": "GET",
    "http.request.method": "GET",
    "http.request.method": "GET",
    "requestUrl": "/crm/orders/42",
    "uriPath": "/crm/orders/42",
    "http.url.path": "/crm/orders/42",
    "queryString": "",
    "statusCode": "200",
    "http.status_code": 200,
    "http.response.status_code": 200,
    "responseTimeMs": 842,
    "http.response_time_ms": 842,
    "clientAddress": "185.220.101.1",
    "http.client_ip": "185.220.101.1",
    "client.address": "185.220.101.1",
    "userAgent": "Mozilla/5.0 (compatible; demo-browser)",
    "user_agent.original": "Mozilla/5.0 (compatible; demo-browser)",
    "http.user_agent": "Mozilla/5.0 (compatible; demo-browser)",
    "user": "cersei",
    "sessionId": "sess_demo_001",
    "requestId": "req_demo_001",
    "request_id": "req_demo_001",
    "workflow_id": "crm-order-sync",
    "workflow_step": "order-detail",
    "correlation.id": "trace_demo_cross_service_001",
    "run_id": "run-octo-attack-lab-001",
    "contentType": "text/html",
    "referrer": "",
    "responseHeaders": "Content-Type: text/html; charset=utf-8",
    "spanName": "HTTP GET /crm/orders/:id",
    "spanAttributes": "document.cookie canvas.toDataURL webgl.getParameter",
    "spanId": "span_demo_root_001",
    "parentSpanId": "",
    "spanKind": "SERVER",
    "apmDomain": "octo-apm-demo",
    "metricName": "http.server.duration",
    "metricValue": "842",
    "metricUnit": "ms",
    "securityAttackType": "xss_reflected",
    "securityAttackSeverity": "high",
    "wafScore": "88",
    "dbTarget": "oracle_atp",
    "db.target": "oracle_atp",
    "db.statement": "select * from orders where id = :id",
    "db.elapsed_ms": 155,
    "db.connection_name": "octo_atp_tp",
    "db.ocid": "ocid1.autonomousdatabase.oc1..example",
    "errorType": "",
    "slowRequest": "false",
    "performance.slow_request": False,
    "java_apm.path": "/api/java-apm/payment/authorize",
    "java_apm.status_code": 200,
    "java_apm.latency_ms": 135,
    "java_apm.error_type": "",
    "security.attack.id": "attack-octo-demo-001",
    "security.attack.stage": "payment_redirect",
    "security.attack.type": "payment_redirect",
    "security.attack.payload": "redirect checkout payment flow",
    "security.attack.detected": True,
    "security.severity": "critical",
    "mitre.tactic": "Credential Access",
    "mitre.technique_id": "T1557",
    "mitre.technique": "Adversary-in-the-Middle",
    "attack.entry_point": "/shop/checkout/payment/redirect",
    "attack.lotl_binary": "nginx-rewrite",
    "source.ip": "203.0.113.77",
    "server.address": "octo-shop-vm-01",
    "destination.ip": "198.51.100.44",
    "destination.port": 443,
    "network.protocol.name": "https",
    "osquery.query": "suspicious-shell-history",
    "osquery.finding": "redirect rule simulation points payment flow to a suspicious host",
    "osquery.sql": "SELECT pid, name, path, cmdline FROM processes;",
    "osquery.result_count": 1,
    "cloud.instance.id": "ocid1.instance.oc1.iad.demoattackshop01",
    "host.name": "octo-shop-vm-01",
    "host.role": "shop-frontend",
    "vm.compromised": True,
    "process.name": "nginx",
    "process.command_line": "nginx -s reload",
    "file.path": "/etc/nginx/conf.d/payment_redirect.conf",
    "payment.provider": "simulated",
    "payment.status": "redirected",
    "payment.risk_score": 97,
    "payment.card_brand": "visa",
    "payment.card_last4": "4242",
    "payment.interception.detected": True,
    "payment.redirect.detected": True,
    "payment.redirect.url": "https://pay-update.example.test/checkout/session",
    "http.redirect.location": "https://pay-update.example.test/checkout/session",
    "network.bytes_out": 4812,
    "wafAction": "DETECT",
    "waf.action": "DETECT",
    "chaos.injected": "false",
    "chaos.scenario": "",
    "chaos.ttl_seconds": 0,
    "chaos.target": "",
    "ordersSyncCreated": 0,
    "ordersSyncUpdated": 0,
    "ordersSyncFailed": 0,
    "ordersSyncSource": "",
    "level": "INFO",
    "severity": "INFO",
    "hostname": "crm-portal-01",
    "business_id": "order-42",
    "user_id_hash": "usr_demo_hash_001",
    "oci.api_gateway.name": "octo-public-api-gateway",
    "oci.api_gateway.scope": "public",
    "oci.api_gateway.deployment_id": "ocid1.apigatewaydeployment.oc1.iad.demo",
    "oci.api_gateway.route": "/api/shop/attack/simulate",
    "oci.api_gateway.route_id": "public-attack-simulate",
    "oci.api_gateway.route_family": "shop_attack",
    "oci.api_gateway.request_id": "gw-req-demo-001",
    "oci.api_gateway.action": "allow",
    "oci.api_gateway.policy.decision": "suspicious_burst_observed",
    "oci.api_gateway.latency_ms": 34,
    "oci.api_gateway.rate_limit.limit": 120,
    "oci.api_gateway.rate_limit.remaining": 87,
    "oci.api_gateway.threat_signal": "attack_lab_probe",
    "message": "Browser telemetry recorded suspicious request",
}

APP_SOURCE_INTERNAL = "socApplicationSource"
APP_SOURCE_DISPLAY = "SOC Application Logs"
APP_SOURCE_DESC = (
    "Application and browser telemetry from OCI-DEMO services in JSON format. "
    "Used by the Application 360 and browser attack dashboards."
)


# ─── OCI VCN Flow Log Parser ──────────────────────────────────

VCN_PARSER_NAME = "socVcnFlowJsonParser"
VCN_PARSER_DISPLAY = "SOC VCN Flow JSON Parser"
VCN_PARSER_DESC = (
    "Parses OCI VCN Flow Log JSON for network egress, C2, and exfiltration hunting. "
    "Maps vendor nested data fields plus SOC aliases for source/destination and byte counts."
)
VCN_FIELD_MAPPINGS = [
    ("msg",                  "$.msg",                         1),
    ("time",                 "$.time",                        2),
    ("Source IP",            "$.data.sourceAddress",          3),
    ("Destination IP",       "$.data.destinationAddress",     4),
    ("Source Port",          "$.data.sourcePort",             5),
    ("Destination Port",     "$.data.destinationPort",        6),
    ("Protocol",             "$.data.protocol",               7),
    ("Action",               "$.data.action",                 8),
    ("Network Action",       "$.data.action",                 9),
    ("Bytes Sent",           "$.data.bytesOut",              10),
    ("Bytes Received",       "$.data.bytesIn",               11),
    ("Packets",              "$.data.packetsOut",            12),
    ("Flow ID",              "$.data.flowId",                13),
    ("Resource ID",          "$.data.vnicId",                14),
    ("Trace ID",             "$.Trace ID",                   15),
    ("Log Type",             "$.type",                       16),
]
VCN_EXAMPLE = {
    "time": "2026-05-04T10:15:00.000Z",
    "type": "com.oraclecloud.vcn.flowlogs.DataEvent",
    "data": {
        "sourceAddress": "10.0.1.50",
        "destinationAddress": "198.51.100.77",
        "sourcePort": 45010,
        "destinationPort": 443,
        "protocol": "6",
        "action": "ACCEPT",
        "bytesOut": 73400320,
        "bytesIn": 2048,
        "packetsOut": 4200,
        "flowId": "flow-w2c-c2-004",
        "vnicId": "ocid1.vnic.oc1..example",
    },
    "Trace ID": "trace_w2c_entry_001",
    "msg": "VCN Flow ACCEPT: 10.0.1.50:45010 -> 198.51.100.77:443",
}

VCN_SOURCE_INTERNAL = "socVcnFlowSource"
VCN_SOURCE_DISPLAY = "SOC VCN Flow Logs"
VCN_SOURCE_DESC = (
    "OCI VCN Flow Log records in JSON format for network egress and exfiltration drilldowns."
)


# ─── OCI Network Firewall Log Parser ───────────────────────────

FW_PARSER_NAME = "socNetworkFirewallJsonParser"
FW_PARSER_DISPLAY = "SOC Network Firewall JSON Parser"
FW_PARSER_DESC = (
    "Parses OCI Network Firewall traffic and threat logs. Maps session, rule, action, "
    "byte volume, and threat fields for web-to-cloud attack drilldowns."
)
FW_FIELD_MAPPINGS = [
    ("msg",                  "$.msg",                         1),
    ("time",                 "$.logContent.time",             2),
    ("Log Type",             "$.logContent.data.log_type",    3),
    ("Action",               "$.logContent.data.action",      4),
    ("Network Action",       "$.logContent.data.action",      5),
    ("Source IP",            "$.logContent.data.src",         6),
    ("Destination IP",       "$.logContent.data.dst",         7),
    ("Source Port",          "$.logContent.data.sport",       8),
    ("Destination Port",     "$.logContent.data.dport",       9),
    ("Protocol",             "$.logContent.data.proto",      10),
    ("Bytes Sent",           "$.logContent.data.bytes_sent", 11),
    ("Bytes Received",       "$.logContent.data.bytes_received", 12),
    ("Firewall Rule",        "$.logContent.data.rule",       13),
    ("Threat Name",          "$.logContent.data.threatid",   14),
    ("Threat Category",      "$.logContent.data.category",   15),
    ("Severity Level",       "$.logContent.data.severity",   16),
    ("Direction",            "$.logContent.data.direction",  17),
    ("Session ID",           "$.logContent.data.sessionid",  18),
    ("Trace ID",             "$.Trace ID",                   19),
]
FW_EXAMPLE = {
    "datetime": 1777890300000,
    "logContent": {
        "time": "2026-05-04T10:25:00.000Z",
        "type": "com.oraclecloud.networkfirewall.logs",
        "data": {
            "log_type": "threat",
            "src": "10.0.1.50",
            "dst": "198.51.100.77",
            "sport": "45010",
            "dport": "443",
            "proto": "tcp",
            "action": "alert",
            "rule": "inspect-app-egress",
            "bytes_sent": "73400320",
            "bytes_received": "2048",
            "threatid": "Suspicious Data Exfiltration",
            "category": "data-theft",
            "severity": "critical",
            "sessionid": "1234567890",
        },
    },
    "Trace ID": "trace_w2c_entry_001",
    "msg": "Network Firewall threat alert: 10.0.1.50 -> 198.51.100.77",
}

FW_SOURCE_INTERNAL = "socNetworkFirewallSource"
FW_SOURCE_DISPLAY = "SOC Network Firewall Logs"
FW_SOURCE_DESC = (
    "OCI Network Firewall traffic and threat logs in JSON format for C2 and exfiltration analysis."
)


# ─── Multicloud Health Parser ──────────────────────────────────

HEALTH_PARSER_NAME = "socMulticloudHealthJsonParser"
HEALTH_PARSER_DISPLAY = "SOC Multicloud Health JSON Parser"
HEALTH_PARSER_DESC = (
    "Parses multicloud health heartbeat JSON for geographic map visualization. "
    "Maps cloud provider, region, lat/lon coordinates, instance metadata, and health metrics."
)
HEALTH_FIELD_MAPPINGS = [
    ("msg",                  "$.msg",                1),
    ("time",                 "$.Timestamp",           2),
    ("Cloud Provider",       "$.Cloud Provider",      3),
    ("Region",               "$.Region",              4),
    ("Region Display",       "$.Region Display",      5),
    ("Country",              "$.Country",             6),
    ("Latitude",             "$.Latitude",            7),
    ("Longitude",            "$.Longitude",           8),
    ("Instance ID",          "$.Instance ID",         9),
    ("Host Name",            "$.Host Name",          10),
    ("IP Address",           "$.IP Address",         11),
    ("Instance Role",        "$.Instance Role",      12),
    ("Service Name",         "$.Service",            13),
    ("Tier",                 "$.Tier",               14),
    ("Operating System",     "$.Operating System",   15),
    ("Instance Type",        "$.Instance Type",      16),
    ("Status",               "$.Status",             17),
    ("Status Code",          "$.Status Code",        18),
    ("CPU Percent",          "$.CPU Percent",        19),
    ("Memory Percent",       "$.Memory Percent",     20),
    ("Disk Percent",         "$.Disk Percent",       21),
    ("Network In Mbps",      "$.Network In Mbps",    22),
    ("Network Out Mbps",     "$.Network Out Mbps",   23),
    ("Uptime Hours",         "$.Uptime Hours",       24),
    ("Open Connections",     "$.Open Connections",   25),
    ("Response Time Ms",     "$.Response Time Ms",   26),
    ("Heartbeat Sequence",   "$.Heartbeat Sequence", 27),
]
HEALTH_EXAMPLE = {
    "Timestamp": "2026-03-10T09:00:00.000Z",
    "Cloud Provider": "OCI",
    "Region": "eu-frankfurt-1",
    "Region Display": "Germany Central (Frankfurt)",
    "Country": "DE",
    "Latitude": 50.1109,
    "Longitude": 8.6821,
    "Instance ID": "ocid1.instance.oc1.eu-frankfurt-1.example",
    "Host Name": "web-server-eu-001",
    "IP Address": "10.0.1.10",
    "Instance Role": "web-server",
    "Service": "nginx",
    "Tier": "frontend",
    "Operating System": "Oracle Linux 9",
    "Instance Type": "VM.Standard.E4.Flex",
    "Status": "healthy",
    "Status Code": 200,
    "CPU Percent": 35.2,
    "Memory Percent": 48.7,
    "Disk Percent": 42.1,
    "Network In Mbps": 15.3,
    "Network Out Mbps": 8.7,
    "Uptime Hours": 720,
    "Open Connections": 142,
    "Response Time Ms": 12,
    "Heartbeat Sequence": 1,
    "Log Source": "SOC Multicloud Health Logs",
    "msg": "HEARTBEAT OK: web-server-eu-001 (OCI/eu-frankfurt-1) cpu=35.2% mem=48.7% uptime=720h status=healthy",
}

HEALTH_SOURCE_INTERNAL = "socMulticloudHealthSource"
HEALTH_SOURCE_DISPLAY = "SOC Multicloud Health Logs"
HEALTH_SOURCE_DESC = (
    "Multicloud health heartbeat logs from OCI, Azure, and GCP instances "
    "with geographic coordinates for global map visualization."
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
    SYSNET_SOURCE_DISPLAY: [],
    WAF_SOURCE_DISPLAY: ["OCI WAF Logs"],
    LB_SOURCE_DISPLAY: ["OCI Load Balancer Access Logs"],
    WEBAPP_SOURCE_DISPLAY: [],
    APP_SOURCE_DISPLAY: [],
    VCN_SOURCE_DISPLAY: ["OCI VCN Flow Logs", "VCN Flow Logs"],
    FW_SOURCE_DISPLAY: ["OCI Network Firewall Logs", "Network Firewall Logs"],
    HEALTH_SOURCE_DISPLAY: [],
}


# ─── Helper Functions ────────────────────────────────────────────

FIELD_LIST_ATTEMPTS = int(os.environ.get("OCI_LOG_ANALYTICS_FIELD_LIST_ATTEMPTS", "3"))
FIELD_LIST_RETRY_DELAY_SECONDS = float(
    os.environ.get("OCI_LOG_ANALYTICS_FIELD_LIST_RETRY_DELAY_SECONDS", "2")
)
LOG_ANALYTICS_READ_TIMEOUT_SECONDS = int(
    os.environ.get("OCI_LOG_ANALYTICS_READ_TIMEOUT_SECONDS", "180")
)

def unique_preserving_order(values):
    """Return values without duplicates while preserving the first occurrence."""
    seen = set()
    result = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def field_data_type_for(display_name):
    """Return the OCI Log Analytics data type to use when creating a field."""
    return FIELD_DATA_TYPE_OVERRIDES.get(display_name, "String")


def is_single_value_string_limit_error(exc):
    """Return True when the tenancy exhausted single-valued string fields."""
    return (
        getattr(exc, "status", None) == 400
        and "single-valued string field" in str(getattr(exc, "message", "")).lower()
    )


def select_field_contract(octo_apm_only=False, application_only=False):
    """Return the field and parser contract for the requested setup scope."""
    if octo_apm_only:
        return custom_fields_for_octo_apm_workshop(), field_mappings_for_octo_apm_workshop()
    if application_only:
        return custom_fields_for_application_logs(), APP_FIELD_MAPPINGS
    return CUSTOM_FIELDS, APP_FIELD_MAPPINGS


def custom_fields_for_application_logs():
    """Return the custom fields needed by the SOC Application/Octo APM parser."""
    mapped_fields = [
        field_name
        for field_name, _json_path, _sequence in APP_FIELD_MAPPINGS
        if field_name not in {"msg", "time"}
    ]
    custom_field_set = set(CUSTOM_FIELDS)
    return [
        field_name
        for field_name in unique_preserving_order(mapped_fields)
        if field_name in custom_field_set
    ]


def custom_fields_for_octo_apm_workshop():
    """Return the minimal fields needed by the Octo APM workshop assets."""
    custom_field_set = set(CUSTOM_FIELDS)
    return [
        field_name
        for field_name in unique_preserving_order(OCTO_APM_WORKSHOP_FIELD_DISPLAY_NAMES)
        if field_name in custom_field_set
    ]


def field_mappings_for_octo_apm_workshop():
    """Return parser mappings limited to the Octo APM workshop contract."""
    allowed_fields = set(OCTO_APM_WORKSHOP_FIELD_DISPLAY_NAMES) | {"msg", "time"}
    return [
        mapping
        for mapping in APP_FIELD_MAPPINGS
        if mapping[0] in allowed_fields
    ]


def missing_octo_apm_workshop_fields(field_map):
    """Return Octo workshop fields that are unavailable for parser creation."""
    missing = []
    for display_name in OCTO_APM_WORKSHOP_FIELD_DISPLAY_NAMES:
        if display_name in field_map or display_name.lower() in field_map:
            continue
        missing.append(display_name)
    return missing


def build_field_inventory_entry(field):
    """Return the stable field metadata needed for reuse/audit decisions."""
    return {
        "display_name": getattr(field, "display_name", None),
        "name": getattr(field, "name", None),
        "data_type": getattr(field, "data_type", None),
        "is_multi_valued": getattr(field, "is_multi_valued", None),
        "is_system": getattr(field, "is_system", None),
    }


def add_field_inventory_lookup(lookup, key, entry):
    """Add exact and case-insensitive lookups without replacing the first match."""
    if not key:
        return
    lookup.setdefault(key, entry)
    lookup.setdefault(key.lower(), entry)


def build_existing_field_inventory(client, namespace):
    """Fetch all existing fields and return lookup metadata for reuse/audit."""
    entries = []
    by_display = {}
    by_name = {}
    page = None
    while True:
        kwargs = {"limit": 1000}
        if page:
            kwargs["page"] = page
        resp = list_fields_with_retry(client, namespace, kwargs)
        for field in resp.data.items:
            entry = build_field_inventory_entry(field)
            entries.append(entry)
            add_field_inventory_lookup(by_display, entry["display_name"], entry)
            add_field_inventory_lookup(by_name, entry["name"], entry)
        page = resp.headers.get("opc-next-page")
        if not page:
            break
    return {
        "entries": entries,
        "by_display": by_display,
        "by_name": by_name,
    }


def list_fields_with_retry(client, namespace, kwargs):
    """List fields with bounded retries for slow Log Analytics namespaces."""
    for attempt in range(1, FIELD_LIST_ATTEMPTS + 1):
        try:
            return client.list_fields(namespace, **kwargs)
        except oci.exceptions.RequestException:
            if attempt == FIELD_LIST_ATTEMPTS:
                raise
            print(
                "  WARNING: list_fields timed out; "
                f"retrying {attempt}/{FIELD_LIST_ATTEMPTS - 1}"
            )
            time.sleep(FIELD_LIST_RETRY_DELAY_SECONDS * attempt)
        except oci.exceptions.ServiceError as exc:
            retryable_statuses = {429, 500, 502, 503, 504}
            if attempt == FIELD_LIST_ATTEMPTS or getattr(exc, "status", None) not in retryable_statuses:
                raise
            print(
                "  WARNING: list_fields returned a retryable OCI error; "
                f"retrying {attempt}/{FIELD_LIST_ATTEMPTS - 1}"
            )
            time.sleep(FIELD_LIST_RETRY_DELAY_SECONDS * attempt)


def find_field_by_display(inventory, display_name):
    """Return an existing field by display name, with case-insensitive fallback."""
    return (
        inventory["by_display"].get(display_name)
        or inventory["by_display"].get(display_name.lower())
    )


def find_field_by_name(inventory, field_name):
    """Return an existing field by internal name, with case-insensitive fallback."""
    return (
        inventory["by_name"].get(field_name)
        or inventory["by_name"].get(field_name.lower())
    )


def find_existing_field_for_creation(inventory, display_name):
    """Return an existing field that can satisfy this requested display name."""
    return find_field_by_display(inventory, display_name)


def field_rewrite_candidates(inventory, missing_field_names):
    """Return audit-only candidates that would require query/display rewrites."""
    candidates = []
    for display_name in missing_field_names:
        if display_name in RESERVED_PARSER_FIELD_DISPLAY_NAMES:
            continue
        for existing_display in FIELD_REWRITE_REUSE_CANDIDATES.get(display_name, ()):
            entry = find_field_by_display(inventory, existing_display)
            if not entry or not entry.get("name"):
                continue
            candidates.append({
                "requested_display_name": display_name,
                "existing_display_name": entry.get("display_name") or existing_display,
                "existing_internal_name": entry["name"],
                "query_rewrite_required": True,
            })
            break
    return candidates


def build_field_reuse_audit(inventory, field_display_names):
    """Return exact namespace reuse, missing fields, and rewrite candidates."""
    exact_reuse = []
    internal_name_reuse = []
    missing = []
    requested = unique_preserving_order(field_display_names)

    for display_name in requested:
        entry = find_field_by_display(inventory, display_name)
        if entry and entry.get("name"):
            exact_reuse.append({
                "requested_display_name": display_name,
                "existing_display_name": entry.get("display_name") or display_name,
                "existing_internal_name": entry["name"],
                "data_type": entry.get("data_type"),
            })
            continue

        entry = find_field_by_name(inventory, display_name)
        if entry and entry.get("name"):
            internal_name_reuse.append({
                "requested_display_name": display_name,
                "existing_display_name": entry.get("display_name"),
                "existing_internal_name": entry["name"],
                "data_type": entry.get("data_type"),
            })

        missing.append(display_name)

    return {
        "total_requested": len(requested),
        "exact_reuse": exact_reuse,
        "internal_name_reuse": internal_name_reuse,
        "missing": missing,
        "rewrite_candidates": field_rewrite_candidates(inventory, missing),
    }


def print_field_reuse_audit(audit, show_exact=False):
    """Print a namespace field audit without tenancy-specific identifiers."""
    exact_count = len(audit["exact_reuse"])
    internal_count = len(audit["internal_name_reuse"])
    missing_count = len(audit["missing"])
    total = audit["total_requested"]

    print("FIELD AUDIT - namespace existing-field reuse")
    print(f"  Requested parser fields: {total}")
    print(f"  Exact display-name fields reused: {exact_count}")
    print(f"  Internal-name matches found: {internal_count}")
    print(f"  Fields that setup would create: {missing_count}")

    if show_exact and audit["exact_reuse"]:
        print("\n  Exact display-name reuse:")
        for row in audit["exact_reuse"]:
            data_type = row.get("data_type") or "unknown"
            print(
                "    - "
                f"{row['requested_display_name']} -> {row['existing_internal_name']} "
                f"({data_type})"
            )

    if audit["internal_name_reuse"]:
        print("\n  Internal-name matches requiring display-name review:")
        for row in audit["internal_name_reuse"]:
            display = row.get("existing_display_name") or row["requested_display_name"]
            print(
                "    - "
                f"{row['requested_display_name']} -> {row['existing_internal_name']} "
                f"(display: {display})"
            )

    if audit["missing"]:
        print("\n  Fields to create if setup runs:")
        for display_name in audit["missing"]:
            print(f"    - {display_name} ({field_data_type_for(display_name)})")

    if audit["rewrite_candidates"]:
        print("\n  Existing-field rewrite candidates, not applied automatically:")
        for row in audit["rewrite_candidates"]:
            print(
                "    - "
                f"{row['requested_display_name']} could reuse "
                f"{row['existing_display_name']} after query/dashboard rewrites"
            )


def audit_existing_fields(client, namespace, field_display_names, show_exact=False):
    """Fetch namespace fields, print an audit, and return the audit details."""
    inventory = build_existing_field_inventory(client, namespace)
    audit = build_field_reuse_audit(inventory, field_display_names)
    print_field_reuse_audit(audit, show_exact=show_exact)
    return audit


def build_existing_field_map(client, namespace):
    """Fetch all existing fields and return name -> internal_name map.

    Supports lookup by both display_name and internal_name, so parser
    field mappings can reference either (e.g., built-in 'msg' and 'time').
    """
    inventory = build_existing_field_inventory(client, namespace)
    result = {}
    for entry in inventory["entries"]:
        if entry.get("display_name") and entry.get("name"):
            result[entry["display_name"]] = entry["name"]
            result[entry["display_name"].lower()] = entry["name"]
        if entry.get("name"):
            result[entry["name"]] = entry["name"]
            result[entry["name"].lower()] = entry["name"]
    return result


def create_fields(client, namespace, field_display_names):
    """Create or upsert custom fields. Returns display_name -> internal_name map."""
    existing = build_existing_field_inventory(client, namespace)
    field_map = {}

    for display_name in unique_preserving_order(field_display_names):
        existing_entry = find_existing_field_for_creation(existing, display_name)
        if existing_entry and existing_entry.get("name"):
            field_map[display_name] = existing_entry["name"]
            print(f"  Field EXISTS {existing_entry['name']:20s} -> {display_name}")
            continue

        details = UpsertLogAnalyticsFieldDetails()
        details.display_name = display_name
        details.data_type = field_data_type_for(display_name)
        details.is_multi_valued = False
        try:
            resp = client.upsert_field(namespace, details)
            field_map[display_name] = resp.data.name
            print(f"  Field OK     {resp.data.name:20s} -> {display_name} ({details.data_type})")
        except oci.exceptions.ServiceError as exc:
            if details.data_type == "String" and is_single_value_string_limit_error(exc):
                details.is_multi_valued = True
                try:
                    resp = client.upsert_field(namespace, details)
                    field_map[display_name] = resp.data.name
                    print(
                        f"  Field OK     {resp.data.name:20s} -> {display_name} "
                        "(multi-valued String fallback)"
                    )
                    continue
                except oci.exceptions.ServiceError as retry_exc:
                    exc = retry_exc
            if details.data_type != "String":
                details.data_type = "String"
                try:
                    resp = client.upsert_field(namespace, details)
                    field_map[display_name] = resp.data.name
                    print(
                        f"  Field OK     {resp.data.name:20s} -> {display_name} "
                        "(fallback String)"
                    )
                    continue
                except oci.exceptions.ServiceError as retry_exc:
                    exc = retry_exc
            print(f"  Field ERR    {display_name}: {exc.message}")

    return field_map


def create_parser(client, namespace, parser_name, display_name, description,
                  field_mappings, field_map, example_log):
    """Create or upsert a JSON parser with field mappings."""
    parser_field_maps = []
    for name_or_display, json_path, seq in field_mappings:
        internal = field_map.get(name_or_display) or field_map.get(name_or_display.lower())
        if not internal:
            print(f"  WARNING: Field '{name_or_display}' not found in field_map, skipping from parser")
            continue
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


def find_existing_source(client, namespace, compartment_id, source_internal_name, source_display_name):
    """Find an existing source by internal or display name."""
    candidates = unique_preserving_order([source_internal_name, source_display_name])
    for candidate in candidates:
        try:
            existing = client.list_sources(
                namespace, compartment_id,
                name=candidate, is_system="ALL",
            )
        except Exception:
            continue
        for src in existing.data.items:
            if src.name in candidates or src.display_name == source_display_name:
                return src

    page = None
    while True:
        kwargs = {"limit": 1000, "is_system": "ALL"}
        if page:
            kwargs["page"] = page
        try:
            resp = client.list_sources(namespace, compartment_id, **kwargs)
        except Exception:
            return None
        for src in resp.data.items:
            if src.name in candidates or src.display_name == source_display_name:
                return src
        page = resp.headers.get("opc-next-page")
        if not page:
            return None


def get_source_etag(client, namespace, compartment_id, source_name):
    """Return the current source ETag when OCI requires optimistic concurrency."""
    try:
        response = client.get_source(namespace, source_name, compartment_id)
        return response.headers.get("etag")
    except Exception:
        return None


def create_source(client, namespace, compartment_id, source_internal_name,
                  source_display_name, source_description, parser_name):
    """Create or refresh a Log Analytics source referencing a parser (via OCI CLI)."""
    existing_source = find_existing_source(
        client, namespace, compartment_id, source_internal_name, source_display_name
    )
    source_name = existing_source.name if existing_source else source_internal_name
    etag = get_source_etag(client, namespace, compartment_id, source_name) if existing_source else None
    action = "REFRESH" if existing_source else "OK"

    try:
        if existing_source:
            print(f"  Source EXISTS: {existing_source.name} (display={existing_source.display_name})")
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
            "--name", source_name,
            "--display-name", source_display_name,
            "--description", source_description,
            "--type-name", "os_file",
            "--is-system", "false",
            "--is-for-cloud", "false",
            "--parsers", f"file://{parsers_path}",
            "--entity-types", f"file://{entity_path}",
        ]
        if OCI_PROFILE:
            cmd.extend(["--profile", OCI_PROFILE])
        if etag:
            cmd.extend(["--if-match", etag])
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"  Source {action}: {source_display_name} -> parser {parser_name}")
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
    """Return (bool, reason) when a custom source should not be created.

    Note: We always create SOC custom sources even when native equivalents exist,
    because native sources use XML/built-in parsers that cannot parse our JSON
    test data. The SOC sources use JSON parsers for field extraction.
    """
    if source_display_name in available_sources:
        return False, ""

    # Do NOT skip — always create SOC sources alongside native ones.
    # Native XML parsers can't parse our JSON uploads; SOC JSON parsers can.
    return False, ""


# ─── Main ────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Set up custom OCI LA log sources for SOC detections")
    parser.add_argument("--dry-run", action="store_true", help="Print plan without executing")
    parser.add_argument("--validate", action="store_true", help="Run pre-flight validation checks")
    parser.add_argument(
        "--application-only",
        action="store_true",
        help="Only create/refresh SOC Application Logs fields, parser, and source",
    )
    parser.add_argument(
        "--octo-apm-only",
        action="store_true",
        help="Alias for --application-only, scoped to the Octo APM demo schema",
    )
    parser.add_argument(
        "--field-audit",
        action="store_true",
        help="Inspect namespace fields and report exact reuse versus fields setup would create",
    )
    parser.add_argument(
        "--field-audit-details",
        action="store_true",
        help="With --field-audit, print every exact field reuse mapping",
    )
    args = parser.parse_args()
    octo_apm_only = args.octo_apm_only
    application_only = args.application_only or octo_apm_only

    if args.validate:
        ok = validate_oci_setup(['ocid', 'cli', 'namespace', 'compartment'])
        sys.exit(0 if ok else 1)

    if args.dry_run:
        fields_to_create, field_mappings = select_field_contract(
            octo_apm_only=octo_apm_only,
            application_only=application_only,
        )
        if not application_only:
            field_mappings = []
        print("DRY RUN - would create:")
        print(f"  up to {len(unique_preserving_order(fields_to_create))} custom fields")
        print("  existing namespace fields are reused by exact display name")
        print("  run with --field-audit to inspect live reuse before creating fields")
        if application_only:
            print(f"  1 JSON parser: {APP_PARSER_DISPLAY} ({len(field_mappings)} field maps)")
            print(f"  1 log source: {APP_SOURCE_DISPLAY} ({APP_SOURCE_INTERNAL})")
            return
        print(f"  15 JSON parsers")
        print(f"  up to 15 log sources (SOC sources skipped when native equivalent exists):")
        print(f"    - {LINUX_SOURCE_DISPLAY} ({LINUX_SOURCE_INTERNAL})")
        print(f"    - {WINDOWS_SOURCE_DISPLAY} ({WINDOWS_SOURCE_INTERNAL})")
        print(f"    - {CG_SOURCE_DISPLAY} ({CG_SOURCE_INTERNAL})")
        print(f"    - {WINSEC_SOURCE_DISPLAY} ({WINSEC_SOURCE_INTERNAL})")
        print(f"    - {WINSYS_SOURCE_DISPLAY} ({WINSYS_SOURCE_INTERNAL})")
        print(f"    - {LINSEC_SOURCE_DISPLAY} ({LINSEC_SOURCE_INTERNAL})")
        print(f"    - {SYSMON_SOURCE_DISPLAY} ({SYSMON_SOURCE_INTERNAL})")
        print(f"    - {SYSNET_SOURCE_DISPLAY} ({SYSNET_SOURCE_INTERNAL})")
        print(f"    - {WAF_SOURCE_DISPLAY} ({WAF_SOURCE_INTERNAL})")
        print(f"    - {LB_SOURCE_DISPLAY} ({LB_SOURCE_INTERNAL})")
        print(f"    - {WEBAPP_SOURCE_DISPLAY} ({WEBAPP_SOURCE_INTERNAL})")
        print(f"    - {APP_SOURCE_DISPLAY} ({APP_SOURCE_INTERNAL})")
        print(f"    - {VCN_SOURCE_DISPLAY} ({VCN_SOURCE_INTERNAL})")
        print(f"    - {FW_SOURCE_DISPLAY} ({FW_SOURCE_INTERNAL})")
        print(f"    - {HEALTH_SOURCE_DISPLAY} ({HEALTH_SOURCE_INTERNAL})")
        return

    la_client = get_la_client(timeout=(10, LOG_ANALYTICS_READ_TIMEOUT_SECONDS))

    # Get namespace + active compartment (resolved per-profile)
    namespace = get_namespace(la_client, quiet=args.field_audit)

    fields_to_create, app_field_mappings = select_field_contract(
        octo_apm_only=octo_apm_only,
        application_only=application_only,
    )

    if args.field_audit:
        audit_existing_fields(
            la_client,
            namespace,
            fields_to_create,
            show_exact=args.field_audit_details,
        )
        return

    compartment_id = resolve_compartment_id()
    print("Compartment: resolved from OCI configuration")
    available_sources = list_available_log_sources(la_client, namespace, compartment_id)
    print(f"Discovered {len(available_sources)} existing log sources")

    # Step 1: Create custom fields
    print("\n" + "=" * 60)
    print("STEP 1: CREATE CUSTOM FIELDS")
    print("=" * 60)
    field_map = create_fields(la_client, namespace, fields_to_create)

    # Also load ALL existing fields (including built-in) for parser creation
    all_fields = build_existing_field_map(la_client, namespace)
    field_map.update(all_fields)
    print(f"\n  Total fields available for parser mapping: {len(field_map)}")

    if octo_apm_only:
        missing_fields = missing_octo_apm_workshop_fields(field_map)
        if missing_fields:
            print("\n  Octo APM workshop field readiness FAILED.")
            for field_name in missing_fields:
                print(f"    - missing field: {field_name}")
            sys.exit(2)
        print("  Octo APM workshop field readiness OK")

    # Step 2: Create parsers
    print("\n" + "=" * 60)
    print("STEP 2: CREATE JSON PARSERS")
    print("=" * 60)

    if application_only:
        print("\n--- Application Telemetry Parser ---")
        create_parser(la_client, namespace,
                      APP_PARSER_NAME, APP_PARSER_DISPLAY, APP_PARSER_DESC,
                      app_field_mappings, field_map, APP_EXAMPLE)

        print("\n" + "=" * 60)
        print("STEP 3: CREATE LOG SOURCES")
        print("=" * 60)
        print("\n--- Application Telemetry Source ---")
        create_source(
            la_client, namespace, compartment_id,
            APP_SOURCE_INTERNAL, APP_SOURCE_DISPLAY, APP_SOURCE_DESC, APP_PARSER_NAME
        )
        print("\n" + "=" * 60)
        print("SETUP COMPLETE")
        print("=" * 60)
        print(f"\nConfigured log source/parser:")
        print(f"  - {APP_SOURCE_DISPLAY}")
        return

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

    print("\n--- Sysmon Network Parser ---")
    create_parser(la_client, namespace,
                  SYSNET_PARSER_NAME, SYSNET_PARSER_DISPLAY, SYSNET_PARSER_DESC,
                  SYSNET_FIELD_MAPPINGS, field_map, SYSNET_EXAMPLE)

    print("\n--- WAF Security Parser ---")
    create_parser(la_client, namespace,
                  WAF_PARSER_NAME, WAF_PARSER_DISPLAY, WAF_PARSER_DESC,
                  WAF_FIELD_MAPPINGS, field_map, WAF_EXAMPLE)

    print("\n--- Load Balancer Access Parser ---")
    create_parser(la_client, namespace,
                  LB_PARSER_NAME, LB_PARSER_DISPLAY, LB_PARSER_DESC,
                  LB_FIELD_MAPPINGS, field_map, LB_EXAMPLE)

    print("\n--- Web Application Parser ---")
    create_parser(la_client, namespace,
                  WEBAPP_PARSER_NAME, WEBAPP_PARSER_DISPLAY, WEBAPP_PARSER_DESC,
                  WEBAPP_FIELD_MAPPINGS, field_map, WEBAPP_EXAMPLE)

    print("\n--- Application Telemetry Parser ---")
    create_parser(la_client, namespace,
                  APP_PARSER_NAME, APP_PARSER_DISPLAY, APP_PARSER_DESC,
                  APP_FIELD_MAPPINGS, field_map, APP_EXAMPLE)

    print("\n--- VCN Flow Parser ---")
    create_parser(la_client, namespace,
                  VCN_PARSER_NAME, VCN_PARSER_DISPLAY, VCN_PARSER_DESC,
                  VCN_FIELD_MAPPINGS, field_map, VCN_EXAMPLE)

    print("\n--- Network Firewall Parser ---")
    create_parser(la_client, namespace,
                  FW_PARSER_NAME, FW_PARSER_DISPLAY, FW_PARSER_DESC,
                  FW_FIELD_MAPPINGS, field_map, FW_EXAMPLE)

    print("\n--- Multicloud Health Parser ---")
    create_parser(la_client, namespace,
                  HEALTH_PARSER_NAME, HEALTH_PARSER_DISPLAY, HEALTH_PARSER_DESC,
                  HEALTH_FIELD_MAPPINGS, field_map, HEALTH_EXAMPLE)

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
            la_client, namespace, compartment_id,
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

    print("\n--- Sysmon Network Source ---")
    create_source_if_needed(
        SYSNET_SOURCE_INTERNAL, SYSNET_SOURCE_DISPLAY, SYSNET_SOURCE_DESC, SYSNET_PARSER_NAME
    )

    print("\n--- WAF Security Source ---")
    create_source_if_needed(
        WAF_SOURCE_INTERNAL, WAF_SOURCE_DISPLAY, WAF_SOURCE_DESC, WAF_PARSER_NAME
    )

    print("\n--- Load Balancer Access Source ---")
    create_source_if_needed(
        LB_SOURCE_INTERNAL, LB_SOURCE_DISPLAY, LB_SOURCE_DESC, LB_PARSER_NAME
    )

    print("\n--- Web Application Source ---")
    create_source_if_needed(
        WEBAPP_SOURCE_INTERNAL, WEBAPP_SOURCE_DISPLAY, WEBAPP_SOURCE_DESC, WEBAPP_PARSER_NAME
    )

    print("\n--- Application Telemetry Source ---")
    create_source_if_needed(
        APP_SOURCE_INTERNAL, APP_SOURCE_DISPLAY, APP_SOURCE_DESC, APP_PARSER_NAME
    )

    print("\n--- VCN Flow Source ---")
    create_source_if_needed(
        VCN_SOURCE_INTERNAL, VCN_SOURCE_DISPLAY, VCN_SOURCE_DESC, VCN_PARSER_NAME
    )

    print("\n--- Network Firewall Source ---")
    create_source_if_needed(
        FW_SOURCE_INTERNAL, FW_SOURCE_DISPLAY, FW_SOURCE_DESC, FW_PARSER_NAME
    )

    print("\n--- Multicloud Health Source ---")
    create_source_if_needed(
        HEALTH_SOURCE_INTERNAL, HEALTH_SOURCE_DISPLAY, HEALTH_SOURCE_DESC, HEALTH_PARSER_NAME
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
    print(f"  - {SYSNET_SOURCE_DISPLAY}")
    print(f"  - {WAF_SOURCE_DISPLAY}")
    print(f"  - {LB_SOURCE_DISPLAY}")
    print(f"  - {WEBAPP_SOURCE_DISPLAY}")
    print(f"  - {APP_SOURCE_DISPLAY}")
    print(f"  - {VCN_SOURCE_DISPLAY}")
    print(f"  - {FW_SOURCE_DISPLAY}")
    print(f"  - {HEALTH_SOURCE_DISPLAY}")
    print(f"  - OCI Audit Logs (built-in)")
    print(f"  - OCI Cloud Guard Problems (native, preferred when available)")
    print(f"  - Windows Sysmon Events (native, preferred when available)")
    print(f"\nNext: python3 scripts/convert_sigma.py")


if __name__ == "__main__":
    main()
