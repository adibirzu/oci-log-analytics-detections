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
    TENANCY_ID, COMPARTMENT_ID, OCI_PROFILE,
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
    "Source Port",
    "Auth Method",
    "Session Type",
    "Service Name",
    "Process",
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
    "Request Body",
    "Content Type",
    "Referrer",
    "Request Headers",
    "WAF Policy",
    "Threat Feeds",
    "Fingerprint",
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
    "msg": "IDOR: Unauthorized access to user profile id=1",
}

WEBAPP_SOURCE_INTERNAL = "socWebAppSource"
WEBAPP_SOURCE_DISPLAY = "SOC Web Application Logs"
WEBAPP_SOURCE_DESC = (
    "Web application security events from Seven Kingdoms Portal for OWASP attack detection."
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
    HEALTH_SOURCE_DISPLAY: [],
}


# ─── Helper Functions ────────────────────────────────────────────

def build_existing_field_map(client, namespace):
    """Fetch all existing fields and return name -> internal_name map.

    Supports lookup by both display_name and internal_name, so parser
    field mappings can reference either (e.g., built-in 'msg' and 'time').
    """
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
            if f.name:
                result[f.name] = f.name
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
        internal = field_map.get(name_or_display)
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
        if OCI_PROFILE:
            cmd.extend(["--profile", OCI_PROFILE])
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
        print(f"  12 JSON parsers")
        print(f"  up to 12 log sources (SOC sources skipped when native equivalent exists):")
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
        print(f"    - {HEALTH_SOURCE_DISPLAY} ({HEALTH_SOURCE_INTERNAL})")
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
    print(f"  - {HEALTH_SOURCE_DISPLAY}")
    print(f"  - OCI Audit Logs (built-in)")
    print(f"  - OCI Cloud Guard Problems (native, preferred when available)")
    print(f"  - Windows Sysmon Events (native, preferred when available)")
    print(f"\nNext: python3 scripts/convert_sigma.py")


if __name__ == "__main__":
    main()
