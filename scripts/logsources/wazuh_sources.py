"""Wazuh log source + parser definitions for OCI Log Analytics.

Models the Wazuh 4.x indexer document schema (the ``wazuh-alerts-*`` and
``wazuh-states-*`` indices) so GOAD endpoint telemetry forwarded from a Wazuh
manager (e.g. ``oci-wazuh-demo-wazuh-aio`` with agents ``winterfell`` /
``kingslanding`` on ``sevenkingdoms.local``) lands in OCI Log Analytics with the
same visibility the Wazuh dashboard provides: MITRE ATT&CK, Vulnerability
Detection, System Inventory, and Security Configuration Assessment (SCA).

Four sources, mirroring the distinct Wazuh modules:

  * ``SOC Wazuh Alerts``         — rule-engine alerts (MITRE, FIM/syscheck, hunting)
  * ``SOC Wazuh Vulnerabilities``— Vulnerability Detector (CVE/CVSS/package)
  * ``SOC Wazuh Inventory``      — Syscollector hardware/OS/package inventory
  * ``SOC Wazuh SCA``            — Security Configuration Assessment / compliance

Field mappings reuse existing SOC custom fields where the semantics match
(``Event ID``, ``Command Line``, ``Process Name``, ``Host Name``, ``MITRE
Tactic``/``MITRE Technique ID``/``MITRE Technique``, ``File Path``, ``Event
Channel``, ``Provider``, ``Target Filename``, ``Process ID``, ``Vulnerability
ID``) and add Wazuh-specific fields (see WAZUH_CUSTOM_FIELDS below) for the rest.

JSONPaths follow the Wazuh indexer document layout (nested ``data.win.*``,
``rule.mitre.*``, ``vulnerability.*``, ``data.sca.*``, ``data.os``/``data.cpu``).
"""

# New custom fields this module introduces. Registered into CUSTOM_FIELDS via
# field_catalog.py so setup_log_sources creates them before parser creation.
WAZUH_CUSTOM_FIELDS = [
    # alert envelope
    "Agent ID",
    "Manager Name",
    "Wazuh Rule ID",
    "Wazuh Rule Level",        # LONG
    "Rule Description",
    "Rule Groups",
    "Decoder Name",
    "Image",
    "User",
    "Provider Name",
    # FIM / syscheck
    "FIM Event",
    "File Hash",
    # vulnerability detector
    "CVE ID",
    "CVSS Score",              # LONG
    "Package Name",
    "Package Version",
    "Vulnerability Severity",
    "Vulnerability Title",
    "Vulnerability Status",
    "Vulnerability Category",
    # syscollector inventory
    "Cores",                   # LONG
    "CPU Name",
    "Memory GB",               # LONG
    "OS Name",
    "OS Version",
    "Hotfix",
    # security configuration assessment
    "SCA Policy",
    "SCA Score",               # LONG
    "SCA Passed",              # LONG
    "SCA Failed",              # LONG
    "SCA Check Title",
    "SCA Check Result",
    "SCA Compliance",
]

# Fields above that must be created as LONG (numeric) rather than the String default.
WAZUH_LONG_FIELDS = [
    "Wazuh Rule Level",
    "CVSS Score",
    "Cores",
    "Memory GB",
    "SCA Score",
    "SCA Passed",
    "SCA Failed",
]


# ─── SOC Wazuh Alerts (MITRE / FIM / threat hunting) ────────────

WAZUH_ALERTS_PARSER_NAME = "socWazuhAlertsJsonParser"
WAZUH_ALERTS_PARSER_DISPLAY = "SOC Wazuh Alerts JSON Parser"
WAZUH_ALERTS_PARSER_DESC = (
    "Parses Wazuh 4.x wazuh-alerts documents: rule engine metadata "
    "(id/level/description/groups), MITRE ATT&CK (rule.mitre.*), agent identity, "
    "and Windows Sysmon eventdata (data.win.*) plus FIM/syscheck fields."
)
WAZUH_ALERTS_FIELD_MAPPINGS = [
    ("msg",                  "$.full_log",                      1),
    ("time",                 "$.timestamp",                     2),
    ("Agent ID",             "$.agent.id",                      3),
    ("Host Name",            "$.agent.name",                    4),
    ("Manager Name",         "$.manager.name",                  5),
    ("Wazuh Rule ID",        "$.rule.id",                       6),
    ("Wazuh Rule Level",     "$.rule.level",                    7),
    ("Rule Description",     "$.rule.description",              8),
    ("Rule Groups",          "$.rule.groups",                   9),
    ("Decoder Name",         "$.decoder.name",                 10),
    # MITRE ATT&CK (arrays in the source doc; LA stores them searchable).
    ("MITRE Technique ID",   "$.rule.mitre.id",                11),
    ("MITRE Tactic",         "$.rule.mitre.tactic",            12),
    ("MITRE Technique",      "$.rule.mitre.technique",         13),
    # Windows Sysmon system + eventdata (GOAD agents are Windows).
    ("Event ID",             "$.data.win.system.eventID",      14),
    ("Event Channel",        "$.data.win.system.channel",      15),
    ("Provider Name",        "$.data.win.system.providerName", 16),
    ("Image",                "$.data.win.eventdata.image",     17),
    ("Command Line",         "$.data.win.eventdata.commandLine", 18),
    ("Target Filename",      "$.data.win.eventdata.targetFilename", 19),
    ("User",                 "$.data.win.eventdata.user",      20),
    ("Process ID",           "$.data.win.eventdata.processId", 21),
    ("RuleName",             "$.data.win.eventdata.ruleName",  22),
    # FIM / syscheck.
    ("File Path",            "$.syscheck.path",                23),
    ("FIM Event",            "$.syscheck.event",               24),
    ("File Hash",            "$.syscheck.sha256_after",        25),
]
WAZUH_ALERTS_EXAMPLE = {
    "timestamp": "2026-06-24T20:02:06.581Z",
    "agent": {"id": "004", "name": "winterfell", "ip": "192.168.56.11"},
    "manager": {"name": "oci-wazuh-demo-wazuh-aio"},
    "rule": {
        "id": "92052",
        "level": 4,
        "description": "Windows command prompt started by an abnormal process",
        "groups": ["windows", "sysmon", "attack"],
        "mitre": {
            "id": ["T1059.003"],
            "tactic": ["Execution"],
            "technique": ["Windows Command Shell"],
        },
    },
    "decoder": {"name": "windows_eventchannel"},
    "data": {
        "win": {
            "system": {
                "eventID": "1",
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "providerName": "Microsoft-Windows-Sysmon",
                "computer": "winterfell.north.sevenkingdoms.local",
            },
            "eventdata": {
                "image": "C:\\Windows\\System32\\cmd.exe",
                "commandLine": "cmd.exe /c whoami",
                "targetFilename": "",
                "user": "NORTH\\arya.stark",
                "processId": "6624",
                "ruleName": "technique_id=T1059.003,technique_name=Windows Command Shell",
            },
        }
    },
    "full_log": "Windows command prompt started by an abnormal process on winterfell",
}

WAZUH_ALERTS_SOURCE_INTERNAL = "socWazuhAlertsSource"
WAZUH_ALERTS_SOURCE_DISPLAY = "SOC Wazuh Alerts"
WAZUH_ALERTS_SOURCE_DESC = (
    "Wazuh 4.x rule-engine alerts (MITRE ATT&CK, FIM/syscheck, threat hunting) "
    "forwarded from a Wazuh manager to OCI Log Analytics."
)


# ─── SOC Wazuh Vulnerabilities (Vulnerability Detector) ─────────

WAZUH_VULN_PARSER_NAME = "socWazuhVulnJsonParser"
WAZUH_VULN_PARSER_DISPLAY = "SOC Wazuh Vulnerability JSON Parser"
WAZUH_VULN_PARSER_DESC = (
    "Parses Wazuh 4.x vulnerability-detector documents: CVE, severity, CVSS "
    "base score, affected package, and agent identity."
)
WAZUH_VULN_FIELD_MAPPINGS = [
    ("msg",                    "$.full_log",                  1),
    ("time",                   "$.timestamp",                 2),
    ("Agent ID",               "$.agent.id",                  3),
    ("Host Name",              "$.agent.name",                4),
    ("CVE ID",                 "$.vulnerability.cve",         5),
    ("Vulnerability ID",       "$.vulnerability.cve",         6),
    ("Vulnerability Severity", "$.vulnerability.severity",    7),
    ("CVSS Score",             "$.vulnerability.score.base",  8),
    ("Package Name",           "$.vulnerability.package.name", 9),
    ("Package Version",        "$.vulnerability.package.version", 10),
    ("Vulnerability Title",    "$.vulnerability.title",      11),
    ("Vulnerability Status",   "$.vulnerability.status",     12),
    ("Vulnerability Category", "$.vulnerability.category",   13),
    ("OS Name",                "$.agent.os.name",            14),
]
WAZUH_VULN_EXAMPLE = {
    "timestamp": "2026-06-24T22:32:14.000Z",
    "agent": {"id": "003", "name": "kingslanding",
              "os": {"name": "Microsoft Windows Server 2019 Standard"}},
    "vulnerability": {
        "cve": "CVE-2024-30080",
        "severity": "Critical",
        "score": {"base": 9.8, "version": "3.1"},
        "package": {"name": "Microsoft Windows Server 2019 Standard", "version": "10.0.17763.5329"},
        "title": "Microsoft Message Queuing (MSMQ) Remote Code Execution Vulnerability",
        "status": "Active",
        "category": "Packages",
        "published_at": "2024-06-11T00:00:00Z",
    },
    "full_log": "CVE-2024-30080 affects Microsoft Windows Server 2019 Standard",
}

WAZUH_VULN_SOURCE_INTERNAL = "socWazuhVulnSource"
WAZUH_VULN_SOURCE_DISPLAY = "SOC Wazuh Vulnerabilities"
WAZUH_VULN_SOURCE_DESC = (
    "Wazuh 4.x Vulnerability Detector findings (CVE/CVSS/package) per agent."
)


# ─── SOC Wazuh Inventory (Syscollector) ─────────────────────────

WAZUH_INV_PARSER_NAME = "socWazuhInventoryJsonParser"
WAZUH_INV_PARSER_DISPLAY = "SOC Wazuh Inventory JSON Parser"
WAZUH_INV_PARSER_DESC = (
    "Parses Wazuh 4.x syscollector documents: hardware (cores/CPU/RAM), OS, "
    "installed packages and hotfixes per agent."
)
WAZUH_INV_FIELD_MAPPINGS = [
    ("msg",             "$.full_log",            1),
    ("time",            "$.timestamp",           2),
    ("Agent ID",        "$.agent.id",            3),
    ("Host Name",       "$.agent.name",          4),
    ("Cores",           "$.data.cpu.cores",      5),
    ("CPU Name",        "$.data.cpu.name",       6),
    ("Memory GB",       "$.data.ram.total_gb",   7),
    ("OS Name",         "$.data.os.name",        8),
    ("OS Version",      "$.data.os.version",     9),
    ("Package Name",    "$.data.program.name",  10),
    ("Package Version", "$.data.program.version", 11),
    ("Hotfix",          "$.data.hotfix",        12),
]
WAZUH_INV_EXAMPLE = {
    "timestamp": "2026-06-24T22:31:47.000Z",
    "agent": {"id": "003", "name": "kingslanding"},
    "data": {
        "cpu": {"cores": 4, "name": "AMD EPYC 9J14 96-Core Processor"},
        "ram": {"total_gb": 32},
        "os": {"name": "Microsoft Windows Server 2019 Standard", "version": "10.0.17763.5329"},
        "program": {"name": "Mozilla Firefox (x64 en-US)", "version": "127.0"},
        "hotfix": "KB5039217",
    },
    "full_log": "syscollector inventory for kingslanding",
}

WAZUH_INV_SOURCE_INTERNAL = "socWazuhInventorySource"
WAZUH_INV_SOURCE_DISPLAY = "SOC Wazuh Inventory"
WAZUH_INV_SOURCE_DESC = (
    "Wazuh 4.x Syscollector inventory (hardware, OS, packages, hotfixes) per agent."
)


# ─── SOC Wazuh SCA (Security Configuration Assessment) ──────────

WAZUH_SCA_PARSER_NAME = "socWazuhScaJsonParser"
WAZUH_SCA_PARSER_DISPLAY = "SOC Wazuh SCA JSON Parser"
WAZUH_SCA_PARSER_DESC = (
    "Parses Wazuh 4.x Security Configuration Assessment documents: policy, "
    "pass/fail counts, score, per-check result and compliance mappings (CIS/PCI)."
)
WAZUH_SCA_FIELD_MAPPINGS = [
    ("msg",              "$.full_log",                 1),
    ("time",             "$.timestamp",                2),
    ("Agent ID",         "$.agent.id",                 3),
    ("Host Name",        "$.agent.name",               4),
    ("SCA Policy",       "$.data.sca.policy",          5),
    ("SCA Score",        "$.data.sca.score",           6),
    ("SCA Passed",       "$.data.sca.passed",          7),
    ("SCA Failed",       "$.data.sca.failed",          8),
    ("SCA Check Title",  "$.data.sca.check.title",     9),
    ("SCA Check Result", "$.data.sca.check.result",   10),
    ("SCA Compliance",   "$.data.sca.check.compliance", 11),
]
WAZUH_SCA_EXAMPLE = {
    "timestamp": "2026-06-24T22:32:14.000Z",
    "agent": {"id": "003", "name": "kingslanding"},
    "data": {
        "sca": {
            "policy": "CIS Microsoft Windows Server 2019 Benchmark v2.0.0",
            "score": 25,
            "passed": 87,
            "failed": 260,
            "check": {
                "title": "Ensure 'Enforce password history' is set to '24 or more password(s)'",
                "result": "failed",
                "compliance": "PCI DSS 8.2.5; CIS 1.1.1",
            },
        }
    },
    "full_log": "SCA scan CIS Microsoft Windows Server 2019 Benchmark v2.0.0 on kingslanding",
}

WAZUH_SCA_SOURCE_INTERNAL = "socWazuhScaSource"
WAZUH_SCA_SOURCE_DISPLAY = "SOC Wazuh SCA"
WAZUH_SCA_SOURCE_DESC = (
    "Wazuh 4.x Security Configuration Assessment results (CIS/PCI policy "
    "pass/fail/score) per agent."
)


# Convenience tuples consumed by setup_log_sources.py.
WAZUH_PARSER_SPECS = [
    (WAZUH_ALERTS_PARSER_NAME, WAZUH_ALERTS_PARSER_DISPLAY, WAZUH_ALERTS_PARSER_DESC,
     WAZUH_ALERTS_FIELD_MAPPINGS, WAZUH_ALERTS_EXAMPLE),
    (WAZUH_VULN_PARSER_NAME, WAZUH_VULN_PARSER_DISPLAY, WAZUH_VULN_PARSER_DESC,
     WAZUH_VULN_FIELD_MAPPINGS, WAZUH_VULN_EXAMPLE),
    (WAZUH_INV_PARSER_NAME, WAZUH_INV_PARSER_DISPLAY, WAZUH_INV_PARSER_DESC,
     WAZUH_INV_FIELD_MAPPINGS, WAZUH_INV_EXAMPLE),
    (WAZUH_SCA_PARSER_NAME, WAZUH_SCA_PARSER_DISPLAY, WAZUH_SCA_PARSER_DESC,
     WAZUH_SCA_FIELD_MAPPINGS, WAZUH_SCA_EXAMPLE),
]
WAZUH_SOURCE_SPECS = [
    (WAZUH_ALERTS_SOURCE_INTERNAL, WAZUH_ALERTS_SOURCE_DISPLAY, WAZUH_ALERTS_SOURCE_DESC, WAZUH_ALERTS_PARSER_NAME),
    (WAZUH_VULN_SOURCE_INTERNAL, WAZUH_VULN_SOURCE_DISPLAY, WAZUH_VULN_SOURCE_DESC, WAZUH_VULN_PARSER_NAME),
    (WAZUH_INV_SOURCE_INTERNAL, WAZUH_INV_SOURCE_DISPLAY, WAZUH_INV_SOURCE_DESC, WAZUH_INV_PARSER_NAME),
    (WAZUH_SCA_SOURCE_INTERNAL, WAZUH_SCA_SOURCE_DISPLAY, WAZUH_SCA_SOURCE_DESC, WAZUH_SCA_PARSER_NAME),
]
