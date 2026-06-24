"""Synthetic SOC Wazuh SCA events (Security Configuration Assessment).

Emits Wazuh 4.x SCA documents matching the canonical schema in
``scripts/logsources/wazuh_sources.py`` (``WAZUH_SCA_EXAMPLE`` /
``WAZUH_SCA_FIELD_MAPPINGS``). Each GOAD agent gets a summary row (policy,
score 25, passed 87, failed 260) plus a set of per-check rows carrying
compliance strings (CIS / PCI DSS).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from testlogs.common import *  # noqa: F401,F403

SCA_POLICY = "CIS Microsoft Windows Server 2019 Benchmark v2.0.0"
SCA_SCORE = 25
SCA_PASSED = 87
SCA_FAILED = 260

SCA_AGENTS = [
    ("003", "kingslanding"),
    ("004", "winterfell"),
    ("005", "meereen"),
    ("002", "castelblack"),
    ("006", "braavos"),
]

# (title, result, compliance) — per-check rows.
SCA_CHECKS = [
    ("Ensure 'Enforce password history' is set to '24 or more password(s)'",
     "failed", "PCI DSS 8.2.5; CIS 1.1.1"),
    ("Ensure 'Minimum password length' is set to '14 or more character(s)'",
     "failed", "PCI DSS 8.2.3; CIS 1.1.4"),
    ("Ensure 'Account lockout threshold' is set to '5 or fewer invalid logon attempt(s)'",
     "failed", "PCI DSS 8.1.6; CIS 1.2.2"),
    ("Ensure 'Audit: Force audit policy subcategory settings' is set to 'Enabled'",
     "passed", "PCI DSS 10.2; CIS 2.3.2.1"),
    ("Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'",
     "passed", "PCI DSS 7.1; CIS 2.3.10.2"),
    ("Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'",
     "failed", "CIS 2.3.7.1"),
    ("Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'",
     "passed", "PCI DSS 1.1; CIS 9.1.1"),
    ("Ensure 'Turn on PowerShell Script Block Logging' is set to 'Enabled'",
     "failed", "CIS 18.9.100.1"),
    ("Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver'",
     "failed", "CIS 18.4.3"),
    ("Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'",
     "passed", "CIS 18.9.7.2"),
    ("Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled'",
     "failed", "CIS 2.3.17.1"),
    ("Ensure 'Audit Credential Validation' is set to 'Success and Failure'",
     "failed", "PCI DSS 10.2.4; CIS 17.1.1"),
]


def generate_wazuh_sca_events():
    """Generate the SOC Wazuh SCA corpus (summary + per-check rows per host)."""
    events = []
    offset = 0

    for agent in SCA_AGENTS:
        agent_id, agent_name = agent

        # Policy summary row.
        offset += 1
        summary = {
            "timestamp": ts(offset),
            "agent": {"id": agent_id, "name": agent_name},
            "data": {
                "sca": {
                    "policy": SCA_POLICY,
                    "score": SCA_SCORE,
                    "passed": SCA_PASSED,
                    "failed": SCA_FAILED,
                    "check": {
                        "title": "SCA scan summary",
                        "result": "summary",
                        "compliance": "CIS Microsoft Windows Server 2019 Benchmark",
                    },
                }
            },
            "full_log": f"SCA scan {SCA_POLICY} on {agent_name}: score {SCA_SCORE} "
                        f"(passed {SCA_PASSED}, failed {SCA_FAILED})",
        }
        events.append(summary)

        # Per-check rows.
        for title, result, compliance in SCA_CHECKS:
            offset += 1
            events.append({
                "timestamp": ts(offset),
                "agent": {"id": agent_id, "name": agent_name},
                "data": {
                    "sca": {
                        "policy": SCA_POLICY,
                        "score": SCA_SCORE,
                        "passed": SCA_PASSED,
                        "failed": SCA_FAILED,
                        "check": {
                            "title": title,
                            "result": result,
                            "compliance": compliance,
                        },
                    }
                },
                "full_log": f"SCA check [{result}] {title} on {agent_name}",
            })

    return events
