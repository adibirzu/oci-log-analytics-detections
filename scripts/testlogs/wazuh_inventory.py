"""Synthetic SOC Wazuh Inventory events (Syscollector hardware/OS/packages).

Emits Wazuh 4.x syscollector documents matching the canonical schema in
``scripts/logsources/wazuh_sources.py`` (``WAZUH_INV_EXAMPLE`` /
``WAZUH_INV_FIELD_MAPPINGS``). One hardware/OS record plus a set of installed
program and hotfix records per GOAD agent.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from testlogs.common import *  # noqa: F401,F403

WIN2019_OS = "Microsoft Windows Server 2019 Standard"
WIN2019_VER = "10.0.17763.5329"
CPU_NAME = "AMD EPYC 9J14 96-Core Processor"

# (id, name, cores, ram_gb)
INV_AGENTS = [
    ("003", "kingslanding", 4, 32),
    ("004", "winterfell", 4, 16),
    ("005", "meereen", 2, 8),
    ("002", "castelblack", 2, 8),
    ("006", "braavos", 2, 8),
]

PROGRAMS = [
    ("Mozilla Firefox (x64 en-US)", "127.0"),
    ("Microsoft Edge", "126.0.2592.81"),
    ("Microsoft Visual C++ 2015-2022 Redistributable (x64)", "14.40.33810"),
    ("Wazuh Agent", "4.9.0"),
    ("Sysmon", "15.14"),
    ("7-Zip 23.01 (x64)", "23.01"),
    ("Windows Defender", "4.18.24070.5"),
    ("PowerShell 7-x64", "7.4.3"),
]

HOTFIXES = [
    "KB5039217", "KB5037782", "KB5040430", "KB5041578", "KB5005112",
]


def _base(agent, offset):
    return {
        "timestamp": ts(offset),
        "agent": {"id": agent[0], "name": agent[1]},
    }


def generate_wazuh_inventory_events():
    """Generate the SOC Wazuh Inventory corpus (hardware/OS/packages/hotfix)."""
    events = []
    offset = 0

    for agent in INV_AGENTS:
        agent_id, agent_name, cores, ram_gb = agent

        # Hardware + OS record (full data envelope).
        offset += 1
        hw = _base(agent, offset)
        hw["data"] = {
            "cpu": {"cores": cores, "name": CPU_NAME},
            "ram": {"total_gb": ram_gb},
            "os": {"name": WIN2019_OS, "version": WIN2019_VER},
            "program": {"name": "Mozilla Firefox (x64 en-US)", "version": "127.0"},
            "hotfix": HOTFIXES[0],
        }
        hw["full_log"] = f"syscollector hardware inventory for {agent_name}"
        events.append(hw)

        # Per-program records.
        for prog_name, prog_ver in PROGRAMS:
            offset += 1
            rec = _base(agent, offset)
            rec["data"] = {
                "cpu": {"cores": cores, "name": CPU_NAME},
                "ram": {"total_gb": ram_gb},
                "os": {"name": WIN2019_OS, "version": WIN2019_VER},
                "program": {"name": prog_name, "version": prog_ver},
                "hotfix": "",
            }
            rec["full_log"] = f"syscollector package {prog_name} {prog_ver} on {agent_name}"
            events.append(rec)

        # Per-hotfix records.
        for hotfix in HOTFIXES:
            offset += 1
            rec = _base(agent, offset)
            rec["data"] = {
                "cpu": {"cores": cores, "name": CPU_NAME},
                "ram": {"total_gb": ram_gb},
                "os": {"name": WIN2019_OS, "version": WIN2019_VER},
                "program": {"name": "", "version": ""},
                "hotfix": hotfix,
            }
            rec["full_log"] = f"syscollector hotfix {hotfix} on {agent_name}"
            events.append(rec)

    return events
