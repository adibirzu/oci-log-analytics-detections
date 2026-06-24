"""Synthetic SOC Wazuh Vulnerabilities events (Vulnerability Detector).

Emits Wazuh 4.x vulnerability-detector documents matching the canonical schema
in ``scripts/logsources/wazuh_sources.py`` (``WAZUH_VULN_EXAMPLE`` /
``WAZUH_VULN_FIELD_MAPPINGS``). Findings are spread across the GOAD Windows
agents (kingslanding / winterfell) using real 2024 Windows Server CVEs plus a
set of Mozilla Firefox CVEs, with CVSS base scores in the 7.0-9.9 band.
"""
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from testlogs.common import *  # noqa: F401,F403

WIN2019_OS = "Microsoft Windows Server 2019 Standard"
WIN2019_PKG_VER = "10.0.17763.5329"
FIREFOX_PKG = "Mozilla Firefox (x64 en-US)"
FIREFOX_PKG_VER = "127.0"

VULN_AGENTS = [
    ("003", "kingslanding"),
    ("004", "winterfell"),
]

# (cve, severity, base_score, title) — real Windows Server 2019 CVEs from 2024.
WIN_CVES = [
    ("CVE-2024-30080", "Critical", 9.8, "Microsoft Message Queuing (MSMQ) Remote Code Execution Vulnerability"),
    ("CVE-2024-38063", "Critical", 9.8, "Windows TCP/IP Remote Code Execution Vulnerability"),
    ("CVE-2024-38074", "Critical", 9.8, "Windows Remote Desktop Licensing Service Remote Code Execution Vulnerability"),
    ("CVE-2024-38076", "Critical", 9.8, "Windows Remote Desktop Licensing Service Remote Code Execution Vulnerability"),
    ("CVE-2024-38077", "Critical", 9.8, "Windows Remote Desktop Licensing Service Remote Code Execution Vulnerability"),
    ("CVE-2024-21407", "High", 8.1, "Windows Hyper-V Remote Code Execution Vulnerability"),
    ("CVE-2024-21412", "High", 8.1, "Internet Shortcut Files Security Feature Bypass Vulnerability"),
    ("CVE-2024-26169", "High", 7.8, "Windows Error Reporting Service Elevation of Privilege Vulnerability"),
    ("CVE-2024-29988", "High", 8.8, "SmartScreen Prompt Security Feature Bypass Vulnerability"),
    ("CVE-2024-30051", "High", 7.8, "Windows DWM Core Library Elevation of Privilege Vulnerability"),
    ("CVE-2024-38080", "High", 7.8, "Windows Hyper-V Elevation of Privilege Vulnerability"),
    ("CVE-2024-38112", "High", 7.5, "Windows MSHTML Platform Spoofing Vulnerability"),
    ("CVE-2024-38193", "High", 7.8, "Windows Ancillary Function Driver for WinSock Elevation of Privilege Vulnerability"),
    ("CVE-2024-43491", "Critical", 9.8, "Microsoft Windows Update Remote Code Execution Vulnerability"),
    ("CVE-2024-49039", "High", 8.8, "Windows Task Scheduler Elevation of Privilege Vulnerability"),
    ("CVE-2024-35250", "High", 7.8, "Windows Kernel-Mode Driver Elevation of Privilege Vulnerability"),
    ("CVE-2024-30088", "High", 7.0, "Windows Kernel Elevation of Privilege Vulnerability"),
    ("CVE-2024-26229", "High", 7.8, "Windows CSC Service Elevation of Privilege Vulnerability"),
    ("CVE-2024-38202", "High", 7.3, "Windows Update Stack Elevation of Privilege Vulnerability"),
    ("CVE-2024-21338", "High", 7.8, "Windows Kernel Elevation of Privilege Vulnerability"),
]

# (cve, severity, base_score, title) — Mozilla Firefox CVEs.
FIREFOX_CVES = [
    ("CVE-2024-4367", "High", 8.8, "Arbitrary JavaScript execution in PDF.js"),
    ("CVE-2024-5274", "High", 8.8, "Type confusion in V8 affecting Firefox-bundled component"),
    ("CVE-2024-6602", "Critical", 9.1, "Memory corruption in NSS leading to RCE"),
    ("CVE-2024-6606", "High", 8.1, "Out-of-bounds read when scanning for nameservers"),
    ("CVE-2024-7518", "High", 7.5, "Fullscreen notification dialog spoofing"),
    ("CVE-2024-7521", "High", 8.8, "Incomplete WebAssembly exception handling use-after-free"),
    ("CVE-2024-7525", "High", 7.4, "Missing permission check when creating StreamFilter"),
    ("CVE-2024-7526", "High", 7.5, "Uninitialized memory used by ANGLE"),
    ("CVE-2024-8381", "Critical", 9.8, "Type confusion when looking up a property name in object"),
    ("CVE-2024-8385", "High", 8.1, "WASM type confusion involving ArrayTypes"),
]


def _vuln(agent, cve, severity, base, title, package, package_version, os_name, offset):
    return {
        "timestamp": ts(offset),
        "agent": {"id": agent[0], "name": agent[1], "os": {"name": os_name}},
        "vulnerability": {
            "cve": cve,
            "severity": severity,
            "score": {"base": base, "version": "3.1"},
            "package": {"name": package, "version": package_version},
            "title": title,
            "status": random.choice(["Active", "Active", "Active", "Solved"]),
            "category": "Packages",
            "published_at": "2024-08-13T00:00:00Z",
        },
        "full_log": f"{cve} ({severity}) affects {package} on {agent[1]}",
    }


def generate_wazuh_vulnerabilities_events():
    """Generate the SOC Wazuh Vulnerabilities corpus (~60 CVEs across hosts)."""
    events = []
    offset = 0

    # Windows Server CVEs against both Windows agents (20 CVEs * 2 agents = 40).
    for agent in VULN_AGENTS:
        for cve, severity, base, title in WIN_CVES:
            offset += 1
            events.append(_vuln(
                agent, cve, severity, base, title,
                package=WIN2019_OS, package_version=WIN2019_PKG_VER,
                os_name=WIN2019_OS, offset=offset,
            ))

    # Firefox CVEs against both Windows agents (10 CVEs * 2 agents = 20).
    for agent in VULN_AGENTS:
        for cve, severity, base, title in FIREFOX_CVES:
            offset += 1
            events.append(_vuln(
                agent, cve, severity, base, title,
                package=FIREFOX_PKG, package_version=FIREFOX_PKG_VER,
                os_name=WIN2019_OS, offset=offset,
            ))

    random.shuffle(events)
    return events
