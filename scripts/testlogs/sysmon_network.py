"""Auto-extracted from generate_test_logs.py — Sysmon network-connection synthetic events.

Behavior-preserving split: function bodies are unchanged. Shared constants and
helpers live in ``testlogs.common`` and are imported via star import.
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
from testlogs.common import *  # noqa: F401,F403


def sysmon_network_event(host=None, user=None, image=None, protocol="tcp",
                         src_ip=None, src_port=None, dst_ip=None, dst_port=None,
                         dst_hostname=None, initiated="true", rule_name=None,
                         technique_name=None, technique_id=None, msg=None, offset=0):
    """Generate a Sysmon Event ID 3 (Network Connection) for the network parser.

    Uses OCI Log Analytics field names for query compatibility alongside
    Sysmon-native field names for reference.
    """
    if host is None:
        host = random.choice(SEVEN_KINGDOMS_HOSTS)
    if user is None:
        user = random.choice(THREAT_ACTORS)
    if src_ip is None:
        src_ip = random.choice(CORPORATE_IPS)
    if src_port is None:
        src_port = random.randint(49152, 65535)
    proc = image or "C:\\Windows\\System32\\cmd.exe"
    return {
        # OCI Log Analytics mapped fields
        "Event ID": 3,
        "Host Name (Server)": host,
        "Process Name": proc,
        "Source IP": src_ip,
        "Source Port": src_port,
        "Destination IP": dst_ip or "",
        "Destination Port": dst_port or 443,
        "Destination Hostname": dst_hostname or "",
        "Technique Name": technique_name or "",
        "Technique ID": technique_id or "",
        # Sysmon-native fields (for raw reference)
        "@timestamp": ts(offset),
        "EventID": 3,
        "Computer": host,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "User": user,
        "Image": proc,
        "Protocol": protocol,
        "SourceIp": src_ip,
        "SourcePort": src_port,
        "DestinationIp": dst_ip or "",
        "DestinationPort": dst_port or 443,
        "DestinationHostname": dst_hostname or "",
        "Initiated": initiated,
        "RuleName": rule_name or "",
        "TechniqueName": technique_name or "",
        "TechniqueId": technique_id or "",
        "AccountName": user.split("\\")[-1] if "\\" in user else user,
        "msg": msg or f"Network connection: {proc} -> {dst_ip}:{dst_port}",
    }


def generate_sysmon_network_events():
    """Generate Sysmon Event ID 3 (network connection) events for all attack scenarios."""
    events = []
    c2_ips = ["185.215.113.206", "103.253.41.45", "89.34.111.113", "5.252.178.48"]

    # ── Lateral Movement: SMB (port 445) ──
    smb_tools = [
        "C:\\Windows\\System32\\psexec.exe",
        "C:\\Windows\\System32\\net.exe",
        "C:\\Windows\\System32\\cmd.exe",
        "C:\\Windows\\System32\\powershell.exe",
        "C:\\Windows\\System32\\robocopy.exe",
    ]
    for i, tool in enumerate(smb_tools):
        for j in range(4):
            events.append(sysmon_network_event(
                image=tool, dst_ip=random.choice(CORPORATE_IPS), dst_port=445,
                protocol="tcp", technique_name="SMB/Windows Admin Shares",
                technique_id="T1021.002",
                msg=f"SMB lateral movement: {tool.split(chr(92))[-1]} -> 445",
                offset=i * 5 + j,
            ))

    # ── Lateral Movement: WinRM (port 5985/5986) ──
    for i in range(8):
        events.append(sysmon_network_event(
            image=random.choice([
                "C:\\Windows\\System32\\powershell.exe",
                "C:\\Windows\\System32\\wsmprovhost.exe",
            ]),
            dst_ip=random.choice(CORPORATE_IPS), dst_port=random.choice([5985, 5986]),
            technique_name="Windows Remote Management", technique_id="T1021.006",
            msg="WinRM lateral movement",
            offset=50 + i,
        ))

    # ── Lateral Movement: RDP (port 3389) ──
    for i in range(6):
        events.append(sysmon_network_event(
            image=random.choice([
                "C:\\Windows\\System32\\mstsc.exe",
                "C:\\Windows\\System32\\cmd.exe",
            ]),
            dst_ip=random.choice(CORPORATE_IPS), dst_port=3389,
            technique_name="Remote Desktop Protocol", technique_id="T1021.001",
            msg="RDP lateral movement",
            offset=70 + i,
        ))

    # ── C2 Beacon: HTTPS to suspicious IPs ──
    beacon_procs = [
        "C:\\Windows\\System32\\rundll32.exe",
        "C:\\Windows\\System32\\regsvr32.exe",
        "C:\\Windows\\System32\\powershell.exe",
        "C:\\Windows\\System32\\cmd.exe",
        "C:\\Windows\\System32\\certutil.exe",
        "C:\\Windows\\System32\\mshta.exe",
    ]
    for i, proc in enumerate(beacon_procs):
        for j in range(5):
            events.append(sysmon_network_event(
                image=proc, dst_ip=random.choice(c2_ips),
                dst_port=random.choice([443, 8443, 4443, 8080]),
                dst_hostname=random.choice([
                    "evil-c2.duckdns.org", "beacon.malware.xyz",
                    "update.evil.cc", "cdn-static.attacker.top",
                ]),
                technique_name="Application Layer Protocol", technique_id="T1071.001",
                msg=f"C2 beacon: {proc.split(chr(92))[-1]} -> HTTPS",
                offset=100 + i * 6 + j,
            ))

    # FreeLabFriday domain-fronting C2 candidates: non-browser processes
    # repeatedly contacting trusted CDN/cloud endpoints over HTTPS.
    domain_fronting_targets = [
        ("d111111abcdef8.cloudfront.net", "13.32.99.20"),
        ("front-door-prod.azureedge.net", "152.199.19.160"),
        ("quiet-worker.workers.dev", "104.21.48.10"),
    ]
    for i, (cdn_host, cdn_ip) in enumerate(domain_fronting_targets):
        for j in range(3):
            events.append(sysmon_network_event(
                host="WS02.sevenkingdoms.local",
                user="arya",
                image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                dst_ip=cdn_ip,
                dst_port=443,
                dst_hostname=cdn_host,
                technique_name="Domain Fronting",
                technique_id="T1090.004",
                msg=f"FreeLabFriday domain-fronting candidate: powershell.exe -> {cdn_host}",
                offset=136 + i * 3 + j,
            ))

    clickfix_network_targets = [
        (CLICKFIX_C2_HOST, CLICKFIX_C2_IP, "ClickFix payload retrieval"),
        ("crashfix-help.example", "203.0.113.201", "CrashFix Python RAT callback"),
    ]
    for i, (hostname, dst_ip, label) in enumerate(clickfix_network_targets):
        for j in range(3):
            event = sysmon_network_event(
                host=CLICKFIX_COMPROMISED_HOST,
                user="CORP\\arya",
                image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" if i == 0 else "C:\\Users\\Public\\Python311\\python.exe",
                src_ip=CLICKFIX_COMPROMISED_PRIVATE_IP,
                dst_ip=dst_ip,
                dst_port=443,
                dst_hostname=hostname,
                technique_name="Application Layer Protocol",
                technique_id="T1071.001",
                msg=label,
                offset=150 + i * 4 + j,
            )
            event["Trace ID"] = CLICKFIX_TRACE_ID
            event["Attack Stage"] = "command_and_control"
            event["Threat Name"] = label
            events.append(event)

    rmm_network_targets = [
        ("relay.screenconnect.example", "203.0.113.210", "C:\\Program Files (x86)\\ScreenConnect Client (d4f1)\\ScreenConnect.ClientService.exe"),
        ("rmm-sync.atera.example", "203.0.113.211", "C:\\Program Files\\Atera Networks\\AteraAgent.exe"),
    ]
    for i, (hostname, dst_ip, image) in enumerate(rmm_network_targets):
        for j in range(4):
            event = sysmon_network_event(
                host=CLICKFIX_COMPROMISED_HOST,
                user="CORP\\arya",
                image=image,
                src_ip=CLICKFIX_COMPROMISED_PRIVATE_IP,
                dst_ip=dst_ip,
                dst_port=443,
                dst_hostname=hostname,
                technique_name="Remote Access Software",
                technique_id="T1219",
                msg=f"RMM post-compromise relay: {hostname}",
                offset=160 + i * 5 + j,
            )
            event["Trace ID"] = RMM_TRACE_ID
            event["Attack Stage"] = "remote_access"
            event["Threat Name"] = "RMM Tool Abuse"
            events.append(event)

    # BLUELIGHT-style drive-by compromise: iexplore.exe reaching non-Microsoft hosts.
    drive_by_hosts = [
        ("jquery.services", "203.0.113.45"),
        ("malicious-news.example.com", "198.51.100.20"),
        ("watering-hole.attacker.top", "203.0.113.99"),
        ("compromised-cdn.bad.example", "198.51.100.55"),
    ]
    for i, (host, ip) in enumerate(drive_by_hosts):
        for j in range(3):
            events.append(sysmon_network_event(
                host="WS01.sevenkingdoms.local", user="joffrey",
                image="C:\\Program Files\\Internet Explorer\\iexplore.exe",
                dst_ip=ip, dst_port=443, dst_hostname=host,
                technique_name="Drive-by Compromise", technique_id="T1189",
                msg=f"BLUELIGHT drive-by: iexplore -> {host}",
                offset=120 + i * 4 + j,
            ))

    # BLUELIGHT YARA Google App C2: non-browser process reaching Google services.
    google_c2_hosts = ["mail.google.com", "myaccount.google.com"]
    google_procs = [
        "C:\\Users\\Public\\bluelight.exe",
        "C:\\Windows\\System32\\rundll32.exe",
    ]
    for i, proc in enumerate(google_procs):
        for j, host in enumerate(google_c2_hosts):
            events.append(sysmon_network_event(
                host="WS01.sevenkingdoms.local", user="joffrey",
                image=proc, dst_ip="142.250.80.46", dst_port=443,
                dst_hostname=host,
                technique_name="Application Layer Protocol",
                technique_id="T1071.001",
                msg=f"BLUELIGHT YARA: Google App C2 from {proc.split(chr(92))[-1]}",
                offset=135 + i * 2 + j,
            ))

    # BLUELIGHT-style Microsoft Graph / cloud storage C2 traffic.
    graph_procs = [
        "C:\\Users\\Public\\bluelight.exe",
        "C:\\Windows\\System32\\rundll32.exe",
        "C:\\Windows\\System32\\powershell.exe",
    ]
    for i, proc in enumerate(graph_procs):
        for j in range(4):
            events.append(sysmon_network_event(
                image=proc,
                dst_ip=random.choice(c2_ips),
                dst_port=443,
                dst_hostname=random.choice(["graph.microsoft.com", "login.microsoftonline.com"]),
                technique_name="Application Layer Protocol",
                technique_id="T1071.001",
                msg=f"Cloud API beacon: {proc.split(chr(92))[-1]} -> Microsoft Graph",
                offset=145 + i * 5 + j,
            ))

    for i in range(4):
        events.append(sysmon_network_event(
            host="WS01.sevenkingdoms.local",
            user="joffrey",
            image="C:\\Users\\Public\\bluelight.exe",
            dst_ip=random.choice(c2_ips),
            dst_port=443,
            dst_hostname="graph.microsoft.com",
            technique_name="Application Layer Protocol",
            technique_id="T1071.001",
            msg="BLUELIGHT Graph API exfiltration",
            offset=162 + i,
        ))

    # ── DNS Tunneling: port 53 from suspicious processes ──
    # Detection ``sysmon_dns_tunneling_via_network_connection`` matches:
    #   Destination Port = 53 AND Initiated = true AND
    #   Process Name in (powershell.exe, cmd.exe, nslookup.exe, iodine.exe,
    #   dnscat2.exe, dns2tcp.exe), excluding svchost.exe and dns.exe.
    dns_tunnel_procs = [
        "C:\\Windows\\System32\\powershell.exe",
        "C:\\Windows\\System32\\nslookup.exe",
        "C:\\Windows\\System32\\cmd.exe",
        "C:\\Tools\\iodine.exe",
        "C:\\Tools\\dnscat2.exe",
        "C:\\Tools\\dns2tcp.exe",
    ]
    for i, proc in enumerate(dns_tunnel_procs):
        for j in range(3):
            events.append(sysmon_network_event(
                image=proc,
                dst_ip="8.8.8.8", dst_port=53, protocol="udp",
                initiated="true",
                technique_name="DNS", technique_id="T1071.004",
                msg=f"DNS tunnel via {proc.split(chr(92))[-1]}",
                offset=170 + i * 4 + j,
            ))

    # ── Kerberoasting: Kerberos (port 88) ──
    for i in range(6):
        events.append(sysmon_network_event(
            image=random.choice([
                "C:\\Tools\\rubeus.exe",
                "C:\\Windows\\System32\\powershell.exe",
                "C:\\Temp\\mimikatz.exe",
            ]),
            dst_ip=random.choice(CORPORATE_IPS), dst_port=88,
            technique_name="Kerberoasting", technique_id="T1558.003",
            msg="Kerberos ticket request from suspicious process",
            offset=190 + i,
        ))

    # ── LDAP Reconnaissance: port 389/636 ──
    for i in range(6):
        events.append(sysmon_network_event(
            image=random.choice([
                "C:\\Tools\\sharphound.exe",
                "C:\\Windows\\System32\\powershell.exe",
                "C:\\Tools\\adfind.exe",
            ]),
            dst_ip=random.choice(CORPORATE_IPS),
            dst_port=random.choice([389, 636, 3268]),
            technique_name="Account Discovery", technique_id="T1087.002",
            msg="LDAP enumeration",
            offset=210 + i,
        ))

    # ── Cobalt Strike C2 patterns ──
    for i in range(6):
        events.append(sysmon_network_event(
            image=random.choice([
                "C:\\Windows\\System32\\rundll32.exe",
                "C:\\Windows\\System32\\dllhost.exe",
            ]),
            dst_ip=random.choice(c2_ips),
            dst_port=random.choice([80, 443, 50050]),
            dst_hostname="cdn-update.cobalt.example.com",
            technique_name="Application Layer Protocol", technique_id="T1071.001",
            msg="Cobalt Strike beacon communication",
            offset=230 + i,
        ))

    # ── Mimikatz network activity ──
    for i in range(4):
        events.append(sysmon_network_event(
            image="C:\\Temp\\mimikatz.exe",
            dst_ip=random.choice(CORPORATE_IPS),
            dst_port=random.choice([88, 389, 445]),
            technique_name="OS Credential Dumping", technique_id="T1003.001",
            msg="Mimikatz accessing DC services",
            offset=250 + i,
        ))

    # ── LOLBin outbound connections ──
    lolbins = [
        "C:\\Windows\\System32\\certutil.exe",
        "C:\\Windows\\System32\\bitsadmin.exe",
        "C:\\Windows\\System32\\mshta.exe",
        "C:\\Windows\\System32\\regsvr32.exe",
    ]
    for i, lolbin in enumerate(lolbins):
        for j in range(3):
            events.append(sysmon_network_event(
                image=lolbin, dst_ip=random.choice(c2_ips),
                dst_port=random.choice([80, 443]),
                technique_name="Signed Binary Proxy Execution", technique_id="T1218",
                msg=f"LOLBin outbound: {lolbin.split(chr(92))[-1]}",
                offset=270 + i * 4 + j,
            ))

    # Web-to-cloud drilldown: compromised Windows host beaconing to the same C2.
    for i in range(4):
        event = sysmon_network_event(
            host=WEB_TO_CLOUD_WINDOWS_HOST,
            user="svc-app",
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            src_ip=WEB_TO_CLOUD_WINDOWS_PRIVATE_IP,
            dst_ip=WEB_TO_CLOUD_C2_IP,
            dst_port=443,
            dst_hostname=WEB_TO_CLOUD_C2_HOST,
            technique_name="Application Layer Protocol",
            technique_id="T1071.001",
            msg="Web-to-cloud C2 beacon after app-tier compromise",
            offset=292 + i,
        )
        event["Trace ID"] = WEB_TO_CLOUD_TRACE_ID
        event["Attack Stage"] = "c2_beacon"
        events.append(event)

    # ── Normal traffic (for contrast) ──
    normal_procs = [
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Windows\\System32\\svchost.exe",
        "C:\\Program Files\\Microsoft Office\\Office16\\OUTLOOK.EXE",
    ]
    for i, proc in enumerate(normal_procs):
        for j in range(5):
            events.append(sysmon_network_event(
                image=proc, dst_ip="142.250.80.46", dst_port=443,
                dst_hostname="www.google.com",
                user="SYSTEM" if "svchost" in proc else random.choice(THREAT_ACTORS),
                msg=f"Normal HTTPS: {proc.split(chr(92))[-1]}",
                offset=300 + i * 6 + j,
            ))

    return events
