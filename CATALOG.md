# Detection Rule Catalog

> **446 base detection queries** + **20 app/APM queries** + **40 hunting queries**

## Summary

| Content Surface | Count | Notes |
|-----------------|-------|-------|
| Base detection queries | 446 | Sigma-derived detections in `queries/` |
| App/APM queries | 20 | 8 Sigma-derived browser detections + 12 curated analytics in `queries/apps/` |
| Hunting queries | 40 | Curated analytics and correlation content in `queries/hunting/` |

**Source YAML rules:** 454 total (cloud: 100, linux: 67, web: 38, windows: 249)

| Platform | Rules |
|----------|-------|
| OCI Cloud | 130 |
| Linux | 67 |
| Windows | 249 |

| Severity | Count |
|----------|-------|
| 🔴 Critical | 83 |
| 🟠 High | 191 |
| 🟡 Medium | 124 |
| 🔵 Low | 18 |
| ⚪ Informational | 30 |

**Atomic Red Team Coverage:** 278/316 testable rules have ART tests (88%) | 3217 total test mappings

**STIG Coverage:** 24 rules covering 12 controls (AC-17, AC-3, AC-6, AU-11, AU-12, CP-9, IA-2, IA-5, IA-8, SC-12, SC-28, SC-7)

## MITRE ATT&CK Coverage

**211 techniques** across **14 tactics**

### Initial Access (32 techniques)

| Technique | Rules |
|-----------|-------|
| T1012 | BLUELIGHT APT37 Kill Chain Correlation |
| T1027 | BLUELIGHT APT37 Kill Chain Correlation |
| T1059 | WAF Log4Shell (CVE-2021-44228) Attack Blocked, Web Server Process Spawning Command Shell, +4 more |
| T1059.001 | Web Server Process Spawning Command Shell |
| T1059.004 | Linux Multi-Stage Attack Indicators (Combined Methods) |
| T1059.007 | WAF SQL Injection Attack Allowed Through, WAF SQL Injection Attack Blocked, +3 more |
| T1071.001 | BLUELIGHT APT37 Kill Chain Correlation |
| T1078 | API Endpoint Unauthorized Access Attempts, OCI Console Login Failure, +7 more |
| T1082 | BLUELIGHT APT37 Kill Chain Correlation |
| T1083 | WAF Path Traversal Attack Blocked, BLUELIGHT APT37 Kill Chain Correlation |
| T1098 | OCI IAM and Fusion Activity Correlation |
| T1105 | BLUELIGHT APT37 Kill Chain Correlation |
| T1110 | OWASP Attack Detection (CRM + Drone Shop), Security Attack Source IP Analysis, +4 more |
| T1110.001 | Linux SSH Failed Login, SSH Brute Force Detection (Frequency Analysis) |
| T1110.003 | OCI Password Spraying Attack |
| T1110.004 | OCI Multiple Users from Same IP (Grouping) |
| T1113 | BLUELIGHT APT37 Kill Chain Correlation |
| T1133 | Cloud Guard Problem: VCN Security List Port RDP, Cloud Guard Problem: VCN Security List Port SSH, Linux External Remote Service Abuse |
| T1185 | APM: Clickjacking - Missing Frame Protection Headers, APM: CSRF Token Missing or Invalid on State-Changing Request |
| T1189 | BLUELIGHT RAT: Internet Explorer Drive-by Compromise, WAF CORS Bypass Attempt Blocked, +4 more |
| T1190 | API Endpoint Unauthorized Access Attempts, Cloud Guard Problem: Bucket Public Write, +27 more |
| T1203 | BLUELIGHT APT37 Kill Chain Correlation |
| T1204.002 | Windows Spearphishing Attachment Execution |
| T1496 | Browser Attack Frequency Analysis (SOC Application Logs) |
| T1550 | Web Application Authentication Bypass |
| T1552.005 | SSRF to Cloud Instance Metadata Service (Linux), SSRF to Cloud Metadata Endpoint (169.254.169.254), WAF Server-Side Request Forgery Blocked |
| T1555.003 | BLUELIGHT APT37 Kill Chain Correlation |
| T1562 | WAF Signal Correlation with Application Traces |
| T1566.001 | Windows Spearphishing Attachment Execution |
| T1567.002 | BLUELIGHT APT37 Kill Chain Correlation |
| T1606 | OCI Federated Identity Provider Modified |
| T1621 | OCI MFA Fatigue Attack Indicators |

### Execution (40 techniques)

| Technique | Rules |
|-----------|-------|
| T1003.001 | Hunting: Credential Attack Correlation (PowerShell + Mimikatz + Kerberoast) |
| T1012 | BLUELIGHT APT37 Kill Chain Correlation |
| T1021.002 | Sysmon PsExec Named Pipe |
| T1021.006 | Sysmon Lateral Movement via WinRM |
| T1027 | Windows Encoded PowerShell Execution, BLUELIGHT APT37 Kill Chain Correlation, Windows Suspiciously Long Command Line (Field Analysis) |
| T1036 | Windows Process from Unusual Path (Rare Value Analysis) |
| T1047 | Windows Management Instrumentation Event Subscription, WMI Process Execution via Wmic |
| T1053.005 | Suspicious Scheduled Task Creation |
| T1056.001 | APM: Suspicious JavaScript Execution Patterns |
| T1059 | Insecure Deserialization Attack Detected, Linux Process Execution from /dev/shm, +10 more |
| T1059.001 | PowerShell Execution via Alternate Shell, PowerShell Script Block with Suspicious Keywords, +7 more |
| T1059.003 | CMD: Suspicious Command Execution (Real Windows Security Events) |
| T1059.004 | Linux Bind Shell Listener, OCI Cloud Shell Session Started, +2 more |
| T1059.005 | Scripting Engine Spawning Network Utility, Visual Basic Script Compilation via vbc.exe, +2 more |
| T1059.006 | Python Execution as Child of System Process |
| T1059.007 | JavaScript Execution via Node.js, APM: DOM-Based Attack via Dangerous JavaScript APIs, +4 more |
| T1071 | Sysmon Suspicious Named Pipe Pattern |
| T1071.001 | BLUELIGHT APT37 Kill Chain Correlation |
| T1082 | BLUELIGHT APT37 Kill Chain Correlation |
| T1083 | BLUELIGHT APT37 Kill Chain Correlation |
| T1086 | PowerShell: Suspicious Command Execution (Real Windows Security Events) |
| T1105 | Finger.exe Abuse for File Download, Windows PowerShell Download Cradle, BLUELIGHT APT37 Kill Chain Correlation |
| T1110 | OWASP Attack Detection (CRM + Drone Shop), Linux Multi-Stage Attack Indicators (Combined Methods), OWASP Multi-Stage Web Attack Chain (Combined Methods) |
| T1113 | BLUELIGHT APT37 Kill Chain Correlation |
| T1127.001 | MSBuild Execution from Non-Standard Location, Windows MSBuild Execution for Code Bypass |
| T1189 | APM: Cross-Site Scripting (XSS) Attack in Request, BLUELIGHT APT37 Kill Chain Correlation, Browser Attack Frequency Analysis (SOC Application Logs) |
| T1190 | Insecure Deserialization Attack Detected, WAF Command Injection Attack Blocked, +8 more |
| T1203 | BLUELIGHT RAT: Browser Spawning Suspicious Child Process, BLUELIGHT APT37 Kill Chain Correlation |
| T1204 | OCI Action: StartInstance, Suspicious Usage of base64, +27 more |
| T1204.002 | BLUELIGHT RAT: YARA PDB Path Indicators (APT_MAL_Win_BlueLight), VBA Macro Spawning Suspicious Child Process, Windows Spearphishing Attachment Execution |
| T1218 | Control Panel Item Execution, SyncAppvPublishingServer Abuse |
| T1218.005 | MSHTA JavaScript Execution |
| T1218.011 | DLL Execution via Rundll32 from User Path |
| T1496 | APM: Suspicious JavaScript Execution Patterns, Browser Attack Frequency Analysis (SOC Application Logs) |
| T1555.003 | BLUELIGHT APT37 Kill Chain Correlation |
| T1558.003 | Hunting: Credential Attack Correlation (PowerShell + Mimikatz + Kerberoast) |
| T1566.001 | Windows Spearphishing Attachment Execution |
| T1567.002 | BLUELIGHT APT37 Kill Chain Correlation |
| T1569.002 | Service Execution via sc.exe Create, Sysmon PsExec Named Pipe |
| T1648 | OCI Function Invoked |

### Persistence (45 techniques)

| Technique | Rules |
|-----------|-------|
| T1053 | Linux Persistence Indicator Score (Combined Methods) |
| T1053.002 | Linux At Job Scheduled |
| T1053.003 | Linux Crontab Modification, Linux Suspicious Cron Job Content |
| T1053.005 | Scheduled Task XML Import, Windows Scheduled Task Creation via Schtasks |
| T1059.004 | Linux Multi-Stage Attack Indicators (Combined Methods) |
| T1078 | OCI IAM and Fusion Activity Correlation, OCI IAM Rapid Configuration Changes (Anomaly Detection), OCI Privilege Escalation Chain Detection |
| T1098 | OCI IAM Policy Modified, OCI User Password Reset by Admin, +4 more |
| T1098.001 | OCI Action: AddUserToGroup, OCI API Key Uploaded, OCI Dynamic Group Created |
| T1098.004 | Linux SSH Authorized Keys Modified, Linux Persistence Indicator Score (Combined Methods) |
| T1110 | Linux Multi-Stage Attack Indicators (Combined Methods) |
| T1136.001 | Linux Password File Direct Modification, New Local Account Created via Net.exe |
| T1136.003 | OCI Action: CreateGroup, OCI Action: CreateUser |
| T1137 | Office Application Startup Persistence |
| T1190 | WAF Web Shell Upload Attempt Blocked |
| T1197 | BITS Job Persistence, Windows BITS Job Abuse for Persistence |
| T1219 | Windows Remote Access Tool Detected |
| T1505.003 | Linux Web Shell File Creation, WAF Web Shell Upload Attempt Blocked |
| T1542 | Boot Configuration Change for Persistence |
| T1543.002 | Linux Systemd Service Persistence, Linux Persistence Indicator Score (Combined Methods) |
| T1543.003 | Windows Service Created with Suspicious Binary Path, Windows Service Creation via SC |
| T1546.001 | Default File Association Hijack |
| T1546.002 | ScreenSaver Hijacking Persistence |
| T1546.003 | Windows WMI Event Subscription Persistence, WMI Event Subscription Persistence |
| T1546.004 | Linux Shell Profile Persistence |
| T1546.007 | Netsh Helper DLL Persistence |
| T1546.008 | Accessibility Features Backdoor |
| T1546.010 | AppInit DLLs Persistence |
| T1546.011 | Application Shimming for Persistence |
| T1546.012 | Image File Execution Options Debugger |
| T1546.015 | COM Object Hijacking via Registry |
| T1547.001 | Registry Run Key Modification via Reg.exe, Startup Folder Modification, Windows Registry Run Key Modification |
| T1547.003 | Time Provider DLL Persistence |
| T1547.004 | Winlogon Helper DLL Modification |
| T1547.005 | Security Support Provider DLL Persistence |
| T1547.006 | Linux Kernel Module Loaded from Temp Directory |
| T1547.009 | Shortcut Modification for Persistence |
| T1547.010 | Port Monitor DLL Persistence |
| T1547.012 | Print Processor Persistence |
| T1547.014 | Active Setup Persistence |
| T1548.001 | Linux Setuid Binary Creation |
| T1556.007 | OCI Identity Provider Created |
| T1558.001 | Golden Ticket: RC4 Encrypted TGT Request |
| T1562.007 | OCI Route Table Update |
| T1574.006 | Linux LD_PRELOAD Library Hijacking |
| T1583 | OCI Action: AttachInternetGateway, OCI Action: CreateInternetGateway, OCI Action: CreateRouteTable |

### Privilege Escalation (19 techniques)

| Technique | Rules |
|-----------|-------|
| T1003.006 | Hunting: AD Attack Timeline - Multi-Stage Credential Attack Chain |
| T1021 | Hunting: Logon Anomaly - Account Activity Profiling |
| T1068 | PrintNightmare Exploitation Attempt |
| T1078 | Mass Assignment Attack Detected, Web Application Privilege Escalation, +4 more |
| T1098 | Cloud Guard Problem: Group Has Too Many Admins, Cloud Guard Problem: Policy Too Permissive, +10 more |
| T1098.001 | Cloud Guard Problem: Instance Principals Enabled |
| T1110.001 | Hunting: AD Attack Timeline - Multi-Stage Credential Attack Chain |
| T1134 | Privilege Escalation: Sensitive Privileges Assigned to Non-Admin, SeDebugPrivilege Abuse, +3 more |
| T1134.001 | Named Pipe Impersonation via PowerShell, Potato Privilege Escalation Tool, Privilege Escalation: Sensitive Privileges Assigned to Non-Admin |
| T1134.002 | Token Manipulation via RunAs |
| T1134.004 | Parent PID Spoofing |
| T1548.001 | Linux Setuid Binary Creation |
| T1548.002 | AlwaysInstallElevated Exploitation, UAC Bypass via ComputerDefaults, +4 more |
| T1548.003 | Linux Sudo Usage, Linux Sudoers File Modification |
| T1550.003 | Hunting: AD Attack Timeline - Multi-Stage Credential Attack Chain |
| T1558.003 | Hunting: AD Attack Timeline - Multi-Stage Credential Attack Chain |
| T1574.009 | Unquoted Service Path Exploitation |
| T1574.011 | DLL Hijacking via Service Registry Permission, Service Permissions Weakness Discovery |
| T1611 | Linux Container Escape Attempt |

### Defense Evasion (63 techniques)

| Technique | Rules |
|-----------|-------|
| T1003.001 | Windows WDigest Authentication Enabled for Credential Harvesting |
| T1012 | BLUELIGHT APT37 Kill Chain Correlation |
| T1027 | BLUELIGHT RAT: Obfuscated Script Execution, Windows Encoded PowerShell Execution, +2 more |
| T1036 | Windows Process from Unusual Path (Rare Value Analysis) |
| T1036.003 | Renamed System Binary Execution |
| T1036.005 | Masquerading System Binary in Non-Standard Path |
| T1055 | Process Ghosting or Herpaderping, Sysmon Cobalt Strike Named Pipe |
| T1055.001 | Process Injection via CreateRemoteThread |
| T1055.008 | Linux Process Injection via Ptrace |
| T1055.012 | Windows Process Hollowing Indicators |
| T1055.013 | Process Doppelganging via TxF |
| T1059 | Windows Rare Process Detection (Stacking) |
| T1059.001 | Windows Encoded PowerShell Execution, Windows Suspiciously Long Command Line (Field Analysis) |
| T1059.004 | Linux Rare Process Detection (Stacking) |
| T1070 | Windows Defense Evasion Score (Combined Methods) |
| T1070.001 | Windows Event Log Cleared via Wevtutil, Windows Event Log Clearing |
| T1070.002 | Linux Log File Tampering |
| T1070.003 | Linux History File Cleared |
| T1070.004 | File Deletion of Security Tools, SDelete Secure File Deletion |
| T1070.006 | Timestomping via PowerShell |
| T1071 | Sysmon Cobalt Strike Named Pipe |
| T1071.001 | BLUELIGHT APT37 Kill Chain Correlation |
| T1082 | BLUELIGHT APT37 Kill Chain Correlation |
| T1083 | BLUELIGHT APT37 Kill Chain Correlation |
| T1098 | OCI After-Hours IAM Activity (Time-Based Anomaly) |
| T1105 | Sysmon Suspicious Outbound Connection from LOLBin, Windows Certutil Download or Decode, BLUELIGHT APT37 Kill Chain Correlation |
| T1113 | BLUELIGHT APT37 Kill Chain Correlation |
| T1127.001 | Windows MSBuild Execution for Code Bypass |
| T1134 | Windows Access Token Manipulation |
| T1140 | Windows Certutil Download or Decode |
| T1189 | BLUELIGHT APT37 Kill Chain Correlation |
| T1190 | WAF Signal Correlation with Application Traces |
| T1197 | Windows BITS Job Abuse for Persistence |
| T1202 | Indirect Command Execution via Forfiles |
| T1203 | BLUELIGHT APT37 Kill Chain Correlation |
| T1204 | Windows Process from Unusual Path (Rare Value Analysis) |
| T1218 | Sysmon Suspicious Outbound Connection from LOLBin, Windows LOLBin Usage: at, +19 more |
| T1218.001 | Compiled HTML File Execution |
| T1218.003 | CMSTP UAC Bypass |
| T1218.004 | InstallUtil Application Whitelisting Bypass |
| T1218.005 | AppLocker Policy Bypass via MSHTML |
| T1218.009 | Regsvcs or Regasm Execution for Code Bypass |
| T1220 | XSL Script Processing via WMIC or Msxsl |
| T1221 | Template Injection via Microsoft Office |
| T1497 | Virtualization Sandbox Evasion Check |
| T1548.002 | Windows UAC Bypass Attempt, Windows Defense Evasion Score (Combined Methods) |
| T1553 | OCI Action: CreateKey |
| T1553.004 | Root Certificate Installation via Certutil |
| T1555.003 | BLUELIGHT APT37 Kill Chain Correlation |
| T1562 | WAF Signal Correlation with Application Traces, Windows Defense Evasion Score (Combined Methods) |
| T1562.001 | AMSI Bypass via PowerShell Reflection, OCI Log Group Deleted, +5 more |
| T1562.002 | ETW Provider Disabled |
| T1562.004 | Disable Windows Firewall via Netsh, OCI Network Firewall Policy Modified, +2 more |
| T1562.007 | OCI Action: CreateSecurityList, OCI Action: UpdateBucket, +7 more |
| T1562.008 | Cloud Guard Problem: Audit Log Retention, Cloud Guard Problem: VCN Flow Log Disabled, +4 more |
| T1564.001 | Linux Hidden File or Directory Creation in Suspicious Location |
| T1564.003 | Hidden PowerShell Window Execution |
| T1564.004 | Alternate Data Stream Execution |
| T1565.001 | Linux Hosts File Modification |
| T1567.002 | BLUELIGHT APT37 Kill Chain Correlation |
| T1574.002 | DLL Side-Loading from Suspicious Directory, Windows DLL Side-Loading via Suspicious Path |
| T1600 | OCI Vault Key Rotation Overdue |
| T1620 | Reflective DLL Loading Indicators |

### Credential Access (48 techniques)

| Technique | Rules |
|-----------|-------|
| T1003 | Internal Monologue NTLM Hash Theft, Windows Credential Dumping via Secretsdump, Windows Credential Access Tool Cluster (Grouping) |
| T1003.001 | Credential Dumping via Comsvcs with Rundll32, Credential Dumping via Windows Task Manager, +10 more |
| T1003.002 | SAM Database Extraction via Reg Save |
| T1003.003 | NTDS.dit Database Copy Attempt, Windows NTDS.dit Database Extraction |
| T1003.004 | LSA Secrets Registry Extraction |
| T1003.006 | DCSync Attack via Replication Request, DCSync: Directory Replication from Non-Domain Controller, +2 more |
| T1003.007 | Linux Process Memory Access via /proc |
| T1005 | Linux Sensitive Data Collection from Local System |
| T1012 | BLUELIGHT APT37 Kill Chain Correlation |
| T1021 | Hunting: Logon Anomaly - Account Activity Profiling |
| T1027 | BLUELIGHT APT37 Kill Chain Correlation |
| T1056.001 | Windows Keylogger Indicators |
| T1059 | OWASP Attack Detection (CRM + Drone Shop), OWASP Multi-Stage Web Attack Chain (Combined Methods) |
| T1059.001 | Hunting: Credential Attack Correlation (PowerShell + Mimikatz + Kerberoast) |
| T1071.001 | BLUELIGHT APT37 Kill Chain Correlation |
| T1078 | Hunting: Logon Anomaly - Account Activity Profiling, OCI Console Login Brute Force (Frequency Analysis), Login Activity Time-Series Anomaly |
| T1082 | BLUELIGHT APT37 Kill Chain Correlation |
| T1083 | BLUELIGHT APT37 Kill Chain Correlation |
| T1098.001 | OCI Customer Secret Key Created |
| T1105 | BLUELIGHT APT37 Kill Chain Correlation |
| T1110 | Cloud Guard Problem: IAM User Console Password Old, WAF Rate Limiting Triggered, +6 more |
| T1110.001 | Brute Force: Failed Logon Spike per Account, Linux SSH Failed Login, +4 more |
| T1110.003 | Brute Force: Failed Logon Spike per Account, OCI Password Spraying Attack, +3 more |
| T1113 | BLUELIGHT APT37 Kill Chain Correlation |
| T1114 | BLUELIGHT RAT: YARA Chrome/Edge Cookie Theft (APT_MAL_Win_BlueLight_B) |
| T1134 | Sysmon Mimikatz Named Pipe, Token Impersonation via Incognito, +2 more |
| T1187 | Forced Authentication via PetitPotam |
| T1189 | BLUELIGHT APT37 Kill Chain Correlation |
| T1190 | SSRF to Cloud Instance Metadata Service (Linux), SSRF to Cloud Metadata Endpoint (169.254.169.254), +3 more |
| T1203 | BLUELIGHT APT37 Kill Chain Correlation |
| T1528 | OCI Auth Token Created |
| T1539 | BLUELIGHT RAT: YARA Chrome/Edge Cookie Theft (APT_MAL_Win_BlueLight_B), Web Application Session Hijacking Indicators, APM: Session Hijacking - Rapid Session Changes |
| T1550.003 | Pass-the-Ticket: Excessive Explicit Credential Logons, Hunting: AD Attack Timeline - Multi-Stage Credential Attack Chain |
| T1550.004 | Web Application Session Hijacking Indicators, APM: Session Hijacking - Rapid Session Changes |
| T1552.001 | Credential File Discovery, WiFi Password Extraction via Netsh |
| T1552.004 | Cloud Guard Problem: IAM User API Key Old |
| T1552.005 | OCI Instance Metadata Service Accessed, SSRF to Cloud Instance Metadata Service (Linux), SSRF to Cloud Metadata Endpoint (169.254.169.254) |
| T1552.006 | Group Policy Preferences Password Extraction |
| T1555 | DPAPI Master Key Extraction, LaZagne Credential Harvester, +2 more |
| T1555.003 | BLUELIGHT RAT: Browser Credential Memory Access, BLUELIGHT RAT: YARA Chrome/Edge Cookie Theft (APT_MAL_Win_BlueLight_B), +2 more |
| T1555.004 | Credential Manager: High-Frequency Credential Read |
| T1556 | NPPSpy Credential Interception, OCI User MFA Not Enabled, Shadow Credentials Attack via Whisker |
| T1558 | Kerberos Ticket Export via Mimikatz |
| T1558.001 | Golden Ticket: RC4 Encrypted TGT Request |
| T1558.003 | Kerberoasting: RC4 Encrypted Service Ticket Request, Kerberoasting: SPN Sweep - Multiple Service Tickets from Single Account, +8 more |
| T1558.004 | AS-REP Roasting via Rubeus |
| T1567.002 | BLUELIGHT APT37 Kill Chain Correlation |
| T1649 | Credential Access via Certutil Certificate Export |

### Discovery (26 techniques)

| Technique | Rules |
|-----------|-------|
| T1012 | BLUELIGHT RAT: Registry Enumeration of Security Products, BLUELIGHT APT37 Kill Chain Correlation |
| T1016 | BLUELIGHT RAT: YARA System Reconnaissance JSON (APT_MAL_Win_BlueLight) |
| T1018 | Windows Remote System Discovery |
| T1027 | BLUELIGHT APT37 Kill Chain Correlation |
| T1033 | Linux System Owner and User Discovery |
| T1046 | Linux Network Service Scanning |
| T1057 | BLUELIGHT RAT: YARA System Reconnaissance JSON (APT_MAL_Win_BlueLight), Process Discovery via Tasklist |
| T1069.001 | Local Group Membership Discovery |
| T1069.002 | Security Group Enumeration: Rapid Membership Queries, Sysmon LDAP Reconnaissance |
| T1071.001 | BLUELIGHT APT37 Kill Chain Correlation |
| T1082 | BLUELIGHT RAT: WMI System Enumeration from Browser Child, BLUELIGHT RAT: YARA System Reconnaissance JSON (APT_MAL_Win_BlueLight), +2 more |
| T1083 | BLUELIGHT RAT: File Discovery from Browser Process, File and Directory Discovery via dir, BLUELIGHT APT37 Kill Chain Correlation |
| T1087.001 | Windows Account Discovery Commands |
| T1087.002 | AD Enumeration via ADFind, BloodHound AD Enumeration, +3 more |
| T1105 | BLUELIGHT APT37 Kill Chain Correlation |
| T1113 | BLUELIGHT APT37 Kill Chain Correlation |
| T1135 | Network Share Enumeration via Net View, Windows Network Share Discovery |
| T1189 | BLUELIGHT APT37 Kill Chain Correlation |
| T1201 | Password Policy Discovery |
| T1203 | BLUELIGHT APT37 Kill Chain Correlation |
| T1482 | Domain Trust Discovery via Nltest |
| T1518 | Software Discovery via WMIC |
| T1518.001 | Query Registry for Security Products |
| T1555.003 | BLUELIGHT APT37 Kill Chain Correlation |
| T1567.002 | BLUELIGHT APT37 Kill Chain Correlation |
| T1580 | OCI Cloud Infrastructure Discovery |

### Lateral Movement (18 techniques)

| Technique | Rules |
|-----------|-------|
| T1003.006 | Hunting: AD Attack Timeline - Multi-Stage Credential Attack Chain |
| T1021 | OCI Bastion Session Created, OCI Instance Console Connection Created, +3 more |
| T1021.001 | RDP Session Hijacking via tscon, SharpRDP Lateral Movement, +2 more |
| T1021.002 | Lateral Movement: Account Authenticating from Multiple Sources, PsExec Service Installation, +5 more |
| T1021.003 | DCOM Lateral Movement via MMC20 |
| T1021.006 | Lateral Movement: Account Authenticating from Multiple Sources, Sysmon Lateral Movement via WinRM, +2 more |
| T1059.001 | Sysmon Lateral Movement via WinRM |
| T1078 | Hunting: Logon Anomaly - Account Activity Profiling |
| T1110.001 | Hunting: AD Attack Timeline - Multi-Stage Credential Attack Chain |
| T1134 | Hunting: AD Attack Timeline - Multi-Stage Credential Attack Chain, Hunting: Logon Anomaly - Account Activity Profiling |
| T1539 | APM: Session Hijacking - Rapid Session Changes |
| T1550.002 | Windows Pass-the-Hash Attack Indicators |
| T1550.003 | Pass-the-Ticket via Rubeus, Pass-the-Ticket: Excessive Explicit Credential Logons, Hunting: AD Attack Timeline - Multi-Stage Credential Attack Chain |
| T1550.004 | APM: Session Hijacking - Rapid Session Changes |
| T1558.003 | Hunting: AD Attack Timeline - Multi-Stage Credential Attack Chain |
| T1569.002 | Sysmon PsExec Named Pipe, Windows PsExec Remote Execution |
| T1570 | Lateral Tool Transfer via Robocopy, Sysmon Lateral Movement via SMB, Windows Lateral Movement Tool Cluster (Grouping) |
| T1599 | OCI DRG Attachment Created, OCI Local Peering Gateway Created, OCI Service Gateway Created |

### Collection (23 techniques)

| Technique | Rules |
|-----------|-------|
| T1005 | Linux Sensitive Data Collection from Local System, Sensitive Data Endpoint Access |
| T1012 | BLUELIGHT APT37 Kill Chain Correlation |
| T1027 | BLUELIGHT APT37 Kill Chain Correlation |
| T1056.001 | BLUELIGHT RAT: YARA Keylogger Component (APT_MAL_Win_BlueLight_B), Keylogging via PowerShell Get-Keystrokes, +2 more |
| T1059.007 | APM: Suspicious JavaScript Execution Patterns |
| T1071.001 | BLUELIGHT APT37 Kill Chain Correlation |
| T1074.001 | Windows Data Staging for Exfiltration, Linux Data Staging and Exfiltration Indicators |
| T1082 | BLUELIGHT APT37 Kill Chain Correlation |
| T1083 | BLUELIGHT APT37 Kill Chain Correlation |
| T1105 | BLUELIGHT APT37 Kill Chain Correlation |
| T1113 | BLUELIGHT RAT: Periodic Screen Capture, Screen Capture via PowerShell, +2 more |
| T1114 | BLUELIGHT RAT: YARA Chrome/Edge Cookie Theft (APT_MAL_Win_BlueLight_B), Email Collection via PowerShell, OCI Notification Subscription Created |
| T1115 | Clipboard Data Collection |
| T1189 | BLUELIGHT APT37 Kill Chain Correlation |
| T1203 | BLUELIGHT APT37 Kill Chain Correlation |
| T1496 | APM: Suspicious JavaScript Execution Patterns |
| T1530 | OCI Action: CreateBucket |
| T1539 | BLUELIGHT RAT: YARA Chrome/Edge Cookie Theft (APT_MAL_Win_BlueLight_B) |
| T1552.001 | Sensitive Data Endpoint Access |
| T1555.003 | BLUELIGHT RAT: YARA Chrome/Edge Cookie Theft (APT_MAL_Win_BlueLight_B), BLUELIGHT APT37 Kill Chain Correlation |
| T1557 | Linux Suspicious Network Traffic Redirect |
| T1560.001 | Data Compression for Exfiltration via 7zip, Linux Archive Data Collected for Exfiltration, Linux Data Staging and Exfiltration Indicators |
| T1567.002 | BLUELIGHT APT37 Kill Chain Correlation |

### Command & Control (29 techniques)

| Technique | Rules |
|-----------|-------|
| T1012 | BLUELIGHT APT37 Kill Chain Correlation |
| T1027 | BLUELIGHT APT37 Kill Chain Correlation |
| T1048 | DNS Exfiltration Detection (Entropy Analysis) |
| T1048.003 | Sysmon DNS Data Exfiltration, Sysmon DNS Tunneling via Network Connection |
| T1055 | Sysmon Cobalt Strike Named Pipe |
| T1059 | Sysmon Suspicious Named Pipe Pattern |
| T1059.001 | Windows PowerShell Download Cradle |
| T1071 | Sysmon Cobalt Strike Named Pipe, Sysmon Suspicious Named Pipe Pattern, C2 Beaconing Detection (Periodic Connection Analysis) |
| T1071.001 | BLUELIGHT RAT: C2 via Microsoft Graph API, BLUELIGHT RAT: YARA Google App C2 Communication (APT_MAL_Win_BlueLight_B), +3 more |
| T1071.004 | Linux DNS Tunneling Detected, Sysmon DNS Data Exfiltration, +4 more |
| T1082 | BLUELIGHT APT37 Kill Chain Correlation |
| T1083 | BLUELIGHT APT37 Kill Chain Correlation |
| T1090 | Linux Proxy and Tunneling Tool Detected |
| T1090.001 | Linux Proxy and Tunneling Tool Detected |
| T1095 | Sysmon Cobalt Strike C2 Network Indicators |
| T1102 | BLUELIGHT RAT: YARA Google App C2 Communication (APT_MAL_Win_BlueLight_B) |
| T1105 | BLUELIGHT RAT: Executable Download via Graph API, Linux Suspicious Download to /tmp, +4 more |
| T1113 | BLUELIGHT APT37 Kill Chain Correlation |
| T1140 | Windows Certutil Download or Decode |
| T1189 | BLUELIGHT APT37 Kill Chain Correlation |
| T1203 | BLUELIGHT APT37 Kill Chain Correlation |
| T1218 | Sysmon Suspicious Outbound Connection from LOLBin |
| T1219 | Windows Remote Access Tool Detected |
| T1555.003 | BLUELIGHT APT37 Kill Chain Correlation |
| T1567.002 | BLUELIGHT APT37 Kill Chain Correlation |
| T1568.002 | Sysmon DNS Query to Known C2 Framework Domains |
| T1572 | Linux SSH Tunneling Detected |
| T1573 | Linux Encrypted Channel C2 Communication, Sysmon C2 Beacon - Periodic Outbound HTTPS, C2 Beaconing Detection (Periodic Connection Analysis) |
| T1573.002 | Linux Encrypted Channel C2 Communication |

### Exfiltration (19 techniques)

| Technique | Rules |
|-----------|-------|
| T1012 | BLUELIGHT APT37 Kill Chain Correlation |
| T1027 | BLUELIGHT APT37 Kill Chain Correlation |
| T1041 | Unusually Large HTTP Response (Data Exfiltration) |
| T1048 | Linux Exfiltration Over Alternative Protocol, Unusually Large HTTP Response (Data Exfiltration), DNS Exfiltration Detection (Entropy Analysis) |
| T1048.003 | Sysmon DNS Data Exfiltration, Sysmon DNS Tunneling via Network Connection |
| T1071.001 | BLUELIGHT APT37 Kill Chain Correlation |
| T1071.004 | Sysmon DNS Data Exfiltration, Sysmon DNS Tunneling via Network Connection, DNS Exfiltration Detection (Entropy Analysis) |
| T1074.001 | Windows Data Staging for Exfiltration, Linux Data Staging and Exfiltration Indicators |
| T1082 | BLUELIGHT APT37 Kill Chain Correlation |
| T1083 | BLUELIGHT APT37 Kill Chain Correlation |
| T1105 | BLUELIGHT APT37 Kill Chain Correlation |
| T1113 | BLUELIGHT APT37 Kill Chain Correlation |
| T1189 | BLUELIGHT APT37 Kill Chain Correlation |
| T1203 | BLUELIGHT APT37 Kill Chain Correlation |
| T1537 | Cloud Guard Problem: Bucket Public Read, OCI Boot Volume Backup Created by Non-Admin, +4 more |
| T1555.003 | BLUELIGHT APT37 Kill Chain Correlation |
| T1560.001 | Linux Archive Data Collected for Exfiltration, Linux Data Staging and Exfiltration Indicators |
| T1567 | OCI Object Storage Pre-Authenticated Request Created |
| T1567.002 | BLUELIGHT RAT: Data Exfiltration via OneDrive/Graph API, BLUELIGHT APT37 Kill Chain Correlation |

### Impact (15 techniques)

| Technique | Rules |
|-----------|-------|
| T1056.001 | APM: Suspicious JavaScript Execution Patterns |
| T1059.007 | APM: Suspicious JavaScript Execution Patterns, Browser Attack Frequency Analysis (SOC Application Logs) |
| T1189 | Browser Attack Frequency Analysis (SOC Application Logs) |
| T1190 | Browser Attack Frequency Analysis (SOC Application Logs) |
| T1485 | OCI Action: DeleteBucket, OCI Action: DeleteKey, +7 more |
| T1486 | Ransomware File Extension Indicators |
| T1489 | OCI Action: DeleteInternetGateway, OCI Action: DeleteSubnet, +6 more |
| T1490 | OCI KMS Key Scheduled for Deletion, System Recovery Disabled via BCDEdit, +4 more |
| T1491.001 | Defacement via Desktop Wallpaper Change |
| T1496 | Cryptominer Deployment Indicators, Linux Cryptominer Activity Detected, +2 more |
| T1499 | Web Application Server Error Spike, Application Error Rate by Service, Slow Request Detection (>2s) |
| T1529 | System Shutdown or Reboot via shutdown.exe |
| T1531 | Account Access Removal, OCI Action: DeleteGroup, +3 more |
| T1561 | Disk Wipe via Format Command |
| T1600 | OCI KMS Key Version Disabled, OCI Vault Secret Version Deprecated |

## All Detection Rules

### OCI Cloud (130 rules)

| # | Title | Severity | MITRE | STIG |
|---|-------|----------|-------|------|
| 1 | Insecure Deserialization Attack Detected | 🔴 critical | T1059, T1190 | - |
| 2 | OCI Audit Configuration Retention Reduced | 🔴 critical | T1562.008 | - |
| 3 | OCI Compartment Deleted | 🔴 critical | T1485 | AC-6 |
| 4 | OCI Database System Terminated | 🔴 critical | T1485 | CP-9 |
| 5 | OCI Federated Identity Provider Modified | 🔴 critical | T1606 | - |
| 6 | OCI KMS Key Scheduled for Deletion | 🔴 critical | T1490 | - |
| 7 | OCI Log Group Deleted | 🔴 critical | T1562.001 | AU-11 |
| 8 | OCI Policy Allows Manage All Resources | 🔴 critical | T1098 | - |
| 9 | WAF Command Injection Attack Blocked | 🔴 critical | T1059, T1190 | - |
| 10 | WAF Log4Shell (CVE-2021-44228) Attack Blocked | 🔴 critical | T1190, T1059 | - |
| 11 | WAF SQL Injection Attack Allowed Through | 🔴 critical | T1190, T1059.007 | - |
| 12 | WAF Server-Side Request Forgery Blocked | 🔴 critical | T1190, T1552.005 | - |
| 13 | WAF Server-Side Template Injection Blocked | 🔴 critical | T1059, T1190 | - |
| 14 | WAF Web Shell Upload Attempt Blocked | 🔴 critical | T1505.003, T1190 | - |
| 15 | Web Application Authentication Bypass | 🔴 critical | T1078, T1550 | - |
| 16 | Web Application Privilege Escalation | 🔴 critical | T1078 | - |
| 17 | Web Application Session Hijacking Indicators | 🔴 critical | T1539, T1550.004 | - |
| 18 | Cloud Guard Problem: Audit Log Retention | 🟠 high | T1562.008 | - |
| 19 | Cloud Guard Problem: Bucket Public Read | 🟠 high | T1537 | - |
| 20 | Cloud Guard Problem: Bucket Public Write | 🟠 high | T1190 | - |
| 21 | Cloud Guard Problem: Group Has Too Many Admins | 🟠 high | T1098 | - |
| 22 | Cloud Guard Problem: IAM User API Key Old | 🟠 high | T1552.004 | - |
| 23 | Cloud Guard Problem: IAM User Console Password Old | 🟠 high | T1110 | - |
| 24 | Cloud Guard Problem: INSTANCE PUBLIC IP | 🟠 high | T1190 | - |
| 25 | Cloud Guard Problem: Instance Principals Enabled | 🟠 high | T1098.001 | - |
| 26 | Cloud Guard Problem: Policy Too Permissive | 🟠 high | T1098 | - |
| 27 | Cloud Guard Problem: VCN Flow Log Disabled | 🟠 high | T1562.008 | - |
| 28 | Cloud Guard Problem: VCN Security List Port RDP | 🟠 high | T1133 | - |
| 29 | Cloud Guard Problem: VCN Security List Port SSH | 🟠 high | T1133 | - |
| 30 | Insecure Direct Object Reference Detected | 🟠 high | T1190 | - |
| 31 | Mass Assignment Attack Detected | 🟠 high | T1078 | - |
| 32 | OCI Audit Configuration Changed | 🟠 high | T1562.008 | AU-11 |
| 33 | OCI Autonomous Database Terminated | 🟠 high | T1485 | - |
| 34 | OCI Cross-Region Data Copy | 🟠 high | T1537 | SC-28 |
| 35 | OCI Customer Secret Key Created | 🟠 high | T1098.001 | IA-5 |
| 36 | OCI Dynamic Group Created with Broad Matching | 🟠 high | T1098 | - |
| 37 | OCI IAM Admin Policy Created with Manage All | 🟠 high | T1098 | - |
| 38 | OCI Identity Provider Created | 🟠 high | T1556.007 | IA-8 |
| 39 | OCI Instance Console Connection Created | 🟠 high | T1021 | AC-17 |
| 40 | OCI KMS Key Version Disabled | 🟠 high | T1600 | - |
| 41 | OCI Log Archival Policy Disabled | 🟠 high | T1562.008 | - |
| 42 | OCI MFA Fatigue Attack Indicators | 🟠 high | T1621 | - |
| 43 | OCI Network Firewall Policy Modified | 🟠 high | T1562.004 | SC-7 |
| 44 | OCI Network Load Balancer Deleted | 🟠 high | T1489 | - |
| 45 | OCI Object Storage Bucket Made Public | 🟠 high | T1537 | - |
| 46 | OCI Object Storage Pre-Authenticated Request Created | 🟠 high | T1567 | AC-3 |
| 47 | OCI Object Storage Replication Policy Created | 🟠 high | T1537 | - |
| 48 | OCI Password Spraying Attack | 🟠 high | T1110.003 | IA-2 |
| 49 | OCI Security List Allows All Protocols | 🟠 high | T1562.007 | SC-7 |
| 50 | OCI User Capabilities Escalation | 🟠 high | T1098 | - |
| 51 | OCI User MFA Not Enabled | 🟠 high | T1556 | IA-2 |
| 52 | OCI User Password Reset by Admin | 🟠 high | T1098 | IA-5 |
| 53 | OCI VCN Flow Log Disabled | 🟠 high | T1562.008 | - |
| 54 | OCI VCN Security List Open to World | 🟠 high | T1562.007 | - |
| 55 | OCI Vault Secret Deleted | 🟠 high | T1485 | SC-28 |
| 56 | OCI WAF Policy Deleted | 🟠 high | T1562.001 | - |
| 57 | Sensitive Data Endpoint Access | 🟠 high | T1005, T1552.001 | - |
| 58 | WAF Cross-Site Scripting Attack Blocked | 🟠 high | T1189 | - |
| 59 | WAF LDAP Injection Attack Blocked | 🟠 high | T1190 | - |
| 60 | WAF NoSQL Injection Attack Blocked | 🟠 high | T1190 | - |
| 61 | WAF Path Traversal Attack Blocked | 🟠 high | T1083, T1190 | - |
| 62 | WAF Protocol Attack Blocked | 🟠 high | T1190 | - |
| 63 | WAF SQL Injection Attack Blocked | 🟠 high | T1190, T1059.007 | - |
| 64 | WAF XML External Entity Attack Blocked | 🟠 high | T1190 | - |
| 65 | API Endpoint Unauthorized Access Attempts | 🟡 medium | T1190, T1078 | - |
| 66 | OCI API Key Uploaded | 🟡 medium | T1098.001 | - |
| 67 | OCI Auth Token Created | 🟡 medium | T1528 | IA-5 |
| 68 | OCI Bastion Session Created | 🟡 medium | T1021 | AC-17 |
| 69 | OCI Boot Volume Backup Created by Non-Admin | 🟡 medium | T1537 | - |
| 70 | OCI Compute Instance Terminated | 🟡 medium | T1485 | - |
| 71 | OCI Console Login Failure | 🟡 medium | T1078 | - |
| 72 | OCI Console Login from Unusual IP | 🟡 medium | T1078 | - |
| 73 | OCI DRG Attachment Created | 🟡 medium | T1599 | - |
| 74 | OCI Database Backup Exported | 🟡 medium | T1537 | - |
| 75 | OCI Dynamic Group Created | 🟡 medium | T1098.001 | AC-6 |
| 76 | OCI IAM Policy Modified | 🟡 medium | T1098 | - |
| 77 | OCI Instance Metadata Service Accessed | 🟡 medium | T1552.005 | - |
| 78 | OCI Local Peering Gateway Created | 🟡 medium | T1599 | - |
| 79 | OCI Network Security Group Rule Added for All Protocols | 🟡 medium | T1562.004 | - |
| 80 | OCI Network Security Group Updated | 🟡 medium | T1562.007 | - |
| 81 | OCI Notification Subscription Created | 🟡 medium | T1114 | AU-12 |
| 82 | OCI Route Table Update | 🟡 medium | T1562.007 | - |
| 83 | OCI VCN Peering Connection Created | 🟡 medium | T1021 | SC-7 |
| 84 | OCI Vault Key Rotation Overdue | 🟡 medium | T1600 | SC-12 |
| 85 | OCI Vault Secret Version Deprecated | 🟡 medium | T1600 | - |
| 86 | OCI WAF Configuration Updated | 🟡 medium | T1562.007 | - |
| 87 | Suspicious or Empty User Agent Detected | 🟡 medium | T1595 | - |
| 88 | Unusually Large HTTP Response (Data Exfiltration) | 🟡 medium | T1041, T1048 | - |
| 89 | WAF CORS Bypass Attempt Blocked | 🟡 medium | T1189 | - |
| 90 | WAF Rate Limiting Triggered | 🟡 medium | T1110 | - |
| 91 | Web Application Brute Force Login Attempt | 🟡 medium | T1110.001, T1110.003 | - |
| 92 | Web Application Server Error Spike | 🟡 medium | T1499 | - |
| 93 | Web Vulnerability Scanner Detected | 🟡 medium | T1595.002 | - |
| 94 | OCI Cloud Infrastructure Discovery | 🔵 low | T1580 | AU-12 |
| 95 | OCI Cloud Shell Session Started | 🔵 low | T1059.004 | AU-12 |
| 96 | OCI Console Login from Suspicious IP Range | 🔵 low | T1078 | - |
| 97 | OCI Function Invoked | 🔵 low | T1648 | AU-12 |
| 98 | OCI Service Gateway Created | 🔵 low | T1599 | - |
| 99 | Suspicious HTTP Method Usage | 🔵 low | T1190 | - |
| 100 | Web Directory Enumeration Detected | 🔵 low | T1083, T1595.002 | - |
| 101 | OCI Action: AddUserToGroup | ⚪ informational | T1098.001 | - |
| 102 | OCI Action: AttachInternetGateway | ⚪ informational | T1583 | - |
| 103 | OCI Action: CreateBucket | ⚪ informational | T1530 | - |
| 104 | OCI Action: CreateGroup | ⚪ informational | T1136.003 | - |
| 105 | OCI Action: CreateInstance | ⚪ informational | T1583.003 | - |
| 106 | OCI Action: CreateInternetGateway | ⚪ informational | T1583 | - |
| 107 | OCI Action: CreateKey | ⚪ informational | T1553 | - |
| 108 | OCI Action: CreatePolicy | ⚪ informational | T1098 | - |
| 109 | OCI Action: CreateRouteTable | ⚪ informational | T1583 | - |
| 110 | OCI Action: CreateSecurityList | ⚪ informational | T1562.007 | - |
| 111 | OCI Action: CreateSubnet | ⚪ informational | T1583 | - |
| 112 | OCI Action: CreateUser | ⚪ informational | T1136.003 | - |
| 113 | OCI Action: CreateVcn | ⚪ informational | T1583 | - |
| 114 | OCI Action: DeleteBucket | ⚪ informational | T1485 | - |
| 115 | OCI Action: DeleteGroup | ⚪ informational | T1531 | - |
| 116 | OCI Action: DeleteInternetGateway | ⚪ informational | T1489 | - |
| 117 | OCI Action: DeleteKey | ⚪ informational | T1485 | - |
| 118 | OCI Action: DeletePolicy | ⚪ informational | T1531 | - |
| 119 | OCI Action: DeleteSubnet | ⚪ informational | T1489 | - |
| 120 | OCI Action: DeleteUser | ⚪ informational | T1531 | - |
| 121 | OCI Action: DeleteVcn | ⚪ informational | T1489 | - |
| 122 | OCI Action: DetachInternetGateway | ⚪ informational | T1489 | - |
| 123 | OCI Action: RemoveUserFromGroup | ⚪ informational | T1531 | - |
| 124 | OCI Action: StartInstance | ⚪ informational | T1204 | - |
| 125 | OCI Action: StopInstance | ⚪ informational | T1489 | - |
| 126 | OCI Action: TerminateInstance | ⚪ informational | T1485 | - |
| 127 | OCI Action: UpdateBucket | ⚪ informational | T1562.007 | - |
| 128 | OCI Action: UpdatePolicy | ⚪ informational | T1098 | - |
| 129 | OCI Action: UpdateRouteTable | ⚪ informational | T1562.007 | - |
| 130 | OCI Action: UpdateSecurityList | ⚪ informational | T1562.007 | - |

### Linux (67 rules)

| # | Title | Severity | MITRE | ART Tests | STIG |
|---|-------|----------|-------|-----------|------|
| 1 | Linux Bind Shell Listener | 🔴 critical | T1059.004 | 17 | - |
| 2 | Linux Container Escape Attempt | 🔴 critical | T1611 | 3 | - |
| 3 | Linux Kernel Module Loaded from Temp Directory | 🔴 critical | T1547.006 | 4 | - |
| 4 | Linux Password File Direct Modification | 🔴 critical | T1136.001 | 10 | - |
| 5 | Linux Process Execution from /dev/shm | 🔴 critical | T1059 | 1 | - |
| 6 | Linux Reverse Shell Detected | 🔴 critical | T1059 | 1 | - |
| 7 | Linux Web Shell File Creation | 🔴 critical | T1505.003 | 1 | - |
| 8 | SSRF to Cloud Instance Metadata Service (Linux) | 🔴 critical | T1552.005, T1190 | - | - |
| 9 | Suspicious Usage of insmod | 🔴 critical | T1204 | 14 | - |
| 10 | Suspicious Usage of shadow | 🔴 critical | T1204 | 14 | - |
| 11 | Web Server Process Spawning Shell with Injection Characters (Linux) | 🔴 critical | T1059, T1190 | - | - |
| 12 | Linux Archive Data Collected for Exfiltration | 🟠 high | T1560.001 | 12 | - |
| 13 | Linux Cryptominer Activity Detected | 🟠 high | T1496 | 2 | - |
| 14 | Linux DNS Tunneling Detected | 🟠 high | T1071.004 | 4 | - |
| 15 | Linux Encrypted Channel C2 Communication | 🟠 high | T1573, T1573.002 | 1 | - |
| 16 | Linux Exfiltration Over Alternative Protocol | 🟠 high | T1048 | 4 | - |
| 17 | Linux LD_PRELOAD Library Hijacking | 🟠 high | T1574.006 | 3 | - |
| 18 | Linux Log File Tampering | 🟠 high | T1070.002 | 20 | - |
| 19 | Linux Network Service Scanning | 🟠 high | T1046 | 12 | - |
| 20 | Linux Post-Exploitation Enumeration Script | 🟠 high | T1082 | 40 | - |
| 21 | Linux Process Injection via Ptrace | 🟠 high | T1055.008 | 13 | - |
| 22 | Linux Process Memory Access via /proc | 🟠 high | T1003.007 | 4 | - |
| 23 | Linux Proxy and Tunneling Tool Detected | 🟠 high | T1090, T1090.001 | 7 | - |
| 24 | Linux SSH Authorized Keys Modified | 🟠 high | T1098.004 | 1 | - |
| 25 | Linux SSH Tunneling Detected | 🟠 high | T1572 | 7 | - |
| 26 | Linux Sensitive Data Collection from Local System | 🟠 high | T1005 | 3 | - |
| 27 | Linux Setuid Binary Creation | 🟠 high | T1548.001 | 10 | - |
| 28 | Linux Sudoers File Modification | 🟠 high | T1548.003 | 6 | - |
| 29 | Linux Suspicious Cron Job Content | 🟠 high | T1053.003 | 4 | - |
| 30 | Linux Suspicious Download to /tmp | 🟠 high | T1105 | 39 | - |
| 31 | Linux Suspicious Network Traffic Redirect | 🟠 high | T1557 | 1 | - |
| 32 | Suspicious Usage of chmod | 🟠 high | T1204 | 14 | - |
| 33 | Suspicious Usage of curl | 🟠 high | T1204 | 14 | - |
| 34 | Suspicious Usage of dd | 🟠 high | T1204 | 14 | - |
| 35 | Suspicious Usage of gdb | 🟠 high | T1204 | 14 | - |
| 36 | Suspicious Usage of modprobe | 🟠 high | T1204 | 14 | - |
| 37 | Suspicious Usage of nc | 🟠 high | T1204 | 14 | - |
| 38 | Suspicious Usage of ncat | 🟠 high | T1204 | 14 | - |
| 39 | Suspicious Usage of netcat | 🟠 high | T1204 | 14 | - |
| 40 | Suspicious Usage of nmap | 🟠 high | T1204 | 14 | - |
| 41 | Suspicious Usage of passwd | 🟠 high | T1204 | 14 | - |
| 42 | Suspicious Usage of rmmod | 🟠 high | T1204 | 14 | - |
| 43 | Suspicious Usage of socat | 🟠 high | T1204 | 14 | - |
| 44 | Suspicious Usage of wget | 🟠 high | T1204 | 14 | - |
| 45 | Linux At Job Scheduled | 🟡 medium | T1053.002 | 3 | - |
| 46 | Linux Crontab Modification | 🟡 medium | T1053.003 | 4 | - |
| 47 | Linux Hidden File or Directory Creation in Suspicious Location | 🟡 medium | T1564.001 | 10 | - |
| 48 | Linux History File Cleared | 🟡 medium | T1070.003 | 14 | - |
| 49 | Linux Hosts File Modification | 🟡 medium | T1565.001 | - | - |
| 50 | Linux Shell Profile Persistence | 🟡 medium | T1546.004 | 7 | - |
| 51 | Linux Systemd Service Persistence | 🟡 medium | T1543.002 | 3 | - |
| 52 | Suspicious Usage of base64 | 🟡 medium | T1204 | 14 | - |
| 53 | Suspicious Usage of chown | 🟡 medium | T1204 | 14 | - |
| 54 | Suspicious Usage of id | 🟡 medium | T1204 | 14 | - |
| 55 | Suspicious Usage of lua | 🟡 medium | T1204 | 14 | - |
| 56 | Suspicious Usage of perl | 🟡 medium | T1204 | 14 | - |
| 57 | Suspicious Usage of python | 🟡 medium | T1204 | 14 | - |
| 58 | Suspicious Usage of ruby | 🟡 medium | T1204 | 14 | - |
| 59 | Suspicious Usage of strace | 🟡 medium | T1204 | 14 | - |
| 60 | Suspicious Usage of tcpdump | 🟡 medium | T1204 | 14 | - |
| 61 | Suspicious Usage of tshark | 🟡 medium | T1204 | 14 | - |
| 62 | Suspicious Usage of whoami | 🟡 medium | T1204 | 14 | - |
| 63 | Suspicious Usage of wireshark | 🟡 medium | T1204 | 14 | - |
| 64 | Linux External Remote Service Abuse | 🔵 low | T1133 | 1 | - |
| 65 | Linux SSH Failed Login | 🔵 low | T1110.001 | 8 | - |
| 66 | Linux Sudo Usage | 🔵 low | T1548.003 | 6 | - |
| 67 | Linux System Owner and User Discovery | 🔵 low | T1033 | 7 | - |

### Windows (249 rules)

| # | Title | Severity | MITRE | ART Tests | STIG |
|---|-------|----------|-------|-----------|------|
| 1 | Accessibility Features Backdoor | 🔴 critical | T1546.008 | 10 | - |
| 2 | AppInit DLLs Persistence | 🔴 critical | T1546.010 | 1 | - |
| 3 | BLUELIGHT RAT: Browser Credential Memory Access | 🔴 critical | T1555.003 | - | - |
| 4 | BLUELIGHT RAT: YARA Chrome/Edge Cookie Theft (APT_MAL_Win_BlueLight_B) | 🔴 critical | T1539, T1555.003, T1114 | - | - |
| 5 | BLUELIGHT RAT: YARA Google App C2 Communication (APT_MAL_Win_BlueLight_B) | 🔴 critical | T1071.001, T1102 | - | - |
| 6 | BLUELIGHT RAT: YARA PDB Path Indicators (APT_MAL_Win_BlueLight) | 🔴 critical | T1204.002 | - | - |
| 7 | BLUELIGHT RAT: YARA System Reconnaissance JSON (APT_MAL_Win_BlueLight) | 🔴 critical | T1082, T1016, T1057 | - | - |
| 8 | BloodHound AD Enumeration | 🔴 critical | T1087.002 | 24 | - |
| 9 | Credential Dumping via Comsvcs with Rundll32 | 🔴 critical | T1003.001 | 14 | - |
| 10 | DCSync Attack via Replication Request | 🔴 critical | T1003.006 | 2 | - |
| 11 | DCSync: Directory Replication from Non-Domain Controller | 🔴 critical | T1003.006 | - | - |
| 12 | Disk Wipe via Format Command | 🔴 critical | T1561 | - | - |
| 13 | Forced Authentication via PetitPotam | 🔴 critical | T1187 | 3 | - |
| 14 | Golden Ticket: RC4 Encrypted TGT Request | 🔴 critical | T1558.001 | - | - |
| 15 | Kerberoasting: SPN Sweep - Multiple Service Tickets from Single Account | 🔴 critical | T1558.003 | - | - |
| 16 | Kerberos Ticket Export via Mimikatz | 🔴 critical | T1558 | 13 | - |
| 17 | Keylogging via PowerShell Get-Keystrokes | 🔴 critical | T1056.001 | 8 | - |
| 18 | LSASS Clone via ProcDump Evasion | 🔴 critical | T1003.001 | 14 | - |
| 19 | LSASS Memory Dump via Comsvcs DLL | 🔴 critical | T1003.001 | 14 | - |
| 20 | LaZagne Credential Harvester | 🔴 critical | T1555 | 8 | - |
| 21 | Mimikatz: Command and Module Indicators in Process Logs | 🔴 critical | T1003.001, T1003.006, T1558.003 | - | - |
| 22 | NTDS.dit Database Copy Attempt | 🔴 critical | T1003.003 | 11 | - |
| 23 | Named Pipe Impersonation via PowerShell | 🔴 critical | T1134.001 | 5 | - |
| 24 | Pass-the-Ticket via Rubeus | 🔴 critical | T1550.003 | 2 | - |
| 25 | Potato Privilege Escalation Tool | 🔴 critical | T1134.001 | 5 | - |
| 26 | PrintNightmare Exploitation Attempt | 🔴 critical | T1068 | - | - |
| 27 | Process Doppelganging via TxF | 🔴 critical | T1055.013 | 13 | - |
| 28 | Ransomware File Extension Indicators | 🔴 critical | T1486 | 10 | - |
| 29 | Reflective DLL Loading Indicators | 🔴 critical | T1620 | 1 | - |
| 30 | SSRF to Cloud Metadata Endpoint (169.254.169.254) | 🔴 critical | T1552.005, T1190 | - | - |
| 31 | Security Support Provider DLL Persistence | 🔴 critical | T1547.005 | 2 | - |
| 32 | Shadow Credentials Attack via Whisker | 🔴 critical | T1556 | 5 | - |
| 33 | Sysmon Cobalt Strike C2 Network Indicators | 🔴 critical | T1071.001, T1095 | 7 | - |
| 34 | Sysmon Cobalt Strike Named Pipe | 🔴 critical | T1071, T1055 | 14 | - |
| 35 | Sysmon Configuration Tampering | 🔴 critical | T1562.001 | 59 | - |
| 36 | Sysmon Mimikatz Named Pipe | 🔴 critical | T1003.001, T1134 | 27 | - |
| 37 | Sysmon Mimikatz Network Activity | 🔴 critical | T1003.001, T1558.003 | 21 | - |
| 38 | Sysmon Suspicious Named Pipe Pattern | 🔴 critical | T1071, T1059 | 2 | - |
| 39 | System Recovery Disabled via BCDEdit | 🔴 critical | T1490 | 13 | - |
| 40 | Volume Shadow Copy Deletion via WMIC | 🔴 critical | T1490 | 13 | - |
| 41 | Web Server Process Spawning Command Shell | 🔴 critical | T1059, T1059.001, T1190 | - | - |
| 42 | Windows Access Token Manipulation | 🔴 critical | T1134 | 13 | - |
| 43 | Windows Boot Configuration Modified | 🔴 critical | T1490 | 13 | - |
| 44 | Windows Credential Dumping via Procdump | 🔴 critical | T1003.001 | 14 | - |
| 45 | Windows Credential Dumping via Secretsdump | 🔴 critical | T1003 | 7 | - |
| 46 | Windows Defender Real-Time Protection Disabled | 🔴 critical | T1562.001 | 59 | - |
| 47 | Windows Kerberoasting Attack | 🔴 critical | T1558.003 | 7 | - |
| 48 | Windows Keylogger Indicators | 🔴 critical | T1056.001 | 8 | - |
| 49 | Windows LSASS Memory Access | 🔴 critical | T1003.001 | 14 | - |
| 50 | Windows Mimikatz Execution Patterns | 🔴 critical | T1003.001 | 14 | - |
| 51 | Windows NTDS.dit Database Extraction | 🔴 critical | T1003.003 | 11 | - |
| 52 | Windows Pass-the-Hash Attack Indicators | 🔴 critical | T1550.002 | 3 | - |
| 53 | Windows Process Hollowing Indicators | 🔴 critical | T1055.012 | 4 | - |
| 54 | Windows Shadow Copy Deletion | 🔴 critical | T1490 | 13 | - |
| 55 | Windows Spearphishing Attachment Execution | 🔴 critical | T1566.001, T1204.002 | 15 | - |
| 56 | AD Enumeration via ADFind | 🟠 high | T1087.002 | 24 | - |
| 57 | AMSI Bypass via PowerShell Reflection | 🟠 high | T1562.001 | 59 | - |
| 58 | AS-REP Roasting via Rubeus | 🟠 high | T1558.004 | 3 | - |
| 59 | Account Access Removal | 🟠 high | T1531 | 8 | - |
| 60 | Active Setup Persistence | 🟠 high | T1547.014 | 3 | - |
| 61 | Alternate Data Stream Execution | 🟠 high | T1564.004 | 5 | - |
| 62 | AppLocker Policy Bypass via MSHTML | 🟠 high | T1218.005 | 10 | - |
| 63 | BLUELIGHT RAT: Browser Spawning Suspicious Child Process | 🟠 high | T1203 | - | - |
| 64 | BLUELIGHT RAT: Data Exfiltration via OneDrive/Graph API | 🟠 high | T1567.002 | - | - |
| 65 | BLUELIGHT RAT: Executable Download via Graph API | 🟠 high | T1105 | - | - |
| 66 | BLUELIGHT RAT: Obfuscated Script Execution | 🟠 high | T1027 | - | - |
| 67 | BLUELIGHT RAT: Periodic Screen Capture | 🟠 high | T1113 | - | - |
| 68 | BLUELIGHT RAT: WMI System Enumeration from Browser Child | 🟠 high | T1082 | - | - |
| 69 | BLUELIGHT RAT: YARA Keylogger Component (APT_MAL_Win_BlueLight_B) | 🟠 high | T1056.001 | - | - |
| 70 | Boot Configuration Change for Persistence | 🟠 high | T1542 | 1 | - |
| 71 | Browser Credential Store Access | 🟠 high | T1555.003 | 17 | - |
| 72 | Brute Force: Failed Logon Spike per Account | 🟠 high | T1110.001, T1110.003 | - | - |
| 73 | CMD: Suspicious Command Execution (Real Windows Security Events) | 🟠 high | T1059.003 | - | - |
| 74 | CMSTP UAC Bypass | 🟠 high | T1218.003 | 2 | - |
| 75 | COM Object Hijacking via Registry | 🟠 high | T1546.015 | 4 | - |
| 76 | Credential Access via Certutil Certificate Export | 🟠 high | T1649 | 1 | - |
| 77 | Credential Dumping via Windows Task Manager | 🟠 high | T1003.001 | 14 | - |
| 78 | Cryptominer Deployment Indicators | 🟠 high | T1496 | 2 | - |
| 79 | DCOM Lateral Movement via MMC20 | 🟠 high | T1021.003 | 2 | - |
| 80 | DLL Execution via Rundll32 from User Path | 🟠 high | T1218.011 | 16 | - |
| 81 | DLL Hijacking via Service Registry Permission | 🟠 high | T1574.011 | 2 | - |
| 82 | DPAPI Master Key Extraction | 🟠 high | T1555 | 8 | - |
| 83 | Disable Windows Firewall via Netsh | 🟠 high | T1562.004 | 25 | - |
| 84 | ETW Provider Disabled | 🟠 high | T1562.002 | 10 | - |
| 85 | Email Collection via PowerShell | 🟠 high | T1114 | 3 | - |
| 86 | Group Policy Preferences Password Extraction | 🟠 high | T1552.006 | 2 | - |
| 87 | Image File Execution Options Debugger | 🟠 high | T1546.012 | 3 | - |
| 88 | InstallUtil Application Whitelisting Bypass | 🟠 high | T1218.004 | 8 | - |
| 89 | Internal Monologue NTLM Hash Theft | 🟠 high | T1003 | 7 | - |
| 90 | Kerberoasting: RC4 Encrypted Service Ticket Request | 🟠 high | T1558.003 | - | - |
| 91 | LSA Secrets Registry Extraction | 🟠 high | T1003.004 | 2 | - |
| 92 | Lateral Movement: Account Authenticating from Multiple Sources | 🟠 high | T1021.002, T1021.006 | - | - |
| 93 | MSBuild Execution from Non-Standard Location | 🟠 high | T1127.001 | 2 | - |
| 94 | MSHTA JavaScript Execution | 🟠 high | T1218.005 | 10 | - |
| 95 | Masquerading System Binary in Non-Standard Path | 🟠 high | T1036.005 | 3 | - |
| 96 | NPPSpy Credential Interception | 🟠 high | T1556 | 5 | - |
| 97 | Netsh Helper DLL Persistence | 🟠 high | T1546.007 | 1 | - |
| 98 | New Local Account Created via Net.exe | 🟠 high | T1136.001 | 10 | - |
| 99 | Parent PID Spoofing | 🟠 high | T1134.004 | 5 | - |
| 100 | Pass-the-Ticket: Excessive Explicit Credential Logons | 🟠 high | T1550.003 | - | - |
| 101 | Port Monitor DLL Persistence | 🟠 high | T1547.010 | 1 | - |
| 102 | PowerShell Script Block with Suspicious Keywords | 🟠 high | T1059.001 | 22 | - |
| 103 | PowerShell: Suspicious Command Execution (Real Windows Security Events) | 🟠 high | T1059.001, T1086 | - | - |
| 104 | Print Processor Persistence | 🟠 high | T1547.012 | 1 | - |
| 105 | Privilege Escalation: Sensitive Privileges Assigned to Non-Admin | 🟠 high | T1134, T1134.001 | - | - |
| 106 | Process Ghosting or Herpaderping | 🟠 high | T1055 | 13 | - |
| 107 | Process Injection via CreateRemoteThread | 🟠 high | T1055.001 | 2 | - |
| 108 | PsExec Service Installation | 🟠 high | T1021.002 | 4 | - |
| 109 | RDP Session Hijacking via tscon | 🟠 high | T1021.001 | 4 | - |
| 110 | Registry Run Key Modification via Reg.exe | 🟠 high | T1547.001 | 20 | - |
| 111 | Regsvcs or Regasm Execution for Code Bypass | 🟠 high | T1218.009 | 2 | - |
| 112 | Remote Service Creation via SC | 🟠 high | T1021.002 | 4 | - |
| 113 | Renamed System Binary Execution | 🟠 high | T1036.003 | 8 | - |
| 114 | Root Certificate Installation via Certutil | 🟠 high | T1553.004 | 7 | - |
| 115 | SAM Database Extraction via Reg Save | 🟠 high | T1003.002 | 8 | - |
| 116 | Screen Capture via PowerShell | 🟠 high | T1113 | 10 | - |
| 117 | Scripting Engine Spawning Network Utility | 🟠 high | T1059.005 | 3 | - |
| 118 | SeDebugPrivilege Abuse | 🟠 high | T1134 | 13 | - |
| 119 | Service Execution via sc.exe Create | 🟠 high | T1569.002 | 8 | - |
| 120 | Service Stop via Net Stop | 🟠 high | T1489 | 8 | - |
| 121 | SharpRDP Lateral Movement | 🟠 high | T1021.001 | 4 | - |
| 122 | Suspicious Scheduled Task Creation | 🟠 high | T1053.005 | 12 | - |
| 123 | SyncAppvPublishingServer Abuse | 🟠 high | T1218 | 16 | - |
| 124 | Sysmon C2 Beacon - Periodic Outbound HTTPS | 🟠 high | T1071.001, T1573 | 4 | - |
| 125 | Sysmon DNS Data Exfiltration | 🟠 high | T1048.003, T1071.004 | 12 | - |
| 126 | Sysmon DNS Query to Known C2 Framework Domains | 🟠 high | T1071.004, T1568.002 | 4 | - |
| 127 | Sysmon DNS Tunneling via Network Connection | 🟠 high | T1071.004, T1048.003 | 12 | - |
| 128 | Sysmon Kerberoasting Network Indicator | 🟠 high | T1558.003 | 7 | - |
| 129 | Sysmon Lateral Movement via SMB | 🟠 high | T1021.002, T1570 | 6 | - |
| 130 | Sysmon Lateral Movement via WinRM | 🟠 high | T1021.006, T1059.001 | 25 | - |
| 131 | Sysmon PsExec Named Pipe | 🟠 high | T1021.002, T1569.002 | 12 | - |
| 132 | Sysmon Suspicious Outbound Connection from LOLBin | 🟠 high | T1218, T1105 | 55 | - |
| 133 | Template Injection via Microsoft Office | 🟠 high | T1221 | 1 | - |
| 134 | Time Provider DLL Persistence | 🟠 high | T1547.003 | 2 | - |
| 135 | Timestomping via PowerShell | 🟠 high | T1070.006 | 10 | - |
| 136 | Token Impersonation via Incognito | 🟠 high | T1134 | 13 | - |
| 137 | UAC Bypass via ComputerDefaults | 🟠 high | T1548.002 | 27 | - |
| 138 | UAC Bypass via Eventvwr | 🟠 high | T1548.002 | 27 | - |
| 139 | UAC Bypass via Fodhelper | 🟠 high | T1548.002 | 27 | - |
| 140 | VBA Macro Spawning Suspicious Child Process | 🟠 high | T1204.002 | 13 | - |
| 141 | WMI Event Subscription Persistence | 🟠 high | T1546.003 | 3 | - |
| 142 | WMI Process Execution via Wmic | 🟠 high | T1047 | 10 | - |
| 143 | Windows AMSI Bypass Attempt | 🟠 high | T1562.001 | 59 | - |
| 144 | Windows BITS Job Abuse for Persistence | 🟠 high | T1197 | 4 | - |
| 145 | Windows Backup Deletion via wbadmin | 🟠 high | T1490 | 13 | - |
| 146 | Windows Certutil Download or Decode | 🟠 high | T1140, T1105 | 50 | - |
| 147 | Windows DLL Side-Loading via Suspicious Path | 🟠 high | T1574.002 | - | - |
| 148 | Windows Defender Exclusion Added via PowerShell | 🟠 high | T1562.001 | 59 | - |
| 149 | Windows Encoded PowerShell Execution | 🟠 high | T1059.001, T1027 | 32 | - |
| 150 | Windows Event Log Cleared via Wevtutil | 🟠 high | T1070.001 | 3 | - |
| 151 | Windows Event Log Clearing | 🟠 high | T1070.001 | 3 | - |
| 152 | Windows Firewall Rule Modification | 🟠 high | T1562.004 | 25 | - |
| 153 | Windows Management Instrumentation Event Subscription | 🟠 high | T1047 | 10 | - |
| 154 | Windows PowerShell Download Cradle | 🟠 high | T1059.001, T1105 | 61 | - |
| 155 | Windows PsExec Remote Execution | 🟠 high | T1021.002, T1569.002 | 12 | - |
| 156 | Windows Registry Run Key Modification | 🟠 high | T1547.001 | 20 | - |
| 157 | Windows Remote Access Tool Detected | 🟠 high | T1219 | 15 | - |
| 158 | Windows Remote Management Shell via Winrs | 🟠 high | T1021.006 | 3 | - |
| 159 | Windows Script Host Execution from Temp | 🟠 high | T1059.005 | 3 | - |
| 160 | Windows Service Created with Suspicious Binary Path | 🟠 high | T1543.003 | 6 | - |
| 161 | Windows UAC Bypass Attempt | 🟠 high | T1548.002 | 27 | - |
| 162 | Windows WDigest Authentication Enabled for Credential Harvesting | 🟠 high | T1003.001 | 14 | - |
| 163 | Windows WMI Event Subscription Persistence | 🟠 high | T1546.003 | 3 | - |
| 164 | Winlogon Helper DLL Modification | 🟠 high | T1547.004 | 5 | - |
| 165 | Wscript Running Encoded Script | 🟠 high | T1059.005 | 3 | - |
| 166 | XSL Script Processing via WMIC or Msxsl | 🟠 high | T1220 | 4 | - |
| 167 | AlwaysInstallElevated Exploitation | 🟡 medium | T1548.002 | 27 | - |
| 168 | Application Shimming for Persistence | 🟡 medium | T1546.011 | 3 | - |
| 169 | BITS Job Persistence | 🟡 medium | T1197 | 4 | - |
| 170 | BLUELIGHT RAT: C2 via Microsoft Graph API | 🟡 medium | T1071.001 | - | - |
| 171 | BLUELIGHT RAT: File Discovery from Browser Process | 🟡 medium | T1083 | - | - |
| 172 | BLUELIGHT RAT: Internet Explorer Drive-by Compromise | 🟡 medium | T1189 | - | - |
| 173 | BLUELIGHT RAT: Registry Enumeration of Security Products | 🟡 medium | T1012 | - | - |
| 174 | Clipboard Data Collection | 🟡 medium | T1115 | 5 | - |
| 175 | Compiled HTML File Execution | 🟡 medium | T1218.001 | 8 | - |
| 176 | Control Panel Item Execution | 🟡 medium | T1218 | 16 | - |
| 177 | Credential File Discovery | 🟡 medium | T1552.001 | 17 | - |
| 178 | Credential Manager: High-Frequency Credential Read | 🟡 medium | T1555.004 | - | - |
| 179 | DLL Side-Loading from Suspicious Directory | 🟡 medium | T1574.002 | - | - |
| 180 | Data Compression for Exfiltration via 7zip | 🟡 medium | T1560.001 | 12 | - |
| 181 | Defacement via Desktop Wallpaper Change | 🟡 medium | T1491.001 | 4 | - |
| 182 | Default File Association Hijack | 🟡 medium | T1546.001 | 1 | - |
| 183 | Domain Trust Discovery via Nltest | 🟡 medium | T1482 | 8 | - |
| 184 | File Deletion of Security Tools | 🟡 medium | T1070.004 | 11 | - |
| 185 | File and Directory Discovery via dir | 🟡 medium | T1083 | 9 | - |
| 186 | Finger.exe Abuse for File Download | 🟡 medium | T1105 | 39 | - |
| 187 | Hidden PowerShell Window Execution | 🟡 medium | T1564.003 | 3 | - |
| 188 | Indirect Command Execution via Forfiles | 🟡 medium | T1202 | 5 | - |
| 189 | JavaScript Execution via Node.js | 🟡 medium | T1059.007 | 2 | - |
| 190 | Office Application Startup Persistence | 🟡 medium | T1137 | 1 | - |
| 191 | Python Execution as Child of System Process | 🟡 medium | T1059.006 | 4 | - |
| 192 | Query Registry for Security Products | 🟡 medium | T1518.001 | 11 | - |
| 193 | SDelete Secure File Deletion | 🟡 medium | T1070.004 | 11 | - |
| 194 | Scheduled Task XML Import | 🟡 medium | T1053.005 | 12 | - |
| 195 | ScreenSaver Hijacking Persistence | 🟡 medium | T1546.002 | 1 | - |
| 196 | Security Group Enumeration: Rapid Membership Queries | 🟡 medium | T1069.002, T1087.002 | - | - |
| 197 | Service Permissions Weakness Discovery | 🟡 medium | T1574.011 | 2 | - |
| 198 | Shortcut Modification for Persistence | 🟡 medium | T1547.009 | 2 | - |
| 199 | Startup Folder Modification | 🟡 medium | T1547.001 | 20 | - |
| 200 | Sysmon DNS Query to Suspicious TLDs | 🟡 medium | T1071.004 | 4 | - |
| 201 | Sysmon LDAP Reconnaissance | 🟡 medium | T1087.002, T1069.002 | 39 | - |
| 202 | Sysmon RDP Lateral Movement | 🟡 medium | T1021.001 | 4 | - |
| 203 | System Shutdown or Reboot via shutdown.exe | 🟡 medium | T1529 | 16 | - |
| 204 | Token Manipulation via RunAs | 🟡 medium | T1134.002 | 2 | - |
| 205 | UAC Bypass via DiskCleanup | 🟡 medium | T1548.002 | 27 | - |
| 206 | Unquoted Service Path Exploitation | 🟡 medium | T1574.009 | 1 | - |
| 207 | Virtualization Sandbox Evasion Check | 🟡 medium | T1497 | 9 | - |
| 208 | Visual Basic Script Compilation via vbc.exe | 🟡 medium | T1059.005 | 3 | - |
| 209 | WiFi Password Extraction via Netsh | 🟡 medium | T1552.001 | 17 | - |
| 210 | WinRM Lateral Movement via PowerShell | 🟡 medium | T1021.006 | 3 | - |
| 211 | Windows Account Discovery Commands | 🟡 medium | T1087.001, T1087.002 | 35 | - |
| 212 | Windows Admin Share Access via Net Use | 🟡 medium | T1021.002 | 4 | - |
| 213 | Windows Credential Manager Access via VaultCmd | 🟡 medium | T1555 | 8 | - |
| 214 | Windows Data Staging for Exfiltration | 🟡 medium | T1074.001 | 3 | - |
| 215 | Windows LOLBin Usage: at | 🟡 medium | T1218 | 16 | - |
| 216 | Windows LOLBin Usage: bitsadmin | 🟡 medium | T1218 | 16 | - |
| 217 | Windows LOLBin Usage: certutil | 🟡 medium | T1218 | 16 | - |
| 218 | Windows LOLBin Usage: cmd | 🟡 medium | T1218 | 16 | - |
| 219 | Windows LOLBin Usage: cscript | 🟡 medium | T1218 | 16 | - |
| 220 | Windows LOLBin Usage: ipconfig | 🟡 medium | T1218 | 16 | - |
| 221 | Windows LOLBin Usage: mshta | 🟡 medium | T1218 | 16 | - |
| 222 | Windows LOLBin Usage: net | 🟡 medium | T1218 | 16 | - |
| 223 | Windows LOLBin Usage: net1 | 🟡 medium | T1218 | 16 | - |
| 224 | Windows LOLBin Usage: powershell | 🟡 medium | T1218 | 16 | - |
| 225 | Windows LOLBin Usage: regsvr32 | 🟡 medium | T1218 | 16 | - |
| 226 | Windows LOLBin Usage: rundll32 | 🟡 medium | T1218 | 16 | - |
| 227 | Windows LOLBin Usage: sc | 🟡 medium | T1218 | 16 | - |
| 228 | Windows LOLBin Usage: schtasks | 🟡 medium | T1218 | 16 | - |
| 229 | Windows LOLBin Usage: systeminfo | 🟡 medium | T1218 | 16 | - |
| 230 | Windows LOLBin Usage: taskkill | 🟡 medium | T1218 | 16 | - |
| 231 | Windows LOLBin Usage: tasklist | 🟡 medium | T1218 | 16 | - |
| 232 | Windows LOLBin Usage: whoami | 🟡 medium | T1218 | 16 | - |
| 233 | Windows LOLBin Usage: wmic | 🟡 medium | T1218 | 16 | - |
| 234 | Windows LOLBin Usage: wscript | 🟡 medium | T1218 | 16 | - |
| 235 | Windows MSBuild Execution for Code Bypass | 🟡 medium | T1127.001 | 2 | - |
| 236 | Windows Network Share Discovery | 🟡 medium | T1135 | 12 | - |
| 237 | Windows RDP Lateral Movement | 🟡 medium | T1021.001 | 4 | - |
| 238 | Windows Remote System Discovery | 🟡 medium | T1018 | 22 | - |
| 239 | Windows Scheduled Task Creation via Schtasks | 🟡 medium | T1053.005 | 12 | - |
| 240 | Windows Screen Capture Activity | 🟡 medium | T1113 | 10 | - |
| 241 | Windows Service Creation via SC | 🟡 medium | T1543.003 | 6 | - |
| 242 | Windows Vault Enumeration | 🟡 medium | T1555 | 8 | - |
| 243 | Lateral Tool Transfer via Robocopy | 🔵 low | T1570 | 2 | - |
| 244 | Local Group Membership Discovery | 🔵 low | T1069.001 | 7 | - |
| 245 | Network Share Enumeration via Net View | 🔵 low | T1135 | 12 | - |
| 246 | Password Policy Discovery | 🔵 low | T1201 | 12 | - |
| 247 | PowerShell Execution via Alternate Shell | 🔵 low | T1059.001 | 22 | - |
| 248 | Process Discovery via Tasklist | 🔵 low | T1057 | 9 | - |
| 249 | Software Discovery via WMIC | 🔵 low | T1518 | 6 | - |

## App / APM Queries

| # | Title | Type | Severity | MITRE |
|---|-------|------|----------|-------|
| 1 | APM: Browser Fingerprinting via Canvas/WebGL/AudioContext | Source-derived browser detection | 🟡 medium | T1592.004 |
| 2 | APM: Clickjacking - Missing Frame Protection Headers | Source-derived browser detection | 🟡 medium | T1185 |
| 3 | APM: CSRF Token Missing or Invalid on State-Changing Request | Source-derived browser detection | 🟡 medium | T1185 |
| 4 | APM: DOM-Based Attack via Dangerous JavaScript APIs | Source-derived browser detection | 🟠 high | T1059.007 |
| 5 | APM: Session Hijacking - Rapid Session Changes | Source-derived browser detection | 🟠 high | T1539, T1550.004 |
| 6 | APM: SQL Injection Attack in Request | Source-derived browser detection | 🔴 critical | T1190 |
| 7 | APM: Suspicious JavaScript Execution Patterns | Source-derived browser detection | 🟠 high | T1059.007, T1056.001, T1496 |
| 8 | APM: Cross-Site Scripting (XSS) Attack in Request | Source-derived browser detection | 🟠 high | T1189, T1059.007 |
| 9 | Application Authentication Brute Force | Curated application analytics | 🟠 high | T1110, T1110.003 |
| 10 | Cross-Service Trace Correlation (CRM ↔ Drone Shop) | Curated application analytics | ⚪ informational | - |
| 11 | Database Performance Correlation (ATP → APM → Logs) | Curated application analytics | ⚪ informational | - |
| 12 | Application Error Rate by Service | Curated application analytics | 🟠 high | T1499 |
| 13 | Order Sync Pipeline Health (Drone Shop → CRM) | Curated application analytics | 🟡 medium | - |
| 14 | OWASP Attack Detection (CRM + Drone Shop) | Curated application analytics | 🔴 critical | T1190, T1059, T1110 |
| 15 | Request Rate by Service and Endpoint | Curated application analytics | ⚪ informational | - |
| 16 | Security Attack Source IP Analysis | Curated application analytics | 🟠 high | T1190, T1110 |
| 17 | Application Service Health Timeline | Curated application analytics | ⚪ informational | - |
| 18 | Slow Request Detection (>2s) | Curated application analytics | 🟡 medium | T1499 |
| 19 | SQL Injection and XSS Attack Detection | Curated application analytics | 🔴 critical | T1190, T1059.007 |
| 20 | WAF Signal Correlation with Application Traces | Curated application analytics | 🟠 high | T1562, T1190 |

## Hunting Queries

| # | Title | Method | Severity | MITRE |
|---|-------|--------|----------|-------|
| 1 | Hunting: AD Attack Timeline - Multi-Stage Credential Attack Chain | - | 🔴 critical | T1003.006, T1558.003, T1110.001, T1134, T1550.003 |
| 2 | BLUELIGHT APT37 Kill Chain Correlation | - | 🔴 critical | T1189, T1203, T1027, T1071.001, T1082, T1012, T1083, T1113, T1555.003, T1105, T1567.002 |
| 3 | Browser Attack Frequency Analysis (SOC Application Logs) | - | 🔴 critical | T1190, T1189, T1059.007, T1496 |
| 4 | Hunting: Credential Attack Correlation (PowerShell + Mimikatz + Kerberoast) | - | 🔴 critical | T1003.001, T1558.003, T1059.001 |
| 5 | DNS Exfiltration Detection (Entropy Analysis) | field_analysis | 🟠 high | T1048, T1071.004 |
| 6 | Hunting: Kerberoasting Anomaly - RC4 vs AES Encryption Ratio | - | 🔴 critical | T1558.003 |
| 7 | Linux Data Staging and Exfiltration Indicators | combined_scoring | 🟠 high | T1560.001, T1074.001 |
| 8 | Linux Multi-Stage Attack Indicators (Combined Methods) | multi_stage | 🔴 critical | T1110, T1059.004 |
| 9 | Linux Persistence Indicator Score (Combined Methods) | scoring | 🟠 high | T1053, T1543.002, T1098.004 |
| 10 | Linux Rare Process Detection (Stacking) | rare_value | 🟡 medium | T1059.004 |
| 11 | Hunting: Logon Anomaly - Account Activity Profiling | - | 🟠 high | T1078, T1021, T1134 |
| 12 | Geographic Health: Cloud Provider Summary | aggregation | ⚪ informational | - |
| 13 | Geographic Health: Instance Detail with Coordinates | detail_view | ⚪ informational | - |
| 14 | Geographic Health: Regional Status on Global Map | geographic_analysis | ⚪ informational | - |
| 15 | Geographic Health: Service Tier Status | aggregation | ⚪ informational | - |
| 16 | Geographic Health: Unhealthy Regions Alert | alerting | 🟠 high | - |
| 17 | C2 Beaconing Detection (Periodic Connection Analysis) | frequency_analysis | 🟠 high | T1071, T1573 |
| 18 | OCI After-Hours IAM Activity (Time-Based Anomaly) | time_anomaly | 🟡 medium | T1098 |
| 19 | OCI Console Login Brute Force (Frequency Analysis) | frequency_analysis | 🟠 high | T1078, T1110 |
| 20 | OCI IAM and Fusion Activity Correlation | grouping_correlation | 🟠 high | T1078, T1098 |
| 21 | OCI IAM Rapid Configuration Changes (Anomaly Detection) | anomaly_detection | 🟠 high | T1098, T1078 |
| 22 | OCI Multiple Users from Same IP (Grouping) | grouping | 🟠 high | T1078, T1110.004 |
| 23 | OCI Privilege Escalation Chain Detection | combined_scoring | 🔴 critical | T1098, T1078 |
| 24 | OCI Resource Destruction Spike (Anomaly Detection) | anomaly_detection | 🔴 critical | T1485, T1489 |
| 25 | SSH Brute Force Detection (Frequency Analysis) | frequency_analysis | 🟠 high | T1110.001 |
| 26 | Login Activity Time-Series Anomaly | time_series_anomaly | 🟠 high | T1078, T1110 |
| 27 | WAF Attack Frequency by Source IP (Frequency Analysis) | frequency_analysis | 🟠 high | T1190 |
| 28 | WAF Multi-Attack Vector Scoring (Combined Methods) | scoring | 🔴 critical | T1190, T1059 |
| 29 | SQL Injection Pattern Stacking (Rare Value Detection) | rare_value | 🟠 high | T1190 |
| 30 | Web Attack Geographic Anomaly (Rare Country Detection) | rare_value | 🟡 medium | T1190 |
| 31 | Web Application Brute Force Detection (Frequency Analysis) | frequency_analysis | 🟠 high | T1110.001, T1110.003 |
| 32 | Web Directory Scanning IP Clustering (Anomaly Detection) | anomaly_detection | 🟡 medium | T1595.002 |
| 33 | OWASP Multi-Stage Web Attack Chain (Combined Methods) | multi_stage | 🔴 critical | T1190, T1110, T1059 |
| 34 | Web Scanner Tool Identification (User Agent Stacking) | rare_value | 🟡 medium | T1595.002 |
| 35 | Windows Credential Access Tool Cluster (Grouping) | grouping | 🔴 critical | T1003, T1558.003 |
| 36 | Windows Defense Evasion Score (Combined Methods) | scoring | 🔴 critical | T1562, T1548.002, T1070 |
| 37 | Windows Lateral Movement Tool Cluster (Grouping) | grouping | 🔴 critical | T1021, T1570 |
| 38 | Windows Suspiciously Long Command Line (Field Analysis) | field_analysis | 🟠 high | T1059.001, T1027 |
| 39 | Windows Process from Unusual Path (Rare Value Analysis) | rare_value | 🟠 high | T1204, T1036 |
| 40 | Windows Rare Process Detection (Stacking) | rare_value | 🟡 medium | T1059 |

## STIG Compliance Rules

| Rule | STIG Control | Category | Severity |
|------|-------------|----------|----------|
| OCI Bastion Session Created | AC-17 | CAT II | medium |
| OCI Instance Console Connection Created | AC-17 | CAT I | high |
| OCI Object Storage Pre-Authenticated Request Created | AC-3 | CAT I | high |
| OCI Compartment Deleted | AC-6 | CAT I | critical |
| OCI Dynamic Group Created | AC-6 | CAT II | medium |
| OCI Audit Configuration Changed | AU-11 | CAT I | high |
| OCI Log Group Deleted | AU-11 | CAT I | critical |
| OCI Cloud Infrastructure Discovery | AU-12 | CAT III | low |
| OCI Cloud Shell Session Started | AU-12 | CAT III | low |
| OCI Function Invoked | AU-12 | CAT III | low |
| OCI Notification Subscription Created | AU-12 | CAT II | medium |
| OCI Database System Terminated | CP-9 | CAT I | critical |
| OCI Password Spraying Attack | IA-2 | CAT I | high |
| OCI User MFA Not Enabled | IA-2 | CAT I | high |
| OCI Auth Token Created | IA-5 | CAT II | medium |
| OCI Customer Secret Key Created | IA-5 | CAT I | high |
| OCI User Password Reset by Admin | IA-5 | CAT I | high |
| OCI Identity Provider Created | IA-8 | CAT I | high |
| OCI Vault Key Rotation Overdue | SC-12 | CAT II | medium |
| OCI Cross-Region Data Copy | SC-28 | CAT I | high |
| OCI Vault Secret Deleted | SC-28 | CAT I | high |
| OCI Network Firewall Policy Modified | SC-7 | CAT I | high |
| OCI Security List Allows All Protocols | SC-7 | CAT I | high |
| OCI VCN Peering Connection Created | SC-7 | CAT II | medium |

---
*Generated from 454 Sigma source rules routed to 446 top-level detection queries and 8 browser app queries, plus 12 curated app/APM analytics and 40 hunting queries*