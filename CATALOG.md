# Detection Rule Catalog

> **478 base detection queries** + **24 app/APM queries** + **45 hunting queries**

## Summary

| Content Surface | Count | Notes |
|-----------------|-------|-------|
| Base detection queries | 478 | Sigma-derived detections in `queries/` |
| App/APM queries | 24 | 8 Sigma-derived browser detections + 16 curated analytics in `queries/apps/` |
| Hunting queries | 45 | Curated analytics and correlation content in `queries/hunting/` |

**Source YAML rules:** 454 total (cloud: 100, linux: 67, web: 38, windows: 249)

| Platform | Rules |
|----------|-------|
| OCI Cloud | 138 |
| Linux | 67 |
| Windows | 273 |

| Severity | Count |
|----------|-------|
| 🔴 Critical | 89 |
| 🟠 High | 208 |
| 🟡 Medium | 133 |
| 🔵 Low | 18 |
| ⚪ Informational | 30 |

**Atomic Red Team Coverage:** 278/340 testable rules have ART tests (82%) | 3217 total test mappings

**STIG Coverage:** 24 rules covering 12 controls (AC-17, AC-3, AC-6, AU-11, AU-12, CP-9, IA-2, IA-5, IA-8, SC-12, SC-28, SC-7)

## MITRE ATT&CK Coverage

**211 techniques** across **14 tactics**

### Initial Access (33 techniques)

| Technique | Rules |
|-----------|-------|
| T1012 | BLUELIGHT APT37 Kill Chain Correlation |
| T1027 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1056.001 | BLUELIGHT: Attack Path (per Host) |
| T1059 | WAF Log4Shell (CVE-2021-44228) Attack Blocked, Web Server Process Spawning Command Shell, +4 more |
| T1059.001 | Web Server Process Spawning Command Shell |
| T1059.004 | Linux Multi-Stage Attack Indicators (Combined Methods) |
| T1059.007 | APM: Cross-Site Scripting (XSS) Attack in Request, WAF SQL Injection Attack Allowed Through, +5 more |
| T1071.001 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), +4 more |
| T1078 | API Endpoint Unauthorized Access Attempts, OCI Console Login Failure, +7 more |
| T1082 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1083 | WAF Path Traversal Attack Blocked, BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1098 | OCI IAM and Fusion Activity Correlation |
| T1105 | BLUELIGHT APT37 Kill Chain Correlation |
| T1110 | OWASP Attack Detection (CRM + Drone Shop), Security Attack Source IP Analysis, +4 more |
| T1110.001 | Linux SSH Failed Login, SSH Brute Force Detection (Frequency Analysis) |
| T1110.003 | OCI Password Spraying Attack |
| T1110.004 | OCI Multiple Users from Same IP (Grouping) |
| T1113 | BLUELIGHT APT37 Kill Chain Correlation |
| T1133 | Cloud Guard Problem: VCN Security List Port RDP, Cloud Guard Problem: VCN Security List Port SSH, Linux External Remote Service Abuse |
| T1185 | APM: Clickjacking - Missing Frame Protection Headers, APM: CSRF Token Missing or Invalid on State-Changing Request, +2 more |
| T1189 | APM: Cross-Site Scripting (XSS) Attack in Request, BLUELIGHT RAT: Internet Explorer Drive-by Compromise, +11 more |
| T1190 | API Endpoint Unauthorized Access Attempts, APM: SQL Injection Attack in Request, +32 more |
| T1203 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), +2 more |
| T1204.002 | Windows Spearphishing Attachment Execution |
| T1496 | Browser Attack Frequency Analysis (SOC Application Logs) |
| T1550 | Web Application Authentication Bypass |
| T1552.005 | SSRF to Cloud Instance Metadata Service (Linux), SSRF to Cloud Metadata Endpoint (169.254.169.254), WAF Server-Side Request Forgery Blocked |
| T1555.003 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), +4 more |
| T1562 | WAF Signal Correlation with Application Traces |
| T1566.001 | Windows Spearphishing Attachment Execution |
| T1567.002 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), BLUELIGHT: Total Detections (24h) |
| T1606 | OCI Federated Identity Provider Modified |
| T1621 | OCI MFA Fatigue Attack Indicators |

### Execution (40 techniques)

| Technique | Rules |
|-----------|-------|
| T1003.001 | Hunting: Credential Attack Correlation (PowerShell + Mimikatz + Kerberoast) |
| T1012 | BLUELIGHT APT37 Kill Chain Correlation |
| T1021.002 | Sysmon PsExec Named Pipe |
| T1021.006 | Sysmon Lateral Movement via WinRM |
| T1027 | Windows Encoded PowerShell Execution, BLUELIGHT APT37 Kill Chain Correlation, +2 more |
| T1036 | Windows Process from Unusual Path (Rare Value Analysis) |
| T1047 | Windows Management Instrumentation Event Subscription, WMI Process Execution via Wmic |
| T1053.005 | Suspicious Scheduled Task Creation |
| T1056.001 | APM: Suspicious JavaScript Execution Patterns, APM: Suspicious JavaScript Execution Patterns, BLUELIGHT: Attack Path (per Host) |
| T1059 | Insecure Deserialization Attack Detected, Linux Process Execution from /dev/shm, +10 more |
| T1059.001 | PowerShell Execution via Alternate Shell, PowerShell Script Block with Suspicious Keywords, +8 more |
| T1059.003 | CMD: Suspicious Command Execution (Real Windows Security Events), CMD: Suspicious Command Execution (Real Windows Security Events) |
| T1059.004 | Linux Bind Shell Listener, OCI Cloud Shell Session Started, +2 more |
| T1059.005 | Scripting Engine Spawning Network Utility, Visual Basic Script Compilation via vbc.exe, +2 more |
| T1059.006 | Python Execution as Child of System Process |
| T1059.007 | APM: DOM-Based Attack via Dangerous JavaScript APIs, APM: Suspicious JavaScript Execution Patterns, +7 more |
| T1071 | Sysmon Suspicious Named Pipe Pattern |
| T1071.001 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), +4 more |
| T1082 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1083 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1086 | PowerShell: Suspicious Command Execution (Real Windows Security Events), PowerShell: Suspicious Command Execution (Real Windows Security Events) |
| T1105 | Finger.exe Abuse for File Download, Windows PowerShell Download Cradle, BLUELIGHT APT37 Kill Chain Correlation |
| T1110 | OWASP Attack Detection (CRM + Drone Shop), Linux Multi-Stage Attack Indicators (Combined Methods), OWASP Multi-Stage Web Attack Chain (Combined Methods) |
| T1113 | BLUELIGHT APT37 Kill Chain Correlation |
| T1127.001 | MSBuild Execution from Non-Standard Location, Windows MSBuild Execution for Code Bypass |
| T1189 | APM: Cross-Site Scripting (XSS) Attack in Request, BLUELIGHT APT37 Kill Chain Correlation, +6 more |
| T1190 | Insecure Deserialization Attack Detected, WAF Command Injection Attack Blocked, +9 more |
| T1203 | BLUELIGHT RAT: Browser Spawning Suspicious Child Process, BLUELIGHT RAT: Browser Spawning Suspicious Child Process, +4 more |
| T1204 | OCI Action: StartInstance, Suspicious Usage of base64, +27 more |
| T1204.002 | BLUELIGHT RAT: YARA PDB Path Indicators (APT_MAL_Win_BlueLight), VBA Macro Spawning Suspicious Child Process, Windows Spearphishing Attachment Execution |
| T1218 | Control Panel Item Execution, SyncAppvPublishingServer Abuse |
| T1218.005 | MSHTA JavaScript Execution |
| T1218.011 | DLL Execution via Rundll32 from User Path |
| T1496 | APM: Suspicious JavaScript Execution Patterns, Browser Attack Frequency Analysis (SOC Application Logs) |
| T1555.003 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), +4 more |
| T1558.003 | Hunting: Credential Attack Correlation (PowerShell + Mimikatz + Kerberoast) |
| T1566.001 | Windows Spearphishing Attachment Execution |
| T1567.002 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), BLUELIGHT: Total Detections (24h) |
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
| T1558.001 | Golden Ticket: RC4 Encrypted TGT Request, Golden Ticket: RC4 Encrypted TGT Request |
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
| T1134 | Privilege Escalation: Sensitive Privileges Assigned to Non-Admin, Privilege Escalation: Sensitive Privileges Assigned to Non-Admin, +4 more |
| T1134.001 | Named Pipe Impersonation via PowerShell, Potato Privilege Escalation Tool, +2 more |
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

### Defense Evasion (64 techniques)

| Technique | Rules |
|-----------|-------|
| T1003.001 | Windows WDigest Authentication Enabled for Credential Harvesting |
| T1012 | BLUELIGHT APT37 Kill Chain Correlation |
| T1027 | BLUELIGHT RAT: Obfuscated Script Execution, BLUELIGHT RAT: Obfuscated Script Execution, +4 more |
| T1036 | Windows Process from Unusual Path (Rare Value Analysis) |
| T1036.003 | Renamed System Binary Execution |
| T1036.005 | Masquerading System Binary in Non-Standard Path |
| T1055 | Process Ghosting or Herpaderping, Sysmon Cobalt Strike Named Pipe |
| T1055.001 | Process Injection via CreateRemoteThread |
| T1055.008 | Linux Process Injection via Ptrace |
| T1055.012 | Windows Process Hollowing Indicators |
| T1055.013 | Process Doppelganging via TxF |
| T1056.001 | BLUELIGHT: Attack Path (per Host) |
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
| T1071.001 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1082 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1083 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1098 | OCI After-Hours IAM Activity (Time-Based Anomaly) |
| T1105 | Sysmon Suspicious Outbound Connection from LOLBin, Windows Certutil Download or Decode, BLUELIGHT APT37 Kill Chain Correlation |
| T1113 | BLUELIGHT APT37 Kill Chain Correlation |
| T1127.001 | Windows MSBuild Execution for Code Bypass |
| T1134 | Windows Access Token Manipulation |
| T1140 | Windows Certutil Download or Decode |
| T1189 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1190 | WAF Signal Correlation with Application Traces |
| T1197 | Windows BITS Job Abuse for Persistence |
| T1202 | Indirect Command Execution via Forfiles |
| T1203 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
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
| T1555.003 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
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
| T1567.002 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1574.002 | DLL Side-Loading from Suspicious Directory, Windows DLL Side-Loading via Suspicious Path |
| T1600 | OCI Vault Key Rotation Overdue |
| T1620 | Reflective DLL Loading Indicators |

### Credential Access (48 techniques)

| Technique | Rules |
|-----------|-------|
| T1003 | Internal Monologue NTLM Hash Theft, Windows Credential Dumping via Secretsdump, Windows Credential Access Tool Cluster (Grouping) |
| T1003.001 | Credential Dumping via Comsvcs with Rundll32, Credential Dumping via Windows Task Manager, +11 more |
| T1003.002 | SAM Database Extraction via Reg Save |
| T1003.003 | NTDS.dit Database Copy Attempt, Windows NTDS.dit Database Extraction |
| T1003.004 | LSA Secrets Registry Extraction |
| T1003.006 | DCSync Attack via Replication Request, DCSync: Directory Replication from Non-Domain Controller, +4 more |
| T1003.007 | Linux Process Memory Access via /proc |
| T1005 | Linux Sensitive Data Collection from Local System |
| T1012 | BLUELIGHT APT37 Kill Chain Correlation |
| T1021 | Hunting: Logon Anomaly - Account Activity Profiling |
| T1027 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1056.001 | Windows Keylogger Indicators, BLUELIGHT: Attack Path (per Host) |
| T1059 | OWASP Attack Detection (CRM + Drone Shop), OWASP Multi-Stage Web Attack Chain (Combined Methods) |
| T1059.001 | Hunting: Credential Attack Correlation (PowerShell + Mimikatz + Kerberoast) |
| T1071.001 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), +4 more |
| T1078 | Hunting: Logon Anomaly - Account Activity Profiling, OCI Console Login Brute Force (Frequency Analysis), Login Activity Time-Series Anomaly |
| T1082 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1083 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1098.001 | OCI Customer Secret Key Created |
| T1105 | BLUELIGHT APT37 Kill Chain Correlation |
| T1110 | Cloud Guard Problem: IAM User Console Password Old, WAF Rate Limiting Triggered, +6 more |
| T1110.001 | Brute Force: Failed Logon Spike per Account, Brute Force: Failed Logon Spike per Account, +5 more |
| T1110.003 | Brute Force: Failed Logon Spike per Account, Brute Force: Failed Logon Spike per Account, +4 more |
| T1113 | BLUELIGHT APT37 Kill Chain Correlation |
| T1114 | BLUELIGHT RAT: YARA Chrome/Edge Cookie Theft (APT_MAL_Win_BlueLight_B) |
| T1134 | Sysmon Mimikatz Named Pipe, Token Impersonation via Incognito, +2 more |
| T1187 | Forced Authentication via PetitPotam |
| T1189 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), +4 more |
| T1190 | SSRF to Cloud Instance Metadata Service (Linux), SSRF to Cloud Metadata Endpoint (169.254.169.254), +3 more |
| T1203 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), +2 more |
| T1528 | OCI Auth Token Created |
| T1539 | APM: Session Hijacking - Rapid Session Changes, BLUELIGHT RAT: YARA Chrome/Edge Cookie Theft (APT_MAL_Win_BlueLight_B), +2 more |
| T1550.003 | Pass-the-Ticket: Excessive Explicit Credential Logons, Pass-the-Ticket: Excessive Explicit Credential Logons, Hunting: AD Attack Timeline - Multi-Stage Credential Attack Chain |
| T1550.004 | APM: Session Hijacking - Rapid Session Changes, Web Application Session Hijacking Indicators, APM: Session Hijacking - Rapid Session Changes |
| T1552.001 | Credential File Discovery, WiFi Password Extraction via Netsh |
| T1552.004 | Cloud Guard Problem: IAM User API Key Old |
| T1552.005 | OCI Instance Metadata Service Accessed, SSRF to Cloud Instance Metadata Service (Linux), SSRF to Cloud Metadata Endpoint (169.254.169.254) |
| T1552.006 | Group Policy Preferences Password Extraction |
| T1555 | DPAPI Master Key Extraction, LaZagne Credential Harvester, +2 more |
| T1555.003 | BLUELIGHT RAT: Browser Credential Memory Access, BLUELIGHT RAT: Browser Credential Memory Access, +8 more |
| T1555.004 | Credential Manager: High-Frequency Credential Read, Credential Manager: High-Frequency Credential Read |
| T1556 | NPPSpy Credential Interception, OCI User MFA Not Enabled, Shadow Credentials Attack via Whisker |
| T1558 | Kerberos Ticket Export via Mimikatz |
| T1558.001 | Golden Ticket: RC4 Encrypted TGT Request, Golden Ticket: RC4 Encrypted TGT Request |
| T1558.003 | Kerberoasting: RC4 Encrypted Service Ticket Request, Kerberoasting: RC4 Encrypted Service Ticket Request, +11 more |
| T1558.004 | AS-REP Roasting via Rubeus |
| T1567.002 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), BLUELIGHT: Total Detections (24h) |
| T1649 | Credential Access via Certutil Certificate Export |

### Discovery (27 techniques)

| Technique | Rules |
|-----------|-------|
| T1012 | BLUELIGHT RAT: Registry Enumeration of Security Products, BLUELIGHT RAT: Registry Enumeration of Security Products, BLUELIGHT APT37 Kill Chain Correlation |
| T1016 | BLUELIGHT RAT: YARA System Reconnaissance JSON (APT_MAL_Win_BlueLight) |
| T1018 | Windows Remote System Discovery |
| T1027 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1033 | Linux System Owner and User Discovery |
| T1046 | Linux Network Service Scanning |
| T1056.001 | BLUELIGHT: Attack Path (per Host) |
| T1057 | BLUELIGHT RAT: YARA System Reconnaissance JSON (APT_MAL_Win_BlueLight), Process Discovery via Tasklist |
| T1069.001 | Local Group Membership Discovery |
| T1069.002 | Security Group Enumeration: Rapid Membership Queries, Security Group Enumeration: Rapid Membership Queries, Sysmon LDAP Reconnaissance |
| T1071.001 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), BLUELIGHT: Total Detections (24h) |
| T1082 | BLUELIGHT RAT: WMI System Enumeration from Browser Child, BLUELIGHT RAT: WMI System Enumeration from Browser Child, +4 more |
| T1083 | BLUELIGHT RAT: File Discovery from Browser Process, BLUELIGHT RAT: File Discovery from Browser Process, +3 more |
| T1087.001 | Windows Account Discovery Commands |
| T1087.002 | AD Enumeration via ADFind, BloodHound AD Enumeration, +4 more |
| T1105 | BLUELIGHT APT37 Kill Chain Correlation |
| T1113 | BLUELIGHT APT37 Kill Chain Correlation |
| T1135 | Network Share Enumeration via Net View, Windows Network Share Discovery |
| T1189 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), BLUELIGHT: Total Detections (24h) |
| T1201 | Password Policy Discovery |
| T1203 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1482 | Domain Trust Discovery via Nltest |
| T1518 | Software Discovery via WMIC |
| T1518.001 | Query Registry for Security Products |
| T1555.003 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), BLUELIGHT: Total Detections (24h) |
| T1567.002 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), BLUELIGHT: Total Detections (24h) |
| T1580 | OCI Cloud Infrastructure Discovery |

### Lateral Movement (18 techniques)

| Technique | Rules |
|-----------|-------|
| T1003.006 | Hunting: AD Attack Timeline - Multi-Stage Credential Attack Chain |
| T1021 | OCI Bastion Session Created, OCI Instance Console Connection Created, +3 more |
| T1021.001 | RDP Session Hijacking via tscon, SharpRDP Lateral Movement, +2 more |
| T1021.002 | Lateral Movement: Account Authenticating from Multiple Sources, Lateral Movement: Account Authenticating from Multiple Sources, +6 more |
| T1021.003 | DCOM Lateral Movement via MMC20 |
| T1021.006 | Lateral Movement: Account Authenticating from Multiple Sources, Lateral Movement: Account Authenticating from Multiple Sources, +3 more |
| T1059.001 | Sysmon Lateral Movement via WinRM |
| T1078 | Hunting: Logon Anomaly - Account Activity Profiling |
| T1110.001 | Hunting: AD Attack Timeline - Multi-Stage Credential Attack Chain |
| T1134 | Hunting: AD Attack Timeline - Multi-Stage Credential Attack Chain, Hunting: Logon Anomaly - Account Activity Profiling |
| T1539 | APM: Session Hijacking - Rapid Session Changes |
| T1550.002 | Windows Pass-the-Hash Attack Indicators |
| T1550.003 | Pass-the-Ticket: Excessive Explicit Credential Logons, Pass-the-Ticket via Rubeus, +2 more |
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
| T1027 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1056.001 | APM: Suspicious JavaScript Execution Patterns, BLUELIGHT RAT: YARA Keylogger Component (APT_MAL_Win_BlueLight_B), +4 more |
| T1059.007 | APM: Suspicious JavaScript Execution Patterns, APM: Suspicious JavaScript Execution Patterns |
| T1071.001 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), BLUELIGHT: Total Detections (24h) |
| T1074.001 | Windows Data Staging for Exfiltration, Linux Data Staging and Exfiltration Indicators |
| T1082 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1083 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1105 | BLUELIGHT APT37 Kill Chain Correlation |
| T1113 | BLUELIGHT RAT: Periodic Screen Capture, BLUELIGHT RAT: Periodic Screen Capture, +3 more |
| T1114 | BLUELIGHT RAT: YARA Chrome/Edge Cookie Theft (APT_MAL_Win_BlueLight_B), Email Collection via PowerShell, OCI Notification Subscription Created |
| T1115 | Clipboard Data Collection |
| T1189 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), BLUELIGHT: Total Detections (24h) |
| T1203 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1496 | APM: Suspicious JavaScript Execution Patterns |
| T1530 | OCI Action: CreateBucket |
| T1539 | BLUELIGHT RAT: YARA Chrome/Edge Cookie Theft (APT_MAL_Win_BlueLight_B) |
| T1552.001 | Sensitive Data Endpoint Access |
| T1555.003 | BLUELIGHT RAT: YARA Chrome/Edge Cookie Theft (APT_MAL_Win_BlueLight_B), BLUELIGHT APT37 Kill Chain Correlation, +2 more |
| T1557 | Linux Suspicious Network Traffic Redirect |
| T1560.001 | Data Compression for Exfiltration via 7zip, Linux Archive Data Collected for Exfiltration, Linux Data Staging and Exfiltration Indicators |
| T1567.002 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), BLUELIGHT: Total Detections (24h) |

### Command & Control (30 techniques)

| Technique | Rules |
|-----------|-------|
| T1012 | BLUELIGHT APT37 Kill Chain Correlation |
| T1027 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1048 | DNS Exfiltration Detection (Entropy Analysis) |
| T1048.003 | Sysmon DNS Data Exfiltration, Sysmon DNS Tunneling via Network Connection |
| T1055 | Sysmon Cobalt Strike Named Pipe |
| T1056.001 | BLUELIGHT: Attack Path (per Host) |
| T1059 | Sysmon Suspicious Named Pipe Pattern |
| T1059.001 | Windows PowerShell Download Cradle |
| T1071 | Sysmon Cobalt Strike Named Pipe, Sysmon Suspicious Named Pipe Pattern, C2 Beaconing Detection (Periodic Connection Analysis) |
| T1071.001 | BLUELIGHT RAT: C2 via Microsoft Graph API, BLUELIGHT RAT: C2 via Microsoft Graph API, +9 more |
| T1071.004 | Linux DNS Tunneling Detected, Sysmon DNS Data Exfiltration, +4 more |
| T1082 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1083 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1090 | Linux Proxy and Tunneling Tool Detected |
| T1090.001 | Linux Proxy and Tunneling Tool Detected |
| T1095 | Sysmon Cobalt Strike C2 Network Indicators |
| T1102 | BLUELIGHT RAT: YARA Google App C2 Communication (APT_MAL_Win_BlueLight_B) |
| T1105 | BLUELIGHT RAT: Executable Download via Graph API, BLUELIGHT RAT: Executable Download via Graph API, +5 more |
| T1113 | BLUELIGHT APT37 Kill Chain Correlation |
| T1140 | Windows Certutil Download or Decode |
| T1189 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), +4 more |
| T1203 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), +2 more |
| T1218 | Sysmon Suspicious Outbound Connection from LOLBin |
| T1219 | Windows Remote Access Tool Detected |
| T1555.003 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), +4 more |
| T1567.002 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), BLUELIGHT: Total Detections (24h) |
| T1568.002 | Sysmon DNS Query to Known C2 Framework Domains |
| T1572 | Linux SSH Tunneling Detected |
| T1573 | Linux Encrypted Channel C2 Communication, Sysmon C2 Beacon - Periodic Outbound HTTPS, C2 Beaconing Detection (Periodic Connection Analysis) |
| T1573.002 | Linux Encrypted Channel C2 Communication |

### Exfiltration (20 techniques)

| Technique | Rules |
|-----------|-------|
| T1012 | BLUELIGHT APT37 Kill Chain Correlation |
| T1027 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1041 | Unusually Large HTTP Response (Data Exfiltration) |
| T1048 | Linux Exfiltration Over Alternative Protocol, Unusually Large HTTP Response (Data Exfiltration), DNS Exfiltration Detection (Entropy Analysis) |
| T1048.003 | Sysmon DNS Data Exfiltration, Sysmon DNS Tunneling via Network Connection |
| T1056.001 | BLUELIGHT: Attack Path (per Host) |
| T1071.001 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), +2 more |
| T1071.004 | Sysmon DNS Data Exfiltration, Sysmon DNS Tunneling via Network Connection, DNS Exfiltration Detection (Entropy Analysis) |
| T1074.001 | Windows Data Staging for Exfiltration, Linux Data Staging and Exfiltration Indicators |
| T1082 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1083 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1105 | BLUELIGHT APT37 Kill Chain Correlation |
| T1113 | BLUELIGHT APT37 Kill Chain Correlation |
| T1189 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), +2 more |
| T1203 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), BLUELIGHT: Kill Chain Timeline |
| T1537 | Cloud Guard Problem: Bucket Public Read, OCI Boot Volume Backup Created by Non-Admin, +4 more |
| T1555.003 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), +2 more |
| T1560.001 | Linux Archive Data Collected for Exfiltration, Linux Data Staging and Exfiltration Indicators |
| T1567 | OCI Object Storage Pre-Authenticated Request Created |
| T1567.002 | BLUELIGHT RAT: Data Exfiltration via OneDrive/Graph API, BLUELIGHT RAT: Data Exfiltration via OneDrive/Graph API, +3 more |

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

### OCI Cloud (138 rules)

| # | Title | Severity | MITRE | STIG |
|---|-------|----------|-------|------|
| 1 | APM: SQL Injection Attack in Request | 🔴 critical | T1190 | - |
| 2 | Insecure Deserialization Attack Detected | 🔴 critical | T1059, T1190 | - |
| 3 | OCI Audit Configuration Retention Reduced | 🔴 critical | T1562.008 | - |
| 4 | OCI Compartment Deleted | 🔴 critical | T1485 | AC-6 |
| 5 | OCI Database System Terminated | 🔴 critical | T1485 | CP-9 |
| 6 | OCI Federated Identity Provider Modified | 🔴 critical | T1606 | - |
| 7 | OCI KMS Key Scheduled for Deletion | 🔴 critical | T1490 | - |
| 8 | OCI Log Group Deleted | 🔴 critical | T1562.001 | AU-11 |
| 9 | OCI Policy Allows Manage All Resources | 🔴 critical | T1098 | - |
| 10 | WAF Command Injection Attack Blocked | 🔴 critical | T1059, T1190 | - |
| 11 | WAF Log4Shell (CVE-2021-44228) Attack Blocked | 🔴 critical | T1190, T1059 | - |
| 12 | WAF SQL Injection Attack Allowed Through | 🔴 critical | T1190, T1059.007 | - |
| 13 | WAF Server-Side Request Forgery Blocked | 🔴 critical | T1190, T1552.005 | - |
| 14 | WAF Server-Side Template Injection Blocked | 🔴 critical | T1059, T1190 | - |
| 15 | WAF Web Shell Upload Attempt Blocked | 🔴 critical | T1505.003, T1190 | - |
| 16 | Web Application Authentication Bypass | 🔴 critical | T1078, T1550 | - |
| 17 | Web Application Privilege Escalation | 🔴 critical | T1078 | - |
| 18 | Web Application Session Hijacking Indicators | 🔴 critical | T1539, T1550.004 | - |
| 19 | APM: Cross-Site Scripting (XSS) Attack in Request | 🟠 high | T1189, T1059.007 | - |
| 20 | APM: DOM-Based Attack via Dangerous JavaScript APIs | 🟠 high | T1059.007 | - |
| 21 | APM: Session Hijacking - Rapid Session Changes | 🟠 high | T1539, T1550.004 | - |
| 22 | APM: Suspicious JavaScript Execution Patterns | 🟠 high | T1059.007, T1056.001 | - |
| 23 | Cloud Guard Problem: Audit Log Retention | 🟠 high | T1562.008 | - |
| 24 | Cloud Guard Problem: Bucket Public Read | 🟠 high | T1537 | - |
| 25 | Cloud Guard Problem: Bucket Public Write | 🟠 high | T1190 | - |
| 26 | Cloud Guard Problem: Group Has Too Many Admins | 🟠 high | T1098 | - |
| 27 | Cloud Guard Problem: IAM User API Key Old | 🟠 high | T1552.004 | - |
| 28 | Cloud Guard Problem: IAM User Console Password Old | 🟠 high | T1110 | - |
| 29 | Cloud Guard Problem: INSTANCE PUBLIC IP | 🟠 high | T1190 | - |
| 30 | Cloud Guard Problem: Instance Principals Enabled | 🟠 high | T1098.001 | - |
| 31 | Cloud Guard Problem: Policy Too Permissive | 🟠 high | T1098 | - |
| 32 | Cloud Guard Problem: VCN Flow Log Disabled | 🟠 high | T1562.008 | - |
| 33 | Cloud Guard Problem: VCN Security List Port RDP | 🟠 high | T1133 | - |
| 34 | Cloud Guard Problem: VCN Security List Port SSH | 🟠 high | T1133 | - |
| 35 | Insecure Direct Object Reference Detected | 🟠 high | T1190 | - |
| 36 | Mass Assignment Attack Detected | 🟠 high | T1078 | - |
| 37 | OCI Audit Configuration Changed | 🟠 high | T1562.008 | AU-11 |
| 38 | OCI Autonomous Database Terminated | 🟠 high | T1485 | - |
| 39 | OCI Cross-Region Data Copy | 🟠 high | T1537 | SC-28 |
| 40 | OCI Customer Secret Key Created | 🟠 high | T1098.001 | IA-5 |
| 41 | OCI Dynamic Group Created with Broad Matching | 🟠 high | T1098 | - |
| 42 | OCI IAM Admin Policy Created with Manage All | 🟠 high | T1098 | - |
| 43 | OCI Identity Provider Created | 🟠 high | T1556.007 | IA-8 |
| 44 | OCI Instance Console Connection Created | 🟠 high | T1021 | AC-17 |
| 45 | OCI KMS Key Version Disabled | 🟠 high | T1600 | - |
| 46 | OCI Log Archival Policy Disabled | 🟠 high | T1562.008 | - |
| 47 | OCI MFA Fatigue Attack Indicators | 🟠 high | T1621 | - |
| 48 | OCI Network Firewall Policy Modified | 🟠 high | T1562.004 | SC-7 |
| 49 | OCI Network Load Balancer Deleted | 🟠 high | T1489 | - |
| 50 | OCI Object Storage Bucket Made Public | 🟠 high | T1537 | - |
| 51 | OCI Object Storage Pre-Authenticated Request Created | 🟠 high | T1567 | AC-3 |
| 52 | OCI Object Storage Replication Policy Created | 🟠 high | T1537 | - |
| 53 | OCI Password Spraying Attack | 🟠 high | T1110.003 | IA-2 |
| 54 | OCI Security List Allows All Protocols | 🟠 high | T1562.007 | SC-7 |
| 55 | OCI User Capabilities Escalation | 🟠 high | T1098 | - |
| 56 | OCI User MFA Not Enabled | 🟠 high | T1556 | IA-2 |
| 57 | OCI User Password Reset by Admin | 🟠 high | T1098 | IA-5 |
| 58 | OCI VCN Flow Log Disabled | 🟠 high | T1562.008 | - |
| 59 | OCI VCN Security List Open to World | 🟠 high | T1562.007 | - |
| 60 | OCI Vault Secret Deleted | 🟠 high | T1485 | SC-28 |
| 61 | OCI WAF Policy Deleted | 🟠 high | T1562.001 | - |
| 62 | Sensitive Data Endpoint Access | 🟠 high | T1005, T1552.001 | - |
| 63 | WAF Cross-Site Scripting Attack Blocked | 🟠 high | T1189 | - |
| 64 | WAF LDAP Injection Attack Blocked | 🟠 high | T1190 | - |
| 65 | WAF NoSQL Injection Attack Blocked | 🟠 high | T1190 | - |
| 66 | WAF Path Traversal Attack Blocked | 🟠 high | T1083, T1190 | - |
| 67 | WAF Protocol Attack Blocked | 🟠 high | T1190 | - |
| 68 | WAF SQL Injection Attack Blocked | 🟠 high | T1190, T1059.007 | - |
| 69 | WAF XML External Entity Attack Blocked | 🟠 high | T1190 | - |
| 70 | API Endpoint Unauthorized Access Attempts | 🟡 medium | T1190, T1078 | - |
| 71 | APM: Browser Fingerprinting via Canvas/WebGL/AudioContext | 🟡 medium | T1592.004 | - |
| 72 | APM: CSRF Token Missing or Invalid on State-Changing Request | 🟡 medium | T1185 | - |
| 73 | APM: Clickjacking - Missing Frame Protection Headers | 🟡 medium | T1185 | - |
| 74 | OCI API Key Uploaded | 🟡 medium | T1098.001 | - |
| 75 | OCI Auth Token Created | 🟡 medium | T1528 | IA-5 |
| 76 | OCI Bastion Session Created | 🟡 medium | T1021 | AC-17 |
| 77 | OCI Boot Volume Backup Created by Non-Admin | 🟡 medium | T1537 | - |
| 78 | OCI Compute Instance Terminated | 🟡 medium | T1485 | - |
| 79 | OCI Console Login Failure | 🟡 medium | T1078 | - |
| 80 | OCI Console Login from Unusual IP | 🟡 medium | T1078 | - |
| 81 | OCI DRG Attachment Created | 🟡 medium | T1599 | - |
| 82 | OCI Database Backup Exported | 🟡 medium | T1537 | - |
| 83 | OCI Dynamic Group Created | 🟡 medium | T1098.001 | AC-6 |
| 84 | OCI IAM Policy Modified | 🟡 medium | T1098 | - |
| 85 | OCI Instance Metadata Service Accessed | 🟡 medium | T1552.005 | - |
| 86 | OCI Local Peering Gateway Created | 🟡 medium | T1599 | - |
| 87 | OCI Network Security Group Rule Added for All Protocols | 🟡 medium | T1562.004 | - |
| 88 | OCI Network Security Group Updated | 🟡 medium | T1562.007 | - |
| 89 | OCI Notification Subscription Created | 🟡 medium | T1114 | AU-12 |
| 90 | OCI Route Table Update | 🟡 medium | T1562.007 | - |
| 91 | OCI VCN Peering Connection Created | 🟡 medium | T1021 | SC-7 |
| 92 | OCI Vault Key Rotation Overdue | 🟡 medium | T1600 | SC-12 |
| 93 | OCI Vault Secret Version Deprecated | 🟡 medium | T1600 | - |
| 94 | OCI WAF Configuration Updated | 🟡 medium | T1562.007 | - |
| 95 | Suspicious or Empty User Agent Detected | 🟡 medium | T1595 | - |
| 96 | Unusually Large HTTP Response (Data Exfiltration) | 🟡 medium | T1041, T1048 | - |
| 97 | WAF CORS Bypass Attempt Blocked | 🟡 medium | T1189 | - |
| 98 | WAF Rate Limiting Triggered | 🟡 medium | T1110 | - |
| 99 | Web Application Brute Force Login Attempt | 🟡 medium | T1110.001, T1110.003 | - |
| 100 | Web Application Server Error Spike | 🟡 medium | T1499 | - |
| 101 | Web Vulnerability Scanner Detected | 🟡 medium | T1595.002 | - |
| 102 | OCI Cloud Infrastructure Discovery | 🔵 low | T1580 | AU-12 |
| 103 | OCI Cloud Shell Session Started | 🔵 low | T1059.004 | AU-12 |
| 104 | OCI Console Login from Suspicious IP Range | 🔵 low | T1078 | - |
| 105 | OCI Function Invoked | 🔵 low | T1648 | AU-12 |
| 106 | OCI Service Gateway Created | 🔵 low | T1599 | - |
| 107 | Suspicious HTTP Method Usage | 🔵 low | T1190 | - |
| 108 | Web Directory Enumeration Detected | 🔵 low | T1083, T1595.002 | - |
| 109 | OCI Action: AddUserToGroup | ⚪ informational | T1098.001 | - |
| 110 | OCI Action: AttachInternetGateway | ⚪ informational | T1583 | - |
| 111 | OCI Action: CreateBucket | ⚪ informational | T1530 | - |
| 112 | OCI Action: CreateGroup | ⚪ informational | T1136.003 | - |
| 113 | OCI Action: CreateInstance | ⚪ informational | T1583.003 | - |
| 114 | OCI Action: CreateInternetGateway | ⚪ informational | T1583 | - |
| 115 | OCI Action: CreateKey | ⚪ informational | T1553 | - |
| 116 | OCI Action: CreatePolicy | ⚪ informational | T1098 | - |
| 117 | OCI Action: CreateRouteTable | ⚪ informational | T1583 | - |
| 118 | OCI Action: CreateSecurityList | ⚪ informational | T1562.007 | - |
| 119 | OCI Action: CreateSubnet | ⚪ informational | T1583 | - |
| 120 | OCI Action: CreateUser | ⚪ informational | T1136.003 | - |
| 121 | OCI Action: CreateVcn | ⚪ informational | T1583 | - |
| 122 | OCI Action: DeleteBucket | ⚪ informational | T1485 | - |
| 123 | OCI Action: DeleteGroup | ⚪ informational | T1531 | - |
| 124 | OCI Action: DeleteInternetGateway | ⚪ informational | T1489 | - |
| 125 | OCI Action: DeleteKey | ⚪ informational | T1485 | - |
| 126 | OCI Action: DeletePolicy | ⚪ informational | T1531 | - |
| 127 | OCI Action: DeleteSubnet | ⚪ informational | T1489 | - |
| 128 | OCI Action: DeleteUser | ⚪ informational | T1531 | - |
| 129 | OCI Action: DeleteVcn | ⚪ informational | T1489 | - |
| 130 | OCI Action: DetachInternetGateway | ⚪ informational | T1489 | - |
| 131 | OCI Action: RemoveUserFromGroup | ⚪ informational | T1531 | - |
| 132 | OCI Action: StartInstance | ⚪ informational | T1204 | - |
| 133 | OCI Action: StopInstance | ⚪ informational | T1489 | - |
| 134 | OCI Action: TerminateInstance | ⚪ informational | T1485 | - |
| 135 | OCI Action: UpdateBucket | ⚪ informational | T1562.007 | - |
| 136 | OCI Action: UpdatePolicy | ⚪ informational | T1098 | - |
| 137 | OCI Action: UpdateRouteTable | ⚪ informational | T1562.007 | - |
| 138 | OCI Action: UpdateSecurityList | ⚪ informational | T1562.007 | - |

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

### Windows (273 rules)

| # | Title | Severity | MITRE | ART Tests | STIG |
|---|-------|----------|-------|-----------|------|
| 1 | Accessibility Features Backdoor | 🔴 critical | T1546.008 | 10 | - |
| 2 | AppInit DLLs Persistence | 🔴 critical | T1546.010 | 1 | - |
| 3 | BLUELIGHT RAT: Browser Credential Memory Access | 🔴 critical | T1555.003 | - | - |
| 4 | BLUELIGHT RAT: Browser Credential Memory Access | 🔴 critical | T1555.003 | - | - |
| 5 | BLUELIGHT RAT: YARA Chrome/Edge Cookie Theft (APT_MAL_Win_BlueLight_B) | 🔴 critical | T1539, T1555.003, T1114 | - | - |
| 6 | BLUELIGHT RAT: YARA Google App C2 Communication (APT_MAL_Win_BlueLight_B) | 🔴 critical | T1071.001, T1102 | - | - |
| 7 | BLUELIGHT RAT: YARA PDB Path Indicators (APT_MAL_Win_BlueLight) | 🔴 critical | T1204.002 | - | - |
| 8 | BLUELIGHT RAT: YARA System Reconnaissance JSON (APT_MAL_Win_BlueLight) | 🔴 critical | T1082, T1016, T1057 | - | - |
| 9 | BloodHound AD Enumeration | 🔴 critical | T1087.002 | 24 | - |
| 10 | Credential Dumping via Comsvcs with Rundll32 | 🔴 critical | T1003.001 | 14 | - |
| 11 | DCSync Attack via Replication Request | 🔴 critical | T1003.006 | 2 | - |
| 12 | DCSync: Directory Replication from Non-Domain Controller | 🔴 critical | T1003.006 | - | - |
| 13 | DCSync: Directory Replication from Non-Domain Controller | 🔴 critical | T1003.006 | - | - |
| 14 | Disk Wipe via Format Command | 🔴 critical | T1561 | - | - |
| 15 | Forced Authentication via PetitPotam | 🔴 critical | T1187 | 3 | - |
| 16 | Golden Ticket: RC4 Encrypted TGT Request | 🔴 critical | T1558.001 | - | - |
| 17 | Golden Ticket: RC4 Encrypted TGT Request | 🔴 critical | T1558.001 | - | - |
| 18 | Kerberoasting: SPN Sweep - Multiple Service Tickets from Single Account | 🔴 critical | T1558.003 | - | - |
| 19 | Kerberoasting: SPN Sweep - Multiple Service Tickets from Single Account | 🔴 critical | T1558.003 | - | - |
| 20 | Kerberos Ticket Export via Mimikatz | 🔴 critical | T1558 | 13 | - |
| 21 | Keylogging via PowerShell Get-Keystrokes | 🔴 critical | T1056.001 | 8 | - |
| 22 | LSASS Clone via ProcDump Evasion | 🔴 critical | T1003.001 | 14 | - |
| 23 | LSASS Memory Dump via Comsvcs DLL | 🔴 critical | T1003.001 | 14 | - |
| 24 | LaZagne Credential Harvester | 🔴 critical | T1555 | 8 | - |
| 25 | Mimikatz: Command and Module Indicators in Process Logs | 🔴 critical | T1003.001, T1003.006, T1558.003 | - | - |
| 26 | Mimikatz: Command and Module Indicators in Process Logs | 🔴 critical | T1003.001, T1003.006, T1558.003 | - | - |
| 27 | NTDS.dit Database Copy Attempt | 🔴 critical | T1003.003 | 11 | - |
| 28 | Named Pipe Impersonation via PowerShell | 🔴 critical | T1134.001 | 5 | - |
| 29 | Pass-the-Ticket via Rubeus | 🔴 critical | T1550.003 | 2 | - |
| 30 | Potato Privilege Escalation Tool | 🔴 critical | T1134.001 | 5 | - |
| 31 | PrintNightmare Exploitation Attempt | 🔴 critical | T1068 | - | - |
| 32 | Process Doppelganging via TxF | 🔴 critical | T1055.013 | 13 | - |
| 33 | Ransomware File Extension Indicators | 🔴 critical | T1486 | 10 | - |
| 34 | Reflective DLL Loading Indicators | 🔴 critical | T1620 | 1 | - |
| 35 | SSRF to Cloud Metadata Endpoint (169.254.169.254) | 🔴 critical | T1552.005, T1190 | - | - |
| 36 | Security Support Provider DLL Persistence | 🔴 critical | T1547.005 | 2 | - |
| 37 | Shadow Credentials Attack via Whisker | 🔴 critical | T1556 | 5 | - |
| 38 | Sysmon Cobalt Strike C2 Network Indicators | 🔴 critical | T1071.001, T1095 | 7 | - |
| 39 | Sysmon Cobalt Strike Named Pipe | 🔴 critical | T1071, T1055 | 14 | - |
| 40 | Sysmon Configuration Tampering | 🔴 critical | T1562.001 | 59 | - |
| 41 | Sysmon Mimikatz Named Pipe | 🔴 critical | T1003.001, T1134 | 27 | - |
| 42 | Sysmon Mimikatz Network Activity | 🔴 critical | T1003.001, T1558.003 | 21 | - |
| 43 | Sysmon Suspicious Named Pipe Pattern | 🔴 critical | T1071, T1059 | 2 | - |
| 44 | System Recovery Disabled via BCDEdit | 🔴 critical | T1490 | 13 | - |
| 45 | Volume Shadow Copy Deletion via WMIC | 🔴 critical | T1490 | 13 | - |
| 46 | Web Server Process Spawning Command Shell | 🔴 critical | T1059, T1059.001, T1190 | - | - |
| 47 | Windows Access Token Manipulation | 🔴 critical | T1134 | 13 | - |
| 48 | Windows Boot Configuration Modified | 🔴 critical | T1490 | 13 | - |
| 49 | Windows Credential Dumping via Procdump | 🔴 critical | T1003.001 | 14 | - |
| 50 | Windows Credential Dumping via Secretsdump | 🔴 critical | T1003 | 7 | - |
| 51 | Windows Defender Real-Time Protection Disabled | 🔴 critical | T1562.001 | 59 | - |
| 52 | Windows Kerberoasting Attack | 🔴 critical | T1558.003 | 7 | - |
| 53 | Windows Keylogger Indicators | 🔴 critical | T1056.001 | 8 | - |
| 54 | Windows LSASS Memory Access | 🔴 critical | T1003.001 | 14 | - |
| 55 | Windows Mimikatz Execution Patterns | 🔴 critical | T1003.001 | 14 | - |
| 56 | Windows NTDS.dit Database Extraction | 🔴 critical | T1003.003 | 11 | - |
| 57 | Windows Pass-the-Hash Attack Indicators | 🔴 critical | T1550.002 | 3 | - |
| 58 | Windows Process Hollowing Indicators | 🔴 critical | T1055.012 | 4 | - |
| 59 | Windows Shadow Copy Deletion | 🔴 critical | T1490 | 13 | - |
| 60 | Windows Spearphishing Attachment Execution | 🔴 critical | T1566.001, T1204.002 | 15 | - |
| 61 | AD Enumeration via ADFind | 🟠 high | T1087.002 | 24 | - |
| 62 | AMSI Bypass via PowerShell Reflection | 🟠 high | T1562.001 | 59 | - |
| 63 | AS-REP Roasting via Rubeus | 🟠 high | T1558.004 | 3 | - |
| 64 | Account Access Removal | 🟠 high | T1531 | 8 | - |
| 65 | Active Setup Persistence | 🟠 high | T1547.014 | 3 | - |
| 66 | Alternate Data Stream Execution | 🟠 high | T1564.004 | 5 | - |
| 67 | AppLocker Policy Bypass via MSHTML | 🟠 high | T1218.005 | 10 | - |
| 68 | BLUELIGHT RAT: Browser Spawning Suspicious Child Process | 🟠 high | T1203 | - | - |
| 69 | BLUELIGHT RAT: Browser Spawning Suspicious Child Process | 🟠 high | T1203 | - | - |
| 70 | BLUELIGHT RAT: Data Exfiltration via OneDrive/Graph API | 🟠 high | T1567.002 | - | - |
| 71 | BLUELIGHT RAT: Data Exfiltration via OneDrive/Graph API | 🟠 high | T1567.002 | - | - |
| 72 | BLUELIGHT RAT: Executable Download via Graph API | 🟠 high | T1105 | - | - |
| 73 | BLUELIGHT RAT: Executable Download via Graph API | 🟠 high | T1105 | - | - |
| 74 | BLUELIGHT RAT: Obfuscated Script Execution | 🟠 high | T1027 | - | - |
| 75 | BLUELIGHT RAT: Obfuscated Script Execution | 🟠 high | T1027 | - | - |
| 76 | BLUELIGHT RAT: Periodic Screen Capture | 🟠 high | T1113 | - | - |
| 77 | BLUELIGHT RAT: Periodic Screen Capture | 🟠 high | T1113 | - | - |
| 78 | BLUELIGHT RAT: WMI System Enumeration from Browser Child | 🟠 high | T1082 | - | - |
| 79 | BLUELIGHT RAT: WMI System Enumeration from Browser Child | 🟠 high | T1082 | - | - |
| 80 | BLUELIGHT RAT: YARA Keylogger Component (APT_MAL_Win_BlueLight_B) | 🟠 high | T1056.001 | - | - |
| 81 | Boot Configuration Change for Persistence | 🟠 high | T1542 | 1 | - |
| 82 | Browser Credential Store Access | 🟠 high | T1555.003 | 17 | - |
| 83 | Brute Force: Failed Logon Spike per Account | 🟠 high | T1110.001, T1110.003 | - | - |
| 84 | Brute Force: Failed Logon Spike per Account | 🟠 high | T1110.001, T1110.003 | - | - |
| 85 | CMD: Suspicious Command Execution (Real Windows Security Events) | 🟠 high | T1059.003 | - | - |
| 86 | CMD: Suspicious Command Execution (Real Windows Security Events) | 🟠 high | T1059.003 | - | - |
| 87 | CMSTP UAC Bypass | 🟠 high | T1218.003 | 2 | - |
| 88 | COM Object Hijacking via Registry | 🟠 high | T1546.015 | 4 | - |
| 89 | Credential Access via Certutil Certificate Export | 🟠 high | T1649 | 1 | - |
| 90 | Credential Dumping via Windows Task Manager | 🟠 high | T1003.001 | 14 | - |
| 91 | Cryptominer Deployment Indicators | 🟠 high | T1496 | 2 | - |
| 92 | DCOM Lateral Movement via MMC20 | 🟠 high | T1021.003 | 2 | - |
| 93 | DLL Execution via Rundll32 from User Path | 🟠 high | T1218.011 | 16 | - |
| 94 | DLL Hijacking via Service Registry Permission | 🟠 high | T1574.011 | 2 | - |
| 95 | DPAPI Master Key Extraction | 🟠 high | T1555 | 8 | - |
| 96 | Disable Windows Firewall via Netsh | 🟠 high | T1562.004 | 25 | - |
| 97 | ETW Provider Disabled | 🟠 high | T1562.002 | 10 | - |
| 98 | Email Collection via PowerShell | 🟠 high | T1114 | 3 | - |
| 99 | Group Policy Preferences Password Extraction | 🟠 high | T1552.006 | 2 | - |
| 100 | Image File Execution Options Debugger | 🟠 high | T1546.012 | 3 | - |
| 101 | InstallUtil Application Whitelisting Bypass | 🟠 high | T1218.004 | 8 | - |
| 102 | Internal Monologue NTLM Hash Theft | 🟠 high | T1003 | 7 | - |
| 103 | Kerberoasting: RC4 Encrypted Service Ticket Request | 🟠 high | T1558.003 | - | - |
| 104 | Kerberoasting: RC4 Encrypted Service Ticket Request | 🟠 high | T1558.003 | - | - |
| 105 | LSA Secrets Registry Extraction | 🟠 high | T1003.004 | 2 | - |
| 106 | Lateral Movement: Account Authenticating from Multiple Sources | 🟠 high | T1021.002, T1021.006 | - | - |
| 107 | Lateral Movement: Account Authenticating from Multiple Sources | 🟠 high | T1021.002, T1021.006 | - | - |
| 108 | MSBuild Execution from Non-Standard Location | 🟠 high | T1127.001 | 2 | - |
| 109 | MSHTA JavaScript Execution | 🟠 high | T1218.005 | 10 | - |
| 110 | Masquerading System Binary in Non-Standard Path | 🟠 high | T1036.005 | 3 | - |
| 111 | NPPSpy Credential Interception | 🟠 high | T1556 | 5 | - |
| 112 | Netsh Helper DLL Persistence | 🟠 high | T1546.007 | 1 | - |
| 113 | New Local Account Created via Net.exe | 🟠 high | T1136.001 | 10 | - |
| 114 | Parent PID Spoofing | 🟠 high | T1134.004 | 5 | - |
| 115 | Pass-the-Ticket: Excessive Explicit Credential Logons | 🟠 high | T1550.003 | - | - |
| 116 | Pass-the-Ticket: Excessive Explicit Credential Logons | 🟠 high | T1550.003 | - | - |
| 117 | Port Monitor DLL Persistence | 🟠 high | T1547.010 | 1 | - |
| 118 | PowerShell Script Block with Suspicious Keywords | 🟠 high | T1059.001 | 22 | - |
| 119 | PowerShell: Suspicious Command Execution (Real Windows Security Events) | 🟠 high | T1059.001, T1086 | - | - |
| 120 | PowerShell: Suspicious Command Execution (Real Windows Security Events) | 🟠 high | T1059.001, T1086 | - | - |
| 121 | Print Processor Persistence | 🟠 high | T1547.012 | 1 | - |
| 122 | Privilege Escalation: Sensitive Privileges Assigned to Non-Admin | 🟠 high | T1134, T1134.001 | - | - |
| 123 | Privilege Escalation: Sensitive Privileges Assigned to Non-Admin | 🟠 high | T1134, T1134.001 | - | - |
| 124 | Process Ghosting or Herpaderping | 🟠 high | T1055 | 13 | - |
| 125 | Process Injection via CreateRemoteThread | 🟠 high | T1055.001 | 2 | - |
| 126 | PsExec Service Installation | 🟠 high | T1021.002 | 4 | - |
| 127 | RDP Session Hijacking via tscon | 🟠 high | T1021.001 | 4 | - |
| 128 | Registry Run Key Modification via Reg.exe | 🟠 high | T1547.001 | 20 | - |
| 129 | Regsvcs or Regasm Execution for Code Bypass | 🟠 high | T1218.009 | 2 | - |
| 130 | Remote Service Creation via SC | 🟠 high | T1021.002 | 4 | - |
| 131 | Renamed System Binary Execution | 🟠 high | T1036.003 | 8 | - |
| 132 | Root Certificate Installation via Certutil | 🟠 high | T1553.004 | 7 | - |
| 133 | SAM Database Extraction via Reg Save | 🟠 high | T1003.002 | 8 | - |
| 134 | Screen Capture via PowerShell | 🟠 high | T1113 | 10 | - |
| 135 | Scripting Engine Spawning Network Utility | 🟠 high | T1059.005 | 3 | - |
| 136 | SeDebugPrivilege Abuse | 🟠 high | T1134 | 13 | - |
| 137 | Service Execution via sc.exe Create | 🟠 high | T1569.002 | 8 | - |
| 138 | Service Stop via Net Stop | 🟠 high | T1489 | 8 | - |
| 139 | SharpRDP Lateral Movement | 🟠 high | T1021.001 | 4 | - |
| 140 | Suspicious Scheduled Task Creation | 🟠 high | T1053.005 | 12 | - |
| 141 | SyncAppvPublishingServer Abuse | 🟠 high | T1218 | 16 | - |
| 142 | Sysmon C2 Beacon - Periodic Outbound HTTPS | 🟠 high | T1071.001, T1573 | 4 | - |
| 143 | Sysmon DNS Data Exfiltration | 🟠 high | T1048.003, T1071.004 | 12 | - |
| 144 | Sysmon DNS Query to Known C2 Framework Domains | 🟠 high | T1071.004, T1568.002 | 4 | - |
| 145 | Sysmon DNS Tunneling via Network Connection | 🟠 high | T1071.004, T1048.003 | 12 | - |
| 146 | Sysmon Kerberoasting Network Indicator | 🟠 high | T1558.003 | 7 | - |
| 147 | Sysmon Lateral Movement via SMB | 🟠 high | T1021.002, T1570 | 6 | - |
| 148 | Sysmon Lateral Movement via WinRM | 🟠 high | T1021.006, T1059.001 | 25 | - |
| 149 | Sysmon PsExec Named Pipe | 🟠 high | T1021.002, T1569.002 | 12 | - |
| 150 | Sysmon Suspicious Outbound Connection from LOLBin | 🟠 high | T1218, T1105 | 55 | - |
| 151 | Template Injection via Microsoft Office | 🟠 high | T1221 | 1 | - |
| 152 | Time Provider DLL Persistence | 🟠 high | T1547.003 | 2 | - |
| 153 | Timestomping via PowerShell | 🟠 high | T1070.006 | 10 | - |
| 154 | Token Impersonation via Incognito | 🟠 high | T1134 | 13 | - |
| 155 | UAC Bypass via ComputerDefaults | 🟠 high | T1548.002 | 27 | - |
| 156 | UAC Bypass via Eventvwr | 🟠 high | T1548.002 | 27 | - |
| 157 | UAC Bypass via Fodhelper | 🟠 high | T1548.002 | 27 | - |
| 158 | VBA Macro Spawning Suspicious Child Process | 🟠 high | T1204.002 | 13 | - |
| 159 | WMI Event Subscription Persistence | 🟠 high | T1546.003 | 3 | - |
| 160 | WMI Process Execution via Wmic | 🟠 high | T1047 | 10 | - |
| 161 | Windows AMSI Bypass Attempt | 🟠 high | T1562.001 | 59 | - |
| 162 | Windows BITS Job Abuse for Persistence | 🟠 high | T1197 | 4 | - |
| 163 | Windows Backup Deletion via wbadmin | 🟠 high | T1490 | 13 | - |
| 164 | Windows Certutil Download or Decode | 🟠 high | T1140, T1105 | 50 | - |
| 165 | Windows DLL Side-Loading via Suspicious Path | 🟠 high | T1574.002 | - | - |
| 166 | Windows Defender Exclusion Added via PowerShell | 🟠 high | T1562.001 | 59 | - |
| 167 | Windows Encoded PowerShell Execution | 🟠 high | T1059.001, T1027 | 32 | - |
| 168 | Windows Event Log Cleared via Wevtutil | 🟠 high | T1070.001 | 3 | - |
| 169 | Windows Event Log Clearing | 🟠 high | T1070.001 | 3 | - |
| 170 | Windows Firewall Rule Modification | 🟠 high | T1562.004 | 25 | - |
| 171 | Windows Management Instrumentation Event Subscription | 🟠 high | T1047 | 10 | - |
| 172 | Windows PowerShell Download Cradle | 🟠 high | T1059.001, T1105 | 61 | - |
| 173 | Windows PsExec Remote Execution | 🟠 high | T1021.002, T1569.002 | 12 | - |
| 174 | Windows Registry Run Key Modification | 🟠 high | T1547.001 | 20 | - |
| 175 | Windows Remote Access Tool Detected | 🟠 high | T1219 | 15 | - |
| 176 | Windows Remote Management Shell via Winrs | 🟠 high | T1021.006 | 3 | - |
| 177 | Windows Script Host Execution from Temp | 🟠 high | T1059.005 | 3 | - |
| 178 | Windows Service Created with Suspicious Binary Path | 🟠 high | T1543.003 | 6 | - |
| 179 | Windows UAC Bypass Attempt | 🟠 high | T1548.002 | 27 | - |
| 180 | Windows WDigest Authentication Enabled for Credential Harvesting | 🟠 high | T1003.001 | 14 | - |
| 181 | Windows WMI Event Subscription Persistence | 🟠 high | T1546.003 | 3 | - |
| 182 | Winlogon Helper DLL Modification | 🟠 high | T1547.004 | 5 | - |
| 183 | Wscript Running Encoded Script | 🟠 high | T1059.005 | 3 | - |
| 184 | XSL Script Processing via WMIC or Msxsl | 🟠 high | T1220 | 4 | - |
| 185 | AlwaysInstallElevated Exploitation | 🟡 medium | T1548.002 | 27 | - |
| 186 | Application Shimming for Persistence | 🟡 medium | T1546.011 | 3 | - |
| 187 | BITS Job Persistence | 🟡 medium | T1197 | 4 | - |
| 188 | BLUELIGHT RAT: C2 via Microsoft Graph API | 🟡 medium | T1071.001 | - | - |
| 189 | BLUELIGHT RAT: C2 via Microsoft Graph API | 🟡 medium | T1071.001 | - | - |
| 190 | BLUELIGHT RAT: File Discovery from Browser Process | 🟡 medium | T1083 | - | - |
| 191 | BLUELIGHT RAT: File Discovery from Browser Process | 🟡 medium | T1083 | - | - |
| 192 | BLUELIGHT RAT: Internet Explorer Drive-by Compromise | 🟡 medium | T1189 | - | - |
| 193 | BLUELIGHT RAT: Internet Explorer Drive-by Compromise | 🟡 medium | T1189 | - | - |
| 194 | BLUELIGHT RAT: Registry Enumeration of Security Products | 🟡 medium | T1012 | - | - |
| 195 | BLUELIGHT RAT: Registry Enumeration of Security Products | 🟡 medium | T1012 | - | - |
| 196 | Clipboard Data Collection | 🟡 medium | T1115 | 5 | - |
| 197 | Compiled HTML File Execution | 🟡 medium | T1218.001 | 8 | - |
| 198 | Control Panel Item Execution | 🟡 medium | T1218 | 16 | - |
| 199 | Credential File Discovery | 🟡 medium | T1552.001 | 17 | - |
| 200 | Credential Manager: High-Frequency Credential Read | 🟡 medium | T1555.004 | - | - |
| 201 | Credential Manager: High-Frequency Credential Read | 🟡 medium | T1555.004 | - | - |
| 202 | DLL Side-Loading from Suspicious Directory | 🟡 medium | T1574.002 | - | - |
| 203 | Data Compression for Exfiltration via 7zip | 🟡 medium | T1560.001 | 12 | - |
| 204 | Defacement via Desktop Wallpaper Change | 🟡 medium | T1491.001 | 4 | - |
| 205 | Default File Association Hijack | 🟡 medium | T1546.001 | 1 | - |
| 206 | Domain Trust Discovery via Nltest | 🟡 medium | T1482 | 8 | - |
| 207 | File Deletion of Security Tools | 🟡 medium | T1070.004 | 11 | - |
| 208 | File and Directory Discovery via dir | 🟡 medium | T1083 | 9 | - |
| 209 | Finger.exe Abuse for File Download | 🟡 medium | T1105 | 39 | - |
| 210 | Hidden PowerShell Window Execution | 🟡 medium | T1564.003 | 3 | - |
| 211 | Indirect Command Execution via Forfiles | 🟡 medium | T1202 | 5 | - |
| 212 | JavaScript Execution via Node.js | 🟡 medium | T1059.007 | 2 | - |
| 213 | Office Application Startup Persistence | 🟡 medium | T1137 | 1 | - |
| 214 | Python Execution as Child of System Process | 🟡 medium | T1059.006 | 4 | - |
| 215 | Query Registry for Security Products | 🟡 medium | T1518.001 | 11 | - |
| 216 | SDelete Secure File Deletion | 🟡 medium | T1070.004 | 11 | - |
| 217 | Scheduled Task XML Import | 🟡 medium | T1053.005 | 12 | - |
| 218 | ScreenSaver Hijacking Persistence | 🟡 medium | T1546.002 | 1 | - |
| 219 | Security Group Enumeration: Rapid Membership Queries | 🟡 medium | T1069.002, T1087.002 | - | - |
| 220 | Security Group Enumeration: Rapid Membership Queries | 🟡 medium | T1069.002, T1087.002 | - | - |
| 221 | Service Permissions Weakness Discovery | 🟡 medium | T1574.011 | 2 | - |
| 222 | Shortcut Modification for Persistence | 🟡 medium | T1547.009 | 2 | - |
| 223 | Startup Folder Modification | 🟡 medium | T1547.001 | 20 | - |
| 224 | Sysmon DNS Query to Suspicious TLDs | 🟡 medium | T1071.004 | 4 | - |
| 225 | Sysmon LDAP Reconnaissance | 🟡 medium | T1087.002, T1069.002 | 39 | - |
| 226 | Sysmon RDP Lateral Movement | 🟡 medium | T1021.001 | 4 | - |
| 227 | System Shutdown or Reboot via shutdown.exe | 🟡 medium | T1529 | 16 | - |
| 228 | Token Manipulation via RunAs | 🟡 medium | T1134.002 | 2 | - |
| 229 | UAC Bypass via DiskCleanup | 🟡 medium | T1548.002 | 27 | - |
| 230 | Unquoted Service Path Exploitation | 🟡 medium | T1574.009 | 1 | - |
| 231 | Virtualization Sandbox Evasion Check | 🟡 medium | T1497 | 9 | - |
| 232 | Visual Basic Script Compilation via vbc.exe | 🟡 medium | T1059.005 | 3 | - |
| 233 | WiFi Password Extraction via Netsh | 🟡 medium | T1552.001 | 17 | - |
| 234 | WinRM Lateral Movement via PowerShell | 🟡 medium | T1021.006 | 3 | - |
| 235 | Windows Account Discovery Commands | 🟡 medium | T1087.001, T1087.002 | 35 | - |
| 236 | Windows Admin Share Access via Net Use | 🟡 medium | T1021.002 | 4 | - |
| 237 | Windows Credential Manager Access via VaultCmd | 🟡 medium | T1555 | 8 | - |
| 238 | Windows Data Staging for Exfiltration | 🟡 medium | T1074.001 | 3 | - |
| 239 | Windows LOLBin Usage: at | 🟡 medium | T1218 | 16 | - |
| 240 | Windows LOLBin Usage: bitsadmin | 🟡 medium | T1218 | 16 | - |
| 241 | Windows LOLBin Usage: certutil | 🟡 medium | T1218 | 16 | - |
| 242 | Windows LOLBin Usage: cmd | 🟡 medium | T1218 | 16 | - |
| 243 | Windows LOLBin Usage: cscript | 🟡 medium | T1218 | 16 | - |
| 244 | Windows LOLBin Usage: ipconfig | 🟡 medium | T1218 | 16 | - |
| 245 | Windows LOLBin Usage: mshta | 🟡 medium | T1218 | 16 | - |
| 246 | Windows LOLBin Usage: net | 🟡 medium | T1218 | 16 | - |
| 247 | Windows LOLBin Usage: net1 | 🟡 medium | T1218 | 16 | - |
| 248 | Windows LOLBin Usage: powershell | 🟡 medium | T1218 | 16 | - |
| 249 | Windows LOLBin Usage: regsvr32 | 🟡 medium | T1218 | 16 | - |
| 250 | Windows LOLBin Usage: rundll32 | 🟡 medium | T1218 | 16 | - |
| 251 | Windows LOLBin Usage: sc | 🟡 medium | T1218 | 16 | - |
| 252 | Windows LOLBin Usage: schtasks | 🟡 medium | T1218 | 16 | - |
| 253 | Windows LOLBin Usage: systeminfo | 🟡 medium | T1218 | 16 | - |
| 254 | Windows LOLBin Usage: taskkill | 🟡 medium | T1218 | 16 | - |
| 255 | Windows LOLBin Usage: tasklist | 🟡 medium | T1218 | 16 | - |
| 256 | Windows LOLBin Usage: whoami | 🟡 medium | T1218 | 16 | - |
| 257 | Windows LOLBin Usage: wmic | 🟡 medium | T1218 | 16 | - |
| 258 | Windows LOLBin Usage: wscript | 🟡 medium | T1218 | 16 | - |
| 259 | Windows MSBuild Execution for Code Bypass | 🟡 medium | T1127.001 | 2 | - |
| 260 | Windows Network Share Discovery | 🟡 medium | T1135 | 12 | - |
| 261 | Windows RDP Lateral Movement | 🟡 medium | T1021.001 | 4 | - |
| 262 | Windows Remote System Discovery | 🟡 medium | T1018 | 22 | - |
| 263 | Windows Scheduled Task Creation via Schtasks | 🟡 medium | T1053.005 | 12 | - |
| 264 | Windows Screen Capture Activity | 🟡 medium | T1113 | 10 | - |
| 265 | Windows Service Creation via SC | 🟡 medium | T1543.003 | 6 | - |
| 266 | Windows Vault Enumeration | 🟡 medium | T1555 | 8 | - |
| 267 | Lateral Tool Transfer via Robocopy | 🔵 low | T1570 | 2 | - |
| 268 | Local Group Membership Discovery | 🔵 low | T1069.001 | 7 | - |
| 269 | Network Share Enumeration via Net View | 🔵 low | T1135 | 12 | - |
| 270 | Password Policy Discovery | 🔵 low | T1201 | 12 | - |
| 271 | PowerShell Execution via Alternate Shell | 🔵 low | T1059.001 | 22 | - |
| 272 | Process Discovery via Tasklist | 🔵 low | T1057 | 9 | - |
| 273 | Software Discovery via WMIC | 🔵 low | T1518 | 6 | - |

## App / APM Queries

| # | Title | Type | Severity | MITRE |
|---|-------|------|----------|-------|
| 1 | APM: Browser Attack to WAF Block Correlation | Curated application analytics | 🟠 high | T1190 |
| 2 | APM: Browser Fingerprinting via Canvas/WebGL/AudioContext | Source-derived browser detection | 🟡 medium | T1592.004 |
| 3 | APM: Clickjacking - Missing Frame Protection Headers | Source-derived browser detection | 🟡 medium | T1185 |
| 4 | APM: CSRF Token Missing or Invalid on State-Changing Request | Source-derived browser detection | 🟡 medium | T1185 |
| 5 | APM: DOM-Based Attack via Dangerous JavaScript APIs | Source-derived browser detection | 🟠 high | T1059.007 |
| 6 | APM: OWASP Attack Volume by Service | Curated application analytics | ⚪ informational | T1190 |
| 7 | APM: Session Hijacking - Rapid Session Changes | Source-derived browser detection | 🟠 high | T1539, T1550.004 |
| 8 | APM: SQL Injection Attack in Request | Source-derived browser detection | 🔴 critical | T1190 |
| 9 | APM: Suspicious JavaScript Execution Patterns | Source-derived browser detection | 🟠 high | T1059.007, T1056.001, T1496 |
| 10 | APM: Total Browser Attacks (24h) | Curated application analytics | ⚪ informational | T1190 |
| 11 | APM: Browser Attack Trace Correlation | Curated application analytics | 🟠 high | T1190, T1059.007 |
| 12 | APM: Cross-Site Scripting (XSS) Attack in Request | Source-derived browser detection | 🟠 high | T1189, T1059.007 |
| 13 | Application Authentication Brute Force | Curated application analytics | 🟠 high | T1110, T1110.003 |
| 14 | Cross-Service Trace Correlation (CRM ↔ Drone Shop) | Curated application analytics | ⚪ informational | - |
| 15 | Database Performance Correlation (ATP → APM → Logs) | Curated application analytics | ⚪ informational | - |
| 16 | Application Error Rate by Service | Curated application analytics | 🟠 high | T1499 |
| 17 | Order Sync Pipeline Health (Drone Shop → CRM) | Curated application analytics | 🟡 medium | - |
| 18 | OWASP Attack Detection (CRM + Drone Shop) | Curated application analytics | 🔴 critical | T1190, T1059, T1110 |
| 19 | Request Rate by Service and Endpoint | Curated application analytics | ⚪ informational | - |
| 20 | Security Attack Source IP Analysis | Curated application analytics | 🟠 high | T1190, T1110 |
| 21 | Application Service Health Timeline | Curated application analytics | ⚪ informational | - |
| 22 | Slow Request Detection (>2s) | Curated application analytics | 🟡 medium | T1499 |
| 23 | SQL Injection and XSS Attack Detection | Curated application analytics | 🔴 critical | T1190, T1059.007 |
| 24 | WAF Signal Correlation with Application Traces | Curated application analytics | 🟠 high | T1562, T1190 |

## Hunting Queries

| # | Title | Method | Severity | MITRE |
|---|-------|--------|----------|-------|
| 1 | Hunting: AD Attack Timeline - Multi-Stage Credential Attack Chain | - | 🔴 critical | T1003.006, T1558.003, T1110.001, T1134, T1550.003 |
| 2 | BLUELIGHT APT37 Kill Chain Correlation | - | 🔴 critical | T1189, T1203, T1027, T1071.001, T1082, T1012, T1083, T1113, T1555.003, T1105, T1567.002 |
| 3 | BLUELIGHT: Attack Path (per Host) | - | 🔴 critical | T1189, T1203, T1027, T1083, T1082, T1555.003, T1056.001, T1071.001, T1567.002 |
| 4 | BLUELIGHT: Kill Chain Timeline | - | ⚪ informational | T1189, T1203, T1071.001, T1555.003 |
| 5 | BLUELIGHT: Source x Process Breakdown | - | ⚪ informational | T1189, T1071.001, T1555.003 |
| 6 | BLUELIGHT: Top Affected Hosts | - | 🟠 high | T1189, T1203, T1555.003, T1071.001 |
| 7 | BLUELIGHT: Total Detections (24h) | - | ⚪ informational | T1189, T1071.001, T1555.003, T1567.002 |
| 8 | Browser Attack Frequency Analysis (SOC Application Logs) | - | 🔴 critical | T1190, T1189, T1059.007, T1496 |
| 9 | Hunting: Credential Attack Correlation (PowerShell + Mimikatz + Kerberoast) | - | 🔴 critical | T1003.001, T1558.003, T1059.001 |
| 10 | DNS Exfiltration Detection (Entropy Analysis) | field_analysis | 🟠 high | T1048, T1071.004 |
| 11 | Hunting: Kerberoasting Anomaly - RC4 vs AES Encryption Ratio | - | 🔴 critical | T1558.003 |
| 12 | Linux Data Staging and Exfiltration Indicators | combined_scoring | 🟠 high | T1560.001, T1074.001 |
| 13 | Linux Multi-Stage Attack Indicators (Combined Methods) | multi_stage | 🔴 critical | T1110, T1059.004 |
| 14 | Linux Persistence Indicator Score (Combined Methods) | scoring | 🟠 high | T1053, T1543.002, T1098.004 |
| 15 | Linux Rare Process Detection (Stacking) | rare_value | 🟡 medium | T1059.004 |
| 16 | Hunting: Logon Anomaly - Account Activity Profiling | - | 🟠 high | T1078, T1021, T1134 |
| 17 | Geographic Health: Cloud Provider Summary | aggregation | ⚪ informational | - |
| 18 | Geographic Health: Instance Detail with Coordinates | detail_view | ⚪ informational | - |
| 19 | Geographic Health: Regional Status on Global Map | geographic_analysis | ⚪ informational | - |
| 20 | Geographic Health: Service Tier Status | aggregation | ⚪ informational | - |
| 21 | Geographic Health: Unhealthy Regions Alert | alerting | 🟠 high | - |
| 22 | C2 Beaconing Detection (Periodic Connection Analysis) | frequency_analysis | 🟠 high | T1071, T1573 |
| 23 | OCI After-Hours IAM Activity (Time-Based Anomaly) | time_anomaly | 🟡 medium | T1098 |
| 24 | OCI Console Login Brute Force (Frequency Analysis) | frequency_analysis | 🟠 high | T1078, T1110 |
| 25 | OCI IAM and Fusion Activity Correlation | grouping_correlation | 🟠 high | T1078, T1098 |
| 26 | OCI IAM Rapid Configuration Changes (Anomaly Detection) | anomaly_detection | 🟠 high | T1098, T1078 |
| 27 | OCI Multiple Users from Same IP (Grouping) | grouping | 🟠 high | T1078, T1110.004 |
| 28 | OCI Privilege Escalation Chain Detection | combined_scoring | 🔴 critical | T1098, T1078 |
| 29 | OCI Resource Destruction Spike (Anomaly Detection) | anomaly_detection | 🔴 critical | T1485, T1489 |
| 30 | SSH Brute Force Detection (Frequency Analysis) | frequency_analysis | 🟠 high | T1110.001 |
| 31 | Login Activity Time-Series Anomaly | time_series_anomaly | 🟠 high | T1078, T1110 |
| 32 | WAF Attack Frequency by Source IP (Frequency Analysis) | frequency_analysis | 🟠 high | T1190 |
| 33 | WAF Multi-Attack Vector Scoring (Combined Methods) | scoring | 🔴 critical | T1190, T1059 |
| 34 | SQL Injection Pattern Stacking (Rare Value Detection) | rare_value | 🟠 high | T1190 |
| 35 | Web Attack Geographic Anomaly (Rare Country Detection) | rare_value | 🟡 medium | T1190 |
| 36 | Web Application Brute Force Detection (Frequency Analysis) | frequency_analysis | 🟠 high | T1110.001, T1110.003 |
| 37 | Web Directory Scanning IP Clustering (Anomaly Detection) | anomaly_detection | 🟡 medium | T1595.002 |
| 38 | OWASP Multi-Stage Web Attack Chain (Combined Methods) | multi_stage | 🔴 critical | T1190, T1110, T1059 |
| 39 | Web Scanner Tool Identification (User Agent Stacking) | rare_value | 🟡 medium | T1595.002 |
| 40 | Windows Credential Access Tool Cluster (Grouping) | grouping | 🔴 critical | T1003, T1558.003 |
| 41 | Windows Defense Evasion Score (Combined Methods) | scoring | 🔴 critical | T1562, T1548.002, T1070 |
| 42 | Windows Lateral Movement Tool Cluster (Grouping) | grouping | 🔴 critical | T1021, T1570 |
| 43 | Windows Suspiciously Long Command Line (Field Analysis) | field_analysis | 🟠 high | T1059.001, T1027 |
| 44 | Windows Process from Unusual Path (Rare Value Analysis) | rare_value | 🟠 high | T1204, T1036 |
| 45 | Windows Rare Process Detection (Stacking) | rare_value | 🟡 medium | T1059 |

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
*Generated from 454 Sigma source rules routed to 478 top-level detection queries and 8 browser app queries, plus 16 curated app/APM analytics and 45 hunting queries*