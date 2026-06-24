# Detection Rule Catalog

> **545 base detection queries** + **590 Microsoft Sentinel conversions** + **62 app/APM queries** + **115 hunting queries**

## Summary

| Content Surface | Count | Notes |
|-----------------|-------|-------|
| Base detection queries | 545 | Sigma-derived detections in `queries/` |
| Microsoft Sentinel conversions | 590 | Source-derived converted detections in `queries/sentinel/` |
| App/APM queries | 62 | 8 Sigma-derived browser detections + 54 curated analytics in `queries/apps/` |
| Hunting queries | 115 | Curated analytics and correlation content in `queries/hunting/` |

**Source YAML rules:** 522 total (cloud: 102, linux: 80, web: 38, windows: 302)

| Platform | Rules |
|----------|-------|
| OCI Cloud | 148 |
| Linux | 81 |
| Windows | 316 |

| Severity | Count |
|----------|-------|
| 🔴 Critical | 110 |
| 🟠 High | 229 |
| 🟡 Medium | 147 |
| 🔵 Low | 29 |
| ⚪ Informational | 30 |

**Atomic Red Team Coverage:** 280/397 testable rules have ART tests (70.5%) | 3208 total test mappings

**STIG Coverage:** 24 rules covering 12 controls (AC-17, AC-3, AC-6, AU-11, AU-12, CP-9, IA-2, IA-5, IA-8, SC-12, SC-28, SC-7)

## MITRE ATT&CK Coverage

**279 techniques** across **14 tactics**

### Reconnaissance (36 techniques)

| Technique | Rules |
|-----------|-------|
| T1005 | CybleVision Alerts Darkweb Marketplace Alerts, CybleVision Alerts Stealer Logs |
| T1041 | Cyble Vision Alerts Postman API Exposure Detection, CybleVision Alerts Darkweb Marketplace Alerts, CybleVision Alerts Stealer Logs |
| T1046 | Cyble Vision Alerts IOC'S, Cyble Vision Alerts Vulnerability |
| T1048 | Cyble Vision Alerts Darkweb Data Breaches |
| T1071 | Cyble Vision Alerts IOC'S |
| T1078 | Cyble Vision Alerts Darkweb Data Breaches |
| T1082 | Cyble Vision Alerts Leaked Credentials |
| T1083 | Web Directory Enumeration Detected |
| T1102 | CybleVision Alerts Telegram Mentions |
| T1133 | Cyble Vision Alerts IOC'S |
| T1189 | CybleVision Alerts Stealer Logs |
| T1195 | CybleVision Alerts Mobile Apps |
| T1203 | Cyble Vision Alerts Vulnerability |
| T1486 | Cyble Vision Alerts Darkweb Ransomware Leak, Cyble Vision Alerts IOC'S |
| T1491 | Cyble Vision Alerts Hacktivism, Cyble Vision Alerts Website Defacement Keyword |
| T1498 | Cyble Vision Alerts Hacktivism |
| T1530 | Cyble Vision Alerts Darkweb Data Breaches |
| T1552 | Cyble Vision Alerts Leaked Credentials, Cyble Vision Alerts Postman API Exposure Detection |
| T1555 | CybleVision Alerts Darkweb Marketplace Alerts, CybleVision Alerts Stealer Logs |
| T1583 | Cyble Vision Alerts TOR Links |
| T1585 | Cyble Vision Alerts Hacktivism, Cyble Vision Alerts Social Media Monitoring, +2 more |
| T1587 | Cyble Advisory Alerts Advisory |
| T1589 | Cyble Vision Alerts Darkweb Data Breaches, Cyble Vision Alerts Flash Report, +5 more |
| T1590 | Cyble Vision Alerts TOR Links |
| T1591 | Cyble Vision Alerts Pastebin |
| T1592 | Cyble Vision Alerts Assets, Cyble Vision Alerts Cyble Web Applications, Cyble Vision Alerts OSINT Mention Detected |
| T1592.004 | APM: Browser Fingerprinting via Canvas/WebGL/AudioContext |
| T1595 | Suspicious or Empty User Agent Detected, Cyble Advisory Alerts Advisory, +11 more |
| T1595.002 | Web Directory Enumeration Detected, Web Vulnerability Scanner Detected, +2 more |
| T1596 | Cyble Advisory Alerts Advisory |
| T1598 | Cyble Vision Alerts Discord Keyword, Cyble Vision Alerts Flash Report, +4 more |
| T1598.003 | Cyble Vision Alerts Phishing Domain Detected |
| T1608 | CybleVision Alerts Mobile Apps |
| T1646 | CybleVision Alerts Cyber Crime Forum Alerts, CybleVision Alerts Darkweb Marketplace Alerts |
| T1657 | Cyble Vision Alerts Darkweb Ransomware Leak |
| T1664 | Cyble Vision Alerts Discord Keyword |

### Resource Development (21 techniques)

| Technique | Rules |
|-----------|-------|
| T1102 | CybleVision Alerts Telegram Mentions |
| T1190 | Cyble Vision Alerts Product Vulnerability Detected |
| T1195 | CybleVision Alerts Mobile Apps |
| T1491 | Cyble Vision Alerts Hacktivism |
| T1498 | Cyble Vision Alerts Hacktivism |
| T1566 | ZeroFox Alerts - High Severity Alerts, ZeroFox Alerts - Informational Severity Alerts, +2 more |
| T1583 | OCI Action: CreateSubnet, OCI Action: CreateVcn, +5 more |
| T1583.003 | OCI Action: CreateInstance |
| T1584 | Cyble Vision Alerts Domain Watchlist |
| T1585 | Cyble Vision Alerts Hacktivism, Cyble Vision Alerts I2P Monitoring, +3 more |
| T1586 | ZeroFox Alerts - High Severity Alerts, ZeroFox Alerts - Informational Severity Alerts, +2 more |
| T1587 | Cyble Advisory Alerts Advisory |
| T1588 | Cyble Vision Alerts Product Vulnerability Detected |
| T1589 | Cyble Vision Alerts OSINT Mention Detected, Cyble Vision Alerts Social Media Monitoring, CybleVision Alerts Cyber Crime Forum Alerts |
| T1590 | Cyble Vision Alerts TOR Links |
| T1592 | Cyble Vision Alerts OSINT Mention Detected |
| T1595 | Cyble Advisory Alerts Advisory, Cyble Vision Alerts Hacktivism, +3 more |
| T1596 | Cyble Advisory Alerts Advisory |
| T1598 | CybleVision Alerts Cyber Crime Forum Alerts, CybleVision Alerts Telegram Mentions |
| T1608 | CybleVision Alerts Mobile Apps |
| T1646 | CybleVision Alerts Cyber Crime Forum Alerts |

### Initial Access (79 techniques)

| Technique | Rules |
|-----------|-------|
| T1005 | CybleVision Alerts Stealer Logs |
| T1008 | Contrast ADR - Security Incident Alert |
| T1012 | BLUELIGHT APT37 Kill Chain Correlation |
| T1018 | Contrast ADR - Security Incident Alert |
| T1027 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), ClickFix: Clipboard PowerShell Execution |
| T1041 | CybleVision Alerts Stealer Logs, 2025-2026: Compromised Machines and Data, +6 more |
| T1046 | Cyble Vision Alerts IOC'S |
| T1048 | Cisco WSA - Rare URL with error, Cisco WSA - User errors, Cyble Vision Alerts Darkweb Data Breaches |
| T1053 | Critical Risks, Vulerabilities |
| T1055 | ApexOne - Top sources with alerts, Contrast ADR - Security Incident Alert, McAfee ePO - Multiple threats on same host |
| T1056.001 | BLUELIGHT: Attack Path (per Host) |
| T1059 | WAF Log4Shell (CVE-2021-44228) Attack Blocked, Web Server Process Spawning Command Shell, +13 more |
| T1059.001 | ClickFix Fake CAPTCHA PowerShell Execution, Web Server Process Spawning Command Shell, +2 more |
| T1059.004 | Linux Multi-Stage Attack Indicators (Combined Methods) |
| T1059.007 | WAF SQL Injection Attack Allowed Through, WAF SQL Injection Attack Blocked, +4 more |
| T1068 | ApexOne - Top sources with alerts, McAfee ePO - Threat was not blocked |
| T1070 | McAfee ePO - Multiple threats on same host, McAfee ePO - Threat was not blocked |
| T1071 | ApexOne - Top sources with alerts, Cyble Vision Alerts IOC'S, MELTS: 2025-2026 Attack Timeline |
| T1071.001 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), +9 more |
| T1078 | API Endpoint Unauthorized Access Attempts, OCI Console Login Failure, +44 more |
| T1082 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1083 | WAF Path Traversal Attack Blocked, BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1087 | OCI Unusual API Caller - First Seen User-Agent |
| T1095 | ApexOne - Top sources with alerts |
| T1098 | Ping Federate - Abnormal password resets for user, Ping Federate - Password reset requests, +2 more |
| T1102 | Cisco WSA - Multiple errors to resource from risky category, CybleVision Alerts Telegram Mentions |
| T1105 | BLUELIGHT APT37 Kill Chain Correlation |
| T1110 | OWASP Attack Detection (CRM + Drone Shop), Security Attack Source IP Analysis, +5 more |
| T1110.001 | Linux SSH Failed Login, SSH Brute Force Detection (Frequency Analysis) |
| T1110.003 | OCI Password Spraying Attack |
| T1110.004 | FLF: Credential Stuffing Pattern, OCI Multiple Users from Same IP (Grouping) |
| T1112 | ApexOne - Top sources with alerts |
| T1113 | BLUELIGHT APT37 Kill Chain Correlation |
| T1133 | Cloud Guard Problem: VCN Security List Port RDP, Cloud Guard Problem: VCN Security List Port SSH, +45 more |
| T1134 | Ping Federate - Abnormal password resets for user |
| T1185 | APM: Clickjacking - Missing Frame Protection Headers, APM: CSRF Token Missing or Invalid on State-Changing Request |
| T1187 | Google DNS - Exchange online autodiscover abuse |
| T1189 | BLUELIGHT RAT: Internet Explorer Drive-by Compromise, WAF CORS Bypass Attempt Blocked, +27 more |
| T1190 | API Endpoint Unauthorized Access Attempts, APM: SQL Injection Attack in Request, +89 more |
| T1195 | CybleVision Alerts Mobile Apps, Google DNS - Malicous Python packages, +6 more |
| T1202 | ApexOne - Top sources with alerts |
| T1203 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), +2 more |
| T1204 | ClickFix Fake CAPTCHA PowerShell Execution, ApexOne - Top sources with alerts, ClickFix: Clipboard PowerShell Execution |
| T1204.002 | Windows Spearphishing Attachment Execution |
| T1210 | Apache - Apache 2.4.49 flaw CVE-2021-41773 |
| T1218 | MELTS: Attack Path Link Drilldown, MELTS: 2025-2026 Attack Signal Overview |
| T1219 | MELTS: 2025-2026 Attack Signal Overview |
| T1486 | Cyble Vision Alerts IOC'S |
| T1496 | Browser Attack Frequency Analysis (SOC Application Logs) |
| T1498 | Apache - Multiple server errors from single IP, Cloudflare - Client errors, +8 more |
| T1499 | Cyble Vision Alerts SSL Certificate Expiry |
| T1505.003 | SharePoint ToolShell: Exploitation Attempts |
| T1528 | 2025-2026: Compromised Machines and Data |
| T1530 | Cyble Vision Alerts Darkweb Data Breaches, MELTS: 2025-2026 Attack Signal Overview |
| T1537 | ApexOne - Top sources with alerts |
| T1543 | McAfee ePO - Multiple threats on same host |
| T1546 | SUNBURST and SUPERNOVA backdoor hashes, SUNBURST and SUPERNOVA backdoor hashes (Normalized File Events), SUNBURST network beacons |
| T1548 | Critical Risks, Vulerabilities |
| T1550 | Web Application Authentication Bypass |
| T1552.005 | SSRF to Cloud Instance Metadata Service (Linux), SSRF to Cloud Metadata Endpoint (169.254.169.254), +4 more |
| T1555 | CybleVision Alerts Stealer Logs |
| T1555.003 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), +4 more |
| T1562 | McAfee ePO - Multiple threats on same host, McAfee ePO - Threat was not blocked, WAF Signal Correlation with Application Traces |
| T1566 | Cisco WSA - Access to unwanted site, Cyble Vision Alerts Malicious Ads Detected, +59 more |
| T1566.001 | Windows Spearphishing Attachment Execution, Acronis - Multiple Inboxes with Malicious Content Detected |
| T1566.002 | Acronis - Multiple Inboxes with Malicious Content Detected, Office ASR rule triggered from browser spawned office process., Suspicious parentprocess relationship - Office child processes. |
| T1567 | ApexOne - Top sources with alerts |
| T1567.002 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), BLUELIGHT: Total Detections (24h) |
| T1583 | ZeroFox Alerts - High Severity Alerts, ZeroFox Alerts - Informational Severity Alerts, +2 more |
| T1585 | CybleVision Alerts Telegram Mentions |
| T1586 | ZeroFox Alerts - High Severity Alerts, ZeroFox Alerts - Informational Severity Alerts, +2 more |
| T1588 | Cyble Vision Alerts Product Vulnerability Detected |
| T1589 | Cyble Vision Alerts Darkweb Data Breaches, CybleVision Alerts Stealer Logs |
| T1595 | Cyble Vision Alerts IOC'S, CybleVision Alerts Mobile Apps |
| T1598 | Cyble Vision Alerts Discord Keyword, CybleVision Alerts Telegram Mentions |
| T1606 | OCI Federated Identity Provider Modified |
| T1608 | CybleVision Alerts Mobile Apps |
| T1621 | OCI MFA Fatigue Attack Indicators |
| T1664 | Cyble Vision Alerts Discord Keyword |

### Execution (77 techniques)

| Technique | Rules |
|-----------|-------|
| T1003.001 | Hunting: Credential Attack Correlation (PowerShell + Mimikatz + Kerberoast) |
| T1005 | Deimos Component Execution |
| T1012 | BLUELIGHT APT37 Kill Chain Correlation |
| T1014 | Linux Boopkit eBPF Rootkit Activity |
| T1020 | Deimos Component Execution |
| T1021.002 | PsExec-style Remote Service Installation (Event 7045), Sysmon PsExec Named Pipe |
| T1021.006 | Sysmon Lateral Movement via WinRM |
| T1027 | Windows Encoded PowerShell Execution, Windows PowerShell Suspicious Script Block, +7 more |
| T1036 | CyberArkEPM - Unexpected executable extension, Hunting: GOAD/Apex Caldera Sandcat Agent Activity, +2 more |
| T1036.005 | Linux Process Execution from Unusual Paths |
| T1041 | 2025-2026: Compromised Machines and Data, MELTS: Attack Path Link Drilldown, +2 more |
| T1046 | Cyble Vision Alerts Vulnerability |
| T1047 | Impacket wmiexec Remote Command Execution, Windows Management Instrumentation Event Subscription, WMI Process Execution via Wmic |
| T1053 | Critical Risks, Vulerabilities |
| T1053.005 | Impacket atexec Remote Scheduled Task Execution, Suspicious Scheduled Task Creation, Hunting: GOAD/Apex Caldera Sandcat Agent Activity |
| T1055 | ApexOne - Top sources with alerts, Windows Rare Parent-Child Process Relationships |
| T1056.001 | APM: Suspicious JavaScript Execution Patterns, BLUELIGHT: Attack Path (per Host) |
| T1059 | Insecure Deserialization Attack Detected, Linux Process Execution from /dev/shm, +35 more |
| T1059.001 | ClickFix Fake CAPTCHA PowerShell Execution, PowerShell Execution via Alternate Shell, +12 more |
| T1059.003 | CMD: Suspicious Command Execution (Real Windows Security Events) |
| T1059.004 | Linux Bind Shell Listener, Linux Boopkit eBPF Rootkit Activity, +4 more |
| T1059.005 | Scripting Engine Spawning Network Utility, Visual Basic Script Compilation via vbc.exe, +2 more |
| T1059.006 | Python Execution as Child of System Process, CrashFix: Python RAT Activity |
| T1059.007 | JavaScript Execution via Node.js, APM: DOM-Based Attack via Dangerous JavaScript APIs, +6 more |
| T1068 | ApexOne - Top sources with alerts |
| T1070 | RedMenshen-BPFDoor-backdoor |
| T1071 | Sysmon Suspicious Named Pipe Pattern, ApexOne - Top sources with alerts, MELTS: 2025-2026 Attack Timeline |
| T1071.001 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), +9 more |
| T1072 | SolarWinds Inventory |
| T1078 | CyberArkEPM - Elevation requests |
| T1082 | Detect Suspicious Commands Initiated by Webserver Processes, BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1083 | Cyble Vision Alerts Docker, BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1086 | PowerShell: Suspicious Command Execution (Real Windows Security Events) |
| T1087 | Detect Suspicious Commands Initiated by Webserver Processes |
| T1095 | Linux Boopkit eBPF Rootkit Activity, ApexOne - Top sources with alerts, RedMenshen-BPFDoor-backdoor |
| T1098 | Azure DevOps Pull Request Policy Bypassing |
| T1102 | Discord download invoked from cmd line, Discord download invoked from cmd line (ASIM Version) |
| T1105 | Finger.exe Abuse for File Download, Windows PowerShell Download Cradle, +3 more |
| T1110 | OWASP Attack Detection (CRM + Drone Shop), Linux Multi-Stage Attack Indicators (Combined Methods), OWASP Multi-Stage Web Attack Chain (Combined Methods) |
| T1112 | ApexOne - Top sources with alerts |
| T1113 | BLUELIGHT APT37 Kill Chain Correlation |
| T1127.001 | MSBuild Execution from Non-Standard Location, Windows MSBuild Execution for Code Bypass |
| T1132 | Cisco Cloud Security - Windows PowerShell User-Agent Detected |
| T1140 | NRT Base64 Encoded Windows Process Command-lines |
| T1189 | ApexOne - Top sources with alerts, Critical Risks, +10 more |
| T1190 | Insecure Deserialization Attack Detected, WAF Command Injection Attack Blocked, +10 more |
| T1195 | SUNBURST and SUPERNOVA backdoor hashes, SUNBURST and SUPERNOVA backdoor hashes (Normalized File Events), SUNBURST network beacons |
| T1202 | ApexOne - Top sources with alerts |
| T1203 | BLUELIGHT RAT: Browser Spawning Suspicious Child Process, Cyble Vision Alerts Vulnerability, +8 more |
| T1204 | ClickFix Fake CAPTCHA PowerShell Execution, OCI Action: StartInstance, +43 more |
| T1204.001 | Acronis - Multiple Endpoints Accessing Malicious URLs |
| T1204.002 | BLUELIGHT RAT: YARA PDB Path Indicators (APT_MAL_Win_BlueLight), VBA Macro Spawning Suspicious Child Process, +11 more |
| T1218 | Control Panel Item Execution, SyncAppvPublishingServer Abuse, +5 more |
| T1218.005 | MSHTA JavaScript Execution, ClickFix: LOLBin Payload Execution |
| T1218.011 | DLL Execution via Rundll32 from User Path, ClickFix: LOLBin Payload Execution |
| T1219 | MELTS: 2025-2026 Attack Signal Overview |
| T1496 | APM: Suspicious JavaScript Execution Patterns, Browser Attack Frequency Analysis (SOC Application Logs) |
| T1505.003 | SharePoint ToolShell: Exploitation Attempts, SharePoint ToolShell: Webshell Post-Exploit |
| T1528 | 2025-2026: Compromised Machines and Data |
| T1530 | MELTS: 2025-2026 Attack Signal Overview |
| T1537 | ApexOne - Top sources with alerts, Cyble Vision Alerts Docker |
| T1543 | SUNBURST suspicious SolarWinds child processes (Normalized Process Events), TEARDROP memory-only dropper |
| T1546 | SUNBURST and SUPERNOVA backdoor hashes, SUNBURST and SUPERNOVA backdoor hashes (Normalized File Events), SUNBURST network beacons |
| T1548 | Critical Risks, VMWare-LPE-2022-22960, Vulerabilities |
| T1555.003 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), +4 more |
| T1558.003 | Hunting: Credential Attack Correlation (PowerShell + Mimikatz + Kerberoast) |
| T1562 | Doppelpaymer Stop Services |
| T1562.001 | Hunting: GOAD/Apex Caldera Sandcat Agent Activity |
| T1566 | Cyble Vision Alerts Malicious Ads Detected, ClickFix: Clipboard PowerShell Execution, +4 more |
| T1566.001 | Windows Spearphishing Attachment Execution |
| T1567 | ApexOne - Top sources with alerts, Discord download invoked from cmd line, Discord download invoked from cmd line (ASIM Version) |
| T1567.002 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), BLUELIGHT: Total Detections (24h) |
| T1569.002 | PsExec-style Remote Service Installation (Event 7045), Service Execution via sc.exe Create, Sysmon PsExec Named Pipe |
| T1574 | Detect Suspicious Commands Initiated by Webserver Processes |
| T1595 | Cyble Vision Alerts Vulnerability |
| T1610 | Cyble Vision Alerts Docker |
| T1648 | OCI Function Invoked |

### Persistence (65 techniques)

| Technique | Rules |
|-----------|-------|
| T1003.006 | DCSync Enablement: Replication Rights Granted via Directory Change (5136) |
| T1027 | TEARDROP memory-only dropper |
| T1053 | Linux Persistence Indicator Score (Combined Methods) |
| T1053.002 | Linux At Job Scheduled |
| T1053.003 | Linux Crontab Modification, Linux Suspicious Cron Job Content |
| T1053.005 | GPO Scheduled Task Written to SYSVOL, Scheduled Task XML Import, +2 more |
| T1055 | McAfee ePO - Multiple threats on same host |
| T1059 | SUNBURST and SUPERNOVA backdoor hashes, SUNBURST and SUPERNOVA backdoor hashes (Normalized File Events), +4 more |
| T1059.004 | Linux Multi-Stage Attack Indicators (Combined Methods) |
| T1070 | McAfee ePO - Multiple threats on same host |
| T1071 | Apache - Unexpected Post Requests |
| T1078 | Cisco Duo - Admin password reset, Cisco Duo - Admin user created, +12 more |
| T1098 | AdminSDHolder ACL Modification for Persistence, Computer Account Creation for Delegation Abuse (MachineAccountQuota), +18 more |
| T1098.001 | OCI Action: AddUserToGroup, OCI API Key Uploaded, OCI Dynamic Group Created |
| T1098.004 | Linux SSH Authorized Keys Modified, Linux Persistence Indicator Score (Combined Methods) |
| T1100 | Apache - Unexpected Post Requests |
| T1105 | Sysmon Executable File Created or Detected |
| T1110 | Linux Multi-Stage Attack Indicators (Combined Methods) |
| T1134 | Ping Federate - Abnormal password resets for user |
| T1136 | SlackAudit - New User created, Unusual identity creation using exchange powershell |
| T1136.001 | Linux Password File Direct Modification, New Local Account Created via Net.exe, FLF: New User Persistence |
| T1136.002 | Computer Account Creation for Delegation Abuse (MachineAccountQuota), FLF: New User Persistence |
| T1136.003 | OCI Action: CreateGroup, OCI Action: CreateUser |
| T1137 | Office Application Startup Persistence |
| T1189 | McAfee ePO - Multiple threats on same host |
| T1190 | WAF Web Shell Upload Attempt Blocked |
| T1195 | McAfee ePO - Multiple threats on same host, SUNBURST and SUPERNOVA backdoor hashes, +2 more |
| T1197 | BITS Job Persistence, Windows BITS Job Abuse for Persistence |
| T1219 | Windows Remote Access Tool Detected |
| T1484.001 | GPO Scheduled Task Written to SYSVOL |
| T1505 | Apache - Unexpected Post Requests, GitHub OAuth App Restrictions Disabled, GitHub OAuth App Restrictions Disabled |
| T1505.003 | Linux Web Shell File Creation, WAF Web Shell Upload Attempt Blocked, SharePoint ToolShell: Webshell Post-Exploit |
| T1542 | Boot Configuration Change for Persistence |
| T1543 | McAfee ePO - Multiple threats on same host, SUNBURST suspicious SolarWinds child processes (Normalized Process Events), TEARDROP memory-only dropper |
| T1543.002 | Linux Systemd Service Persistence, Linux Persistence Indicator Score (Combined Methods) |
| T1543.003 | Windows Service Created with Suspicious Binary Path, Windows Service Creation via SC, Windows Service Installed from Event Logs |
| T1546 | SUNBURST and SUPERNOVA backdoor hashes, SUNBURST and SUPERNOVA backdoor hashes (Normalized File Events), SUNBURST network beacons |
| T1546.001 | Default File Association Hijack |
| T1546.002 | ScreenSaver Hijacking Persistence |
| T1546.003 | Windows WMI Event Subscription Persistence, WMI Event Subscription Persistence |
| T1546.004 | Linux Shell Profile Persistence |
| T1546.007 | Netsh Helper DLL Persistence |
| T1546.008 | Accessibility Features Backdoor |
| T1546.010 | AppInit DLLs Persistence |
| T1546.011 | Application Shimming for Persistence |
| T1546.012 | Image File Execution Options Debugger, Known Nylon Typhoon Registry modifications patterns, Persisting via IFEO Registry Key |
| T1546.015 | COM Object Hijacking via Registry |
| T1547 | Midnight Blizzard - suspicious rundll32.exe execution of vbscript |
| T1547.001 | Registry Run Key Modification via Reg.exe, Startup Folder Modification, +2 more |
| T1547.003 | Time Provider DLL Persistence |
| T1547.004 | Winlogon Helper DLL Modification |
| T1547.005 | Security Support Provider DLL Persistence |
| T1547.006 | Linux Kernel Module Loaded from Temp Directory |
| T1547.009 | Shortcut Modification for Persistence |
| T1547.010 | Port Monitor DLL Persistence |
| T1547.012 | Print Processor Persistence |
| T1547.014 | Active Setup Persistence |
| T1548.001 | Linux Setuid Binary Creation |
| T1556 | DSRM Admin Logon Behavior Enabled for Persistence, Shadow Credentials: msDS-KeyCredentialLink Modified (Event 5136) |
| T1556.007 | OCI Identity Provider Created |
| T1558.001 | Golden Ticket: RC4 Encrypted TGT Request |
| T1562 | GitHub OAuth App Restrictions Disabled, GitHub OAuth App Restrictions Disabled, McAfee ePO - Multiple threats on same host |
| T1562.007 | OCI Route Table Update |
| T1574.006 | Linux LD_PRELOAD Library Hijacking |
| T1583 | OCI Action: AttachInternetGateway, OCI Action: CreateInternetGateway, OCI Action: CreateRouteTable |

### Privilege Escalation (46 techniques)

| Technique | Rules |
|-----------|-------|
| T1003 | Linux User Privilege Change Correlation |
| T1003.006 | Hunting: AD Attack Timeline - Multi-Stage Credential Attack Chain, Hunting: GOAD/Apex Caldera Attack Chain (Multi-Stage) |
| T1021 | Hunting: Logon Anomaly - Account Activity Profiling |
| T1053 | Critical Risks, Vulerabilities |
| T1053.005 | Windows Scheduled Task Created or Updated |
| T1055 | ApexOne - Top sources with alerts, McAfee ePO - Multiple threats on same host |
| T1059 | Critical Risks, Vulerabilities |
| T1068 | PrintNightmare Exploitation Attempt, Zerologon (CVE-2020-1472) Netlogon Exploitation, +4 more |
| T1070 | McAfee ePO - Multiple threats on same host, McAfee ePO - Threat was not blocked |
| T1071 | ApexOne - Top sources with alerts |
| T1078 | Mass Assignment Attack Detected, Web Application Privilege Escalation, +11 more |
| T1095 | ApexOne - Top sources with alerts |
| T1098 | Certifried (CVE-2022-26923): Machine Account dNSHostName Abuse, Cloud Guard Problem: Group Has Too Many Admins, +18 more |
| T1098.001 | Cloud Guard Problem: Instance Principals Enabled |
| T1110.001 | Hunting: AD Attack Timeline - Multi-Stage Credential Attack Chain, Hunting: GOAD/Apex Caldera Attack Chain (Multi-Stage) |
| T1112 | ApexOne - Top sources with alerts |
| T1134 | Privilege Escalation: Sensitive Privileges Assigned to Non-Admin, SeDebugPrivilege Abuse, +5 more |
| T1134.001 | Named Pipe Impersonation via PowerShell, Potato Privilege Escalation Tool, Privilege Escalation: Sensitive Privileges Assigned to Non-Admin |
| T1134.002 | Token Manipulation via RunAs |
| T1134.004 | Parent PID Spoofing |
| T1134.005 | SID History Added or Failed (Events 4765/4766), SID History Injection via mimikatz |
| T1136.002 | Computer Account Creation for Delegation Abuse (MachineAccountQuota) |
| T1189 | ApexOne - Top sources with alerts, Critical Risks, +3 more |
| T1195 | McAfee ePO - Multiple threats on same host, McAfee ePO - Threat was not blocked |
| T1202 | ApexOne - Top sources with alerts |
| T1203 | Suspicious Tomcat Confluence Process Launch, Suspicious Tomcat Confluence Process Launch |
| T1204 | ApexOne - Top sources with alerts, CyberArkEPM - Elevation requests, VMWare-LPE-2022-22960 |
| T1210 | Zerologon (CVE-2020-1472) Netlogon Exploitation, Oracle suspicious command execution |
| T1484.001 | GPO Abuse via SharpGPOAbuse |
| T1537 | ApexOne - Top sources with alerts |
| T1543 | McAfee ePO - Multiple threats on same host |
| T1543.003 | Windows Service Installed from Event Logs |
| T1548 | Critical Risks, VMWare-LPE-2022-22960, Vulerabilities |
| T1548.001 | Linux Setuid Binary Creation |
| T1548.002 | AlwaysInstallElevated Exploitation, UAC Bypass via ComputerDefaults, +4 more |
| T1548.003 | Linux Sudo Usage, Linux Sudoers File Modification, Linux User Privilege Change Correlation |
| T1550.003 | Hunting: AD Attack Timeline - Multi-Stage Credential Attack Chain, Hunting: GOAD/Apex Caldera Attack Chain (Multi-Stage) |
| T1558.003 | Hunting: AD Attack Timeline - Multi-Stage Credential Attack Chain, Hunting: GOAD/Apex Caldera Attack Chain (Multi-Stage) |
| T1562 | McAfee ePO - Multiple threats on same host, McAfee ePO - Threat was not blocked |
| T1567 | ApexOne - Top sources with alerts |
| T1574 | Windows Print Spooler Service Suspicious File Creation |
| T1574.009 | Unquoted Service Path Exploitation |
| T1574.011 | DLL Hijacking via Service Registry Permission, Service Permissions Weakness Discovery |
| T1611 | Linux Container Escape Attempt, Oracle suspicious command execution |
| T1649 | Certifried (CVE-2022-26923): Machine Account dNSHostName Abuse |
| t1574 | Windows Anitivirus and EDR Elevation of Privilege Vulnerability, Windows Spooler Service Suspicious File Creation |

### Defense Evasion (93 techniques)

| Technique | Rules |
|-----------|-------|
| T1003.001 | Windows WDigest Authentication Enabled for Credential Harvesting |
| T1008 | Contrast ADR - Security Incident Alert |
| T1012 | BLUELIGHT APT37 Kill Chain Correlation |
| T1014 | Linux Boopkit eBPF Rootkit Activity |
| T1018 | Contrast ADR - Security Incident Alert |
| T1027 | BLUELIGHT RAT: Obfuscated Script Execution, Windows Encoded PowerShell Execution, +8 more |
| T1036 | CyberArkEPM - Unexpected executable extension, Potential re-named sdelete usage, +4 more |
| T1036.003 | Renamed System Binary Execution |
| T1036.005 | Masquerading System Binary in Non-Standard Path, Linux Process Execution from Unusual Paths |
| T1048.003 | FLF: BITS Exfiltration Hunt |
| T1053.005 | Hunting: GOAD/Apex Caldera Sandcat Agent Activity |
| T1055 | Process Ghosting or Herpaderping, Sysmon Cobalt Strike Named Pipe, +4 more |
| T1055.001 | Process Injection via CreateRemoteThread |
| T1055.008 | Linux Process Injection via Ptrace |
| T1055.012 | Windows Process Hollowing Indicators |
| T1055.013 | Process Doppelganging via TxF |
| T1056.001 | BLUELIGHT: Attack Path (per Host) |
| T1059 | Detect Suspicious Commands Initiated by Webserver Processes, Doppelpaymer Stop Services, +6 more |
| T1059.001 | Windows Encoded PowerShell Execution, Windows PowerShell Suspicious Script Block, +3 more |
| T1059.004 | Linux Boopkit eBPF Rootkit Activity, Linux Rare Process Detection (Stacking) |
| T1059.007 | ClickFix: LOLBin Payload Execution |
| T1068 | ApexOne - Top sources with alerts, McAfee ePO - Threat was not blocked |
| T1070 | Bitglass - The SmartEdge endpoint agent was uninstalled, CiscoISE - Attempt to delete local store logs, +11 more |
| T1070.001 | Windows Event Log Cleared via Wevtutil, Windows Event Log Clearing, Windows Security or System Event Log Cleared |
| T1070.002 | Linux Log File Tampering |
| T1070.003 | Linux History File Cleared |
| T1070.004 | File Deletion of Security Tools, SDelete Secure File Deletion, CiscoISE - Log files deleted |
| T1070.006 | Timestomping via PowerShell |
| T1071 | Sysmon Cobalt Strike Named Pipe, ApexOne - Top sources with alerts, McAfee ePO - Firewall disabled |
| T1071.001 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), +2 more |
| T1078 | OracleDBAudit - Active Users, OCI Off-Hours Administrative Activity |
| T1082 | Detect Suspicious Commands Initiated by Webserver Processes, BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1083 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1087 | Detect Suspicious Commands Initiated by Webserver Processes |
| T1090.004 | FLF: Domain Fronting CDN C2 Hunt |
| T1095 | Linux Boopkit eBPF Rootkit Activity, ApexOne - Top sources with alerts |
| T1098 | OCI After-Hours IAM Activity (Time-Based Anomaly), OCI Off-Hours Administrative Activity |
| T1105 | Sysmon Suspicious Outbound Connection from LOLBin, Windows Certutil Download or Decode, BLUELIGHT APT37 Kill Chain Correlation |
| T1112 | ApexOne - Top sources with alerts, shimcache-flushed |
| T1113 | BLUELIGHT APT37 Kill Chain Correlation |
| T1127 | CyberArkEPM - MSBuild usage as LOLBin |
| T1127.001 | Windows MSBuild Execution for Code Bypass |
| T1132 | Cisco Cloud Security - Windows PowerShell User-Agent Detected |
| T1134 | Windows Access Token Manipulation |
| T1140 | Windows Certutil Download or Decode, NRT Base64 Encoded Windows Process Command-lines |
| T1189 | ApexOne - Top sources with alerts, McAfee ePO - Multiple threats on same host, +3 more |
| T1190 | Contrast ADR - Security Incident Alert, WAF Signal Correlation with Application Traces |
| T1195 | McAfee ePO - Multiple threats on same host, McAfee ePO - Threat was not blocked |
| T1197 | Windows BITS Job Abuse for Persistence, FLF: BITS Exfiltration Hunt |
| T1202 | Indirect Command Execution via Forfiles, ApexOne - Top sources with alerts |
| T1203 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1204 | ApexOne - Top sources with alerts, CyberArkEPM - Unexpected executable extension, +2 more |
| T1207 | DCShadow Rogue Domain Controller Registration |
| T1218 | Sysmon Suspicious Outbound Connection from LOLBin, Windows LOLBin Usage: at, +22 more |
| T1218.001 | Compiled HTML File Execution |
| T1218.003 | CMSTP UAC Bypass |
| T1218.004 | InstallUtil Application Whitelisting Bypass |
| T1218.005 | AppLocker Policy Bypass via MSHTML, ClickFix: LOLBin Payload Execution |
| T1218.009 | Regsvcs or Regasm Execution for Code Bypass |
| T1218.011 | Rundll32 (LOLBins and LOLScripts, Normalized Process Events), ClickFix: LOLBin Payload Execution |
| T1220 | XSL Script Processing via WMIC or Msxsl |
| T1221 | Template Injection via Microsoft Office, detect-office-applications-spawning-msdt-CVE-2022-30190 |
| T1485 | Potential re-named sdelete usage, Potential re-named sdelete usage (ASIM Version) |
| T1497 | Virtualization Sandbox Evasion Check |
| T1505 | GitHub OAuth App Restrictions Disabled, GitHub OAuth App Restrictions Disabled |
| T1537 | ApexOne - Top sources with alerts |
| T1539 | Cyble Vision Alerts Compromised Endpoint Cookies |
| T1543 | McAfee ePO - Multiple threats on same host, TEARDROP memory-only dropper |
| T1548.002 | Windows UAC Bypass Attempt, Windows Defense Evasion Score (Combined Methods) |
| T1550 | Cyble Vision Alerts Compromised Endpoint Cookies, GCP IAM - Empty user agent, GWorkspace - API Access Granted |
| T1553 | OCI Action: CreateKey |
| T1553.004 | Root Certificate Installation via Certutil |
| T1555.003 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1556.001 | Skeleton Key Domain Backdoor via mimikatz |
| T1562 | Cisco SE - Modified agents on hosts, Cisco SE - Policy update failure, +18 more |
| T1562.001 | AMSI Bypass via PowerShell Reflection, OCI Log Group Deleted, +8 more |
| T1562.002 | ETW Provider Disabled, Windows Audit Policy Changed, CiscoISE - Log collector was suspended |
| T1562.004 | Disable Windows Firewall via Netsh, OCI Network Firewall Policy Modified, +2 more |
| T1562.007 | OCI Action: CreateSecurityList, OCI Action: UpdateBucket, +7 more |
| T1562.008 | Cloud Guard Problem: Audit Log Retention, Cloud Guard Problem: VCN Flow Log Disabled, +4 more |
| T1564.001 | Linux Hidden File or Directory Creation in Suspicious Location |
| T1564.003 | Hidden PowerShell Window Execution |
| T1564.004 | Alternate Data Stream Execution |
| T1565.001 | Linux Hosts File Modification |
| T1566 | ClickFix: Clipboard PowerShell Execution |
| T1567 | ApexOne - Top sources with alerts |
| T1567.002 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1574 | Detect Suspicious Commands Initiated by Webserver Processes |
| T1574.002 | DLL Side-Loading from Suspicious Directory, Windows DLL Side-Loading via Suspicious Path |
| T1578 | OCI - Updated instances |
| T1600 | OCI Vault Key Rotation Overdue |
| T1620 | Reflective DLL Loading Indicators |
| T1649 | ADCS ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 Flag Enabled via Certutil |

### Credential Access (70 techniques)

| Technique | Rules |
|-----------|-------|
| T1003 | Caldera - LSASS Memory Dump via ProcDump or Task Manager (Caldera Emulation), Internal Monologue NTLM Hash Theft, +7 more |
| T1003.001 | Caldera - LSASS Memory Dump via ProcDump or Task Manager (Caldera Emulation), Credential Dumping via Comsvcs with Rundll32, +12 more |
| T1003.002 | SAM Database Extraction via Reg Save |
| T1003.003 | NTDS.dit Database Copy Attempt, Windows NTDS.dit Database Extraction |
| T1003.004 | LSA Secrets Registry Extraction |
| T1003.006 | DCSync Attack via Replication Request, DCSync: Directory Replication from Non-Domain Controller, +5 more |
| T1003.007 | Linux Process Memory Access via /proc |
| T1005 | Linux Sensitive Data Collection from Local System, CybleVision Alerts Darkweb Marketplace Alerts, CybleVision Alerts Stealer Logs |
| T1012 | BLUELIGHT APT37 Kill Chain Correlation |
| T1021 | Hunting: Logon Anomaly - Account Activity Profiling |
| T1027 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1041 | Cyble Vision Alerts Compromised Files, Cyble Vision Alerts Postman API Exposure Detection, +7 more |
| T1056.001 | Windows Keylogger Indicators, BLUELIGHT: Attack Path (per Host) |
| T1059 | OWASP Attack Detection (CRM + Drone Shop), 2025-2026: Compromised Machines and Data, OWASP Multi-Stage Web Attack Chain (Combined Methods) |
| T1059.001 | Hunting: Credential Attack Correlation (PowerShell + Mimikatz + Kerberoast), MELTS: 2025-2026 Attack Signal Overview |
| T1071.001 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), +8 more |
| T1078 | FLF: Credential Stuffing Pattern, Hunting: Logon Anomaly - Account Activity Profiling, +3 more |
| T1082 | Cyble Vision Alerts Leaked Credentials, BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1083 | Cyble Vision Alerts Bitbucket, BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1098 | Certifried (CVE-2022-26923): Machine Account dNSHostName Abuse, DCSync Enablement: Replication Rights Granted via Directory Change (5136), Shadow Credentials: msDS-KeyCredentialLink Modified (Event 5136) |
| T1098.001 | OCI Customer Secret Key Created |
| T1105 | BLUELIGHT APT37 Kill Chain Correlation |
| T1110 | Cloud Guard Problem: IAM User Console Password Old, WAF Rate Limiting Triggered, +11 more |
| T1110.001 | Brute Force: Failed Logon Spike per Account, Linux SSH Failed Login, +5 more |
| T1110.003 | Brute Force: Failed Logon Spike per Account, OCI Password Spraying Attack, +3 more |
| T1110.004 | FLF: Credential Stuffing Pattern |
| T1111 | GWorkspace - Two-step authentification disabled for a user |
| T1113 | BLUELIGHT APT37 Kill Chain Correlation |
| T1114 | BLUELIGHT RAT: YARA Chrome/Edge Cookie Theft (APT_MAL_Win_BlueLight_B) |
| T1134 | Sysmon Mimikatz Named Pipe, Token Impersonation via Incognito, +3 more |
| T1187 | Coercer Multi-Protocol Authentication Coercion, DFSCoerce MS-DFSNM Authentication Coercion, +3 more |
| T1189 | CybleVision Alerts Stealer Logs, BLUELIGHT APT37 Kill Chain Correlation, +5 more |
| T1190 | SSRF to Cloud Instance Metadata Service (Linux), SSRF to Cloud Metadata Endpoint (169.254.169.254), +6 more |
| T1203 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), +2 more |
| T1213 | Cyble Vision Alerts Github |
| T1218 | MELTS: 2025-2026 Attack Signal Overview |
| T1219 | MELTS: 2025-2026 Attack Signal Overview |
| T1528 | OCI Auth Token Created, Trust Monitor Event, +2 more |
| T1530 | Cyble Vision Alerts Github, Cloud Identity: AiTM Token Abuse, +2 more |
| T1537 | Cyble Vision Alerts Bitbucket |
| T1538 | Cloud Identity: AiTM Token Abuse |
| T1539 | BLUELIGHT RAT: YARA Chrome/Edge Cookie Theft (APT_MAL_Win_BlueLight_B), Web Application Session Hijacking Indicators, +2 more |
| T1548.003 | Linux User Privilege Change Correlation |
| T1550 | Cyble Vision Alerts Compromised Endpoint Cookies |
| T1550.002 | Overpass-the-Hash via Rubeus asktgt |
| T1550.003 | Pass-the-Cert / UnPAC-the-Hash via Certipy auth, Pass-the-Ticket: Excessive Explicit Credential Logons, +2 more |
| T1550.004 | Web Application Session Hijacking Indicators, APM: Session Hijacking - Rapid Session Changes |
| T1552 | Caldera - Credential Search in Config and Environment Files (Windows), Caldera - Credential Search in Files via grep (Linux), +6 more |
| T1552.001 | Caldera - Credential Search in Config and Environment Files (Windows), Caldera - Credential Search in Files via grep (Linux), +2 more |
| T1552.004 | Cloud Guard Problem: IAM User API Key Old |
| T1552.005 | OCI Instance Metadata Service Accessed, SSRF to Cloud Instance Metadata Service (Linux), +5 more |
| T1552.006 | Group Policy Preferences Password Extraction |
| T1555 | DPAPI Master Key Extraction, gMSA Managed Password Read Attempt, +7 more |
| T1555.003 | BLUELIGHT RAT: Browser Credential Memory Access, BLUELIGHT RAT: YARA Chrome/Edge Cookie Theft (APT_MAL_Win_BlueLight_B), +7 more |
| T1555.004 | Credential Manager: High-Frequency Credential Read |
| T1556 | NPPSpy Credential Interception, OCI User MFA Not Enabled, +2 more |
| T1556.001 | Skeleton Key Domain Backdoor via mimikatz |
| T1557.001 | ADCS ESC8: NTLM Relay to Certificate Web Enrollment, ntlmrelayx NTLM Relay Execution Indicators |
| T1558 | Kerberos Ticket Export via Mimikatz, Timeroasting: Computer Account Hash Harvest via NTP, Unconstrained Delegation TGT Capture via Rubeus monitor |
| T1558.001 | Golden Ticket: RC4 Encrypted TGT Request |
| T1558.002 | Silver Ticket: Forged Kerberos Service Ticket |
| T1558.003 | Constrained Delegation S4U2Proxy Abuse via Rubeus, Kerberoasting: RC4 Encrypted Service Ticket Request, +12 more |
| T1558.004 | AS-REP Roasting via Rubeus, Targeted AS-REP Roasting: DoNotRequirePreAuth Set |
| T1566 | Google DNS - Exchange online autodiscover abuse, 2025-2026: Compromised Machines and Data, MELTS: 2025-2026 Attack Signal Overview |
| T1567.002 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), BLUELIGHT: Total Detections (24h) |
| T1580 | Web-to-Cloud: Compromised Cloud Identity |
| T1589 | CybleVision Alerts Darkweb Marketplace Alerts, CybleVision Alerts Stealer Logs |
| T1595 | Cyble Vision Alerts Postman API Exposure Detection |
| T1646 | CybleVision Alerts Darkweb Marketplace Alerts |
| T1649 | ADCS ESC1: Subject Alternative Name Abuse via Certipy/Certify, ADCS ESC4: Certificate Template ACL Modification via Certipy, +5 more |

### Discovery (52 techniques)

| Technique | Rules |
|-----------|-------|
| T0830 | Cyble Vision Alerts OT/ICS Threat Activity Detected |
| T0842 | Cyble Vision Alerts OT/ICS Threat Activity Detected |
| T1008 | Contrast ADR - Security Incident Alert |
| T1012 | BLUELIGHT RAT: Registry Enumeration of Security Products, Microsoft Entra ID Local Device Join Information and Transport Key Registry Keys Access, BLUELIGHT APT37 Kill Chain Correlation |
| T1016 | BLUELIGHT RAT: YARA System Reconnaissance JSON (APT_MAL_Win_BlueLight), Caldera - Network Configuration Recon via ipconfig and route (Windows), +2 more |
| T1018 | Windows Remote System Discovery, Contrast ADR - Security Incident Alert |
| T1027 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1033 | Caldera - System Owner and Identity Discovery via id/whoami (Linux), Caldera - System Owner and User Discovery (Windows), +2 more |
| T1046 | Linux Network Service Scanning, Cyble Vision Alerts IOC'S, Cyble Vision Alerts Vulnerability |
| T1049 | Caldera - System Network Connections Discovery (Linux), Caldera - System Network Connections Discovery (Windows) |
| T1055 | Contrast ADR - Security Incident Alert |
| T1056.001 | BLUELIGHT: Attack Path (per Host) |
| T1057 | BLUELIGHT RAT: YARA System Reconnaissance JSON (APT_MAL_Win_BlueLight), Process Discovery via Tasklist |
| T1059 | Detect Suspicious Commands Initiated by Webserver Processes |
| T1069 | Windows Account or Group Enumeration Spike, OCI - Insecure metadata endpoint |
| T1069.001 | Local Group Membership Discovery |
| T1069.002 | Domain Admins Group Enumeration via net group, Security Group Enumeration: Rapid Membership Queries, Sysmon LDAP Reconnaissance |
| T1071 | Cyble Vision Alerts IOC'S |
| T1071.001 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), BLUELIGHT: Total Detections (24h) |
| T1078 | OCI Unusual API Caller - First Seen User-Agent |
| T1082 | BLUELIGHT RAT: WMI System Enumeration from Browser Child, BLUELIGHT RAT: YARA System Reconnaissance JSON (APT_MAL_Win_BlueLight), +8 more |
| T1083 | BLUELIGHT RAT: File Discovery from Browser Process, File and Directory Discovery via dir, +5 more |
| T1087 | Windows Account or Group Enumeration Spike, Detect Suspicious Commands Initiated by Webserver Processes, OCI Unusual API Caller - First Seen User-Agent |
| T1087.001 | Windows Account Discovery Commands |
| T1087.002 | AD Enumeration via ADFind, BloodHound AD Enumeration, +4 more |
| T1087.004 | OCI Cross-Compartment Activity Anomaly |
| T1105 | BLUELIGHT APT37 Kill Chain Correlation |
| T1113 | BLUELIGHT APT37 Kill Chain Correlation |
| T1133 | Cyble Vision Alerts IOC'S |
| T1135 | Network Share Enumeration via Net View, Windows Network Share Discovery |
| T1189 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), BLUELIGHT: Total Detections (24h) |
| T1190 | Contrast ADR - Security Incident Alert |
| T1201 | Password Policy Discovery |
| T1203 | Cyble Vision Alerts Vulnerability, BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1482 | Domain Trust Discovery via Nltest, PowerView / PowerSploit Domain Reconnaissance, Dev-0270 WMIC  Discovery |
| T1486 | Cyble Vision Alerts IOC'S |
| T1518 | Software Discovery via WMIC |
| T1518.001 | Query Registry for Security Products |
| T1526 | SOCRadar Audit Analysis |
| T1528 | Cloud Identity: AiTM Token Abuse |
| T1530 | Cloud Identity: AiTM Token Abuse, Web-to-Cloud: OCI Audit Cloud Abuse, Web-to-Cloud: Compromised Cloud Identity |
| T1537 | Cyble Vision Alerts Bitbucket, Cyble Vision Alerts Cloud Storage, Cyble Vision Alerts Docker |
| T1538 | Cloud Identity: AiTM Token Abuse |
| T1552 | Cyble Vision Alerts Bitbucket, Cyble Vision Alerts Leaked Credentials |
| T1552.005 | Web-to-Cloud: Compromised Cloud Identity |
| T1555.003 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), BLUELIGHT: Total Detections (24h) |
| T1567 | Web-to-Cloud: OCI Audit Cloud Abuse |
| T1567.002 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), BLUELIGHT: Total Detections (24h) |
| T1574 | Detect Suspicious Commands Initiated by Webserver Processes |
| T1580 | OCI Cloud Infrastructure Discovery, OCI Cross-Compartment Activity Anomaly, +2 more |
| T1595 | Cyble Vision Alerts IOC'S, Cyble Vision Alerts Vulnerability |
| T1610 | Cyble Vision Alerts Docker |

### Lateral Movement (35 techniques)

| Technique | Rules |
|-----------|-------|
| T1003.006 | Hunting: AD Attack Timeline - Multi-Stage Credential Attack Chain, Hunting: GOAD/Apex Caldera Attack Chain (Multi-Stage) |
| T1021 | OCI Bastion Session Created, OCI Instance Console Connection Created, +3 more |
| T1021.001 | RDP Session Hijacking via tscon, SharpRDP Lateral Movement, +3 more |
| T1021.002 | Caldera - SMB Lateral Movement via Impacket from Linux, Executable Written to Remote Admin Share (Lateral Tool Transfer), +10 more |
| T1021.003 | DCOM Lateral Movement via MMC20 |
| T1021.004 | FLF: Port Knocking Sequence Drilldown |
| T1021.006 | Caldera - WinRM Lateral Movement via Evil-WinRM from Linux, Lateral Movement: Account Authenticating from Multiple Sources, +4 more |
| T1039 | Windows Administrative Share Access Spike |
| T1047 | Impacket wmiexec Remote Command Execution |
| T1053.005 | Impacket atexec Remote Scheduled Task Execution |
| T1059.001 | Sysmon Lateral Movement via WinRM |
| T1068 | Zerologon (CVE-2020-1472) Netlogon Exploitation |
| T1071.001 | RMM: Post-Compromise Remote Access Activity |
| T1078 | Hunting: Logon Anomaly - Account Activity Profiling |
| T1087.004 | OCI Cross-Compartment Activity Anomaly |
| T1095 | FLF: Port Knocking Sequence Drilldown |
| T1110.001 | Hunting: AD Attack Timeline - Multi-Stage Credential Attack Chain, Hunting: GOAD/Apex Caldera Attack Chain (Multi-Stage) |
| T1133 | Apache - Apache 2.4.49 flaw CVE-2021-41773 |
| T1134 | Hunting: AD Attack Timeline - Multi-Stage Credential Attack Chain, Hunting: GOAD/Apex Caldera Attack Chain (Multi-Stage), Hunting: Logon Anomaly - Account Activity Profiling |
| T1190 | Apache - Apache 2.4.49 flaw CVE-2021-41773 |
| T1210 | Zerologon (CVE-2020-1472) Netlogon Exploitation, Apache - Apache 2.4.49 flaw CVE-2021-41773, Oracle suspicious command execution |
| T1219 | RMM: Post-Compromise Remote Access Activity |
| T1539 | APM: Session Hijacking - Rapid Session Changes |
| T1550 | GWorkspace - API Access Granted |
| T1550.002 | Overpass-the-Hash via Rubeus asktgt, Windows Pass-the-Hash Attack Indicators |
| T1550.003 | Pass-the-Ticket via Rubeus, Pass-the-Ticket: Excessive Explicit Credential Logons, +2 more |
| T1550.004 | APM: Session Hijacking - Rapid Session Changes |
| T1558.003 | Hunting: AD Attack Timeline - Multi-Stage Credential Attack Chain, Hunting: GOAD/Apex Caldera Attack Chain (Multi-Stage) |
| T1569.002 | PsExec-style Remote Service Installation (Event 7045), Sysmon PsExec Named Pipe, Windows PsExec Remote Execution |
| T1570 | Caldera - Lateral Tool Transfer via scp/rsync (Linux), Executable Written to Remote Admin Share (Lateral Tool Transfer), +4 more |
| T1574 | Windows Print Spooler Service Suspicious File Creation |
| T1580 | OCI Cross-Compartment Activity Anomaly |
| T1599 | OCI DRG Attachment Created, OCI Local Peering Gateway Created, OCI Service Gateway Created |
| T1611 | Oracle suspicious command execution |
| t1574 | Windows Anitivirus and EDR Elevation of Privilege Vulnerability, Windows Spooler Service Suspicious File Creation |

### Collection (46 techniques)

| Technique | Rules |
|-----------|-------|
| T0830 | Cyble Vision Alerts OT/ICS Threat Activity Detected |
| T0842 | Cyble Vision Alerts OT/ICS Threat Activity Detected |
| T1005 | Caldera - Data Collection from Local System via findstr and PowerShell (Windows), Caldera - Document and Data File Collection from Linux Host, +5 more |
| T1012 | BLUELIGHT APT37 Kill Chain Correlation |
| T1020 | Deimos Component Execution |
| T1021.002 | Windows Administrative Share Access Spike |
| T1027 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1039 | Caldera - Data Collection from Network Shared Drive (Linux), Caldera - Data Collection from Network Shared Drive (Windows), Windows Administrative Share Access Spike |
| T1041 | CybleVision Alerts Darkweb Marketplace Alerts, CybleVision Alerts Stealer Logs, +2 more |
| T1048 | Cyble Vision Alerts Darkweb Data Breaches |
| T1056.001 | BLUELIGHT RAT: YARA Keylogger Component (APT_MAL_Win_BlueLight_B), Keylogging via PowerShell Get-Keystrokes, +3 more |
| T1059 | Deimos Component Execution, Office Apps Launching Wscipt |
| T1059.007 | APM: Suspicious JavaScript Execution Patterns |
| T1071.001 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), BLUELIGHT: Total Detections (24h) |
| T1074 | Caldera - Local Data Staging in Writable Directories (Linux), Caldera - Remote Data Staging via SMB Share Write |
| T1074.001 | Caldera - Local Data Staging in Writable Directories (Linux), Windows Data Staging for Exfiltration, Linux Data Staging and Exfiltration Indicators |
| T1074.002 | Caldera - Remote Data Staging via SMB Share Write |
| T1078 | Cyble Vision Alerts Darkweb Data Breaches |
| T1082 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1083 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1105 | Office Apps Launching Wscipt, BLUELIGHT APT37 Kill Chain Correlation |
| T1113 | BLUELIGHT RAT: Periodic Screen Capture, Screen Capture via PowerShell, +2 more |
| T1114 | BLUELIGHT RAT: YARA Chrome/Edge Cookie Theft (APT_MAL_Win_BlueLight_B), Email Collection via PowerShell, +2 more |
| T1115 | Clipboard Data Collection |
| T1119 | OCI API Call Burst by User |
| T1189 | CybleVision Alerts Stealer Logs, BLUELIGHT APT37 Kill Chain Correlation, +2 more |
| T1203 | Office Apps Launching Wscipt, BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1213 | Cyble Vision Alerts Github |
| T1496 | APM: Suspicious JavaScript Execution Patterns |
| T1528 | Cloud Identity: AiTM Token Abuse |
| T1530 | OCI Action: CreateBucket, Cyble Vision Alerts Darkweb Data Breaches, +7 more |
| T1538 | Cloud Identity: AiTM Token Abuse |
| T1539 | BLUELIGHT RAT: YARA Chrome/Edge Cookie Theft (APT_MAL_Win_BlueLight_B) |
| T1552 | Cyble Vision Alerts Github |
| T1552.001 | Sensitive Data Endpoint Access |
| T1552.005 | Web-to-Cloud: Compromised Cloud Identity |
| T1555 | CybleVision Alerts Darkweb Marketplace Alerts, CybleVision Alerts Stealer Logs |
| T1555.003 | BLUELIGHT RAT: YARA Chrome/Edge Cookie Theft (APT_MAL_Win_BlueLight_B), BLUELIGHT APT37 Kill Chain Correlation, +2 more |
| T1557 | Linux Suspicious Network Traffic Redirect |
| T1560 | Judgement Panda Exfil Activity |
| T1560.001 | Data Compression for Exfiltration via 7zip, Linux Archive Data Collected for Exfiltration, Linux Data Staging and Exfiltration Indicators |
| T1567 | 2025-2026: Exfiltration After Initial Access, Web-to-Cloud: OCI Audit Cloud Abuse, Web-to-Cloud: Exfiltrated Data Evidence |
| T1567.002 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), BLUELIGHT: Total Detections (24h) |
| T1580 | Web-to-Cloud: OCI Audit Cloud Abuse, Web-to-Cloud: Compromised Cloud Identity |
| T1589 | Cyble Vision Alerts Darkweb Data Breaches, CybleVision Alerts Darkweb Marketplace Alerts, CybleVision Alerts Stealer Logs |
| T1646 | CybleVision Alerts Darkweb Marketplace Alerts |

### Command & Control (64 techniques)

| Technique | Rules |
|-----------|-------|
| T1001.003 | Cisco Cloud Security - Empty User Agent Detected |
| T1008 | Contrast ADR - Security Incident Alert |
| T1012 | BLUELIGHT APT37 Kill Chain Correlation |
| T1014 | Linux Boopkit eBPF Rootkit Activity |
| T1018 | Contrast ADR - Security Incident Alert |
| T1021.004 | FLF: Port Knocking Sequence Drilldown |
| T1027 | Cisco Cloud Security - Windows PowerShell User-Agent Detected, BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1036 | Hunting: GOAD/Apex Caldera Sandcat Agent Activity |
| T1041 | Cisco Cloud Security - Crypto Miner User-Agent Detected, Ubiquiti - connection to non-corporate DNS server, +12 more |
| T1046 | Cyble Vision Alerts IOC'S |
| T1048 | Cisco WSA - Rare URL with error, Cisco WSA - User errors, DNS Exfiltration Detection (Entropy Analysis) |
| T1048.003 | Sysmon DNS Data Exfiltration, Sysmon DNS Tunneling via Network Connection, +3 more |
| T1053.005 | Hunting: GOAD/Apex Caldera Sandcat Agent Activity |
| T1055 | Sysmon Cobalt Strike Named Pipe, ApexOne - Top sources with alerts, Contrast ADR - Security Incident Alert |
| T1056.001 | BLUELIGHT: Attack Path (per Host) |
| T1059 | Sysmon Suspicious Named Pipe Pattern, Office Apps Launching Wscipt, +3 more |
| T1059.001 | Windows PowerShell Download Cradle, Cisco Cloud Security - Windows PowerShell User-Agent Detected, MELTS: 2025-2026 Attack Signal Overview |
| T1059.004 | Linux Boopkit eBPF Rootkit Activity |
| T1059.006 | CrashFix: Python RAT Activity |
| T1068 | ApexOne - Top sources with alerts |
| T1071 | Sysmon Cobalt Strike Named Pipe, Sysmon Suspicious Named Pipe Pattern, +13 more |
| T1071.001 | BLUELIGHT RAT: C2 via Microsoft Graph API, BLUELIGHT RAT: YARA Google App C2 Communication (APT_MAL_Win_BlueLight_B), +27 more |
| T1071.004 | Linux DNS Tunneling Detected, Sysmon DNS Data Exfiltration, +11 more |
| T1082 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1083 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1090 | Linux Proxy and Tunneling Tool Detected |
| T1090.001 | Linux Proxy and Tunneling Tool Detected |
| T1090.004 | FLF: Domain Fronting CDN C2 Hunt |
| T1095 | Linux Boopkit eBPF Rootkit Activity, Sysmon Cobalt Strike C2 Network Indicators, +16 more |
| T1100 | Apache - Unexpected Post Requests |
| T1102 | BLUELIGHT RAT: YARA Google App C2 Communication (APT_MAL_Win_BlueLight_B), Cisco SE - Possible webshell, +5 more |
| T1105 | BLUELIGHT RAT: Executable Download via Graph API, Linux Suspicious Download to /tmp, +9 more |
| T1112 | ApexOne - Top sources with alerts |
| T1113 | BLUELIGHT APT37 Kill Chain Correlation |
| T1132 | Cisco Cloud Security - Windows PowerShell User-Agent Detected |
| T1133 | Cyble Vision Alerts IOC'S |
| T1140 | Windows Certutil Download or Decode |
| T1189 | ApexOne - Top sources with alerts, Cisco WSA - Multiple errors to resource from risky category, +8 more |
| T1190 | Contrast ADR - Security Incident Alert, Web-to-Cloud: Attack Path Link Analysis, +2 more |
| T1202 | ApexOne - Top sources with alerts |
| T1203 | Office Apps Launching Wscipt, BLUELIGHT APT37 Kill Chain Correlation, +3 more |
| T1204 | ApexOne - Top sources with alerts, Discord download invoked from cmd line, Discord download invoked from cmd line (ASIM Version) |
| T1218 | Sysmon Suspicious Outbound Connection from LOLBin, MELTS: Attack Path Link Drilldown, MELTS: 2025-2026 Attack Signal Overview |
| T1219 | Windows Remote Access Tool Detected, MELTS: 2025-2026 Attack Signal Overview, RMM: Post-Compromise Remote Access Activity |
| T1486 | Cyble Vision Alerts IOC'S |
| T1496 | Cisco Cloud Security - Crypto Miner User-Agent Detected |
| T1505 | Apache - Unexpected Post Requests |
| T1530 | MELTS: 2025-2026 Attack Signal Overview |
| T1537 | ApexOne - Top sources with alerts |
| T1547.001 | Sysmon Executable File Created or Detected |
| T1552.005 | Web-to-Cloud: Attack Path Link Analysis, Web-to-Cloud: Correlated Attack Timeline, Web-to-Cloud: MITRE Stage Breakdown |
| T1555.003 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), +4 more |
| T1562 | McAfee ePO - Firewall disabled |
| T1562.001 | Hunting: GOAD/Apex Caldera Sandcat Agent Activity |
| T1566 | MELTS: Attack Path Link Drilldown, MELTS: 2025-2026 Attack Signal Overview, MELTS: 2025-2026 Attack Timeline |
| T1567 | ApexOne - Top sources with alerts, Discord download invoked from cmd line, +2 more |
| T1567.002 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), +2 more |
| T1568.002 | Sysmon DNS Query to Known C2 Framework Domains, C2: Unique DNS Domains KPI |
| T1572 | Linux SSH Tunneling Detected, Ubiquiti - connection to non-corporate DNS server |
| T1573 | Linux Encrypted Channel C2 Communication, Sysmon C2 Beacon - Periodic Outbound HTTPS, C2 Beaconing Detection (Periodic Connection Analysis) |
| T1573.002 | Linux Encrypted Channel C2 Communication |
| T1585 | CybleVision Alerts Telegram Mentions |
| T1595 | Cyble Vision Alerts IOC'S |
| T1598 | CybleVision Alerts Telegram Mentions |

### Exfiltration (55 techniques)

| Technique | Rules |
|-----------|-------|
| T1005 | CybleVision Alerts Darkweb Marketplace Alerts, CybleVision Alerts Stealer Logs, Deimos Component Execution |
| T1012 | BLUELIGHT APT37 Kill Chain Correlation |
| T1020 | Cisco Cloud Security - 'Blocked' User-Agents., Deimos Component Execution |
| T1027 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1041 | Caldera - Exfiltration of Staged Data over C2 Channel (Linux), Caldera - Exfiltration over C2 Channel via PowerShell (Windows), +22 more |
| T1048 | Linux Exfiltration Over Alternative Protocol, Unusually Large HTTP Response (Data Exfiltration), +7 more |
| T1048.003 | Sysmon DNS Data Exfiltration, Sysmon DNS Tunneling via Network Connection, +4 more |
| T1055 | ApexOne - Top sources with alerts |
| T1056.001 | BLUELIGHT: Attack Path (per Host) |
| T1059 | Deimos Component Execution, 2025-2026: Compromised Machines and Data, +2 more |
| T1059.001 | MELTS: 2025-2026 Attack Signal Overview |
| T1068 | ApexOne - Top sources with alerts |
| T1071 | ApexOne - Top sources with alerts, Linux Unusual Outbound Connection Frequency, MELTS: 2025-2026 Attack Timeline |
| T1071.001 | Cisco Cloud Security - Crypto Miner User-Agent Detected, BLUELIGHT APT37 Kill Chain Correlation, +14 more |
| T1071.004 | Sysmon DNS Data Exfiltration, Sysmon DNS Tunneling via Network Connection, +4 more |
| T1074.001 | Windows Data Staging for Exfiltration, Linux Data Staging and Exfiltration Indicators |
| T1078 | Bitglass - Applications used, Cyble Vision Alerts Darkweb Data Breaches |
| T1082 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host) |
| T1083 | Cyble Vision Alerts Bitbucket, Cyble Vision Alerts Cloud Storage, +3 more |
| T1095 | ApexOne - Top sources with alerts |
| T1102 | Discord download invoked from cmd line, Discord download invoked from cmd line (ASIM Version) |
| T1105 | BLUELIGHT APT37 Kill Chain Correlation |
| T1112 | ApexOne - Top sources with alerts |
| T1113 | BLUELIGHT APT37 Kill Chain Correlation |
| T1119 | OCI API Call Burst by User |
| T1189 | ApexOne - Top sources with alerts, CybleVision Alerts Stealer Logs, +4 more |
| T1190 | Web-to-Cloud: Attack Path Link Analysis, Web-to-Cloud: Correlated Attack Timeline, Web-to-Cloud: MITRE Stage Breakdown |
| T1197 | FLF: BITS Exfiltration Hunt |
| T1202 | ApexOne - Top sources with alerts |
| T1203 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), BLUELIGHT: Kill Chain Timeline |
| T1204 | ApexOne - Top sources with alerts, Discord download invoked from cmd line, Discord download invoked from cmd line (ASIM Version) |
| T1218 | MELTS: Attack Path Link Drilldown, MELTS: 2025-2026 Attack Signal Overview |
| T1219 | MELTS: 2025-2026 Attack Signal Overview |
| T1486 | Cyble Vision Alerts Darkweb Ransomware Leak |
| T1496 | Cisco Cloud Security - Crypto Miner User-Agent Detected |
| T1528 | 2025-2026: Compromised Machines and Data |
| T1530 | Cyble Vision Alerts Darkweb Data Breaches, 2025-2026: Exfiltration After Initial Access, +4 more |
| T1537 | Caldera/OpenAEV - Transfer Data to Cloud Account via OCI Object Storage, Cloud Guard Problem: Bucket Public Read, +9 more |
| T1552 | Cyble Vision Alerts Bitbucket, Cyble Vision Alerts Compromised Files, Cyble Vision Alerts Postman API Exposure Detection |
| T1552.005 | Web-to-Cloud: Attack Path Link Analysis, Web-to-Cloud: Correlated Attack Timeline, Web-to-Cloud: MITRE Stage Breakdown |
| T1555 | CybleVision Alerts Darkweb Marketplace Alerts, CybleVision Alerts Stealer Logs |
| T1555.003 | BLUELIGHT APT37 Kill Chain Correlation, BLUELIGHT: Attack Path (per Host), +2 more |
| T1560.001 | Linux Archive Data Collected for Exfiltration, Linux Data Staging and Exfiltration Indicators |
| T1566 | 2025-2026: Compromised Machines and Data, MELTS: Attack Path Link Drilldown, +2 more |
| T1567 | Caldera - Exfiltration to Web Service from Windows Endpoint, Caldera - Exfiltration to Web Service via curl (Linux), +13 more |
| T1567.002 | BLUELIGHT RAT: Data Exfiltration via OneDrive/Graph API, BLUELIGHT APT37 Kill Chain Correlation, +3 more |
| T1572 | Ubiquiti - connection to non-corporate DNS server |
| T1580 | Web-to-Cloud: OCI Audit Cloud Abuse |
| T1585 | CybleVision Alerts Cyber Crime Forum Alerts |
| T1589 | Cyble Vision Alerts Darkweb Data Breaches, CybleVision Alerts Cyber Crime Forum Alerts, +2 more |
| T1595 | Cyble Vision Alerts Postman API Exposure Detection |
| T1598 | CybleVision Alerts Cyber Crime Forum Alerts |
| T1610 | Cyble Vision Alerts Docker |
| T1646 | CybleVision Alerts Cyber Crime Forum Alerts, CybleVision Alerts Darkweb Marketplace Alerts |
| T1657 | Cyble Vision Alerts Darkweb Ransomware Leak |

### Impact (28 techniques)

| Technique | Rules |
|-----------|-------|
| T1036 | Potential re-named sdelete usage, Potential re-named sdelete usage (ASIM Version) |
| T1041 | Cisco Cloud Security - Crypto Miner User-Agent Detected |
| T1046 | Cyble Vision Alerts IOC'S |
| T1056.001 | APM: Suspicious JavaScript Execution Patterns |
| T1059.007 | APM: Suspicious JavaScript Execution Patterns, Browser Attack Frequency Analysis (SOC Application Logs) |
| T1071 | Cyble Vision Alerts IOC'S |
| T1071.001 | Cisco Cloud Security - Crypto Miner User-Agent Detected |
| T1133 | Apache - Multiple server errors from single IP, Cloudflare - Client errors, +9 more |
| T1189 | Browser Attack Frequency Analysis (SOC Application Logs) |
| T1190 | Apache - Multiple server errors from single IP, Cloudflare - Client errors, +10 more |
| T1485 | OCI Action: DeleteBucket, OCI Action: DeleteKey, +12 more |
| T1486 | Ransomware File Extension Indicators, Acronis - Multiple Endpoints Infected by Ransomware, +8 more |
| T1489 | OCI Action: DeleteInternetGateway, OCI Action: DeleteSubnet, +8 more |
| T1490 | OCI KMS Key Scheduled for Deletion, System Recovery Disabled via BCDEdit, +5 more |
| T1491 | Cyble Vision Alerts Hacktivism, Cyble Vision Alerts Website Defacement Content, +2 more |
| T1491.001 | Defacement via Desktop Wallpaper Change |
| T1496 | Cryptominer Deployment Indicators, Linux Cryptominer Activity Detected, +5 more |
| T1498 | Apache - Multiple server errors from single IP, Cloudflare - Client errors, +9 more |
| T1499 | GenAI Gateway: Denial of ML Service / Inference Flood (AML.T0029 / AML.T0046), Web Application Server Error Spike, +8 more |
| T1529 | System Shutdown or Reboot via shutdown.exe, OCI - Multiple instances terminated, +3 more |
| T1531 | Account Access Removal, OCI Action: DeleteGroup, +10 more |
| T1561 | Disk Wipe via Format Command |
| T1565 | Jira - Updated workflow schemes |
| T1585 | Cyble Vision Alerts Hacktivism |
| T1595 | Cyble Vision Alerts Hacktivism, Cyble Vision Alerts IOC'S |
| T1598 | Cyble Vision Alerts Website Defacement Keyword |
| T1600 | OCI KMS Key Version Disabled, OCI Vault Secret Version Deprecated |
| T1657 | Cyble Vision Alerts Darkweb Ransomware Leak |

## MITRE ATLAS Coverage (AI / ML Systems)

Adversarial threats against AI/LLM systems, mapped to **MITRE ATLAS** (AML.T* techniques). **10 ATLAS techniques** across **10 tactics**, detected on `SOC Application Logs` and the `SOC GenAI Gateway Logs` source.

| ATLAS Technique | Detections |
|-----------------|------------|
| AML.T0010 | GenAI Gateway: ML Supply-Chain / Model Provenance Failure (AML.T0010) |
| AML.T0024 | GenAI Gateway: Bulk Inference Exfiltration / Model Extraction (AML.T0024), ATLAS: Bulk Extraction via ML Inference API (AML.T0024 / AML.T0040) |
| AML.T0029 | GenAI Gateway: Denial of ML Service / Inference Flood (AML.T0029 / AML.T0046), ATLAS: Denial of ML Service / Inference Flood (AML.T0029 / AML.T0046) |
| AML.T0040 | GenAI Gateway: Unauthorized / Rejected Inference Access (AML.T0040), ATLAS: Bulk Extraction via ML Inference API (AML.T0024 / AML.T0040), ATLAS: Unauthorized ML Inference API Access (AML.T0040) |
| AML.T0043 | GenAI Gateway: Adversarial / Obfuscated Guardrail Evasion (AML.T0043), ATLAS: Adversarial / Obfuscated Input to ML Endpoint (AML.T0043) |
| AML.T0044 | GenAI Gateway: Full Model Access / Weight Export (AML.T0044) |
| AML.T0046 | GenAI Gateway: Denial of ML Service / Inference Flood (AML.T0029 / AML.T0046), ATLAS: Denial of ML Service / Inference Flood (AML.T0029 / AML.T0046) |
| AML.T0051 | GenAI Gateway: LLM Prompt Injection Detected (AML.T0051), ATLAS: LLM Prompt Injection in Application Request (AML.T0051) |
| AML.T0054 | GenAI Gateway: LLM Jailbreak Detected (AML.T0054), ATLAS: LLM Jailbreak Attempt Against Application (AML.T0054) |
| AML.T0057 | GenAI Gateway: LLM Sensitive-Information Disclosure (AML.T0057), ATLAS: LLM Sensitive-Information Disclosure Attempt (AML.T0057) |

## All Detection Rules

### OCI Cloud (148 rules)

| # | Title | Severity | MITRE | STIG |
|---|-------|----------|-------|------|
| 1 | APM: SQL Injection Attack in Request | 🔴 critical | T1190 | - |
| 2 | Cloud Guard Instance Security: High Severity Pivots | 🔴 critical | - | - |
| 3 | GenAI Gateway: Full Model Access / Weight Export (AML.T0044) | 🔴 critical | T1567 | - |
| 4 | GenAI Gateway: LLM Sensitive-Information Disclosure (AML.T0057) | 🔴 critical | - | - |
| 5 | GenAI Gateway: ML Supply-Chain / Model Provenance Failure (AML.T0010) | 🔴 critical | - | - |
| 6 | Insecure Deserialization Attack Detected | 🔴 critical | T1059, T1190 | - |
| 7 | OCI Audit Configuration Retention Reduced | 🔴 critical | T1562.008 | - |
| 8 | OCI Compartment Deleted | 🔴 critical | T1485 | AC-6 |
| 9 | OCI Database System Terminated | 🔴 critical | T1485 | CP-9 |
| 10 | OCI Federated Identity Provider Modified | 🔴 critical | T1606 | - |
| 11 | OCI KMS Key Scheduled for Deletion | 🔴 critical | T1490 | - |
| 12 | OCI Log Group Deleted | 🔴 critical | T1562.001 | AU-11 |
| 13 | OCI Policy Allows Manage All Resources | 🔴 critical | T1098 | - |
| 14 | WAF Command Injection Attack Blocked | 🔴 critical | T1059, T1190 | - |
| 15 | WAF Log4Shell (CVE-2021-44228) Attack Blocked | 🔴 critical | T1190, T1059 | - |
| 16 | WAF SQL Injection Attack Allowed Through | 🔴 critical | T1190, T1059.007 | - |
| 17 | WAF Server-Side Request Forgery Blocked | 🔴 critical | T1190, T1552.005 | - |
| 18 | WAF Server-Side Template Injection Blocked | 🔴 critical | T1059, T1190 | - |
| 19 | WAF Web Shell Upload Attempt Blocked | 🔴 critical | T1505.003, T1190 | - |
| 20 | Web Application Authentication Bypass | 🔴 critical | T1078, T1550 | - |
| 21 | Web Application Privilege Escalation | 🔴 critical | T1078 | - |
| 22 | Web Application Session Hijacking Indicators | 🔴 critical | T1539, T1550.004 | - |
| 23 | Cloud Guard Instance Security: Findings by Host | 🟠 high | - | - |
| 24 | Cloud Guard Instance Security: Findings by Pack Query | 🟠 high | - | - |
| 25 | Cloud Guard Problem: Audit Log Retention | 🟠 high | T1562.008 | - |
| 26 | Cloud Guard Problem: Bucket Public Read | 🟠 high | T1537 | - |
| 27 | Cloud Guard Problem: Bucket Public Write | 🟠 high | T1190 | - |
| 28 | Cloud Guard Problem: Group Has Too Many Admins | 🟠 high | T1098 | - |
| 29 | Cloud Guard Problem: IAM User API Key Old | 🟠 high | T1552.004 | - |
| 30 | Cloud Guard Problem: IAM User Console Password Old | 🟠 high | T1110 | - |
| 31 | Cloud Guard Problem: INSTANCE PUBLIC IP | 🟠 high | T1190 | - |
| 32 | Cloud Guard Problem: Instance Principals Enabled | 🟠 high | T1098.001 | - |
| 33 | Cloud Guard Problem: Policy Too Permissive | 🟠 high | T1098 | - |
| 34 | Cloud Guard Problem: VCN Flow Log Disabled | 🟠 high | T1562.008 | - |
| 35 | Cloud Guard Problem: VCN Security List Port RDP | 🟠 high | T1133 | - |
| 36 | Cloud Guard Problem: VCN Security List Port SSH | 🟠 high | T1133 | - |
| 37 | GenAI Gateway: Adversarial / Obfuscated Guardrail Evasion (AML.T0043) | 🟠 high | - | - |
| 38 | GenAI Gateway: LLM Jailbreak Detected (AML.T0054) | 🟠 high | - | - |
| 39 | GenAI Gateway: LLM Prompt Injection Detected (AML.T0051) | 🟠 high | - | - |
| 40 | Insecure Direct Object Reference Detected | 🟠 high | T1190 | - |
| 41 | Mass Assignment Attack Detected | 🟠 high | T1078 | - |
| 42 | OCI Audit Configuration Changed | 🟠 high | T1562.008 | AU-11 |
| 43 | OCI Autonomous Database Terminated | 🟠 high | T1485 | - |
| 44 | OCI Cross-Region Data Copy | 🟠 high | T1537 | SC-28 |
| 45 | OCI Customer Secret Key Created | 🟠 high | T1098.001 | IA-5 |
| 46 | OCI Dynamic Group Created with Broad Matching | 🟠 high | T1098 | - |
| 47 | OCI IAM Admin Policy Created with Manage All | 🟠 high | T1098 | - |
| 48 | OCI Identity Provider Created | 🟠 high | T1556.007 | IA-8 |
| 49 | OCI Instance Console Connection Created | 🟠 high | T1021 | AC-17 |
| 50 | OCI KMS Key Version Disabled | 🟠 high | T1600 | - |
| 51 | OCI Log Archival Policy Disabled | 🟠 high | T1562.008 | - |
| 52 | OCI MFA Fatigue Attack Indicators | 🟠 high | T1621 | - |
| 53 | OCI Network Firewall Policy Modified | 🟠 high | T1562.004 | SC-7 |
| 54 | OCI Network Load Balancer Deleted | 🟠 high | T1489 | - |
| 55 | OCI Object Storage Bucket Made Public | 🟠 high | T1537 | - |
| 56 | OCI Object Storage Pre-Authenticated Request Created | 🟠 high | T1567 | AC-3 |
| 57 | OCI Object Storage Replication Policy Created | 🟠 high | T1537 | - |
| 58 | OCI Password Spraying Attack | 🟠 high | T1110.003 | IA-2 |
| 59 | OCI Security List Allows All Protocols | 🟠 high | T1562.007 | SC-7 |
| 60 | OCI User Capabilities Escalation | 🟠 high | T1098 | - |
| 61 | OCI User MFA Not Enabled | 🟠 high | T1556 | IA-2 |
| 62 | OCI User Password Reset by Admin | 🟠 high | T1098 | IA-5 |
| 63 | OCI VCN Flow Log Disabled | 🟠 high | T1562.008 | - |
| 64 | OCI VCN Security List Open to World | 🟠 high | T1562.007 | - |
| 65 | OCI Vault Secret Deleted | 🟠 high | T1485 | SC-28 |
| 66 | OCI WAF Policy Deleted | 🟠 high | T1562.001 | - |
| 67 | Sensitive Data Endpoint Access | 🟠 high | T1005, T1552.001 | - |
| 68 | WAF Cross-Site Scripting Attack Blocked | 🟠 high | T1189 | - |
| 69 | WAF LDAP Injection Attack Blocked | 🟠 high | T1190 | - |
| 70 | WAF NoSQL Injection Attack Blocked | 🟠 high | T1190 | - |
| 71 | WAF Path Traversal Attack Blocked | 🟠 high | T1083, T1190 | - |
| 72 | WAF Protocol Attack Blocked | 🟠 high | T1190 | - |
| 73 | WAF SQL Injection Attack Blocked | 🟠 high | T1190, T1059.007 | - |
| 74 | WAF XML External Entity Attack Blocked | 🟠 high | T1190 | - |
| 75 | API Endpoint Unauthorized Access Attempts | 🟡 medium | T1190, T1078 | - |
| 76 | Caldera/OpenAEV - Exfiltration via OCI Object Storage Bulk Upload with New Bucket | 🟡 medium | T1567 | - |
| 77 | Caldera/OpenAEV - Transfer Data to Cloud Account via OCI Object Storage | 🟡 medium | T1537 | - |
| 78 | Cloud Guard Instance Security: Instance to Query Link View | 🟡 medium | - | - |
| 79 | Cloud Guard Instance Security: Pack Coverage | 🟡 medium | - | - |
| 80 | Cloud Guard Instance Security: Raw Result Detail | 🟡 medium | - | - |
| 81 | GenAI Gateway: Bulk Inference Exfiltration / Model Extraction (AML.T0024) | 🟡 medium | T1567 | - |
| 82 | GenAI Gateway: Denial of ML Service / Inference Flood (AML.T0029 / AML.T0046) | 🟡 medium | T1499 | - |
| 83 | GenAI Gateway: Unauthorized / Rejected Inference Access (AML.T0040) | 🟡 medium | - | - |
| 84 | OCI API Key Uploaded | 🟡 medium | T1098.001 | - |
| 85 | OCI Auth Token Created | 🟡 medium | T1528 | IA-5 |
| 86 | OCI Bastion Session Created | 🟡 medium | T1021 | AC-17 |
| 87 | OCI Boot Volume Backup Created by Non-Admin | 🟡 medium | T1537 | - |
| 88 | OCI Compute Instance Terminated | 🟡 medium | T1485 | - |
| 89 | OCI Console Login Failure | 🟡 medium | T1078 | - |
| 90 | OCI Console Login from Unusual IP | 🟡 medium | T1078 | - |
| 91 | OCI DRG Attachment Created | 🟡 medium | T1599 | - |
| 92 | OCI Database Backup Exported | 🟡 medium | T1537 | - |
| 93 | OCI Dynamic Group Created | 🟡 medium | T1098.001 | AC-6 |
| 94 | OCI IAM Policy Modified | 🟡 medium | T1098 | - |
| 95 | OCI Instance Metadata Service Accessed | 🟡 medium | T1552.005 | - |
| 96 | OCI Local Peering Gateway Created | 🟡 medium | T1599 | - |
| 97 | OCI Network Security Group Rule Added for All Protocols | 🟡 medium | T1562.004 | - |
| 98 | OCI Network Security Group Updated | 🟡 medium | T1562.007 | - |
| 99 | OCI Notification Subscription Created | 🟡 medium | T1114 | AU-12 |
| 100 | OCI Route Table Update | 🟡 medium | T1562.007 | - |
| 101 | OCI VCN Peering Connection Created | 🟡 medium | T1021 | SC-7 |
| 102 | OCI Vault Key Rotation Overdue | 🟡 medium | T1600 | SC-12 |
| 103 | OCI Vault Secret Version Deprecated | 🟡 medium | T1600 | - |
| 104 | OCI WAF Configuration Updated | 🟡 medium | T1562.007 | - |
| 105 | Suspicious or Empty User Agent Detected | 🟡 medium | T1595 | - |
| 106 | Unusually Large HTTP Response (Data Exfiltration) | 🟡 medium | T1041, T1048 | - |
| 107 | WAF CORS Bypass Attempt Blocked | 🟡 medium | T1189 | - |
| 108 | WAF Rate Limiting Triggered | 🟡 medium | T1110 | - |
| 109 | Web Application Brute Force Login Attempt | 🟡 medium | T1110.001, T1110.003 | - |
| 110 | Web Application Server Error Spike | 🟡 medium | T1499 | - |
| 111 | Web Vulnerability Scanner Detected | 🟡 medium | T1595.002 | - |
| 112 | OCI Cloud Infrastructure Discovery | 🔵 low | T1580 | AU-12 |
| 113 | OCI Cloud Shell Session Started | 🔵 low | T1059.004 | AU-12 |
| 114 | OCI Console Login from Suspicious IP Range | 🔵 low | T1078 | - |
| 115 | OCI Function Invoked | 🔵 low | T1648 | AU-12 |
| 116 | OCI Service Gateway Created | 🔵 low | T1599 | - |
| 117 | Suspicious HTTP Method Usage | 🔵 low | T1190 | - |
| 118 | Web Directory Enumeration Detected | 🔵 low | T1083, T1595.002 | - |
| 119 | OCI Action: AddUserToGroup | ⚪ informational | T1098.001 | - |
| 120 | OCI Action: AttachInternetGateway | ⚪ informational | T1583 | - |
| 121 | OCI Action: CreateBucket | ⚪ informational | T1530 | - |
| 122 | OCI Action: CreateGroup | ⚪ informational | T1136.003 | - |
| 123 | OCI Action: CreateInstance | ⚪ informational | T1583.003 | - |
| 124 | OCI Action: CreateInternetGateway | ⚪ informational | T1583 | - |
| 125 | OCI Action: CreateKey | ⚪ informational | T1553 | - |
| 126 | OCI Action: CreatePolicy | ⚪ informational | T1098 | - |
| 127 | OCI Action: CreateRouteTable | ⚪ informational | T1583 | - |
| 128 | OCI Action: CreateSecurityList | ⚪ informational | T1562.007 | - |
| 129 | OCI Action: CreateSubnet | ⚪ informational | T1583 | - |
| 130 | OCI Action: CreateUser | ⚪ informational | T1136.003 | - |
| 131 | OCI Action: CreateVcn | ⚪ informational | T1583 | - |
| 132 | OCI Action: DeleteBucket | ⚪ informational | T1485 | - |
| 133 | OCI Action: DeleteGroup | ⚪ informational | T1531 | - |
| 134 | OCI Action: DeleteInternetGateway | ⚪ informational | T1489 | - |
| 135 | OCI Action: DeleteKey | ⚪ informational | T1485 | - |
| 136 | OCI Action: DeletePolicy | ⚪ informational | T1531 | - |
| 137 | OCI Action: DeleteSubnet | ⚪ informational | T1489 | - |
| 138 | OCI Action: DeleteUser | ⚪ informational | T1531 | - |
| 139 | OCI Action: DeleteVcn | ⚪ informational | T1489 | - |
| 140 | OCI Action: DetachInternetGateway | ⚪ informational | T1489 | - |
| 141 | OCI Action: RemoveUserFromGroup | ⚪ informational | T1531 | - |
| 142 | OCI Action: StartInstance | ⚪ informational | T1204 | - |
| 143 | OCI Action: StopInstance | ⚪ informational | T1489 | - |
| 144 | OCI Action: TerminateInstance | ⚪ informational | T1485 | - |
| 145 | OCI Action: UpdateBucket | ⚪ informational | T1562.007 | - |
| 146 | OCI Action: UpdatePolicy | ⚪ informational | T1098 | - |
| 147 | OCI Action: UpdateRouteTable | ⚪ informational | T1562.007 | - |
| 148 | OCI Action: UpdateSecurityList | ⚪ informational | T1562.007 | - |

### Linux (81 rules)

| # | Title | Severity | MITRE | ART Tests | STIG |
|---|-------|----------|-------|-----------|------|
| 1 | Linux Bind Shell Listener | 🔴 critical | T1059.004 | 17 | - |
| 2 | Linux Boopkit eBPF Rootkit Activity | 🔴 critical | T1014, T1059.004, T1095 | - | - |
| 3 | Linux Container Escape Attempt | 🔴 critical | T1611 | 3 | - |
| 4 | Linux Kernel Module Loaded from Temp Directory | 🔴 critical | T1547.006 | 4 | - |
| 5 | Linux Password File Direct Modification | 🔴 critical | T1136.001 | 10 | - |
| 6 | Linux Process Execution from /dev/shm | 🔴 critical | T1059 | 1 | - |
| 7 | Linux Reverse Shell Detected | 🔴 critical | T1059 | 1 | - |
| 8 | Linux Web Shell File Creation | 🔴 critical | T1505.003 | 1 | - |
| 9 | SSRF to Cloud Instance Metadata Service (Linux) | 🔴 critical | T1552.005, T1190 | - | - |
| 10 | Suspicious Usage of insmod | 🔴 critical | T1204 | 14 | - |
| 11 | Suspicious Usage of shadow | 🔴 critical | T1204 | 14 | - |
| 12 | Web Server Process Spawning Shell with Injection Characters (Linux) | 🔴 critical | T1059, T1190 | 1 | - |
| 13 | Caldera - Exfiltration of Staged Data over C2 Channel (Linux) | 🟠 high | T1041 | - | - |
| 14 | Caldera - Exfiltration to Web Service via curl (Linux) | 🟠 high | T1567 | - | - |
| 15 | Caldera - Lateral Tool Transfer via scp/rsync (Linux) | 🟠 high | T1570 | - | - |
| 16 | Caldera - SMB Lateral Movement via Impacket from Linux | 🟠 high | T1021.002 | - | - |
| 17 | Caldera - WinRM Lateral Movement via Evil-WinRM from Linux | 🟠 high | T1021.006 | - | - |
| 18 | Linux Archive Data Collected for Exfiltration | 🟠 high | T1560.001 | 12 | - |
| 19 | Linux Cryptominer Activity Detected | 🟠 high | T1496 | 2 | - |
| 20 | Linux DNS Tunneling Detected | 🟠 high | T1071.004 | 4 | - |
| 21 | Linux Encrypted Channel C2 Communication | 🟠 high | T1573, T1573.002 | 1 | - |
| 22 | Linux Exfiltration Over Alternative Protocol | 🟠 high | T1048 | 4 | - |
| 23 | Linux LD_PRELOAD Library Hijacking | 🟠 high | T1574.006 | 3 | - |
| 24 | Linux Log File Tampering | 🟠 high | T1070.002 | 20 | - |
| 25 | Linux Network Service Scanning | 🟠 high | T1046 | 12 | - |
| 26 | Linux Post-Exploitation Enumeration Script | 🟠 high | T1082 | 40 | - |
| 27 | Linux Process Injection via Ptrace | 🟠 high | T1055.008 | 13 | - |
| 28 | Linux Process Memory Access via /proc | 🟠 high | T1003.007 | 4 | - |
| 29 | Linux Proxy and Tunneling Tool Detected | 🟠 high | T1090, T1090.001 | 7 | - |
| 30 | Linux SSH Authorized Keys Modified | 🟠 high | T1098.004 | 1 | - |
| 31 | Linux SSH Tunneling Detected | 🟠 high | T1572 | 7 | - |
| 32 | Linux Sensitive Data Collection from Local System | 🟠 high | T1005 | 3 | - |
| 33 | Linux Setuid Binary Creation | 🟠 high | T1548.001 | 10 | - |
| 34 | Linux Sudoers File Modification | 🟠 high | T1548.003 | 6 | - |
| 35 | Linux Suspicious Cron Job Content | 🟠 high | T1053.003 | 4 | - |
| 36 | Linux Suspicious Download to /tmp | 🟠 high | T1105 | 39 | - |
| 37 | Linux Suspicious Network Traffic Redirect | 🟠 high | T1557 | 1 | - |
| 38 | Suspicious Usage of chmod | 🟠 high | T1204 | 14 | - |
| 39 | Suspicious Usage of curl | 🟠 high | T1204 | 14 | - |
| 40 | Suspicious Usage of dd | 🟠 high | T1204 | 14 | - |
| 41 | Suspicious Usage of gdb | 🟠 high | T1204 | 14 | - |
| 42 | Suspicious Usage of modprobe | 🟠 high | T1204 | 14 | - |
| 43 | Suspicious Usage of nc | 🟠 high | T1204 | 14 | - |
| 44 | Suspicious Usage of ncat | 🟠 high | T1204 | 14 | - |
| 45 | Suspicious Usage of netcat | 🟠 high | T1204 | 14 | - |
| 46 | Suspicious Usage of nmap | 🟠 high | T1204 | 14 | - |
| 47 | Suspicious Usage of passwd | 🟠 high | T1204 | 14 | - |
| 48 | Suspicious Usage of rmmod | 🟠 high | T1204 | 14 | - |
| 49 | Suspicious Usage of socat | 🟠 high | T1204 | 14 | - |
| 50 | Suspicious Usage of wget | 🟠 high | T1204 | 14 | - |
| 51 | Caldera - Credential Search in Files via grep (Linux) | 🟡 medium | T1552, T1552.001 | - | - |
| 52 | Caldera - Data Collection from Network Shared Drive (Linux) | 🟡 medium | T1039 | - | - |
| 53 | Caldera - Document and Data File Collection from Linux Host | 🟡 medium | T1005 | - | - |
| 54 | Caldera - Local Data Staging in Writable Directories (Linux) | 🟡 medium | T1074, T1074.001 | - | - |
| 55 | Linux At Job Scheduled | 🟡 medium | T1053.002 | 3 | - |
| 56 | Linux Crontab Modification | 🟡 medium | T1053.003 | 4 | - |
| 57 | Linux Hidden File or Directory Creation in Suspicious Location | 🟡 medium | T1564.001 | 10 | - |
| 58 | Linux History File Cleared | 🟡 medium | T1070.003 | 14 | - |
| 59 | Linux Hosts File Modification | 🟡 medium | T1565.001 | - | - |
| 60 | Linux Shell Profile Persistence | 🟡 medium | T1546.004 | 7 | - |
| 61 | Linux Systemd Service Persistence | 🟡 medium | T1543.002 | 3 | - |
| 62 | Suspicious Usage of base64 | 🟡 medium | T1204 | 14 | - |
| 63 | Suspicious Usage of chown | 🟡 medium | T1204 | 14 | - |
| 64 | Suspicious Usage of id | 🟡 medium | T1204 | 14 | - |
| 65 | Suspicious Usage of lua | 🟡 medium | T1204 | 14 | - |
| 66 | Suspicious Usage of perl | 🟡 medium | T1204 | 14 | - |
| 67 | Suspicious Usage of python | 🟡 medium | T1204 | 14 | - |
| 68 | Suspicious Usage of ruby | 🟡 medium | T1204 | 14 | - |
| 69 | Suspicious Usage of strace | 🟡 medium | T1204 | 14 | - |
| 70 | Suspicious Usage of tcpdump | 🟡 medium | T1204 | 14 | - |
| 71 | Suspicious Usage of tshark | 🟡 medium | T1204 | 14 | - |
| 72 | Suspicious Usage of whoami | 🟡 medium | T1204 | 14 | - |
| 73 | Suspicious Usage of wireshark | 🟡 medium | T1204 | 14 | - |
| 74 | Caldera - System Information Discovery via Native Linux Commands | 🔵 low | T1082 | - | - |
| 75 | Caldera - System Network Configuration Discovery (Linux) | 🔵 low | T1016 | - | - |
| 76 | Caldera - System Network Connections Discovery (Linux) | 🔵 low | T1049 | - | - |
| 77 | Caldera - System Owner and Identity Discovery via id/whoami (Linux) | 🔵 low | T1033 | - | - |
| 78 | Linux External Remote Service Abuse | 🔵 low | T1133 | 1 | - |
| 79 | Linux SSH Failed Login | 🔵 low | T1110.001 | 8 | - |
| 80 | Linux Sudo Usage | 🔵 low | T1548.003 | 6 | - |
| 81 | Linux System Owner and User Discovery | 🔵 low | T1033 | 7 | - |

### Windows (316 rules)

| # | Title | Severity | MITRE | ART Tests | STIG |
|---|-------|----------|-------|-----------|------|
| 1 | ADCS ESC1: Subject Alternative Name Abuse via Certipy/Certify | 🔴 critical | T1649 | - | - |
| 2 | ADCS ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 Flag Enabled via Certutil | 🔴 critical | T1649 | - | - |
| 3 | ADCS ESC8: NTLM Relay to Certificate Web Enrollment | 🔴 critical | T1649, T1557.001 | - | - |
| 4 | Accessibility Features Backdoor | 🔴 critical | T1546.008 | 10 | - |
| 5 | AdminSDHolder ACL Modification for Persistence | 🔴 critical | T1098 | - | - |
| 6 | AppInit DLLs Persistence | 🔴 critical | T1546.010 | 1 | - |
| 7 | BLUELIGHT RAT: Browser Credential Memory Access | 🔴 critical | T1555.003 | - | - |
| 8 | BLUELIGHT RAT: YARA Chrome/Edge Cookie Theft (APT_MAL_Win_BlueLight_B) | 🔴 critical | T1539, T1555.003, T1114 | - | - |
| 9 | BLUELIGHT RAT: YARA Google App C2 Communication (APT_MAL_Win_BlueLight_B) | 🔴 critical | T1071.001, T1102 | - | - |
| 10 | BLUELIGHT RAT: YARA PDB Path Indicators (APT_MAL_Win_BlueLight) | 🔴 critical | T1204.002 | - | - |
| 11 | BLUELIGHT RAT: YARA System Reconnaissance JSON (APT_MAL_Win_BlueLight) | 🔴 critical | T1082, T1016, T1057 | - | - |
| 12 | BloodHound AD Enumeration | 🔴 critical | T1087.002 | 24 | - |
| 13 | Caldera - LSASS Memory Dump via ProcDump or Task Manager (Caldera Emulation) | 🔴 critical | T1003, T1003.001 | - | - |
| 14 | Certifried (CVE-2022-26923): Machine Account dNSHostName Abuse | 🔴 critical | T1649, T1098 | - | - |
| 15 | ClickFix Fake CAPTCHA PowerShell Execution | 🔴 critical | T1204, T1059.001 | - | - |
| 16 | Credential Dumping via Comsvcs with Rundll32 | 🔴 critical | T1003.001 | 14 | - |
| 17 | DCShadow Rogue Domain Controller Registration | 🔴 critical | T1207 | - | - |
| 18 | DCSync Attack via Replication Request | 🔴 critical | T1003.006 | 2 | - |
| 19 | DCSync Enablement: Replication Rights Granted via Directory Change (5136) | 🔴 critical | T1098, T1003.006 | - | - |
| 20 | DCSync: Directory Replication from Non-Domain Controller | 🔴 critical | T1003.006 | - | - |
| 21 | Disk Wipe via Format Command | 🔴 critical | T1561 | - | - |
| 22 | Forced Authentication via PetitPotam | 🔴 critical | T1187 | 3 | - |
| 23 | GPO Abuse via SharpGPOAbuse | 🔴 critical | T1484.001 | - | - |
| 24 | Golden Ticket: RC4 Encrypted TGT Request | 🔴 critical | T1558.001 | - | - |
| 25 | Kerberoasting: SPN Sweep - Multiple Service Tickets from Single Account | 🔴 critical | T1558.003 | - | - |
| 26 | Kerberos Ticket Export via Mimikatz | 🔴 critical | T1558 | 13 | - |
| 27 | Keylogging via PowerShell Get-Keystrokes | 🔴 critical | T1056.001 | 8 | - |
| 28 | LSASS Clone via ProcDump Evasion | 🔴 critical | T1003.001 | 14 | - |
| 29 | LSASS Memory Dump via Comsvcs DLL | 🔴 critical | T1003.001 | 14 | - |
| 30 | LaZagne Credential Harvester | 🔴 critical | T1555 | 8 | - |
| 31 | Mimikatz: Command and Module Indicators in Process Logs | 🔴 critical | T1003.001, T1003.006, T1558.003 | - | - |
| 32 | Mimikatz: Command and Module Indicators in Process Logs | 🔴 critical | T1003.001, T1003.006, T1558.003 | - | - |
| 33 | NTDS.dit Database Copy Attempt | 🔴 critical | T1003.003 | 11 | - |
| 34 | Named Pipe Impersonation via PowerShell | 🔴 critical | T1134.001 | 5 | - |
| 35 | Pass-the-Ticket via Rubeus | 🔴 critical | T1550.003 | 2 | - |
| 36 | Potato Privilege Escalation Tool | 🔴 critical | T1134.001 | 5 | - |
| 37 | PrintNightmare Exploitation Attempt | 🔴 critical | T1068 | - | - |
| 38 | Process Doppelganging via TxF | 🔴 critical | T1055.013 | 13 | - |
| 39 | RBCD: msDS-AllowedToActOnBehalfOfOtherIdentity Modified (Event 5136) | 🔴 critical | T1098 | - | - |
| 40 | Ransomware File Extension Indicators | 🔴 critical | T1486 | 10 | - |
| 41 | Reflective DLL Loading Indicators | 🔴 critical | T1620 | 1 | - |
| 42 | SID History Added or Failed (Events 4765/4766) | 🔴 critical | T1134.005 | - | - |
| 43 | SID History Injection via mimikatz | 🔴 critical | T1134.005 | - | - |
| 44 | SSRF to Cloud Metadata Endpoint (169.254.169.254) | 🔴 critical | T1552.005, T1190 | - | - |
| 45 | Security Support Provider DLL Persistence | 🔴 critical | T1547.005 | 2 | - |
| 46 | Shadow Credentials Attack via Whisker | 🔴 critical | T1556 | 5 | - |
| 47 | Shadow Credentials: msDS-KeyCredentialLink Modified (Event 5136) | 🔴 critical | T1556, T1098 | - | - |
| 48 | Silver Ticket: Forged Kerberos Service Ticket | 🔴 critical | T1558.002 | - | - |
| 49 | Skeleton Key Domain Backdoor via mimikatz | 🔴 critical | T1556.001 | - | - |
| 50 | Sysmon Cobalt Strike C2 Network Indicators | 🔴 critical | T1071.001, T1095 | 7 | - |
| 51 | Sysmon Cobalt Strike Named Pipe | 🔴 critical | T1071, T1055 | 14 | - |
| 52 | Sysmon Configuration Tampering | 🔴 critical | T1562.001 | 59 | - |
| 53 | Sysmon Mimikatz Named Pipe | 🔴 critical | T1003.001, T1134 | 27 | - |
| 54 | Sysmon Mimikatz Network Activity | 🔴 critical | T1003.001, T1558.003 | 21 | - |
| 55 | Sysmon Suspicious Named Pipe Pattern | 🔴 critical | T1071, T1059 | 2 | - |
| 56 | System Recovery Disabled via BCDEdit | 🔴 critical | T1490 | 13 | - |
| 57 | Volume Shadow Copy Deletion via WMIC | 🔴 critical | T1490 | 13 | - |
| 58 | Web Server Process Spawning Command Shell | 🔴 critical | T1059, T1059.001, T1190 | 1 | - |
| 59 | Windows Access Token Manipulation | 🔴 critical | T1134 | 13 | - |
| 60 | Windows Boot Configuration Modified | 🔴 critical | T1490 | 13 | - |
| 61 | Windows Credential Dumping via Procdump | 🔴 critical | T1003.001 | 14 | - |
| 62 | Windows Credential Dumping via Secretsdump | 🔴 critical | T1003 | 7 | - |
| 63 | Windows Defender Real-Time Protection Disabled | 🔴 critical | T1562.001 | 59 | - |
| 64 | Windows Kerberoasting Attack | 🔴 critical | T1558.003 | 7 | - |
| 65 | Windows Keylogger Indicators | 🔴 critical | T1056.001 | 8 | - |
| 66 | Windows LSASS Memory Access | 🔴 critical | T1003.001 | 14 | - |
| 67 | Windows Mimikatz Execution Patterns | 🔴 critical | T1003.001 | 14 | - |
| 68 | Windows NTDS.dit Database Extraction | 🔴 critical | T1003.003 | 11 | - |
| 69 | Windows Pass-the-Hash Attack Indicators | 🔴 critical | T1550.002 | 3 | - |
| 70 | Windows Privileged Group Membership Changed | 🔴 critical | T1098 | - | - |
| 71 | Windows Process Hollowing Indicators | 🔴 critical | T1055.012 | 4 | - |
| 72 | Windows Security or System Event Log Cleared | 🔴 critical | T1070.001 | - | - |
| 73 | Windows Shadow Copy Deletion | 🔴 critical | T1490 | 13 | - |
| 74 | Windows Spearphishing Attachment Execution | 🔴 critical | T1566.001, T1204.002 | 15 | - |
| 75 | Zerologon (CVE-2020-1472) Netlogon Exploitation | 🔴 critical | T1068, T1210 | - | - |
| 76 | ntlmrelayx NTLM Relay Execution Indicators | 🔴 critical | T1557.001 | - | - |
| 77 | AD Enumeration via ADFind | 🟠 high | T1087.002 | 24 | - |
| 78 | ADCS ESC4: Certificate Template ACL Modification via Certipy | 🟠 high | T1649 | - | - |
| 79 | AMSI Bypass via PowerShell Reflection | 🟠 high | T1562.001 | 59 | - |
| 80 | AS-REP Roasting via Rubeus | 🟠 high | T1558.004 | 3 | - |
| 81 | Account Access Removal | 🟠 high | T1531 | 8 | - |
| 82 | Active Setup Persistence | 🟠 high | T1547.014 | 3 | - |
| 83 | Alternate Data Stream Execution | 🟠 high | T1564.004 | 5 | - |
| 84 | AppLocker Policy Bypass via MSHTML | 🟠 high | T1218.005 | 10 | - |
| 85 | BLUELIGHT RAT: Browser Spawning Suspicious Child Process | 🟠 high | T1203 | - | - |
| 86 | BLUELIGHT RAT: Data Exfiltration via OneDrive/Graph API | 🟠 high | T1567.002 | - | - |
| 87 | BLUELIGHT RAT: Executable Download via Graph API | 🟠 high | T1105 | - | - |
| 88 | BLUELIGHT RAT: Obfuscated Script Execution | 🟠 high | T1027 | - | - |
| 89 | BLUELIGHT RAT: Periodic Screen Capture | 🟠 high | T1113 | - | - |
| 90 | BLUELIGHT RAT: WMI System Enumeration from Browser Child | 🟠 high | T1082 | - | - |
| 91 | BLUELIGHT RAT: YARA Keylogger Component (APT_MAL_Win_BlueLight_B) | 🟠 high | T1056.001 | - | - |
| 92 | Boot Configuration Change for Persistence | 🟠 high | T1542 | 1 | - |
| 93 | Browser Credential Store Access | 🟠 high | T1555.003 | 17 | - |
| 94 | Brute Force: Failed Logon Spike per Account | 🟠 high | T1110.001, T1110.003 | - | - |
| 95 | CMD: Suspicious Command Execution (Real Windows Security Events) | 🟠 high | T1059.003 | 1 | - |
| 96 | CMSTP UAC Bypass | 🟠 high | T1218.003 | 2 | - |
| 97 | COM Object Hijacking via Registry | 🟠 high | T1546.015 | 4 | - |
| 98 | Caldera - Exfiltration over C2 Channel via PowerShell (Windows) | 🟠 high | T1041 | - | - |
| 99 | Caldera - Exfiltration to Web Service from Windows Endpoint | 🟠 high | T1567 | - | - |
| 100 | Coercer Multi-Protocol Authentication Coercion | 🟠 high | T1187 | - | - |
| 101 | Computer Account Creation for Delegation Abuse (MachineAccountQuota) | 🟠 high | T1136.002, T1098 | - | - |
| 102 | Constrained Delegation S4U2Proxy Abuse via Rubeus | 🟠 high | T1558.003 | - | - |
| 103 | Credential Access via Certutil Certificate Export | 🟠 high | T1649 | 1 | - |
| 104 | Credential Dumping via Windows Task Manager | 🟠 high | T1003.001 | 14 | - |
| 105 | Cryptominer Deployment Indicators | 🟠 high | T1496 | 2 | - |
| 106 | DCOM Lateral Movement via MMC20 | 🟠 high | T1021.003 | 2 | - |
| 107 | DFSCoerce MS-DFSNM Authentication Coercion | 🟠 high | T1187 | - | - |
| 108 | DLL Execution via Rundll32 from User Path | 🟠 high | T1218.011 | 16 | - |
| 109 | DLL Hijacking via Service Registry Permission | 🟠 high | T1574.011 | 2 | - |
| 110 | DPAPI Master Key Extraction | 🟠 high | T1555 | 8 | - |
| 111 | DSRM Admin Logon Behavior Enabled for Persistence | 🟠 high | T1556 | - | - |
| 112 | Disable Windows Firewall via Netsh | 🟠 high | T1562.004 | 25 | - |
| 113 | ETW Provider Disabled | 🟠 high | T1562.002 | 10 | - |
| 114 | Email Collection via PowerShell | 🟠 high | T1114 | 3 | - |
| 115 | GPO Scheduled Task Written to SYSVOL | 🟠 high | T1484.001, T1053.005 | - | - |
| 116 | Group Policy Preferences Password Extraction | 🟠 high | T1552.006 | 2 | - |
| 117 | Image File Execution Options Debugger | 🟠 high | T1546.012 | 3 | - |
| 118 | Impacket atexec Remote Scheduled Task Execution | 🟠 high | T1053.005 | - | - |
| 119 | Impacket wmiexec Remote Command Execution | 🟠 high | T1047 | - | - |
| 120 | InstallUtil Application Whitelisting Bypass | 🟠 high | T1218.004 | 8 | - |
| 121 | Internal Monologue NTLM Hash Theft | 🟠 high | T1003 | 7 | - |
| 122 | Kerberoasting: RC4 Encrypted Service Ticket Request | 🟠 high | T1558.003 | - | - |
| 123 | LAPS Clear-Text Local Admin Password Read Attempt | 🟠 high | T1555 | - | - |
| 124 | LSA Secrets Registry Extraction | 🟠 high | T1003.004 | 2 | - |
| 125 | Lateral Movement: Account Authenticating from Multiple Sources | 🟠 high | T1021.002, T1021.006 | - | - |
| 126 | MSBuild Execution from Non-Standard Location | 🟠 high | T1127.001 | 2 | - |
| 127 | MSHTA JavaScript Execution | 🟠 high | T1218.005 | 10 | - |
| 128 | Masquerading System Binary in Non-Standard Path | 🟠 high | T1036.005 | 3 | - |
| 129 | NPPSpy Credential Interception | 🟠 high | T1556 | 5 | - |
| 130 | Netsh Helper DLL Persistence | 🟠 high | T1546.007 | 1 | - |
| 131 | New Local Account Created via Net.exe | 🟠 high | T1136.001 | 10 | - |
| 132 | Overpass-the-Hash via Rubeus asktgt | 🟠 high | T1550.002 | - | - |
| 133 | Parent PID Spoofing | 🟠 high | T1134.004 | 5 | - |
| 134 | Pass-the-Cert / UnPAC-the-Hash via Certipy auth | 🟠 high | T1550.003, T1649 | - | - |
| 135 | Pass-the-Ticket: Excessive Explicit Credential Logons | 🟠 high | T1550.003 | - | - |
| 136 | Port Monitor DLL Persistence | 🟠 high | T1547.010 | 1 | - |
| 137 | PowerShell Script Block with Suspicious Keywords | 🟠 high | T1059.001 | 22 | - |
| 138 | PowerShell: Suspicious Command Execution (Real Windows Security Events) | 🟠 high | T1059.001, T1086 | - | - |
| 139 | Print Processor Persistence | 🟠 high | T1547.012 | 1 | - |
| 140 | PrinterBug / SpoolSample Authentication Coercion | 🟠 high | T1187 | - | - |
| 141 | Privilege Escalation: Sensitive Privileges Assigned to Non-Admin | 🟠 high | T1134, T1134.001 | - | - |
| 142 | Process Ghosting or Herpaderping | 🟠 high | T1055 | 13 | - |
| 143 | Process Injection via CreateRemoteThread | 🟠 high | T1055.001 | 2 | - |
| 144 | PsExec Service Installation | 🟠 high | T1021.002 | 4 | - |
| 145 | PsExec-style Remote Service Installation (Event 7045) | 🟠 high | T1569.002, T1021.002 | - | - |
| 146 | RBCD Configuration via PowerShell / PowerView | 🟠 high | T1098 | - | - |
| 147 | RDP Session Hijacking via tscon | 🟠 high | T1021.001 | 4 | - |
| 148 | Registry Run Key Modification via Reg.exe | 🟠 high | T1547.001 | 20 | - |
| 149 | Regsvcs or Regasm Execution for Code Bypass | 🟠 high | T1218.009 | 2 | - |
| 150 | Remote Service Creation via SC | 🟠 high | T1021.002 | 4 | - |
| 151 | Renamed System Binary Execution | 🟠 high | T1036.003 | 8 | - |
| 152 | Root Certificate Installation via Certutil | 🟠 high | T1553.004 | 7 | - |
| 153 | SAM Database Extraction via Reg Save | 🟠 high | T1003.002 | 8 | - |
| 154 | Screen Capture via PowerShell | 🟠 high | T1113 | 10 | - |
| 155 | Scripting Engine Spawning Network Utility | 🟠 high | T1059.005 | 3 | - |
| 156 | SeDebugPrivilege Abuse | 🟠 high | T1134 | 13 | - |
| 157 | Service Execution via sc.exe Create | 🟠 high | T1569.002 | 8 | - |
| 158 | Service Stop via Net Stop | 🟠 high | T1489 | 8 | - |
| 159 | SharpRDP Lateral Movement | 🟠 high | T1021.001 | 4 | - |
| 160 | Suspicious Scheduled Task Creation | 🟠 high | T1053.005 | 12 | - |
| 161 | SyncAppvPublishingServer Abuse | 🟠 high | T1218 | 16 | - |
| 162 | Sysmon C2 Beacon - Periodic Outbound HTTPS | 🟠 high | T1071.001, T1573 | 4 | - |
| 163 | Sysmon DNS Data Exfiltration | 🟠 high | T1048.003, T1071.004 | 12 | - |
| 164 | Sysmon DNS Query to Known C2 Framework Domains | 🟠 high | T1071.004, T1568.002 | 4 | - |
| 165 | Sysmon DNS Tunneling via Network Connection | 🟠 high | T1071.004, T1048.003 | 12 | - |
| 166 | Sysmon Kerberoasting Network Indicator | 🟠 high | T1558.003 | 7 | - |
| 167 | Sysmon Lateral Movement via SMB | 🟠 high | T1021.002, T1570 | 6 | - |
| 168 | Sysmon Lateral Movement via WinRM | 🟠 high | T1021.006, T1059.001 | 25 | - |
| 169 | Sysmon PsExec Named Pipe | 🟠 high | T1021.002, T1569.002 | 12 | - |
| 170 | Sysmon Suspicious Outbound Connection from LOLBin | 🟠 high | T1218, T1105 | 55 | - |
| 171 | Targeted AS-REP Roasting: DoNotRequirePreAuth Set | 🟠 high | T1558.004 | - | - |
| 172 | Targeted Kerberoasting: SPN Set on User Account | 🟠 high | T1558.003 | - | - |
| 173 | Template Injection via Microsoft Office | 🟠 high | T1221 | 1 | - |
| 174 | Time Provider DLL Persistence | 🟠 high | T1547.003 | 2 | - |
| 175 | Timeroasting: Computer Account Hash Harvest via NTP | 🟠 high | T1558 | - | - |
| 176 | Timestomping via PowerShell | 🟠 high | T1070.006 | 10 | - |
| 177 | Token Impersonation via Incognito | 🟠 high | T1134 | 13 | - |
| 178 | UAC Bypass via ComputerDefaults | 🟠 high | T1548.002 | 27 | - |
| 179 | UAC Bypass via Eventvwr | 🟠 high | T1548.002 | 27 | - |
| 180 | UAC Bypass via Fodhelper | 🟠 high | T1548.002 | 27 | - |
| 181 | Unconstrained Delegation TGT Capture via Rubeus monitor | 🟠 high | T1558 | - | - |
| 182 | VBA Macro Spawning Suspicious Child Process | 🟠 high | T1204.002 | 13 | - |
| 183 | WMI Event Subscription Persistence | 🟠 high | T1546.003 | 3 | - |
| 184 | WMI Process Execution via Wmic | 🟠 high | T1047 | 10 | - |
| 185 | Windows AMSI Bypass Attempt | 🟠 high | T1562.001 | 59 | - |
| 186 | Windows Administrative Share Access Spike | 🟠 high | T1021.002, T1039 | - | - |
| 187 | Windows Audit Policy Changed | 🟠 high | T1562.002 | - | - |
| 188 | Windows BITS Job Abuse for Persistence | 🟠 high | T1197 | 4 | - |
| 189 | Windows Backup Deletion via wbadmin | 🟠 high | T1490 | 13 | - |
| 190 | Windows Certutil Download or Decode | 🟠 high | T1140, T1105 | 50 | - |
| 191 | Windows DLL Side-Loading via Suspicious Path | 🟠 high | T1574.002 | - | - |
| 192 | Windows Defender Exclusion Added via PowerShell | 🟠 high | T1562.001 | 59 | - |
| 193 | Windows Defender Malware or Remediation Event | 🟠 high | T1562.001 | - | - |
| 194 | Windows Encoded PowerShell Execution | 🟠 high | T1059.001, T1027 | 32 | - |
| 195 | Windows Event Log Cleared via Wevtutil | 🟠 high | T1070.001 | 3 | - |
| 196 | Windows Event Log Clearing | 🟠 high | T1070.001 | 3 | - |
| 197 | Windows Firewall Rule Modification | 🟠 high | T1562.004 | 25 | - |
| 198 | Windows Management Instrumentation Event Subscription | 🟠 high | T1047 | 10 | - |
| 199 | Windows PowerShell Download Cradle | 🟠 high | T1059.001, T1105 | 61 | - |
| 200 | Windows PowerShell Suspicious Script Block | 🟠 high | T1059.001, T1027 | - | - |
| 201 | Windows PsExec Remote Execution | 🟠 high | T1021.002, T1569.002 | 12 | - |
| 202 | Windows Registry Run Key Modification | 🟠 high | T1547.001 | 20 | - |
| 203 | Windows Remote Access Tool Detected | 🟠 high | T1219 | 15 | - |
| 204 | Windows Remote Management Shell via Winrs | 🟠 high | T1021.006 | 3 | - |
| 205 | Windows Scheduled Task Created or Updated | 🟠 high | T1053.005 | - | - |
| 206 | Windows Script Host Execution from Temp | 🟠 high | T1059.005 | 3 | - |
| 207 | Windows Service Created with Suspicious Binary Path | 🟠 high | T1543.003 | 6 | - |
| 208 | Windows Service Installed from Event Logs | 🟠 high | T1543.003 | - | - |
| 209 | Windows UAC Bypass Attempt | 🟠 high | T1548.002 | 27 | - |
| 210 | Windows WDigest Authentication Enabled for Credential Harvesting | 🟠 high | T1003.001 | 14 | - |
| 211 | Windows WMI Event Subscription Persistence | 🟠 high | T1546.003 | 3 | - |
| 212 | Winlogon Helper DLL Modification | 🟠 high | T1547.004 | 5 | - |
| 213 | Wscript Running Encoded Script | 🟠 high | T1059.005 | 3 | - |
| 214 | XSL Script Processing via WMIC or Msxsl | 🟠 high | T1220 | 4 | - |
| 215 | gMSA Managed Password Read Attempt | 🟠 high | T1555 | - | - |
| 216 | AlwaysInstallElevated Exploitation | 🟡 medium | T1548.002 | 27 | - |
| 217 | Application Shimming for Persistence | 🟡 medium | T1546.011 | 3 | - |
| 218 | BITS Job Persistence | 🟡 medium | T1197 | 4 | - |
| 219 | BLUELIGHT RAT: C2 via Microsoft Graph API | 🟡 medium | T1071.001 | - | - |
| 220 | BLUELIGHT RAT: File Discovery from Browser Process | 🟡 medium | T1083 | - | - |
| 221 | BLUELIGHT RAT: Internet Explorer Drive-by Compromise | 🟡 medium | T1189 | - | - |
| 222 | BLUELIGHT RAT: Registry Enumeration of Security Products | 🟡 medium | T1012 | - | - |
| 223 | Caldera - Credential Search in Config and Environment Files (Windows) | 🟡 medium | T1552, T1552.001 | - | - |
| 224 | Caldera - Data Collection from Local System via findstr and PowerShell (Windows) | 🟡 medium | T1005 | - | - |
| 225 | Caldera - Data Collection from Network Shared Drive (Windows) | 🟡 medium | T1039 | - | - |
| 226 | Caldera - Remote Data Staging via SMB Share Write | 🟡 medium | T1074, T1074.002 | - | - |
| 227 | Clipboard Data Collection | 🟡 medium | T1115 | 5 | - |
| 228 | Compiled HTML File Execution | 🟡 medium | T1218.001 | 8 | - |
| 229 | Control Panel Item Execution | 🟡 medium | T1218 | 16 | - |
| 230 | Credential File Discovery | 🟡 medium | T1552.001 | 17 | - |
| 231 | Credential Manager: High-Frequency Credential Read | 🟡 medium | T1555.004 | - | - |
| 232 | DLL Side-Loading from Suspicious Directory | 🟡 medium | T1574.002 | - | - |
| 233 | Data Compression for Exfiltration via 7zip | 🟡 medium | T1560.001 | 12 | - |
| 234 | Defacement via Desktop Wallpaper Change | 🟡 medium | T1491.001 | 4 | - |
| 235 | Default File Association Hijack | 🟡 medium | T1546.001 | 1 | - |
| 236 | Domain Admins Group Enumeration via net group | 🟡 medium | T1069.002 | - | - |
| 237 | Domain Trust Discovery via Nltest | 🟡 medium | T1482 | 8 | - |
| 238 | Executable Written to Remote Admin Share (Lateral Tool Transfer) | 🟡 medium | T1021.002, T1570 | - | - |
| 239 | File Deletion of Security Tools | 🟡 medium | T1070.004 | 11 | - |
| 240 | File and Directory Discovery via dir | 🟡 medium | T1083 | 9 | - |
| 241 | Finger.exe Abuse for File Download | 🟡 medium | T1105 | 39 | - |
| 242 | Hidden PowerShell Window Execution | 🟡 medium | T1564.003 | 3 | - |
| 243 | Indirect Command Execution via Forfiles | 🟡 medium | T1202 | 5 | - |
| 244 | JavaScript Execution via Node.js | 🟡 medium | T1059.007 | 2 | - |
| 245 | Office Application Startup Persistence | 🟡 medium | T1137 | 1 | - |
| 246 | PowerView / PowerSploit Domain Reconnaissance | 🟡 medium | T1087.002, T1482 | - | - |
| 247 | Python Execution as Child of System Process | 🟡 medium | T1059.006 | 4 | - |
| 248 | Query Registry for Security Products | 🟡 medium | T1518.001 | 11 | - |
| 249 | SDelete Secure File Deletion | 🟡 medium | T1070.004 | 11 | - |
| 250 | Scheduled Task XML Import | 🟡 medium | T1053.005 | - | - |
| 251 | ScreenSaver Hijacking Persistence | 🟡 medium | T1546.002 | 1 | - |
| 252 | Security Group Enumeration: Rapid Membership Queries | 🟡 medium | T1069.002, T1087.002 | - | - |
| 253 | Service Permissions Weakness Discovery | 🟡 medium | T1574.011 | 2 | - |
| 254 | Shortcut Modification for Persistence | 🟡 medium | T1547.009 | 2 | - |
| 255 | Startup Folder Modification | 🟡 medium | T1547.001 | 20 | - |
| 256 | Sysmon DNS Query to Suspicious TLDs | 🟡 medium | T1071.004 | 4 | - |
| 257 | Sysmon Executable File Created or Detected | 🟡 medium | T1105, T1547.001 | - | - |
| 258 | Sysmon LDAP Reconnaissance | 🟡 medium | T1087.002, T1069.002 | 39 | - |
| 259 | Sysmon RDP Lateral Movement | 🟡 medium | T1021.001 | 4 | - |
| 260 | System Shutdown or Reboot via shutdown.exe | 🟡 medium | T1529 | 16 | - |
| 261 | Token Manipulation via RunAs | 🟡 medium | T1134.002 | 2 | - |
| 262 | UAC Bypass via DiskCleanup | 🟡 medium | T1548.002 | 27 | - |
| 263 | Unquoted Service Path Exploitation | 🟡 medium | T1574.009 | 1 | - |
| 264 | Virtualization Sandbox Evasion Check | 🟡 medium | T1497 | 9 | - |
| 265 | Visual Basic Script Compilation via vbc.exe | 🟡 medium | T1059.005 | 3 | - |
| 266 | WiFi Password Extraction via Netsh | 🟡 medium | T1552.001 | 17 | - |
| 267 | WinRM Lateral Movement via PowerShell | 🟡 medium | T1021.006 | 3 | - |
| 268 | Windows Account Discovery Commands | 🟡 medium | T1087.001, T1087.002 | 35 | - |
| 269 | Windows Account or Group Enumeration Spike | 🟡 medium | T1087, T1069 | - | - |
| 270 | Windows Admin Share Access via Net Use | 🟡 medium | T1021.002 | 4 | - |
| 271 | Windows Credential Manager Access via VaultCmd | 🟡 medium | T1555 | 8 | - |
| 272 | Windows Data Staging for Exfiltration | 🟡 medium | T1074.001 | 3 | - |
| 273 | Windows Kerberos Pre-Authentication Failure Spike | 🟡 medium | T1110 | - | - |
| 274 | Windows LOLBin Usage: at | 🟡 medium | T1218 | 16 | - |
| 275 | Windows LOLBin Usage: bitsadmin | 🟡 medium | T1218 | 16 | - |
| 276 | Windows LOLBin Usage: certutil | 🟡 medium | T1218 | 16 | - |
| 277 | Windows LOLBin Usage: cmd | 🟡 medium | T1218 | 16 | - |
| 278 | Windows LOLBin Usage: cscript | 🟡 medium | T1218 | 16 | - |
| 279 | Windows LOLBin Usage: ipconfig | 🟡 medium | T1218 | 16 | - |
| 280 | Windows LOLBin Usage: mshta | 🟡 medium | T1218 | 16 | - |
| 281 | Windows LOLBin Usage: net | 🟡 medium | T1218 | 16 | - |
| 282 | Windows LOLBin Usage: net1 | 🟡 medium | T1218 | 16 | - |
| 283 | Windows LOLBin Usage: powershell | 🟡 medium | T1218 | 16 | - |
| 284 | Windows LOLBin Usage: regsvr32 | 🟡 medium | T1218 | 16 | - |
| 285 | Windows LOLBin Usage: rundll32 | 🟡 medium | T1218 | 16 | - |
| 286 | Windows LOLBin Usage: sc | 🟡 medium | T1218 | 16 | - |
| 287 | Windows LOLBin Usage: schtasks | 🟡 medium | T1218 | 16 | - |
| 288 | Windows LOLBin Usage: systeminfo | 🟡 medium | T1218 | 16 | - |
| 289 | Windows LOLBin Usage: taskkill | 🟡 medium | T1218 | 16 | - |
| 290 | Windows LOLBin Usage: tasklist | 🟡 medium | T1218 | 16 | - |
| 291 | Windows LOLBin Usage: whoami | 🟡 medium | T1218 | 16 | - |
| 292 | Windows LOLBin Usage: wmic | 🟡 medium | T1218 | 16 | - |
| 293 | Windows LOLBin Usage: wscript | 🟡 medium | T1218 | 16 | - |
| 294 | Windows MSBuild Execution for Code Bypass | 🟡 medium | T1127.001 | 2 | - |
| 295 | Windows NTLM Authentication Failure Spike | 🟡 medium | T1110 | - | - |
| 296 | Windows Network Share Discovery | 🟡 medium | T1135 | 12 | - |
| 297 | Windows RDP Lateral Movement | 🟡 medium | T1021.001 | 4 | - |
| 298 | Windows Remote System Discovery | 🟡 medium | T1018 | 22 | - |
| 299 | Windows Scheduled Task Creation via Schtasks | 🟡 medium | T1053.005 | 12 | - |
| 300 | Windows Screen Capture Activity | 🟡 medium | T1113 | 10 | - |
| 301 | Windows Service Creation via SC | 🟡 medium | T1543.003 | 6 | - |
| 302 | Windows Vault Enumeration | 🟡 medium | T1555 | 8 | - |
| 303 | Caldera - Network Configuration Recon via ipconfig and route (Windows) | 🔵 low | T1016 | - | - |
| 304 | Caldera - System Information Discovery via systeminfo and WMI (Windows) | 🔵 low | T1082 | - | - |
| 305 | Caldera - System Network Configuration Discovery (Windows) | 🔵 low | T1016 | - | - |
| 306 | Caldera - System Network Connections Discovery (Windows) | 🔵 low | T1049 | - | - |
| 307 | Caldera - System Owner Discovery via whoami and query Commands (Windows) | 🔵 low | T1033 | - | - |
| 308 | Caldera - System Owner and User Discovery (Windows) | 🔵 low | T1033 | - | - |
| 309 | Caldera - WMIC OS and Hardware Enumeration (Windows) | 🔵 low | T1082 | - | - |
| 310 | Lateral Tool Transfer via Robocopy | 🔵 low | T1570 | 2 | - |
| 311 | Local Group Membership Discovery | 🔵 low | T1069.001 | 7 | - |
| 312 | Network Share Enumeration via Net View | 🔵 low | T1135 | 12 | - |
| 313 | Password Policy Discovery | 🔵 low | T1201 | 12 | - |
| 314 | PowerShell Execution via Alternate Shell | 🔵 low | T1059.001 | 22 | - |
| 315 | Process Discovery via Tasklist | 🔵 low | T1057 | 9 | - |
| 316 | Software Discovery via WMIC | 🔵 low | T1518 | 6 | - |

## Microsoft Sentinel Converted Queries

| # | Title | Category | Severity | MITRE | Live Validation |
|---|-------|----------|----------|-------|-----------------|
| 1 | 7-zip-prep-for-exfiltration | endpoint | 🟡 medium | - | passed |
| 2 | Acronis - Multiple Endpoints Accessing Malicious URLs | network | 🟡 medium | T1204.001 | passed |
| 3 | Acronis - Multiple Endpoints Infected by Ransomware | network | 🟠 high | T1486 | passed |
| 4 | Acronis - Multiple Inboxes with Malicious Content Detected | network | 🟡 medium | T1566.002, T1566.001 | passed |
| 5 | AcroRd-Exploits | endpoint | 🟡 medium | - | passed |
| 6 | AD account with Don't Expire Password | endpoint | 🔵 low | T1098 | passed |
| 7 | Add malicious user to Admins and RDP users group via PowerShell | endpoint | 🟡 medium | - | passed |
| 8 | alt-data-streams | endpoint | 🟡 medium | - | passed |
| 9 | Apache - Apache 2.4.49 flaw CVE-2021-41773 | network | 🟠 high | T1190, T1133, T1210 | passed |
| 10 | Apache - Command in URI | network | 🟠 high | T1190, T1133 | passed |
| 11 | Apache - Known malicious user agent | network | 🟠 high | T1190, T1133 | passed |
| 12 | Apache - Multiple client errors from single IP | network | 🟡 medium | T1190, T1133 | passed |
| 13 | Apache - Multiple server errors from single IP | network | 🟡 medium | T1498, T1190, T1133 | passed |
| 14 | Apache - Unexpected Post Requests | network | 🟡 medium | T1100, T1505, T1071 | passed |
| 15 | ApexOne - Attack Discovery Detection | endpoint | 🟠 high | T1190 | passed |
| 16 | ApexOne - C&C callback events | endpoint | 🟠 high | T1071 | passed |
| 17 | ApexOne - Multiple deny or terminate actions on single IP | endpoint | 🟠 high | T1190 | passed |
| 18 | ApexOne - Spyware detection | endpoint | 🟡 medium | T1204 | passed |
| 19 | ApexOne - Suspicious files events | endpoint | 🟡 medium | T1204 | passed |
| 20 | ApexOne - Top sources with alerts | endpoint | 🟡 medium | T1204, T1189, T1068, T1202, T1112, T1055, T1071, T1095, T1537, T1567 | passed |
| 21 | app-armor-stopped | endpoint | 🟡 medium | - | passed |
| 22 | APT29 thinktanks | endpoint | 🟡 medium | - | passed |
| 23 | apt sofacy zebrocy | endpoint | 🟡 medium | - | passed |
| 24 | apt ta17 293a ps | endpoint | 🟡 medium | - | passed |
| 25 | apt tropictrooper | endpoint | 🟡 medium | - | passed |
| 26 | apt unidentified nov 18 | endpoint | 🟡 medium | - | passed |
| 27 | apt unidentified nov 18 (1) | endpoint | 🟡 medium | - | passed |
| 28 | ARGOS Cloud Security - Exploitable Cloud Resources | azure_custom | 🟠 high | T1190 | passed |
| 29 | Azure DevOps Pull Request Policy Bypassing | m365 | 🟡 medium | T1098 | passed |
| 30 | backup-deletion | m365 | 🟡 medium | - | passed |
| 31 | Base64encodePEFile | endpoint | 🟡 medium | - | passed |
| 32 | Best Practice Compliance Check Not Passed | azure_custom | 🟡 medium | - | passed |
| 33 | Bitglass - Applications used | azure_custom | 🟡 medium | T1078 | passed |
| 34 | Bitglass - Impossible travel distance | azure_custom | 🟡 medium | T1078 | passed |
| 35 | Bitglass - Login failures | azure_custom | 🟡 medium | T1078 | passed |
| 36 | Bitglass - Multiple failed logins | azure_custom | 🟠 high | T1110 | passed |
| 37 | Bitglass - New admin user | azure_custom | 🟡 medium | T1078 | passed |
| 38 | Bitglass - New risky user | azure_custom | 🟠 high | T1078 | passed |
| 39 | Bitglass - Privileged login failures | azure_custom | 🟡 medium | T1078 | passed |
| 40 | Bitglass - Risky users | azure_custom | 🟡 medium | T1078 | passed |
| 41 | Bitglass - Risky users | azure_custom | 🟡 medium | T1078 | passed |
| 42 | Bitglass - The SmartEdge endpoint agent was uninstalled | azure_custom | 🟡 medium | T1070 | passed |
| 43 | Bitglass - User devices | azure_custom | 🟡 medium | T1078 | passed |
| 44 | Box - Executable file in folder | m365 | 🟡 medium | T1189 | passed |
| 45 | Box - File containing sensitive data | m365 | 🟡 medium | T1048 | passed |
| 46 | Box - IP list for admin users | m365 | 🟡 medium | T1078 | passed |
| 47 | c2-lookup-from-nonbrowser[Nobelium] | endpoint | 🟡 medium | - | passed |
| 48 | c2-lookup-response[Nobelium] | endpoint | 🟡 medium | - | passed |
| 49 | Certutil (LOLBins and LOLScripts, Normalized Process Events) | endpoint | 🟡 medium | T1105 | passed |
| 50 | Certutil (LOLBins and LOLScripts, Normalized Process Events) | azure_custom | 🟡 medium | T1105 | passed |
| 51 | check-for-shadowhammer-activity-download-domain | endpoint | 🟡 medium | - | passed |
| 52 | Cisco Cloud Security - 'Blocked' User-Agents. | network | 🟡 medium | T1020 | passed |
| 53 | Cisco Cloud Security - Crypto Miner User-Agent Detected | network | 🟡 medium | T1496, T1071.001, T1041 | passed |
| 54 | Cisco Cloud Security - Empty User Agent Detected | network | 🟡 medium | T1001.003 | passed |
| 55 | Cisco Cloud Security - Proxy 'Allowed' to unreliable categories. | network | 🟡 medium | T1189 | passed |
| 56 | Cisco Cloud Security - Windows PowerShell User-Agent Detected | network | 🟡 medium | T1132, T1027, T1059.001 | passed |
| 57 | Cisco Duo - AD sync failed | identity | 🟡 medium | T1489 | passed |
| 58 | Cisco Duo - Admin failure authentications | identity | 🟡 medium | T1078 | passed |
| 59 | Cisco Duo - Admin failure authentications | identity | 🟡 medium | T1078 | passed |
| 60 | Cisco Duo - Admin password reset | identity | 🟠 high | T1078 | passed |
| 61 | Cisco Duo - Admin user created | identity | 🟡 medium | T1078 | passed |
| 62 | Cisco Duo - Admin user deleted | identity | 🟡 medium | T1531 | passed |
| 63 | Cisco Duo - Authentication error reasons | identity | 🟡 medium | T1078 | passed |
| 64 | Cisco Duo - Authentication errors | identity | 🟡 medium | T1078 | passed |
| 65 | Cisco Duo - Delete actions | identity | 🟡 medium | T1531 | passed |
| 66 | Cisco Duo - Deleted users | identity | 🟡 medium | T1531 | passed |
| 67 | Cisco Duo - Fraud authentications | identity | 🟡 medium | T1078 | passed |
| 68 | Cisco Duo - Multiple admin 2FA failures | identity | 🟠 high | T1078 | passed |
| 69 | Cisco Duo - Multiple user login failures | identity | 🟠 high | T1078 | passed |
| 70 | Cisco Duo - Multiple users deleted | identity | 🟡 medium | T1531 | passed |
| 71 | Cisco Duo - New users | identity | 🟡 medium | T1078 | passed |
| 72 | Cisco SE - Connection to known C2 server | endpoint | 🟠 high | T1071 | passed |
| 73 | Cisco SE - Dropper activity on host | endpoint | 🟠 high | T1204.002 | passed |
| 74 | Cisco SE - Generic IOC | endpoint | 🟠 high | T1204.002 | passed |
| 75 | Cisco SE - Infected hosts | endpoint | 🟠 high | T1204.002 | passed |
| 76 | Cisco SE - Infected users | endpoint | 🟠 high | T1204.002 | passed |
| 77 | Cisco SE - Malware execusion on host | endpoint | 🟠 high | T1204.002 | passed |
| 78 | Cisco SE - Modified agents on hosts | endpoint | 🔵 low | T1562 | passed |
| 79 | Cisco SE - Policy update failure | endpoint | 🟡 medium | T1562 | passed |
| 80 | Cisco SE - Possible webshell | endpoint | 🟠 high | T1102 | passed |
| 81 | Cisco SE - Ransomware Activity | endpoint | 🟠 high | T1486 | passed |
| 82 | Cisco SE - Rare scanned files | endpoint | 🟡 medium | T1204.002 | passed |
| 83 | Cisco SE - Scanned files | endpoint | 🟡 medium | T1204.002 | passed |
| 84 | Cisco SE - Suspicious powershel downloads | endpoint | 🟡 medium | T1204.002 | passed |
| 85 | Cisco SE - Uncommon application behavior | endpoint | 🟡 medium | T1204.002 | passed |
| 86 | Cisco SE - User Logins | endpoint | 🔵 low | T1078 | passed |
| 87 | Cisco SE - Vulnerable applications | endpoint | 🟡 medium | T1204.002 | passed |
| 88 | Cisco Umbrella - Crypto Miner User-Agent Detected | network | 🟡 medium | - | passed |
| 89 | Cisco Umbrella - Empty User Agent Detected | network | 🟡 medium | - | passed |
| 90 | Cisco Umbrella - Windows PowerShell User-Agent Detected | network | 🟡 medium | - | passed |
| 91 | Cisco WSA - Access to unwanted site | network | 🟠 high | T1566 | passed |
| 92 | Cisco WSA - Blocked files | network | 🟡 medium | T1189 | passed |
| 93 | Cisco WSA - Multiple errors to resource from risky category | network | 🟡 medium | T1189, T1102 | passed |
| 94 | Cisco WSA - Multiple errors to URL | network | 🟡 medium | T1102 | passed |
| 95 | Cisco WSA - Potentially risky resources | network | 🟡 medium | T1189 | passed |
| 96 | Cisco WSA - Rare URL with error | network | 🟡 medium | T1189, T1048 | passed |
| 97 | Cisco WSA - Top URLs | network | 🟡 medium | T1189 | passed |
| 98 | Cisco WSA - Uncategorized URLs | network | 🟡 medium | T1189 | passed |
| 99 | Cisco WSA - URL shorteners | network | 🟡 medium | T1189 | passed |
| 100 | Cisco WSA - User errors | network | 🟡 medium | T1189, T1048 | passed |
| 101 | CiscoISE - Attempt to delete local store logs | identity | 🟡 medium | T1070 | passed |
| 102 | CiscoISE - Attempts to suspend the log collector | identity | 🟡 medium | - | passed |
| 103 | CiscoISE - Authentication attempts to suspended user account | identity | 🟡 medium | - | passed |
| 104 | CiscoISE - Backup failed | identity | 🟡 medium | T1490 | passed |
| 105 | CiscoISE - Certificate has expired | identity | 🟡 medium | T1552 | passed |
| 106 | CiscoISE - Dynamic authorization failed | identity | 🟡 medium | - | passed |
| 107 | CiscoISE - Expired certificate in the client certificates chain | identity | 🟡 medium | - | passed |
| 108 | CiscoISE - Failed authentication events | identity | 🟡 medium | - | passed |
| 109 | CiscoISE - Failed login attempts via SSH CLI (users) | identity | 🟡 medium | - | passed |
| 110 | CiscoISE - Guest authentication failed | identity | 🟡 medium | - | passed |
| 111 | CiscoISE - Guest authentication succeeded | identity | 🟡 medium | - | passed |
| 112 | CiscoISE - ISE administrator password has been reset | identity | 🟡 medium | T1098 | passed |
| 113 | CiscoISE - Log collector was suspended | identity | 🟡 medium | T1562.002 | passed |
| 114 | CiscoISE - Log files deleted | identity | 🟡 medium | T1070.004 | passed |
| 115 | CiscoISE - Sources with high number of 'Failed Authentication' events | identity | 🟡 medium | - | passed |
| 116 | clear-system-logs | endpoint | 🟡 medium | - | passed |
| 117 | Clear System Logs | endpoint | 🟡 medium | - | passed |
| 118 | Clearing of forensic evidence from event logs using wevtutil | endpoint | 🟡 medium | - | passed |
| 119 | Cloud Hopper | endpoint | 🟡 medium | - | passed |
| 120 | Cloudflare - Client errors | network | 🟡 medium | T1190, T1133, T1498 | passed |
| 121 | Cloudflare - Client errors | network | 🟡 medium | T1190, T1133, T1498 | passed |
| 122 | Cloudflare - Empty user agent | network | 🟡 medium | T1190, T1133 | passed |
| 123 | Cloudflare - Empty user agent | network | 🟡 medium | T1190, T1133 | passed |
| 124 | Cloudflare - Multiple error requests from single source | network | 🔵 low | T1190, T1133 | passed |
| 125 | Cloudflare - Multiple error requests from single source | network | 🔵 low | T1190, T1133 | passed |
| 126 | Cloudflare - Multiple user agents for single source | network | 🟡 medium | T1190, T1133 | passed |
| 127 | Cloudflare - Multiple user agents for single source | network | 🟡 medium | T1190, T1133 | passed |
| 128 | Cloudflare - Rare user agents | network | 🔵 low | T1190, T1133 | passed |
| 129 | Cloudflare - Rare user agents | network | 🔵 low | T1190, T1133 | passed |
| 130 | Cloudflare - Server errors | network | 🟡 medium | T1190, T1133, T1498 | passed |
| 131 | Cloudflare - Server errors | network | 🟡 medium | T1190, T1133, T1498 | passed |
| 132 | Cloudflare - WAF Allowed threat | network | 🟠 high | T1190, T1133 | passed |
| 133 | Cloudflare - WAF Allowed threat | network | 🟠 high | T1190, T1133 | passed |
| 134 | Contrast ADR - Security Incident Alert | azure_custom | 🟡 medium | T1190, T1055, T1018, T1008 | passed |
| 135 | Credential Harvesting Using LaZagne | endpoint | 🟡 medium | - | passed |
| 136 | Critical Risks | network | 🟠 high | T1189, T1059, T1053, T1548 | passed |
| 137 | cve-2019-0808-c2 | endpoint | 🟡 medium | - | passed |
| 138 | cve-2019-0808-nufsys-file creation | endpoint | 🟡 medium | - | passed |
| 139 | cve-2019-0808-set-scheduled-task | endpoint | 🟡 medium | - | passed |
| 140 | CVE-2022-22965 Network Activity | endpoint | 🟡 medium | - | passed |
| 141 | CyberArkEPM - Elevation requests | endpoint | 🟡 medium | T1204, T1078 | passed |
| 142 | CyberArkEPM - MSBuild usage as LOLBin | endpoint | 🟡 medium | T1127 | passed |
| 143 | CyberArkEPM - Possible execution of Powershell Empire | endpoint | 🟠 high | T1204 | passed |
| 144 | CyberArkEPM - Powershell downloads | endpoint | 🟡 medium | T1204, T1059 | passed |
| 145 | CyberArkEPM - Powershell scripts execution parameters | endpoint | 🔵 low | T1204, T1059 | passed |
| 146 | CyberArkEPM - Processes with Internet access attempts | endpoint | 🟡 medium | T1095 | passed |
| 147 | CyberArkEPM - Rare process run by users | endpoint | 🔵 low | T1204 | passed |
| 148 | CyberArkEPM - Suspicious activity attempts | endpoint | 🟡 medium | T1204 | passed |
| 149 | CyberArkEPM - Unexpected executable extension | endpoint | 🟡 medium | T1204, T1036 | passed |
| 150 | Cybersixgill Actionable alerts | azure_custom | 🟡 medium | - | passed |
| 151 | Cyble Advisory Alerts Advisory | azure_custom | 🔵 low | T1595, T1596, T1587 | passed |
| 152 | Cyble Vision Alerts Assets | azure_custom | 🔵 low | T1592 | passed |
| 153 | Cyble Vision Alerts Bitbucket | azure_custom | 🔵 low | T1552, T1537, T1083 | passed |
| 154 | Cyble Vision Alerts Cloud Storage | azure_custom | 🔵 low | T1537, T1083 | passed |
| 155 | Cyble Vision Alerts Compromised Endpoint Cookies | azure_custom | 🔵 low | T1539, T1550 | passed |
| 156 | Cyble Vision Alerts Compromised Files | azure_custom | 🔵 low | T1552, T1041 | passed |
| 157 | Cyble Vision Alerts Cyble Web Applications | azure_custom | 🔵 low | T1595, T1592 | passed |
| 158 | Cyble Vision Alerts Darkweb Data Breaches | azure_custom | 🔵 low | T1589, T1078, T1048, T1530 | passed |
| 159 | Cyble Vision Alerts Darkweb Ransomware Leak | azure_custom | 🔵 low | T1486, T1657 | passed |
| 160 | Cyble Vision Alerts Discord Keyword | azure_custom | 🔵 low | T1598, T1664 | passed |
| 161 | Cyble Vision Alerts Discovered Subdomain | azure_custom | 🔵 low | T1595 | passed |
| 162 | Cyble Vision Alerts Docker | azure_custom | 🔵 low | T1537, T1610, T1083 | passed |
| 163 | Cyble Vision Alerts Domain Expiry Alert | azure_custom | 🔵 low | T1499 | passed |
| 164 | Cyble Vision Alerts Domain Watchlist | azure_custom | 🔵 low | T1584 | passed |
| 165 | Cyble Vision Alerts Flash Report | azure_custom | 🔵 low | T1598, T1589 | passed |
| 166 | Cyble Vision Alerts Github | azure_custom | 🔵 low | T1213, T1530, T1552 | passed |
| 167 | Cyble Vision Alerts Hacktivism | azure_custom | 🔵 low | T1595, T1491, T1498, T1585 | passed |
| 168 | Cyble Vision Alerts I2P Monitoring | azure_custom | 🔵 low | T1585 | passed |
| 169 | Cyble Vision Alerts IOC'S | azure_custom | 🔵 low | T1595, T1133, T1046, T1071, T1486 | passed |
| 170 | Cyble Vision Alerts IP Risk Score | azure_custom | 🔵 low | T1595 | passed |
| 171 | Cyble Vision Alerts Leaked Credentials | azure_custom | 🔵 low | T1552, T1082 | passed |
| 172 | Cyble Vision Alerts Malicious Ads Detected | azure_custom | 🔵 low | T1189, T1566, T1059 | passed |
| 173 | Cyble Vision Alerts New Vulnerability Detected | azure_custom | 🔵 low | T1190 | passed |
| 174 | Cyble Vision Alerts News Feed Alert | azure_custom | 🔵 low | T1598 | passed |
| 175 | Cyble Vision Alerts OSINT Mention Detected | azure_custom | 🔵 low | T1592, T1589 | passed |
| 176 | Cyble Vision Alerts OT/ICS Threat Activity Detected | azure_custom | 🔵 low | T0842, T0830 | passed |
| 177 | Cyble Vision Alerts Pastebin | azure_custom | 🔵 low | T1591 | passed |
| 178 | Cyble Vision Alerts Phishing Domain Detected | azure_custom | 🔵 low | T1598.003 | passed |
| 179 | Cyble Vision Alerts Physical Threat Alert | azure_custom | 🔵 low | T1486 | passed |
| 180 | Cyble Vision Alerts Postman API Exposure Detection | azure_custom | 🔵 low | T1595, T1552, T1041 | passed |
| 181 | Cyble Vision Alerts Product Vulnerability Detected | azure_custom | 🔵 low | T1190, T1588 | passed |
| 182 | Cyble Vision Alerts Social Media Monitoring | azure_custom | 🔵 low | T1595, T1585, T1589 | passed |
| 183 | Cyble Vision Alerts SSL Certificate Expiry | azure_custom | 🔵 low | T1190, T1499 | passed |
| 184 | Cyble Vision Alerts Suspicious Domain | azure_custom | 🔵 low | T1595 | passed |
| 185 | Cyble Vision Alerts TOR Links | azure_custom | 🔵 low | T1583, T1590, T1595 | passed |
| 186 | Cyble Vision Alerts Vulnerability | azure_custom | 🔵 low | T1595, T1203, T1046 | passed |
| 187 | Cyble Vision Alerts Website Defacement Content | azure_custom | 🔵 low | T1491 | passed |
| 188 | Cyble Vision Alerts Website Defacement Keyword | azure_custom | 🔵 low | T1491, T1598 | passed |
| 189 | Cyble Vision Alerts Website Defacement URL | azure_custom | 🔵 low | T1491 | passed |
| 190 | CybleVision Alerts Cyber Crime Forum Alerts | azure_custom | 🔵 low | T1598, T1585, T1589, T1646 | passed |
| 191 | CybleVision Alerts Darkweb Marketplace Alerts | azure_custom | 🔵 low | T1555, T1005, T1041, T1589, T1646 | passed |
| 192 | CybleVision Alerts Mobile Apps | azure_custom | 🔵 low | T1595, T1608, T1195 | passed |
| 193 | CybleVision Alerts Stealer Logs | azure_custom | 🔵 low | T1555, T1005, T1041, T1589, T1189 | passed |
| 194 | CybleVision Alerts Telegram Mentions | azure_custom | 🔵 low | T1598, T1585, T1102 | passed |
| 195 | cypherpunk-exclusive-commands | endpoint | 🟡 medium | - | passed |
| 196 | cypherpunk-remote-exec-w-psexesvc | endpoint | 🟡 medium | - | passed |
| 197 | deimos-component-execution | endpoint | 🟡 medium | - | passed |
| 198 | Deimos Component Execution | endpoint | 🟠 high | T1059, T1005, T1020 | passed |
| 199 | Deimos Component Execution | endpoint | 🟡 medium | - | passed |
| 200 | deleting-data-w-cipher-tool | endpoint | 🟡 medium | - | passed |
| 201 | Deletion of data on multiple drives using cipher exe | endpoint | 🟡 medium | T1485 | passed |
| 202 | Deletion of data on multiple drives using cipher exe | endpoint | 🟡 medium | - | passed |
| 203 | Deletion of data on multiple drives using cipher exe | endpoint | 🟡 medium | - | passed |
| 204 | dell-driver-vulnerability-2021 | endpoint | 🟡 medium | - | passed |
| 205 | detect-bluekeep-exploitation-attempts | endpoint | 🟡 medium | - | passed |
| 206 | detect-bluekeep-related-mining | endpoint | 🟡 medium | - | passed |
| 207 | detect-cve-2019-0863-AngryPolarBearBug2-exploit | endpoint | 🟡 medium | - | passed |
| 208 | detect-cve-2019-0973-installerbypass-exploit | endpoint | 🟡 medium | - | passed |
| 209 | detect-cve-2019-1053-sandboxescape-exploit | endpoint | 🟡 medium | - | passed |
| 210 | detect-cyzfc-activity (1) | endpoint | 🟡 medium | - | passed |
| 211 | detect-cyzfc-activity (3) | endpoint | 🟡 medium | - | passed |
| 212 | detect-doublepulsar-execution | endpoint | 🟡 medium | - | passed |
| 213 | detect-exploitation-of-cve-2018-8653 | endpoint | 🟡 medium | - | passed |
| 214 | detect-jscript-file-creation | endpoint | 🟡 medium | - | passed |
| 215 | detect-malicious-rar-extraction | endpoint | 🟡 medium | - | passed |
| 216 | detect-malicious-use-of-msiexec-mimikatz | endpoint | 🟡 medium | - | passed |
| 217 | detect-malicious-use-of-msiexec-powershell | endpoint | 🟡 medium | - | passed |
| 218 | detect-malicious-use-of-msiexec | endpoint | 🟡 medium | - | passed |
| 219 | detect-office-applications-spawning-msdt-CVE-2022-30190 | endpoint | 🟡 medium | T1221 | passed |
| 220 | detect-office-products-spawning-wmic | endpoint | 🟡 medium | - | passed |
| 221 | detect-suspicious-mshta-usage | endpoint | 🟡 medium | - | passed |
| 222 | Detect Malicious use of MSIExec | endpoint | 🟡 medium | - | passed |
| 223 | Detect Malicious use of Msiexec Mimikatz | endpoint | 🟡 medium | - | passed |
| 224 | Detect Suspicious Commands Initiated by Webserver Processes | endpoint | 🟠 high | T1059, T1574, T1087, T1082 | passed |
| 225 | Detect Suspicious Mshta Usage | endpoint | 🟡 medium | - | passed |
| 226 | DetectTorrentUse | endpoint | 🟡 medium | - | passed |
| 227 | Dev-0270 Registry IOC - September 2022 | endpoint | 🟠 high | T1486 | passed |
| 228 | Dev-0270 WMIC  Discovery | endpoint | 🟠 high | T1482 | passed |
| 229 | Dev-0530 File Extension Rename | endpoint | 🟠 high | T1486 | passed |
| 230 | Digital Guardian - Exfiltration using DNS protocol | azure_custom | 🟠 high | T1048 | passed |
| 231 | Digital Guardian - Rare destination ports | azure_custom | 🟡 medium | T1048 | passed |
| 232 | Digital Guardian - Unexpected protocol | azure_custom | 🟠 high | T1048 | passed |
| 233 | Disable or Modify Windows Defender | endpoint | 🟡 medium | T1562.001 | passed |
| 234 | Disabling Security Services via Registry | endpoint | 🟡 medium | T1562 | passed |
| 235 | Disabling Services via Registry | endpoint | 🟡 medium | - | passed |
| 236 | Disabling Services via Registry | endpoint | 🟡 medium | - | passed |
| 237 | Discord download invoked from cmd line | endpoint | 🟡 medium | T1204, T1102, T1567 | passed |
| 238 | Discord download invoked from cmd line (ASIM Version) | endpoint | 🟡 medium | T1204, T1102, T1567 | passed |
| 239 | Discover hosts doing possible network scans | endpoint | 🟡 medium | - | passed |
| 240 | DLLHost.exe file creation via PowerShell | endpoint | 🟡 medium | - | passed |
| 241 | DLLHost.exe WMIC domain discovery | endpoint | 🟡 medium | - | passed |
| 242 | DLLHost.exe WMIC domain discovery | endpoint | 🟡 medium | - | passed |
| 243 | DNS events related to mining pools (ASIM DNS Schema) | azure_custom | 🔵 low | T1496 | passed |
| 244 | DNS events related to ToR proxies  (ASIM DNS Schema) | azure_custom | 🔵 low | T1048 | passed |
| 245 | Domain controller installation media creation | endpoint | 🟡 medium | T1003 | passed |
| 246 | doppelpaymer-procdump | endpoint | 🟡 medium | - | passed |
| 247 | doppelpaymer-stop-services | endpoint | 🟡 medium | - | passed |
| 248 | Doppelpaymer Stop Services | endpoint | 🟠 high | T1059, T1562 | passed |
| 249 | Doppelpaymer Stop Services | endpoint | 🟡 medium | - | passed |
| 250 | DopplePaymer Procdump | endpoint | 🟠 high | T1003 | passed |
| 251 | DopplePaymer Procdump | endpoint | 🟡 medium | - | passed |
| 252 | Dragon Fly | endpoint | 🟡 medium | - | passed |
| 253 | Dragos Notifications | azure_custom | 🟡 medium | - | passed |
| 254 | Dropping payload via certutil | endpoint | 🟡 medium | - | passed |
| 255 | Dropping Payload via certutil | endpoint | 🟡 medium | - | passed |
| 256 | Electron-CVE-2018-1000006 | endpoint | 🟡 medium | - | passed |
| 257 | Elise backdoor | endpoint | 🟡 medium | - | passed |
| 258 | Email data exfiltration via PowerShell | endpoint | 🟡 medium | - | passed |
| 259 | Email Top 10 Targeted Users (Spam) | m365 | 🟡 medium | T1566 | passed |
| 260 | Email Top 10 Targeted Users (Spam) | m365 | 🟡 medium | T1566 | passed |
| 261 | Email Top 15 Targeted Users (Spam) with Additional Details | m365 | 🟡 medium | T1566 | passed |
| 262 | Email Top 15 Targeted Users (Spam) with Additional Details | m365 | 🟡 medium | T1566 | passed |
| 263 | Equation Group C2 Communication | endpoint | 🟡 medium | - | passed |
| 264 | Establishing internal proxies | endpoint | 🟡 medium | T1090 | passed |
| 265 | evasive-powershell-strings | endpoint | 🟡 medium | - | passed |
| 266 | Excel launching anomalous processes | endpoint | 🟡 medium | - | passed |
| 267 | Excel Macro Execution | endpoint | 🟡 medium | - | passed |
| 268 | exchange-powershell-snapin-loaded | endpoint | 🟡 medium | - | passed |
| 269 | Exchange IIS Worker Dropping Webshells | endpoint | 🟡 medium | - | passed |
| 270 | ExecuteBase64DecodedPayload | endpoint | 🟡 medium | - | passed |
| 271 | ExploitGuardASRStats | endpoint | 🟡 medium | - | passed |
| 272 | ExploitGuardASRStats (1) | endpoint | 🟡 medium | - | passed |
| 273 | ExploitGuardBlockOfficeChildProcess | endpoint | 🟡 medium | - | passed |
| 274 | ExploitGuardBlockOfficeChildProcess (2) | endpoint | 🟡 medium | - | passed |
| 275 | ExploitGuardControlledFolderAccess | endpoint | 🟡 medium | - | passed |
| 276 | ExploitGuardControlledFolderAccess (1) | endpoint | 🟡 medium | - | passed |
| 277 | ExploitGuardStats | endpoint | 🟡 medium | - | passed |
| 278 | Failed Logon Attempt | endpoint | 🟡 medium | - | passed |
| 279 | Flash-CVE-2018-4848 | endpoint | 🟡 medium | - | passed |
| 280 | Fortiweb - WAF Allowed threat | azure_custom | 🟠 high | T1190, T1133 | passed |
| 281 | GCP IAM - Empty user agent | azure_cloud | 🟡 medium | T1550 | passed |
| 282 | General attempts to access local email store | endpoint | 🟡 medium | - | passed |
| 283 | GitHub - A payment method was removed | m365 | 🟡 medium | T1078 | passed |
| 284 | GitHub - Oauth application - a client secret was removed | m365 | 🟡 medium | T1078 | passed |
| 285 | GitHub - pull request was created | m365 | 🟡 medium | T1078 | passed |
| 286 | GitHub - pull request was merged | m365 | 🟡 medium | T1078 | passed |
| 287 | GitHub - Repository was created | m365 | 🟡 medium | T1078 | passed |
| 288 | GitHub - Repository was destroyed | m365 | 🟡 medium | T1078 | passed |
| 289 | GitHub OAuth App Restrictions Disabled | azure_custom | 🟡 medium | T1505, T1562 | passed |
| 290 | GitHub OAuth App Restrictions Disabled | m365 | 🟡 medium | T1505, T1562 | passed |
| 291 | Google DNS - CVE-2021-34527 (PrintNightmare) external exploit | network | 🟠 high | T1068 | passed |
| 292 | Google DNS - CVE-2021-40444 exploitation | network | 🟠 high | T1068 | passed |
| 293 | Google DNS - Domains with rare errors | network | 🔵 low | T1095 | passed |
| 294 | Google DNS - Errors | network | 🔵 low | T1095 | passed |
| 295 | Google DNS - Exchange online autodiscover abuse | network | 🟡 medium | T1566, T1187 | passed |
| 296 | Google DNS - IP check activity | network | 🟡 medium | T1095 | passed |
| 297 | Google DNS - Malicous Python packages | network | 🟠 high | T1195 | passed |
| 298 | Google DNS - Multiple errors for source | network | 🟡 medium | T1095 | passed |
| 299 | Google DNS - Possible data exfiltration | network | 🟠 high | T1567 | passed |
| 300 | Google DNS - Rare domains | network | 🟡 medium | T1095 | passed |
| 301 | Google DNS - Request to dynamic DNS service | network | 🟡 medium | T1095 | passed |
| 302 | Google DNS - Requests to IP lookup resources | network | 🟡 medium | T1095 | passed |
| 303 | Google DNS - Requests to online shares | network | 🟡 medium | T1095 | passed |
| 304 | Google DNS - Requests to TOR resources | network | 🟡 medium | T1095 | passed |
| 305 | Google DNS - Sources with high number of errors | network | 🔵 low | T1095 | passed |
| 306 | Google DNS - UNC2452 (Nobelium) APT Group activity | network | 🟠 high | T1095 | passed |
| 307 | GWorkspace - Admin permissions granted | m365 | 🟠 high | T1098 | passed |
| 308 | GWorkspace - Alert events | m365 | 🟠 high | T1190, T1133 | passed |
| 309 | GWorkspace - An Outbound Relay has been added to a G Suite Domain | m365 | 🟡 medium | T1114 | passed |
| 310 | GWorkspace - API Access Granted | m365 | 🟡 medium | T1550 | passed |
| 311 | GWorkspace - Suspended users | m365 | 🟡 medium | T1531 | passed |
| 312 | GWorkspace - Two-step authentification disabled for a user | m365 | 🟡 medium | T1111 | passed |
| 313 | GWorkspace - User access has been changed | m365 | 🔵 low | T1098 | passed |
| 314 | hiding-java-class-file | endpoint | 🟡 medium | - | passed |
| 315 | HTA Startup Persistence | endpoint | 🟡 medium | - | passed |
| 316 | Hunt for TABL changes | m365 | 🟡 medium | T1562 | passed |
| 317 | Hunt for TABL changes | m365 | 🟡 medium | T1562 | passed |
| 318 | Hurricane Panda activity | endpoint | 🟡 medium | - | passed |
| 319 | Identify EUROPIUM IOCs | endpoint | 🟡 medium | - | passed |
| 320 | Identify Mango Sandstorm powershell commands | endpoint | 🟠 high | T1570 | passed |
| 321 | Identify unusual identity additions related to EUROPIUM | endpoint | 🟡 medium | - | passed |
| 322 | Imperva - Forbidden HTTP request method in request | network | 🟡 medium | T1190, T1133 | passed |
| 323 | Imperva - Malicious user agent | network | 🟠 high | T1190, T1133 | passed |
| 324 | Imperva - Multiple user agents from same source | network | 🟡 medium | T1190, T1133 | passed |
| 325 | Imperva - Rare destination ports | network | 🟡 medium | T1190 | passed |
| 326 | Imperva - Request from unexpected countries | network | 🟠 high | T1190, T1133 | passed |
| 327 | Imperva - Request to unexpected destination port | network | 🟠 high | T1190, T1133 | passed |
| 328 | Imperva - Top destinations with blocked requests | network | 🟡 medium | T1190, T1133, T1498 | passed |
| 329 | Imperva - Top sources with blocked requests | network | 🟡 medium | T1190, T1133, T1498 | passed |
| 330 | Imperva - Top sources with error requests | network | 🟡 medium | T1190 | passed |
| 331 | insider-threat-detection-queries (12) | endpoint | 🟡 medium | - | passed |
| 332 | insider-threat-detection-queries (16) | endpoint | 🟡 medium | - | passed |
| 333 | insider-threat-detection-queries (3) | endpoint | 🟡 medium | - | passed |
| 334 | insider-threat-detection-queries (4) | endpoint | 🟡 medium | - | passed |
| 335 | insider-threat-detection-queries (6) | endpoint | 🟡 medium | - | passed |
| 336 | java-executing-cmd-to-run-powershell | endpoint | 🟡 medium | - | passed |
| 337 | Java Executing cmd to run Powershell | endpoint | 🟠 high | T1059 | passed |
| 338 | Java Executing cmd to run Powershell | endpoint | 🟡 medium | - | passed |
| 339 | Jira - Updated workflow schemes | m365 | 🟡 medium | T1565 | passed |
| 340 | Jira - Users' IP addresses | m365 | 🟡 medium | T1078 | passed |
| 341 | JNLP-File-Attachment | azure_custom | 🟡 medium | T1566 | passed |
| 342 | JNLP-File-Attachment | azure_custom | 🟡 medium | T1566 | passed |
| 343 | jse-launched-by-word | endpoint | 🟡 medium | - | passed |
| 344 | Judgement Panda Exfil Activity | endpoint | 🟡 medium | T1560 | passed |
| 345 | Judgement Panda exfil activity | endpoint | 🟡 medium | - | passed |
| 346 | kinsing-miner-download | endpoint | 🟡 medium | - | passed |
| 347 | KNOTWEED-PE File Dropped in Color Profile Folder | endpoint | 🟡 medium | - | passed |
| 348 | Known Nylon Typhoon Registry modifications patterns | endpoint | 🟡 medium | T1546.012 | passed |
| 349 | launching-cmd-echo[Nobelium] | endpoint | 🟡 medium | - | passed |
| 350 | lazagne | endpoint | 🟡 medium | - | passed |
| 351 | LaZagne Credential Theft | endpoint | 🟡 medium | T1003 | passed |
| 352 | LaZagne Credential Theft | endpoint | 🟡 medium | - | passed |
| 353 | LaZagne Credential Theft | endpoint | 🟡 medium | - | passed |
| 354 | LemonDuck-component-download-structure | endpoint | 🟡 medium | - | passed |
| 355 | LemonDuck-component-names | endpoint | 🟡 medium | - | passed |
| 356 | LemonDuck-control-structure | endpoint | 🟡 medium | - | passed |
| 357 | LemonDuck-defender-exclusions | endpoint | 🟡 medium | - | passed |
| 358 | LemonDuck-id-generation | endpoint | 🟡 medium | - | passed |
| 359 | Linux-DynoRoot-CVE-2018-1111 | endpoint | 🟡 medium | - | passed |
| 360 | locate-dll-created-locally[Nobelium] | endpoint | 🟡 medium | - | passed |
| 361 | locate-dll-loaded-in-memory[Nobelium] | endpoint | 🟡 medium | - | passed |
| 362 | locate-shlayer-payload-decryption-activity | endpoint | 🟡 medium | - | passed |
| 363 | locate-shlayer-payload-decrytion-activity | endpoint | 🟡 medium | - | passed |
| 364 | locate-surfbuyer-downloader-decoding-activity | endpoint | 🟡 medium | - | passed |
| 365 | LSASS Credential Dumping with Procdump | endpoint | 🟠 high | T1003 | passed |
| 366 | LSASS Credential Dumping with Procdump | endpoint | 🟡 medium | - | passed |
| 367 | MacOceanLotusBackdoor | endpoint | 🟡 medium | - | passed |
| 368 | Malicious bat file | endpoint | 🟡 medium | - | passed |
| 369 | Malicious Connection to LDAP port for CVE-2021-44228 vulnerability | endpoint | 🟡 medium | T1071 | passed |
| 370 | Malicious URL Clicks by workload | m365 | 🟡 medium | T1566 | passed |
| 371 | Malicious URL Clicks by workload | m365 | 🟡 medium | T1566 | passed |
| 372 | Malicious Use of MSBuild as LOLBin | endpoint | 🟡 medium | - | passed |
| 373 | Malware Event Detected | azure_custom | 🟡 medium | - | passed |
| 374 | Malware_In_recyclebin | endpoint | 🟡 medium | - | passed |
| 375 | Mass account password change | endpoint | 🟡 medium | - | passed |
| 376 | McAfee ePO - Agent Handler down | endpoint | 🟡 medium | T1562 | passed |
| 377 | McAfee ePO - Attempt uninstall McAfee agent | endpoint | 🟡 medium | T1562, T1070 | passed |
| 378 | McAfee ePO - Deployment failed | endpoint | 🟠 high | T1562 | passed |
| 379 | McAfee ePO - Error sending alert | endpoint | 🟡 medium | T1562, T1070 | passed |
| 380 | McAfee ePO - Firewall disabled | endpoint | 🟡 medium | T1562, T1071 | passed |
| 381 | McAfee ePO - Infected Systems | endpoint | 🟡 medium | T1189, T1195 | passed |
| 382 | McAfee ePO - Multiple threats on same host | endpoint | 🟡 medium | T1562, T1070, T1189, T1195, T1543, T1055 | passed |
| 383 | McAfee ePO - Scanning engine disabled | endpoint | 🔵 low | T1562, T1070 | passed |
| 384 | McAfee ePO - Spam Email detected | endpoint | 🟡 medium | T1566 | passed |
| 385 | McAfee ePO - Threat was not blocked | endpoint | 🟠 high | T1562, T1070, T1068, T1189, T1195 | passed |
| 386 | McAfee ePO - Update failed | endpoint | 🟡 medium | T1562, T1070 | passed |
| 387 | Microsoft Entra ID Local Device Join Information and Transport Key Registry Keys Access | endpoint | 🟡 medium | T1012 | passed |
| 388 | Midnight Blizzard - Script payload stored in Registry | endpoint | 🟡 medium | T1059 | passed |
| 389 | Midnight Blizzard - suspicious rundll32.exe execution of vbscript | endpoint | 🟡 medium | T1547 | passed |
| 390 | Modifying the registry to add a ransom message notification | endpoint | 🟡 medium | - | passed |
| 391 | NGINX - Command in URI | network | 🟠 high | T1190, T1133 | passed |
| 392 | NGINX - Core Dump | network | 🟠 high | T1499 | passed |
| 393 | NGINX - Multiple client errors from single IP address | network | 🟡 medium | T1190, T1133 | passed |
| 394 | NGINX - Multiple server errors from single IP address | network | 🟡 medium | T1498, T1190, T1133 | passed |
| 395 | NRT Base64 Encoded Windows Process Command-lines | endpoint | 🟡 medium | T1059, T1027, T1140 | passed |
| 396 | NTDS theft | endpoint | 🟡 medium | - | passed |
| 397 | oceanlotus-apt32-network | endpoint | 🟡 medium | - | passed |
| 398 | OCI - Delete operations | azure_cloud | 🟡 medium | T1485 | passed |
| 399 | OCI - Deleted users | azure_cloud | 🟡 medium | T1531 | passed |
| 400 | OCI - Event rule deleted | azure_cloud | 🟠 high | T1070 | passed |
| 401 | OCI - Insecure metadata endpoint | azure_cloud | 🟠 high | T1069 | passed |
| 402 | OCI - Launched instances | azure_cloud | 🟡 medium | T1499 | passed |
| 403 | OCI - Multiple instances launched | azure_cloud | 🟡 medium | T1496 | passed |
| 404 | OCI - Multiple instances terminated | azure_cloud | 🟠 high | T1529 | passed |
| 405 | OCI - New users | azure_cloud | 🟡 medium | T1078 | passed |
| 406 | OCI - Terminated instances | azure_cloud | 🟡 medium | T1529 | passed |
| 407 | OCI - Updated instances | azure_cloud | 🟡 medium | T1578 | passed |
| 408 | office-apps-launching-wscipt | endpoint | 🟡 medium | - | passed |
| 409 | Office Apps Launching Wscipt | endpoint | 🟡 medium | T1059, T1105, T1203 | passed |
| 410 | Office Apps Launching Wscipt | endpoint | 🟡 medium | - | passed |
| 411 | Office ASR rule triggered from browser spawned office process. | endpoint | 🟡 medium | T1566.002 | passed |
| 412 | oracle-webLogic-executing-powershell | endpoint | 🟡 medium | - | passed |
| 413 | Oracle - Command in URI | network | 🟠 high | T1190, T1133 | passed |
| 414 | Oracle - Error messages | network | 🟠 high | T1070 | passed |
| 415 | Oracle - Multiple client errors from single IP | network | 🟡 medium | T1190, T1133 | passed |
| 416 | Oracle - Multiple server errors from single IP | network | 🟡 medium | T1498, T1190, T1133 | passed |
| 417 | Oracle - Oracle WebLogic Exploit CVE-2021-2109 | network | 🟠 high | T1190 | passed |
| 418 | Oracle suspicious command execution | endpoint | 🟡 medium | T1210, T1611 | passed |
| 419 | OracleDBAudit - Active Users | azure_custom | 🟡 medium | T1078 | passed |
| 420 | Palo Alto Prisma Cloud - Opened alerts | azure_cloud | 🟡 medium | T1078 | passed |
| 421 | Palo Alto Prisma Cloud - Updated resources | azure_cloud | 🟡 medium | T1133 | passed |
| 422 | PaloAlto - Multiple Deny result by user | network | 🟡 medium | T1190, T1133 | passed |
| 423 | PaloAlto - Rare files observed | network | 🟡 medium | T1190, T1133 | passed |
| 424 | PE file dropped in Color Profile Folder | endpoint | 🟡 medium | T1203 | passed |
| 425 | Persisting via IFEO Registry Key | endpoint | 🟡 medium | T1546.012 | passed |
| 426 | Ping Federate - Abnormal password reset attempts | azure_custom | 🟠 high | T1110 | passed |
| 427 | Ping Federate - Abnormal password resets for user | azure_custom | 🟠 high | T1078, T1098, T1134 | passed |
| 428 | Ping Federate - Password reset requests | azure_custom | 🔵 low | T1078, T1098 | passed |
| 429 | Ping Federate - Rare source IP addresses | azure_custom | 🟡 medium | T1078 | passed |
| 430 | Ping Federate - Top source IP addresses | azure_custom | 🔵 low | T1078 | passed |
| 431 | Ping Federate - Users recently reseted password | azure_custom | 🟡 medium | T1078, T1098 | passed |
| 432 | Potential re-named sdelete usage | endpoint | 🔵 low | T1485, T1036 | passed |
| 433 | Potential re-named sdelete usage (ASIM Version) | endpoint | 🔵 low | T1485, T1036 | passed |
| 434 | powercat-download | endpoint | 🟡 medium | - | passed |
| 435 | powershell-version-2.0-execution | endpoint | 🟡 medium | - | passed |
| 436 | PowerShell adding exclusion path for Microsoft Defender of ProgramData | endpoint | 🟡 medium | - | passed |
| 437 | PowerShell adding exclusion path for Microsoft Defender of ProgramData | endpoint | 🟡 medium | - | passed |
| 438 | PowerShell Downloads | endpoint | 🟡 medium | - | passed |
| 439 | PowerShell downloads | endpoint | 🟡 medium | - | passed |
| 440 | printnightmare-cve-2021-1675 usage detection | endpoint | 🟡 medium | - | passed |
| 441 | PrintNightmare CVE-2021-1675 usage Detection | endpoint | 🟡 medium | - | passed |
| 442 | Private Key Files | endpoint | 🟡 medium | - | passed |
| 443 | procdump-lsass-credentials | endpoint | 🟡 medium | - | passed |
| 444 | PSExec Attrib commands | endpoint | 🟡 medium | - | passed |
| 445 | python-use-by-ransomware-macos | endpoint | 🟡 medium | - | passed |
| 446 | qakbot-campaign-esentutl | endpoint | 🟡 medium | - | passed |
| 447 | qakbot-campaign-outlook | endpoint | 🟡 medium | - | passed |
| 448 | qakbot-campaign-process-injection | endpoint | 🟡 medium | - | passed |
| 449 | qakbot-campaign-self-deletion | endpoint | 🟡 medium | - | passed |
| 450 | qakbot-campaign-suspicious-javascript | endpoint | 🟡 medium | - | passed |
| 451 | Qakbot Campaign Self Deletion | endpoint | 🟡 medium | T1070 | passed |
| 452 | Qakbot Campaign Self Deletion | endpoint | 🟡 medium | - | passed |
| 453 | Qakbot email theft | endpoint | 🟡 medium | - | passed |
| 454 | Qakbot email theft (1) | endpoint | 🟡 medium | - | passed |
| 455 | Quarantine release trend | m365 | 🟡 medium | T1566 | passed |
| 456 | Quarantine release trend | m365 | 🟡 medium | T1566 | passed |
| 457 | Ransomware hits healthcare - Alternate Data Streams use | endpoint | 🟡 medium | - | passed |
| 458 | Ransomware hits healthcare - Cipher.exe tool deleting data | endpoint | 🟡 medium | - | passed |
| 459 | Ransomware hits healthcare - Clearing of system logs | endpoint | 🟡 medium | - | passed |
| 460 | Ransomware hits healthcare - Robbinhood activity | endpoint | 🟡 medium | - | passed |
| 461 | Ransomware hits healthcare - Turning off System Restore | endpoint | 🟡 medium | - | passed |
| 462 | Ransomware hits healthcare - Vulnerable Gigabyte drivers | endpoint | 🟡 medium | - | passed |
| 463 | rce-on-vulnerable-server | endpoint | 🟡 medium | - | passed |
| 464 | recon-with-rundll | endpoint | 🟡 medium | - | passed |
| 465 | Recon with Rundll | endpoint | 🟡 medium | - | passed |
| 466 | RedMenshen-BPFDoor-backdoor | endpoint | 🟡 medium | T1095, T1059.004, T1070 | passed |
| 467 | reverse-shell-ransomware-macos | endpoint | 🟡 medium | - | passed |
| 468 | robbinhood-driver | endpoint | 🟡 medium | - | passed |
| 469 | robbinhood-evasion | endpoint | 🟡 medium | - | passed |
| 470 | Robbinhood Driver | endpoint | 🟡 medium | - | passed |
| 471 | Rundll32 (LOLBins and LOLScripts, Normalized Process Events) | endpoint | 🟡 medium | T1218.011 | passed |
| 472 | RunDLL Suspicious Network Connection | endpoint | 🟡 medium | - | passed |
| 473 | shimcache-flushed | endpoint | 🟡 medium | T1112 | passed |
| 474 | SlackAudit - Deactivated users | m365 | 🟡 medium | T1531 | passed |
| 475 | SlackAudit - New User created | m365 | 🟡 medium | T1136 | passed |
| 476 | SlackAudit - User logins by IP | m365 | 🟡 medium | T1078 | passed |
| 477 | SlackAudit - User Permission Changed | m365 | 🟡 medium | T1078 | passed |
| 478 | SlackAudit - User role changed to admin or owner | m365 | 🔵 low | T1098, T1078 | passed |
| 479 | snip3-encoded-powershell-structure | endpoint | 🟡 medium | - | passed |
| 480 | snip3-malicious-network-connectivity | endpoint | 🟡 medium | - | passed |
| 481 | snip3-revengerat-c2-exfiltration | endpoint | 🟡 medium | - | passed |
| 482 | Snip3 Malicious Network Connectivity | endpoint | 🟡 medium | - | passed |
| 483 | SOCRadar Audit Analysis | azure_custom | 🔵 low | T1526 | passed |
| 484 | SolarWinds Inventory | endpoint | 🟡 medium | T1072 | passed |
| 485 | Spoolsv Spawning Rundll32 | endpoint | 🟡 medium | - | passed |
| 486 | Spoolsv Spawning Rundll32 | endpoint | 🟡 medium | - | passed |
| 487 | Sticky Keys | m365 | 🟡 medium | - | passed |
| 488 | Stolen Images Execution | endpoint | 🟡 medium | - | passed |
| 489 | Stopping multiple processes using taskkill | endpoint | 🟡 medium | T1562 | passed |
| 490 | Stopping multiple processes using taskkill | endpoint | 🟡 medium | - | passed |
| 491 | Stopping multiple processes using taskkill | endpoint | 🟡 medium | - | passed |
| 492 | Stopping processes using net stop | endpoint | 🟡 medium | - | passed |
| 493 | StrRAT-AV-Discovery | endpoint | 🟡 medium | - | passed |
| 494 | StrRAT-Malware-Persistence | endpoint | 🟡 medium | - | passed |
| 495 | SUNBURST and SUPERNOVA backdoor hashes | endpoint | 🟠 high | T1195, T1059, T1546 | passed |
| 496 | SUNBURST and SUPERNOVA backdoor hashes (Normalized File Events) | endpoint | 🟠 high | T1195, T1059, T1546 | passed |
| 497 | SUNBURST network beacons | endpoint | 🟡 medium | T1195, T1059, T1546 | passed |
| 498 | SUNBURST suspicious SolarWinds child processes (Normalized Process Events) | endpoint | 🟡 medium | T1059, T1543 | passed |
| 499 | Suspicious Bitlocker Encryption | endpoint | 🟡 medium | - | passed |
| 500 | Suspicious files in spool folder | endpoint | 🟡 medium | - | passed |
| 501 | Suspicious Files in spool Folder | endpoint | 🟡 medium | - | passed |
| 502 | Suspicious Image Load related to IcedId | endpoint | 🟡 medium | - | passed |
| 503 | Suspicious Image Load related to IcedId | endpoint | 🟡 medium | - | passed |
| 504 | Suspicious JScript staging comment | endpoint | 🟡 medium | - | passed |
| 505 | Suspicious parentprocess relationship - Office child processes. | endpoint | 🟡 medium | T1566.002 | passed |
| 506 | Suspicious PowerShell curl flags | endpoint | 🟡 medium | - | passed |
| 507 | Suspicious process event creation from VMWare Horizon TomcatService | endpoint | 🟡 medium | - | passed |
| 508 | Suspicious Process Injection from Office application | endpoint | 🟡 medium | T1204 | passed |
| 509 | Suspicious Tomcat Confluence Process Launch | endpoint | 🟡 medium | T1203 | passed |
| 510 | Suspicious Tomcat Confluence Process Launch | endpoint | 🟡 medium | T1203 | passed |
| 511 | Teams Malware ZAP | m365 | 🟡 medium | T1566 | passed |
| 512 | Teams Malware ZAP | m365 | 🟡 medium | T1566 | passed |
| 513 | Teams Phish ZAP | m365 | 🟡 medium | T1566 | passed |
| 514 | Teams Phish ZAP | m365 | 🟡 medium | T1566 | passed |
| 515 | Teams Spam ZAP | m365 | 🟡 medium | T1566 | passed |
| 516 | Teams Spam ZAP | m365 | 🟡 medium | T1566 | passed |
| 517 | TEARDROP memory-only dropper | endpoint | 🟠 high | T1543, T1059, T1027 | passed |
| 518 | test | azure_custom |  test | T1190, T1133 | passed |
| 519 | Threat actor Phosphorus masquerading as conference organizers | m365 | 🟡 medium | - | passed |
| 520 | tomcat-8-executing-powershell | endpoint | 🟡 medium | - | passed |
| 521 | Tomcat - Catalina errors | network | 🟡 medium | T1070 | passed |
| 522 | Tomcat - Commands in URI | network | 🟠 high | T1190, T1133 | passed |
| 523 | Tomcat - Known malicious user agent | network | 🟠 high | T1190, T1133 | passed |
| 524 | Tomcat - Multiple client errors from single IP address | network | 🟡 medium | T1190, T1133 | passed |
| 525 | Tomcat - Multiple server errors from single IP address | network | 🟡 medium | T1498, T1190, T1133 | passed |
| 526 | Top 10 External Senders (Malware) | m365 | 🟡 medium | T1566 | passed |
| 527 | Top 10 External Senders (Malware) | m365 | 🟡 medium | T1566 | passed |
| 528 | Top 10 External Senders (Phish) | m365 | 🟡 medium | T1566 | passed |
| 529 | Top 10 External Senders (Phish) | m365 | 🟡 medium | T1566 | passed |
| 530 | Top 10 External Senders (Spam) | m365 | 🟡 medium | T1566 | passed |
| 531 | Top 10 External Senders (Spam) | m365 | 🟡 medium | T1566 | passed |
| 532 | Top 10 External Senders (Spam) | m365 | 🟡 medium | T1566 | passed |
| 533 | Top 10 External Senders (Spam) | m365 | 🟡 medium | T1566 | passed |
| 534 | Top 10 Targeted Users (Malware+Phish+Spam) | m365 | 🟡 medium | T1566 | passed |
| 535 | Top 10 Targeted Users (Malware+Phish+Spam) | m365 | 🟡 medium | T1566 | passed |
| 536 | Top 10 Users clicking on Malicious URLs (Malware) | m365 | 🟡 medium | T1566 | passed |
| 537 | Top 10 Users clicking on Malicious URLs (Malware) | m365 | 🟡 medium | T1566 | passed |
| 538 | Top 10 Users clicking on Malicious URLs (Malware+Phish+Spam) | m365 | 🟡 medium | T1566 | passed |
| 539 | Top 10 Users clicking on Malicious URLs (Malware+Phish+Spam) | m365 | 🟡 medium | T1566 | passed |
| 540 | Top 10 Users clicking on Malicious URLs (Phish) | m365 | 🟡 medium | T1566 | passed |
| 541 | Top 10 Users clicking on Malicious URLs (Phish) | m365 | 🟡 medium | T1566 | passed |
| 542 | Top 10 Users clicking on Malicious URLs (Spam) | m365 | 🟡 medium | T1566 | passed |
| 543 | Top 10 Users clicking on Malicious URLs (Spam) | m365 | 🟡 medium | T1566 | passed |
| 544 | Top external malicious senders | m365 | 🟡 medium | T1566 | passed |
| 545 | Top external malicious senders | m365 | 🟡 medium | T1566 | passed |
| 546 | Top malicious URLs clicked by users in Teams | m365 | 🟡 medium | T1566 | passed |
| 547 | Top malicious URLs clicked by users in Teams | m365 | 🟡 medium | T1566 | passed |
| 548 | Top targeted users | m365 | 🟡 medium | T1566 | passed |
| 549 | Top targeted users | m365 | 🟡 medium | T1566 | passed |
| 550 | Top Users receiving Malware | m365 | 🟡 medium | T1566 | passed |
| 551 | Top Users receiving Malware | m365 | 🟡 medium | T1566 | passed |
| 552 | Top Users receiving Phish | m365 | 🟡 medium | T1566 | passed |
| 553 | Top Users receiving Phish | m365 | 🟡 medium | T1566 | passed |
| 554 | Total Submissions by Submission Type | m365 | 🟡 medium | T1566 | passed |
| 555 | Total Submissions by Submission Type | m365 | 🟡 medium | T1566 | passed |
| 556 | Trend Micro CAS - Ransomware infection | m365 | 🟠 high | T1486 | passed |
| 557 | Trend Micro CAS - Ransomware outbreak | m365 | 🟠 high | T1486 | passed |
| 558 | Trust Monitor Event | azure_custom | 🟡 medium | T1528, T1555 | passed |
| 559 | turn-off-system-restore | endpoint | 🟡 medium | - | passed |
| 560 | Turning off services using sc exe | endpoint | 🟡 medium | - | passed |
| 561 | Turning off services using sc exe | endpoint | 🟡 medium | - | passed |
| 562 | Turning off System Restore | endpoint | 🟡 medium | - | passed |
| 563 | Ubiquiti - connection to non-corporate DNS server | azure_custom | 🟡 medium | T1572, T1041 | passed |
| 564 | umworkerprocess-unusual-subprocess-activity | endpoint | 🟡 medium | - | passed |
| 565 | UMWorkerProcess Creating Webshell | endpoint | 🟡 medium | - | passed |
| 566 | Unusual identity creation using exchange powershell | endpoint | 🟠 high | T1136 | passed |
| 567 | URL Clicks by Action | m365 | 🟡 medium | T1566 | passed |
| 568 | URL Clicks by Action | m365 | 🟡 medium | T1566 | passed |
| 569 | URL Detection | endpoint | 🟡 medium | - | passed |
| 570 | Use of MSBuild as LOLBin | endpoint | 🟡 medium | - | passed |
| 571 | Vaikora - Feed outage detection | azure_custom | 🔵 low | - | passed |
| 572 | Valence Security Alerts | azure_custom | 🟠 high | - | passed |
| 573 | VMWare-LPE-2022-22960 | endpoint | 🟡 medium | T1204, T1548 | passed |
| 574 | Vulerabilities | network | 🟠 high | T1189, T1059, T1053, T1548 | passed |
| 575 | Webserver Executing Suspicious Applications | endpoint | 🟡 medium | - | passed |
| 576 | Webserver Executing Suspicious Applications | endpoint | 🟡 medium | - | passed |
| 577 | Windows Anitivirus and EDR Elevation of Privilege Vulnerability | endpoint | 🟡 medium | t1574 | passed |
| 578 | Windows Print Spooler Service Suspicious File Creation | endpoint | 🟡 medium | T1574 | passed |
| 579 | Windows Spooler Service Suspicious File Creation | endpoint | 🟡 medium | t1574 | passed |
| 580 | Windows System Shutdown/Reboot (Normalized Process Events) | endpoint | 🟡 medium | T1529 | passed |
| 581 | Windows System Shutdown/Reboot (Normalized Process Events) | azure_custom | 🟡 medium | T1529 | passed |
| 582 | winrar-cve-2018-20250-ace-files | endpoint | 🟡 medium | - | passed |
| 583 | winrar-cve-2018-20250-file-creation | endpoint | 🟡 medium | - | passed |
| 584 | ZeroFox Alerts - High Severity Alerts | azure_custom | 🟠 high | T1583, T1586, T1566 | passed |
| 585 | ZeroFox Alerts - Informational Severity Alerts | azure_custom | ⚪ informational | T1583, T1586, T1566 | passed |
| 586 | ZeroFox Alerts - Low Severity Alerts | azure_custom | 🔵 low | T1583, T1586, T1566 | passed |
| 587 | ZeroFox Alerts - Medium Severity Alerts | azure_custom | 🟡 medium | T1583, T1586, T1566 | passed |
| 588 | Zip-Doc - Word Launching MSHTA | endpoint | 🟡 medium | - | passed |
| 589 | Zscaler - Applications using by accounts | azure_custom | 🔵 low | T1190, T1133 | passed |
| 590 | Zscaler - Unexpected event count of rejects by policy | azure_custom | 🟠 high | T1078, T1133 | passed |

## App / APM Queries

| # | Title | Type | Severity | MITRE |
|---|-------|------|----------|-------|
| 1 | APM: Browser Attack to WAF Block Correlation | Curated application analytics | 🟠 high | T1190 |
| 2 | APM: Browser Fingerprinting via Canvas/WebGL/AudioContext | Source-derived browser detection | 🟡 medium | T1592.004 |
| 3 | APM: Clickjacking - Missing Frame Protection Headers | Source-derived browser detection | 🟡 medium | T1185 |
| 4 | APM: CSRF Token Missing or Invalid on State-Changing Request | Source-derived browser detection | 🟡 medium | T1185 |
| 5 | APM: DOM-Based Attack via Dangerous JavaScript APIs | Source-derived browser detection | 🟠 high | T1059.007 |
| 6 | APM: Octo Demo API Gateway Edge Decisions | Curated application analytics | 🟠 high | - |
| 7 | APM: Octo Demo Attack Path Link | Curated application analytics | 🔴 critical | - |
| 8 | APM: Octo Demo Attack Timeline | Curated application analytics | 🟠 high | - |
| 9 | APM: Octo Demo Attack Trace Correlation | Curated application analytics | 🟠 high | - |
| 10 | APM: Octo Demo Compromised VM Pivots | Curated application analytics | 🔴 critical | - |
| 11 | APM: Octo Demo Database Spans | Curated application analytics | 🟡 medium | - |
| 12 | APM: Octo Demo Error Logs by Span | Curated application analytics | 🟠 high | - |
| 13 | APM: Octo Demo Java Sidecar Error Correlation | Curated application analytics | 🟡 medium | - |
| 14 | APM: Octo Demo Metric Samples | Curated application analytics | ⚪ informational | - |
| 15 | APM: Octo Demo OSQuery Host Evidence | Curated application analytics | 🟠 high | - |
| 16 | APM: Octo Demo Payment Threats | Curated application analytics | 🔴 critical | - |
| 17 | APM: Octo Demo RED Metrics | Curated application analytics | ⚪ informational | - |
| 18 | APM: Octo Demo Request and Error Timeline | Curated application analytics | ⚪ informational | - |
| 19 | APM: Octo Demo API Gateway Threat Detection Rule | Curated application analytics | 🟠 high | - |
| 20 | APM: Octo Demo Compromised VM Detection Rule | Curated application analytics | 🔴 critical | - |
| 21 | APM: Octo Demo Java Payment Error Detection Rule | Curated application analytics | 🟠 high | - |
| 22 | APM: Octo Demo Payment Interception Detection Rule | Curated application analytics | 🔴 critical | - |
| 23 | APM: Octo Demo Payment Redirect Detection Rule | Curated application analytics | 🔴 critical | - |
| 24 | APM: Octo Demo Span Latency Hotspots | Curated application analytics | 🟡 medium | - |
| 25 | APM: Octo Demo Span Link Analysis | Curated application analytics | 🟡 medium | - |
| 26 | APM: Octo Demo Trace Investigation Tiles | Curated application analytics | 🟠 high | - |
| 27 | APM: Octo Demo Trace to Log Correlation | Curated application analytics | 🟡 medium | - |
| 28 | APM: OWASP Attack Volume by Service | Curated application analytics | ⚪ informational | T1190 |
| 29 | APM: Session Hijacking - Rapid Session Changes | Source-derived browser detection | 🟠 high | T1539, T1550.004 |
| 30 | APM: SQL Injection Attack in Request | Source-derived browser detection | 🔴 critical | T1190 |
| 31 | APM: Suspicious JavaScript Execution Patterns | Source-derived browser detection | 🟠 high | T1059.007, T1056.001, T1496 |
| 32 | APM: Total Browser Attacks (24h) | Curated application analytics | ⚪ informational | T1190 |
| 33 | APM: Browser Attack Trace Correlation | Curated application analytics | 🟠 high | T1190, T1059.007 |
| 34 | APM: Cross-Site Scripting (XSS) Attack in Request | Source-derived browser detection | 🟠 high | T1189, T1059.007 |
| 35 | Application Authentication Brute Force | Curated application analytics | 🟠 high | T1110, T1110.003 |
| 36 | Cross-Service Trace Correlation (CRM ↔ Drone Shop) | Curated application analytics | ⚪ informational | - |
| 37 | Database Performance Correlation (ATP → APM → Logs) | Curated application analytics | ⚪ informational | - |
| 38 | Application Error Rate by Service | Curated application analytics | 🟠 high | T1499 |
| 39 | Order Sync Pipeline Health (Drone Shop → CRM) | Curated application analytics | 🟡 medium | - |
| 40 | OWASP Attack Detection (CRM + Drone Shop) | Curated application analytics | 🔴 critical | T1190, T1059, T1110 |
| 41 | Request Rate by Service and Endpoint | Curated application analytics | ⚪ informational | - |
| 42 | Security Attack Source IP Analysis | Curated application analytics | 🟠 high | T1190, T1110 |
| 43 | Application Service Health Timeline | Curated application analytics | ⚪ informational | - |
| 44 | Slow Request Detection (>2s) | Curated application analytics | 🟡 medium | T1499 |
| 45 | SQL Injection and XSS Attack Detection | Curated application analytics | 🔴 critical | T1190, T1059.007 |
| 46 | WAF Signal Correlation with Application Traces | Curated application analytics | 🟠 high | T1562, T1190 |
| 47 | ATLAS: Adversarial / Obfuscated Input to ML Endpoint (AML.T0043) | Curated application analytics | 🟡 medium | - |
| 48 | ATLAS: LLM Jailbreak Attempt Against Application (AML.T0054) | Curated application analytics | 🟠 high | - |
| 49 | ATLAS: LLM Sensitive-Information Disclosure Attempt (AML.T0057) | Curated application analytics | 🟠 high | - |
| 50 | ATLAS: Bulk Extraction via ML Inference API (AML.T0024 / AML.T0040) | Curated application analytics | 🟡 medium | T1567 |
| 51 | ATLAS: Unauthorized ML Inference API Access (AML.T0040) | Curated application analytics | 🟡 medium | - |
| 52 | ATLAS: Denial of ML Service / Inference Flood (AML.T0029 / AML.T0046) | Curated application analytics | 🟡 medium | T1499 |
| 53 | ATLAS: LLM Prompt Injection in Application Request (AML.T0051) | Curated application analytics | 🟠 high | - |
| 54 | OKE: Boopkit Attack Timeline | Curated application analytics | 🔴 critical | - |
| 55 | OKE: eBPF Rootkit Activity | Curated application analytics | 🔴 critical | - |
| 56 | OKE: Exec and Node Escape | Curated application analytics | 🟠 high | - |
| 57 | OKE: Kubernetes Attack Overview | Curated application analytics | 🟠 high | - |
| 58 | OKE: Kubernetes Attack Path Link | Curated application analytics | 🟠 high | - |
| 59 | OKE: Privileged Workload Creation | Curated application analytics | 🔴 critical | - |
| 60 | OKE: Boopkit eBPF Rootkit Detection Rule | Curated application analytics | 🔴 critical | - |
| 61 | OKE: Privileged Kubernetes Workload Detection Rule | Curated application analytics | 🔴 critical | - |
| 62 | OKE: Secrets and RBAC Abuse | Curated application analytics | 🔴 critical | - |

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
| 9 | C2: Affected Hosts KPI | - | 🔴 critical | T1071, T1095 |
| 10 | C2: Beacon Activity Timeline | - | 🟠 high | T1071, T1071.001, T1071.004 |
| 11 | C2: Communication Topology | - | 🔴 critical | T1071, T1095 |
| 12 | C2: Destination IP Drilldown | - | 🔴 critical | T1071.001, T1041 |
| 13 | C2: DNS Beacon Queries KPI | - | 🟠 high | T1071.004 |
| 14 | C2: DNS Beacon Sources | - | 🟠 high | T1071.004 |
| 15 | C2: Flow Connections KPI | - | 🔴 critical | T1071.001, T1041 |
| 16 | C2: HTTPS Beaconing Drilldown | - | 🔴 critical | T1071.001 |
| 17 | C2: Top DNS Beacon Domains | - | 🟠 high | T1071.004, T1048.003 |
| 18 | C2: Unique DNS Domains KPI | - | 🟡 medium | T1071.004, T1568.002 |
| 19 | ClickFix: Clipboard PowerShell Execution | - | 🔴 critical | T1566, T1204, T1059.001, T1027 |
| 20 | ClickFix: LOLBin Payload Execution | - | 🟠 high | T1218, T1218.005, T1218.011, T1059.007 |
| 21 | Cloud Identity: AiTM Token Abuse | - | 🔴 critical | T1528, T1538, T1530 |
| 22 | 2025-2026: Compromised Machines and Data | - | 🟠 high | T1566, T1059, T1528, T1041 |
| 23 | Coordinator Scenarios: Affected Hosts (l7d) | - | 🟠 high | - |
| 24 | Coordinator Scenarios: Attack Timeline (l7d) | - | 🟠 high | - |
| 25 | Coordinator Scenarios: Critical Alerts (l7d) | - | 🔴 critical | - |
| 26 | Coordinator Scenarios: Log Source → Process (l7d) | - | 🟠 high | - |
| 27 | Coordinator Scenarios: Distinct Processes Observed (l7d) | - | 🟠 high | - |
| 28 | Coordinator Scenarios: Log Source Breakdown (l7d) | - | 🟠 high | - |
| 29 | Coordinator Scenarios: Top Affected Hosts (l7d) | - | 🟠 high | - |
| 30 | Coordinator Scenarios: Total Hits (l7d) | - | 🔴 critical | - |
| 31 | CrashFix: Python RAT Activity | - | 🔴 critical | T1059.006, T1105, T1071.001 |
| 32 | Hunting: Credential Attack Correlation (PowerShell + Mimikatz + Kerberoast) | - | 🔴 critical | T1003.001, T1558.003, T1059.001 |
| 33 | Attack Activity Timeline by Log Source (l21d) | - | ⚪ informational | - |
| 34 | Cloud: Critical OCI Audit Events (l21d) | - | 🔴 critical | - |
| 35 | Top Attacker Source IPs - OCI Audit (l21d) | - | 🟠 high | - |
| 36 | DNS Exfiltration Detection (Entropy Analysis) | field_analysis | 🟠 high | T1048, T1071.004 |
| 37 | 2025-2026: Exfiltration After Initial Access | - | 🔴 critical | T1530, T1041, T1567 |
| 38 | FLF: BITS Exfiltration Hunt | free_lab_friday_source_hunt | 🟠 high | T1197, T1048.003 |
| 39 | FLF: Cloud Service Exfiltration Hunt | free_lab_friday_source_hunt | 🔴 critical | T1071.001, T1567, T1567.002 |
| 40 | FLF: Credential Stuffing Pattern | free_lab_friday_source_hunt | 🟠 high | T1110.004, T1078 |
| 41 | FLF: DNS C2 Pattern Analysis | free_lab_friday_source_hunt | 🟠 high | T1071.004, T1048.003 |
| 42 | FLF: Domain Fronting CDN C2 Hunt | free_lab_friday_source_hunt | 🟠 high | T1090.004, T1071.001 |
| 43 | FLF: New User Persistence | free_lab_friday_source_hunt | 🔴 critical | T1136.001, T1136.002 |
| 44 | FLF: Port Knocking Sequence Drilldown | free_lab_friday_source_hunt | 🟡 medium | T1021.004, T1095 |
| 45 | FLF: vsagent HTTP Beaconing | free_lab_friday_source_hunt | 🔴 critical | T1071.001, T1041 |
| 46 | Hunting: GOAD/Apex Caldera Attack Chain (Multi-Stage) | - | 🔴 critical | T1003.006, T1558.003, T1110.001, T1134, T1550.003 |
| 47 | Hunting: GOAD/Apex Caldera Sandcat Agent Activity | - | 🔴 critical | T1053.005, T1036, T1071.001, T1562.001 |
| 48 | Hunting: Kerberoasting Anomaly - RC4 vs AES Encryption Ratio | - | 🔴 critical | T1558.003 |
| 49 | Linux Data Staging and Exfiltration Indicators | combined_scoring | 🟠 high | T1560.001, T1074.001 |
| 50 | Linux Multi-Stage Attack Indicators (Combined Methods) | multi_stage | 🔴 critical | T1110, T1059.004 |
| 51 | Linux Unusual Outbound Connection Frequency | - | 🟡 medium | T1071, T1041 |
| 52 | Linux Persistence Indicator Score (Combined Methods) | scoring | 🟠 high | T1053, T1543.002, T1098.004 |
| 53 | Linux Process Execution from Unusual Paths | - | 🟡 medium | T1059, T1036.005 |
| 54 | Linux Rare Process Detection (Stacking) | rare_value | 🟡 medium | T1059.004 |
| 55 | Linux Rare Process Execution by Host | - | 🟡 medium | T1059, T1036 |
| 56 | Linux User Privilege Change Correlation | - | 🟡 medium | T1548.003, T1003 |
| 57 | Hunting: Logon Anomaly - Account Activity Profiling | - | 🟠 high | T1078, T1021, T1134 |
| 58 | MELTS: Attack Path Link Drilldown | - | 🔴 critical | T1566, T1059, T1218, T1071.001, T1041 |
| 59 | MELTS: 2025-2026 Attack Signal Overview | - | 🔴 critical | T1566, T1059.001, T1218, T1219, T1071.001, T1530, T1041 |
| 60 | MELTS: 2025-2026 Attack Timeline | - | 🟠 high | T1566, T1059, T1071, T1041 |
| 61 | Geographic Health: Cloud Provider Summary | aggregation | ⚪ informational | - |
| 62 | Geographic Health: Instance Detail with Coordinates | detail_view | ⚪ informational | - |
| 63 | Geographic Health: Regional Status on Global Map | geographic_analysis | ⚪ informational | - |
| 64 | Geographic Health: Service Tier Status | aggregation | ⚪ informational | - |
| 65 | Geographic Health: Unhealthy Regions Alert | alerting | 🟠 high | - |
| 66 | C2 Beaconing Detection (Periodic Connection Analysis) | frequency_analysis | 🟠 high | T1071, T1573 |
| 67 | OCI After-Hours IAM Activity (Time-Based Anomaly) | time_anomaly | 🟡 medium | T1098 |
| 68 | OCI API Call Burst by User | - | 🟡 medium | T1119, T1530 |
| 69 | OCI Console Login Brute Force (Frequency Analysis) | frequency_analysis | 🟠 high | T1078, T1110 |
| 70 | OCI Cross-Compartment Activity Anomaly | - | 🟡 medium | T1087.004, T1580 |
| 71 | OCI Failed Action Spike by Source IP | - | 🟡 medium | T1110, T1078 |
| 72 | OCI IAM and Fusion Activity Correlation | grouping_correlation | 🟠 high | T1078, T1098 |
| 73 | OCI IAM Rapid Configuration Changes (Anomaly Detection) | anomaly_detection | 🟠 high | T1098, T1078 |
| 74 | OCI Multiple Users from Same IP (Grouping) | grouping | 🟠 high | T1078, T1110.004 |
| 75 | OCI Off-Hours Administrative Activity | - | 🟡 medium | T1078, T1098 |
| 76 | OCI Privilege Escalation Chain Detection | combined_scoring | 🔴 critical | T1098, T1078 |
| 77 | OCI Resource Deletion Wave | - | 🟡 medium | T1485, T1489 |
| 78 | OCI Resource Destruction Spike (Anomaly Detection) | anomaly_detection | 🔴 critical | T1485, T1489 |
| 79 | OCI Unusual API Caller - First Seen User-Agent | - | 🟡 medium | T1087, T1078 |
| 80 | Octo Chaos — Stale Scenario State | - | 🟡 medium | - |
| 81 | Octo Checkout — DB Slowness Correlated With Chaos | - | 🟡 medium | T1499 |
| 82 | Octo WAF Detections vs App 5xx | - | 🟡 medium | T1190 |
| 83 | RMM: Post-Compromise Remote Access Activity | - | 🟠 high | T1219, T1071.001 |
| 84 | SharePoint ToolShell: Exploitation Attempts | - | 🔴 critical | T1190, T1505.003 |
| 85 | SharePoint ToolShell: Webshell Post-Exploit | - | 🔴 critical | T1505.003, T1059 |
| 86 | SSH Brute Force Detection (Frequency Analysis) | frequency_analysis | 🟠 high | T1110.001 |
| 87 | Login Activity Time-Series Anomaly | time_series_anomaly | 🟠 high | T1078, T1110 |
| 88 | WAF Attack Frequency by Source IP (Frequency Analysis) | frequency_analysis | 🟠 high | T1190 |
| 89 | WAF Multi-Attack Vector Scoring (Combined Methods) | scoring | 🔴 critical | T1190, T1059 |
| 90 | SQL Injection Pattern Stacking (Rare Value Detection) | rare_value | 🟠 high | T1190 |
| 91 | Web Attack Geographic Anomaly (Rare Country Detection) | rare_value | 🟡 medium | T1190 |
| 92 | Web Application Brute Force Detection (Frequency Analysis) | frequency_analysis | 🟠 high | T1110.001, T1110.003 |
| 93 | Web Directory Scanning IP Clustering (Anomaly Detection) | anomaly_detection | 🟡 medium | T1595.002 |
| 94 | OWASP Multi-Stage Web Attack Chain (Combined Methods) | multi_stage | 🔴 critical | T1190, T1110, T1059 |
| 95 | Web Scanner Tool Identification (User Agent Stacking) | rare_value | 🟡 medium | T1595.002 |
| 96 | Web-to-Cloud: Attack Path Link Analysis | - | 🔴 critical | T1190, T1552.005, T1071.001, T1041 |
| 97 | Web-to-Cloud: Correlated Attack Timeline | - | 🔴 critical | T1190, T1552.005, T1071.001, T1041 |
| 98 | Web-to-Cloud: OCI Audit Cloud Abuse | - | 🔴 critical | T1580, T1530, T1567 |
| 99 | Web-to-Cloud: Compromised Cloud Identity | - | 🔴 critical | T1552.005, T1580, T1530 |
| 100 | Web-to-Cloud: Compromised Machines | - | 🟠 high | T1059, T1071.001 |
| 101 | Web-to-Cloud: Entry Point and SSRF Evidence | - | 🔴 critical | T1190 |
| 102 | Web-to-Cloud: Exfiltrated Data Evidence | - | 🔴 critical | T1530, T1041, T1567 |
| 103 | Web-to-Cloud: Network Firewall C2 and Threat Alerts | - | 🔴 critical | T1071.001, T1041 |
| 104 | Web-to-Cloud: MITRE Stage Breakdown | - | 🟠 high | T1190, T1552.005, T1071.001, T1041 |
| 105 | Web-to-Cloud: VCN Egress and Exfil Flows | - | 🔴 critical | T1071.001, T1041 |
| 106 | Windows High-Entropy DNS Queries | - | 🟡 medium | T1071.004, T1048.003 |
| 107 | Windows Lateral Movement Timeline | - | 🟡 medium | T1021.002, T1021.006, T1021.001 |
| 108 | Windows LOLBin Usage Frequency Anomaly | - | 🟡 medium | T1218, T1059 |
| 109 | Windows Rare Parent-Child Process Relationships | - | 🟡 medium | T1055, T1218 |
| 110 | Windows Credential Access Tool Cluster (Grouping) | grouping | 🔴 critical | T1003, T1558.003 |
| 111 | Windows Defense Evasion Score (Combined Methods) | scoring | 🔴 critical | T1562, T1548.002, T1070 |
| 112 | Windows Lateral Movement Tool Cluster (Grouping) | grouping | 🔴 critical | T1021, T1570 |
| 113 | Windows Suspiciously Long Command Line (Field Analysis) | field_analysis | 🟠 high | T1059.001, T1027 |
| 114 | Windows Process from Unusual Path (Rare Value Analysis) | rare_value | 🟠 high | T1204, T1036 |
| 115 | Windows Rare Process Detection (Stacking) | rare_value | 🟡 medium | T1059 |

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
*Generated from 522 Sigma source rules routed to 545 top-level detection queries and 8 browser app queries, plus 590 Microsoft Sentinel conversions, 54 curated app/APM analytics, and 115 hunting queries*