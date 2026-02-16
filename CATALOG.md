# Detection Rule Catalog

> **200 detection rules** + **20 hunting queries** | Auto-generated from Sigma YAML sources

## Summary

| Platform | Rules |
|----------|-------|
| OCI Cloud | 80 |
| Linux | 65 |
| Windows | 55 |

| Severity | Count |
|----------|-------|
| 🔴 Critical | 23 |
| 🟠 High | 63 |
| 🟡 Medium | 50 |
| 🔵 Low | 34 |
| ⚪ Informational | 30 |

**STIG Coverage:** 24 rules covering 12 controls (AC-17, AC-3, AC-6, AU-11, AU-12, CP-9, IA-2, IA-5, IA-8, SC-12, SC-28, SC-7)

## MITRE ATT&CK Coverage

**100 techniques** across **12 tactics**

### Initial Access (9 techniques)

| Technique | Rules |
|-----------|-------|
| T1059.004 | Linux Multi-Stage Attack Indicators (Combined Methods) |
| T1078 | OCI Console Login Failure, OCI Console Login from Unusual IP, +3 more |
| T1110 | Linux Multi-Stage Attack Indicators (Combined Methods), OCI Console Login Brute Force (Frequency Analysis), Login Activity Time-Series Anomaly |
| T1110.001 | SSH Brute Force Detection (Frequency Analysis) |
| T1110.003 | OCI Password Spraying Attack |
| T1110.004 | OCI Multiple Users from Same IP (Grouping) |
| T1133 | Linux External Remote Service Abuse |
| T1204.002 | Windows Spearphishing Attachment Execution |
| T1566.001 | Windows Spearphishing Attachment Execution |

### Execution (12 techniques)

| Technique | Rules |
|-----------|-------|
| T1027 | Windows Encoded PowerShell Execution, Windows Suspiciously Long Command Line (Field Analysis) |
| T1036 | Windows Process from Unusual Path (Rare Value Analysis) |
| T1059 | Linux Process Execution from /dev/shm, Linux Reverse Shell Detected, Windows Rare Process Detection (Stacking) |
| T1059.001 | Windows Encoded PowerShell Execution, Windows PowerShell Download Cradle, Windows Suspiciously Long Command Line (Field Analysis) |
| T1059.004 | Linux Bind Shell Listener, OCI Cloud Shell Session Started, +2 more |
| T1105 | Windows PowerShell Download Cradle |
| T1110 | Linux Multi-Stage Attack Indicators (Combined Methods) |
| T1127.001 | Windows MSBuild Execution for Code Bypass |
| T1204 | Suspicious Usage of base64, Suspicious Usage of chmod, +26 more |
| T1204.002 | Windows Spearphishing Attachment Execution |
| T1566.001 | Windows Spearphishing Attachment Execution |
| T1648 | OCI Function Invoked |

### Persistence (23 techniques)

| Technique | Rules |
|-----------|-------|
| T1053 | Linux Persistence Indicator Score (Combined Methods) |
| T1053.002 | Linux At Job Scheduled |
| T1053.003 | Linux Crontab Modification, Linux Suspicious Cron Job Content |
| T1053.005 | Windows Scheduled Task Creation via Schtasks |
| T1059.004 | Linux Multi-Stage Attack Indicators (Combined Methods) |
| T1078 | OCI IAM Rapid Configuration Changes (Anomaly Detection), OCI Privilege Escalation Chain Detection |
| T1098 | OCI User Password Reset by Admin, OCI After-Hours IAM Activity (Time-Based Anomaly), +2 more |
| T1098.001 | OCI Dynamic Group Created |
| T1098.004 | Linux SSH Authorized Keys Modified, Linux Persistence Indicator Score (Combined Methods) |
| T1110 | Linux Multi-Stage Attack Indicators (Combined Methods) |
| T1136.001 | Linux Password File Direct Modification |
| T1197 | Windows BITS Job Abuse for Persistence |
| T1219 | Windows Remote Access Tool Detected |
| T1505.003 | Linux Web Shell File Creation |
| T1543.002 | Linux Systemd Service Persistence, Linux Persistence Indicator Score (Combined Methods) |
| T1543.003 | Windows Service Creation via SC |
| T1546.003 | Windows WMI Event Subscription Persistence |
| T1546.004 | Linux Shell Profile Persistence |
| T1547.001 | Windows Registry Run Key Modification |
| T1547.006 | Linux Kernel Module Loaded from Temp Directory |
| T1548.001 | Linux Setuid Binary Creation |
| T1556.007 | OCI Identity Provider Created |
| T1574.006 | Linux LD_PRELOAD Library Hijacking |

### Privilege Escalation (7 techniques)

| Technique | Rules |
|-----------|-------|
| T1078 | OCI IAM Rapid Configuration Changes (Anomaly Detection), OCI Privilege Escalation Chain Detection |
| T1098 | OCI IAM Admin Policy Created with Manage All, OCI IAM Rapid Configuration Changes (Anomaly Detection), OCI Privilege Escalation Chain Detection |
| T1134 | Windows Access Token Manipulation |
| T1548.001 | Linux Setuid Binary Creation |
| T1548.002 | Windows UAC Bypass Attempt |
| T1548.003 | Linux Sudoers File Modification |
| T1611 | Linux Container Escape Attempt |

### Defense Evasion (30 techniques)

| Technique | Rules |
|-----------|-------|
| T1003.001 | Windows WDigest Authentication Enabled for Credential Harvesting |
| T1027 | Windows Encoded PowerShell Execution, Windows Suspiciously Long Command Line (Field Analysis) |
| T1036 | Windows Process from Unusual Path (Rare Value Analysis) |
| T1055.008 | Linux Process Injection via Ptrace |
| T1055.012 | Windows Process Hollowing Indicators |
| T1059 | Windows Rare Process Detection (Stacking) |
| T1059.001 | Windows Encoded PowerShell Execution, Windows Suspiciously Long Command Line (Field Analysis) |
| T1059.004 | Linux Rare Process Detection (Stacking) |
| T1070 | Windows Defense Evasion Score (Combined Methods) |
| T1070.001 | Windows Event Log Clearing |
| T1070.002 | Linux Log File Tampering |
| T1070.003 | Linux History File Cleared |
| T1098 | OCI After-Hours IAM Activity (Time-Based Anomaly) |
| T1105 | Windows Certutil Download or Decode |
| T1127.001 | Windows MSBuild Execution for Code Bypass |
| T1134 | Windows Access Token Manipulation |
| T1140 | Windows Certutil Download or Decode |
| T1197 | Windows BITS Job Abuse for Persistence |
| T1204 | Windows Process from Unusual Path (Rare Value Analysis) |
| T1218 | Windows LOLBin Usage: at, Windows LOLBin Usage: bitsadmin, +18 more |
| T1548.002 | Windows UAC Bypass Attempt, Windows Defense Evasion Score (Combined Methods) |
| T1562 | Windows Defense Evasion Score (Combined Methods) |
| T1562.001 | OCI Log Group Deleted, Windows AMSI Bypass Attempt |
| T1562.004 | OCI Network Firewall Policy Modified, Windows Firewall Rule Modification |
| T1562.007 | OCI Security List Allows All Protocols |
| T1562.008 | OCI Audit Configuration Changed |
| T1564.001 | Linux Hidden File or Directory Creation in Suspicious Location |
| T1565.001 | Linux Hosts File Modification |
| T1574.002 | Windows DLL Side-Loading via Suspicious Path |
| T1600 | OCI Vault Key Rotation Overdue |

### Credential Access (14 techniques)

| Technique | Rules |
|-----------|-------|
| T1003 | Windows Credential Access Tool Cluster (Grouping) |
| T1003.001 | Windows Credential Dumping via Procdump, Windows LSASS Memory Access, +2 more |
| T1003.003 | Windows NTDS.dit Database Extraction |
| T1003.007 | Linux Process Memory Access via /proc |
| T1005 | Linux Sensitive Data Collection from Local System |
| T1056.001 | Windows Keylogger Indicators |
| T1078 | OCI Console Login Brute Force (Frequency Analysis), Login Activity Time-Series Anomaly |
| T1098.001 | OCI Customer Secret Key Created |
| T1110 | OCI Console Login Brute Force (Frequency Analysis), Login Activity Time-Series Anomaly |
| T1110.001 | SSH Brute Force Detection (Frequency Analysis) |
| T1110.003 | OCI Password Spraying Attack |
| T1528 | OCI Auth Token Created |
| T1556 | OCI User MFA Not Enabled |
| T1558.003 | Windows Kerberoasting Attack, Windows Credential Access Tool Cluster (Grouping) |

### Discovery (8 techniques)

| Technique | Rules |
|-----------|-------|
| T1018 | Windows Remote System Discovery |
| T1033 | Linux System Owner and User Discovery |
| T1046 | Linux Network Service Scanning |
| T1082 | Linux Post-Exploitation Enumeration Script |
| T1087.001 | Windows Account Discovery Commands |
| T1087.002 | Windows Account Discovery Commands |
| T1135 | Windows Network Share Discovery |
| T1580 | OCI Cloud Infrastructure Discovery |

### Lateral Movement (6 techniques)

| Technique | Rules |
|-----------|-------|
| T1021 | OCI Bastion Session Created, OCI Instance Console Connection Created, +2 more |
| T1021.001 | Windows RDP Lateral Movement |
| T1021.002 | Windows PsExec Remote Execution |
| T1550.002 | Windows Pass-the-Hash Attack Indicators |
| T1569.002 | Windows PsExec Remote Execution |
| T1570 | Windows Lateral Movement Tool Cluster (Grouping) |

### Collection (7 techniques)

| Technique | Rules |
|-----------|-------|
| T1005 | Linux Sensitive Data Collection from Local System |
| T1056.001 | Windows Keylogger Indicators |
| T1074.001 | Windows Data Staging for Exfiltration, Linux Data Staging and Exfiltration Indicators |
| T1113 | Windows Screen Capture Activity |
| T1114 | OCI Notification Subscription Created |
| T1557 | Linux Suspicious Network Traffic Redirect |
| T1560.001 | Linux Archive Data Collected for Exfiltration, Linux Data Staging and Exfiltration Indicators |

### Command & Control (12 techniques)

| Technique | Rules |
|-----------|-------|
| T1048 | DNS Exfiltration Detection (Entropy Analysis) |
| T1059.001 | Windows PowerShell Download Cradle |
| T1071 | C2 Beaconing Detection (Periodic Connection Analysis) |
| T1071.004 | Linux DNS Tunneling Detected, DNS Exfiltration Detection (Entropy Analysis) |
| T1090 | Linux Proxy and Tunneling Tool Detected |
| T1090.001 | Linux Proxy and Tunneling Tool Detected |
| T1105 | Linux Suspicious Download to /tmp, Windows Certutil Download or Decode, Windows PowerShell Download Cradle |
| T1140 | Windows Certutil Download or Decode |
| T1219 | Windows Remote Access Tool Detected |
| T1572 | Linux SSH Tunneling Detected |
| T1573 | Linux Encrypted Channel C2 Communication, C2 Beaconing Detection (Periodic Connection Analysis) |
| T1573.002 | Linux Encrypted Channel C2 Communication |

### Exfiltration (6 techniques)

| Technique | Rules |
|-----------|-------|
| T1048 | Linux Exfiltration Over Alternative Protocol, DNS Exfiltration Detection (Entropy Analysis) |
| T1071.004 | DNS Exfiltration Detection (Entropy Analysis) |
| T1074.001 | Windows Data Staging for Exfiltration, Linux Data Staging and Exfiltration Indicators |
| T1537 | OCI Cross-Region Data Copy |
| T1560.001 | Linux Archive Data Collected for Exfiltration, Linux Data Staging and Exfiltration Indicators |
| T1567 | OCI Object Storage Pre-Authenticated Request Created |

### Impact (4 techniques)

| Technique | Rules |
|-----------|-------|
| T1485 | OCI Autonomous Database Terminated, OCI Compartment Deleted, +3 more |
| T1489 | OCI Network Load Balancer Deleted, OCI Resource Destruction Spike (Anomaly Detection) |
| T1490 | OCI KMS Key Scheduled for Deletion, Windows Boot Configuration Modified, Windows Shadow Copy Deletion |
| T1496 | Linux Cryptominer Activity Detected |

## All Detection Rules

### OCI Cloud (80 rules)

| # | Title | Severity | MITRE | STIG |
|---|-------|----------|-------|------|
| 1 | OCI Compartment Deleted | 🔴 critical | T1485 | AC-6 |
| 2 | OCI Database System Terminated | 🔴 critical | T1485 | CP-9 |
| 3 | OCI KMS Key Scheduled for Deletion | 🔴 critical | T1490 | - |
| 4 | OCI Log Group Deleted | 🔴 critical | T1562.001 | AU-11 |
| 5 | Cloud Guard Problem: Audit Log Retention | 🟠 high | - | - |
| 6 | Cloud Guard Problem: Bucket Public Read | 🟠 high | - | - |
| 7 | Cloud Guard Problem: Bucket Public Write | 🟠 high | - | - |
| 8 | Cloud Guard Problem: Group Has Too Many Admins | 🟠 high | - | - |
| 9 | Cloud Guard Problem: IAM User API Key Old | 🟠 high | - | - |
| 10 | Cloud Guard Problem: IAM User Console Password Old | 🟠 high | - | - |
| 11 | Cloud Guard Problem: INSTANCE PUBLIC IP | 🟠 high | - | - |
| 12 | Cloud Guard Problem: Instance Principals Enabled | 🟠 high | - | - |
| 13 | Cloud Guard Problem: Policy Too Permissive | 🟠 high | - | - |
| 14 | Cloud Guard Problem: VCN Flow Log Disabled | 🟠 high | - | - |
| 15 | Cloud Guard Problem: VCN Security List Port RDP | 🟠 high | - | - |
| 16 | Cloud Guard Problem: VCN Security List Port SSH | 🟠 high | - | - |
| 17 | OCI Audit Configuration Changed | 🟠 high | T1562.008 | AU-11 |
| 18 | OCI Autonomous Database Terminated | 🟠 high | T1485 | - |
| 19 | OCI Cross-Region Data Copy | 🟠 high | T1537 | SC-28 |
| 20 | OCI Customer Secret Key Created | 🟠 high | T1098.001 | IA-5 |
| 21 | OCI IAM Admin Policy Created with Manage All | 🟠 high | T1098 | - |
| 22 | OCI Identity Provider Created | 🟠 high | T1556.007 | IA-8 |
| 23 | OCI Instance Console Connection Created | 🟠 high | T1021 | AC-17 |
| 24 | OCI Network Firewall Policy Modified | 🟠 high | T1562.004 | SC-7 |
| 25 | OCI Network Load Balancer Deleted | 🟠 high | T1489 | - |
| 26 | OCI Object Storage Bucket Made Public | 🟠 high | - | - |
| 27 | OCI Object Storage Pre-Authenticated Request Created | 🟠 high | T1567 | AC-3 |
| 28 | OCI Password Spraying Attack | 🟠 high | T1110.003 | IA-2 |
| 29 | OCI Security List Allows All Protocols | 🟠 high | T1562.007 | SC-7 |
| 30 | OCI User MFA Not Enabled | 🟠 high | T1556 | IA-2 |
| 31 | OCI User Password Reset by Admin | 🟠 high | T1098 | IA-5 |
| 32 | OCI VCN Security List Open to World | 🟠 high | - | - |
| 33 | OCI Vault Secret Deleted | 🟠 high | T1485 | SC-28 |
| 34 | OCI API Key Uploaded | 🟡 medium | - | - |
| 35 | OCI Auth Token Created | 🟡 medium | T1528 | IA-5 |
| 36 | OCI Bastion Session Created | 🟡 medium | T1021 | AC-17 |
| 37 | OCI Compute Instance Terminated | 🟡 medium | - | - |
| 38 | OCI Console Login Failure | 🟡 medium | T1078 | - |
| 39 | OCI Console Login from Unusual IP | 🟡 medium | T1078 | - |
| 40 | OCI Dynamic Group Created | 🟡 medium | T1098.001 | AC-6 |
| 41 | OCI IAM Policy Modified | 🟡 medium | - | - |
| 42 | OCI Network Security Group Updated | 🟡 medium | - | - |
| 43 | OCI Notification Subscription Created | 🟡 medium | T1114 | AU-12 |
| 44 | OCI Route Table Update | 🟡 medium | - | - |
| 45 | OCI VCN Peering Connection Created | 🟡 medium | T1021 | SC-7 |
| 46 | OCI Vault Key Rotation Overdue | 🟡 medium | T1600 | SC-12 |
| 47 | OCI WAF Configuration Updated | 🟡 medium | - | - |
| 48 | OCI Cloud Infrastructure Discovery | 🔵 low | T1580 | AU-12 |
| 49 | OCI Cloud Shell Session Started | 🔵 low | T1059.004 | AU-12 |
| 50 | OCI Function Invoked | 🔵 low | T1648 | AU-12 |
| 51 | OCI Action: AddUserToGroup | ⚪ informational | - | - |
| 52 | OCI Action: AttachInternetGateway | ⚪ informational | - | - |
| 53 | OCI Action: CreateBucket | ⚪ informational | - | - |
| 54 | OCI Action: CreateGroup | ⚪ informational | - | - |
| 55 | OCI Action: CreateInstance | ⚪ informational | - | - |
| 56 | OCI Action: CreateInternetGateway | ⚪ informational | - | - |
| 57 | OCI Action: CreateKey | ⚪ informational | - | - |
| 58 | OCI Action: CreatePolicy | ⚪ informational | - | - |
| 59 | OCI Action: CreateRouteTable | ⚪ informational | - | - |
| 60 | OCI Action: CreateSecurityList | ⚪ informational | - | - |
| 61 | OCI Action: CreateSubnet | ⚪ informational | - | - |
| 62 | OCI Action: CreateUser | ⚪ informational | - | - |
| 63 | OCI Action: CreateVcn | ⚪ informational | - | - |
| 64 | OCI Action: DeleteBucket | ⚪ informational | - | - |
| 65 | OCI Action: DeleteGroup | ⚪ informational | - | - |
| 66 | OCI Action: DeleteInternetGateway | ⚪ informational | - | - |
| 67 | OCI Action: DeleteKey | ⚪ informational | - | - |
| 68 | OCI Action: DeletePolicy | ⚪ informational | - | - |
| 69 | OCI Action: DeleteSubnet | ⚪ informational | - | - |
| 70 | OCI Action: DeleteUser | ⚪ informational | - | - |
| 71 | OCI Action: DeleteVcn | ⚪ informational | - | - |
| 72 | OCI Action: DetachInternetGateway | ⚪ informational | - | - |
| 73 | OCI Action: RemoveUserFromGroup | ⚪ informational | - | - |
| 74 | OCI Action: StartInstance | ⚪ informational | - | - |
| 75 | OCI Action: StopInstance | ⚪ informational | - | - |
| 76 | OCI Action: TerminateInstance | ⚪ informational | - | - |
| 77 | OCI Action: UpdateBucket | ⚪ informational | - | - |
| 78 | OCI Action: UpdatePolicy | ⚪ informational | - | - |
| 79 | OCI Action: UpdateRouteTable | ⚪ informational | - | - |
| 80 | OCI Action: UpdateSecurityList | ⚪ informational | - | - |

### Linux (65 rules)

| # | Title | Severity | MITRE | STIG |
|---|-------|----------|-------|------|
| 1 | Linux Bind Shell Listener | 🔴 critical | T1059.004 | - |
| 2 | Linux Container Escape Attempt | 🔴 critical | T1611 | - |
| 3 | Linux Kernel Module Loaded from Temp Directory | 🔴 critical | T1547.006 | - |
| 4 | Linux Password File Direct Modification | 🔴 critical | T1136.001 | - |
| 5 | Linux Process Execution from /dev/shm | 🔴 critical | T1059 | - |
| 6 | Linux Reverse Shell Detected | 🔴 critical | T1059 | - |
| 7 | Linux Web Shell File Creation | 🔴 critical | T1505.003 | - |
| 8 | Linux Archive Data Collected for Exfiltration | 🟠 high | T1560.001 | - |
| 9 | Linux Cryptominer Activity Detected | 🟠 high | T1496 | - |
| 10 | Linux DNS Tunneling Detected | 🟠 high | T1071.004 | - |
| 11 | Linux Encrypted Channel C2 Communication | 🟠 high | T1573, T1573.002 | - |
| 12 | Linux Exfiltration Over Alternative Protocol | 🟠 high | T1048 | - |
| 13 | Linux LD_PRELOAD Library Hijacking | 🟠 high | T1574.006 | - |
| 14 | Linux Log File Tampering | 🟠 high | T1070.002 | - |
| 15 | Linux Network Service Scanning | 🟠 high | T1046 | - |
| 16 | Linux Post-Exploitation Enumeration Script | 🟠 high | T1082 | - |
| 17 | Linux Process Injection via Ptrace | 🟠 high | T1055.008 | - |
| 18 | Linux Process Memory Access via /proc | 🟠 high | T1003.007 | - |
| 19 | Linux Proxy and Tunneling Tool Detected | 🟠 high | T1090, T1090.001 | - |
| 20 | Linux SSH Authorized Keys Modified | 🟠 high | T1098.004 | - |
| 21 | Linux SSH Tunneling Detected | 🟠 high | T1572 | - |
| 22 | Linux Sensitive Data Collection from Local System | 🟠 high | T1005 | - |
| 23 | Linux Setuid Binary Creation | 🟠 high | T1548.001 | - |
| 24 | Linux Sudoers File Modification | 🟠 high | T1548.003 | - |
| 25 | Linux Suspicious Cron Job Content | 🟠 high | T1053.003 | - |
| 26 | Linux Suspicious Download to /tmp | 🟠 high | T1105 | - |
| 27 | Linux Suspicious Network Traffic Redirect | 🟠 high | T1557 | - |
| 28 | Linux At Job Scheduled | 🟡 medium | T1053.002 | - |
| 29 | Linux Crontab Modification | 🟡 medium | T1053.003 | - |
| 30 | Linux Hidden File or Directory Creation in Suspicious Location | 🟡 medium | T1564.001 | - |
| 31 | Linux History File Cleared | 🟡 medium | T1070.003 | - |
| 32 | Linux Hosts File Modification | 🟡 medium | T1565.001 | - |
| 33 | Linux Shell Profile Persistence | 🟡 medium | T1546.004 | - |
| 34 | Linux Systemd Service Persistence | 🟡 medium | T1543.002 | - |
| 35 | Linux External Remote Service Abuse | 🔵 low | T1133 | - |
| 36 | Linux SSH Failed Login | 🔵 low | - | - |
| 37 | Linux Sudo Usage | 🔵 low | - | - |
| 38 | Linux System Owner and User Discovery | 🔵 low | T1033 | - |
| 39 | Suspicious Usage of base64 | 🔵 low | T1204 | - |
| 40 | Suspicious Usage of chmod | 🔵 low | T1204 | - |
| 41 | Suspicious Usage of chown | 🔵 low | T1204 | - |
| 42 | Suspicious Usage of curl | 🔵 low | T1204 | - |
| 43 | Suspicious Usage of dd | 🔵 low | T1204 | - |
| 44 | Suspicious Usage of gdb | 🔵 low | T1204 | - |
| 45 | Suspicious Usage of id | 🔵 low | T1204 | - |
| 46 | Suspicious Usage of insmod | 🔵 low | T1204 | - |
| 47 | Suspicious Usage of lua | 🔵 low | T1204 | - |
| 48 | Suspicious Usage of modprobe | 🔵 low | T1204 | - |
| 49 | Suspicious Usage of nc | 🔵 low | T1204 | - |
| 50 | Suspicious Usage of ncat | 🔵 low | T1204 | - |
| 51 | Suspicious Usage of netcat | 🔵 low | T1204 | - |
| 52 | Suspicious Usage of nmap | 🔵 low | T1204 | - |
| 53 | Suspicious Usage of passwd | 🔵 low | T1204 | - |
| 54 | Suspicious Usage of perl | 🔵 low | T1204 | - |
| 55 | Suspicious Usage of python | 🔵 low | T1204 | - |
| 56 | Suspicious Usage of rmmod | 🔵 low | T1204 | - |
| 57 | Suspicious Usage of ruby | 🔵 low | T1204 | - |
| 58 | Suspicious Usage of shadow | 🔵 low | T1204 | - |
| 59 | Suspicious Usage of socat | 🔵 low | T1204 | - |
| 60 | Suspicious Usage of strace | 🔵 low | T1204 | - |
| 61 | Suspicious Usage of tcpdump | 🔵 low | T1204 | - |
| 62 | Suspicious Usage of tshark | 🔵 low | T1204 | - |
| 63 | Suspicious Usage of wget | 🔵 low | T1204 | - |
| 64 | Suspicious Usage of whoami | 🔵 low | T1204 | - |
| 65 | Suspicious Usage of wireshark | 🔵 low | T1204 | - |

### Windows (55 rules)

| # | Title | Severity | MITRE | STIG |
|---|-------|----------|-------|------|
| 1 | Windows Access Token Manipulation | 🔴 critical | T1134 | - |
| 2 | Windows Boot Configuration Modified | 🔴 critical | T1490 | - |
| 3 | Windows Credential Dumping via Procdump | 🔴 critical | T1003.001 | - |
| 4 | Windows Kerberoasting Attack | 🔴 critical | T1558.003 | - |
| 5 | Windows Keylogger Indicators | 🔴 critical | T1056.001 | - |
| 6 | Windows LSASS Memory Access | 🔴 critical | T1003.001 | - |
| 7 | Windows Mimikatz Execution Patterns | 🔴 critical | T1003.001 | - |
| 8 | Windows NTDS.dit Database Extraction | 🔴 critical | T1003.003 | - |
| 9 | Windows Pass-the-Hash Attack Indicators | 🔴 critical | T1550.002 | - |
| 10 | Windows Process Hollowing Indicators | 🔴 critical | T1055.012 | - |
| 11 | Windows Shadow Copy Deletion | 🔴 critical | T1490 | - |
| 12 | Windows Spearphishing Attachment Execution | 🔴 critical | T1566.001, T1204.002 | - |
| 13 | Windows AMSI Bypass Attempt | 🟠 high | T1562.001 | - |
| 14 | Windows BITS Job Abuse for Persistence | 🟠 high | T1197 | - |
| 15 | Windows Certutil Download or Decode | 🟠 high | T1140, T1105 | - |
| 16 | Windows DLL Side-Loading via Suspicious Path | 🟠 high | T1574.002 | - |
| 17 | Windows Encoded PowerShell Execution | 🟠 high | T1059.001, T1027 | - |
| 18 | Windows Event Log Clearing | 🟠 high | T1070.001 | - |
| 19 | Windows Firewall Rule Modification | 🟠 high | T1562.004 | - |
| 20 | Windows PowerShell Download Cradle | 🟠 high | T1059.001, T1105 | - |
| 21 | Windows PsExec Remote Execution | 🟠 high | T1021.002, T1569.002 | - |
| 22 | Windows Registry Run Key Modification | 🟠 high | T1547.001 | - |
| 23 | Windows Remote Access Tool Detected | 🟠 high | T1219 | - |
| 24 | Windows UAC Bypass Attempt | 🟠 high | T1548.002 | - |
| 25 | Windows WDigest Authentication Enabled for Credential Harvesting | 🟠 high | T1003.001 | - |
| 26 | Windows WMI Event Subscription Persistence | 🟠 high | T1546.003 | - |
| 27 | Windows Account Discovery Commands | 🟡 medium | T1087.001, T1087.002 | - |
| 28 | Windows Data Staging for Exfiltration | 🟡 medium | T1074.001 | - |
| 29 | Windows LOLBin Usage: at | 🟡 medium | T1218 | - |
| 30 | Windows LOLBin Usage: bitsadmin | 🟡 medium | T1218 | - |
| 31 | Windows LOLBin Usage: certutil | 🟡 medium | T1218 | - |
| 32 | Windows LOLBin Usage: cmd | 🟡 medium | T1218 | - |
| 33 | Windows LOLBin Usage: cscript | 🟡 medium | T1218 | - |
| 34 | Windows LOLBin Usage: ipconfig | 🟡 medium | T1218 | - |
| 35 | Windows LOLBin Usage: mshta | 🟡 medium | T1218 | - |
| 36 | Windows LOLBin Usage: net | 🟡 medium | T1218 | - |
| 37 | Windows LOLBin Usage: net1 | 🟡 medium | T1218 | - |
| 38 | Windows LOLBin Usage: powershell | 🟡 medium | T1218 | - |
| 39 | Windows LOLBin Usage: regsvr32 | 🟡 medium | T1218 | - |
| 40 | Windows LOLBin Usage: rundll32 | 🟡 medium | T1218 | - |
| 41 | Windows LOLBin Usage: sc | 🟡 medium | T1218 | - |
| 42 | Windows LOLBin Usage: schtasks | 🟡 medium | T1218 | - |
| 43 | Windows LOLBin Usage: systeminfo | 🟡 medium | T1218 | - |
| 44 | Windows LOLBin Usage: taskkill | 🟡 medium | T1218 | - |
| 45 | Windows LOLBin Usage: tasklist | 🟡 medium | T1218 | - |
| 46 | Windows LOLBin Usage: whoami | 🟡 medium | T1218 | - |
| 47 | Windows LOLBin Usage: wmic | 🟡 medium | T1218 | - |
| 48 | Windows LOLBin Usage: wscript | 🟡 medium | T1218 | - |
| 49 | Windows MSBuild Execution for Code Bypass | 🟡 medium | T1127.001 | - |
| 50 | Windows Network Share Discovery | 🟡 medium | T1135 | - |
| 51 | Windows RDP Lateral Movement | 🟡 medium | T1021.001 | - |
| 52 | Windows Remote System Discovery | 🟡 medium | T1018 | - |
| 53 | Windows Scheduled Task Creation via Schtasks | 🟡 medium | T1053.005 | - |
| 54 | Windows Screen Capture Activity | 🟡 medium | T1113 | - |
| 55 | Windows Service Creation via SC | 🟡 medium | T1543.003 | - |

## Hunting Queries

| # | Title | Method | Severity | MITRE |
|---|-------|--------|----------|-------|
| 1 | DNS Exfiltration Detection (Entropy Analysis) | field_analysis | 🟠 high | T1048, T1071.004 |
| 2 | Linux Data Staging and Exfiltration Indicators | combined_scoring | 🟠 high | T1560.001, T1074.001 |
| 3 | Linux Multi-Stage Attack Indicators (Combined Methods) | multi_stage | 🔴 critical | T1110, T1059.004 |
| 4 | Linux Persistence Indicator Score (Combined Methods) | scoring | 🟠 high | T1053, T1543.002, T1098.004 |
| 5 | Linux Rare Process Detection (Stacking) | rare_value | 🟡 medium | T1059.004 |
| 6 | C2 Beaconing Detection (Periodic Connection Analysis) | frequency_analysis | 🟠 high | T1071, T1573 |
| 7 | OCI After-Hours IAM Activity (Time-Based Anomaly) | time_anomaly | 🟡 medium | T1098 |
| 8 | OCI Console Login Brute Force (Frequency Analysis) | frequency_analysis | 🟠 high | T1078, T1110 |
| 9 | OCI IAM Rapid Configuration Changes (Anomaly Detection) | anomaly_detection | 🟠 high | T1098, T1078 |
| 10 | OCI Multiple Users from Same IP (Grouping) | grouping | 🟠 high | T1078, T1110.004 |
| 11 | OCI Privilege Escalation Chain Detection | combined_scoring | 🔴 critical | T1098, T1078 |
| 12 | OCI Resource Destruction Spike (Anomaly Detection) | anomaly_detection | 🔴 critical | T1485, T1489 |
| 13 | SSH Brute Force Detection (Frequency Analysis) | frequency_analysis | 🟠 high | T1110.001 |
| 14 | Login Activity Time-Series Anomaly | time_series_anomaly | 🟠 high | T1078, T1110 |
| 15 | Windows Credential Access Tool Cluster (Grouping) | grouping | 🔴 critical | T1003, T1558.003 |
| 16 | Windows Defense Evasion Score (Combined Methods) | scoring | 🔴 critical | T1562, T1548.002, T1070 |
| 17 | Windows Lateral Movement Tool Cluster (Grouping) | grouping | 🔴 critical | T1021, T1570 |
| 18 | Windows Suspiciously Long Command Line (Field Analysis) | field_analysis | 🟠 high | T1059.001, T1027 |
| 19 | Windows Process from Unusual Path (Rare Value Analysis) | rare_value | 🟠 high | T1204, T1036 |
| 20 | Windows Rare Process Detection (Stacking) | rare_value | 🟡 medium | T1059 |

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
*Generated from 200 Sigma rules + 20 hunting queries*