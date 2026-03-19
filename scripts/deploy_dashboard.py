"""
Deploy SOC detection dashboards to OCI Log Analytics.

Creates saved searches and organizes them into 10 SOC dashboards:
  1. SOC Overview Dashboard              - Cross-domain security summary
  2. SOC: OCI STIG Compliance            - STIG compliance: MFA, key rotation, audit, network
  3. SOC: OCI Audit Security             - IAM, Network, Compute, Storage, KMS, DB
  4. SOC: Cloud Guard Security           - Cloud Guard problem detection
  5. SOC: Linux Security                 - SSH, sudo, GTFOBins, reverse shells, persistence
  6. SOC: Windows Security               - LOLBins, encoded PowerShell, credential dumping
  7. SOC: Threat Hunting Dashboard       - Cookbook-inspired analytics (frequency, anomaly, scoring)
  8. SOC: Sysmon Network & Lateral       - Network connections, C2 beacons, DNS, named pipes
  9. SOC: Web Application Security       - OWASP Top 10 attack detection via WAF/LB/App logs
 10. SOC: Web Threat Hunting Dashboard   - Web attack hunting: frequency, stacking, scoring
 11. OCI-DEMO: Application 360 Monitoring - CRM + Drone Shop 360 observability (APM, logs, WAF, DB, security)

Usage:
  python3 scripts/deploy_dashboard.py              # Deploy all
  python3 scripts/deploy_dashboard.py --cleanup     # Delete existing SOC content first
  python3 scripts/deploy_dashboard.py --dry-run     # Print plan without executing
"""

import json
import os
import sys
import argparse
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from oci_config import (
    TENANCY_ID, COMPARTMENT_ID, QUERIES_DIR, HUNTING_DIR,
    get_dashboard_client, validate_oci_setup,
)

import oci


# ─── Dashboard Definitions ────────────────────────────────────────

DASHBOARDS = {
    "SOC Overview Dashboard": {
        "description": "Executive-level cross-domain security summary with critical alerts and hunting analytics.",
        "widgets": [
            {"title": "SOC: Console Login Failures", "query_file": "oci_console_login_failure.json"},
            {"title": "SOC: KMS Key Deletion Alert", "query_file": "oci_kms_key_scheduled_for_deletion.json"},
            {"title": "SOC: Reverse Shell Detection", "query_file": "linux_reverse_shell_detected.json"},
            {"title": "SOC: Credential Dumping Alert", "query_file": "windows_credential_dumping_via_procdump.json"},
            {"title": "SOC: Critical IAM Policy Changes", "query_file": "oci_iam_policy_modified.json"},
            {"title": "SOC: VCN Open to World", "query_file": "oci_vcn_security_list_open_to_world.json"},
            {"title": "SOC: SSH Failed Logins", "query_file": "linux_ssh_failed_login.json"},
            {"title": "SOC: Suspicious Linux Binaries", "query_file": "suspicious_usage_of_netcat.json"},
            {"title": "SOC: Shadow Copy Deletion", "query_file": "windows_shadow_copy_deletion.json"},
            {"title": "SOC: Compartment Deleted", "query_file": "oci_compartment_deleted.json"},
            {"title": "Hunt: SSH Brute Force", "query_file": "hunting/ssh_brute_force_frequency.json"},
            {"title": "Hunt: OCI Destruction Spike", "query_file": "hunting/oci_resource_destruction_spike.json"},
            {"title": "Hunt: Web Multi-Stage Attack", "query_file": "hunting/web_owasp_multi_stage_attack.json"},
            {"title": "Hunt: WAF Multi-Attack Score", "query_file": "hunting/waf_multi_attack_scoring.json"},
        ]
    },
    "SOC: OCI STIG Compliance Dashboard": {
        "description": "OCI STIG compliance monitoring: MFA, key rotation, audit configuration, network security, identity governance.",
        "widgets": [
            {"title": "STIG: MFA Disabled", "query_file": "oci_user_mfa_not_enabled.json"},
            {"title": "STIG: Identity Provider Created", "query_file": "oci_identity_provider_created.json"},
            {"title": "STIG: Dynamic Group Created", "query_file": "oci_dynamic_group_created.json"},
            {"title": "STIG: Auth Token Created", "query_file": "oci_auth_token_created.json"},
            {"title": "STIG: Compartment Deleted", "query_file": "oci_compartment_deleted.json"},
            {"title": "STIG: Audit Config Changed", "query_file": "oci_audit_configuration_changed.json"},
            {"title": "STIG: Key Rotation Update", "query_file": "oci_vault_key_rotation_overdue.json"},
            {"title": "STIG: Security List All Protocols", "query_file": "oci_security_list_allows_all_protocols.json"},
            {"title": "STIG: Network Firewall Modified", "query_file": "oci_network_firewall_policy_modified.json"},
            {"title": "STIG: VCN Peering Created", "query_file": "oci_vcn_peering_connection_created.json"},
            {"title": "STIG: Cross-Region Data Copy", "query_file": "oci_cross-region_data_copy.json"},
            {"title": "STIG: Pre-Auth Request Created", "query_file": "oci_object_storage_pre-authenticated_request_created.json"},
            {"title": "STIG: Cloud Shell Session", "query_file": "oci_cloud_shell_session_started.json"},
            {"title": "STIG: Function Invoked", "query_file": "oci_function_invoked.json"},
            {"title": "STIG: Vault Secret Deleted", "query_file": "oci_vault_secret_deleted.json"},
            {"title": "STIG: User Password Reset", "query_file": "oci_user_password_reset_by_admin.json"},
            {"title": "STIG: Customer Secret Key", "query_file": "oci_customer_secret_key_created.json"},
        ]
    },
    "SOC: OCI Audit Security Dashboard": {
        "description": "OCI Audit event monitoring: IAM, Network, Compute, Storage, KMS, and Database.",
        "widgets": [
            {"title": "OCI: Console Login from Unusual IP", "query_file": "oci_console_login_from_unusual_ip.json"},
            {"title": "OCI: Console Login Failure", "query_file": "oci_console_login_failure.json"},
            {"title": "OCI: IAM Policy Modified", "query_file": "oci_iam_policy_modified.json"},
            {"title": "OCI: Admin Policy - Manage All", "query_file": "oci_iam_admin_policy_created_with_manage_all.json"},
            {"title": "OCI: API Key Uploaded", "query_file": "oci_api_key_uploaded.json"},
            {"title": "OCI: Compute Instance Terminated", "query_file": "oci_compute_instance_terminated.json"},
            {"title": "OCI: Autonomous DB Terminated", "query_file": "oci_autonomous_database_terminated.json"},
            {"title": "OCI: DB System Terminated", "query_file": "oci_database_system_terminated.json"},
            {"title": "OCI: KMS Key Scheduled Deletion", "query_file": "oci_kms_key_scheduled_for_deletion.json"},
            {"title": "OCI: Load Balancer Deleted", "query_file": "oci_network_load_balancer_deleted.json"},
            {"title": "OCI: Bucket Made Public", "query_file": "oci_object_storage_bucket_made_public.json"},
            {"title": "OCI: NSG Updated", "query_file": "oci_network_security_group_updated.json"},
            {"title": "OCI: Route Table Updated", "query_file": "oci_route_table_update.json"},
            {"title": "OCI: WAF Configuration Updated", "query_file": "oci_waf_configuration_updated.json"},
            {"title": "OCI: VCN Security List Open", "query_file": "oci_vcn_security_list_open_to_world.json"},
            {"title": "OCI: Pre-Auth Request", "query_file": "oci_object_storage_pre-authenticated_request_created.json"},
            {"title": "OCI: Bastion Session Created", "query_file": "oci_bastion_session_created.json"},
            {"title": "OCI: Console Connection", "query_file": "oci_instance_console_connection_created.json"},
            {"title": "OCI: Notification Subscription", "query_file": "oci_notification_subscription_created.json"},
            {"title": "OCI: Log Group Deleted", "query_file": "oci_log_group_deleted.json"},
            {"title": "OCI: Cloud Infra Discovery", "query_file": "oci_cloud_infrastructure_discovery.json"},
            {"title": "OCI: Password Spraying", "query_file": "oci_password_spraying_attack.json"},
        ]
    },
    "SOC: Cloud Guard Security Dashboard": {
        "description": "Cloud Guard problem monitoring for security posture issues.",
        "widgets": [
            {"title": "CG: Bucket Public Read", "query_file": "cloud_guard_problem_bucket_public_read.json"},
            {"title": "CG: Bucket Public Write", "query_file": "cloud_guard_problem_bucket_public_write.json"},
            {"title": "CG: Instance Public IP", "query_file": "cloud_guard_problem_instance_public_ip.json"},
            {"title": "CG: Instance Principals", "query_file": "cloud_guard_problem_instance_principals_enabled.json"},
            {"title": "CG: Policy Too Permissive", "query_file": "cloud_guard_problem_policy_too_permissive.json"},
            {"title": "CG: Too Many Admins", "query_file": "cloud_guard_problem_group_has_too_many_admins.json"},
            {"title": "CG: Stale API Key", "query_file": "cloud_guard_problem_iam_user_api_key_old.json"},
            {"title": "CG: Stale Console Password", "query_file": "cloud_guard_problem_iam_user_console_password_old.json"},
            {"title": "CG: Audit Log Retention", "query_file": "cloud_guard_problem_audit_log_retention.json"},
            {"title": "CG: VCN Flow Logs Disabled", "query_file": "cloud_guard_problem_vcn_flow_log_disabled.json"},
            {"title": "CG: SSH Port Open", "query_file": "cloud_guard_problem_vcn_security_list_port_ssh.json"},
            {"title": "CG: RDP Port Open", "query_file": "cloud_guard_problem_vcn_security_list_port_rdp.json"},
        ]
    },
    "SOC: Linux Security Dashboard": {
        "description": "Linux endpoint security: SSH, sudo, GTFOBins, reverse shells, persistence, anti-forensics, container escape.",
        "widgets": [
            {"title": "Linux: Reverse Shell Detected", "query_file": "linux_reverse_shell_detected.json"},
            {"title": "Linux: SSH Failed Logins", "query_file": "linux_ssh_failed_login.json"},
            {"title": "Linux: Sudo Usage", "query_file": "linux_sudo_usage.json"},
            {"title": "Linux: Crontab Persistence", "query_file": "linux_crontab_modification.json"},
            {"title": "Linux: SSH Authorized Keys", "query_file": "linux_ssh_authorized_keys_modified.json"},
            {"title": "Linux: History Cleared", "query_file": "linux_history_file_cleared.json"},
            {"title": "Linux: Container Escape", "query_file": "linux_container_escape_attempt.json"},
            {"title": "Linux: LD_PRELOAD Hijack", "query_file": "linux_ld_preload_library_hijacking.json"},
            {"title": "Linux: Kernel Module /tmp", "query_file": "linux_kernel_module_loaded_from_temp_directory.json"},
            {"title": "Linux: Passwd File Modified", "query_file": "linux_password_file_direct_modification.json"},
            {"title": "Linux: Ptrace Injection", "query_file": "linux_process_injection_via_ptrace.json"},
            {"title": "Linux: Network Redirect", "query_file": "linux_suspicious_network_traffic_redirect.json"},
            {"title": "Linux: Systemd Persistence", "query_file": "linux_systemd_service_persistence.json"},
            {"title": "Linux: SSH Tunneling", "query_file": "linux_ssh_tunneling_detected.json"},
            {"title": "Linux: Download to /tmp", "query_file": "linux_suspicious_download_to_tmp.json"},
            {"title": "Linux: /dev/shm Execution", "query_file": "linux_process_execution_from_devshm.json"},
            {"title": "Linux: Sudoers Modified", "query_file": "linux_sudoers_file_modification.json"},
            {"title": "Linux: Shell Profile Persist", "query_file": "linux_shell_profile_persistence.json"},
            {"title": "Linux: At Job Scheduled", "query_file": "linux_at_job_scheduled.json"},
            {"title": "Linux: DNS Tunneling", "query_file": "linux_dns_tunneling_detected.json"},
        ]
    },
    "SOC: Linux Advanced Threats Dashboard": {
        "description": "Linux advanced threat detection: C2, exfiltration, discovery, web shells, cryptomining, and post-exploitation.",
        "widgets": [
            {"title": "Linux: Hosts File Modified", "query_file": "linux_hosts_file_modification.json"},
            {"title": "Linux: /proc Memory Access", "query_file": "linux_process_memory_access_via_proc.json"},
            {"title": "Linux: Web Shell Created", "query_file": "linux_web_shell_file_creation.json"},
            {"title": "Linux: Cryptominer Detected", "query_file": "linux_cryptominer_activity_detected.json"},
            {"title": "Linux: Log Tampering", "query_file": "linux_log_file_tampering.json"},
            {"title": "Linux: Enumeration Script", "query_file": "linux_post-exploitation_enumeration_script.json"},
            {"title": "Linux: Bind Shell", "query_file": "linux_bind_shell_listener.json"},
            {"title": "Linux: Suspicious Cron Job", "query_file": "linux_suspicious_cron_job_content.json"},
            {"title": "Linux: Hidden File Creation", "query_file": "linux_hidden_file_or_directory_creation_in_suspicious_location.json"},
            {"title": "Linux: Network Scanning", "query_file": "linux_network_service_scanning.json"},
            {"title": "Linux: User Discovery", "query_file": "linux_system_owner_and_user_discovery.json"},
            {"title": "Linux: Remote Service Abuse", "query_file": "linux_external_remote_service_abuse.json"},
            {"title": "Linux: Exfil Alt Protocol", "query_file": "linux_exfiltration_over_alternative_protocol.json"},
            {"title": "Linux: Archive for Exfil", "query_file": "linux_archive_data_collected_for_exfiltration.json"},
            {"title": "Linux: Sensitive Data Access", "query_file": "linux_sensitive_data_collection_from_local_system.json"},
            {"title": "Linux: Proxy/Tunnel Tool", "query_file": "linux_proxy_and_tunneling_tool_detected.json"},
            {"title": "Linux: Encrypted C2", "query_file": "linux_encrypted_channel_c2_communication.json"},
            {"title": "Linux: SUID Binary Created", "query_file": "linux_setuid_binary_creation.json"},
        ]
    },
    "SOC: Windows Security Dashboard": {
        "description": "Windows endpoint security: ransomware indicators, AMSI bypass, WMI persistence, credential dumping, LOLBins.",
        "widgets": [
            {"title": "Win: Shadow Copy Deletion", "query_file": "windows_shadow_copy_deletion.json"},
            {"title": "Win: Boot Config Modified", "query_file": "windows_boot_configuration_modified.json"},
            {"title": "Win: Credential Dump (LSASS)", "query_file": "windows_credential_dumping_via_procdump.json"},
            {"title": "Win: Encoded PowerShell", "query_file": "windows_encoded_powershell_execution.json"},
            {"title": "Win: AMSI Bypass", "query_file": "windows_amsi_bypass_attempt.json"},
            {"title": "Win: WMI Persistence", "query_file": "windows_wmi_event_subscription_persistence.json"},
            {"title": "Win: Registry Run Key", "query_file": "windows_registry_run_key_modification.json"},
            {"title": "Win: DLL Side-Loading", "query_file": "windows_dll_side-loading_via_suspicious_path.json"},
            {"title": "Win: Certutil Download/Decode", "query_file": "windows_certutil_download_or_decode.json"},
            {"title": "Win: Service Creation (SC)", "query_file": "windows_service_creation_via_sc.json"},
            {"title": "Win: PowerShell LOLBin", "query_file": "windows_lolbin_usage_powershell.json"},
            {"title": "Win: WMIC LOLBin", "query_file": "windows_lolbin_usage_wmic.json"},
            {"title": "Win: Mimikatz Patterns", "query_file": "windows_mimikatz_execution_patterns.json"},
            {"title": "Win: Firewall Rule Change", "query_file": "windows_firewall_rule_modification.json"},
            {"title": "Win: RDP Lateral Movement", "query_file": "windows_rdp_lateral_movement.json"},
            {"title": "Win: Scheduled Task (schtasks)", "query_file": "windows_scheduled_task_creation_via_schtasks.json"},
            {"title": "Win: PS Download Cradle", "query_file": "windows_powershell_download_cradle.json"},
            {"title": "Win: LSASS Memory Access", "query_file": "windows_lsass_memory_access.json"},
            {"title": "Win: Event Log Clearing", "query_file": "windows_event_log_clearing.json"},
            {"title": "Win: PsExec Lateral Move", "query_file": "windows_psexec_remote_execution.json"},
        ]
    },
    "SOC: Windows Advanced Threats Dashboard": {
        "description": "Windows advanced threat detection: Kerberoasting (real AD data), Mimikatz, PowerShell attacks, UAC bypass, pass-the-hash, process hollowing, credential harvesting, and exfiltration.",
        "widgets": [
            {"title": "Kerb: RC4 Ticket (Kerberoast)", "query_file": "kerberoasting_rc4_ticket_request.json"},
            {"title": "Kerb: SPN Sweep", "query_file": "kerberoasting_spn_sweep.json"},
            {"title": "PS: Suspicious Commands", "query_file": "powershell_suspicious_commands.json"},
            {"title": "CMD: Suspicious Execution", "query_file": "cmd_suspicious_child_process.json"},
            {"title": "Mimikatz: Command Indicators", "query_file": "mimikatz_command_indicators.json"},
            {"title": "Win: UAC Bypass", "query_file": "windows_uac_bypass_attempt.json"},
            {"title": "Win: Kerberoasting (Sysmon)", "query_file": "windows_kerberoasting_attack.json"},
            {"title": "Win: Pass-the-Hash", "query_file": "windows_pass-the-hash_attack_indicators.json"},
            {"title": "Win: Process Hollowing", "query_file": "windows_process_hollowing_indicators.json"},
            {"title": "Win: WDigest Credential", "query_file": "windows_wdigest_authentication_enabled_for_credential_harvesting.json"},
            {"title": "Win: NTDS.dit Extraction", "query_file": "windows_ntdsdit_database_extraction.json"},
            {"title": "Win: Data Staging", "query_file": "windows_data_staging_for_exfiltration.json"},
            {"title": "Win: Keylogger Indicators", "query_file": "windows_keylogger_indicators.json"},
            {"title": "Hunt: Kerb RC4/AES Ratio", "query_file": "hunting/kerberoasting_anomaly_detection.json"},
            {"title": "Hunt: Credential Attack Corr", "query_file": "hunting/credential_attack_correlation.json"},
            {"title": "Win: Screen Capture", "query_file": "windows_screen_capture_activity.json"},
            {"title": "Win: Remote Access Tool", "query_file": "windows_remote_access_tool_detected.json"},
            {"title": "Win: Token Manipulation", "query_file": "windows_access_token_manipulation.json"},
        ]
    },
    "SOC: Threat Hunting Dashboard": {
        "description": "Advanced threat hunting analytics inspired by the Threat Hunter's Cookbook. Uses frequency analysis, rare value detection, anomaly scoring, multi-stage correlation, and grouping techniques across all log sources.",
        "widgets": [
            {"title": "Hunt: SSH Brute Force (Frequency)", "query_file": "hunting/ssh_brute_force_frequency.json"},
            {"title": "Hunt: OCI Console Brute Force", "query_file": "hunting/oci_console_brute_force.json"},
            {"title": "Hunt: Windows Rare Processes", "query_file": "hunting/windows_rare_process.json"},
            {"title": "Hunt: Linux Rare Processes", "query_file": "hunting/linux_rare_process.json"},
            {"title": "Hunt: Long Command Lines", "query_file": "hunting/windows_long_command_line.json"},
            {"title": "Hunt: OCI IAM Rapid Changes", "query_file": "hunting/oci_iam_rapid_changes.json"},
            {"title": "Hunt: OCI IAM + Fusion Correlation", "query_file": "hunting/oci_iam_fusion_activity_correlation.json"},
            {"title": "Hunt: Lateral Movement Cluster", "query_file": "hunting/windows_lateral_movement_cluster.json"},
            {"title": "Hunt: Linux Multi-Stage Attack", "query_file": "hunting/linux_multi_stage_attack.json"},
            {"title": "Hunt: OCI Destruction Spike", "query_file": "hunting/oci_resource_destruction_spike.json"},
            {"title": "Hunt: Credential Access Cluster", "query_file": "hunting/windows_credential_access_cluster.json"},
            {"title": "Hunt: Multi-User Same IP", "query_file": "hunting/oci_multi_user_same_ip.json"},
            {"title": "Hunt: Linux Persistence Score", "query_file": "hunting/linux_persistence_score.json"},
            {"title": "Hunt: Unusual Process Paths", "query_file": "hunting/windows_process_unusual_path.json"},
            {"title": "Hunt: After-Hours IAM Activity", "query_file": "hunting/oci_after_hours_iam_activity.json"},
            {"title": "Hunt: Defense Evasion Score", "query_file": "hunting/windows_defense_evasion_score.json"},
        ]
    },
    "SOC: Sysmon Network and Lateral Movement Dashboard": {
        "description": "Sysmon network connection analysis: lateral movement detection, C2 beacon identification, DNS tunneling, named pipe activity, and MITRE ATT&CK technique mapping.",
        "widgets": [
            {"title": "Net: C2 Beacon Candidates", "query_file": "sysmon_c2_beacon_-_periodic_outbound_https.json"},
            {"title": "Net: Lateral Movement - SMB", "query_file": "sysmon_lateral_movement_via_smb.json"},
            {"title": "Net: Lateral Movement - WinRM", "query_file": "sysmon_lateral_movement_via_winrm.json"},
            {"title": "Net: RDP Lateral Movement", "query_file": "sysmon_rdp_lateral_movement.json"},
            {"title": "Net: DNS Tunnel Indicators", "query_file": "sysmon_dns_tunneling_via_network_connection.json"},
            {"title": "Net: LOLBin Outbound Traffic", "query_file": "sysmon_suspicious_outbound_connection_from_lolbin.json"},
            {"title": "Net: Kerberoasting Network", "query_file": "sysmon_kerberoasting_network_indicator.json"},
            {"title": "Net: LDAP Reconnaissance", "query_file": "sysmon_ldap_reconnaissance.json"},
            {"title": "Net: Cobalt Strike C2", "query_file": "sysmon_cobalt_strike_c2_network_indicators.json"},
            {"title": "Net: Mimikatz Network", "query_file": "sysmon_mimikatz_network_activity.json"},
            {"title": "Pipe: Cobalt Strike Pipes", "query_file": "sysmon_cobalt_strike_named_pipe.json"},
            {"title": "Pipe: PsExec Pipes", "query_file": "sysmon_psexec_named_pipe.json"},
            {"title": "Pipe: Mimikatz Pipes", "query_file": "sysmon_mimikatz_named_pipe.json"},
            {"title": "Pipe: Suspicious C2 Pipes", "query_file": "sysmon_suspicious_named_pipe_pattern.json"},
            {"title": "DNS: Data Exfiltration", "query_file": "sysmon_dns_data_exfiltration.json"},
            {"title": "DNS: C2 Framework Domains", "query_file": "sysmon_dns_query_to_known_c2_framework_domains.json"},
            {"title": "DNS: Suspicious TLDs", "query_file": "sysmon_dns_query_to_suspicious_tlds.json"},
        ]
    },
    "SOC: Web Application Security Dashboard": {
        "description": "OWASP Top 10 web attack detection via WAF, Load Balancer, and application logs. SQL injection, XSS, path traversal, SSRF, command injection, and more.",
        "widgets": [
            {"title": "WAF: SQL Injection Blocked", "query_file": "waf_sql_injection_attack_blocked.json"},
            {"title": "WAF: SQL Injection Allowed", "query_file": "waf_sql_injection_attack_allowed_through.json"},
            {"title": "WAF: XSS Attack Blocked", "query_file": "waf_cross-site_scripting_attack_blocked.json"},
            {"title": "WAF: Path Traversal Blocked", "query_file": "waf_path_traversal_attack_blocked.json"},
            {"title": "WAF: Command Injection Blocked", "query_file": "waf_command_injection_attack_blocked.json"},
            {"title": "WAF: SSRF Attack Blocked", "query_file": "waf_server-side_request_forgery_blocked.json"},
            {"title": "WAF: XXE Attack Blocked", "query_file": "waf_xml_external_entity_attack_blocked.json"},
            {"title": "WAF: SSTI Attack Blocked", "query_file": "waf_server-side_template_injection_blocked.json"},
            {"title": "WAF: Log4Shell Blocked", "query_file": "waf_log4shell_cve-2021-44228_attack_blocked.json"},
            {"title": "WAF: NoSQL Injection Blocked", "query_file": "waf_nosql_injection_attack_blocked.json"},
            {"title": "WAF: LDAP Injection Blocked", "query_file": "waf_ldap_injection_attack_blocked.json"},
            {"title": "WAF: Web Shell Upload Blocked", "query_file": "waf_web_shell_upload_attempt_blocked.json"},
            {"title": "WAF: Protocol Attack Blocked", "query_file": "waf_protocol_attack_blocked.json"},
            {"title": "WAF: Rate Limiting Triggered", "query_file": "waf_rate_limiting_triggered.json"},
            {"title": "WAF: CORS Bypass Blocked", "query_file": "waf_cors_bypass_attempt_blocked.json"},
            {"title": "LB: Vulnerability Scanner", "query_file": "web_vulnerability_scanner_detected.json"},
            {"title": "LB: Brute Force Login", "query_file": "web_application_brute_force_login_attempt.json"},
            {"title": "LB: Directory Enumeration", "query_file": "web_directory_enumeration_detected.json"},
            {"title": "LB: Sensitive Data Access", "query_file": "sensitive_data_endpoint_access.json"},
            {"title": "LB: HTTP Method Abuse", "query_file": "suspicious_http_method_usage.json"},
            {"title": "LB: Large Response Exfil", "query_file": "unusually_large_http_response_data_exfiltration.json"},
            {"title": "LB: Server Errors", "query_file": "web_application_server_error_spike.json"},
            {"title": "LB: API Unauthorized", "query_file": "api_endpoint_unauthorized_access_attempts.json"},
            {"title": "LB: Suspicious User Agent", "query_file": "suspicious_or_empty_user_agent_detected.json"},
            {"title": "App: IDOR Detected", "query_file": "insecure_direct_object_reference_detected.json"},
            {"title": "App: Privilege Escalation", "query_file": "web_application_privilege_escalation.json"},
            {"title": "App: Auth Bypass", "query_file": "web_application_authentication_bypass.json"},
            {"title": "App: Insecure Deserialization", "query_file": "insecure_deserialization_attack_detected.json"},
            {"title": "App: Session Hijacking", "query_file": "web_application_session_hijacking_indicators.json"},
            {"title": "App: Mass Assignment", "query_file": "mass_assignment_attack_detected.json"},
        ]
    },
    "SOC: Web Threat Hunting Dashboard": {
        "description": "Advanced web application threat hunting analytics. WAF attack frequency, SQL injection stacking, multi-vector scoring, geographic anomalies, and multi-stage attack chain correlation.",
        "widgets": [
            {"title": "Hunt: WAF Attack by Source IP", "query_file": "hunting/waf_attack_frequency_by_source.json"},
            {"title": "Hunt: SQLi Pattern Stacking", "query_file": "hunting/waf_sqli_pattern_stacking.json"},
            {"title": "Hunt: Web Brute Force", "query_file": "hunting/web_brute_force_frequency.json"},
            {"title": "Hunt: Directory Scan Cluster", "query_file": "hunting/web_directory_scan_clustering.json"},
            {"title": "Hunt: Multi-Attack Scoring", "query_file": "hunting/waf_multi_attack_scoring.json"},
            {"title": "Hunt: Attack Geo Anomaly", "query_file": "hunting/web_attack_geo_anomaly.json"},
            {"title": "Hunt: OWASP Multi-Stage", "query_file": "hunting/web_owasp_multi_stage_attack.json"},
            {"title": "Hunt: Scanner Tool Stacking", "query_file": "hunting/web_scanner_tool_stacking.json"},
        ]
    },
    "OCI-DEMO: Application 360 Monitoring Dashboard": {
        "description": "360-degree observability for OCI-DEMO applications (CRM Portal + Drone Shop). Correlates APM traces, application logs, WAF signals, database performance (OPSI/DB Management), and security events using trace_id as the universal join key.",
        "widgets": [
            {"title": "App: Error Rate by Service", "query_file": "apps/app_error_rate_by_service.json"},
            {"title": "App: Slow Requests (>2s)", "query_file": "apps/app_slow_requests.json"},
            {"title": "App: Request Rate by Endpoint", "query_file": "apps/app_request_rate_by_endpoint.json"},
            {"title": "App: Service Health Timeline", "query_file": "apps/app_service_health_timeline.json"},
            {"title": "App: OWASP Attack Detection", "query_file": "apps/app_owasp_attack_detection.json"},
            {"title": "App: WAF Signal Correlation", "query_file": "apps/app_waf_signal_correlation.json"},
            {"title": "App: SQLi + XSS Detection", "query_file": "apps/app_sqli_xss_detection.json"},
            {"title": "App: Auth Brute Force", "query_file": "apps/app_auth_brute_force.json"},
            {"title": "App: Security Attack by IP", "query_file": "apps/app_security_attack_by_ip.json"},
            {"title": "App: Cross-Service Trace Correlation", "query_file": "apps/app_cross_service_trace_correlation.json"},
            {"title": "App: Order Sync Pipeline", "query_file": "apps/app_order_sync_pipeline.json"},
            {"title": "App: DB Performance Correlation", "query_file": "apps/app_db_performance_correlation.json"},
        ]
    },
    "SOC: Geographic Health Dashboard": {
        "description": "Multicloud geographic health visualization. Regional instance health status across OCI, Azure, and GCP on a global map with provider summaries, tier breakdowns, and unhealthy region alerts.",
        "widgets": [
            {"title": "Geo: Regional Health Map", "query_file": "hunting/multicloud_geo_health_regional_map.json"},
            {"title": "Geo: Cloud Provider Summary", "query_file": "hunting/multicloud_geo_health_by_provider.json"},
            {"title": "Geo: Instance Detail", "query_file": "hunting/multicloud_geo_health_instance_detail.json"},
            {"title": "Geo: Unhealthy Regions", "query_file": "hunting/multicloud_geo_health_unhealthy_regions.json"},
            {"title": "Geo: Service Tier Status", "query_file": "hunting/multicloud_geo_health_tier_status.json"},
        ]
    },
    "SOC: APT Detection Dashboard": {
        "description": "APT threat detection: BLUELIGHT RAT (S0657/APT37) full kill chain + YARA-enhanced indicators from Volexity research. Covers browser exploitation, Graph API/Google C2, cookie theft, keylogging, and OneDrive exfiltration.",
        "widgets": [
            {"title": "APT37: Drive-by Compromise", "query_file": "bluelight_drive_by_compromise.json"},
            {"title": "APT37: Browser Child Process", "query_file": "bluelight_browser_child_process.json"},
            {"title": "APT37: Obfuscated Commandline", "query_file": "bluelight_obfuscated_commandline.json"},
            {"title": "APT37: Graph API C2", "query_file": "bluelight_graph_api_c2.json"},
            {"title": "APT37: WMI System Discovery", "query_file": "bluelight_system_discovery.json"},
            {"title": "APT37: Registry Enumeration", "query_file": "bluelight_registry_enumeration.json"},
            {"title": "APT37: File Discovery", "query_file": "bluelight_file_discovery.json"},
            {"title": "APT37: Screen Capture", "query_file": "bluelight_screen_capture.json"},
            {"title": "APT37: Browser Credential Theft", "query_file": "bluelight_browser_credential_theft.json"},
            {"title": "APT37: Ingress Tool Transfer", "query_file": "bluelight_ingress_tool_transfer.json"},
            {"title": "APT37: OneDrive Exfiltration", "query_file": "bluelight_onedrive_exfiltration.json"},
            {"title": "YARA: PDB Path Indicators", "query_file": "bluelight_yara_pdb_strings.json"},
            {"title": "YARA: System Recon JSON", "query_file": "bluelight_yara_system_recon.json"},
            {"title": "YARA: Cookie Theft (Chrome/Edge)", "query_file": "bluelight_yara_cookie_theft.json"},
            {"title": "YARA: Keylogger Staging", "query_file": "bluelight_yara_keylogger.json"},
            {"title": "YARA: Google App C2", "query_file": "bluelight_yara_google_c2.json"},
            {"title": "Hunt: BLUELIGHT Kill Chain", "query_file": "hunting/bluelight_apt37_kill_chain.json"},
        ]
    },
    "SOC: Browser Attack Detection Dashboard": {
        "description": "Browser-side attack detection via OCI APM and OpenTelemetry. XSS, SQLi, CSRF, session hijacking, clickjacking, DOM attacks, cryptomining, and fingerprinting across monitored applications.",
        "widgets": [
            {"title": "Browser: XSS Attack Detection", "query_file": "apps/apm_xss_attack_detection.json"},
            {"title": "Browser: SQL Injection Detection", "query_file": "apps/apm_sqli_attack_detection.json"},
            {"title": "Browser: CSRF Violation", "query_file": "apps/apm_csrf_violation_detection.json"},
            {"title": "Browser: Session Hijacking", "query_file": "apps/apm_session_hijacking_detection.json"},
            {"title": "Browser: Clickjacking Detection", "query_file": "apps/apm_clickjacking_detection.json"},
            {"title": "Browser: DOM-Based Attacks", "query_file": "apps/apm_dom_attack_detection.json"},
            {"title": "Browser: Suspicious JS Patterns", "query_file": "apps/apm_suspicious_js_patterns.json"},
            {"title": "Browser: Fingerprinting Detection", "query_file": "apps/apm_browser_fingerprinting.json"},
            {"title": "Hunt: Browser Attack Frequency", "query_file": "hunting/browser_attack_frequency_analysis.json"},
        ]
    },
}


# ─── Scope Filters (compartment-aware) ───────────────────────────

def build_scope_filters(compartment_id):
    """Build OCI LA scope filters that scope queries to the correct compartment."""
    return {
        "LogGroup": {
            "flags": {"IncludeSubCompartments": True},
            "type": "LogGroup",
            "values": [{"label": "root", "value": compartment_id}],
        },
        "Entity": {
            "flags": {"IncludeDependents": True, "ScopeCompartmentId": compartment_id},
            "type": "Entity",
            "values": [],
        },
        "LogSet": {"flags": {}, "type": "LogSet", "values": []},
        "filters": [
            {"flags": {"IncludeSubCompartments": True}, "type": "LogGroup",
             "values": [{"label": "root", "value": compartment_id}]},
            {"flags": {"IncludeDependents": True, "ScopeCompartmentId": compartment_id},
             "type": "Entity", "values": []},
            {"flags": {}, "type": "LogSet", "values": []},
        ],
        "isGlobal": False,
    }


# ─── Saved Search Definition Builder ─────────────────────────────

def build_saved_search_json(search_id, title, query, description="", tags=None):
    """Build a saved search JSON definition for embedding in a dashboard import.

    The import_dashboard API requires saved searches to be embedded in the
    dashboard JSON. Tiles reference them by their 'id' field (not OCID).
    """
    scope_filters = build_scope_filters(COMPARTMENT_ID)

    return {
        "id": search_id,
        "displayName": title,
        "providerId": "log-analytics",
        "providerName": "Log Analytics",
        "providerVersion": "3.0.0",
        "compartmentId": COMPARTMENT_ID,
        "isOobSavedSearch": False,
        "description": description,
        "nls": {},
        "type": "SEARCH_SHOW_IN_DASHBOARD",
        "uiConfig": {
            "enableWidgetInApp": True,
            "queryString": query,
            "scopeFilters": scope_filters,
            "showTitle": True,
            "timeSelection": {"timePeriod": "l60min"},
            "visualizationOptions": {},
            "visualizationType": "table",
            "vizType": "lxSavedSearchWidgetType",
        },
        "dataConfig": [],
        "screenImage": " ",
        "metadataVersion": "2.0",
        "widgetTemplate": "visualizations/chartWidgetTemplate.html",
        "widgetVM": "jet-modules/dashboards/widgets/lxSavedSearchWidget",
        "freeformTags": tags or {},
        "parametersConfig": [],
    }


# ─── Dashboard Creation via Import ────────────────────────────────

def build_dashboard_json(dashboard_id, name, description, widgets, widget_queries):
    """Build a complete dashboard JSON with embedded saved searches.

    The import_dashboard API requires both tiles and their saved search
    definitions in a single JSON. Tiles reference saved searches by short
    'id' fields, not OCIDs.
    """
    tiles = []
    saved_searches = []

    for i, (widget, query_info) in enumerate(zip(widgets, widget_queries)):
        if query_info is None:
            continue

        # Generate a stable short ID from the query filename
        search_id = widget['query_file'].replace('.json', '').replace('_', '-')

        row = i // 2
        col = (i % 2) * 6

        # Build the tile referencing the saved search by short ID
        tiles.append({
            "displayName": widget['title'],
            "savedSearchId": search_id,
            "row": row,
            "column": col,
            "height": 4,
            "width": 6,
            "nls": {},
            "uiConfig": {},
            "dataConfig": [],
            "state": "DEFAULT",
            "drilldownConfig": [],
            "parametersMap": {
                "log-analytics-entity": "$(dashboard.params.log-analytics-entity-filter)",
                "log-analytics-log-group-compartment": "$(dashboard.params.log-analytics-loggroup-filter)",
                "time": "$(dashboard.params.time)",
            },
        })

        # Build the embedded saved search definition
        tags = {}
        if query_info.get('tags'):
            tags["mitre_techniques"] = ",".join(query_info['tags'])
        if query_info.get('sigma_id'):
            tags["sigma_id"] = query_info['sigma_id']
        tags["platform"] = "soc-detection-rules"

        saved_searches.append(build_saved_search_json(
            search_id=search_id,
            title=widget['title'],
            query=query_info['query'],
            description=query_info.get('description', ''),
            tags=tags,
        ))

    dashboard = {
        "dashboardId": dashboard_id,
        "providerId": "log-analytics",
        "providerName": "Log Analytics",
        "providerVersion": "3.0.0",
        "displayName": name,
        "description": description,
        "compartmentId": COMPARTMENT_ID,
        "isOobDashboard": False,
        "isShowInHome": True,
        "isShowDescription": True,
        "metadataVersion": "2.0",
        "type": "normal",
        "isFavorite": False,
        "nls": {},
        "uiConfig": {
            "isFilteringEnabled": True,
            "isRefreshEnabled": True,
        },
        "dataConfig": [],
        "screenImage": " ",
        "freeformTags": {"platform": "soc-detection-rules"},
        "parametersConfig": [
            {
                "paramName": "log-analytics-loggroup-filter",
                "displayName": "Log Group Compartment",
                "paramType": "LogAnalyticsLogGroupCompartment",
                "defaultValue": COMPARTMENT_ID,
                "isRequired": False,
            },
            {
                "paramName": "log-analytics-entity-filter",
                "displayName": "Entity",
                "paramType": "LogAnalyticsEntity",
                "defaultValue": "",
                "isRequired": False,
            },
            {
                "paramName": "time",
                "displayName": "Time Range",
                "paramType": "Time",
                "defaultValue": "l60min",
                "isRequired": False,
            },
        ],
        "tiles": tiles,
        "savedSearches": saved_searches,
    }

    return dashboard


def delete_existing_dashboard(md_client, display_name):
    """Delete any existing dashboard with the given name (dedup-safe).

    Uses OCID from list results for deletion (short dashboardId won't work
    for delete after OCI's soft-delete window).
    """
    try:
        dashboards = md_client.list_management_dashboards(
            compartment_id=COMPARTMENT_ID,
            display_name=display_name
        ).data.items
        for d in dashboards:
            try:
                md_client.delete_management_dashboard(d.dashboard_id)
                print(f"    - Deleted old dashboard: {display_name} ({d.dashboard_id})")
            except Exception as del_err:
                print(f"    - Could not delete dashboard {display_name}: {del_err}")
    except Exception as e:
        print(f"    - Could not list dashboards for '{display_name}': {e}")


def import_dashboard(md_client, dashboard_json):
    """Import a dashboard using the ManagementDashboardImportDetails API."""
    import_details = oci.management_dashboard.models.ManagementDashboardImportDetails(
        dashboards=[dashboard_json]
    )

    try:
        md_client.import_dashboard(import_details)
        print(f"  Imported dashboard: {dashboard_json['displayName']}")
        return True
    except oci.exceptions.ServiceError as exc:
        print(f"  Error importing '{dashboard_json['displayName']}': {exc.message[:200]}")
        return False


# ─── Cleanup ──────────────────────────────────────────────────────

def cleanup_soc_content(md_client):
    """Delete all SOC-related saved searches and dashboards."""
    print("\n  Cleaning up existing SOC content...")

    # Delete dashboards
    for dashboard_name in DASHBOARDS.keys():
        try:
            dashboards = md_client.list_management_dashboards(
                compartment_id=COMPARTMENT_ID,
                display_name=dashboard_name
            ).data.items
            for d in dashboards:
                try:
                    md_client.delete_management_dashboard(d.dashboard_id)
                    print(f"    - Deleted dashboard: {dashboard_name}")
                except Exception:
                    pass
        except Exception:
            pass

    # Delete saved searches
    all_widget_titles = set()
    for config in DASHBOARDS.values():
        for widget in config['widgets']:
            all_widget_titles.add(widget['title'])

    for title in all_widget_titles:
        try:
            searches = md_client.list_management_saved_searches(
                compartment_id=COMPARTMENT_ID,
                display_name=title
            ).data.items
            for s in searches:
                md_client.delete_management_saved_search(s.id)
                print(f"    - Deleted saved search: {title}")
        except Exception:
            pass

    print("  Cleanup complete.\n")


# ─── Main Deploy ──────────────────────────────────────────────────

def deploy(cleanup=False, dry_run=False):
    print("=" * 60)
    print("OCI Log Analytics - SOC Dashboard Deployment")
    print("=" * 60)

    if dry_run:
        print("\n  [DRY RUN] No changes will be made.\n")
        missing = 0
        invalid = 0
        for name, config in DASHBOARDS.items():
            print(f"  Dashboard: {name}")
            print(f"    Widgets: {len(config['widgets'])}")
            for w in config['widgets']:
                query_path = os.path.join(QUERIES_DIR, w['query_file'])
                if not os.path.exists(query_path):
                    print(f"      - {w['title']} ({w['query_file']}) [MISSING]")
                    missing += 1
                    continue
                try:
                    with open(query_path, 'r') as f:
                        data = json.load(f)
                    if 'query' not in data:
                        print(f"      - {w['title']} ({w['query_file']}) [NO QUERY FIELD]")
                        invalid += 1
                    else:
                        print(f"      - {w['title']} ({w['query_file']})")
                except json.JSONDecodeError:
                    print(f"      - {w['title']} ({w['query_file']}) [INVALID JSON]")
                    invalid += 1
        total_widgets = sum(len(c['widgets']) for c in DASHBOARDS.values())
        print(f"\n  Total: {len(DASHBOARDS)} dashboards, {total_widgets} saved searches")
        if missing or invalid:
            print(f"  Warnings: {missing} missing files, {invalid} invalid files")
        return

    md_client = get_dashboard_client()
    print(f"\n  Compartment: {COMPARTMENT_ID}")

    if cleanup:
        cleanup_soc_content(md_client)

    total_searches = 0
    total_dashboards = 0

    for dashboard_name, dashboard_config in DASHBOARDS.items():
        print(f"\n{'─' * 50}")
        print(f"  Dashboard: {dashboard_name}")
        print(f"  Widgets: {len(dashboard_config['widgets'])}")
        print(f"{'─' * 50}")

        # Load query data for each widget
        widget_queries = []
        for widget in dashboard_config['widgets']:
            query_path = os.path.join(QUERIES_DIR, widget['query_file'])
            if not os.path.exists(query_path):
                print(f"    ? Missing query file: {widget['query_file']}")
                widget_queries.append(None)
                continue

            with open(query_path, 'r') as f:
                rule_data = json.load(f)

            widget_queries.append(rule_data)
            print(f"    + Loaded: {widget['title']}")
            total_searches += 1

        # Build and import dashboard with embedded saved searches
        valid_queries = [q for q in widget_queries if q is not None]
        if valid_queries:
            # Delete existing dashboard BEFORE generating new ID
            delete_existing_dashboard(md_client, dashboard_name)

            # Use timestamp suffix to avoid OCI soft-delete ID collisions
            ts = int(time.time())
            slug = dashboard_name.lower().replace(' ', '-').replace(':', '').replace('&', 'and')
            dashboard_id = f"soc-{slug}-{ts}"

            dashboard_json = build_dashboard_json(
                dashboard_id=dashboard_id,
                name=dashboard_name,
                description=dashboard_config['description'],
                widgets=dashboard_config['widgets'],
                widget_queries=widget_queries,
            )

            if import_dashboard(md_client, dashboard_json):
                total_dashboards += 1

    # Summary
    print(f"\n{'=' * 60}")
    print("Deployment Summary")
    print(f"{'=' * 60}")
    print(f"  Saved Searches created/found: {total_searches}")
    print(f"  Dashboards imported: {total_dashboards}")
    print(f"\n  View in OCI Console:")
    print(f"  Observability & Management > Log Analytics > Dashboards")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deploy SOC dashboards to OCI Log Analytics")
    parser.add_argument('--cleanup', action='store_true',
                        help='Delete existing SOC saved searches and dashboards before deploying')
    parser.add_argument('--dry-run', action='store_true',
                        help='Print deployment plan and validate query files without executing')
    parser.add_argument('--validate', action='store_true',
                        help='Run pre-flight validation checks')
    args = parser.parse_args()

    if args.validate:
        ok = validate_oci_setup(['ocid', 'cli', 'namespace', 'compartment', 'query_files'])
        sys.exit(0 if ok else 1)

    deploy(cleanup=args.cleanup, dry_run=args.dry_run)
