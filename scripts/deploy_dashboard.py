"""
Deploy SOC detection dashboards to OCI Log Analytics.

Creates 22 dashboards backed by 343 embedded saved-search widgets covering:
  - OCI audit and STIG compliance
  - Cloud Guard, Linux, Windows, Sysmon network, and web detections
  - Browser/APM detections, application analytics, APT content, and hunting
  - FreeLabFriday-inspired C2/exfiltration/persistence hunts
  - 2025-2026 MELTS hunts for ClickFix, ToolShell, RMM, token replay, and exfiltration
  - Geographic health / multicloud operational views

Usage:
  python3 scripts/deploy_dashboard.py              # Deploy all
  python3 scripts/deploy_dashboard.py --cleanup     # Delete existing SOC content first
  python3 scripts/deploy_dashboard.py --dashboard-name "C2 & Beaconing Detection"
  python3 scripts/deploy_dashboard.py --dry-run     # Print plan without executing
  python3 scripts/deploy_dashboard.py --export-inventory
"""

import json
import os
import sys
import argparse
import multiprocessing
import re
import signal
import time
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from oci_config import (
    TENANCY_ID, COMPARTMENT_ID, QUERIES_DIR, HUNTING_DIR, LA_NAMESPACE,
    get_dashboard_client, get_la_client, get_namespace, validate_oci_setup,
)
from oci_time import build_time_window
from query_artifacts import is_saved_search_query_file

import oci

SUPPORTED_VISUALIZATION_TYPES = {
    "bar",
    "cluster",
    "distinct",
    "hbar",
    "issues",
    "line",
    "link",
    "map",
    "pie",
    "records",
    "records_histogram",
    "summary_table",
    "sunburst",
    "table",
    "table_histogram",
    "tile",
    "treemap",
}

ADVANCED_VISUALIZATION_TYPES = {
    "bar",
    "hbar",
    "line",
    "link",
    "map",
    "pie",
    "summary_table",
    "sunburst",
    "tile",
    "treemap",
}

FIELD_REFERENCE_RE = re.compile(r"'([^']+)'")
FIELD_OPERATOR_RE = re.compile(r"\s*(?:=|!=|>=|<=|>|<|\blike\b|\bnot\s+like\b|\bin\b|\bnot\s+in\b|\bis\b)", re.IGNORECASE)
PROGRESS_REDACTIONS = (
    (re.compile(r"\bopc-request-id\s*[:=]\s*[A-Za-z0-9_.:-]+", re.IGNORECASE), "opc-request-id=<redacted>"),
    (re.compile(r"\bocid1\.[A-Za-z0-9_.-]+\b"), "<OCI_OCID>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<IP_ADDRESS>"),
    (re.compile(r"\bhttps?://[^\s\"']+"), "<URL>"),
    (re.compile(r"\bprofile\s+['\"]?[A-Za-z0-9_.:-]+['\"]?", re.IGNORECASE), "profile <redacted>"),
    (re.compile(r"\bnamespace\s+['\"]?[A-Za-z0-9_.:-]+['\"]?", re.IGNORECASE), "namespace <redacted>"),
)


def _iter_quoted_values(text):
    in_quote = False
    escaped = False
    start = 0
    value = []
    for index, char in enumerate(text):
        if escaped:
            value.append(char)
            escaped = False
            continue
        if char == "\\" and in_quote:
            escaped = True
            value.append(char)
            continue
        if char == "'":
            if in_quote:
                yield "".join(value), start, index + 1
                in_quote = False
                value = []
            else:
                in_quote = True
                start = index
                value = []
            continue
        if in_quote:
            value.append(char)

DASHBOARD_INVENTORY_PATH = os.path.join(QUERIES_DIR, "dashboard_inventory.json")
DEFAULT_DASHBOARD_TIME_PERIOD = "l24h"
DEFAULT_QUERY_VALIDATION_LOOKBACK = "24h"
OCTO_APM_WORKSHOP_TIME_SELECTION = {"timePeriod": "l21d"}
DASHBOARD_GRID_COLUMNS = 12

VISUALIZATION_LAYOUT_DEFAULTS = {
    "bar": {"width": 6, "height": 5},
    "cluster": {"width": 12, "height": 6},
    "distinct": {"width": 3, "height": 3},
    "hbar": {"width": 6, "height": 5},
    "issues": {"width": 12, "height": 6},
    "line": {"width": 6, "height": 5},
    "link": {"width": 12, "height": 6},
    "map": {"width": 12, "height": 6},
    "pie": {"width": 6, "height": 5},
    "records": {"width": 12, "height": 6},
    "records_histogram": {"width": 12, "height": 6},
    "summary_table": {"width": 12, "height": 5},
    "sunburst": {"width": 6, "height": 6},
    "table": {"width": 12, "height": 5},
    "table_histogram": {"width": 12, "height": 6},
    "tile": {"width": 3, "height": 3},
    "treemap": {"width": 6, "height": 6},
}


def octo_apm_workshop_widget(title, query_file):
    """Return an Octo workshop widget pinned to the workshop evidence window."""
    return {
        "title": title,
        "query_file": query_file,
        "time_selection": OCTO_APM_WORKSHOP_TIME_SELECTION.copy(),
    }


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
        "description": "Windows advanced threat detection: Kerberoasting, Golden Ticket, DCSync, Mimikatz, pass-the-ticket, privilege escalation — all against real GOAD AD lab data (3M+ events).",
        "widgets": [
            {"title": "Kerb: RC4 Ticket (Kerberoast)", "query_file": "kerberoasting_rc4_ticket_request.json"},
            {"title": "Kerb: SPN Sweep", "query_file": "kerberoasting_spn_sweep.json"},
            {"title": "Golden Ticket: RC4 TGT", "query_file": "golden_ticket_anomaly.json"},
            {"title": "DCSync: Directory Replication", "query_file": "dcsync_directory_replication.json"},
            {"title": "Pass-the-Ticket: Explicit Cred", "query_file": "pass_the_ticket_logon.json"},
            {"title": "PrivEsc: Sensitive Privileges", "query_file": "privilege_escalation_sensitive_privileges.json"},
            {"title": "Lateral: Network Logon Sweep", "query_file": "lateral_movement_logon_pattern.json"},
            {"title": "Brute Force: Failed Logons", "query_file": "brute_force_failed_logon_spike.json"},
            {"title": "PS: Suspicious Commands", "query_file": "powershell_suspicious_commands.json"},
            {"title": "CMD: Suspicious Execution", "query_file": "cmd_suspicious_child_process.json"},
            {"title": "Mimikatz: Command Indicators", "query_file": "mimikatz_command_and_module_indicators_in_process_logs.json"},
            {"title": "Cred Manager: Dump Activity", "query_file": "credential_manager_access.json"},
            {"title": "Group Enum: SharpHound/BloodH", "query_file": "security_group_enumeration.json"},
            {"title": "Hunt: Kerb RC4/AES Ratio", "query_file": "hunting/kerberoasting_anomaly_detection.json"},
            {"title": "Hunt: AD Attack Timeline", "query_file": "hunting/ad_attack_timeline.json"},
            {"title": "Win: Screen Capture", "query_file": "windows_screen_capture_activity.json"},
            {"title": "Win: Remote Access Tool", "query_file": "windows_remote_access_tool_detected.json"},
            {"title": "Win: Token Manipulation", "query_file": "windows_access_token_manipulation.json"},
        ]
    },
    "SOC: GOAD Caldera Operations Dashboard": {
        "description": "Maps the 5 Caldera adversary operations from c7_run_caldera_operations.sh (Discovery, Credential Access, Lateral Movement, Collection, Exfiltration) to detection rules firing on the 10 GOAD + Apex AD Windows hosts (kingslanding, winterfell, meereen, castelblack, braavos, hq-dc01, eu-dc01, eu-app01, apac-dc01, apac-db01). Each Caldera operation phase maps to a row of detection tiles plus two host-scoped hunting tiles (sandcat agent activity + multi-stage attack chain) that filter to the 11 lab Entities so red-team noise stays scoped and BLUE drilldowns stay attributable to a specific Caldera op.",
        "widgets": [
            {"title": "Op1 Discovery: AD Enum (AdFind)", "query_file": "ad_enumeration_via_adfind.json"},
            {"title": "Op1 Discovery: BloodHound", "query_file": "bloodhound_ad_enumeration.json"},
            {"title": "Op1 Discovery: Domain Trust (nltest)", "query_file": "domain_trust_discovery_via_nltest.json"},
            {"title": "Op1 Discovery: Net View Shares", "query_file": "network_share_enumeration_via_net_view.json"},
            {"title": "Op1 Discovery: Win Share Enum", "query_file": "windows_network_share_discovery.json"},
            {"title": "Op2 CredAccess: Kerberoast RC4", "query_file": "kerberoasting_rc4_ticket_request.json"},
            {"title": "Op2 CredAccess: AS-REP Roasting", "query_file": "as-rep_roasting_via_rubeus.json"},
            {"title": "Op2 CredAccess: LSASS via comsvcs", "query_file": "lsass_memory_dump_via_comsvcs_dll.json"},
            {"title": "Op2 CredAccess: DCSync (Non-DC)", "query_file": "dcsync_directory_replication.json"},
            {"title": "Op2 CredAccess: Mimikatz Indicators", "query_file": "mimikatz_command_and_module_indicators_in_process_logs.json"},
            {"title": "Op3 Lateral: PSExec Remote Exec", "query_file": "windows_psexec_remote_execution.json"},
            {"title": "Op3 Lateral: WinRM (PowerShell)", "query_file": "winrm_lateral_movement_via_powershell.json"},
            {"title": "Op3 Lateral: Admin Share (net use)", "query_file": "windows_admin_share_access_via_net_use.json"},
            {"title": "Op3 Lateral: Pass-the-Ticket", "query_file": "pass_the_ticket_logon.json"},
            {"title": "Op3 Lateral: Tool Transfer (robocopy)", "query_file": "lateral_tool_transfer_via_robocopy.json"},
            {"title": "Op4 Collection: 7-Zip Archive", "query_file": "data_compression_for_exfiltration_via_7zip.json"},
            {"title": "Op4 Collection: Screen Capture", "query_file": "windows_screen_capture_activity.json"},
            {"title": "Op4 Collection: Data Staging", "query_file": "windows_data_staging_for_exfiltration.json"},
            {"title": "Op5 Exfil: BITS Job Abuse", "query_file": "windows_bits_job_abuse_for_persistence.json"},
            {"title": "Op5 Exfil: PowerShell Download Cradle", "query_file": "windows_powershell_download_cradle.json"},
            {"title": "Op5 Exfil: Large HTTP Response", "query_file": "unusually_large_http_response_data_exfiltration.json"},
            {"title": "Hunt: Sandcat Agent Activity (GOAD/Apex)", "query_file": "hunting/goad_caldera_sandcat_activity.json"},
            {"title": "Hunt: Caldera Attack Chain (GOAD/Apex)", "query_file": "hunting/goad_caldera_attack_chain.json"},
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
    "C2 & Beaconing Detection": {
        "description": "Enhanced command-and-control investigation dashboard for DNS beacons, HTTPS callbacks, suspicious C2 destinations, VCN/Network Firewall egress, and host-to-destination link analysis across the 21-day demo dataset.",
        "widgets": [
            {"title": "Top C2 DNS Domains", "query_file": "hunting/c2_top_dns_domains.json"},
            {"title": "Beacon Activity Timeline", "query_file": "hunting/c2_beacon_activity_timeline.json"},
            {"title": "DNS Beacon Queries", "query_file": "hunting/c2_dns_beacon_queries_kpi.json"},
            {"title": "C2 Destination IPs", "query_file": "hunting/c2_destination_ips.json"},
            {"title": "C2 Communication Topology", "query_file": "hunting/c2_communication_topology.json"},
            {"title": "DNS Beacon Sources", "query_file": "hunting/c2_dns_beacon_sources.json"},
            {"title": "Unique C2 Domains", "query_file": "hunting/c2_unique_domains_kpi.json"},
            {"title": "C2 Flow Connections", "query_file": "hunting/c2_flow_connections_kpi.json"},
            {"title": "HTTPS Beaconing (Port 443)", "query_file": "hunting/c2_https_beaconing.json"},
            {"title": "Affected Hosts", "query_file": "hunting/c2_affected_hosts_kpi.json"},
        ]
    },
    "SOC: FreeLabFriday Threat Hunting Dashboard": {
        "description": "Black Hills InfoSec FreeLabFriday-inspired hunting dashboard for DNS C2, BITS and cloud-service exfiltration, domain-fronted C2, vsagent HTTP beaconing, credential stuffing, rogue user persistence, and port-knocking drilldowns.",
        "widgets": [
            {"title": "FLF: DNS C2 Patterns", "query_file": "hunting/flf_dns_c2_pattern_analysis.json"},
            {"title": "FLF: BITS Exfiltration", "query_file": "hunting/flf_bits_exfiltration.json"},
            {"title": "FLF: Cloud Service Exfiltration", "query_file": "hunting/flf_cloud_service_exfiltration.json"},
            {"title": "FLF: Domain Fronting CDN C2", "query_file": "hunting/flf_domain_fronting_cdn_c2.json"},
            {"title": "FLF: vsagent HTTP Beaconing", "query_file": "hunting/flf_vsagent_http_beaconing.json"},
            {"title": "FLF: Credential Stuffing", "query_file": "hunting/flf_credential_stuffing_pattern.json"},
            {"title": "FLF: New User Persistence", "query_file": "hunting/flf_new_user_persistence.json"},
            {"title": "FLF: Port Knocking Sequence", "query_file": "hunting/flf_port_knocking_sequence.json"},
        ]
    },
    "SOC: 2025-2026 Threat Hunting Dashboard": {
        "description": "MELTS-driven threat-hunting dashboard for 2025-2026 attack tradecraft: ClickFix/CrashFix, SharePoint ToolShell, RMM abuse, AiTM token replay, compromised-machine drilldowns, and exfiltration evidence.",
        "widgets": [
            {"title": "MELTS: Signal Overview", "query_file": "hunting/melts_attack_signal_overview.json"},
            {"title": "MELTS: Attack Timeline", "query_file": "hunting/melts_attack_timeline.json"},
            {"title": "MELTS: Attack Path Link", "query_file": "hunting/melts_attack_path_link.json"},
            {"title": "ClickFix: Clipboard PowerShell", "query_file": "hunting/clickfix_clipboard_powershell_execution.json"},
            {"title": "ClickFix: LOLBin Payloads", "query_file": "hunting/clickfix_lolbin_payload_execution.json"},
            {"title": "CrashFix: Python RAT", "query_file": "hunting/crashfix_python_rat_activity.json"},
            {"title": "SharePoint: ToolShell Attempts", "query_file": "hunting/sharepoint_toolshell_exploitation.json"},
            {"title": "SharePoint: Webshell Post-Exploit", "query_file": "hunting/sharepoint_toolshell_webshell_post_exploit.json"},
            {"title": "RMM: Post-Compromise Activity", "query_file": "hunting/rmm_post_compromise_activity.json"},
            {"title": "Cloud Identity: AiTM Token Abuse", "query_file": "hunting/cloud_identity_aitm_token_abuse.json"},
            {"title": "Exfil: After Initial Access", "query_file": "hunting/exfiltration_after_initial_access_2025_2026.json"},
            {"title": "Compromised Machines and Data", "query_file": "hunting/compromised_machines_and_data_2025_2026.json"},
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
    "SOC: Web-to-Cloud Threat Hunting Dashboard": {
        "description": "Incident-focused dashboard for the web-to-cloud attack chain: SSRF entry point, compromised machines and identity, VCN egress, Network Firewall C2, OCI Audit cloud abuse, and exfiltration evidence with link and sunburst drilldowns.",
        "widgets": [
            {"title": "W2C: Correlated Timeline", "query_file": "hunting/web_to_cloud_attack_timeline.json"},
            {"title": "W2C: Entry Point and SSRF", "query_file": "hunting/web_to_cloud_entry_point.json"},
            {"title": "W2C: Compromised Machines", "query_file": "hunting/web_to_cloud_compromised_machines.json"},
            {"title": "W2C: Compromised Identity", "query_file": "hunting/web_to_cloud_compromised_identity.json"},
            {"title": "W2C: VCN Egress", "query_file": "hunting/web_to_cloud_vcn_egress.json"},
            {"title": "W2C: Network Firewall C2", "query_file": "hunting/web_to_cloud_firewall_c2.json"},
            {"title": "W2C: OCI Audit Cloud Abuse", "query_file": "hunting/web_to_cloud_cloud_abuse.json"},
            {"title": "W2C: Exfiltrated Data", "query_file": "hunting/web_to_cloud_exfiltration.json"},
            {"title": "W2C: Attack Path Link", "query_file": "hunting/web_to_cloud_attack_path_link.json"},
            {"title": "W2C: MITRE Stage Breakdown", "query_file": "hunting/web_to_cloud_mitre_sunburst.json"},
        ]
    },
    "OCI-DEMO: Application 360 Monitoring Dashboard": {
        "description": "360-degree observability for OCI-DEMO applications (CRM Portal + Drone Shop). Runs on SOC Application Logs, a custom JSON telemetry source that models application, browser, and trace context with a shared Trace ID for correlation.",
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
    "OCI-DEMO: Octo APM Demo Dashboard": {
        "description": "Dedicated APM correlation dashboard for octo-apm-demo data in SOC Application Logs. Correlates request logs, APM span hierarchy, DB spans, Java sidecar errors, API Gateway edge decisions, OSQuery host evidence, payment threats, and metric samples by Trace ID, Span ID, Parent Span ID, Request ID, Run ID, and Attack ID.",
        "widgets": [
            octo_apm_workshop_widget("Octo APM: RED Metrics", "apps/apm_octo_red_metrics.json"),
            octo_apm_workshop_widget("Octo APM: Request Timeline", "apps/apm_octo_request_timeline.json"),
            octo_apm_workshop_widget("Octo APM: Span Hotspots", "apps/apm_octo_span_latency_hotspots.json"),
            octo_apm_workshop_widget("Octo APM: Trace Logs Correlation", "apps/apm_octo_trace_logs_correlation.json"),
            octo_apm_workshop_widget("Octo APM: Trace Investigation Tiles", "apps/apm_octo_trace_investigation_tiles.json"),
            octo_apm_workshop_widget("Octo APM: Span Link Analysis", "apps/apm_octo_span_link.json"),
            octo_apm_workshop_widget("Octo APM: Error Logs", "apps/apm_octo_error_logs.json"),
            octo_apm_workshop_widget("Octo APM: Metric Samples", "apps/apm_octo_metric_samples.json"),
            octo_apm_workshop_widget("Octo APM: Database Spans", "apps/apm_octo_db_spans.json"),
            octo_apm_workshop_widget("Octo APM: Java Sidecar Errors", "apps/apm_octo_java_sidecar_errors.json"),
            octo_apm_workshop_widget("Octo APM: API Gateway Edge Decisions", "apps/apm_octo_api_gateway_edge.json"),
            octo_apm_workshop_widget("Octo APM: Attack Timeline", "apps/apm_octo_attack_timeline.json"),
            octo_apm_workshop_widget("Octo APM: Attack Path Link", "apps/apm_octo_attack_path_link.json"),
            octo_apm_workshop_widget("Octo APM: Attack Trace Correlation", "apps/apm_octo_attack_trace_correlation.json"),
            octo_apm_workshop_widget("Octo APM: Payment Threats", "apps/apm_octo_payment_threats.json"),
            octo_apm_workshop_widget("Octo APM: OSQuery Host Evidence", "apps/apm_octo_osquery_findings.json"),
            octo_apm_workshop_widget("Octo APM: Compromised VM Pivots", "apps/apm_octo_compromised_vm_pivots.json"),
        ]
    },
    "SOC: Geographic Health Dashboard": {
        "description": "Multicloud geographic health visualization. Regional instance health status across OCI, Azure, AWS, and GCP on a global map with provider summaries, tier breakdowns, and unhealthy region alerts.",
        "widgets": [
            {"title": "Geo: Regional Health Map", "query_file": "hunting/multicloud_geo_health_regional_map.json"},
            {"title": "Geo: Cloud Provider Summary", "query_file": "hunting/multicloud_geo_health_by_provider.json"},
            {"title": "Geo: Instance Detail", "query_file": "hunting/multicloud_geo_health_instance_detail.json"},
            {"title": "Geo: Unhealthy Regions", "query_file": "hunting/multicloud_geo_health_unhealthy_regions.json"},
            {"title": "Geo: Service Tier Status", "query_file": "hunting/multicloud_geo_health_tier_status.json"},
        ]
    },
    "SOC: APT Detection Dashboard": {
        "description": "APT threat detection: BLUELIGHT RAT (S0657/APT37) full kill chain + YARA-enhanced indicators from Volexity research. Covers browser exploitation, Graph API/Google C2, cookie theft, keylogging, and OneDrive exfiltration. Showcase row at the top renders the full attack path on a single canvas.",
        "widgets": [
            {"title": "BLUELIGHT: Total Detections (24h)", "query_file": "hunting/bluelight_total_detections_kpi.json"},
            {"title": "BLUELIGHT: Top Affected Hosts", "query_file": "hunting/bluelight_top_affected_hosts.json"},
            {"title": "BLUELIGHT: MITRE Tactics x Techniques", "query_file": "hunting/bluelight_mitre_tactics_sunburst.json"},
            {"title": "BLUELIGHT: Kill Chain Timeline", "query_file": "hunting/bluelight_kill_chain_timeline.json"},
            {"title": "BLUELIGHT: Attack Path (per Host)", "query_file": "hunting/bluelight_attack_path_link.json"},
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
        "description": "Browser-side attack detection using SOC Application Logs, a custom OpenTelemetry-shaped JSON source for browser and application telemetry. Showcase row at the top renders cross-tier trace correlation with the WAF and OWASP attack-mix breakdowns. Detection widgets below cover XSS, SQLi, CSRF, session hijacking, clickjacking, DOM attacks, cryptomining, and fingerprinting across monitored applications.",
        "widgets": [
            {"title": "APM: Total Browser Attacks (24h)", "query_file": "apps/apm_total_attacks_kpi.json"},
            {"title": "APM: OWASP Attack Mix by Service", "query_file": "apps/apm_owasp_breakdown_sunburst.json"},
            {"title": "APM: Browser Attack -> WAF Correlation", "query_file": "apps/apm_attack_to_waf_correlation.json"},
            {"title": "APM: Trace Correlation (APM x WAF)", "query_file": "apps/apm_trace_correlation_link.json"},
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


SENTINEL_DASHBOARD_GROUPS = {
    "identity": "SOC: Microsoft Sentinel Identity Converted Detections",
    "endpoint": "SOC: Microsoft Sentinel Endpoint Converted Detections",
    "azure_cloud": "SOC: Microsoft Sentinel Azure Cloud Converted Detections",
    "m365": "SOC: Microsoft Sentinel M365 Converted Detections",
    "network": "SOC: Microsoft Sentinel Network Converted Detections",
}

SENTINEL_DASHBOARD_DESCRIPTIONS = {
    "identity": "Live-validated Microsoft Sentinel identity detections converted to OCI Log Analytics Logan QL.",
    "endpoint": "Live-validated Microsoft Sentinel endpoint detections converted to OCI Log Analytics Logan QL.",
    "azure_cloud": "Live-validated Microsoft Sentinel Azure cloud detections converted to OCI Log Analytics Logan QL.",
    "m365": "Live-validated Microsoft Sentinel Microsoft 365 detections converted to OCI Log Analytics Logan QL.",
    "network": "Live-validated Microsoft Sentinel network detections converted to OCI Log Analytics Logan QL.",
}

SENTINEL_LIVE_VALIDATION_PASS_VALUES = {"passed", "ok", "success"}
SENTINEL_DASHBOARD_UNSUPPORTED_QUERY_PATTERNS = (
    "Properties like",
)


def _as_sorted_strings(value):
    if isinstance(value, list):
        return sorted(str(item) for item in value if item)
    if value:
        return [str(value)]
    return []


def _sentinel_connector_names(connectors):
    names = []
    if not isinstance(connectors, list):
        return names
    for connector in connectors:
        if not isinstance(connector, dict):
            continue
        connector_id = connector.get("connector_id") or connector.get("connectorId")
        if connector_id:
            names.append(str(connector_id))
        for data_type in connector.get("data_types") or connector.get("dataTypes") or []:
            if data_type:
                names.append(str(data_type))
    return sorted(set(names))


def _sentinel_coverage_keys(payload):
    keys = []
    for table in _as_sorted_strings(payload.get("sentinel_tables")):
        keys.append(("table", table))
    if payload.get("level"):
        keys.append(("level", str(payload["level"])))
    mitre = payload.get("mitre_attack", {})
    if isinstance(mitre, dict):
        for technique in _as_sorted_strings(mitre.get("techniques")):
            keys.append(("technique", technique))
    for connector in _sentinel_connector_names(payload.get("required_data_connectors")):
        keys.append(("connector", connector))
    if not keys:
        keys.append(("query", payload.get("title", "")))
    return tuple(keys)


def _select_sentinel_dashboard_widgets(widgets, max_widgets):
    """Choose a deterministic, coverage-aware subset of Sentinel widgets."""
    remaining = sorted(widgets, key=lambda item: (item.get("title", ""), item.get("query_file", "")))
    selected = []
    covered = set()
    while remaining and len(selected) < max_widgets:
        best_index = 0
        best_score = None
        for index, widget in enumerate(remaining):
            coverage = set(widget.get("_coverage_keys", ()))
            new_coverage = len(coverage - covered)
            score = (-new_coverage, widget.get("title", ""), widget.get("query_file", ""))
            if best_score is None or score < best_score:
                best_index = index
                best_score = score
        widget = remaining.pop(best_index)
        covered.update(widget.get("_coverage_keys", ()))
        selected.append({key: value for key, value in widget.items() if not key.startswith("_")})
    return selected


def load_sentinel_dashboard_groups(queries_dir=QUERIES_DIR, max_widgets=24):
    """Load Sentinel dashboard groups from live-validated converted query JSON."""
    sentinel_dir = os.path.join(queries_dir, "sentinel")
    if not os.path.isdir(sentinel_dir):
        return {}

    grouped = {category: [] for category in SENTINEL_DASHBOARD_GROUPS}
    for filename in sorted(os.listdir(sentinel_dir)):
        if not filename.endswith(".json"):
            continue
        path = os.path.join(sentinel_dir, filename)
        try:
            with open(path) as f:
                payload = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue

        if payload.get("source_type") != "microsoft_sentinel":
            continue
        if payload.get("conversion_status") != "promoted":
            continue
        if str(payload.get("live_validation_status", "")).lower() not in SENTINEL_LIVE_VALIDATION_PASS_VALUES:
            continue
        if any(pattern in payload.get("query", "") for pattern in SENTINEL_DASHBOARD_UNSUPPORTED_QUERY_PATTERNS):
            continue

        category = payload.get("sentinel_category", "")
        if category not in grouped:
            continue

        dashboard_meta = payload.get("dashboard", {})
        grouped[category].append({
            "title": f"Sentinel: {payload.get('title', filename)}",
            "query_file": f"sentinel/{filename}",
            "visualization_type": dashboard_meta.get("visualizationType", "table"),
            "_coverage_keys": _sentinel_coverage_keys(payload),
        })

    dashboards = {}
    for category, widgets in grouped.items():
        if not widgets:
            continue
        dashboards[SENTINEL_DASHBOARD_GROUPS[category]] = {
            "description": SENTINEL_DASHBOARD_DESCRIPTIONS[category],
            "widgets": _select_sentinel_dashboard_widgets(widgets, max_widgets),
        }
    return dashboards


DASHBOARDS.update(load_sentinel_dashboard_groups())


# ─── Query and Dashboard Inventory Helpers ───────────────────────

def select_dashboards(dashboard_names=None, dashboards=None):
    """Return a display-name keyed dashboard subset for targeted operations."""
    dashboards = dashboards or DASHBOARDS
    if not dashboard_names:
        return dashboards

    selected = {}
    name_lookup = {name.lower(): name for name in dashboards}
    missing = []
    for requested_name in dashboard_names:
        canonical_name = requested_name if requested_name in dashboards else None
        if canonical_name is None:
            canonical_name = name_lookup.get(requested_name.lower())
        if canonical_name is None:
            missing.append(requested_name)
            continue
        selected[canonical_name] = dashboards[canonical_name]

    if missing:
        available = ", ".join(sorted(dashboards))
        raise ValueError(
            f"unknown dashboard name(s): {', '.join(missing)}. "
            f"Available dashboards: {available}"
        )

    return selected


def load_query_info(query_file, queries_dir=QUERIES_DIR):
    """Load and validate one query JSON payload referenced by a dashboard widget."""
    query_path = os.path.join(queries_dir, query_file)
    if not os.path.exists(query_path):
        raise FileNotFoundError(f"missing query file: {query_file}")
    if not is_saved_search_query_file(query_path):
        raise ValueError(f"{query_file}: generated support artifact is not a saved-search query file")

    with open(query_path, "r") as f:
        query_info = json.load(f)

    if not isinstance(query_info, dict):
        raise ValueError(f"{query_file}: query payload must be an object")
    if not query_info.get("title"):
        raise ValueError(f"{query_file}: missing title")
    if not query_info.get("query"):
        raise ValueError(f"{query_file}: missing query")

    return query_info


def _resolve_ask_ai_prompts(widget, query_info):
    dashboard_meta = query_info.get("dashboard", {}) if isinstance(query_info, dict) else {}
    return widget.get("ask_ai_prompts", dashboard_meta.get("ask_ai_prompts", []))


def _quote_context_indicates_field(query, start, end):
    after = query[end:]
    before = query[:start]
    if FIELD_OPERATOR_RE.match(after):
        return True
    return bool(re.search(r"\b(?:distinctcount|unique|count|sum|max|min|avg|average)\s*\($", before[-32:].lower()))


def extract_dashboard_query_fields(query):
    fields = []
    for value, start, end in _iter_quoted_values(query):
        if value not in fields and _quote_context_indicates_field(query, start, end):
            fields.append(value)
    for by_match in re.finditer(
        r"\|\s*(?:stats|timestats|eventstats|link)[^|]*\bby\b(?P<clause>[^|]+)",
        query,
        flags=re.IGNORECASE,
    ):
        for value, _start, _end in _iter_quoted_values(by_match.group("clause")):
            if value not in fields:
                fields.append(value)
    for fields_match in re.finditer(r"\|\s*fields\s+(?P<clause>[^|]+)", query, flags=re.IGNORECASE):
        for value, _start, _end in _iter_quoted_values(fields_match.group("clause")):
            if value not in fields:
                fields.append(value)
    return fields


def build_widget_drilldowns(query_info):
    """Return lightweight field-pivot metadata for downstream UIs."""
    fields = [
        field for field in extract_dashboard_query_fields(query_info.get("query", ""))
        if field not in {"Log Source", "Count"}
    ]
    return [
        {
            "type": "log_explorer_field_pivot",
            "field": field,
            "label": f"Pivot by {field}",
        }
        for field in fields[:6]
    ]


def score_dashboard_widget_quality(ui_config, layout):
    """Additive dashboard-quality metadata; live row health is filled by CAP checks."""
    checks = {
        "no_overlap": True,
        "supported_visualization": ui_config["visualizationType"] in SUPPORTED_VISUALIZATION_TYPES,
        "widget_returns_rows_in_cap": "not_run",
        "field_contract_coverage": "not_evaluated",
        "visualization_task_fit": "not_scored",
    }
    score = 100
    if not checks["supported_visualization"]:
        score -= 40
    if layout["width"] > DASHBOARD_GRID_COLUMNS or layout["width"] < 1:
        score -= 20
    if layout["height"] < 1:
        score -= 20
    return {
        "score": max(score, 0),
        "checks": checks,
    }


def _build_widget_inventory_record(dashboard_name, dashboard_index, widget, widget_index, queries_dir):
    query_info = load_query_info(widget["query_file"], queries_dir=queries_dir)
    ui_config = resolve_widget_ui_config(widget, query_info)
    layout = resolve_widget_layout(widget, query_info)

    return {
        "dashboard_name": dashboard_name,
        "dashboard_index": dashboard_index,
        "widget_index": widget_index,
        "title": widget["title"],
        "query_file": widget["query_file"],
        "query_title": query_info["title"],
        "description": query_info.get("description", ""),
        "level": query_info.get("level", ""),
        "type": query_info.get("type", "detection" if query_info.get("sigma_id") else "curated"),
        "sigma_id": query_info.get("sigma_id", ""),
        "tags": query_info.get("tags", []),
        "references": query_info.get("references", []),
        "logsource": query_info.get("logsource", {}),
        "mitre_attack": query_info.get("mitre_attack", {}),
        "visualization_type": ui_config["visualizationType"],
        "visualization_options": ui_config.get("visualizationOptions", {}),
        "time_selection": ui_config.get("timeSelection", {}),
        "layout": layout,
        "ask_ai_prompts": _resolve_ask_ai_prompts(widget, query_info),
        "advanced_visualization": ui_config["visualizationType"] in ADVANCED_VISUALIZATION_TYPES,
        "drilldowns": build_widget_drilldowns(query_info),
        "dashboard_quality": score_dashboard_widget_quality(ui_config, layout),
    }


def build_dashboard_inventory(dashboards=None, queries_dir=QUERIES_DIR, generated_at=None):
    """Build a dashboard/widget inventory artifact from ``DASHBOARDS``.

    The resulting JSON is the dashboard-facing contract. It lets downstream UI
    code consume dashboard/widget/query metadata without importing or parsing
    this Python deployment script at runtime.
    """
    dashboards = dashboards or DASHBOARDS
    generated_at = generated_at or datetime.now(timezone.utc).isoformat()

    dashboard_records = []
    visualization_counts = Counter()
    level_counts = Counter()
    total_widgets = 0

    for dashboard_index, (dashboard_name, config) in enumerate(dashboards.items()):
        widget_records = []
        for widget_index, widget in enumerate(config["widgets"]):
            record = _build_widget_inventory_record(
                dashboard_name=dashboard_name,
                dashboard_index=dashboard_index,
                widget=widget,
                widget_index=widget_index,
                queries_dir=queries_dir,
            )
            widget_records.append(record)
            visualization_counts[record["visualization_type"]] += 1
            if record["level"]:
                level_counts[record["level"]] += 1

        total_widgets += len(widget_records)
        dashboard_records.append({
            "name": dashboard_name,
            "description": config.get("description", ""),
            "widget_count": len(widget_records),
            "widgets": widget_records,
        })

    return {
        "version": "1.0",
        "generated_at": generated_at,
        "source": "scripts/deploy_dashboard.py:DASHBOARDS",
        "summary": {
            "total_dashboards": len(dashboard_records),
            "total_widgets": total_widgets,
            "advanced_visualization_widgets": sum(
                count for viz, count in visualization_counts.items()
                if viz in ADVANCED_VISUALIZATION_TYPES
            ),
            "visualization_types": dict(sorted(visualization_counts.items())),
            "levels": dict(sorted(level_counts.items())),
        },
        "dashboards": dashboard_records,
    }


def _resolve_inventory_source_widget(dashboard_name, inventory_widget):
    """Find the source DASHBOARDS widget for an inventory widget."""
    dashboard_config = DASHBOARDS.get(dashboard_name, {})
    source_widgets = dashboard_config.get("widgets", [])
    widget_index = inventory_widget.get("widget_index")
    query_file = inventory_widget.get("query_file")

    if isinstance(widget_index, int) and 0 <= widget_index < len(source_widgets):
        source_widget = source_widgets[widget_index]
        if source_widget.get("query_file") == query_file:
            return source_widget

    for source_widget in source_widgets:
        if (
            source_widget.get("query_file") == query_file
            and source_widget.get("title") == inventory_widget.get("title")
        ):
            return source_widget

    return inventory_widget


def validate_dashboard_inventory(inventory, queries_dir=QUERIES_DIR):
    """Validate that an inventory artifact still matches query metadata."""
    errors = []
    dashboards = inventory.get("dashboards", [])

    summary = inventory.get("summary", {})
    expected_dashboard_count = len(dashboards)
    actual_widget_count = sum(len(dashboard.get("widgets", [])) for dashboard in dashboards)

    if summary.get("total_dashboards") != expected_dashboard_count:
        errors.append(
            f"summary.total_dashboards mismatch: "
            f"{summary.get('total_dashboards')} != {expected_dashboard_count}"
        )
    if summary.get("total_widgets") != actual_widget_count:
        errors.append(
            f"summary.total_widgets mismatch: "
            f"{summary.get('total_widgets')} != {actual_widget_count}"
        )

    for dashboard in dashboards:
        dashboard_name = dashboard.get("name", "<unknown dashboard>")
        widgets = dashboard.get("widgets", [])
        if dashboard.get("widget_count") != len(widgets):
            errors.append(f"{dashboard_name}: widget_count mismatch")

        for widget in widgets:
            query_file = widget.get("query_file", "")
            label = f"{dashboard_name} / {query_file}"
            try:
                query_info = load_query_info(query_file, queries_dir=queries_dir)
                source_widget = _resolve_inventory_source_widget(dashboard_name, widget)
                ui_config = resolve_widget_ui_config(source_widget, query_info)
            except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
                errors.append(f"{label}: {exc}")
                continue

            if widget.get("query_title") != query_info.get("title"):
                errors.append(
                    f"{label}: query_title mismatch "
                    f"({widget.get('query_title')!r} != {query_info.get('title')!r})"
                )

            if widget.get("references", []) != query_info.get("references", []):
                errors.append(f"{label}: references mismatch")

            expected_viz = ui_config["visualizationType"]
            if widget.get("visualization_type") != expected_viz:
                errors.append(
                    f"{label}: visualization_type mismatch "
                    f"({widget.get('visualization_type')!r} != {expected_viz!r})"
                )

            expected_layout = resolve_widget_layout(source_widget, query_info)
            if widget.get("layout") != expected_layout:
                errors.append(
                    f"{label}: layout mismatch "
                    f"({widget.get('layout')!r} != {expected_layout!r})"
                )

    return errors


def write_dashboard_inventory(path=DASHBOARD_INVENTORY_PATH, inventory=None):
    """Write the generated dashboard inventory artifact to disk."""
    inventory = inventory or build_dashboard_inventory()
    errors = validate_dashboard_inventory(inventory)
    if errors:
        raise ValueError("dashboard inventory validation failed:\n" + "\n".join(errors))

    with open(path, "w") as f:
        json.dump(inventory, f, indent=2)
        f.write("\n")

    return path


def iter_inventory_widgets(inventory):
    """Yield all widget inventory records."""
    for dashboard in inventory.get("dashboards", []):
        for widget in dashboard.get("widgets", []):
            yield widget


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

def resolve_widget_ui_config(widget, query_info):
    """Resolve visualization and investigation metadata for a widget.

    Query-local dashboard metadata is the default. Explicit widget-level
    overrides win if they are provided in ``DASHBOARDS``.
    """
    dashboard_meta = query_info.get("dashboard", {}) if isinstance(query_info, dict) else {}

    visualization_type = widget.get(
        "visualization_type",
        dashboard_meta.get("visualizationType", "table"),
    )
    if visualization_type not in SUPPORTED_VISUALIZATION_TYPES:
        raise ValueError(f"unsupported visualization type: {visualization_type}")

    visualization_options = dashboard_meta.get("visualizationOptions", {}).copy()
    visualization_options.update(widget.get("visualization_options", {}))

    ask_ai_prompts = widget.get("ask_ai_prompts", dashboard_meta.get("ask_ai_prompts", []))
    if ask_ai_prompts and not isinstance(ask_ai_prompts, list):
        raise ValueError("ask_ai_prompts must be a list of strings")

    return {
        "enableWidgetInApp": True,
        "queryString": query_info["query"],
        "scopeFilters": build_scope_filters(COMPARTMENT_ID),
        "showTitle": widget.get("show_title", dashboard_meta.get("showTitle", True)),
        "timeSelection": widget.get(
            "time_selection",
            dashboard_meta.get("timeSelection", {"timePeriod": DEFAULT_DASHBOARD_TIME_PERIOD}),
        ),
        "visualizationOptions": visualization_options,
        "visualizationType": visualization_type,
        "vizType": "lxSavedSearchWidgetType",
    }


def _coerce_layout_dimension(value, fallback, lower_bound, upper_bound=None):
    """Normalize widget layout dimensions from query/widget metadata."""
    try:
        dimension = int(value)
    except (TypeError, ValueError):
        dimension = fallback
    dimension = max(lower_bound, dimension)
    if upper_bound is not None:
        dimension = min(upper_bound, dimension)
    return dimension


def resolve_widget_layout(widget, query_info):
    """Return OCI dashboard tile dimensions for one widget.

    Wide result sets are the default in this repository, so table-like
    visualizations receive full-width tiles unless explicitly overridden.
    """
    dashboard_meta = query_info.get("dashboard", {}) if isinstance(query_info, dict) else {}
    visualization_type = resolve_widget_ui_config(widget, query_info)["visualizationType"]
    layout = VISUALIZATION_LAYOUT_DEFAULTS.get(visualization_type, {"width": 12, "height": 5}).copy()

    metadata_layout = dashboard_meta.get("layout", {})
    if isinstance(metadata_layout, dict):
        layout.update(metadata_layout)

    widget_layout = widget.get("layout", {})
    if isinstance(widget_layout, dict):
        layout.update(widget_layout)

    width = _coerce_layout_dimension(
        layout.get("width"),
        VISUALIZATION_LAYOUT_DEFAULTS.get(visualization_type, {}).get("width", 12),
        lower_bound=1,
        upper_bound=DASHBOARD_GRID_COLUMNS,
    )
    height = _coerce_layout_dimension(
        layout.get("height"),
        VISUALIZATION_LAYOUT_DEFAULTS.get(visualization_type, {}).get("height", 5),
        lower_bound=1,
    )
    return {"width": width, "height": height}


def build_saved_search_json(search_id, title, query, description="", tags=None, ui_config=None):
    """Build a saved search JSON definition for embedding in a dashboard import.

    The import_dashboard API requires saved searches to be embedded in the
    dashboard JSON. Tiles reference them by their 'id' field (not OCID).
    """
    if ui_config is None:
        ui_config = {
            "enableWidgetInApp": True,
            "queryString": query,
            "scopeFilters": build_scope_filters(COMPARTMENT_ID),
            "showTitle": True,
            "timeSelection": {"timePeriod": DEFAULT_DASHBOARD_TIME_PERIOD},
            "visualizationOptions": {},
            "visualizationType": "table",
            "vizType": "lxSavedSearchWidgetType",
        }

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
        "uiConfig": ui_config,
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
    current_row = 0
    current_column = 0
    current_row_height = 0

    for i, (widget, query_info) in enumerate(zip(widgets, widget_queries)):
        if query_info is None:
            continue

        # Generate a stable short ID from the query filename
        search_id = widget['query_file'].replace('.json', '').replace('_', '-')

        layout = resolve_widget_layout(widget, query_info)
        width = layout["width"]
        height = layout["height"]

        if current_column and current_column + width > DASHBOARD_GRID_COLUMNS:
            current_row += current_row_height
            current_column = 0
            current_row_height = 0

        row = current_row
        col = current_column

        # Build the tile referencing the saved search by short ID
        tiles.append({
            "displayName": widget['title'],
            "savedSearchId": search_id,
            "row": row,
            "column": col,
            "height": height,
            "width": width,
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

        current_column += width
        current_row_height = max(current_row_height, height)
        if current_column >= DASHBOARD_GRID_COLUMNS:
            current_row += current_row_height
            current_column = 0
            current_row_height = 0

        # Build the embedded saved search definition
        tags = {}
        if query_info.get('tags'):
            tags["mitre_techniques"] = ",".join(query_info['tags'])
        if query_info.get('sigma_id'):
            tags["sigma_id"] = query_info['sigma_id']
        tags["platform"] = "soc-detection-rules"
        dashboard_meta = query_info.get("dashboard", {})
        if dashboard_meta.get("ask_ai_prompts"):
            tags["ask_ai_prompts"] = json.dumps(dashboard_meta["ask_ai_prompts"])
        if dashboard_meta.get("visualizationType"):
            tags["visualization_type"] = dashboard_meta["visualizationType"]

        ui_config = resolve_widget_ui_config(widget, query_info)

        saved_searches.append(build_saved_search_json(
            search_id=search_id,
            title=widget['title'],
            query=query_info['query'],
            description=query_info.get('description', ''),
            tags=tags,
            ui_config=ui_config,
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
                "defaultValue": DEFAULT_DASHBOARD_TIME_PERIOD,
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


def import_dashboard(md_client, dashboard_json, attempts=3):
    """Import a dashboard using the ManagementDashboardImportDetails API."""
    import_details = oci.management_dashboard.models.ManagementDashboardImportDetails(
        dashboards=[dashboard_json]
    )

    display_name = dashboard_json["displayName"]
    for attempt in range(1, attempts + 1):
        try:
            md_client.import_dashboard(import_details)
            print(f"  Imported dashboard: {display_name}")
            return True
        except oci.exceptions.ServiceError as exc:
            print(f"  Error importing '{display_name}': {exc.message[:200]}")
            return False
        except oci.exceptions.RequestException as exc:
            if attempt == attempts:
                print(f"  Error importing '{display_name}' after {attempts} attempts: {exc}")
                return False
            delay = attempt * 10
            print(
                f"  Retry {attempt}/{attempts - 1} importing '{display_name}' "
                f"after transient OCI request error: {exc}"
            )
            time.sleep(delay)


# ─── Live Query Validation ───────────────────────────────────────

@contextmanager
def query_deadline(seconds):
    """Raise TimeoutError when one live OCI validation query runs too long."""
    if not seconds or not hasattr(signal, "SIGALRM"):
        yield
        return

    def _raise_timeout(_signum, _frame):
        raise TimeoutError(f"query validation exceeded {seconds}s")

    previous_handler = signal.signal(signal.SIGALRM, _raise_timeout)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)


def validate_query_in_oci(la_client, namespace, query_file, query_string, lookback, timeout=None):
    """Execute a query against OCI Log Analytics to catch parser/runtime errors."""
    time_start, time_end = build_time_window(lookback)
    try:
        with query_deadline(timeout):
            response = la_client.query(
                namespace_name=namespace,
                query_details=oci.log_analytics.models.QueryDetails(
                    compartment_id=COMPARTMENT_ID,
                    compartment_id_in_subtree=True,
                    query_string=query_string,
                    sub_system="LOG",
                    time_filter=oci.log_analytics.models.TimeRange(
                        time_start=time_start,
                        time_end=time_end,
                        time_zone="UTC",
                    ),
                    max_total_count=1,
                ),
            ).data
        rows = len(getattr(response, "items", []) or [])
        return {
            "query_file": query_file,
            "ok": True,
            "rows": rows,
            "empty": rows == 0,
            "error": "",
        }
    except Exception as exc:
        return {
            "query_file": query_file,
            "ok": False,
            "rows": 0,
            "empty": False,
            "error": str(exc),
        }


def _validate_query_worker(queue, namespace, query_file, query_string, lookback, client_timeout):
    """Run one OCI query validation in a child process."""
    la_client = get_la_client(timeout=(10, client_timeout))
    result = validate_query_in_oci(
        la_client=la_client,
        namespace=namespace,
        query_file=query_file,
        query_string=query_string,
        lookback=lookback,
        timeout=None,
    )
    queue.put(result)


def validate_query_in_oci_isolated(namespace, query_file, query_string, lookback, query_timeout):
    """Validate one query in a killable child process."""
    context_name = "fork" if hasattr(os, "fork") else "spawn"
    context = multiprocessing.get_context(context_name)
    queue = context.Queue()
    process = context.Process(
        target=_validate_query_worker,
        args=(queue, namespace, query_file, query_string, lookback, query_timeout),
    )

    process.start()
    process.join(query_timeout + 5)

    if process.is_alive():
        process.terminate()
        process.join(5)
        return {
            "query_file": query_file,
            "ok": False,
            "rows": 0,
            "empty": False,
            "error": f"query validation exceeded {query_timeout}s",
        }

    if process.exitcode != 0 and queue.empty():
        return {
            "query_file": query_file,
            "ok": False,
            "rows": 0,
            "empty": False,
            "error": f"query validation process exited with code {process.exitcode}",
        }

    if queue.empty():
        return {
            "query_file": query_file,
            "ok": False,
            "rows": 0,
            "empty": False,
            "error": "query validation process returned no result",
        }

    return queue.get()


def resolve_validation_namespace(client_timeout):
    """Resolve the Log Analytics namespace for live validation."""
    if LA_NAMESPACE:
        print(f"  Namespace (from env): {LA_NAMESPACE}")
        return LA_NAMESPACE
    la_client = get_la_client(timeout=(10, client_timeout))
    return get_namespace(la_client)


def _redact_progress_text(value):
    redacted = str(value or "")
    for pattern, replacement in PROGRESS_REDACTIONS:
        redacted = pattern.sub(replacement, redacted)
    return " ".join(redacted.split())


def _validation_status(result):
    if not result.get("ok"):
        return "failed"
    if result.get("empty"):
        return "empty"
    return "passed"


def _should_emit_validation_progress(progress, progress_interval, index, total):
    if not progress:
        return False
    interval = int(progress_interval or 1)
    if interval <= 1:
        return True
    return index == 1 or index == total or index % interval == 0


def _format_validation_progress(index, total, result):
    status = _validation_status(result)
    query_file = result.get("query_file", "<unknown>")
    rows = result.get("rows", 0)
    message = f"    [{index:03d}/{total:03d}] {query_file} status={status} rows={rows}"
    if status == "failed" and result.get("error"):
        error = _redact_progress_text(result["error"])
        message = f"{message} error={error[:180]}"
    return message


def validate_inventory_queries_in_oci(
    inventory,
    lookback=DEFAULT_QUERY_VALIDATION_LOOKBACK,
    query_timeout=60,
    progress=False,
    progress_interval=1,
    isolated=True,
):
    """Validate every unique inventory query in OCI before dashboard import."""
    namespace = resolve_validation_namespace(query_timeout)
    la_client = None if isolated else get_la_client(timeout=(10, query_timeout))

    query_files = sorted({widget["query_file"] for widget in iter_inventory_widgets(inventory)})
    seen = {}
    for index, query_file in enumerate(query_files, start=1):
        emit_progress = _should_emit_validation_progress(progress, progress_interval, index, len(query_files))
        if emit_progress:
            print(f"    [{index:03d}/{len(query_files):03d}] validating {query_file}", flush=True)
        query_info = load_query_info(query_file)
        if isolated:
            seen[query_file] = validate_query_in_oci_isolated(
                namespace=namespace,
                query_file=query_file,
                query_string=query_info["query"],
                lookback=lookback,
                query_timeout=query_timeout,
            )
        else:
            seen[query_file] = validate_query_in_oci(
                la_client=la_client,
                namespace=namespace,
                query_file=query_file,
                query_string=query_info["query"],
                lookback=lookback,
                timeout=query_timeout,
            )
        if emit_progress:
            print(_format_validation_progress(index, len(query_files), seen[query_file]), flush=True)

    return [seen[query_file] for query_file in query_files]


# ─── Cleanup ──────────────────────────────────────────────────────

def cleanup_soc_content(md_client, dashboards=None):
    """Delete all SOC-related saved searches and dashboards."""
    dashboards = dashboards or DASHBOARDS
    print("\n  Cleaning up existing SOC content...")

    # Delete dashboards
    for dashboard_name in dashboards.keys():
        try:
            dashboard_items = md_client.list_management_dashboards(
                compartment_id=COMPARTMENT_ID,
                display_name=dashboard_name
            ).data.items
            for d in dashboard_items:
                try:
                    md_client.delete_management_dashboard(d.dashboard_id)
                    print(f"    - Deleted dashboard: {dashboard_name}")
                except Exception:
                    pass
        except Exception:
            pass

    # Delete saved searches
    all_widget_titles = set()
    for config in dashboards.values():
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

def deploy(
    cleanup=False,
    dry_run=False,
    live_validate=True,
    query_lookback=DEFAULT_QUERY_VALIDATION_LOOKBACK,
    query_timeout=60,
    validation_progress_interval=1,
    dashboard_names=None,
):
    print("=" * 60)
    print("OCI Log Analytics - SOC Dashboard Deployment")
    print("=" * 60)

    try:
        dashboards_to_deploy = select_dashboards(dashboard_names)
    except ValueError as exc:
        print(f"\n  {exc}")
        raise SystemExit(1) from exc

    inventory = build_dashboard_inventory(dashboards=dashboards_to_deploy)
    inventory_errors = validate_dashboard_inventory(inventory)
    if inventory_errors:
        print("\n  Dashboard inventory validation failed:")
        for error in inventory_errors:
            print(f"    - {error}")
        raise SystemExit(1)

    if dry_run:
        print("\n  [DRY RUN] No changes will be made.\n")
        for dashboard in inventory["dashboards"]:
            print(f"  Dashboard: {dashboard['name']}")
            print(f"    Widgets: {dashboard['widget_count']}")
            for widget in dashboard["widgets"]:
                print(
                    f"      - {widget['title']} ({widget['query_file']}) "
                    f"[viz={widget['visualization_type']}]"
                )
        print(
            f"\n  Total: {inventory['summary']['total_dashboards']} dashboards, "
            f"{inventory['summary']['total_widgets']} saved searches"
        )
        return

    if live_validate:
        print(
            f"\n  Validating dashboard queries in OCI Log Analytics "
            f"(lookback={query_lookback}, timeout={query_timeout}s)..."
        )
        live_results = validate_inventory_queries_in_oci(
            inventory,
            lookback=query_lookback,
            query_timeout=query_timeout,
            progress=validation_progress_interval != 0,
            progress_interval=validation_progress_interval,
        )
        errors = [result for result in live_results if not result["ok"]]
        empty = [result for result in live_results if result["ok"] and result["empty"]]

        if errors:
            print("  Query validation failed; no dashboards or saved searches will be imported.")
            for result in errors:
                print(f"    - {result['query_file']}: {result['error'][:180]}")
            raise SystemExit(1)

        print(f"  Validated {len(live_results)} unique query files in OCI Log Analytics.")
        if empty:
            print(f"  Note: {len(empty)} validated query files returned no rows in this window.")

    # Publish the dashboard-facing artifact only after local and optional live
    # validation pass. Dashboard import and saved-search mapping happen after this.
    if dashboard_names:
        print("\n  Targeted deployment: queries/dashboard_inventory.json was not rewritten.")
    else:
        write_dashboard_inventory(inventory=inventory)
        print(f"\n  Dashboard inventory: {DASHBOARD_INVENTORY_PATH}")

    md_client = get_dashboard_client()
    print(f"\n  Compartment: {COMPARTMENT_ID}")

    if cleanup:
        cleanup_soc_content(md_client, dashboards=dashboards_to_deploy)

    total_searches = 0
    total_dashboards = 0

    for dashboard_name, dashboard_config in dashboards_to_deploy.items():
        print(f"\n{'─' * 50}")
        print(f"  Dashboard: {dashboard_name}")
        print(f"  Widgets: {len(dashboard_config['widgets'])}")
        print(f"{'─' * 50}")

        # Load query data only after local and optional live validation pass.
        widget_queries = []
        for widget in dashboard_config['widgets']:
            rule_data = load_query_info(widget["query_file"])
            widget_queries.append(rule_data)
            print(f"    + Loaded: {widget['title']}")
            total_searches += 1

        # Build and import dashboard with embedded saved searches
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
    parser.add_argument('--export-inventory', action='store_true',
                        help='Generate queries/dashboard_inventory.json and exit')
    parser.add_argument('--inventory-path', default=DASHBOARD_INVENTORY_PATH,
                        help='Output path for --export-inventory')
    parser.add_argument('--skip-live-validation', action='store_true',
                        help='Skip live OCI query validation before dashboard import')
    parser.add_argument('--query-lookback', default=DEFAULT_QUERY_VALIDATION_LOOKBACK,
                        help='Lookback window for live OCI query validation')
    parser.add_argument('--query-timeout', type=int, default=60,
                        help='Per-query timeout in seconds for live OCI query validation')
    parser.add_argument('--validation-progress-interval', type=int, default=1,
                        help='Print live query validation progress every N queries; 0 disables progress')
    parser.add_argument('--dashboard-name', action='append', dest='dashboard_names',
                        help='Deploy only the named dashboard. Can be supplied multiple times.')
    args = parser.parse_args()

    if args.validate:
        ok = validate_oci_setup(['ocid', 'cli', 'namespace', 'compartment', 'query_files'])
        inventory = build_dashboard_inventory()
        inventory_errors = validate_dashboard_inventory(inventory)
        for error in inventory_errors:
            print(f"  [ERR ] Dashboard inventory: {error}")
        ok = ok and not inventory_errors
        sys.exit(0 if ok else 1)

    if args.export_inventory:
        path = write_dashboard_inventory(path=args.inventory_path)
        print(f"Dashboard inventory written to: {path}")
        sys.exit(0)

    deploy(
        cleanup=args.cleanup,
        dry_run=args.dry_run,
        live_validate=not args.skip_live_validation,
        query_lookback=args.query_lookback,
        query_timeout=args.query_timeout,
        validation_progress_interval=args.validation_progress_interval,
        dashboard_names=args.dashboard_names,
    )
