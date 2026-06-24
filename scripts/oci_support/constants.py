"""Static source, test-data, and stream catalogs for OCI SOC detections."""

CUSTOM_LOG_SOURCES = [
    "SOC Linux Syslog Logs",
    "SOC Windows Sysmon Logs",
    "SOC Sysmon Network Logs",
    "SOC Cloud Guard Logs",
    "SOC Cloud Guard Instance Security Logs",
    "SOC OSQuery Result Logs",
    "Windows PowerShell Operational Logs",
    "Windows Defender Operational Logs",
    "Azure Log Analytics Custom Logs",
    "SOC Application Logs",
    "SOC VCN Flow Logs",
    "SOC Network Firewall Logs",
]

# Preferred-to-fallback source candidates by detection family.
# Order matters: first match wins for runtime source selection.
SOURCE_CANDIDATE_GROUPS = {
    "oci_audit": [
        "OCI Audit Logs",
    ],
    "wazuh_alerts": [
        "SOC Wazuh Alerts",
    ],
    "wazuh_vulnerabilities": [
        "SOC Wazuh Vulnerabilities",
    ],
    "wazuh_inventory": [
        "SOC Wazuh Inventory",
    ],
    "wazuh_sca": [
        "SOC Wazuh SCA",
    ],
    # SOC source first: native OCI Cloud Guard Problems parser does not extract
    # the ``problemName`` JSON field that detections queries on, so test data
    # must land in SOC Cloud Guard Logs whose parser maps it to ``Problem Name``.
    "cloud_guard": [
        "SOC Cloud Guard Logs",
        "OCI Cloud Guard Problems",
        "OCI Cloud Guard Logs",
    ],
    "cloud_guard_instance_security": [
        "SOC Cloud Guard Instance Security Logs",
        "OCI Cloud Guard Instance Security Logs",
        "SOC OSQuery Result Logs",
    ],
    "osquery_results": [
        "SOC OSQuery Result Logs",
        "SOC Cloud Guard Instance Security Logs",
    ],
    # No exact native equivalent covers all SOC Linux Syslog detection patterns.
    "linux_syslog": [
        "SOC Linux Syslog Logs",
        "Linux Secure Logs",
        "Linux Syslog Logs",
        "Linux Audit Logs",
    ],
    # SOC source first: native sources use XML parsers that can't parse JSON uploads
    "windows_sysmon": [
        "SOC Windows Sysmon Logs",
        "Windows Sysmon Events",
        "Windows Sysmon Operational Logs",
    ],
    "windows_event_security": [
        "Windows Event Security Logs",
        "Windows Security Events",
    ],
    "windows_event_system": [
        "Windows Event System Logs",
    ],
    "windows_powershell_operational": [
        "Windows PowerShell Operational Logs",
    ],
    "windows_defender_operational": [
        "Windows Defender Operational Logs",
    ],
    # SOC source first: native ``Linux Secure Logs`` parser does not extract
    # ``Command Line`` from our JSON, so detection queries that LIKE on
    # argv (crontab -e, sudo -i, etc.) never match. SOC Linux Syslog parser
    # accepts the same JSON shape and exposes the Command Line column.
    "linux_secure": [
        "SOC Linux Syslog Logs",
        "Linux Secure Logs",
    ],
    # SOC source first: native sources use XML parsers that can't parse JSON uploads
    "sysmon_operational": [
        "Windows Sysmon Operational Logs",
        "SOC Windows Sysmon Logs",
        "Windows Sysmon Events",
    ],
    # Network connection events require a parser that maps Event ID 3 fields.
    "sysmon_network": [
        "SOC Sysmon Network Logs",
        "Windows Sysmon Operational Logs",
        "Windows Sysmon Events",
    ],
    "waf_security": [
        "SOC WAF Security Logs",
        "OCI WAF Logs",
    ],
    "lb_access": [
        "SOC Load Balancer Access Logs",
        "OCI Load Balancer Access Logs",
    ],
    "webapp_security": [
        "SOC Web Application Logs",
    ],
    "application_logs": [
        "SOC Application Logs",
    ],
    "genai_gateway": [
        "SOC GenAI Gateway Logs",
    ],
    "azure_log_analytics_custom": [
        "Azure Log Analytics Custom Logs",
        "SOC Application Logs",
    ],
    "vcn_flow": [
        "SOC VCN Flow Logs",
        "OCI VCN Flow Logs",
        "VCN Flow Logs",
    ],
    "network_firewall": [
        "SOC Network Firewall Logs",
        "OCI Network Firewall Logs",
        "Network Firewall Logs",
    ],
    "multicloud_health": [
        "SOC Multicloud Health Logs",
    ],
}

TEST_DATA_FILES = [
    "oci_audit.jsonl",
    "cloud_guard.jsonl",
    "cloud_guard_instance_security.jsonl",
    "linux_syslog.jsonl",
    "windows_sysmon.jsonl",
    "windows_event_security.jsonl",
    "windows_event_system.jsonl",
    "windows_powershell_operational.jsonl",
    "windows_defender_operational.jsonl",
    "linux_secure.jsonl",
    "sysmon_operational.jsonl",
    "sysmon_network.jsonl",
    "waf_security.jsonl",
    "lb_access.jsonl",
    "webapp_security.jsonl",
    "application_logs.jsonl",
    "genai_gateway.jsonl",
    "vcn_flow.jsonl",
    "network_firewall.jsonl",
    "multicloud_health.jsonl",
    "wazuh_alerts.jsonl",
    "wazuh_vulnerabilities.jsonl",
    "wazuh_inventory.jsonl",
    "wazuh_sca.jsonl",
]

CORE_SOC_STREAMS = [
    "soc-detection-oci-audit",
    "soc-detection-cloud-guard",
    "soc-detection-linux-audit",
    "soc-detection-windows-sysmon",
]
