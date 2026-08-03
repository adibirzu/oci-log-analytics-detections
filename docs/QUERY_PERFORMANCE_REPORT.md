# OCI Log Analytics Query Performance Audit

Audited **1337** saved-search artifacts; **791** have advisory or strict findings.

Static findings are risk indicators, not live performance proof. Leading-wildcard and raw-content searches require representative live timing before promotion.

| File | Leading wildcard | Raw content | Regex | Strict issue |
|---|---:|---:|---:|---|
| `queries/sentinel/tomcat_-_known_malicious_user_agent.json` | 90 | 0 | 0 | - |
| `queries/sentinel/imperva_-_malicious_user_agent.json` | 43 | 0 | 0 | - |
| `queries/sentinel/google_dns_-_requests_to_online_shares.json` | 42 | 0 | 0 | - |
| `queries/sentinel/nginx_-_command_in_uri.json` | 38 | 0 | 0 | - |
| `queries/sentinel/oracle_-_command_in_uri.json` | 38 | 0 | 0 | - |
| `queries/sentinel/tomcat_-_commands_in_uri.json` | 37 | 0 | 0 | - |
| `queries/web_server_process_spawning_command_shell.json` | 34 | 0 | 0 | - |
| `queries/powershell_suspicious_commands.json` | 32 | 0 | 0 | - |
| `queries/mimikatz_command_and_module_indicators_in_process_logs.json` | 31 | 0 | 0 | - |
| `queries/mimikatz_command_indicators.json` | 31 | 0 | 0 | - |
| `queries/cmd_suspicious_child_process.json` | 30 | 0 | 0 | - |
| `queries/web_directory_enumeration_detected.json` | 30 | 0 | 0 | - |
| `queries/sentinel/box_-_file_containing_sensitive_data.json` | 28 | 0 | 0 | - |
| `queries/web_vulnerability_scanner_detected.json` | 27 | 0 | 0 | - |
| `queries/apps/apm_sqli_attack_detection.json` | 24 | 0 | 0 | - |
| `queries/clickfix_fake_captcha_powershell_execution.json` | 24 | 0 | 0 | - |
| `queries/caldera_-_exfiltration_to_web_service_via_curl_linux.json` | 22 | 22 | 0 | - |
| `queries/hunting/coordinator_affected_hosts_kpi.json` | 22 | 22 | 0 | - |
| `queries/hunting/coordinator_attack_timeline.json` | 22 | 22 | 0 | - |
| `queries/hunting/coordinator_critical_alerts_kpi.json` | 22 | 22 | 0 | - |
| `queries/hunting/coordinator_mitre_sunburst.json` | 22 | 22 | 0 | - |
| `queries/hunting/coordinator_mitre_techniques_kpi.json` | 22 | 22 | 0 | - |
| `queries/hunting/coordinator_scenario_breakdown.json` | 22 | 22 | 0 | - |
| `queries/hunting/coordinator_top_affected_hosts.json` | 22 | 22 | 0 | - |
| `queries/hunting/coordinator_total_hits_kpi.json` | 22 | 22 | 0 | - |
| `queries/web_server_process_spawning_shell_with_injection_characters_linux.json` | 22 | 22 | 0 | - |
| `queries/caldera_-_credential_search_in_config_and_environment_files_windows.json` | 22 | 0 | 0 | - |
| `queries/waf_cross-site_scripting_attack_blocked.json` | 22 | 0 | 0 | - |
| `queries/caldera_-_credential_search_in_files_via_grep_linux.json` | 21 | 21 | 0 | - |
| `queries/sensitive_data_endpoint_access.json` | 21 | 0 | 0 | - |
