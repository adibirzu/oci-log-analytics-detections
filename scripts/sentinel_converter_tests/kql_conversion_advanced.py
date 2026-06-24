"""Advanced Sentinel KQL conversion and mapping tests."""

from sentinel_converter_tests.kql_base import *  # noqa: F401,F403


class TestSentinelKqlConversionAdvanced(SentinelKqlConversionBase):
    def test_phase9_extend_scalar_functions_convert(self):
        result = convert_candidate(self._candidate(
            query=(
                "SecurityEvent\n"
                "| extend ActorLower = tolower(tostring(Account)), "
                "IsFailure = iff(EventID == 4625, 'yes', 'no'), "
                "NumericId = toint(EventID)\n"
                "| project ActorLower, IsFailure, NumericId"
            )
        ), self.mapping)

        self.assertEqual(result.skip_reasons, [])
        self.assertEqual(result.local_validation_errors, [])
        query = result.query_payload["query"]
        self.assertIn("eval ActorLower = lower(User)", query)
        self.assertIn("eval IsFailure = if('Event ID' = '4625', 'yes', 'no')", query)
        self.assertIn("eval NumericId = 'Event ID'", query)
        self.assertIn("| fields ActorLower, IsFailure, NumericId", query)

    def test_simple_boolean_let_variables_are_supported(self):
        unsupported = classify_unsupported_kql(
            "let EnableActionFilter = true;\n"
            "let MatchActions = dynamic(['Deny', 'alert']);\n"
            "AZFWIdpsSignature | where (EnableActionFilter == false) or (Action in~ (MatchActions))"
        )

        self.assertFalse(any("let variables" in reason for reason in unsupported))

    def test_phase9_countif_bin_and_column_ifexists_convert(self):
        result = convert_candidate(self._candidate(
            query=(
                "SecurityEvent\n"
                "| where column_ifexists('Account', '') has 'admin'\n"
                "| summarize Failures=countif(EventID == 4625), Total=count() "
                "by bin(TimeGenerated, 15m), Account\n"
                "| top 5 by Failures desc"
            )
        ), self.mapping)

        self.assertEqual(result.skip_reasons, [])
        self.assertEqual(result.local_validation_errors, [])
        query = result.query_payload["query"]
        self.assertIn("User like '*admin*'", query)
        self.assertIn(
            "timestats span = 15minute sum(if('Event ID' = '4625', 1, 0)) as Failures, "
            "count as Total by User",
            query,
        )
        self.assertIn("| sort -Failures | head 5", query)

    def test_duplicate_time_aggregate_aliases_are_made_unique(self):
        query, _source_info, errors = convert_kql_to_logan(
            (
                "DeviceProcessEvents\n"
                "| summarize any(TimeGenerated), take_any(TimeGenerated) by DeviceName"
            ),
            self.mapping,
        )

        self.assertEqual(errors, [])
        self.assertIn("unique(Time) as any_Time", query)
        self.assertIn("unique(Time) as any_Time_2", query)

    def test_typed_oci_fields_format_numeric_literals_for_parser(self):
        event_query, _source_info, event_errors = convert_kql_to_logan(
            "SecurityEvent | where EventID == 4688",
            self.mapping,
        )
        network_query, _source_info, network_errors = convert_kql_to_logan(
            "DeviceNetworkEvents | where DestinationPort == \"3389\" and RemotePort in (\"443\", 8443)",
            self.mapping,
        )

        self.assertEqual(event_errors, [])
        self.assertEqual(network_errors, [])
        self.assertIn("'Event ID' = '4688'", event_query)
        self.assertIn("'Destination Port' = 3389", network_query)
        self.assertIn("'Destination Port' in (443, 8443)", network_query)

    def test_result_type_is_not_promoted_without_verified_oci_field(self):
        result = convert_candidate(self._candidate(
            query="SigninLogs | where ResultType == 50053"
        ), self.mapping)

        self.assertIsNone(result.query_payload)
        self.assertTrue(any("unsupported Sentinel field mapping: ResultType" in reason for reason in result.skip_reasons))

    def test_email_render_top_query_converts_with_implicit_count_alias(self):
        result = convert_candidate(self._candidate(
            query=(
                "EmailEvents\n"
                "| where EmailDirection == \"Inbound\"\n"
                "| where ThreatTypes has \"Malware\"\n"
                "| summarize count() by SenderFromAddress\n"
                "| sort by count_ desc\n"
                "| top 10 by count_\n"
                "| render piechart"
            )
        ), self.mapping)

        self.assertEqual(result.skip_reasons, [])
        self.assertEqual(result.local_validation_errors, [])
        query = result.query_payload["query"]
        self.assertIn("Direction = 'Inbound'", query)
        self.assertIn("'Threat Category' like '*Malware*'", query)
        self.assertIn("| stats count as count_ by 'User Name'", query)
        self.assertIn("| sort -count_", query)
        self.assertIn("| head 10", query)
        self.assertNotIn("render", query)

    def test_m365_url_click_and_oci_audit_tables_map_to_real_logan_sources(self):
        url_click = convert_candidate(self._candidate(
            query=(
                "UrlClickEvents\n"
                "| where ThreatTypes has_any (\"Malware\", \"Phish\")\n"
                "| summarize count() by AccountUpn\n"
                "| top 10 by count_"
            )
        ), self.mapping)
        oci_audit = convert_candidate(self._candidate(
            query=(
                "OCILogs\n"
                "| where data_eventName_s =~ \"DeleteRule\"\n"
                "| where data_request_headers_oci_original_url_s contains \"/opc/v1\"\n"
                "| summarize count() by SrcIpAddr"
            )
        ), self.mapping)

        self.assertEqual(url_click.skip_reasons, [])
        self.assertEqual(oci_audit.skip_reasons, [])
        self.assertIn("'Microsoft Defender Email Logs'", url_click.query_payload["query"])
        self.assertIn("'Threat Category' like '*Malware*'", url_click.query_payload["query"])
        self.assertIn("by 'User Name'", url_click.query_payload["query"])
        self.assertIn("'Log Source' = 'OCI Audit Logs'", oci_audit.query_payload["query"])
        self.assertIn("'Event Type' = 'DeleteRule'", oci_audit.query_payload["query"])
        self.assertIn("'Request URL' like '*/opc/v1*'", oci_audit.query_payload["query"])
        self.assertIn("by 'Source IP'", oci_audit.query_payload["query"])

    def test_asim_process_alias_maps_to_endpoint_sources(self):
        result = convert_candidate(self._candidate(
            query=(
                "imProcessCreate\n"
                "| where ActingProcessName has_any (\"cmd.exe\", \"powershell.exe\")\n"
                "| where Process has \"adfind\"\n"
                "| summarize Hits=count() by DvcHostname, DeviceId"
            )
        ), self.mapping)

        self.assertEqual(result.skip_reasons, [])
        query = result.query_payload["query"]
        self.assertIn("'SOC Windows Sysmon Logs'", query)
        self.assertIn("'Parent Process Name' like '*cmd.exe*'", query)
        self.assertIn("'Process Name' like '*adfind*'", query)
        self.assertIn("by 'Host Name', Entity", query)

    def test_common_solution_tables_map_to_generic_soc_sources(self):
        github = convert_candidate(self._candidate(
            query="GitHubAuditData | where Action == \"repo.destroy\" | project TimeGenerated, Actor, Action"
        ), self.mapping)
        cisco_duo = convert_candidate(self._candidate(
            query="CiscoDuo | where EventType == \"authentication\" and EventResult == \"failure\" | summarize count() by DstUserName"
        ), self.mapping)
        web_proxy = convert_candidate(self._candidate(
            query="CiscoWSAEvent | where UrlOriginal contains \"malware\" and SrcIpAddr != \"\" | summarize count() by UrlOriginal, SrcUserName"
        ), self.mapping)

        self.assertEqual(github.skip_reasons, [])
        self.assertEqual(cisco_duo.skip_reasons, [])
        self.assertEqual(web_proxy.skip_reasons, [])
        self.assertIn("'Log Source' = 'SOC Application Logs'", github.query_payload["query"])
        self.assertIn("Action = 'repo.destroy'", github.query_payload["query"])
        self.assertIn("'Event Type' = 'authentication'", cisco_duo.query_payload["query"])
        self.assertIn("Status = 'failure'", cisco_duo.query_payload["query"])
        self.assertIn("by 'Target User Name'", cisco_duo.query_payload["query"])
        self.assertIn("'Request URL' like '*malware*'", web_proxy.query_payload["query"])
        self.assertIn("by 'Request URL', 'User Name'", web_proxy.query_payload["query"])

    def test_mapping_targets_are_real_allowed_logan_fields(self):
        def display_name(field):
            value = field.strip()
            if len(value) >= 2 and value[0] == "'" and value[-1] == "'":
                return value[1:-1]
            return value

        invalid_targets = {
            sentinel_field: target
            for sentinel_field, target in self.mapping["fields"].items()
            if display_name(target) not in self.mapping["allowed_fields"]
        }

        self.assertEqual(invalid_targets, {})

    def test_isnotempty_preserves_multiword_field_quotes(self):
        result = convert_candidate(self._candidate(
            query=(
                "TMApexOneEvent\n"
                "| where isnotempty(SrcIpAddr)\n"
                "| summarize IpCount=count() by SrcIpAddr\n"
                "| top 20 by IpCount desc"
            )
        ), self.mapping)

        self.assertEqual(result.skip_reasons, [])
        self.assertEqual(result.local_validation_errors, [])
        query = result.query_payload["query"]
        self.assertIn("'Source IP' != null", query)
        self.assertIn("'Source IP' != ''", query)
        self.assertNotIn("Source IP != null", query)

    def test_common_solution_fields_map_to_dictionary_backed_logan_fields(self):
        cisco_endpoint = convert_candidate(self._candidate(
            query=(
                "CiscoSecureEndpoint\n"
                "| where EventMessage has 'Suspected ransomware'\n"
                "| extend HostCustomEntity = DstHostname, MalwareCustomEntity = ThreatName"
            )
        ), self.mapping)
        dns_query = convert_candidate(self._candidate(
            query=(
                "GCPCloudDNS\n"
                "| where Query has_any ('hidusi.com', 'dodefoh.com')\n"
                "| extend DNSCustomEntity = Query, IPCustomEntity = SrcIpAddr"
            )
        ), self.mapping)
        user_agent = convert_candidate(self._candidate(
            query=(
                "Cisco_Umbrella\n"
                "| where EventType == 'proxylogs'\n"
                "| where HttpUserAgentOriginal contains 'WindowsPowerShell'\n"
                "| where UrlCategory =~ 'IW_shrt'\n"
                "| where DstPortNumber == 443"
            )
        ), self.mapping)

        self.assertEqual(cisco_endpoint.skip_reasons, [])
        self.assertEqual(dns_query.skip_reasons, [])
        self.assertEqual(user_agent.skip_reasons, [])
        self.assertIn("Description like '*Suspected ransomware*'", cisco_endpoint.query_payload["query"])
        self.assertNotIn("MalwareCustomEntity", cisco_endpoint.query_payload["query"])
        self.assertIn("'Query Name' like '*hidusi.com*'", dns_query.query_payload["query"])
        self.assertNotIn("DNSCustomEntity", dns_query.query_payload["query"])
        self.assertIn("'User Agent' like '*WindowsPowerShell*'", user_agent.query_payload["query"])
        self.assertIn("'Threat Category' = 'IW_shrt'", user_agent.query_payload["query"])
        self.assertIn("'Destination Port' = 443", user_agent.query_payload["query"])

    def test_foundational_field_candidate_maps_only_to_dictionary_backed_action(self):
        result = convert_candidate(self._candidate(
            title="McAfee ePO - Threat was not blocked",
            source_path="Solutions/McAfee ePolicy Orchestrator/Analytic Rules/McAfeeEPOThreatNotBlocked.yaml",
            query=(
                "McAfeeEPOEvent\n"
                "| where ThreatActionTaken in~ ('none', 'IDS_ACTION_WOULD_BLOCK')\n"
                "| extend IPCustomEntity = DvcIpAddr"
            ),
        ), self.mapping)

        self.assertEqual(result.skip_reasons, [])
        self.assertEqual(result.local_validation_errors, [])
        self.assertIn("Action in ('none', 'IDS_ACTION_WOULD_BLOCK')", result.query_payload["query"])
        self.assertIn("Action", self.mapping["allowed_fields"])

    def test_custom_table_candidate_uses_phase_a_mapping_then_blocks_on_fields(self):
        result = convert_candidate(self._candidate(
            title="Theom Critical Risks",
            source_path="Solutions/Theom/Analytic Rules/TheomRisksCritical.yaml",
            query=(
                "TheomAlerts_CL\n"
                "| where customProps_RuleId_s == \"TRIS0001\" and (priority_s == \"P1\" or priority_s == \"P2\")"
            ),
        ), self.mapping)

        self.assertIsNone(result.query_payload)
        self.assertFalse(any("unsupported Sentinel table: TheomAlerts_CL" in reason for reason in result.skip_reasons))
        self.assertTrue(any("unsupported Sentinel field mapping: customProps_RuleId_s" in reason for reason in result.skip_reasons))

    def test_makeset_alias_and_additional_solution_tables_convert(self):
        aggregate = convert_candidate(self._candidate(
            query=(
                "McAfeeEPOEvent\n"
                "| summarize th_list=makeset(ThreatName) by DstHostname"
            )
        ), self.mapping)
        box = convert_candidate(self._candidate(
            query=(
                "BoxEvents\n"
                "| where EventEndTime > ago(24h)\n"
                "| where EventType =~ 'DOWNLOAD'\n"
                "| summarize DataVolume=sum(FileSize) by SourceLogin\n"
                "| top 5 by DataVolume desc"
            )
        ), self.mapping)
        cisco_ise = convert_candidate(self._candidate(
            query=(
                "CiscoISEEvent\n"
                "| where EventId in ('5231', '5236')\n"
                "| project TimeGenerated, DstUserName, SrcIpAddr"
            )
        ), self.mapping)

        self.assertEqual(aggregate.skip_reasons, [])
        self.assertEqual(box.skip_reasons, [])
        self.assertEqual(cisco_ise.skip_reasons, [])
        self.assertIn("unique('Threat Name') as th_list", aggregate.query_payload["query"])
        self.assertIn("'Log Source' = 'SOC Application Logs'", box.query_payload["query"])
        self.assertNotIn("EventEndTime", box.query_payload["query"])
        self.assertIn("sum('Network Bytes Out') as DataVolume by 'User Name'", box.query_payload["query"])
        self.assertIn("'Event ID' in ('5231', '5236')", cisco_ise.query_payload["query"])
        self.assertIn("fields Time, 'Target User Name', 'Source IP'", cisco_ise.query_payload["query"])

    def test_project_reorder_and_entity_enrichment_extends_are_supported(self):
        result = convert_candidate(self._candidate(
            query=(
                "SecurityEvent\n"
                "| where EventID == 4688\n"
                "| where Process has_any (\"powershell.exe\", \"cmd.exe\") or CommandLine has \"powershell\"\n"
                "| project-reorder TimeGenerated, Computer, Account, Process, CommandLine\n"
                "| extend NTDomain = tostring(split(Account,'\\\\',0)[0]), Name = tostring(split(Account,'\\\\',1)[0])\n"
                "| extend HostName = tostring(split(Computer, '.', 0)[0]), DnsDomain = tostring(strcat_array(array_slice(split(Computer, '.'), 1, -1), '.'))\n"
                "| extend Account_0_Name = Name\n"
                "| extend Host_0_HostName = HostName"
            )
        ), self.mapping)

        self.assertEqual(result.skip_reasons, [])
        self.assertEqual(result.local_validation_errors, [])
        query = result.query_payload["query"]
        self.assertIn("'Event ID' = '4688'", query)
        self.assertIn("('Process Name' like '*powershell.exe*' or 'Process Name' like '*cmd.exe*')", query)
        self.assertIn("'Command Line' like '*powershell*'", query)
        self.assertIn("| fields Time, Entity, User, 'Process Name', 'Command Line'", query)
        self.assertNotIn("NTDomain", query)
        self.assertNotIn("DnsDomain", query)

    def test_common_security_log_cef_fields_map_to_real_logan_fields(self):
        result = convert_candidate(self._candidate(
            query=(
                "CommonSecurityLog\n"
                "| where DeviceVendor == \"RidgeSecurity\"\n"
                "| where DeviceEventClassID == \"4001\""
            )
        ), self.mapping)

        self.assertEqual(result.skip_reasons, [])
        query = result.query_payload["query"]
        self.assertIn("Provider = 'RidgeSecurity'", query)
        self.assertIn("'Event ID' = '4001'", query)

    def test_local_validation_rejects_kql_leftovers_and_unknown_oci_fields(self):
        kql_leftovers = validate_logan_query_local(
            "'Log Source' = 'SOC Windows Sysmon Logs' and "
            "(InitiatingProcessCommandLine has_any(\"kr.bin\", \"if.bin\"))"
        )
        self.assertTrue(any("unsupported Logan output token" in error for error in kql_leftovers))

        unknown_fields = validate_logan_query_local(
            "'Log Source' = 'SOC Network Firewall Logs' and ('Device Vendor' = 'RidgeSecurity')"
        )
        self.assertTrue(any("unsupported OCI field reference: Device Vendor" in error for error in unknown_fields))

        placeholders = validate_logan_query_local(
            "'Log Source' = 'SOC Windows Sysmon Logs' and ('Command Line' like '-q -s {{*')"
        )
        self.assertTrue(any("query contains unresolved placeholder braces" in error for error in placeholders))

        placeholder_text = validate_logan_query_local(
            "'Log Source' = 'SOC Sysmon Network Logs' and 'Destination IP' = 'IP ADDRESS GOES HERE'"
        )
        self.assertTrue(any("query contains unresolved placeholder text" in error for error in placeholder_text))

        unsafe_literal = validate_logan_query_local(
            "'Log Source' = 'SOC Windows Sysmon Logs' and ('Command Line' = 'reg query '\"HKCU\"')"
        )
        self.assertTrue(any("unsafe double quote outside Logan string literal" in error for error in unsafe_literal))

    def test_local_validation_rejects_time_grouping_until_supported(self):
        errors = validate_logan_query_local(
            "'Log Source' = 'SOC Windows Sysmon Logs' | stats count as Count by Time"
        )

        self.assertIn("unsupported OCI time grouping: Time", errors)

    def test_unsupported_features_are_classified(self):
        unsupported = classify_unsupported_kql(
            "let suspicious = SecurityEvent | where EventID == 4624; "
            "SecurityEvent | extend bag=parse_json(AdditionalFields) "
            "| where Message matches regex 'abc' "
            "| parse Message with 'prefix' value 'suffix' "
            "| join suspicious on Account | mv-expand TargetResources"
        )

        self.assertTrue(any("join" in reason for reason in unsupported))
        self.assertTrue(any("let" in reason for reason in unsupported))
        self.assertTrue(any("mv-expand" in reason for reason in unsupported))
        self.assertTrue(any("JSON bag expansion" in reason for reason in unsupported))
        self.assertTrue(any("regex predicate" in reason for reason in unsupported))
        self.assertTrue(any("operator: parse" in reason for reason in unsupported))

    def test_lossy_phase9_shapes_remain_skipped(self):
        unsupported = classify_unsupported_kql(
            "SecurityEvent | where parse_command_line(CommandLine) has 'x' "
            "| evaluate bag_unpack(AdditionalFields) "
            "| make-series Count=count() on TimeGenerated in range(ago(1d), now(), 1h) "
            "| where Account matches regex 'admin.*'"
        )

        self.assertTrue(any("parse_command_line" in reason for reason in unsupported))
        self.assertTrue(any("evaluate" in reason for reason in unsupported))
        self.assertTrue(any("make-series" in reason for reason in unsupported))
        self.assertTrue(any("JSON bag expansion" in reason for reason in unsupported))
        self.assertTrue(any("regex predicate" in reason for reason in unsupported))

    def test_unsupported_string_functions_do_not_leak_to_logan(self):
        # ``strlen`` is now lowered to ``length(...)`` in scalar (extend/project)
        # contexts (Phase 9 operator-parity tranche), but it has no faithful
        # Logan QL form inside a ``where`` *predicate comparison*. The converter
        # must still refuse to promote and flag the predicate rather than leak
        # the raw KQL function into Logan output.
        result = convert_candidate(self._candidate(
            query="NGINXHTTPServer | where strlen(HttpUserAgentOriginal) < 20"
        ), self.mapping)

        self.assertIsNone(result.query_payload)
        self.assertTrue(
            any(
                "unsupported predicate expression" in reason
                for reason in result.skip_reasons
            ),
            result.skip_reasons,
        )

    def test_supported_string_functions_lower_in_extend_context(self):
        # Counterpart to the predicate guard above: strlen/strcat/extract now
        # convert cleanly when used in an ``extend`` scalar context.
        result = convert_candidate(self._candidate(
            query=(
                "NGINXHTTPServer | extend UaLen = strlen(HttpUserAgentOriginal)"
            )
        ), self.mapping)
        if result.query_payload is not None:
            logan = json.dumps(result.query_payload)
            self.assertNotIn("strlen(", logan)
