"""Core Sentinel KQL conversion tests."""

from sentinel_converter_tests.kql_base import *  # noqa: F401,F403


class TestSentinelKqlConversionCore(SentinelKqlConversionBase):
    def test_rank_candidates_quality_first(self):
        candidates = [
            self._candidate(sentinel_id="low", severity="low", mitre_attack={"tactics": [], "techniques": []}),
            self._candidate(sentinel_id="high", severity="high"),
            self._candidate(sentinel_id="join", query="SigninLogs | join AuditLogs on UserPrincipalName"),
        ]

        ranked = rank_candidates(candidates, self.mapping)
        top = select_top_candidates(candidates, self.mapping, top=2)

        self.assertEqual(ranked[0]["sentinel_id"], "high")
        self.assertEqual([candidate["sentinel_id"] for candidate in top], ["high", "low"])

    def test_convert_candidates_emits_periodic_status_and_quality_progress(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            progress = StringIO()
            report = convert_candidates(
                candidates=[
                    self._candidate(sentinel_id="convertible"),
                    self._candidate(
                        sentinel_id="unsupported",
                        query="UnknownCustomTable_CL | where Field == 'x'",
                    ),
                ],
                mapping=self.mapping,
                top=2,
                validate_live=False,
                write_working=False,
                output_dir=Path(tmpdir) / "sentinel",
                report_path=Path(tmpdir) / "report.json",
                progress_interval=0,
                progress_every=1,
                progress_stream=progress,
            )

            progress_text = progress.getvalue()
            self.assertEqual(report["summary"]["attempted_candidates"], 2)
            self.assertIn("[sentinel-convert] start total_candidates=2 attempted=2", progress_text)
            self.assertIn("score=", progress_text)
            self.assertIn('title="Failed sign-in burst"', progress_text)
            self.assertIn("status=converted", progress_text)
            self.assertIn("status=skipped", progress_text)
            self.assertIn("unsupported Sentinel table: UnknownCustomTable_CL", progress_text)
            self.assertIn("[sentinel-convert] complete attempted=2", progress_text)

    def test_convert_supported_predicates_aggregations_sort_and_limits(self):
        result = convert_candidate(self._candidate(), self.mapping)

        self.assertTrue(result.promoted_candidate)
        self.assertEqual(result.skip_reasons, [])
        query = result.query_payload["query"]
        self.assertIn("'Log Source' = 'Azure Entra ID Sign-in Logs'", query)
        self.assertNotIn("TimeGenerated", query)
        self.assertNotIn("ago(", query)
        self.assertIn("Status != 'Success'", query)
        self.assertIn("'User Name' like '*admin*'", query)
        self.assertIn("'Source IP' in ('10.0.0.1', '10.0.0.2')", query)
        self.assertIn("| stats count as Failures, distinctcount('User Name') as Users by 'User Name', 'Source IP'", query)
        self.assertIn("| sort -Failures", query)
        self.assertIn("| head 10", query)
        self.assertEqual(validate_logan_query_local(query), [])

    def test_search_in_operator_maps_tables_and_terms(self):
        query, source_info, errors = convert_kql_to_logan(
            'search in (Perf, Event, Alert) "Contoso" | take 10',
            self.mapping,
        )

        self.assertEqual(errors, [])
        self.assertEqual(source_info["tables"], ["Perf", "Event", "Alert"])
        self.assertIn("'Log Source' = 'SOC Application Logs'", query)
        self.assertIn("'Log Source' = 'Windows Event System Logs'", query)
        self.assertIn("'Original Log Content' like '*Contoso*'", query)
        self.assertIn("msg like '*Contoso*'", query)
        self.assertIn("| head 10", query)
        self.assertEqual(validate_logan_query_local(query), [])

    def test_search_stage_after_table_supports_field_predicates(self):
        query, source_info, errors = convert_kql_to_logan(
            'Perf | search CounterName == "% Processor Time" | summarize AvgCpu=avg(CounterValue) by Computer',
            self.mapping,
        )

        self.assertEqual(errors, [])
        self.assertEqual(source_info["tables"], ["Perf"])
        self.assertIn("'Metric Name' = '% Processor Time'", query)
        self.assertIn("avg('Metric Value') as AvgCpu by Entity", query)
        self.assertEqual(validate_logan_query_local(query), [])

    def test_count_stage_maps_to_stats_count(self):
        query, _source_info, errors = convert_kql_to_logan(
            "SecurityEvent | where EventID == 4624 | count",
            self.mapping,
        )

        self.assertEqual(errors, [])
        self.assertIn("'Event ID' = '4624'", query)
        self.assertIn("| stats count as Count", query)
        self.assertEqual(validate_logan_query_local(query), [])

    def test_between_predicates_and_time_ranges_convert_safely(self):
        query, _source_info, errors = convert_kql_to_logan(
            "Perf | where TimeGenerated between (ago(1h) .. now()) "
            "and CounterValue between (80 .. 100) | count",
            self.mapping,
        )

        self.assertEqual(errors, [])
        self.assertNotIn("TimeGenerated", query)
        self.assertNotIn("ago(", query)
        self.assertIn("'Metric Value' >= '80'", query)
        self.assertIn("'Metric Value' <= '100'", query)
        self.assertIn("| stats count as Count", query)
        self.assertEqual(validate_logan_query_local(query), [])

    def test_project_aliases_and_case_scalar_convert(self):
        query, _source_info, errors = convert_kql_to_logan(
            (
                "SecurityEvent\n"
                "| extend Outcome = case(EventID == 4625, 'failed', EventID == 4624, 'success', 'other')\n"
                "| project Actor = SubjectUserName, Outcome"
            ),
            self.mapping,
        )

        self.assertEqual(errors, [])
        self.assertIn("eval Outcome = if('Event ID' = '4625', 'failed', if('Event ID' = '4624', 'success', 'other'))", query)
        self.assertIn("eval Actor = 'Subject User Name'", query)
        self.assertIn("| fields Actor, Outcome", query)
        self.assertEqual(validate_logan_query_local(query), [])

    def test_summarize_by_without_aggregate_maps_to_distinct_count(self):
        query, _source_info, errors = convert_kql_to_logan(
            "SecurityEvent | summarize by Computer, EventID | sort by Count",
            self.mapping,
        )

        self.assertEqual(errors, [])
        self.assertIn("| stats count as Count by Entity, 'Event ID'", query)
        self.assertIn("| sort -Count", query)
        self.assertEqual(validate_logan_query_local(query), [])

    def test_filter_stage_converts_as_where_alias(self):
        result = convert_candidate(self._candidate(
            query=(
                "SigninLogs\n"
                "| filter Result != \"Success\" and UserPrincipalName has \"admin\""
            )
        ), self.mapping)

        self.assertEqual(result.skip_reasons, [])
        self.assertEqual(result.local_validation_errors, [])
        query = result.query_payload["query"]
        self.assertIn("Status != 'Success'", query)
        self.assertIn("'User Name' like '*admin*'", query)
        self.assertNotRegex(query, r"\bfilter\b")

    def test_role_mismatched_field_comparison_is_skipped(self):
        result = convert_candidate(self._candidate(
            query="SecurityEvent | where SubjectUserName == TargetUserName",
        ), self.mapping)

        self.assertIsNone(result.query_payload)
        self.assertIn("role_mismatch:SubjectUserName:TargetUserName", result.skip_reasons)

    def test_eventdata_directory_mapping_is_parser_ready(self):
        result = convert_candidate(self._candidate(
            query="SecurityEvent | where ObjectDN has 'Admin'",
        ), self.mapping)

        self.assertEqual(result.skip_reasons, [])
        self.assertIsNotNone(result.query_payload)
        self.assertIn("'Target Object' like '*Admin*'", result.query_payload["query"])

    def test_generic_eventdata_mapping_stays_pending(self):
        result = convert_candidate(self._candidate(
            query="SecurityEvent | where EventData has 'RawValue'",
        ), self.mapping)

        self.assertIsNone(result.query_payload)
        self.assertIn("parser_readiness:pending:EventData", result.skip_reasons)

    def test_convert_project_distinct_and_simple_union(self):
        candidate = self._candidate(
            query=(
                "union isfuzzy=true SigninLogs, AuditLogs\n"
                "| where OperationName startswith \"Add\" or Result has \"failure\" "
                "and IPAddress not in (\"127.0.0.1\")\n"
                "| distinct UserPrincipalName, IPAddress\n"
                "| project UserPrincipalName, IPAddress"
            )
        )

        result = convert_candidate(candidate, self.mapping)

        self.assertEqual(result.skip_reasons, [])
        query = result.query_payload["query"]
        self.assertIn("'Azure Entra ID Sign-in Logs'", query)
        self.assertIn("'Azure Entra ID Audit Logs'", query)
        self.assertIn("Operation like 'Add*'", query)
        self.assertIn("Status like '*failure*'", query)
        self.assertIn("'Source IP' not in ('127.0.0.1')", query)
        self.assertIn("| stats count as Count by 'User Name', 'Source IP'", query)
        self.assertIn("| fields 'User Name', 'Source IP'", query)

    def test_collection_string_operators_are_converted(self):
        result = convert_candidate(self._candidate(
            query=(
                "DeviceProcessEvents\n"
                "| where InitiatingProcessCommandLine has_any(\"kr.bin\", \"if.bin\")\n"
                "| where ProcessCommandLine has_all(\"echo\", \"tmp+\")\n"
                "| where FileName hasprefix \"cmd\" and FolderPath hassuffix \"payload.exe\" and FileName !~ \"bad.exe\""
            )
        ), self.mapping)

        self.assertEqual(result.skip_reasons, [])
        self.assertEqual(result.local_validation_errors, [])
        query = result.query_payload["query"]
        self.assertNotRegex(query, r"\b(has_any|has_all|hasprefix|!~)\b")
        self.assertIn("('Command Line' like '*kr.bin*' or 'Command Line' like '*if.bin*')", query)
        self.assertIn("('Command Line' like '*echo*' and 'Command Line' like '*tmp+*')", query)
        self.assertIn("'Process Name' like 'cmd*'", query)
        self.assertIn("'Target Filename' like '*payload.exe'", query)
        self.assertIn("'Process Name' != 'bad.exe'", query)

    def test_simple_let_scalars_and_arrays_are_substituted(self):
        result = convert_candidate(self._candidate(
            query=(
                "let suspiciousProcesses = dynamic([\"cmd.exe\", \"powershell.exe\"]);\n"
                "let threshold = 3;\n"
                "DeviceProcessEvents\n"
                "| where FileName has_any (suspiciousProcesses)\n"
                "| summarize Hits=count() by DeviceName\n"
                "| where Hits > threshold"
            )
        ), self.mapping)

        self.assertEqual(result.skip_reasons, [])
        self.assertEqual(result.local_validation_errors, [])
        query = result.query_payload["query"]
        self.assertNotIn("let ", query)
        self.assertIn("('Process Name' like '*cmd.exe*' or 'Process Name' like '*powershell.exe*')", query)
        self.assertIn("| stats count as Hits by 'Host Name (Server)'", query)
        self.assertIn("| where Hits > 3", query)

    def test_set_directives_are_stripped(self):
        result = convert_candidate(self._candidate(
            query=(
                "set timeout = 5m;\n"
                "set query_take_max_records = 5000;\n"
                "SecurityEvent\n"
                "| where EventID == 4624"
            )
        ), self.mapping)

        self.assertEqual(result.skip_reasons, [])
        self.assertEqual(result.local_validation_errors, [])
        query = result.query_payload["query"]
        self.assertNotIn("set timeout", query)
        self.assertIn("'Event ID' = '4624'", query)

    def test_tabular_let_variables_remain_unsupported(self):
        result = convert_candidate(self._candidate(
            query=(
                "let suspicious = DeviceProcessEvents | where FileName == \"cmd.exe\";\n"
                "DeviceProcessEvents\n"
                "| where FileName in (suspicious)"
            )
        ), self.mapping)

        self.assertIsNone(result.query_payload)
        self.assertTrue(any("unsupported KQL construct: let variables" in reason for reason in result.skip_reasons))

    def test_inline_comments_and_timestamp_filters_do_not_leak(self):
        result = convert_candidate(self._candidate(
            query=(
                "DeviceFileEvents\n"
                "| where Timestamp > ago(14d)\n"
                "| where FolderPath contains @\"C:\\\\Temp\" and FileName in~(\"payload.exe\") // Sentinel note"
            )
        ), self.mapping)

        self.assertEqual(result.skip_reasons, [])
        self.assertEqual(result.local_validation_errors, [])
        query = result.query_payload["query"]
        self.assertNotIn("Timestamp", query)
        self.assertNotIn("ago(", query)
        self.assertNotIn("//", query)
        self.assertIn("'Target Filename' like '*C:\\\\\\\\Temp*'", query)
        self.assertIn("'Process Name' in ('payload.exe')", query)

    def test_post_summarize_where_preserves_pipeline_order(self):
        query, _source_info, errors = convert_kql_to_logan(
            (
                "SecurityEvent\n"
                "| where EventID == 4625\n"
                "| summarize Failures=count() by Account\n"
                "| where Failures > 3\n"
                "| sort by Failures desc"
            ),
            self.mapping,
        )

        self.assertEqual(errors, [])
        self.assertIn("('Event ID' = '4625') | stats count as Failures by User", query)
        self.assertIn("| where Failures > 3 | sort -Failures", query)
        self.assertLess(query.index("| stats"), query.index("| where Failures > 3"))

    def test_make_set_take_any_and_time_bins_convert_to_unique_context(self):
        query, _source_info, errors = convert_kql_to_logan(
            (
                "DeviceProcessEvents\n"
                "| summarize DiscoveryCommands=dcount(ProcessCommandLine), "
                "CommandSamples=make_set(ProcessCommandLine, 1000), "
                "AnyFile=take_any(FileName) by DeviceName, bin(TimeGenerated, 5m)\n"
                "| where DiscoveryCommands >= 3"
            ),
            self.mapping,
        )

        self.assertEqual(errors, [])
        self.assertIn("distinctcount('Command Line') as DiscoveryCommands", query)
        self.assertIn("unique('Command Line') as CommandSamples", query)
        self.assertIn("unique('Process Name') as AnyFile", query)
        self.assertIn("timestats span = 5minute", query)
        self.assertIn("by 'Host Name (Server)'", query)
        self.assertIn("| where DiscoveryCommands >= 3", query)

        time_query, _source_info, time_errors = convert_kql_to_logan(
            "DeviceProcessEvents | summarize take_any(TimeGenerated) by DeviceName",
            self.mapping,
        )
        self.assertEqual(time_errors, [])
        self.assertIn("unique(Time) as any_Time", time_query)
        self.assertNotIn("TimeGenerated", time_query)
