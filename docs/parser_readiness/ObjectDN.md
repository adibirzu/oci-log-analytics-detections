# Parser Readiness: ObjectDN

**Status:** pending parser extraction
**Phase:** 9

`ObjectDN` appears inside Windows directory-service EventData payloads. The shard maps it to the real `Target Object` display field, and the SOC Windows Event Security JSON parser extracts it from `$.EventData.ObjectDN`.

Verification: `scripts/test_setup_log_sources.py::TestSetupLogSources::test_windows_event_security_parser_extracts_eventdata_directory_fields` covers the parser contract; Sentinel converter tests assert `ObjectDN` no longer emits `parser_readiness:pending:ObjectDN`.
