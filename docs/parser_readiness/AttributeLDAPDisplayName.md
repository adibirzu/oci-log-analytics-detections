# Parser Readiness: AttributeLDAPDisplayName

**Status:** pending parser extraction
**Phase:** 9

`AttributeLDAPDisplayName` is present in directory-service EventData. The shard maps it to the real `Object Type` field, and the SOC Windows Event Security JSON parser extracts it from `$.EventData.AttributeLDAPDisplayName`.

Verification: `scripts/test_setup_log_sources.py` covers the parser JSON path and example payload. Live OCI validation still belongs to the normal promotion/deployment gates.
