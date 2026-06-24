# Parser Readiness: ObjectName

**Status:** pending parser extraction
**Phase:** 9

`ObjectName` is another EventData-derived object field. The shard maps it to the real `Target Object` display field, and the SOC Windows Event Security JSON parser extracts it from `$.EventData.ObjectName`.

Verification: the parser contract and example payload are covered by `scripts/test_setup_log_sources.py`; converter coverage follows the same ready path as `ObjectDN`.
