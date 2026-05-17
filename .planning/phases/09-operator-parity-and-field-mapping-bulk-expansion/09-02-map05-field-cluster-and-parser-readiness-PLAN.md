---
phase: 09-operator-parity-and-field-mapping-bulk-expansion
plan: 2
type: execute
wave: 2
depends_on: ["09-01"]
files_modified:
  - config/mapping/fields/*.yaml
  - config/sentinel_oci_mapping.yaml
  - docs/parser_readiness/*.md
  - scripts/test_mapping_loader.py
autonomous: true

requirements:
  - MAP-05
  - MAP-06
  - PARSER-01
  - PARSER-02
  - PARSER-03

must_haves:
  truths:
    - "MAP-05 fields are either mapped to approved OCI fields or documented as parser-change-required."
    - "EventData ObjectDN/ObjectName/AttributeLDAPDisplayName readiness is documented."
    - "Mapping compatibility export regenerates cleanly."
---

<objective>
Add the MAP-05 field cluster safely, with parser-readiness documentation instead of placeholder fields.
</objective>

<tasks>
<task type="auto">
  <name>Task 1: Add grounded mappings and parser-readiness docs</name>
  <files>config/mapping/fields/*.yaml, docs/parser_readiness/*.md, scripts/test_mapping_loader.py</files>
  <action>
    Add only mappings backed by current field dictionary or approved built-ins. For fields needing parser extraction, mark `parser_change_required: true` and write docs under `docs/parser_readiness/`.
  </action>
  <verify>python3 scripts/generate_mapping_config.py --export-compat && python3 -m pytest scripts/test_mapping_loader.py -q</verify>
</task>
</tasks>

