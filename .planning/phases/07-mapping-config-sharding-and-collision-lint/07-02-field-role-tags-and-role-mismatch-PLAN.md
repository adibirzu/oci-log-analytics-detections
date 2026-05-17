---
phase: 07-mapping-config-sharding-and-collision-lint
plan: 2
type: execute
wave: 1
depends_on: ["07-01"]
files_modified:
  - config/mapping/fields/common.yaml
  - config/mapping/fields/subject.yaml
  - config/mapping/fields/process.yaml
  - config/mapping/fields/office.yaml
  - config/mapping/fields/network.yaml
  - scripts/kql/mapping_loader.py
  - scripts/kql/_facade_impl.py
  - scripts/test_sentinel_converter.py
  - scripts/test_mapping_loader.py
autonomous: true

requirements:
  - MAP-04

must_haves:
  truths:
    - "Every mapped Sentinel field has one role from subject, target, initiator, resource, time, hash, network."
    - "Legacy converter callers still receive mapping['fields'][sentinel] as a Logan display field string."
    - "Role-mismatched field-to-field comparisons are skipped with role_mismatch:<a>:<b>."
  artifacts:
    - path: scripts/kql/mapping_loader.py
      provides: "role validation and legacy field projection"
    - path: scripts/test_sentinel_converter.py
      provides: "converter regression for role_mismatch skip"
---

<objective>
Make field mappings role-aware without breaking existing converter callers, then block lossy subject-to-target field comparisons before they emit weaker Logan QL.
</objective>

<tasks>

<task type="auto">
  <name>Task 1: Add role tags and validate roles during load</name>
  <files>config/mapping/fields/*.yaml, scripts/kql/mapping_loader.py</files>
  <action>
    Convert each field mapping shard entry to a structured mapping containing `target` and `role`. Validate roles against the allowed role set and expose `mapping['field_roles']` alongside the legacy `mapping['fields']` projection.
  </action>
  <verify>python3 -m pytest scripts/test_mapping_loader.py -q</verify>
</task>

<task type="auto">
  <name>Task 2: Detect role-mismatched comparisons in predicates</name>
  <files>scripts/kql/_facade_impl.py, scripts/test_sentinel_converter.py</files>
  <action>
    In predicate conversion, detect simple field-to-field comparisons before literal comparison rewrites. If both sides are mapped fields and their roles differ, return a structured `role_mismatch:<left>:<right>` skip reason instead of emitting Logan QL.
  </action>
  <verify>python3 -m pytest scripts/test_sentinel_converter.py scripts/test_kql/test_operators.py -q</verify>
</task>

</tasks>

