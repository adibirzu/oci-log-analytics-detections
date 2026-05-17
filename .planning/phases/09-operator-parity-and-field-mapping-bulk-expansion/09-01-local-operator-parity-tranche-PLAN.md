---
phase: 09-operator-parity-and-field-mapping-bulk-expansion
plan: 1
type: execute
wave: 1
depends_on: []
files_modified:
  - scripts/kql/_facade_impl.py
  - scripts/kql/operators/extend_op.py
  - scripts/kql/operators/project_op.py
  - scripts/kql/operators/summarize_op.py
  - scripts/test_sentinel_converter.py
  - scripts/test_kql/test_operators.py
autonomous: true

requirements:
  - OP-01
  - OP-02
  - OP-03
  - OP-04
  - OP-05
  - OP-06

must_haves:
  truths:
    - "KQL set directives are stripped before classification."
    - "Supported scalar extend functions emit local-valid Logan QL."
    - "countif, column_ifexists, bin(TimeGenerated,...), project/project-away/top/distinct have regression coverage."
    - "Lossy out-of-scope constructs remain skipped."
---

<objective>
Land the local operator parity tranche required before any live promotion expansion.
</objective>

<tasks>
<task type="auto">
  <name>Task 1: Add operator translations and guardrail tests</name>
  <files>scripts/kql/_facade_impl.py, scripts/test_sentinel_converter.py, scripts/test_kql/test_operators.py</files>
  <action>
    Extend existing converter helpers in place, keeping output Logan QL locally valid. Add tests for supported shapes and explicit skipped lossy shapes.
  </action>
  <verify>python3 -m pytest scripts/test_sentinel_converter.py scripts/test_kql/test_operators.py -q</verify>
</task>
</tasks>

