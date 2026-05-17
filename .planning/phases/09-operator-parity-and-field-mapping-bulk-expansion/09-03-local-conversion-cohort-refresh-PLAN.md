---
phase: 09-operator-parity-and-field-mapping-bulk-expansion
plan: 3
type: execute
wave: 3
depends_on: ["09-01", "09-02"]
files_modified:
  - queries/sentinel_backlog_priority.json
  - queries/sentinel_conversion_report.json
  - docs/sentinel_converter.html
autonomous: true

requirements:
  - OP-01
  - OP-02
  - OP-03
  - OP-04
  - OP-05
  - OP-06
  - MAP-05

must_haves:
  truths:
    - "Local conversion attempts show reduced operator/MAP-05 blocker counts."
    - "Backlog priority artifact is regenerated from current converter/mapping state."
    - "Promoted Sentinel JSON is not hand-edited in this local tranche."
---

<objective>
Refresh local conversion and backlog artifacts after local operator and mapping work, without promoting new Sentinel JSON.
</objective>

<tasks>
<task type="auto">
  <name>Task 1: Run local conversion and regenerate priority artifact</name>
  <files>queries/sentinel_backlog_priority.json</files>
  <action>
    Run local conversion/reporting commands that do not write promoted Sentinel JSON, regenerate priority artifact, and compare blocker counts.
  </action>
  <verify>python3 scripts/sentinel_backlog_prioritize.py --skip-sync --check</verify>
</task>
</tasks>

