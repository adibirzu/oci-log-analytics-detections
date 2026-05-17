---
phase: 09-operator-parity-and-field-mapping-bulk-expansion
plan: 4
type: execute
wave: 4
depends_on: ["09-01", "09-02", "09-03"]
files_modified:
  - queries/sentinel/*.json
  - queries/sentinel_conversion_report.json
  - queries/catalog.json
  - queries/dashboard_inventory.json
  - .planning/STATE.md
  - .planning/ROADMAP.md
autonomous: true

requirements:
  - MAP-05
  - MAP-06
  - OP-01
  - OP-02
  - OP-03
  - OP-04
  - OP-05
  - OP-06
  - PARSER-01
  - PARSER-02
  - PARSER-03

must_haves:
  truths:
    - "New promoted Sentinel JSON is converter-generated and live-validation passed."
    - "promoted_count reaches at least 50 or live blocker evidence is documented."
    - "Local gates pass after promotion/artifact refresh."
---

<objective>
Run the live `cap` promotion gate and close Phase 9 if the roadmap promotion target is met.
</objective>

<tasks>
<task type="auto">
  <name>Task 1: Promote through cap live validation and close phase</name>
  <files>queries/sentinel/*.json, queries/sentinel_conversion_report.json, .planning/**</files>
  <action>
    Use the canonical promotion workflow with `OCI_PROFILE=cap`. If live validation cannot run or promoted_count remains below 50, document the blocker and do not mark Phase 9 complete.
  </action>
  <verify>OCI_PROFILE=cap python3 scripts/sentinel_conversion_workflow.py promote --top all --timeout 60 --progress-interval 0</verify>
</task>
</tasks>

