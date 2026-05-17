---
phase: 08-backlog-prioritizer-and-cohort-overlay
plan: 2
type: execute
wave: 2
depends_on: ["08-01"]
files_modified:
  - scripts/release_checklist.py
  - scripts/query_artifacts.py
  - scripts/test_sentinel_backlog_prioritize.py
autonomous: true

requirements:
  - PRI-03

must_haves:
  truths:
    - "release_checklist prints Sentinel backlog: <N> ranked; top blocker: <reason> when the priority artifact exists."
    - "sentinel_backlog_priority.json is treated as a generated query artifact."
  artifacts:
    - path: scripts/release_checklist.py
      provides: "non-blocking Sentinel backlog advisory"
---

<objective>
Expose the prioritizer result in release output and keep the generated priority JSON out of saved-search query validation.
</objective>

<tasks>
<task type="auto">
  <name>Task 1: Wire advisory and artifact classification</name>
  <files>scripts/release_checklist.py, scripts/query_artifacts.py</files>
  <action>
    Add a small helper that reads `queries/sentinel_backlog_priority.json` and prints the advisory after checklist output. Add the new JSON name to generated artifact classification.
  </action>
  <verify>python3 scripts/release_checklist.py --skip-tests</verify>
</task>
</tasks>

