---
phase: 08-backlog-prioritizer-and-cohort-overlay
plan: 1
type: execute
wave: 1
depends_on: []
files_modified:
  - scripts/sentinel_backlog_prioritize.py
  - scripts/test_sentinel_backlog_prioritize.py
  - queries/sentinel_backlog_priority.json
autonomous: true

requirements:
  - PRI-01
  - PRI-02
  - PRI-04

must_haves:
  truths:
    - "Prioritizer writes non-empty deterministic queries/sentinel_backlog_priority.json."
    - "Each ranked entry has primary_blocker and unblock_chain_length."
    - "Prioritizer runs sync_sentinel_kql.py before loading candidates by default."
  artifacts:
    - path: scripts/sentinel_backlog_prioritize.py
      provides: "backlog ranking CLI"
    - path: queries/sentinel_backlog_priority.json
      provides: "generated cohort priority artifact"
---

<objective>
Create the deterministic Sentinel backlog prioritizer and generated priority JSON artifact.
</objective>

<tasks>
<task type="auto">
  <name>Task 1: Implement prioritizer CLI and tests</name>
  <files>scripts/sentinel_backlog_prioritize.py, scripts/test_sentinel_backlog_prioritize.py</files>
  <action>
    Load candidates and conversion report, exclude promoted IDs, classify blockers, rank by MITRE coverage and converter tier difficulty, compute unblock-chain length by normalized blocker, and write JSON. Default to running `sync_sentinel_kql.py --no-fetch` first; allow `--skip-sync` for deterministic tests.
  </action>
  <verify>python3 -m pytest scripts/test_sentinel_backlog_prioritize.py -q</verify>
</task>
</tasks>

