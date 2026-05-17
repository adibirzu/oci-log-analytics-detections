---
phase: 08-backlog-prioritizer-and-cohort-overlay
plan: 3
type: execute
wave: 3
depends_on: ["08-01", "08-02"]
files_modified:
  - .planning/STATE.md
  - .planning/ROADMAP.md
  - .planning/REQUIREMENTS.md
  - .planning/phases/08-backlog-prioritizer-and-cohort-overlay/*-SUMMARY.md
autonomous: true

requirements:
  - PRI-01
  - PRI-02
  - PRI-03
  - PRI-04

must_haves:
  truths:
    - "Top 20 priority entries cite concrete Phase 9/MAP-05-style blockers."
    - "Focused tests and release gates pass."
    - "GSD state marks Phase 8 complete when gates pass."
---

<objective>
Close Phase 8 with summaries, GSD state updates, and local verification.
</objective>

<tasks>
<task type="auto">
  <name>Task 1: Run final gates and update planning docs</name>
  <files>.planning/**</files>
  <action>
    Verify the priority JSON, run local gates, write summaries, and update roadmap/state/requirements if successful.
  </action>
  <verify>python3 -m pytest -q</verify>
</task>
</tasks>

