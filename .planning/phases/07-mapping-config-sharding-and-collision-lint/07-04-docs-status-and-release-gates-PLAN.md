---
phase: 07-mapping-config-sharding-and-collision-lint
plan: 4
type: execute
wave: 3
depends_on: ["07-01", "07-02", "07-03"]
files_modified:
  - docs/sentinel_mapping_strict_loader.md
  - .planning/STATE.md
  - .planning/ROADMAP.md
  - .planning/phases/07-mapping-config-sharding-and-collision-lint/*-SUMMARY.md
autonomous: true

requirements:
  - MAP-01
  - MAP-02
  - MAP-03
  - MAP-04

must_haves:
  truths:
    - "Strict-loader findings are documented."
    - "Promoted Sentinel status revalidates with no promoted_count regression."
    - "Phase 7 GSD state and roadmap are updated after verification."
  artifacts:
    - path: docs/sentinel_mapping_strict_loader.md
      provides: "first strict-load findings and operating guidance"
---

<objective>
Close Phase 7 with documented strict-loader findings, generated artifacts, summaries, GSD state updates, and local release gates.
</objective>

<tasks>

<task type="auto">
  <name>Task 1: Document strict-load findings</name>
  <files>docs/sentinel_mapping_strict_loader.md</files>
  <action>
    Document the first strict-load run, whether duplicate overrides were found, how to reproduce duplicate-key failures, and how to regenerate the compatibility export and collision report.
  </action>
  <verify>test -s docs/sentinel_mapping_strict_loader.md</verify>
</task>

<task type="auto">
  <name>Task 2: Run local verification gates and update GSD artifacts</name>
  <files>.planning/STATE.md, .planning/ROADMAP.md, .planning/phases/07-mapping-config-sharding-and-collision-lint/*-SUMMARY.md</files>
  <action>
    Run focused tests, Sentinel strict status, inventory/security checks, and full pytest. Then write Phase 7 summaries and mark Phase 7 complete in GSD state/roadmap if the gates pass.
  </action>
  <verify>python3 -m pytest -q</verify>
</task>

</tasks>

