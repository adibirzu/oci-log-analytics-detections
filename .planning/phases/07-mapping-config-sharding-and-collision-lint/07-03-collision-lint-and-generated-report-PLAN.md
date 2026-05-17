---
phase: 07-mapping-config-sharding-and-collision-lint
plan: 3
type: execute
wave: 2
depends_on: ["07-01", "07-02"]
files_modified:
  - scripts/kql/mapping_loader.py
  - scripts/lint_mapping_collisions.py
  - scripts/query_artifacts.py
  - scripts/test_mapping_loader.py
  - queries/mapping_collisions.json
autonomous: true

requirements:
  - MAP-03

must_haves:
  truths:
    - "Collision lint reports known many-to-one fan-outs as lossy_mapping_collision:<a>+<b>→<col>."
    - "queries/mapping_collisions.json is deterministic and generated from current mapping shards."
    - "Generated artifact classification knows about queries/mapping_collisions.json if needed by drift checks."
  artifacts:
    - path: scripts/lint_mapping_collisions.py
      provides: "CLI lint/report generator"
    - path: queries/mapping_collisions.json
      provides: "generated collision inventory"
---

<objective>
Add a deterministic mapping-collision lint report that surfaces lossy many-to-one Sentinel-to-Logan field fan-outs before expanded mapping work starts.
</objective>

<tasks>

<task type="auto">
  <name>Task 1: Implement collision report generation</name>
  <files>scripts/kql/mapping_loader.py, scripts/lint_mapping_collisions.py, queries/mapping_collisions.json</files>
  <action>
    Group field mappings by Logan target and emit collisions for multi-source groups. Include machine-readable reasons using the roadmap format, and ensure the known `User Name` and `Entity` collisions are present.
  </action>
  <verify>python3 scripts/lint_mapping_collisions.py --check && python3 -m pytest scripts/test_mapping_loader.py -q</verify>
</task>

</tasks>

