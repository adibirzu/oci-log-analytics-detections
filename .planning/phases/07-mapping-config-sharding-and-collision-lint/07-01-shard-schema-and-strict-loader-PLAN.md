---
phase: 07-mapping-config-sharding-and-collision-lint
plan: 1
type: execute
wave: 1
depends_on: []
files_modified:
  - config/mapping/_root.yaml
  - config/mapping/tables/identity.yaml
  - config/mapping/tables/endpoint.yaml
  - config/mapping/tables/cloud_azure.yaml
  - config/mapping/tables/cloud_office.yaml
  - config/mapping/tables/network.yaml
  - config/mapping/fields/common.yaml
  - config/mapping/fields/subject.yaml
  - config/mapping/fields/process.yaml
  - config/mapping/fields/office.yaml
  - config/mapping/fields/network.yaml
  - config/sentinel_oci_mapping.yaml
  - scripts/kql/mapping_loader.py
  - scripts/kql/_facade_impl.py
  - scripts/test_mapping_loader.py
autonomous: true

requirements:
  - MAP-01
  - MAP-02

must_haves:
  truths:
    - "Mapping shards under config/mapping/ are the authoritative editing surface."
    - "config/sentinel_oci_mapping.yaml remains loadable as the generated compatibility re-export."
    - "Strict duplicate-key loading fails with duplicate_key:<path>."
  artifacts:
    - path: config/mapping/_root.yaml
      provides: "deterministic table and field shard load order"
    - path: scripts/kql/mapping_loader.py
      provides: "strict loader, shard merger, and compatibility export helpers"
    - path: scripts/test_mapping_loader.py
      provides: "duplicate-key and parity tests"
---

<objective>
Move the Sentinel mapping editing surface from the monolithic YAML into deterministic shards while preserving the legacy `config/sentinel_oci_mapping.yaml` compatibility path.
</objective>

<tasks>

<task type="auto">
  <name>Task 1: Create mapping shards from the current monolith</name>
  <files>config/mapping/**, config/sentinel_oci_mapping.yaml</files>
  <action>
    Split current `tables:` entries by existing category into the required table shards. Split current `fields:` entries into the required field shards using stable domain heuristics. Keep values semantically identical, and add role metadata in Plan 07-02.
  </action>
  <verify>python3 -m pytest scripts/test_mapping_loader.py -q</verify>
</task>

<task type="auto">
  <name>Task 2: Replace mapping_loader delegation with strict shard loading</name>
  <files>scripts/kql/mapping_loader.py, scripts/kql/_facade_impl.py</files>
  <action>
    Implement a strict PyYAML loader that rejects duplicate keys, merge shard payloads in `_root.yaml` order, and make `load_mapping_config()` consume the shard loader by default. Retain fallback loading for an explicit monolithic path.
  </action>
  <verify>python3 -m pytest scripts/test_mapping_loader.py scripts/test_sentinel_converter.py -q</verify>
</task>

</tasks>

