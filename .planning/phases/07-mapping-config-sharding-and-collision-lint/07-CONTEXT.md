# Phase 7: Mapping Config Sharding and Collision Lint - Context

**Gathered:** 2026-05-17
**Status:** Ready for planning
**Mode:** Auto-generated (infrastructure-only autonomous discuss)

<domain>
## Phase Boundary

This phase shards the Microsoft Sentinel to Logan QL mapping configuration, adds strict duplicate-key loading, role metadata, and collision linting, and preserves the generated `config/sentinel_oci_mapping.yaml` compatibility surface. It does not promote new Sentinel detections or relax live OCI validation gates.

</domain>

<decisions>
## Implementation Decisions

### the agent's Discretion
- Treat this as a pure infrastructure phase: implementation choices are at the agent's discretion when they satisfy the roadmap success criteria and existing repo conventions.
- Preserve `config/sentinel_oci_mapping.yaml` as the public compatibility artifact while introducing shard files under `config/mapping/`.
- Keep duplicate-key, collision, and role-mismatch failures explicit and machine-readable because downstream workflow/reporting code consumes structured reasons.
- Do not add placeholder OCI fields. Every mapping must remain grounded in `queries/log_source_field_dictionary.json`, approved built-ins, or documented parser-readiness gaps.

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `scripts/kql/mapping_loader.py` already exists as the natural home for strict shard loading and compatibility re-export helpers.
- `scripts/convert_sentinel_kql.py` is now a facade over `scripts/kql/_facade_impl.py`; mapping behavior currently flows through `load_mapping_config`, `map_field`, and source-filter helpers imported from the facade implementation.
- `config/sentinel_oci_mapping.yaml` is the current allow-list for Sentinel tables, source candidates, categories, services, and field mappings.
- `scripts/query_artifacts.py` centralizes generated-artifact vs saved-search file classification and should be extended if new generated JSON artifacts are introduced.

### Established Patterns
- Scripts are plain Python modules under `scripts/`, with tests under `scripts/test_*.py` and direct imports via `sys.path` setup.
- Generated JSON/YAML artifacts should be deterministic, stably sorted, and reviewed in git.
- Validation failures should be explicit; avoid swallowed exceptions and avoid silently guessing field/source mappings.
- README/STATUS and generated inventories must reconcile with `queries/catalog.json`.

### Integration Points
- Converter tests live in `scripts/test_sentinel_converter.py`, `scripts/test_sentinel_conversion_workflow.py`, and the `scripts/test_kql/` fixture tree.
- Sentinel conversion status and promotion checks use `queries/sentinel_conversion_report.json`, `queries/sentinel/*.json`, and `scripts/sentinel_conversion_workflow.py status --json --strict`.
- Release gates include `python3 -m pytest -q`, Sentinel strict status, dashboard dry-run/validation, inventory drift, and sensitive-value scanning.

</code_context>

<specifics>
## Specific Ideas

No user-specific overrides. Use the roadmap success criteria as the implementation contract.

</specifics>

<deferred>
## Deferred Ideas

- Bulk field expansion and operator parity belong to Phase 9.
- Drift and synthetic-hit promotion enforcement belong to Phase 10.
- CI lane split and live-call caching belong to Phase 11.

</deferred>
