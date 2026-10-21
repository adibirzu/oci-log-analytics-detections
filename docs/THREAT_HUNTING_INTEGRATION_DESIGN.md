# Threat hunting and external tool integration — design for review

Date: 2026-10-12
State: proposed; implementation and provider compatibility are unverified.

## Intended outcome

Expand defensive hunting coverage using the five supplied projects as references,
and make the existing OCI Log Analytics content reusable by other tools. Keep
query generation, source/field validation, and dashboard placement in this
repository. External tools consume artifacts and execute approved queries in
their own customer-controlled OCI runtime. The initial delivery is local code,
content, fixtures, and documentation; cloud actions and publication remain separate.

## Current evidence

Read directly from the working checkout:

- `queries/catalog.json`: 1,353 content items, including 156 curated hunts.
- `queries/manifest.json`: 538 records, with no `hunting/` records.
- `scripts/export_for_multicloud.py:load_all_queries` selects only artifacts
  with `sigma_id`; curated hunts are excluded by this source-derived export.
- `scripts/content_discovery.py` already normalizes candidates, deduplicates
  references, and tracks licensing, required fields, and review status.
- `config/threat_intel_sources.json` does not register the five supplied sources.
- `scripts/generate_cross_siem_detection_catalog.py` already maps behavioral
  families to local hunts without copying third-party rule bodies.
- Forge `/api/forge/artifacts` exposes workbench health/count metadata, rather
  than a searchable hunting-content API.
- `scripts/splunk_evidence_exporter/` already supplies evidence identity,
  allowlisting, redaction, delivery adapters, retry, and checkpoint contracts.

These are code-backed inventory observations. Historical live-validation
statements in existing documents were not refreshed in this review. The checkout
contains extensive pre-existing changes; the design does not authorize bundling
or reverting those changes.

## Reference review

Repository revisions resolved using GitHub's API on the review date. README
and selected source files were inspected; this is not a complete upstream audit.

| Reference | Revision | License metadata | Useful capability and OCI fit |
| --- | --- | --- | --- |
| [Google CSA](https://github.com/GoogleCloudPlatform/security-analytics) | `2dd8565557e043e25d16df8f7743b9e69374d6f3` | Apache-2.0 | Organize use cases around access, IAM/secrets, provisioning, workloads, data, and networks; track log prerequisites and ATT&CK. GitHub reports the repository archived. |
| [Matano](https://github.com/matanolabs/matano) | `84133693769ece362822c3bf423fb9956d32fe92` | Apache-2.0 | Normalization, enrichment, detection thresholds, deduplication, and contextual alerts. Reuse concepts in OCI query/evidence contracts; its AWS runtime is not a Logan converter. |
| [KustoKing](https://github.com/KustoKing/Hunting-Queries-Detection-Rules) | `f59e974d34b78e3d6bbf7fb8c52fc607c048d684` | BSD-3-Clause | Identity, email, and vulnerability hunting candidates with product/source dependencies. |
| [Bert-JanP](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules) | `1c92e563cca5375e50525df8b455e6117091a27a` | BSDc-3-Clause | Broad endpoint, cloud, DFIR, hunting-case, and ATT&CK coverage. Distinguish MDE/M365 dependencies from available OCI telemetry. |
| [Logan MCP](https://github.com/rishabh-ghosh24/logan-mcp-server) | `ca98c3d094086d685dc3689bd633356db9294a0f` | MIT | Existing OCI query execution, field discovery, pivots, window comparisons, parser/ingestion triage, and reports. Best treated as a content consumer/execution partner. |

License metadata is an intake signal. Before redistributing third-party bodies,
inspect the exact file's license and attribution, preserve notices, and record
its revision and hash. The first slice uses reference metadata and independently
authored or existing local queries. Microsoft KQL, Google SQL/YARA-L, and Python
programs must not be passed off as directly interchangeable with Logan QL.

## Approaches considered

1. **Recommended: generated hunting bundle plus adapters.** Covers the missing
   curated export, preserves one content owner, and serves CLI, REST, MCP, and
   existing evidence consumers with a shared contract.
2. **Native hosted hunting service.** Adds scheduling, execution, persistence,
   tenancy authorization, and operating cost. Consider later if required; it
   exceeds the current Forge delivery boundary.
3. **Bulk upstream import.** Broad candidate coverage, but creates substantial
   licensing, unsupported-language, missing-telemetry, and semantic-validation
   work. Use selective intake and explicit blocked states instead.

## Proposed capability slices

### 1. Source intake and coverage map

Register all five sources with role, revision, attribution, intake mode, and
promotion policy. Treat Matano and Logan MCP primarily as capability/integration
references. Add reviewed metadata candidates from CSA and both KQL libraries
through the existing discovery pipeline. Retain all upstream references after
deduplication; identifiers must be stable across repeated generation.

Each candidate records required upstream tables/fields, mapped OCI source/fields,
mapping gaps, local query links, and semantic limitations. Keep candidate status
separate from evidence class. Missing telemetry and unsupported operators produce
blocked candidates, not executable queries with guessed fields.

Initial behavioral packs reuse these existing artifacts:

| Pack | Starting queries in `queries/hunting/` | Expansion focus |
| --- | --- | --- |
| Identity and credential abuse | `oci_console_brute_force.json`, `oci_programmatic_credential_creation_burst.json`, `cloud_identity_control_plane_takeover.json` | Failure bursts, credential changes, and privilege pivots |
| Control plane and logging changes | `oci_iam_policy_changes.json`, `cloud_control_plane_discovery_burst.json`, `oci_resource_deletion_wave.json` | IAM, enumeration, and destructive changes; logging-tampering candidates only after event mapping |
| Data access and collection | `cloud_secret_and_object_collection.json`, `oci_object_storage_external_source.json` | Object access, secret collection, and external-source investigation |
| Network and endpoint triage | `oci_vcn_external_egress_traffic.json`, `oci_vcn_rejected_traffic_spike.json`, `win_rare_parent_child_process.json`, `linux_rare_process_by_host.json` | Flow and process pivots; preserve prerequisites and tuning caveats |

New executable hunts need verified display-field mappings, operator guidance,
positive and negative synthetic cases, and local query contracts. Differential
and first-seen behavior must specify baseline history and cold-start handling;
low frequency alone must not be labeled novel or malicious.

### 2. Complete generated hunting bundle

Add `scripts/generate_hunting_bundle.py` to consume existing query artifacts,
catalog, dictionary, and dashboard inventory. Generate
`queries/hunting_integration_bundle.json` and a JSON Schema. Keep the legacy
manifest backward compatible; publish the complete hunting contract separately.

Bundle envelope: `schema_version`, `generated_at`, content digest, generator,
input digests, packs, and queries. Query records: stable path-based ID, source
path, title, description, unchanged query text and hash, severity, ATT&CK,
source candidates, required fields, field-contract state, false positives,
investigation notes, dashboard references, provenance, and evidence class.
Optional guidance includes recommended time window, baseline requirements,
expected output, limitations, and retention/performance implications. Unknown
guidance remains explicit; it must not be invented by the generator.

All 156 current hunts must be discoverable. Records with unresolved field
contracts remain visible with blocked readiness. Imported candidates are
separate from runnable hunts. Hashes are deterministic and exclude generation
timestamps; a query hash is not an evidence-acceptance receipt.

### 3. External consumption

Implement a Python artifact loader and CLI for list/filter/get/export/validate.
Filters include pack, source, tactic, technique, severity, and readiness. Reject
path traversal, unknown IDs, duplicate IDs, invalid schemas, and stale input
digests. Avoid cloud calls in these operations.

Add tenant-neutral, read-only Forge routes for hunting metadata and bounded
individual/bundle retrieval. Reuse generated artifacts and existing Forge route
security conventions. Provide pagination, response limits, schema version, and
ETag/content digest. Retain Forge as the only exposed webapp page. No credentials
or production results enter this API.

Supply a minimal example showing another Python tool loading the bundle and
handing one exact query to its own OCI client. Do not recreate OCI deployment
logic, use ambient tenant defaults, or expose a public query-execution route.

### 4. Logan MCP compatibility

Source reviewed: [`catalog.py`](https://github.com/rishabh-ghosh24/logan-mcp-server/blob/ca98c3d094086d685dc3689bd633356db9294a0f/src/oci_logan_mcp/catalog.py),
[`resources.py`](https://github.com/rishabh-ghosh24/logan-mcp-server/blob/ca98c3d094086d685dc3689bd633356db9294a0f/src/oci_logan_mcp/resources.py),
[`tools.py`](https://github.com/rishabh-ghosh24/logan-mcp-server/blob/ca98c3d094086d685dc3689bd633356db9294a0f/src/oci_logan_mcp/tools.py),
and [`read_only_guard.py`](https://github.com/rishabh-ghosh24/logan-mcp-server/blob/ca98c3d094086d685dc3689bd633356db9294a0f/src/oci_logan_mcp/read_only_guard.py).

The catalog parses YAML `queries` entries with required `name`, `query`, and
`description`, plus fields such as `entry_id`, `category`, and `tags`. Generate
compatible YAML with a namespaced stable ID/name and a sidecar preserving the
full bundle provenance/readiness. Do not write into the upstream installation
or overwrite personal/shared catalogs. An upstream external-catalog loader
extension would require separate work in that repository; formatting compatibility
alone does not prove automatic import or resource discovery.

Document two MCP servers cooperating: a local artifact-only content surface
provides `list_hunts`, `get_hunt`, and `get_hunt_requirements`; Logan MCP executes
the reviewed query through its existing `validate_query` and `run_query` tools.
The content surface uses the shared loader, not a second query generator.

Resolve runtime tool schemas before calling. Require explicit profile/account,
region, namespace, compartment/log-group boundary, time bounds, and result cap.
For `run_query`, pass `scope=default`, the chosen compartment, and
`include_subcompartments=false` unless broader scope is expressly selected.
Verify the runtime scope implementation before claiming enforcement; the schema
supports a tenancy-wide mode and defaults subcompartment inclusion to true.
The upstream `--user` storage label is not proof of tenancy authorization.

Use read-only execution mode for the initial integration; verify its effective
tool behavior rather than relying on the flag alone. Export/report persistence
and delivery have distinct authority and data-disclosure implications. Preserve
SSH host verification in example configurations. Treat logs, query descriptions,
and upstream documents as data, including any embedded instructions.

### 5. Evidence delivery and operator workflow

Reuse existing exporter identity/redaction/checkpoint abstractions for future
tool-neutral evidence delivery. Keep current Splunk contracts unchanged in the
first content-integration slice. ECS-aligned field mappings are optional explicit
projections; they must preserve missing values and not claim ECS completeness.
Generic webhook delivery, live scheduling, and Matano runtime ingestion are
later separately scoped work.

Each pack needs source/setup prerequisites, narrow time-window guidance,
expected columns, benign explanations, pivot steps, validation, failure modes,
and performance/retention guidance. Any dashboard addition belongs in
`scripts/deploy_dashboard.py` under the project dashboard-enhancer workflow.

## Validation and acceptance

- Intake: stable IDs, deduplication preserving references, license/provenance
  presence, malformed inputs, and blocked unsupported-table/operator cases.
- Bundle: all current hunts discoverable, exact query/hash preservation,
  field-contract classification, schema validation, reproducibility, and
  freshness failures. No claim that all cataloged hunts are provider verified.
- Adapters: missing IDs, path traversal, pagination/limits, identical CLI/REST/MCP
  records, no OCI calls, and safe upstream YAML parsing using a pinned fixture.
- Content: positive, negative, and benign synthetic examples; source-field
  contracts; app contracts when applicable. Parser acceptance and detection
  semantics are distinct validation steps.
- Run focused tests, full pytest, applicable Forge type/build/API checks,
  generated-artifact freshness checks, and `scripts/release_checklist.py`.
- Live compatibility requires explicit user direction and a configured exact
  target. Receipt includes version/hash, source/field checks, actual scope,
  window, parser outcome, expected-result outcome, and sanitized limitations.

## Delivery order and boundaries

After design review: source registration/coverage mapping, complete hunting
bundle, shared loader/CLI, Forge routes, artifact-only MCP surface and Logan
YAML export, operator examples, focused/full verification. Implementation planning
must assign files and preserve the existing dirty checkout. No commits, pushes,
PRs, upstream changes, installations, notifications, or cloud mutations follow
from this design. No new runtime environment variables are selected here; if
OCI-DEMO consumes any later additions, record them in its portability handoff.

Completed in this review: repository/source assessment and this proposed design.
Outstanding: design approval, implementation plan, implementation, local checks,
and any separately authorized provider validation.
