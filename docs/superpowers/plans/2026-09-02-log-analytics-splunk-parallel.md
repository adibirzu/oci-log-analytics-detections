# OCI Log Analytics and Splunk Parallel Operations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and document two tested Splunk integration modes: raw OCI Logging fan-out through `adibirzu/oci-splunk`, and replay-safe export of selected Log Analytics detection evidence to Splunk HEC.

**Architecture:** Existing OCI sources continue to land in Log Analytics as the canonical analytics plane. Mode 1 uses separate Connector Hub routes to Log Analytics and OCI Streaming, with the external `oci-splunk` project owning Streaming-to-HEC transport. Mode 2 turns a Log Analytics detection metric into an alarm/Notifications trigger, then uses a least-privilege OCI Function to re-query a bounded evidence window, normalize and deduplicate events, deliver them to HEC, and commit a checkpoint only after confirmed delivery.

**Tech Stack:** Python 3.11+, JSON Schema, PyYAML, OCI Python SDK, OCI Functions/Fn Python FDK, Terraform/OCI Resource Manager, OCI Log Analytics, Monitoring, Notifications, Vault, Object Storage, Splunk HEC, pytest, Mermaid, Excalidraw.

**Spec:** `docs/superpowers/specs/2026-09-02-log-analytics-splunk-parallel-design.md`

## Implementation status

**Tasks 1-10: complete for the scoped local implementation.** The delivery policy, schemas, generated nine-rule registry, replay-safe exporter, OCI/HEC adapters, operator CLI, opt-in Terraform module, ten Mermaid/Excalidraw workflow pairs, four operator guides, navigation, and self-hashed offline release receipt are present in the file map below. The Splunk-specific offline release stage passes 12/12 gates, and native `terraform init -backend=false` plus `terraform validate` succeeds with OCI provider 8.2.0.

Provider validation remains not run: no OCI tenancy, Windows host, Vault secret, live Log Analytics query, Function, Streaming consumer, Splunk HEC endpoint, or Splunk search was contacted by this implementation run. The live-canary follow-on remains an independently approved, target-bound gate. The repository-wide release checklist also reports pre-existing promoted-Sentinel parser-schema drift; that separate gate is not rewritten or waived here.

Fast verification:

```bash
python3 scripts/generate_splunk_detection_registry.py --check
python3 scripts/splunk_evidence_exporter_cli.py validate-config
python3 scripts/splunk_evidence_exporter_cli.py local-e2e --scenario success
python3 scripts/release_checklist.py --splunk-parallel-offline-stage
terraform -chdir=stack init -backend=false
terraform -chdir=stack validate
```

## Global Constraints

- Keep Log Analytics as the canonical analytics plane and keep existing query surfaces: `rules/**`, `queries/*.json`, `queries/apps/*.json`, and `queries/hunting/*.json`.
- Do not create `queries/splunk/`, hand-edit generated Sigma JSON, or hand-edit promoted Sentinel JSON.
- Reuse `https://github.com/adibirzu/oci-splunk` for Mode 1; do not copy its Terraform, consumers, HEC secrets, or Splunk app into this repository.
- Production instructions must pin a reviewed `oci-splunk` tag or commit; discovery links may target `main`.
- Mode 2 is additive and disabled by default. No existing alarm, topic, or HEC credential is changed automatically.
- Detection rules emit Monitoring metrics; the evidence exporter performs a separate bounded Log Analytics query for matching records.
- Default evidence excludes `Original Log Content`; a rule must opt in to a bounded redacted subset.
- Never commit HEC tokens, OCIDs, namespaces, customer topology, hostnames, IPs, or live payloads. Documentation uses explicit `<PLACEHOLDER>` tokens.
- Commit steps in this plan are commands for an authorized executor only. Do not commit or push without explicit repository authority.
- Local/configured/provider/release evidence classes remain distinct.
- Live OCI or Splunk validation requires an exact approved target, cost boundary, canary, rollback, and sanitized receipt.

## File map

| File | Responsibility |
|---|---|
| `config/splunk_parallel_delivery.yaml` | Hand-authored delivery policy and initial migration entries |
| `schemas/splunk_detection_registry.schema.json` | Validates the generated migration registry |
| `schemas/splunk_evidence_event.schema.json` | Validates each HEC evidence event |
| `queries/splunk_detection_registry.json` | Generated Splunk-to-Log-Analytics mapping contract; not a saved search |
| `scripts/generate_splunk_detection_registry.py` | Builds and validates the registry deterministically |
| `scripts/splunk_evidence_exporter/models.py` | Frozen domain types and serialization |
| `scripts/splunk_evidence_exporter/window.py` | Alarm-window and checkpoint-overlap calculation |
| `scripts/splunk_evidence_exporter/envelope.py` | Redaction, event-key generation, envelope creation, and batching |
| `scripts/splunk_evidence_exporter/retry.py` | HEC error classification and bounded backoff |
| `scripts/splunk_evidence_exporter/ports.py` | Protocols for query, secret, state, DLQ, metrics, and HEC adapters |
| `scripts/splunk_evidence_exporter/service.py` | Pure orchestration and commit-after-delivery semantics |
| `scripts/splunk_evidence_exporter/adapters.py` | OCI SDK, Vault, Object Storage, and Splunk HEC adapters |
| `scripts/splunk_evidence_exporter/handler.py` | OCI Functions FDK entry point |
| `scripts/splunk_evidence_exporter_cli.py` | Offline plan, fixture E2E, payload validation, and guarded canary CLI |
| `scripts/test_splunk_detection_registry.py` | Registry and initial-rule tests |
| `scripts/test_splunk_evidence_exporter.py` | Unit and local adapter tests |
| `scripts/test_splunk_evidence_e2e.py` | In-process fake Log Analytics and mock HEC E2E tests |
| `stack/modules/splunk_evidence_exporter/**` | Optional Function/topic/subscription/state/DLQ/monitoring module |
| `docs/SPLUNK_*.md` | Operator, migration, export, and E2E guides |
| `docs/diagrams/logan-splunk-*` | Mermaid, Excalidraw, and JSON diagram specifications |

---

### Task 1: Define delivery-policy, registry, and evidence schemas

**Files:**
- Create: `config/splunk_parallel_delivery.yaml`
- Create: `schemas/splunk_detection_registry.schema.json`
- Create: `schemas/splunk_evidence_event.schema.json`
- Test: `scripts/test_splunk_detection_registry.py`

**Interfaces:**
- Consumes: canonical query paths and `queries/log_source_field_dictionary.json`.
- Produces: `DeliveryPolicy`, registry JSON shape, and `oci.logan.splunk.evidence.v1` validation contract used by every later task.

- [ ] **Step 1: Write failing schema tests**

Add tests that load both schemas with `jsonschema.Draft202012Validator.check_schema`, validate one good policy-derived registry entry and one good evidence event, and reject these exact cases: unknown query path, `dimensions` length greater than three, `include_original_content: true` without `redaction_profile`, missing `event_key`, and any `hec_token` property.

```python
def test_evidence_schema_rejects_hec_token():
    event = valid_evidence_event()
    event["hec_token"] = "secret"
    errors = list(EVIDENCE_VALIDATOR.iter_errors(event))
    assert any("Additional properties" in error.message for error in errors)
```

- [ ] **Step 2: Run the focused test and confirm RED**

Run: `python3 -m pytest scripts/test_splunk_detection_registry.py -q`

Expected: failure because the configuration and schemas do not exist.

- [ ] **Step 3: Add the delivery policy**

Define these top-level keys with `version: 1`: `defaults`, `raw_sources`, `detections`, and `splunk_target`. Defaults must specify `delivery_mode: evidence`, `include_original_content: false`, `lookback: 15m`, `overlap: 2m`, `max_rows: 1000`, `max_batch_events: 100`, `max_attempts: 4`, and `sourcetype: oci:logan:detection`. `splunk_target` contains environment-variable names and index/sourcetype placeholders, never values.

- [ ] **Step 4: Add strict Draft 2020-12 schemas**

Set `additionalProperties: false` at every object layer. Registry entries require `id`, `title`, `splunk`, `oci_query_file`, `required_sources`, `required_fields`, `fidelity`, `detection`, `delivery`, and `evidence`. Evidence events require `schema_version`, `event_key`, `batch_id`, `detection`, `evidence`, and `provenance`.

- [ ] **Step 5: Run schema and sensitive-value tests**

Run: `python3 -m pytest scripts/test_splunk_detection_registry.py scripts/test_scan_sensitive_values.py -q`

Expected: PASS.

- [ ] **Step 6: Authorized commit checkpoint**

```bash
git add config/splunk_parallel_delivery.yaml schemas/splunk_detection_registry.schema.json schemas/splunk_evidence_event.schema.json scripts/test_splunk_detection_registry.py
git commit -m "feat: define Splunk evidence delivery contracts"
```

### Task 2: Generate the canonical Splunk detection registry

**Files:**
- Create: `scripts/generate_splunk_detection_registry.py`
- Modify: `scripts/query_artifacts.py`
- Create: `queries/splunk_detection_registry.json`
- Modify: `scripts/test_splunk_detection_registry.py`

**Interfaces:**
- Consumes: `config/splunk_parallel_delivery.yaml`, query JSON, field dictionary, and both schemas from Task 1.
- Produces: `build_registry(config_path: Path) -> dict`, `validate_registry(registry: dict) -> list[str]`, and CLI options `--out`, `--check`, and `--json`.

- [ ] **Step 1: Write failing generator tests**

Test deterministic ordering by migration ID, rejection of missing query files/fields, preservation of Splunk repository/app/version/search provenance, and exclusion of `queries/splunk_detection_registry.json` from saved-search walkers.

```python
def test_registry_is_deterministic():
    first = build_registry(CONFIG)
    second = build_registry(CONFIG)
    first.pop("generated_at", None)
    second.pop("generated_at", None)
    assert first == second
    assert [x["id"] for x in first["detections"]] == sorted(x["id"] for x in first["detections"])
```

- [ ] **Step 2: Confirm RED**

Run: `python3 -m pytest scripts/test_splunk_detection_registry.py -q`

Expected: import failure for `generate_splunk_detection_registry`.

- [ ] **Step 3: Implement generator loading and validation**

Implement small functions:

```python
def load_delivery_config(path: Path) -> dict: ...
def load_field_dictionary(path: Path) -> set[str]: ...
def build_registry(config_path: Path = DEFAULT_CONFIG) -> dict: ...
def validate_registry(registry: dict) -> list[str]: ...
def write_registry(registry: dict, output: Path) -> None: ...
```

`validate_registry` must check schema, query existence, query title, required source/field declarations, scheduled eligibility via `build_detection_rule_spec`, and forbidden secret/tenant keys.

- [ ] **Step 4: Mark the generated registry as non-query metadata**

Update `is_saved_search_query_file()` and its tests so the new registry is skipped by catalog, dashboard, export, and detection-rule query walkers.

- [ ] **Step 5: Generate and check the registry**

Run:

```bash
python3 scripts/generate_splunk_detection_registry.py --out queries/splunk_detection_registry.json
python3 scripts/generate_splunk_detection_registry.py --check --out queries/splunk_detection_registry.json
python3 -m pytest scripts/test_splunk_detection_registry.py scripts/test_query_artifacts.py -q
```

Expected: registry written; drift check and tests PASS.

- [ ] **Step 6: Authorized commit checkpoint**

```bash
git add scripts/generate_splunk_detection_registry.py scripts/query_artifacts.py scripts/test_splunk_detection_registry.py scripts/test_query_artifacts.py queries/splunk_detection_registry.json
git commit -m "feat: generate Splunk detection migration registry"
```

### Task 3: Register and validate the initial nine detections

**Files:**
- Modify: `config/splunk_parallel_delivery.yaml`
- Modify: existing canonical files in `queries/*.json` or `queries/hunting/*.json` only when a required query is absent
- Modify: `scripts/test_splunk_detection_registry.py`
- Modify/generated: `queries/splunk_detection_registry.json`
- Modify/generated: `queries/detection_rule_specs.json`

**Interfaces:**
- Consumes: generator from Task 2 and `build_detection_rule_spec(query_path: str, payload: dict) -> dict`.
- Produces: nine validated registry entries and nine deployable or explicitly unsupported detection classifications.

- [ ] **Step 1: Write failing coverage tests**

Require IDs for `vcn-rejected-traffic-spike`, `oci-audit-failures`, `oci-iam-policy-change`, `object-storage-new-external-source`, and the five `windows-access-*` rules. Assert each entry has an existing canonical query, a provenance URL/version, required sources/fields, fidelity, and an evidence delivery policy.

- [ ] **Step 2: Confirm RED for missing mappings**

Run: `python3 -m pytest scripts/test_splunk_detection_registry.py -q`

Expected: failure listing the missing initial migration IDs.

- [ ] **Step 3: Reuse current Windows access queries**

Map the five existing `queries/hunting/windows_access_*.json` files. Do not duplicate their LAQL. Preserve their 5-minute schedule/lookback and metric/dimension restrictions.

- [ ] **Step 4: Map or add the four OCI rules**

Search current canonical queries before authoring. If an exact query exists, reference it. If only a transport-side Splunk alert exists, add a tenant-neutral Sigma rule when portable; otherwise add one curated `queries/hunting/*.json` aggregation with explicit source fields, dashboard metadata, false positives, and `detection_rule` settings.

- [ ] **Step 5: Validate scheduled eligibility and fixtures**

For every scheduled entry, assert one numeric metric alias and no more than three dimensions. Add positive and negative synthetic records to the existing source generators rather than static hand-authored `test_data/` output.

- [ ] **Step 6: Regenerate owned artifacts and run tests**

```bash
python3 scripts/convert_sigma.py
python3 scripts/generate_splunk_detection_registry.py --out queries/splunk_detection_registry.json
python3 scripts/detection_rule_creator.py --write-default
python3 scripts/generate_catalog.py
python3 scripts/deploy_dashboard.py --export-inventory
python3 -m pytest scripts/test_splunk_detection_registry.py scripts/test_windows_access_onboarding.py scripts/test_catalog.py -q
```

Expected: nine entries classified; generated-artifact checks PASS.

- [ ] **Step 7: Authorized commit checkpoint**

Stage only the source/configuration/tests and their owned generated artifacts, then commit with `feat: add initial Splunk migration detection pack` if authorized.

### Task 4: Implement the pure evidence-export domain core

**Files:**
- Create: `scripts/splunk_evidence_exporter/__init__.py`
- Create: `scripts/splunk_evidence_exporter/models.py`
- Create: `scripts/splunk_evidence_exporter/window.py`
- Create: `scripts/splunk_evidence_exporter/envelope.py`
- Create: `scripts/splunk_evidence_exporter/retry.py`
- Create: `scripts/splunk_evidence_exporter/ports.py`
- Test: `scripts/test_splunk_evidence_exporter.py`

**Interfaces:**
- Consumes: evidence schema and registry entry from Tasks 1–3.
- Produces: `AlarmTrigger`, `QueryWindow`, `EvidenceEvent`, `ExportBatch`, adapter Protocols, `calculate_window`, `event_key`, `build_evidence_event`, `batch_events`, and `classify_hec_failure`.

- [ ] **Step 1: Write model and alarm-decoding tests**

Use a sanitized OCI alarm fixture. Assert detection ID, alarm end time, namespace, metric name, and dimensions are parsed; reject missing detection ID and more than three dimensions.

- [ ] **Step 2: Write window/checkpoint tests**

Assert `calculate_window(alarm_end, lookback=15m, overlap=2m, checkpoint=None)` returns a 17-minute window; with a checkpoint, start at `checkpoint - overlap`; never allow start after end or a window above a configured maximum.

- [ ] **Step 3: Write event-key/envelope tests**

Assert key stability across dictionary order, different keys for different rule/time/entity, schema-valid output, exclusion of `Original Log Content` by default, and redaction of keys matching `token`, `password`, `authorization`, `secret`, `ocid`, and configured sensitive fields.

- [ ] **Step 4: Write retry classification tests**

Expected classification: timeout/408/429/5xx → `retryable`; 400/401/403/404/413/422 → `quarantine`; success only for HEC-confirmed 2xx response with valid acknowledgement semantics selected by configuration.

- [ ] **Step 5: Confirm RED**

Run: `python3 -m pytest scripts/test_splunk_evidence_exporter.py -q`

- [ ] **Step 6: Implement immutable domain types and pure functions**

Use frozen dataclasses and Protocols. No OCI SDK import, network access, environment access, clock access, or filesystem write is allowed in these modules.

```python
def event_key(rule_id: str, row: Mapping[str, object]) -> str:
    canonical = json.dumps(normalize_for_hash(row), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(f"{rule_id}\n{canonical}".encode()).hexdigest()
```

- [ ] **Step 7: Run focused tests**

Run: `python3 -m pytest scripts/test_splunk_evidence_exporter.py -q`

Expected: PASS.

- [ ] **Step 8: Authorized commit checkpoint**

Commit the exporter domain modules and focused test only if authorized.

### Task 5: Implement orchestration and external adapters

**Files:**
- Create: `scripts/splunk_evidence_exporter/service.py`
- Create: `scripts/splunk_evidence_exporter/adapters.py`
- Create: `scripts/splunk_evidence_exporter/handler.py`
- Modify: `scripts/test_splunk_evidence_exporter.py`

**Interfaces:**
- Consumes: Protocols and domain types from Task 4.
- Produces: `EvidenceExportService.export(trigger: AlarmTrigger) -> ExportReceipt`, `OciLogAnalyticsQueryAdapter`, `OciVaultSecretAdapter`, `ObjectStorageStateAdapter`, `ObjectStorageDeadLetterAdapter`, `SplunkHecAdapter`, and `handler(ctx, data=None)`.

- [ ] **Step 1: Write service tests with in-memory adapters**

Test exact order: load registry → read checkpoint → calculate window → query → normalize/dedupe → deliver batches → commit checkpoint → emit success receipt. Assert zero-row queries record `no_evidence` without HEC call; HEC failures never commit a checkpoint.

- [ ] **Step 2: Write adapter contract tests**

Mock OCI SDK/HTTP boundaries. Assert Log Analytics query includes exact compartment/subtree/window/max rows; Vault token is never represented in `repr`/logs; HEC uses HTTPS, configured index/sourcetype, bounded timeout, and JSON event endpoint; state/DLQ object names contain only sanitized rule/time/hash identifiers.

- [ ] **Step 3: Confirm RED**

Run: `python3 -m pytest scripts/test_splunk_evidence_exporter.py -q`

- [ ] **Step 4: Implement `EvidenceExportService`**

Inject adapters and clock. Use checkpoint commit only after every HEC batch confirms. If some batches succeed and a later batch fails, write one DLQ record containing delivered event keys plus remaining events so replay does not duplicate confirmed events.

- [ ] **Step 5: Implement OCI and HEC adapters**

Use resource-principal signing in OCI Functions. Keep SDK imports behind adapters. Use `urllib` or an already-approved minimal HTTP dependency; do not add a broad web framework. Validate configuration at startup and reject non-HTTPS HEC except in explicit local-test mode.

- [ ] **Step 6: Implement the FDK handler**

Decode one Notifications alarm message, invoke the service, return a sanitized receipt summary, and emit structured logs without query results, tokens, OCIDs, or raw event content.

- [ ] **Step 7: Run focused tests and secret scan**

```bash
python3 -m pytest scripts/test_splunk_evidence_exporter.py -q
python3 scripts/redact.py --check scripts/splunk_evidence_exporter
```

Expected: PASS.

- [ ] **Step 8: Authorized commit checkpoint**

Commit service, adapters, handler, and tests only if authorized.

### Task 6: Build the local E2E harness, replay, and operator CLI

**Files:**
- Create: `scripts/splunk_evidence_exporter_cli.py`
- Create: `scripts/test_splunk_evidence_e2e.py`
- Create: `scripts/fixtures/splunk_evidence/alarm.json`
- Create: `scripts/fixtures/splunk_evidence/query_rows.json`
- Create: `scripts/fixtures/splunk_evidence/hec_responses.json`

**Interfaces:**
- Consumes: registry, schema, and exporter service.
- Produces CLI commands `plan`, `validate-config`, `validate-payload`, `local-e2e`, `render-function-config`, `render-iam`, `canary-plan`, and `replay-plan`.

- [ ] **Step 1: Write failing CLI contract tests**

Assert `plan --json` is offline and reports both modes, nine detections, disabled defaults, components, policies, and evidence gates. Assert `local-e2e --scenario success` sends query rows into an in-process mock HEC and produces a committed checkpoint.

- [ ] **Step 2: Add failure/replay E2E tests**

Cover duplicate invocation, zero evidence, timeout, 429, 500, 400, 401, oversized batch, missing secret, DLQ write, DLQ failure, retry exhaustion, and approved replay. Assert no token or raw OCI identifier appears in captured stdout/stderr.

- [ ] **Step 3: Confirm RED**

Run: `python3 -m pytest scripts/test_splunk_evidence_e2e.py -q`

- [ ] **Step 4: Implement the CLI and in-process adapters**

`local-e2e` must use the same `EvidenceExportService` as the Function with only adapters replaced. `canary-plan` and `replay-plan` render reviewable steps and never call OCI unless a separate explicit live subcommand is later approved.

- [ ] **Step 5: Run the scenario matrix**

```bash
python3 scripts/splunk_evidence_exporter_cli.py plan --json
python3 scripts/splunk_evidence_exporter_cli.py validate-config
python3 scripts/splunk_evidence_exporter_cli.py local-e2e --scenario success
python3 -m pytest scripts/test_splunk_evidence_e2e.py scripts/test_splunk_evidence_exporter.py -q
```

Expected: all scenarios PASS with tenant-neutral receipts.

- [ ] **Step 6: Authorized commit checkpoint**

Commit CLI, fixtures, and E2E tests only if authorized.

### Task 7: Add the optional OCI deployment module and IAM preview

**Files:**
- Create: `stack/modules/splunk_evidence_exporter/main.tf`
- Create: `stack/modules/splunk_evidence_exporter/variables.tf`
- Create: `stack/modules/splunk_evidence_exporter/outputs.tf`
- Create: `stack/modules/splunk_evidence_exporter/function/func.yaml`
- Create: `stack/modules/splunk_evidence_exporter/function/requirements.txt`
- Modify: `stack/main.tf`
- Modify: `stack/variables.tf`
- Modify: `stack/outputs.tf`
- Modify: `stack/schema.yaml`
- Modify: `scripts/splunk_evidence_exporter_cli.py`
- Create: `scripts/test_splunk_evidence_terraform.py`

**Interfaces:**
- Consumes: exporter handler and operator-rendered placeholders.
- Produces optional resources controlled by `enable_splunk_evidence_exporter = false`, plus only non-secret resource identifiers as sensitive outputs where unavoidable.

- [ ] **Step 1: Write failing Terraform contract tests**

Parse Terraform text and assert the module defaults disabled, accepts an existing Vault secret OCID but no token value, creates alarms disabled, limits topic subscription to the exact Function, enables Function/connector logs, configures state/DLQ lifecycle, and marks identifier outputs sensitive.

- [ ] **Step 2: Confirm RED**

Run: `python3 -m pytest scripts/test_splunk_evidence_terraform.py -q`

- [ ] **Step 3: Implement the module**

Create the Function application/function, dynamic group or documented resource-principal matching rule, topic/function subscription, Object Storage state/DLQ bucket or existing-bucket inputs, Vault secret reference, service logs, exporter metrics namespace, and disabled alarm wiring. Do not create a HEC secret value or broad VCN.

- [ ] **Step 4: Add least-privilege rendered policy categories**

`render-iam` outputs separate blocks for operator, Connector Hub Mode 1, Function query, Vault secret, state/DLQ, Notifications invocation, Monitoring, and logging. Use exact placeholders and include a warning that resource-family shortcuts broaden access.

- [ ] **Step 5: Format and validate**

```bash
terraform -chdir=stack fmt -check -recursive
terraform -chdir=stack init -backend=false
terraform -chdir=stack validate
python3 -m pytest scripts/test_splunk_evidence_terraform.py -q
```

Expected: format, validate, and tests PASS without provider changes.

- [ ] **Step 6: Authorized commit checkpoint**

Commit the optional module, stack wiring, IAM renderer, and tests only if authorized.

### Task 8: Create and validate Mermaid and Excalidraw workflow set

**Files:**
- Create: `docs/diagrams/logan-splunk-architecture.json`
- Create: `docs/diagrams/logan-splunk-architecture.mmd`
- Create: `docs/diagrams/logan-splunk-architecture.excalidraw`
- Create: `docs/diagrams/logan-splunk-raw-fanout.mmd`
- Create: `docs/diagrams/logan-splunk-evidence-export.mmd`
- Create: `docs/diagrams/logan-splunk-onprem-agent.mmd`
- Create: `docs/diagrams/logan-splunk-export-sequence.mmd`
- Create: `docs/diagrams/logan-splunk-replay-state.mmd`
- Create: `docs/diagrams/logan-splunk-iam-boundaries.mmd`
- Create: `docs/diagrams/logan-splunk-onboarding.mmd`
- Create: `docs/diagrams/logan-splunk-validation.mmd`
- Create: `docs/diagrams/logan-splunk-troubleshooting.mmd`
- Create: `scripts/test_splunk_diagrams.py`

**Interfaces:**
- Consumes: approved topology and state/sequence behavior from prior tasks.
- Produces ten tenant-neutral, editable views with matching terminology and evidence labels.

- [ ] **Step 1: Write failing diagram inventory tests**

Require all ten Mermaid files, one Excalidraw source, the JSON specification, no active Mermaid `click`/script content, no external Excalidraw embeds, no OCIDs/IPs/secrets, and exact nodes for `oci-splunk`, Management Agent, Log Analytics, Monitoring, Notifications, Function, Vault, checkpoint/DLQ, and Splunk HEC.

- [ ] **Step 2: Confirm RED**

Run: `python3 -m pytest scripts/test_splunk_diagrams.py -q`

- [ ] **Step 3: Generate the main architecture from JSON**

Use `skills/oci-diagramming/scripts/oci_diagram.py generate` for Mermaid and Excalidraw. Use 5–9 primary objects per view, split runtime from control flow, and label telemetry/control/response edges.

- [ ] **Step 4: Author the nine focused Mermaid views**

Copy terminology from the spec and implemented interfaces. Do not put code snippets or policy statements inside diagrams. Each file starts with a title/evidence comment and remains renderable in GitHub Markdown.

- [ ] **Step 5: Validate and visually inspect**

```bash
python3 skills/oci-diagramming/scripts/oci_diagram.py validate --format mermaid --input docs/diagrams/logan-splunk-architecture.mmd
python3 skills/oci-diagramming/scripts/oci_diagram.py validate --format excalidraw --input docs/diagrams/logan-splunk-architecture.excalidraw
python3 -m pytest scripts/test_splunk_diagrams.py -q
```

Open the main and focused diagrams at README width and check reading order, labels, crossings, contrast, and boundaries.

- [ ] **Step 6: Authorized commit checkpoint**

Commit the JSON, Mermaid, Excalidraw sources, and diagram test only if authorized.

### Task 9: Write the complete operator documentation and integrate navigation

**Files:**
- Create: `docs/SPLUNK_PARALLEL_OPERATIONS.md`
- Create: `docs/SPLUNK_RULE_MIGRATION.md`
- Create: `docs/SPLUNK_EVIDENCE_EXPORT_RUNBOOK.md`
- Create: `docs/SPLUNK_E2E_VALIDATION.md`
- Modify: `README.md`
- Modify: `docs/README.md`
- Modify: `docs/ARCHITECTURE.md`
- Modify: `docs/MIGRATION_AND_SECURITY_GUIDE.md`
- Modify: `docs/FAST_ONBOARDING_TRACK.md`
- Modify: `docs/DEPLOYMENT.md`
- Modify: `docs/WINDOWS_ACCESS_FAST_ONBOARDING.md`
- Modify: `docs/WINDOWS_ACCESS_WORKFLOW_DIAGRAMS.md`
- Create: `scripts/test_splunk_documentation.py`

**Interfaces:**
- Consumes: actual commands, configuration, schemas, Terraform variables, diagrams, and tests from Tasks 1–8.
- Produces: manual and scripted procedures that reference only implemented interfaces.

- [ ] **Step 1: Write failing documentation contract tests**

Assert all navigation links resolve; every guide includes prerequisites, ownership, IAM/network, manual steps, scripted steps, validation, failure modes, cost/retention/privacy, rollback/cleanup/replay, evidence class, Oracle sources, and a pinned-version warning for `oci-splunk`. Assert README embeds concise diagrams and links the full guide.

- [ ] **Step 2: Confirm RED**

Run: `python3 -m pytest scripts/test_splunk_documentation.py -q`

- [ ] **Step 3: Write `SPLUNK_PARALLEL_OPERATIONS.md`**

Cover the decision matrix, Mode 1 `oci-splunk` handoff, Mode 2 source-of-truth path, hybrid per-source policy, component inventory, on-prem path, service limits, cost model, steady-state operations, health metrics, and rollback.

- [ ] **Step 4: Write migration, exporter, and E2E guides**

Use the implemented registry and CLI commands verbatim. The manual runbook must be executable through OCI Console/Splunk UI. The scripted path must start with offline plan/preflight and keep apply/canary/replay as separate reviewed actions.

- [ ] **Step 5: Enhance existing documentation**

Add the two-mode decision to README and the documentation hub. Expand architecture, migration, onboarding, deployment, Windows, and workflow pages with the relevant focused diagrams and cross-links; do not duplicate the full operator procedure into every page.

- [ ] **Step 6: Run docs, link, diagram, and secret tests**

```bash
python3 -m pytest scripts/test_splunk_documentation.py scripts/test_splunk_diagrams.py scripts/test_scan_sensitive_values.py -q
python3 scripts/splunk_evidence_exporter_cli.py plan --json
```

Expected: PASS and a tenant-neutral plan.

- [ ] **Step 7: Authorized commit checkpoint**

Commit the documentation and documentation tests only if authorized.

### Task 10: Integrate release gates and produce a local evidence packet

**Files:**
- Modify: `scripts/release_checklist.py`
- Create: `docs/health/splunk-parallel-local-evidence.example.json`
- Modify: `CONTRIBUTING.md`
- Modify: `STATUS.md` if present and inventory-backed
- Test: existing full suite plus all new tests

**Interfaces:**
- Consumes: all generated artifacts and local test commands.
- Produces: one local release stage that remains offline, restart-safe, and evidence-classified.

- [ ] **Step 1: Write failing release-stage test**

Assert the release checklist calls registry drift validation, schema validation, local exporter success/duplicate/failure scenarios, diagram checks, docs checks, and Terraform static validation without calling OCI, Splunk, HEC, Vault, or external endpoints.

- [ ] **Step 2: Confirm RED**

Run the focused release-checklist test and verify the new stage is absent.

- [ ] **Step 3: Add the offline release stage**

Return structured status with `evidence_class: locally_verified`, scenario counts, artifact hashes, and explicit `provider_validation: not_run`. Do not write a false live receipt.

- [ ] **Step 4: Run focused then full gates**

```bash
python3 -m pytest -q \
  scripts/test_splunk_detection_registry.py \
  scripts/test_splunk_evidence_exporter.py \
  scripts/test_splunk_evidence_e2e.py \
  scripts/test_splunk_evidence_terraform.py \
  scripts/test_splunk_diagrams.py \
  scripts/test_splunk_documentation.py
python3 scripts/deploy_dashboard.py --validate
python3 scripts/deploy_dashboard.py --dry-run
python3 -m pytest -q
python3 scripts/release_checklist.py
```

Expected: all new stages PASS. If an unrelated pre-existing gate fails, record its exact stage and do not alter protected generated content to force green.

- [ ] **Step 5: Inspect repository state and evidence class**

Run `git diff --check`, reconcile README/STATUS counts with `queries/catalog.json`, validate every local link and diagram, scan changed files for secrets, and classify the result as code-backed/locally verified only.

- [ ] **Step 6: Authorized commit checkpoint**

Commit the release integration and local example evidence only if authorized. Do not push, open a PR, deploy, or run a live canary without separate approval.

## Live-canary follow-on

Live execution is not part of this local implementation plan. When separately authorized, create a target-bound canary plan that records:

- exact OCI account/profile, region, compartment, Log Analytics namespace/log group, Function application, topic, Vault secret, state/DLQ, alarm, and source;
- exact Splunk owner, HEC endpoint, index, sourcetype, TLS trust, and maintenance window;
- one safe canary event and one negative control;
- maximum query window, row count, HEC batch, retries, and cost;
- rollback and stop conditions;
- sanitized evidence fields and customer acceptance owner.

The live gate closes only after the event is queryable in Log Analytics, produces the intended metric/alarm, invokes the exporter, receives a confirmed HEC delivery, and is queryable in Splunk with the deterministic event key.

## Plan self-review

- Spec coverage: both delivery modes, on-prem Management Agent, initial rule pack, canonical ownership, exporter, IAM/network/security, replay, diagrams, docs, testing, rollback, and evidence classes map to Tasks 1–10.
- Placeholder scan: no `TBD`, `TODO`, “implement later,” or undefined “appropriate handling” instructions remain. Angle-bracket values are deliberate security placeholders required by repository policy.
- Type consistency: registry, trigger, window, evidence, batch, receipt, adapter, service, and CLI names are defined before downstream use.
- Scope: the tasks form one ordered vertical slice; the optional OCI module remains disabled and separately testable.
