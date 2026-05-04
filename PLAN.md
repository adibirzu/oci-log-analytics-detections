# OCI Log Analytics Detection Rules Enhancement Plan

## Goal
Enhance the OCI Log Analytics project by creating a comprehensive library of detection rules (starting with 100+) inspired by industry standards (Sigma, Elastic, Splunk) and tailored for OCI. The project will include automated tooling to convert Sigma-format rules into OCI Log Analytics Query Language (OCL).

## Phase 1: Foundation & Setup ✅
- [x] **Project Structure:** Initialize directories for rules, queries, scripts, and config.
- [x] **Metadata Definition:** Define the schema for tracking rule status, fields, and sources.
- [x] **Mapping Configuration:** Create `sigma_oci_mapping.yaml` to map Sigma fields to OCI Log Analytics fields.

## Phase 2: Tooling (The "Converter") ✅
- [x] **Advanced Scripting:** `scripts/convert_sigma.py` supports advanced logic (NOT, AND/OR, startswith, endswith).
- [x] **Field Modifiers:** Support for `|contains`, `|startswith`, `|endswith`.
- [ ] **Validation:** Implement automated validation of generated OCL syntax.

## Phase 3: Content Creation (First 100 Rules) ✅
- [x] **OCI Specific Rules:** Implemented audit events for IAM, Network, and Compute.
- [x] **Cloud Guard Integration:** Rules for Cloud Guard problem detection.
- [x] **OS Level Rules:** Linux suspicious binaries and Windows LOLBins.
- [x] **Continuous Expansion:** Surpassed 200 source rules and continued expansion through SigmaHQ adaptation and custom content.

## Phase 4: Dashboard & Visualization ✅
- [x] **Dashboard Scripting:** `scripts/generate_dashboard_config.py` created.
- [x] **OCI Deployment Tool:** `scripts/deploy_dashboard.py` fully functional.
- [x] **Test Data:** `scripts/ingest_test_data.py` created for simulation.
- [x] **Dashboard Completion:** Successfully deployed the SOC Security Dashboard with 6 core widgets.

## Phase 5: OCI Log Analytics Deployment ✅
- [x] **Log Source Mapping Fix:** Corrected Cloud Guard, Linux, and Windows log source mappings.
- [x] **UUID Fix:** Replaced all placeholder UUIDs with proper UUIDs.
- [x] **Query Regeneration:** Generated query inventory expanded far beyond the initial 113-query milestone.
- [x] **Saved Searches:** Deployment pipeline matured from the initial 58 saved searches to the current 255-saved-search, 16-dashboard content set documented in the repo.
- [x] **Dashboards:** 5 dashboards deployed (SOC Overview, OCI Audit, Cloud Guard, Linux, Windows).
- [x] **Test Data Pipeline:** 279 NDJSON events generated and uploaded for all 113 rules.
- [x] **Dashboard Widget Fix:** Rewrote saved searches with proper `ui_config`/`scopeFilters` format and embedded in dashboard JSON for `import_dashboard` API.
- [x] **Documentation:** Updated README.md, STATUS.md, PLAN.md.

## Phase 6: Advanced Features & Automation ✅
- [x] **Remote Rule Sync:** `scripts/sync_sigmahq.py` fetches rules from SigmaHQ repository.
- [x] **Rule Catalog:** `scripts/generate_catalog.py` generates CATALOG.md and catalog.json.
- [x] **CI/CD Integration:** `.github/workflows/validate-rules.yml` validates on push/PR.

## Phase 8: OCI Resource Manager Stack ✅
- [x] **Terraform Stack:** Full ORM-compatible stack in `stack/` directory for one-click deployment.
- [x] **ORM Schema:** `schema.yaml` renders variable form UI in OCI Console (compartment picker, toggles for log sources/dashboards/test data).
- [x] **Infrastructure as Code:** Log Analytics log group, 4 streams, 4 SCH connectors, IAM policies — all managed declaratively.
- [x] **Python Provisioners:** `null_resource` blocks call existing scripts (`setup_log_sources.py`, `deploy_dashboard.py`, `ingest_test_data.py`) with proper dependency ordering.
- [x] **Build Script:** `build_stack.sh` produces `soc-detection-stack.zip` ready for ORM upload.
- [x] **Validation:** `terraform init` + `terraform validate` pass cleanly.

## Rule Organization
- **Format:** Sigma (YAML) as the source of truth.
- **Output:** OCL queries (JSON format).
- **Structure:**
    ```
    rules/
      cloud/
        oci/
          audit_events/
          cloud_guard/
        aws/
        gcp/
      linux/
        suspicious_binaries/
      windows/
        process_creation/
    ```

## Phase 7: STIG Compliance & Advanced Attack Patterns
- [x] **OCI STIG Rules:** 15 new rules with STIG control mappings (IA-2, SC-7, AU-11, etc.)
- [x] **Advanced Linux Rules:** Container escape, LD_PRELOAD hijack, kernel module from /tmp, passwd modification, ptrace injection, network redirect.
- [x] **Advanced Windows Rules:** Shadow copy deletion (ransomware), AMSI bypass, WMI persistence, registry run key, DLL side-loading, bcdedit recovery disable.
- [x] **Enhanced Converter:** List support for startswith/endswith, STIG metadata, condition tokenizer, validation and stats modes.
- [x] **STIG Compliance Dashboard:** New dedicated dashboard with 14 compliance widgets.
- [x] **Test Data Expansion:** 360 events (up from 279) covering all 140 rules.
- [x] **Multicloud Integration:** Export script for ~/dev/multicloudoperations with shared manifest.

## Phase 9: Canonical Inventory Reconciliation ✅
- [x] **Canonical Source Rule Count:** Verified 454 YAML rules on disk.
- [x] **Canonical Generated Query Count:** Verified 446 base detection queries, 40 hunting queries, and 20 app/APM queries.
- [x] **Documentation Reconciliation:** Updated README/PLAN to distinguish source rules from generated query assets.
- [x] **Catalog Contract Hardening:** Extended `queries/catalog.json` generation with inventory metadata for downstream consumers.

## Success Criteria
1.  100+ high-quality detection rules implemented. (Achieved: 454 source YAML rules)
2.  Functional conversion script from Sigma to OCL. (Achieved: Advanced version with STIG metadata and catalog generation)
3.  Comprehensive documentation. (Achieved, with canonical inventory reconciled to disk state)
4.  Functional SOC Dashboards in OCI. (Achieved: 16 dashboards, 264 saved searches deployed; 263/264 widgets HIT against live OCI Log Analytics)
5.  STIG compliance mapping for OCI rules. (Achieved: 24 generated detection queries carry STIG mappings, spanning 12 controls)
6.  Cross-project integration with multicloudoperations. (Achieved: export script + manifest + canonical CSP schema builders ported to `scripts/schemas/`)
7.  One-click deployment via OCI Resource Manager. (Achieved: Terraform stack with ORM schema)
8.  Live dashboard health verifier. (Achieved: `scripts/verify_deployed_dashboards.py` runs every embedded saved search against live OCI LA; `scripts/daily_health_check.py` chains the inventory + smoke + verifier with JSON report under `docs/health/`)

## Phase 10: Canonical CSP Schema Builders (2026-04-28) ✅

- [x] **Schema Module Port:** Brought `oci_audit_schema`, `windows_audit_schema`, `azure_audit_schema`, `gcp_audit_schema` from `multicloudoperations/shared/` into `scripts/schemas/`.
- [x] **Refactor Generators:** `oci_audit_event`, `winsec_event`, `sysmon_op_event` now delegate to the canonical builders so synthetic logs match real CSP envelopes verified against live API output.
- [x] **Schema Fidelity Tests:** Ported 4 schema fidelity test modules; pinned 35 new tests against the real CloudEvents v0.1, EVTX, Azure Monitor, and GCP LogEntry shapes.
- [x] **Dual-Keyed Records:** Every record carries native CSP envelope at top level + parallel OCI LA display-name columns so detection queries match through either path.

## Phase 11: Operational Toolkit and Health Loop (2026-04-28 → 2026-05-04) ✅

- [x] **Inventory Tool:** `scripts/inventory_dashboards.py` — census + classification of dashboards, flags missing/duplicate/legacy/broken instances.
- [x] **Cleanup Tool:** `scripts/cleanup_soc_dashboards.py` — aggressive deletion of SOC dashboards + saved searches by name prefix (catches drift from prior iterations).
- [x] **Smoke Test (Targeted):** `scripts/smoke_test_bluelight.py` — 17 BLUELIGHT widgets + kill-chain hunt against live OCI LA.
- [x] **Smoke Test (Full):** `scripts/smoke_test_all_queries.py` — walks every `queries/**.json` and runs the raw filter half against live OCI LA.
- [x] **Verifier:** `scripts/verify_deployed_dashboards.py` — fetches every deployed dashboard, runs the actually-stored saved-search `queryString` against live OCI LA, reports per-dashboard HIT/MISS/ERROR.
- [x] **Daily Wrapper:** `scripts/daily_health_check.py` — chains inventory + smoke + verifier with JSON report under `docs/health/`.
- [x] **Cloud Guard Routing Fix:** Reordered `SOURCE_CANDIDATE_GROUPS["cloud_guard"]` so test data lands in `SOC Cloud Guard Logs` whose parser extracts `Problem Name`. Closed all 12 Cloud Guard widget MISSes.
- [x] **Linux Crontab Routing Fix:** Reordered `SOURCE_CANDIDATE_GROUPS["linux_secure"]` so test data lands in `SOC Linux Syslog Logs` whose parser extracts `Command Line`.
- [x] **OCI Status Dual-Form:** Source rules now use Sigma list syntax `status: [Success, '200']` so detections match both operator-friendly and HTTP-code parser projections.
- [x] **OCI LA SEARCH-LIKE Caveats:** Documented in `docs/ARCHITECTURE.md` — String-typed field quoting, multi-word LIKE wildcard tokenisation, `Original Log Content` truncation window, parser projection vs filter divergence.
- [x] **Monitoring Runbook:** `docs/MONITORING.md` — daily check, cleanup → redeploy round-trip, Cloud Guard data-path note, sample cron line.
- [x] **Codex Stop-Time Review Gate:** Enabled via `node …/codex-companion.mjs setup --json --enable-review-gate` so every stop runs an independent code review.

## Phase 12: Forward Roadmap (Next 4–6 Weeks)

Sorted by impact / cost ratio.

### 12.1 Sigma converter — backslash escape fix (1–2 days)

**Problem.** `convert_sigma.py` emits LAQL like `'Pipe Name' = '\interprocess_'` (one literal backslash) for Windows pipe-name rules. OCI LA's SEARCH parser rejects this with `Unexpected input for SEARCH: '\interprocess_'`. Affected detection queries (Cobalt Strike, Mimikatz pipes) currently exist as hand-edited files that must not be regenerated.

**Plan.**
- [ ] Add a backslash-doubling pass in `scripts/convert_sigma.py` for any value containing literal `\` so the generated LAQL has properly-escaped patterns.
- [ ] Add a fallback wildcard heuristic for `Pipe Name` rules: `*pattern*` rather than exact-match.
- [ ] Add a `do_not_overwrite: true` rule annotation respected by the converter so hand-edited query files are protected even when their YAML source runs through a regeneration sweep.
- [ ] Regenerate all queries cleanly and re-verify with `verify_deployed_dashboards.py` to confirm no widget regresses.

### 12.2 Sweep dual-Status across remaining OCI rules (2–3 hours)

- [ ] Audit every `rules/cloud/oci/*.yaml` rule that filters on `status: Success` (12 rules currently).
- [ ] Convert each to the list form `status: [Success, '200']` so the detection survives both SOC custom and native OCI Audit parser projections.
- [ ] Regenerate queries via `convert_sigma.py`; redeploy widgets with surgical `update_management_saved_search` patches (avoids the slow full-redeploy path).

### 12.3 Provision Fusion Apps source or strip the widget (1 hour)

The single remaining MISS — `Hunt: OCI IAM + Fusion Correlation` — needs `Fusion Apps: Sign In - Sign Out Activity Logs` and `Fusion Apps: ESS Audit Logs` log sources. Two options:

- [ ] **Option A:** add a Fusion Apps test-data emitter + parser, ingest, and verify the correlation widget HITs.
- [ ] **Option B:** drop the Fusion correlation widget from `SOC: Threat Hunting Dashboard` to bring widget health to **264 / 264 (100 %)** in tenancies that do not run Fusion.

### 12.4 Schedule the daily health check (1 hour)

- [ ] Add a recurring routine that runs `scripts/daily_health_check.py --lookback 14d` on a weekly cadence.
- [ ] Diff the JSON report against the previous run; surface widget regressions before deploy.
- [ ] Optionally publish the banner to a Slack channel via `slack:draft-announcement` skill.

### 12.5 Sigma converter — `condition` operator coverage (3–5 days)

Minor backlog from earlier phases:

- [ ] Implement automated validation of generated OCL syntax (Phase 2 leftover).
- [ ] Audit converter coverage for advanced Sigma `condition` operators: `1 of`, `all of`, `near`, count modifiers.
- [ ] Add a per-rule `--validate` mode that round-trips the generated query through OCI LA syntax check.

### 12.6 Field dictionary — `DET-MISS-002` (2 days)

- [ ] Generate a machine-readable log-source field dictionary from `scripts/setup_log_sources.py:*_FIELD_MAPPINGS` so downstream UIs (LoganSecurityDashboardv0) know which display names exist on which sources.
- [ ] Cross-reference each detection query's field dependencies against the dictionary; flag queries that reference unmapped fields before deploy.

### 12.7 Test-data schema validation (3 days)

- [ ] Add `scripts/validate_synthetic_logs.py` checks for every `test_data/*.jsonl` against `config/synthetic_log_contracts.json`.
- [ ] Run the validator inside CI so generator drift breaks the build.
- [ ] Pin schema version with the same `do_not_overwrite` discipline as the canonical schema builders in `scripts/schemas/`.

### 12.8 Expand live verification beyond Caldera discovery (2 weeks)

- [ ] Caldera operations covering: credential-access, lateral-movement, collection, and exfiltration.
- [ ] Per-operation verification queries layered on `scripts/verify_caldera_detections.py`.
- [ ] Demo data deterministic enough that `daily_health_check.py` confirms each kill-chain stage independently.
