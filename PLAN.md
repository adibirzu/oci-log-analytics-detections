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
- [ ] **Continuous Expansion:** Target 200+ rules by adapting AWS/GCP rules from SigmaHQ.

## Phase 4: Dashboard & Visualization ✅
- [x] **Dashboard Scripting:** `scripts/generate_dashboard_config.py` created.
- [x] **OCI Deployment Tool:** `scripts/deploy_dashboard.py` fully functional.
- [x] **Test Data:** `scripts/ingest_test_data.py` created for simulation.
- [x] **Dashboard Completion:** Successfully deployed the SOC Security Dashboard with 6 core widgets.

## Phase 5: OCI Log Analytics Deployment ✅
- [x] **Log Source Mapping Fix:** Corrected Cloud Guard, Linux, and Windows log source mappings.
- [x] **UUID Fix:** Replaced all placeholder UUIDs with proper UUIDs.
- [x] **Query Regeneration:** All 113 queries regenerated with correct mappings.
- [x] **Saved Searches:** 58 saved searches deployed to OCI Log Analytics.
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

## Success Criteria
1.  100+ high-quality detection rules implemented. (Achieved: 140)
2.  Functional conversion script from Sigma to OCL. (Achieved: Advanced version with STIG metadata)
3.  Comprehensive documentation. (Achieved)
4.  Functional SOC Dashboards in OCI. (Achieved: 6 dashboards, 76 saved searches)
5.  STIG compliance mapping for OCI rules. (Achieved: 15 rules with DoD STIG IDs)
6.  Cross-project integration with multicloudoperations. (Achieved: export script + manifest)
7.  One-click deployment via OCI Resource Manager. (Achieved: Terraform stack with ORM schema)
