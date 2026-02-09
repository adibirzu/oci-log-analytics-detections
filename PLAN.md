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

## Phase 5: Advanced Features & Documentation 🔄
- [x] **Basic Documentation:** `README.md`, `CONTRIBUTING.md`, `STATUS.md`.
- [ ] **Remote Rule Sync:** Script to fetch latest rules from `SigmaHQ/sigma` repository.
- [ ] **Rule Catalog:** Auto-generate a searchable markdown or HTML catalog of all rules.
- [ ] **CI/CD Integration:** GitHub Actions to validate rules and auto-generate queries on push.

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

## Success Criteria
1.  100+ high-quality detection rules implemented. (Achieved: 100)
2.  Functional conversion script from Sigma to OCL. (Achieved: Advanced version)
3.  Comprehensive documentation. (In Progress)
4.  Functional SOC Dashboard in OCI. (Achieved: SOC Security Dashboard deployed)
