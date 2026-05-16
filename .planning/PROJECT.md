# OCI Log Analytics Detections

## What This Is

This is a brownfield detection-content and deployment repository for Oracle Cloud Infrastructure Log Analytics. It converts Sigma/YAML and live-validated Microsoft Sentinel content into OCI Log Analytics Query Language, maintains curated hunting and app analytics, generates synthetic demo data, and deploys OCI Management Dashboards for SOC demonstrations and operator workflows.

The repo is the canonical detection and dashboard artifact producer for companion tools such as `LoganSecurityDashboardv0` and `mcp-oci-logan-server`; those tools should consume generated artifacts from this repo rather than duplicate generation logic.

## Core Value

Every committed detection, query, dashboard, parser mapping, and generated artifact must remain deployable and verifiable against OCI Log Analytics without leaking tenant-specific data.

## Current Milestone: v2.0 Sentinel KQL Parity to Logan QL

**Goal:** Close the conversion gap between Microsoft Sentinel KQL and OCI Log Analytics QL across capabilities, field mappings, and coverage so the converter can move promoted Sentinel content from 8 toward thousands of queries while keeping live OCI parser validation as the only promotion gate.

**Target features:**
- KQL operator/expression parity in the Sentinel conversion workflow (`parse`, `extend`, `column_ifexists`, `parse_command_line`, `iff`, `countof`, and other recurring unsupported expressions).
- Field and table mapping completeness in `config/sentinel_oci_mapping.yaml` for unmapped Sentinel fields (Subject*, InitiatingProcess*, EventData, MailboxOwner*, OfficeWorkload, OrganizationName, etc.).
- Promoted coverage expansion against the 4452-candidate Sentinel corpus, with promotion still gated on live OCI parser validation.
- Backlog prioritization helper that ranks unmapped Sentinel rules by MITRE value and conversion complexity.
- Conversion drift detector that flags promoted Sentinel queries that regress after mapping or parser changes.
- CI workflow running converter dry-run, catalog regeneration, and release-checklist local gates on every PR.

**Phase numbering:** continues from v1.0 — starts at Phase 6.

## Requirements

### Validated

- [x] Sigma/YAML authoring layer exists under `rules/**` with 454 source rules and quality audit coverage.
- [x] OCI query artifacts are generated and cataloged under `queries/**`, with `queries/catalog.json` as the canonical machine-readable inventory.
- [x] Microsoft Sentinel conversion workflow promotes only live OCI parser-passing queries into `queries/sentinel/**`.
- [x] Dashboard inventory is generated from `scripts/deploy_dashboard.py` and currently covers 27 dashboards and 450 widgets.
- [x] Synthetic log generation and parser/source setup support SOC security, app/APM, WAF, VCN, firewall, and multicloud-health demo paths.
- [x] Local tests currently pass with `244 passed, 5 skipped, 2 subtests passed`.

### Active

- [ ] Keep GSD planning state current for every substantial development phase.
- [ ] Maintain zero rule-quality audit findings across source rules and generated Sigma queries.
- [ ] Keep catalog, dashboard inventory, manifest, field dictionary, detection-rule specs, and docs synchronized after content changes.
- [ ] Improve Sentinel conversion coverage by triaging local validation failures, field/table mapping gaps, and live validation failures.
- [ ] Harden release evidence so local gates and optional live verification can be run consistently before demos or deployments.
- [ ] Preserve the Octo APM workshop bundle contract for downstream deployment from `octo-apm-demo`.
- [ ] Drive Sentinel KQL parity (capabilities, mappings, coverage) toward the v2.0 milestone goal while keeping live OCI parser validation as the only promotion gate.

### Out of Scope

- Building the companion UI/API inside this repo - sibling projects consume this repo's generated artifacts.
- Hand-authoring promoted Sentinel JSON under `queries/sentinel/**` - use the converter and live-validation workflow.
- Hand-authoring content in `logandetectionqueries/` or `logandetectionrules/` - they are legacy empty directories.
- Committing public IPs, OCIDs, tenancy names, credentials, API tokens, or profile-specific values.
- Creating OCI alarms or Terraform applies by default from detection-rule specs - specs remain metadata/export artifacts unless explicitly requested.

## Context

- Primary language is Python. The repo uses stdlib `unittest` plus pytest-compatible tests under `scripts/test_*.py`.
- Runtime dependencies are minimal: `oci`, `PyYAML`, and `python-dotenv` in `requirements.txt`.
- Source content surfaces:
  - `rules/**` - source Sigma/YAML rules.
  - `queries/*.json` and generated `queries/apps/*.json` - Sigma-derived OCI saved-search queries.
  - `queries/sentinel/*.json` - Microsoft Sentinel conversions that passed live OCI parser validation.
  - `queries/apps/*.json` and `queries/hunting/*.json` - curated app/hunting analytics.
- Generated contracts:
  - `queries/catalog.json`
  - `queries/dashboard_inventory.json`
  - `queries/content_candidates.json`
  - `queries/log_source_field_dictionary.json`
  - `queries/detection_rule_specs.json`
  - `queries/octo_apm_workshop_bundle.json`
  - `queries/sentinel_conversion_report.json`
  - `queries/manifest.json`
  - `test_data/manifest.json`
- Existing project-specific Claude guidance lives in `CLAUDE.md`; Codex should read `AGENTS.md` and `.planning/**` going forward.

## Constraints

- **OCI Log Analytics compatibility**: Generated OCL must avoid unsupported functions and parser-invalid field usage because deployment validation blocks dashboard import.
- **Source-of-truth discipline**: `rules/**` and converter configs drive generated source-derived queries; generated artifacts should not be patched manually except for curated app/hunting surfaces.
- **Live validation boundary**: Sentinel promotion requires live OCI parser validation; failed candidates stay in `queries/sentinel_conversion_report.json`.
- **Demo safety**: Committed artifacts must use placeholders and redaction for tenant-specific values.
- **Dirty worktree reality**: This repo often has broad generated changes. Future agents must isolate their own edits and avoid reverting unrelated work.
- **Dashboard layout**: Widget placement must use `scripts/deploy_dashboard.py:resolve_widget_layout()` and 12-column metadata; do not hand-author imported row/column placement.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Use `.planning/` as the GSD project state root | Enables GSD phase planning, review, verification, and session continuity for this brownfield repo | Pending |
| Treat `queries/catalog.json` as canonical inventory | Avoids stale hand-maintained counts and aligns README/STATUS with generated content | Good |
| Keep companion UI/API out of this repo | Prevents duplicate query/dashboard generation and preserves a clean artifact-producer boundary | Good |
| Promote Sentinel content only after live OCI parser validation | Prevents parser-invalid KQL conversions from becoming dashboard or saved-search assets | Good |
| Keep GSD `commit_docs` enabled but do not auto-commit in dirty worktrees | Planning docs should be tracked, but commits must not include unrelated generated changes | Pending |

## GSD Usage

- Start phase work with `$gsd-plan-phase <phase-number>`.
- Use `$gsd-audit-fix` for audit-to-fix loops when there are concrete findings.
- Use `$gsd-map-codebase` after major structural changes to refresh `.planning/codebase/**`.
- Keep `.planning/STATE.md` updated after major sessions and phase transitions.

---
*Last updated: 2026-05-14 after GSD brownfield initialization*
