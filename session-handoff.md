## 2026-10-27 — PR 19 CI receipt repair

- Inspected actual failed-step logs from CI run `40423555636`, Webapp CI `40423555574`, and Sentinel Converter `40423555598`. These are executed failures, not billing-only exceptions.
- Reproduced both reported Python failures. The only stale artifact hash in the Splunk local example was `stack/provisioners.tf`, changed by this PR. Regenerated `docs/health/splunk-parallel-local-evidence.example.json` through `python3 scripts/release_checklist.py --refresh-splunk-parallel-example`; bootstrap and normal verification passed all 13 offline gates and five exporter scenarios, external calls empty, provider validation not run. No generator, tests, scanners, canonical catalogs, IOCs, or IDs changed.
- Retained failing gates outside the PR diff: Sentinel has 590 `parser_schema_hash_mismatch` errors, reproduced via `sentinel_drift_check.build_drift_report(baseline_ref="f44ee1be0b16a0caa9f79f14b7c615f8f10c30bd")`. Promoted artifacts, dictionary, report, and checker are unchanged from that base. Webapp CI passed typecheck/lint/unit/build and 25 e2e tests but failed four artifacts API contracts: its unchanged loader emits `forgeDetectionCatalog`, which the unchanged response enum rejects with ZodError/HTTP 500. Relevant route, schema, loader, and e2e tests are unchanged from base. Neither gate is waived or accepted; owning repair remains required.
- Locally verified: `python3 scripts/scan_sensitive_values.py` passed; `git diff --check` passed. `python3 -m pytest scripts/ -q` completed with 1503 passed, 5 skipped, 65 subtests passed and two missing-fixture failures (ignored `test_data/` was absent). After running the exact CI prerequisites `python3 scripts/generate_test_logs.py --days 1` and `python3 scripts/generate_geo_health_logs.py --duration 60 --interval 5`, reran `python3 -m pytest -q scripts/test_ingest_manifest.py scripts/test_check_inventory_drift.py::TestReleaseChecklistEvidence::test_splunk_parallel_offline_stage_returns_classified_structured_evidence scripts/test_splunk_documentation.py::test_contributor_release_guidance_links_classified_local_evidence_example`: 11 passed, 2 subtests passed. Removed only the unrelated catalog timestamp side effect produced by the suite; final tracked diff is the generated receipt plus this handoff. Full archive scan limitations and all provider/release gates remain as previously recorded. Outer executor owns subsequent phases; no push or pipeline control performed.

## 2026-10-27 — PR 19 CI repair (local evidence)

- Inspected GitHub runs `40422090746` (CI), `40422090668` (Webapp CI), and `40422090763` (Sentinel Converter). Actual steps failed; no billing-only exception applies.
- Added the missing `jsonschema>=4.23` development dependency required by the Splunk schema tests. Replaced the stale 163-hunt assertion with observable full-list identity/count parity against the validated bundle; the old assertion reproduced `171 != 163`. Canonical query artifacts and IDs are unchanged. During rebase, upstream canonical source-path membership, uniqueness, omission/duplication negatives, tamper rejection and filtered-list checks were retained; the historical bundle-only count comparison was superseded.
- Locally verified: `PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -p no:cacheprovider scripts/test_splunk_detection_registry.py scripts/test_splunk_evidence_e2e.py scripts/test_splunk_evidence_exporter.py scripts/test_sentinel_drift_check.py -q` — 126 passed. From `webapp/`, `node --experimental-strip-types --experimental-test-coverage --test-coverage-branches=80 --test-coverage-functions=80 --test-coverage-lines=80 --test tests/unit/*.test.ts` — 10 passed; lines/functions 100%, branches 88.51%. Local Node 26.8.1 and preinstalled Zod 3.25.76 differ from CI Node 22 / locked Zod 3.24.1; temporary dependency symlink removed, no package installation performed.
- Retained blocker: executable `sentinel_drift_check.build_drift_report(baseline_ref='f44ee1b')` reports 590 `parser_schema_hash_mismatch` errors. Promoted files, dictionary, conversion report and checker are byte-identical to base `f44ee1b`. No hashes were restamped and no gate was weakened. Parser reconciliation requires separate owning review; CI is not accepted.
- Full webapp build/e2e, subsequent release checks, provider and release acceptance remain open. Outer executor owns the next CI run and all other phases.

## 2026-10-27 Forge foundation documentation and lint phase

- Updated owner guidance: contributor-only example regeneration and actual Sentinel failure diagnostics in `CONTRIBUTING.md`; local parser compatibility in `docs/SENTINEL_CONVERSION.md`, linked from the integration schema; schema-backed artifact status keys in `docs/WEBAPP.md`; canonical hunting membership in `docs/THREAT_HUNTING_INTEGRATIONS.md`. No generated receipt or functional source changed in this phase.
- Locally verified static checks: compile-only syntax for all 44 changed Python files; `python3.11 scripts/check_module_size.py` (zero violations); `git diff --check`; ESLint on the four changed TypeScript files; TypeScript `--noEmit --incremental false`. Existing borrowed dependencies reported ESLint 9.39.4 and TypeScript 5.0.2. ESLint required the installed pnpm shared-plugin directory in task-local `NODE_PATH`; the temporary `webapp/node_modules` link was removed. No installs or global changes.
- Code-backed review follow-up R3 removed the two unused dashboard pattern copies from cases B/C; the consumed rule remains in cases A. Test execution and collection parity were not rerun during this document phase. Earlier test counts and receipt results below remain historical; outer validation, independent review, CI, provider and release gates retain their owners.

## 2026-10-27 Forge foundation review fixes

- Findings R1 and R2 confirmed: relocated domain/handler tests asserted source syntax rather than runtime boundaries. Their existing pytest IDs now execute isolated domain imports and real handler/service exports through injected factories. Shared runtime traps reject SDK imports (including `from oci import client`), cached SDK construction, credential-file reads, network access, and subprocess attempts; domain execution also rejects environment and implicit-clock dependencies. Factory negatives fail before queries, delivery, or checkpoint writes. Both HEC and Streaming paths assert construction arguments, canonical query routing, delivery, and checkpoint behavior.
- Owned files: `scripts/splunk_exporter_cases_common.py`, `scripts/splunk_exporter_domain_cases.py`, `scripts/splunk_exporter_handler_cases.py`, this handoff, and the generated `docs/health/splunk-parallel-local-evidence.example.json`. Production APIs, CLI, query bytes, scanner rules, and the 800-line gate remain unchanged. Only the two reported test bodies intentionally depart from legacy relocation parity.
- Locally verified: `python -m pytest -q -p no:cacheprovider scripts/test_splunk_evidence_exporter.py` passed 72 tests in 6.96 seconds. Baseline/current pytest collection comparison preserved all 102 exporter/dashboard node IDs exactly once. Python 3.11.16 used existing dependencies, disabled dotenv/bytecode/plugin autoload, and OS denial of external network and operator credential reads; no installs or global configuration changes.
- Generated only through `python scripts/release_checklist.py --refresh-splunk-parallel-example`: bootstrap and final offline stages passed; the refreshed example records 13/13 gates, 5/5 scenarios, 97/97 independently recomputed artifact hashes, `external_calls: []`, and `provider_validation: not_run`. The unchanged `scripts/check_module_size.py` gate passed with zero violations. These are local source/generation checks, not deployed parser acceptance.
- Remaining gates: outer executor owns integrated tests, lint, independent final review, push/PR/CI and release acceptance after this material test change. Earlier integrated counts are historical, not rerun here. The reported raw Gitleaks diagnostic remains failed with four classified findings; it was not rerun or waived. No provider actions, promotion, deployment, credential use, public artifacts, or PR19 integration occurred in this review phase.

## 2026-10-27 ORM executable package closure

Base `f44ee1be0b16a0caa9f79f14b7c615f8f10c30bd`. The
[package contract](docs/DEPLOYMENT.md#package-source-inventory-and-executable-closure)
owns behavior, local verification, archive-scan triage and remaining gates;
KB-001 indexes the repair. Coordinator independently passed 42 tests plus 24
subtests in 21.57 seconds under all-network/operator-credential denial. All five
implementation/test hashes match the reviewed freeze. Independent review's
JSON variable-file finding is resolved; scoped lint/shell checks and changed-source
privacy checks pass. No generated archive is publicly uploaded. Source publication
gates, full application, OCI-DEMO admission, provider and release acceptance remain
open; dirty root instruction/context edits are preserved.

## 2026-10-21 OCI4CCA ecosystem contract synchronization

- Last Updated: 2026-10-21. Owner: cross-project ecosystem coordinator.
- Current Objective: portable 13-project relationship matrix and shared baseline synchronization; clean-main reconciliation.
- Files: managed `oci4cca-ecosystem-matrix` blocks in root AGENTS.md and existing CLAUDE.md/GEMINI.md; `docs/OCI4CCA_ECOSYSTEM.md`. ObserveAI/Guardian also receive their declared baseline catalog copies. Existing instruction text is preserved.
- Verification Evidence: eight offline sync contract tests pass; generator preserves owner text, rejects malformed markers and symlink targets. Catalog copies are byte-identical: 200 entries, five unique rule queries, provider validation unverified. OKE discovery found 16 pods Running/Ready in eight requested namespaces. Authenticated in-pod requests: Guacamole sync HTTP 200 (12 configured targets), detection ecosystem summary HTTP 200, Compliance interconnect refresh HTTP 200 (health only). These checks do not establish tenant evidence replication, framework evaluation or release acceptance.
- ConfigMaps/mounts: none created or patched by this packet; existing deployment mounts preserved.
- Blockers: prior dirty application work, existing branch history, redaction and authoritative tests require their owner gates before broad merge. Scanner checkout resolves Git to its parent dev directory and cannot be independently committed as a Scanner repository. No remote push authorized/performed.
- Recommended Next Step: use the canonical OCI-DEMO generator check for managed artifacts; reconcile only redaction-clean reviewed changes into local main while preserving every unrelated source/index change. Record final branch hashes and individual holds in OCI-DEMO session handoff.


## 2026-10-21 Agent 17b authorized local application consolidation

- Last Updated: 2026-10-21. Owner: consolidation coordinator.
- Files: authorized pending application, UI, backend, test, deployment-source and documentation candidates; exact scoped diff retained in Git. Runtime env/data, databases, browser artifacts, generated site output and unrelated harness installs excluded and preserved.
- Verification Evidence: staged full-file identifier redaction and Python syntax checks; focused offline verification results recorded in the OCI-DEMO consolidation report. Original index/diff recovery patches retained privately.
- ConfigMaps and mounts: no live changes in this packet. Live routes/screenshots: not refreshed; previous receipts remain historical. No push or deployment.
- Blockers: full application/release acceptance is not established; scanner semantic reconciliation requires approval after automatic review rejection. Local merge is source consolidation only.
- Recommended Next Step: inspect local main diff and outstanding test/environment failures before any separately authorized publication or deployment.
