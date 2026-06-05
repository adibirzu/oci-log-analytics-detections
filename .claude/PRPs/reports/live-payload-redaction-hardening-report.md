# Implementation Report: Live OCI Payload Redaction Hardening

## Summary
Implemented a centralized redaction layer (`scripts/redaction.py`) and applied it at every site that serializes a live OCI error to disk or CI evidence. Fixed the `scan_sensitive_values.py` false negative that let a tenancy namespace + request IDs reach a committed public report, promoted the scanner to an always-on CI gate, and corrected the stale hunting path in `validate-rules.yml`. Shipped on branch `fix/live-payload-redaction` (PR #5).

## Assessment vs Reality
| Metric | Predicted (Plan) | Actual |
|---|---|---|
| Complexity | Medium | Medium |
| Confidence | 8/10 | Accurate — single-pass on the planned sites; a second sweep found additional write sites |
| Files Changed | ~10 | 13 (1 new module, 1 new test, 9 updated, 1 report scrub, 1 plan) |

## Tasks Completed
| # | Task | Status | Notes |
|---|---|---|---|
| 1 | Centralized redaction module | Complete | `redaction.py` (`redact_text` / `redact_live_payload`), structural patterns only |
| 2 | Apply redaction at write sites | Complete | **Deviated**: plan named 3 sites; a sweep found 8 (verify_deployed ×4, deploy_dashboard, query_audit, demo_readiness, setup_streaming_pipeline) |
| 3 | Fix the scanner | Complete | **Deviated**: dropped the over-broad `oci_endpoint` scanner check (flagged public service hosts); kept it in redaction only |
| 4 | Tests | Complete | `test_redaction.py` (6) + dict-style live-payload regression in the scanner suite |
| 5 | CI gates | Complete | scanner always-on in `ci.yml`; `validate-rules.yml` → `queries/hunting/**` |
| 6 | Scrub committed report | Complete | `queries/sentinel_conversion_report.json` redacted; `git grep` empty |

## Validation Results
| Level | Status | Notes |
|---|---|---|
| Static / imports | Pass | All 9 edited scripts import cleanly |
| Unit Tests | Pass | 482 passed, 5 skipped, 21 subtests |
| Sensitive scan | Pass | `ok: true`, 0 findings |
| convert_sigma --validate | Pass | 678 queries, 0 warnings |
| Workflow YAML | Pass | all parse |
| CI (PR #5) | Pass | Local release gates, drift, validate, GitGuardian all green |

## Files Changed
| File | Action |
|---|---|
| `scripts/redaction.py` | CREATED |
| `scripts/test_redaction.py` | CREATED |
| `scripts/convert_sentinel_kql.py` | UPDATED (import + redact `live_validation_error`) |
| `scripts/parse_validate_all_queries.py` | UPDATED (redact error + query) |
| `scripts/verify_deployed_dashboards.py` | UPDATED (4 error sinks) |
| `scripts/deploy_dashboard.py` | UPDATED (query-validation error) |
| `scripts/query_audit.py` | UPDATED (audit error) |
| `scripts/demo_readiness.py` | UPDATED (readiness error) |
| `scripts/setup_streaming_pipeline.py` | UPDATED (connector ServiceError messages) |
| `scripts/scan_sensitive_values.py` | UPDATED (dict-style opc regex, LA-namespace pattern, narrowed queries/ exemption) |
| `scripts/test_scan_sensitive_values.py` | UPDATED (dict-style regression test) |
| `.github/workflows/ci.yml` | UPDATED (scanner gate) |
| `.github/workflows/validate-rules.yml` | UPDATED (queries/hunting/**) |
| `queries/sentinel_conversion_report.json` | UPDATED (scrubbed) |

## Deviations from Plan
1. **More write sites than planned** — the plan named 3 raw-error sinks; a comprehensive `grep` found 8. Codex's stop-review caught the dashboard ones I initially missed, prompting the full sweep. All now redacted.
2. **Dropped `oci_endpoint` from the scanner** — it flagged generic public OCI service hostnames (false positives). The sensitive part is the namespace-in-path, covered by `la_namespace`. Endpoint redaction is retained in `redaction.py` as defense-in-depth.
3. **Redacted the plan doc itself** — the plan used the real namespace as the literal example, which `git grep` flagged during validation. Replaced with `<LA_NAMESPACE>`. The scanner cannot structurally detect a *bare* namespace token without a hardcoded value list (which would itself leak), so redaction-at-authoring is the mitigation.

## Issues Encountered
- A self-test in the first `redaction.py` hardcoded the real namespace (re-leak); caught by the hardened scanner, replaced with the unit test using fake values + `# scanner-fixture` markers.
- `deploy_dashboard.py` redacted the *console* error display but stored the *raw* value in the result dict — fixed at the source.

## Tests Written
| Test File | Tests | Coverage |
|---|---|---|
| `scripts/test_redaction.py` | 6 | namespace/endpoint/opc/OCID/recursion/passthrough |
| `scripts/test_scan_sensitive_values.py` | +1 | dict-style live-payload under queries/ is flagged |

## Next Steps
- [ ] Merge PR #5 (`/prp-pr` already satisfied — PR exists and is green)
- [ ] Operator decision: public-history purge of the pre-existing namespace (`git filter-repo --replace-text` + force-push)
- [ ] Future: P2 Sentinel converter backlog, P3 dashboard health/viz, P4 webapp CI tests (captured in the plan's roadmap)
