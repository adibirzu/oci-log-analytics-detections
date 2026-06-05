# Plan: Live OCI Payload Redaction Hardening

## Summary
Introduce a single, reusable redaction layer for OCI live-validation payloads and apply it everywhere a live error or query is written to disk or uploaded as CI evidence. Close the `scan_sensitive_values.py` false negative that let a tenancy namespace + request IDs reach a committed, public report, and promote the scanner to an always-on CI gate.

## User Story
As a maintainer of a public detection-content repo,
I want every generated report and CI artifact to be free of tenancy-specific OCI metadata,
So that promoting/publishing detections never leaks namespaces, request IDs, or endpoints.

## Problem → Solution
`queries/sentinel_conversion_report.json` ships raw OCI SDK error dicts containing `<LA_NAMESPACE>` (LA namespace), `opc-request-id`s, and `request_endpoint` URLs — and the scanner reports `ok: true` because it exempts `queries/` and its request-id regex misses dict-style payloads → **Centralize redaction, apply it at every live-payload write site, fix + un-exempt the scanner, and gate it in CI.**

## Metadata
- **Complexity**: Medium
- **Source PRD**: N/A (from `/codex:rescue` review, 2026-06-05)
- **PRD Phase**: N/A
- **Estimated Files**: ~10 (1 new module, 1 new test, ~5 updates, 2 workflow updates, 1 committed-report scrub)

---

## UX Design
Internal/operational change — no user-facing UX. CI gains a visible "sensitive-value scan" step; generated reports show `<LA_NAMESPACE>` / `<OPC_REQUEST_ID>` placeholders instead of real values.

### Interaction Changes
| Touchpoint | Before | After |
|---|---|---|
| `sentinel_conversion_report.json` `live_validation_error` | raw OCI dict w/ namespace + request-id | redacted dict (`<LA_NAMESPACE>`, `<OPC_REQUEST_ID>`, `<OCI_ENDPOINT>`) |
| `docs/health/parse-validate-all.json` | raw `exc.message` + query | redacted error |
| CI (`ci.yml`) | scanner only in `release_checklist.py` | scanner is an always-on gate |
| `git grep <LA_NAMESPACE>` | 1 hit (committed) | 0 hits |

---

## Mandatory Reading
| Priority | File | Lines | Why |
|---|---|---|---|
| P0 | `scripts/scan_sensitive_values.py` | 52–62, 150–172, 222–330 | Pattern set, allow-markers, the `queries/` exemption to fix |
| P0 | `scripts/convert_sentinel_kql.py` | ~462–478 | Primary leak write site (`live_validation_error`) |
| P0 | `scripts/parse_validate_all_queries.py` | ~82–90 | Writes raw `exc.message` + `query` |
| P0 | `scripts/verify_deployed_dashboards.py` | ~88–94, ~304 | Returns/serializes `str(exc)` |
| P1 | `scripts/test_scan_sensitive_values.py` | 19–160 | unittest structure to mirror (`test_detects_*` / `test_allows_*`) |
| P1 | `.github/workflows/ci.yml` | 35–48 | Where to add the scanner gate |
| P1 | `.github/workflows/validate-rules.yml` | 7 | `hunting/**` → `queries/hunting/**` (finding #4) |
| P2 | `~/.claude/CLAUDE.md` (global) "Redaction Convention" | — | Canonical placeholder tokens |

## External Documentation
No external research needed — uses established internal patterns (stdlib `re`, `unittest`, existing scanner regexes).

---

## Patterns to Mirror

### SCANNER_REGEX
```python
# SOURCE: scripts/scan_sensitive_values.py:52-62
PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
OPC_REQUEST_ID_RE = re.compile(...)   # too narrow — extend for 'opc-request-id': '<id>'
OCID_RE = re.compile(r"\bocid1\.[A-Za-z0-9][A-Za-z0-9._-]{8,}\b", re.IGNORECASE)
```

### ALLOW_MARKER (keep narrow)
```python
# SOURCE: scripts/scan_sensitive_values.py:150-151
def _has_allowed_marker(line: str) -> bool:
    return "scanner-fixture" in line or "allow-sensitive-value" in line
```

### TEST_STRUCTURE
```python
# SOURCE: scripts/test_scan_sensitive_values.py:19,75
class TestSensitiveValueScanner(unittest.TestCase):
    def test_detects_request_ids_real_ocids_and_public_ips(self): ...
    def test_allows_placeholders_example_ocids_and_documentation_ips(self): ...
```

---

## Files to Change
| File | Action | Justification |
|---|---|---|
| `scripts/redaction.py` | CREATE | Single `redact_text()` / `redact_live_payload()` used everywhere |
| `scripts/test_redaction.py` | CREATE | Fence redaction on dict-style OCI errors + endpoint URLs |
| `scripts/convert_sentinel_kql.py` | UPDATE | Redact `live_validation_error` before writing |
| `scripts/parse_validate_all_queries.py` | UPDATE | Redact error + query before writing JSON |
| `scripts/verify_deployed_dashboards.py` | UPDATE | Redact `str(exc)` before serializing |
| `scripts/scan_sensitive_values.py` | UPDATE | Add LA-namespace + endpoint + dict-style request-id patterns; remove broad `queries/` exemption (keep synthetic/test-fixture allowances) |
| `scripts/test_scan_sensitive_values.py` | UPDATE | Add dict-style OCI-error detection test; assert `queries/*report*.json` is scanned |
| `.github/workflows/ci.yml` | UPDATE | Add always-on `scan_sensitive_values.py --json` gate |
| `.github/workflows/validate-rules.yml` | UPDATE | Watch/validate `queries/hunting/**` |
| `queries/sentinel_conversion_report.json` | UPDATE | Scrub the 2 committed live-error blocks (working-tree fix) |

## NOT Building
- Git history rewrite / force-push (operator decision — see Remediation).
- A vault/secret-manager integration (out of scope).
- Changing how live validation runs (only how its output is recorded).
- Redacting console *progress* output beyond what already exists.

---

## Step-by-Step Tasks

### Task 1: Centralized redaction module
- **ACTION**: Create `scripts/redaction.py` with `redact_text(s: str) -> str` and `redact_live_payload(obj)` (recurses dict/list, applies `redact_text` to str leaves).
- **IMPLEMENT**: regex replacements → `ocid1\.\w+\.oc1[\w.-]+`→`<OCID>`; `/namespaces/[a-z0-9]+/`→`/namespaces/<LA_NAMESPACE>/`; `'opc-request-id':\s*'[^']+'`→`'opc-request-id': '<OPC_REQUEST_ID>'`; `https://[a-z0-9.-]*\.oci\.oraclecloud\.com[^\s'"]*`→`<OCI_ENDPOINT>`; public-IP ranges → `<PUBLIC_IP>`.
- **MIRROR**: regex style from `scan_sensitive_values.py:52-62`.
- **GOTCHA**: the payload is often a `str(dict)` (single-quoted), not JSON — match single-quoted forms too.
- **VALIDATE**: `python3 -c "from scripts.redaction import redact_text; assert '<LA_NAMESPACE>' not in redact_text(open('queries/sentinel_conversion_report.json').read())"`

### Task 2: Apply redaction at write sites
- **ACTION**: Wrap the three sinks.
- **IMPLEMENT**: `convert_sentinel_kql.py:~470` → `redact_text(result.live_validation_result.get("error",""))`; `parse_validate_all_queries.py:~86` → `redact_text(...)` for both `error` and `query`; `verify_deployed_dashboards.py:~92` → `redact_text(str(exc))`.
- **MIRROR**: existing import style at top of each script.
- **VALIDATE**: regenerate the sentinel report locally and `git grep -c <LA_NAMESPACE> queries/sentinel_conversion_report.json` → 0.

### Task 3: Fix the scanner
- **ACTION**: Add patterns + un-exempt generated reports.
- **IMPLEMENT**: add `LA_NAMESPACE_RE` (e.g. `/namespaces/[a-z0-9]{8,}/`), `OCI_ENDPOINT_RE`, broaden `OPC_REQUEST_ID_RE` to the quoted-dict form; in the `queries/` allowance (line ~172) stop exempting `*report*.json` / `*.json` that aren't query fixtures (keep `test_data/` + `scanner-fixture` allowances).
- **GOTCHA**: must NOT start flagging the legitimate detection queries (they contain no tenancy data); scope new patterns to namespace/request-id/endpoint only.
- **VALIDATE**: `python3 scripts/scan_sensitive_values.py --json` → non-zero/findings BEFORE Task 2 scrub, `ok:true` AFTER.

### Task 4: Tests
- **ACTION**: `test_redaction.py` (dict-style error, endpoint URL, OCID, IP) + extend `test_scan_sensitive_values.py` with a `queries/x_report.json` containing a dict-style `opc-request-id` → asserts a finding.
- **MIRROR**: `test_scan_sensitive_values.py:75,95`.
- **VALIDATE**: `python3 -m pytest scripts/test_redaction.py scripts/test_scan_sensitive_values.py -q`

### Task 5: CI gates
- **ACTION**: Add scanner step to `ci.yml` (after Pytest); change `validate-rules.yml` paths `hunting/**`→`queries/hunting/**`.
- **MIRROR**: `ci.yml:47-48` step shape.
- **VALIDATE**: `python3 -c "import yaml,glob;[yaml.safe_load(open(f)) for f in glob.glob('.github/workflows/*.yml')]"`

### Task 6: Scrub the committed report (working tree)
- **ACTION**: Regenerate the report through the now-redacting converter, or manually replace the 2 leaked blocks with placeholders.
- **VALIDATE**: `git grep -l <LA_NAMESPACE>` → empty.

---

## Validation Commands
```bash
python3 -m pytest scripts/ -q                              # EXPECT: all pass
python3 scripts/redaction.py --selftest 2>/dev/null || true
python3 scripts/scan_sensitive_values.py --json            # EXPECT: ok:true, 0 findings AFTER scrub
git grep -lI '<LA_NAMESPACE>'                                # EXPECT: (empty)
python3 scripts/convert_sigma.py --validate                # EXPECT: 678 queries, 0 warnings
python3 -c "import yaml,glob;[yaml.safe_load(open(f)) for f in glob.glob('.github/workflows/*.yml')]"
```

## Acceptance Criteria
- [ ] `git grep <LA_NAMESPACE>` returns nothing in the working tree
- [ ] `scan_sensitive_values.py` flags a dict-style `opc-request-id` under `queries/` (regression test) and passes clean after scrub
- [ ] All three live-payload write sites route through `redaction.py`
- [ ] Scanner runs as an always-on CI gate; `validate-rules.yml` watches `queries/hunting/**`
- [ ] `pytest` green, `convert_sigma --validate` 0 warnings

## Risks
| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| New scanner patterns flag legitimate queries | Med | CI noise | Scope patterns to namespace/request-id/endpoint; add allow-markers narrowly |
| History still contains the namespace after working-tree scrub | High | Leak persists in public history | Operator runs `git filter-repo` (see Remediation) — out of this plan's code scope |
| Redaction over-aggressively mangles useful error text | Low | Harder debugging | Replace only sensitive substrings, preserve the parser-syntax message |

## Notes
- The leaked value `<LA_NAMESPACE>` is a tenancy LA **namespace** (fingerprint), not a credential — medium severity, but a redaction-rule violation already in 3 public commits.
- Working-tree scrub stops re-leaking; **purging public history requires `git filter-repo --replace-text` + force-push (operator decision).**

## Broader roadmap (from the review — not in this plan)
- **P2 Sentinel converter**: fix 2 live failures, then 25 field-mapping candidates; continue splitting `_facade_impl.py` (1819 lines).
- **P3 Dashboards**: scheduled *sanitized* live-health workflow; richer advanced-viz on Sentinel dashboards (still mostly table widgets).
- **P4 Forge webapp**: add webapp typecheck/lint + CSRF/rate-limit API tests to CI; keep production writes behind the API Gateway token.
