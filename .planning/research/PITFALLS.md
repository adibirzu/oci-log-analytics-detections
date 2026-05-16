# Pitfalls Research

**Domain:** Sentinel KQL → OCI Log Analytics QL parity converter (brownfield, parser-validated promotion)
**Researched:** 2026-05-15
**Confidence:** HIGH (grounded in this repo's `sentinel_conversion_report.json`, `sentinel_oci_mapping.yaml`, `sentinel_conversion_workflow.py`, `release_checklist.py`)
**Scale context:** 8 promoted today / 4452 candidates / 53 known live-failed kept out of promotion / 25 attempted in the canonical report.

The goal of this document is to flag the failure modes that get worse as the converter scales from a curated 8 to thousands of promoted queries while live OCI parser validation remains the only promotion gate. Each pitfall identifies the trigger condition, the observable symptom, a concrete prevention, and the phase that should own that prevention.

---

## Critical Pitfalls

### Pitfall 1: Silent semantic loss in "permissive" expression handlers

**What goes wrong:**
The converter learns to handle a new KQL expression but produces a syntactically valid Logan QL output that is semantically wrong. Concrete patterns observed or imminent:

- `parse_command_line(x)` reduced to `tostring(x)` — the structured token array is gone, downstream `array_length`/`countof` becomes meaningless.
- `column_ifexists(Col, default)` collapsed to `Col` — the fallback branch is lost; queries promote on parser pass and silently return zero rows for any source where `Col` is absent.
- `iff(cond, then, else)` collapsed to a missing-else form (e.g. `if(cond, then)`) — the conversion report already shows `Direction = iff(ProcessCommandLine has "/Upload", 'Upload', 'Download')` as unsupported; the next iteration will be a permissive "support" that drops the else branch.
- `countof(InitiatingProcessCommandLine, ".exe")` lowered to `strlen` or `array_length` of the wrong tokenization.
- Multi-stage `extend a=... | extend b=f(a) | extend a=g(b)` reordered because the converter emits one combined `eval` block; later `a` overwrites earlier `a` before `b` consumed the original.

The query parses cleanly on OCI, passes live validation against a non-representative time window with zero matches, and gets promoted. The detection is now inert.

**Why it happens:**
Live parser validation is a syntactic-and-binding check — it does NOT check semantic equivalence to the source KQL. With 8 promoted queries, a human reviewed each one. With 1,000+ promoted queries from a "permissive" KQL handler, no human will.

**How to avoid:**
- Encode each KQL operator's semantics as a small set of golden-pair fixtures: KQL input → expected Logan QL output, plus a synthetic-log fixture that produces a known non-zero, non-trivial result count. Anything the converter outputs must match the golden Logan QL OR fail loudly. No "best-effort" lowering.
- Add a converter-level "lossy expression" allow-list. If the converter would drop a branch or collapse a function, it must raise and the candidate stays in `skip_reasons` with reason `lossy_lowering:<expr>`. Use unsupported skips as the safety net, not lenient lowering.
- Tier conversions: TIER-1 (lossless, deterministic — `extend`, `where`, `project`, simple `parse` with literal anchors), TIER-2 (semantic-checked golden fixtures required — `iff`, `case`, `countof`, `parse_command_line`, `column_ifexists`), TIER-3 (skip until a real OCI equivalent exists — `materialize`, `evaluate`, `series_decompose`, `bag_unpack` over arbitrary keys, regex with backrefs).
- Differential output test: before each release, run the converter twice against a frozen candidate set and diff the generated Logan QL. Unexpected diffs without a corresponding fixture change fail the gate.

**Warning signs:**
- Promotion count climbs while average row count per promoted query on the dashboard health report stays at 0.
- `live_validation_passed` grows but `widget_count` HIT count on the live baseline (`docs/health/all-dashboard-verify.json`) does not.
- Golden-fixture diff shows new outputs the operator did not consciously author.

**Phase to address:**
**Phase 6 (KQL Operator Parity, TIER-1+TIER-2 expressions).** Golden-fixture infrastructure must land BEFORE any new operator support. This is the highest-leverage prevention in the whole milestone.

---

### Pitfall 2: Mapping collisions and one-to-many fan-out without dedup

**What goes wrong:**
`config/sentinel_oci_mapping.yaml` currently maps many distinct Sentinel fields to the same Logan QL column. Examples in the live file:

- `Account`, `AccountName`, `Actor`, `User`, `SrcUserName`, `SrcUsername`, `ActorUsername`, `UserPrincipalName`, `UserName`, `UPN`, `SenderFromAddress`, `SourceLogin` → all collapse onto `User Name` or `User`.
- `InitiatingProcessFolderPath` → `'Parent Process Name'` (path becomes a name).
- `FileSize` → `'Network Bytes Out'` (unrelated semantics, almost certainly a copy-paste).
- `DeviceId` → `Entity` while `Computer` → `Entity` (loss of host-vs-device distinction).
- `TimeGenerated`, `Timestamp`, `EventCreationTime`, `EventEndTime` → all collapse onto `Time`.

When a Sentinel rule joins or self-correlates on two of these (e.g., `SubjectUserName != TargetUserName` or `Account == InitiatingProcessAccountName`), the converter produces `'User Name' != 'Target User Name'` — fine in some cases — but `Account == InitiatingProcessAccountName` becomes `'User Name' == 'User Name'`, always true.

At 8 queries a reviewer catches this. At 1,000 it slips through because both columns "exist."

**Why it happens:**
Mapping was driven by "make the candidate promote" not by "preserve the source query's relational semantics." There is no dedup or collision lint on the YAML.

**How to avoid:**
- Add a converter-time pass: if two distinct Sentinel field references in the SAME query map to the SAME Logan column, emit `lossy_mapping_collision:<sentinel_a>+<sentinel_b>→<oci_col>` and skip promotion. Force the operator to either add a synthetic disambiguation column to the parser or accept the skip.
- Lint `sentinel_oci_mapping.yaml` for: (a) many-to-one keys with conflicting categories (initiator vs target vs subject), (b) targets that are not present in `queries/log_source_field_dictionary.json`, (c) targets that are NOT the canonical Logan column for that semantic role (use `field_dictionary.py` as the oracle).
- Tag every mapping with a `role` (subject | target | initiator | resource | time | hash | network) and forbid same-role collisions inside one query without an explicit override.
- Audit the existing 100+ mappings before opening parity work. Track collisions in `queries/mapping_collisions.json` as a generated artifact; the inventory drift check should treat new collisions as a failure.

**Warning signs:**
- Generated Logan QL where the same quoted column appears on both sides of a comparison.
- Sentinel rules that reference `Subject*`, `Target*`, and `Initiating*` all promoting to identical Logan QL bodies that differ only in literal arguments.
- Field dictionary diff shows new mapping targets that were not added through the field dictionary script.

**Phase to address:**
**Phase 7 (Field/Table Mapping Completeness).** Collision lint and role tagging must land before any bulk mapping additions. Do this BEFORE expanding mappings for `Subject*`/`InitiatingProcess*`/`MailboxOwner*`/`OfficeWorkload`/`OrganizationName`.

---

### Pitfall 3: Live validation passes on empty result sets ("zero-row false pass")

**What goes wrong:**
Live validation checks: "Does OCI accept this OCL and return without parser error?" It does NOT check: "Does this OCL return meaningful data?" A query that compiles, binds all columns, and returns 0 rows over the configured lookback (default `24h`) is indistinguishable from a query that compiles, binds, and would return rows if the data window contained any. Once a small % of mappings break (Pitfall 2) or a parser version changes column casing, the population of "compiles + zero rows" expands silently.

At promoted=8 with active synthetic data, this is mostly fine. At promoted=1000+ over a real demo tenancy with sparse synthetic coverage, the majority of promoted queries will live in "passed and empty" forever.

**Why it happens:**
The promotion gate is a 1-bit signal. The release baseline (`343/343 HIT`) catches it for currently-deployed widgets, but newly promoted Sentinel queries that are not yet on a dashboard never get checked for HIT.

**How to avoid:**
- Pair every promoted Sentinel query with a synthetic log fixture under `test_data/sentinel_synthetic/` that produces ≥1 row when the query runs. Reuse the existing `sentinel_synthetic_logs.py plan` command. Promotion requires HIT against the synthetic fixture, not just parser pass.
- Promote a new "expected_hit" check into `release_checklist.py` between `sentinel strict status` and `dashboard dry run`: every entry in `queries/sentinel/*.json` must show `live_validation_status=passed` AND `live_synthetic_hit_count>0`.
- Track `live_validation_passed_with_rows` vs `live_validation_passed_zero_rows` separately in the conversion report summary. The CI should fail when the zero-row population grows by >N% release-over-release.
- Use a representative `--lookback` for promotion that matches synthetic coverage windows; don't promote queries whose lookback exceeds synthetic data retention.

**Warning signs:**
- `live_validation_passed` increases but `widget_count HIT` on the live baseline does not.
- `sentinel_conversion_report.json` shows `live_validation_passed > 0` but `live_validation_passed_with_rows` is empty or absent.
- A new mapping change ships and *no* zero-row counts shift downward.

**Phase to address:**
**Phase 6 prerequisite + Phase 8 (Coverage Expansion).** The synthetic-fixture-must-hit gate is the single most important promotion improvement. Land before scaling promoted count beyond ~50.

---

### Pitfall 4: Tenancy-specific parser quirks bleeding into committed artifacts

**What goes wrong:**
A Sentinel rule promotes because it passed live validation in the `<OCI_PROFILE_CAP>` tenancy. That tenancy has custom parsers / extracted fields / log sources not present in customer tenancies. The promoted JSON now references a column name or source that only `CAP` understands. The artifact is committed and shipped to consumers (`LoganSecurityDashboardv0`, `mcp-oci-logan-server`) that deploy it in *other* tenancies, where it silently breaks or fails dashboard import.

Already visible in the mapping file (`DnsEvents → SOC Windows Sysmon Logs`) — that source exists because the demo tenancy was set up that way, not because it's the canonical Sentinel-to-OCI mapping.

**Why it happens:**
There is exactly one validation profile, and it is the same one that the SOC-content authors maintain.

**How to avoid:**
- Add an "abstract parser contract" check: every column referenced in a promoted query must exist in `queries/log_source_field_dictionary.json` as a canonical field for the declared log source, NOT just exist in the validating tenancy.
- Maintain a tenancy-neutral fixture set under `test_data/` derived from the field dictionary. Run a second validation pass against an OCI Log Analytics CLI dry-parse mode (or static parser metadata export) that does not depend on actual records.
- Scan promoted JSON for tenancy-flavored values: OCIDs, compartment names, region codes, profile names, namespace strings. The existing `scan_sensitive_values.py` is the right hook — extend its pattern set.
- Document the abstract-contract requirement in `CLAUDE.md` Hard Rules.

**Warning signs:**
- A field in promoted Logan QL is not present in `queries/log_source_field_dictionary.json` despite the query passing live validation.
- `release_checklist.py` `field dictionary validation` step passes only because the field dictionary was regenerated *from* the new promoted query (chicken-and-egg).
- Customer-reported "0 rows" reports for queries that show HIT in `docs/health/`.

**Phase to address:**
**Phase 7 (Mapping Completeness) + Phase 10 (CI hardening).** The field-dictionary-is-the-oracle check belongs in CI before any large mapping additions.

---

### Pitfall 5: Promoted queries silently regressing after mapping or parser changes (drift)

**What goes wrong:**
Operator extends `sentinel_oci_mapping.yaml` for a new Sentinel field. The change inadvertently overrides or shadows an existing mapping (YAML keys are unordered to humans), or a parser update changes a column from `User` to `User Name`. Previously promoted queries are not regenerated — they still live as committed JSON under `queries/sentinel/`. The dashboards backed by those JSON files continue to run with stale Logan QL. By the next release, several promoted queries reference a column the parser no longer emits, but they pass live validation as "binds to nothing, returns 0 rows" (Pitfall 3).

**Why it happens:**
Promoted JSON is generated once and committed. Mapping schema is a moving target. There is no re-emission check.

**How to avoid:**
- Implement the "conversion drift detector" promised in PROJECT.md as a first-class CI gate: re-run the converter against the same Sentinel candidate corpus that produced the currently-promoted JSON; if the regenerated Logan QL diverges from the committed Logan QL for any promoted file, fail CI and require either a re-promotion or an explicit `drift_accepted.json` entry.
- Pin parser metadata version per promoted artifact. Each promoted JSON gets `parser_schema_hash` derived from `log_source_field_dictionary.json` at promotion time. Drift detector compares current hash to recorded hash.
- On every mapping YAML change, regenerate the converter's text output for the full attempted set and diff. Any non-zero diff requires explicit acknowledgement.
- Mappings file should be loaded with a strict "no duplicate keys" YAML loader (PyYAML's default silently overrides on duplicates).

**Warning signs:**
- `git diff` on `config/sentinel_oci_mapping.yaml` shows a key being added that matches an existing key (case-insensitive collision).
- `queries/sentinel_conversion_report.json` `summary.promoted_count` matches file count, but file content differs from the last regeneration timestamp (catalog ages out vs source rules).
- Field dictionary version bumped without re-promotion.

**Phase to address:**
**Phase 9 (Drift Detector).** Build the drift detector as a dedicated phase; it has its own deliverable in PROJECT.md. The strict YAML loader change is a 1-line precursor that can land in Phase 7.

---

### Pitfall 6: Live API budget exhaustion at scale + non-deterministic CI

**What goes wrong:**
The promote workflow today runs `--top all` with `--timeout 20`. Against 4452 candidates this is a substantial OCI Log Analytics API budget. At 1,000+ attempted promotions per CI run, the workflow will:

- Hit rate limits (OCI Log Analytics throttling) — some queries return throttling errors that get classified as `live_environment` (because the existing classifier triggers on `status=401` / `clock skew`) but the throttling error wasn't matched, so it becomes a generic `live_validation` failure. Next run, the same candidate may pass — non-deterministic flapping.
- Exceed the 1200s pytest step and 3600s live-verify step in `release_checklist.py`, breaking CI.
- Burn through tenancy quota — the `CAP` baseline (343 widgets) plus 1000+ converter probes plus dashboard health verification.

**Why it happens:**
Live validation is the only promotion gate, and "more promoted" multiplies live cost linearly. CI was sized for ~25 attempted candidates.

**How to avoid:**
- Two-stage validation: local validation (cheap, deterministic, no API) gates 95%+ of candidates; live validation only runs on the small set that passed local AND has a fixture HIT. Sequence is already in the workflow but is not enforced as a hard gate.
- Cache live validation results keyed by `(logan_ql_hash, parser_schema_hash, lookback)`. If nothing relevant changed, skip the live call.
- Add throttling-aware classification: extend `classify_next_query_candidate` to recognize 429 / throttle / quota in the `live_validation_error` string. Throttled candidates must NOT be classified as a query defect.
- Concurrency limit + exponential backoff on the converter side. Treat live validation as a budgeted resource (e.g., `--max-live-calls-per-run`).
- CI matrix: PR runs do local + drift check only. Nightly / pre-release runs do live promote for delta-only candidates.

**Warning signs:**
- Two consecutive CI runs disagree on the promoted set.
- `live_validation_error` strings start showing throttling / 429 / `RequestThrottled` / `TooManyRequests`.
- Release-checklist `live profile dashboard verification` step times out at 3600s.

**Phase to address:**
**Phase 10 (CI workflow).** Throttling classification is a small Phase 6/7 fix; the architectural shift to delta-only live validation is the Phase 10 deliverable.

---

### Pitfall 7: Brittle string-based converter tests vs. AST tests

**What goes wrong:**
The natural way to test converter output is `assert generated_ocl == "user='admin' and Time > dateRelative(24h) | stats count by 'User Name'"`. This becomes brittle when:

- Whitespace, quoting style, or argument ordering is normalized differently between converter releases.
- A safe refactor (e.g., always emit canonical column-name quoting) requires changing thousands of fixture strings.
- Operators read green tests as evidence of semantic correctness when they only prove string equality.

**Why it happens:**
String comparison is easy to write. AST/IR comparison requires a Logan QL parser, which the project does not currently have.

**How to avoid:**
- Build a minimal Logan QL canonicalizer: tokenize, sort commutative comparisons, normalize quoting and whitespace, emit canonical form. Tests compare canonical forms.
- For TIER-2 semantic correctness, write fixture-driven tests: `(kql_source, expected_canonical_ocl, synthetic_log_fixture, expected_row_count)`. The test runs the converter, canonicalizes, compares, then runs the OCL against the synthetic fixture (mocked or in-process query engine if available) and compares row count.
- Tag tests with `pytest.mark.integration` (live OCI) vs `pytest.mark.unit` (canonicalized output) vs `pytest.mark.fixture` (synthetic-log round-trip). Per `~/.claude/rules/python/testing.md` — use `pytest` with marks.
- Replace `print()` statements with `logging` (per Python hooks rule).

**Warning signs:**
- Fixture diffs in PRs are larger than the converter diff itself.
- Test names like `test_iff_conversion` that assert only on string output.
- Tests run only in `unittest` discovery mode, not parameterized.

**Phase to address:**
**Phase 6 (KQL Parity).** Canonicalizer + AAA-pattern parametrized pytest harness must precede operator parity work, otherwise every new operator carries its own brittle fixture set.

---

### Pitfall 8: Sequencing capabilities before mappings (or vice versa) — throwaway work

**What goes wrong:**
Two valid orderings produce different throwaway work:

- **Capabilities first:** Operator implements `parse_command_line`, `column_ifexists`, `countof`, etc. Many candidates that *would* now convert still fail because their field references (`SubjectUserName`, `InitiatingProcessAccountName`, `MailboxOwnerUPN`, `OfficeWorkload`) are unmapped. Operator authors a lot of test scaffolding for operators against synthetic candidates that never reach live promotion.
- **Mappings first:** Operator adds 200 new field mappings. Most candidates that use those fields still skip because they also use an unsupported operator (`parse EventData with ...` / `iff(...)` / `countof(...)`). Mapping coverage looks great in the YAML but `promoted_count` barely moves.

Both orderings produce work that has no immediate effect on the headline metric (`promoted_count`).

**Why it happens:**
Conversion blockers are conjunctive: a candidate promotes only when ALL its blockers clear. Working on one axis in isolation has diminishing returns.

**How to avoid:**
- Use the existing `next-queries --strategy foundational` and triage output to pick a *cohort* of candidates whose blockers form a closed set, then close all blockers for that cohort before moving on. The workflow already supports this — explicitly drive it.
- Set the success metric per phase as "N candidates moved from skipped to promoted" not "N operators implemented" or "N mappings added."
- Track an "unblock chain length" metric per skipped candidate: how many independent blockers are left. Prioritize candidates with chain length 1 first (single-blocker fixes have immediate promotion payoff).
- Combine Phase 6 (capabilities) and Phase 7 (mappings) into cohort-driven sprints rather than two sequential monoliths.

**Warning signs:**
- After significant operator parity work, `promoted_count` did not move.
- Top skip reasons in the report shift but the total skip count stays flat.
- Operators committing new YAML entries that never appear in any promoted Logan QL.

**Phase to address:**
**Phase 8 (Coverage Expansion) governs sequencing for Phase 6 and Phase 7.** Treat Phase 8 as a project-management overlay (cohort selection, prioritization helper) rather than purely an execution phase. The backlog prioritization helper promised in PROJECT.md is exactly this overlay.

---

### Pitfall 9: Data hygiene leaks into promoted JSON

**What goes wrong:**
Promoted Sentinel JSON ends up committed with one of:

- A tenancy-specific log source name (e.g., `<TENANT-PREFIX>_SOC_Audit` instead of canonical `OCI Audit Logs`).
- A compartment OCID or `compartmentName` literal inside a `where` clause.
- An IP address from the validation tenancy in an example or comment field.
- An `opc-request-id` echoed back from an OCI error into a `live_validation_error` and then into the report.
- A user UPN or sample username from the tenancy used as a test literal.

This violates the global rule (`~/.claude/CLAUDE.md`) AND the project Hard Rule #7. `scan_sensitive_values.py` is the existing line of defense but its pattern coverage is finite.

**Why it happens:**
Live validation runs in a real tenancy and emits real values into errors and metadata. The converter persists those into the report and from the report into per-file JSON.

**How to avoid:**
- Apply redaction at the converter boundary, not just at the release-checklist boundary. `release_checklist.py` redacts `_redact_output` but only on the stdout/stderr of step results — it does NOT redact the artifacts the converter writes (`queries/sentinel/*.json`, `queries/sentinel_conversion_report.json`).
- Extend `_safe_error_summary` in `sentinel_conversion_workflow.py` (already strips `opc-request-id`) to also strip OCIDs, public IPs, compartment names, and tenancy prefixes BEFORE the report is persisted.
- Add a hard pre-commit check that every promoted file passes `scan_sensitive_values.py`. Make it a release-checklist gate that runs *after* promotion, not just before commit.
- Treat field references with tenancy-specific casing (e.g., `<TENANT>_User_Name`) as a separate class of hygiene violation distinct from value leaks.

**Warning signs:**
- `scan_sensitive_values.py` finds matches inside `queries/sentinel/*.json` or `queries/sentinel_conversion_report.json`.
- A reviewer notices an IP, OCID, or tenancy name in a diff.
- A consumer project (`LoganSecurityDashboardv0`) reports a "compartment not found" deployment error after pulling an updated artifact.

**Phase to address:**
**Phase 7 (Mapping Completeness) for the field-name hygiene + Phase 10 (CI) for the artifact-level scan gate.**

---

### Pitfall 10: Catalog/inventory/manifest falling out of sync with promoted reality

**What goes wrong:**
A promoted Sentinel JSON is added but `queries/catalog.json`, `queries/dashboard_inventory.json`, `queries/manifest.json`, or `CATALOG.md` is not regenerated. README/STATUS counts diverge from canonical inventory. Downstream consumers that read the manifest (per the artifact-producer contract in CLAUDE.md) miss the new content.

The repo already shows symptoms of this in `git status`: many catalog and report files are modified but not consistently together.

**Why it happens:**
Regeneration is a separate command. Operators forget. Hard Rule #6 ("README/STATUS counts must reconcile with `queries/catalog.json` before commit") is enforced by humans.

**How to avoid:**
- Make `refresh-artifacts` mandatory after every promotion in CI. The workflow already supports it; the gate should be that promotion commits without an artifact refresh fail CI.
- The `inventory drift check` step exists in `release_checklist.py` — extend it to compare `queries/sentinel/*.json` file set against `sentinel_conversion_report.json` `summary.promoted_count` and against catalog entries. Mismatches must fail.
- Auto-update README/STATUS counts from the catalog rather than hand-editing them. Treat README/STATUS counts as generated content.

**Warning signs:**
- `release_checklist.py` step "inventory drift check" fails.
- README count differs from `queries/catalog.json` length.
- A new file in `queries/sentinel/` is not represented in `queries/manifest.json`.

**Phase to address:**
**Phase 10 (CI workflow).** This is largely a CI-gate problem; the generators already exist.

---

## Technical Debt Patterns

| Shortcut | Immediate Benefit | Long-term Cost | When Acceptable |
|---|---|---|---|
| Lower an unsupported KQL expression to a string-only equivalent (`tostring`) | One more candidate promotes today | Silent semantic regression; the rule becomes inert for all customers | **Never** — keep it skipped with `lossy_lowering:<expr>` |
| Map multiple Sentinel fields to one Logan column without role tagging | Mapping table looks complete | Cross-field comparisons in queries become tautologies | Only when source roles are provably identical (e.g., `IpAddress` and `IPAddress` aliases) |
| Promote a candidate that lives validated but did not synthetic-hit | `promoted_count` climbs | "Zero-row passing" population grows; detection inert | Only TIER-1 lossless queries with a documented "no synthetic coverage yet" follow-up |
| Skip the drift detector for "tiny" mapping changes | Faster iteration | Promoted JSON silently diverges from current converter output | Only inside a single PR; never across releases |
| Use `--top all` live promotion in CI | Maximum coverage per run | API budget exhaustion, throttling, flaky CI | Only in nightly / pre-release; PR CI must use delta or local-only |
| Hand-edit `queries/sentinel/*.json` to fix a small issue | One-line fix | Breaks the generator-only invariant; next regeneration overwrites it | **Never** — fix at converter, mapping, or rule source |
| Add a new Sentinel field directly to `sentinel_oci_mapping.yaml` without dictionary entry | New mapping ships fast | Tenancy-specific column names leak; drift detector cannot validate | Only when the column already exists in `log_source_field_dictionary.json` |

---

## Integration Gotchas

| Integration | Common Mistake | Correct Approach |
|---|---|---|
| OCI Log Analytics live API | Treating any error string as "the query is wrong" | Classify throttling (429), auth (401), parser (400) separately; only parser errors are query defects |
| OCI parser schema | Assuming column names are stable across regions/tenancies | Pin `parser_schema_hash` per promoted artifact; re-validate on parser version bumps |
| Sentinel source rules (upstream Azure-Sentinel repo) | Pulling new candidates without re-running drift detector | Sentinel sync → drift detect → triage → promote, in that order |
| Companion consumers (`LoganSecurityDashboardv0`, `mcp-oci-logan-server`) | Allowing them to read mid-release artifacts | Manifest version pinning; consumers read tagged releases only |
| `scripts/deploy_dashboard.py` | Hand-authoring widget `row`/`column` on imported Sentinel content | Always use `resolve_widget_layout()`; Sentinel widgets get width/height only |
| Synthetic log generators | Generating fixtures only for promoted queries | Generate fixtures for *candidate* queries too, so skipped ones can be unblocked |
| `field_dictionary.py` | Treating the field dictionary as a downstream artifact | The dictionary is an **input contract**: mappings must match it, not the other way around |

---

## Performance Traps

| Trap | Symptoms | Prevention | When It Breaks |
|---|---|---|---|
| Live-validate every candidate on every PR | CI runtime climbs linearly with candidate count | Delta-only live validation against converter output hash | Breaks at ~200 attempted candidates per CI run |
| Loading `sentinel_oci_mapping.yaml` and re-parsing per-candidate | Converter wall-clock grows quadratically | Load YAML once, build lookup dict at startup | Breaks at ~1000 attempted candidates per run |
| Writing `queries/sentinel_conversion_report.json` after every candidate | Disk I/O dominates | Buffer in-memory, write once at end (already the case — protect this) | Already constrained; would break at ~5000 |
| Regenerating `catalog.json` and `dashboard_inventory.json` in serial during refresh | Wall-clock of `refresh-artifacts` grows | Parallelize independent generators; already independent on disk | Breaks at full corpus (~5000 promoted) |
| Holding all 4452 candidates in memory with full `live_validation_error` strings | RSS climbs to hundreds of MB | Stream/append to report, drop large error strings after classification | Breaks at ~10000 candidates |
| `live_failure_examples` truncation at 8 in triage output | Triage hides the long tail of failures | Provide a `--limit` and a `--full` JSON path for analysis | Already constrained; OK for human triage, not for CI |
| Synchronous `subprocess.run` for live API calls | No concurrency; wall-clock = N × per-call latency | Bounded async pool with backoff | Breaks at ~100 attempted candidates with 20s timeout |

---

## Security Mistakes

| Mistake | Risk | Prevention |
|---|---|---|
| Promoted JSON contains a raw OCID, public IP, compartment name, or tenancy prefix | Violates Hard Rule #7 + global `~/.claude/CLAUDE.md`; leaks customer infra topology | Redact at converter boundary; run `scan_sensitive_values.py` on `queries/sentinel/*.json` in CI |
| `live_validation_error` strings persisted with `opc-request-id` | Leaks request IDs into committed history | `_safe_error_summary` already redacts; extend coverage to OCIDs/IPs **before** the report is written |
| Hard-coded compartment IDs in a `where` clause for a tenancy-scoped query | The query only runs in that tenancy; consumers leak the OCID | Forbid OCID literals in promoted Logan QL via lint |
| Synthetic log fixtures committed with real user data scraped from a demo tenancy | PII leak | Fixture generator must use deterministic fake identities; review fixture commits |
| Mapping YAML targeting tenancy-named columns (e.g., `<TENANT>_user`) | Tenancy name leak in committed config | YAML lint: targets must match the canonical Logan column names from `field_dictionary.py` |
| Logging the full `convert_sentinel_kql.py` stdout including error context to CI logs without redaction | OCIDs/IPs land in public CI logs | The release checklist already runs `_redact_output` — ensure the converter's own logs go through the same redactor |
| Live validation profile credentials checked into `.env` or referenced by name in artifacts | Credential leak | `.env` is gitignored; never reference profile names in promoted JSON |

---

## "Looks Done But Isn't" Checklist

- [ ] **New KQL operator support:** Often missing a TIER-2 golden-fixture pair and a synthetic-log round-trip. Verify: `tests/converter/golden/<operator>_*.json` exists, has both KQL and canonical OCL, and the synthetic fixture produces a non-zero row count.
- [ ] **New field mapping:** Often missing a `field_dictionary` entry and a role tag. Verify: target appears in `queries/log_source_field_dictionary.json` AND the YAML entry passes the collision lint.
- [ ] **Live-validated promotion:** Often missing a synthetic-hit check. Verify: `live_synthetic_hit_count > 0` in the conversion report for every entry in `queries/sentinel/*.json`.
- [ ] **Mapping YAML change merged:** Often missing a drift detector run. Verify: regenerated converter output for the full attempted set is identical to committed Logan QL OR a `drift_accepted.json` entry exists.
- [ ] **Catalog regenerated:** Often missing manifest and dashboard inventory sync. Verify: `release_checklist.py` "inventory drift check" passes.
- [ ] **README/STATUS counts updated:** Often missing the catalog reconciliation. Verify: counts match `queries/catalog.json` length per category.
- [ ] **CI workflow added:** Often missing local-only gating; runs live on every PR. Verify: PR-tier CI does not consume live API budget; nightly does.
- [ ] **Throttling-aware classification:** Often missing — throttle errors become "live_validation" defects. Verify: 429/RequestThrottled mapped to `live_environment` in `classify_next_query_candidate`.
- [ ] **Strict YAML loader:** Often missing — duplicate keys silently override. Verify: `sentinel_oci_mapping.yaml` loads under a strict (duplicate-key-detecting) loader in converter and in tests.
- [ ] **Tenancy-neutral artifacts:** Often missing — committed JSON references tenancy-specific columns or sources. Verify: every column in promoted Logan QL appears in the field dictionary as canonical, not just exists-in-CAP.

---

## Recovery Strategies

| Pitfall | Recovery Cost | Recovery Steps |
|---|---|---|
| Pitfall 1 (semantic loss) | HIGH | Roll back the operator handler to skip-only; identify promoted queries that used the lossy operator via converter re-run; revert those JSON files; mark candidates skipped with `lossy_lowering` reason until golden fixtures exist |
| Pitfall 2 (mapping collision) | MEDIUM | Add role tags to YAML; regenerate; failed-collision candidates revert to skipped; targeted parser changes to disambiguate where SOC needs both columns |
| Pitfall 3 (zero-row false pass) | MEDIUM | Backfill synthetic fixtures for existing promoted queries; queries without fixtures get `live_synthetic_hit_count=0` and are demoted on next CI run |
| Pitfall 4 (tenancy quirks) | HIGH | Audit every promoted column against field dictionary; demote violators; restore once parser contract is canonical |
| Pitfall 5 (drift) | MEDIUM | Run drift detector retroactively; produce a `drift_report.json`; demote diverged queries; re-promote after regeneration |
| Pitfall 6 (API budget) | LOW | Add throttling classification and delta-only live validation; existing data is unaffected |
| Pitfall 7 (brittle tests) | MEDIUM | Build canonicalizer; rewrite tests incrementally; do not delete brittle tests until canonical replacements exist |
| Pitfall 8 (sequencing) | LOW | Switch to cohort-driven prioritization via `next-queries --strategy foundational` |
| Pitfall 9 (data hygiene) | HIGH if leaked to git history | Use `git filter-repo` per `~/.claude/CLAUDE.md`; rotate any exposed credentials; add converter-side redaction to prevent recurrence |
| Pitfall 10 (catalog drift) | LOW | Run `refresh-artifacts`; reconcile README/STATUS; add CI gate |

---

## Pitfall-to-Phase Mapping

| Pitfall | Prevention Phase | Verification |
|---|---|---|
| P1 — Silent semantic loss | **Phase 6** (KQL operator parity) | Golden-fixture tests pass; canonicalizer-based diff catches lossy lowering |
| P2 — Mapping collisions | **Phase 7** (mapping completeness) — *prerequisite work* | Collision lint passes on every YAML PR; converter emits `lossy_mapping_collision` skips |
| P3 — Zero-row false pass | **Phase 6 prerequisite + Phase 8** (coverage) | Synthetic-hit gate in `release_checklist.py`; `live_validation_passed_with_rows` tracked |
| P4 — Tenancy-specific leakage | **Phase 7 + Phase 10** (CI) | Every promoted column appears in `log_source_field_dictionary.json` as canonical |
| P5 — Drift after schema change | **Phase 9** (drift detector) | Drift detector CI step passes; `parser_schema_hash` pinned per artifact |
| P6 — Live API budget / non-determinism | **Phase 10** (CI workflow) | PR CI runs local-only; nightly does delta live promote; throttling classified separately |
| P7 — Brittle string-based tests | **Phase 6** (precedes operator work) | Pytest harness uses canonicalized OCL; tests marked `unit`/`integration`/`fixture` |
| P8 — Sequencing / throwaway work | **Phase 8** (coverage) — *as PM overlay* | Phase success measured in candidates promoted, not features built |
| P9 — Data hygiene in artifacts | **Phase 7 + Phase 10** | Converter-side redaction; `scan_sensitive_values.py` runs on `queries/sentinel/*.json` in CI |
| P10 — Catalog/inventory drift | **Phase 10** (CI workflow) | `inventory drift check` step extended to cover Sentinel JSON ↔ report ↔ catalog ↔ manifest |

**Roadmap implications:**
- Phase 6 is structurally the most important — its prerequisites (golden fixtures, canonicalizer, TIER-1/2/3 classification) must land before any operator work or the entire milestone risks silent regression.
- Phase 7 should be split into "lint + role tags + dictionary contract" (prerequisite) and "bulk mapping additions" (execution). The first half is small; skipping it accelerates Pitfall 2 dramatically.
- Phase 8 is best treated as a project-management overlay (cohort selection) rather than a discrete code-delivery phase.
- Phase 9 (drift detector) needs to ship before Phase 7's bulk mapping additions, otherwise the mapping work itself creates the first drift incident.
- Phase 10 (CI) carries five of ten pitfalls. It deserves equal weight to Phase 6.

**Recommended out-of-scope items for the roadmap:**
- Lenient/best-effort KQL lowering (P1 — never acceptable).
- Hand-authored promoted Sentinel JSON (already out of scope in PROJECT.md; reinforce).
- New mapping entries without a corresponding `field_dictionary.py` canonical entry (P2/P4).
- Live promotion runs from PR CI (P6 — nightly only).
- Treating `live_validation_passed` as proof of correctness without a synthetic-fixture hit check (P3).

---

## Sources

- `queries/sentinel_conversion_report.json` — current promoted=8, attempted=25, total_candidates=4452, live_passed=8, live_failed=10; concrete unsupported-feature distribution (SubjectAccount, EventData, iff/countof extends, parse stage, MailboxOwnerUPN, OfficeWorkload, OrganizationName, ActingProcessFileInternalName).
- `config/sentinel_oci_mapping.yaml` — observed many-to-one collisions (User/User Name fan-in, FileSize→Network Bytes Out, Computer/DeviceId→Entity, four time fields→Time).
- `scripts/sentinel_conversion_workflow.py` — current classifier logic for `live_environment` vs `live_validation` (does not classify 429/throttling); `_safe_error_summary` redacts `opc-request-id` only.
- `scripts/release_checklist.py` — current release gates and redaction patterns (`OCID_RE`, `IPV4_RE`, `PRIVATE_KEY_RE`, `REQUEST_ID_RE` — applied to step output only, not to artifact contents).
- `CLAUDE.md` Hard Rules — generator-only invariants, dashboard layout discipline, README/catalog reconciliation, sensitive-value prohibition.
- `~/.claude/CLAUDE.md` global rule — no public IPs, OCIDs, credentials, PII in committed files; remediation requires `git filter-repo`.
- `.planning/PROJECT.md` — milestone goal, target features (operator parity, mapping completeness, coverage expansion, backlog helper, drift detector, CI workflow), promotion-only-via-live-validation invariant.
- Live baseline (`<OCI_PROFILE_CAP>` 343/343 HIT) referenced in `CLAUDE.md` — basis for the "promoted but never widgetized → zero-row false pass" argument (P3).

---
*Pitfalls research for: Sentinel KQL → OCI Log Analytics QL parity converter scaling*
*Researched: 2026-05-15*
