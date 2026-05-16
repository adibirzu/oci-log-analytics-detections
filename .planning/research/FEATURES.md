# Feature Research

**Domain:** Microsoft Sentinel KQL to OCI Log Analytics QL (Logan QL) parity converter, applied to MITRE-relevant detection content
**Researched:** 2026-05-15
**Confidence:** HIGH (grounded in `scripts/convert_sentinel_kql.py`, `scripts/sentinel_conversion_workflow.py`, `config/sentinel_oci_mapping.yaml`, and the live `queries/sentinel_conversion_report.json` blocker counter)

## Context Recap (existing capabilities — do not re-research)

| Already shipped (v1.x) | Source |
|---|---|
| KQL `where` with `==`, `=~`, `!=`, `in`, `!in`, `has`, `has_any`, `contains`, `startswith`, `endswith` translation | `convert_predicate` in `convert_sentinel_kql.py` |
| `summarize` with `count`, `dcount/distinctcount`, `sum/min/max/avg`, `make_list`/`make_set`/`take_any` mapped to OCL `stats ... | unique` | `SUPPORTED_AGGREGATIONS` |
| Table allow-list (60+ Sentinel tables incl. `SecurityEvent`, `Sysmon`, `Device*Events`, `SigninLogs`, `OfficeActivity`, `EmailEvents`, `imProcess*`, `CommonSecurityLog`, etc.) | `config/sentinel_oci_mapping.yaml` |
| Field map (~140 Sentinel fields → quoted OCI display names) | `fields:` in mapping YAML |
| Live OCI parser validation gate before promotion | `sentinel_conversion_workflow.py promote` |
| Triage / `next-queries` / `status --json --strict` helpers | `build_triage`, `build_next_query_backlog` |
| Skip-reason inventory in `sentinel_conversion_report.json` (25 attempted, 8 promoted, 4452 candidate corpus) | report summary |

Anything below is the gap to v2.0 parity. Existing items are not table stakes for this milestone — they're prerequisites already met.

## Feature Landscape

### Table Stakes (Required for "Parity Converter" Claim)

Operators and mappings that recur in the live blocker counter, and that a Sentinel-fluent user assumes will Just Work. Missing any of these keeps the converter in "8 of 4452" territory.

#### A. KQL operator/expression capabilities

| Feature | Why Expected | Complexity | Notes / Mapping target |
|---|---|---|---|
| `extend` with simple aliasing (`extend X = Y`, `extend X = tolower(Y)`) | Recurring in nearly every Defender XDR rule | LOW | Already partially handled; finish coverage and emit `eval X = lower(Y)` |
| `extend` with `iff(cond, a, b)` (ternary) | Hit in current report (`Direction = iff(...)`) | MEDIUM | Translate to OCL `eval` with `if(cond, a, b)` once OCL builtin verified live; otherwise drop or pass-through-constant |
| `extend` with `tostring`, `toint`, `tolower`, `toupper`, `tolong` | Required for any normalization step | LOW | Map to OCL `tostring`/`tolower`/`toupper`/`tonumber` |
| `extend` with `countof(haystack, needle)` | Hit in current report (`Exe = countof(...)`) | MEDIUM | No direct OCL equivalent — translate to `eval` with regex-replace-length pattern, or mark BLOCKED with explicit reason |
| `extend` with `parse_command_line(cmd, 'windows')` + array indexing `Parsed[-1]` | Hit in current report (4 occurrences across BITS rule) | HARD | OCL has no array indexing; translate to `Command Line` regex split, or BLOCKED |
| `column_ifexists('X', default)` predicate (commonly with `=~`) | Hit in current report (BITS bitsadmin rule) | MEDIUM | OCL is strict — emit as `( 'X' = default OR 'X' is not null )` fallback or BLOCKED with action "promote `X` into mapping" |
| `project` and `project-away` | Universal in Sentinel hunting queries | LOW | Map to OCL `fields` |
| `project-rename` / `project-reorder` | Common cosmetic step | LOW | Drop silently (semantic noop on detection logic) or translate to `fields` |
| `top N by X` | Standard hunt pattern | LOW | Map to OCL `sort ... | head N` |
| `distinct` (operator form, not aggregation) | Standard hunt pattern | LOW | Map to `stats by ...` with no aggregate |
| `where` with chained `and`/`or` and parentheses | Universal | LOW | Already handled — verify parenthesis preservation under negation |
| `matches regex "..."` predicate | Hit in current `UNSUPPORTED_PATTERNS` (line 176) | MEDIUM | Map to OCL `like` with `%` wildcards when pattern is trivial, BLOCKED for true regex |
| `parse Field with "lit" Capture1 "lit" Capture2 ...` | Hit in report (`parse EventData with * 'ObjectDN">' ...`) | HARD | OCL has no inline parse; produce explanatory BLOCKED with suggested parser-side fix |
| `mv-expand` / `mv-apply` | Already explicitly blocked (line 165) — common in Office/Email rules | HARD | BLOCKED. Document mitigation: pre-flatten at parser level |
| `make-series` + `series_decompose_anomalies` / time-series ML | Blocked (line 164) | BLOCKED | Anti-feature — see below |
| `join kind=inner|leftouter|innerunique` across tables | Already blocked (line 162) | HARD | Most cross-table joins are anti-feature in OCL; flag for split into two saved searches + correlation in dashboard |
| `let var = ...` bindings (constants and table aliases) | Already blocked (line 163) | MEDIUM | Constant-let inlining is achievable (substitute literal); table-let blocked |
| `let table = T | where ...; table | summarize ...` (table-let chain) | Universal pattern in Sentinel hunting queries | MEDIUM | Inline the bound table at first use; refuse if used more than once or in a join |
| `union T1, T2` | Frequent in cross-table hunts | HARD | OCL `*` source pattern partly covers; otherwise BLOCKED |
| `ago(Nd / Nh)` time window | Universal | LOW | Strip (OCL gets time window from saved-search metadata `defaultTimeRangeMinutes`) |
| `bin(TimeGenerated, 1h)` time bucketing | Universal in hunting summaries | MEDIUM | Map to OCL `timestats span=1h` |
| `parse_json` / `todynamic` / `bag_unpack` / `extractjson` | Blocked (line 174) — common for EventData/AdditionalFields | HARD | BLOCKED with action "promote nested field into parser extraction" |
| `extract(regex, captureIdx, source)` | Blocked (line 175) — common in CommandLine inspection | HARD | BLOCKED; rebuild via parser-side regex field |
| `countif(predicate)` aggregate | Blocked (line 177) | MEDIUM | Translate to `eval flag = if(predicate, 1, 0) | stats sum(flag)` |
| `strlen(X)` | Blocked (line 173) | LOW | Map to OCL `length()` if available; otherwise BLOCKED |
| `evaluate` plugin invocation (e.g. `bag_unpack`, `pivot`) | Blocked (line 171) | BLOCKED | Anti-feature |
| `materialize()` | Blocked (line 172) | BLOCKED | Anti-feature |
| `_GetWatchlist(...)` / `watchlist` references | Blocked (line 168-169) | BLOCKED | Anti-feature unless OCI Lookups replacement is in scope |
| `invoke FunctionName(...)` (KQL stored functions) | Blocked (line 170) | HARD | BLOCKED — flag for manual inline if function source is in repo |

#### B. Field mapping table stakes (concrete unmapped fields from live report)

| Field cluster | Tables | Why expected | Complexity |
|---|---|---|---|
| `Subject*` (SubjectAccount, SubjectDomainName, SubjectLogonId, SubjectUserSid, SubjectUserName) | SecurityEvent (Windows 4624/4672 family) | Almost every Windows logon rule uses these | LOW per field, MEDIUM as a set (need to confirm `SOC Windows Security Events` parser exposes them) |
| `InitiatingProcess*` extras (InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessSHA256, InitiatingProcessId) | DeviceProcessEvents, Sysmon | Defender XDR detections lean on these | LOW |
| `ParentProcessName` (already separate from `InitiatingProcessParentFileName`) | SecurityEvent 4688, Sysmon 1 | Process-tree rules | LOW |
| `ProcessId` | All endpoint tables | Used in correlation joins | LOW (map to OCI `Process ID` if parser exposes) |
| `Exe` (Defender alt naming) | DeviceProcessEvents | Single rule today | LOW |
| `EventData` (xml chunk) and inline-parsed children e.g. `ObjectDN` | SecurityEvent (4662, 4742 etc.) | Directory Service rules | HARD (requires parser-side extraction, not just mapping) |
| `MailboxOwnerUPN`, `OfficeWorkload`, `OrganizationName`, `ClientInfoString`, `UserType` | OfficeActivity, EmailEvents | All M365 mailbox/audit detections | LOW (mapping) but MEDIUM if SOC parser missing fields |
| `LocalFile`, `RemoteUrl` (Defender BITS rule extracts) | DeviceProcessEvents | Derived via `parse_command_line` | BLOCKED at operator level (see HARD entries above) |
| `Logon_Type` (alt spelling) | SecurityEvent | Already mapped as `LogonType`; need alias | TRIVIAL |
| `ActingProcessFileInternalName` | CommonSecurityLog / CyberArk | EDR-specific | LOW or BLOCKED if parser absent |
| `timeout` (literal token treated as a field) | False-positive — KQL `query_timeout` directive | TRIVIAL | Filter out the KQL `set timeout=...` and `set truncationmaxsize=...` directives before parsing |

#### C. Automation surface (already partially present)

| Feature | Status | Notes |
|---|---|---|
| Live OCI parser validation gate | DONE | Keep. Hard rule #3 |
| Triage report (`workflow.py triage`) | DONE | Expand to surface "field mapping" vs "operator" vs "live failure" buckets distinctly |
| `next-queries --limit N` backlog classifier | DONE | Already classifies by `_extract_mapping_blocker` / `_build_oci_gap` |
| `status --json --strict` machine gate | DONE | Wire to CI |
| Conversion drift detector (re-validate promoted queries after each mapping/parser change) | MISSING | Required to keep promoted set honest |
| CI workflow (dry-run convert + catalog regen + release-checklist local gates) | MISSING | Repeated in PROJECT.md target features |

### Differentiators (Raise the bar from "converter" to "parity program")

| Feature | Value Proposition | Complexity | Notes |
|---|---|---|---|
| **MITRE coverage scoring on backlog** | Lets product owner rank "promote 20 next" by ATT&CK technique gap vs converter difficulty, not alphabetically | MEDIUM | Combine `quality_score` from Sentinel rule YAML, MITRE techniques from rule `relevantTechniques`, and current OCI MITRE coverage from `queries/catalog.json` |
| **Conversion drift detector** | Catches mapping changes that silently invalidate already-promoted Sentinel queries before they ship to dashboards | MEDIUM | Re-run live validation across `queries/sentinel/*.json` whenever `sentinel_oci_mapping.yaml` or parsers change; emit `drift_report.json` |
| **CI dry-run on every PR** | Prevents promotion regressions; makes Sentinel parity visible in PR review | LOW | GitHub Actions: `sentinel_conversion_workflow.py local` (writes to `/tmp`), `convert_sigma.py`, `generate_catalog.py`, `release_checklist.py` |
| **Operator-level gap report** | Tells maintainers which 3 operators would unlock the most candidates if implemented | LOW | Aggregate `unsupported_features` from the report, weight by parent rule's MITRE/severity |
| **Field-mapping gap report** | Same as above, but for `sentinel_oci_mapping.yaml` extensions | LOW | Already half-baked in `_extract_mapping_blocker`; surface as a ranked CSV / Markdown |
| **"Promotable next N" generator** | Pick the N candidates whose blockers are fully addressable inside the current PR's diff | MEDIUM | Cross-reference candidate's required operators/fields against what the PR diff actually adds |
| **Static converter HTML page** | Already exists (`docs/sentinel_converter.html`); enhance with operator/field rollup | LOW | Extend `refresh-artifacts` |
| **Round-trip syntax check (Logan QL → OCI dry validate → back)** | Detects OCL builtin drift without running live validation every time | HARD | Requires offline Logan QL grammar — likely not worth it; live validation is the truth |
| **Per-table promotion velocity dashboard** | Internal metric: how many MITRE techniques per Sentinel solution are we converting per week | LOW | Aggregate `sentinel_conversion_report.json` over time (git log) |

### Anti-Features (Do NOT build)

| Feature | Why Requested | Why Problematic | Alternative |
|---|---|---|---|
| KQL ML operators (`series_decompose_anomalies`, `series_outliers`, `autocluster`) | Sentinel UEBA rules use them heavily | OCL has no equivalent; emulating ML in OCL would be unsound | BLOCKED with clear reason — direct user to OCI Anomaly Detection service if needed |
| KQL `geo_info_from_ip_address` and `geo_distance_2points` | GeoIP enrichment in cloud-identity rules | OCL has no geo plugin; getting it right requires a parser-side enrichment | BLOCKED — recommend OCI Threat Intelligence Service or parser-side geo lookup |
| KQL `parse_json` / `todynamic` / `bag_unpack` (deep dynamic expansion) | Common for `EventData`, `AdditionalFields` | OCL field model is flat; matching dynamic bag semantics requires schema-on-read which OCL doesn't do | BLOCKED — push extraction to parser fields and re-promote |
| Cross-table `join kind=inner|leftouter` with summarize | Many Sentinel SolarWinds/Defender rules | OCL `link` and saved-search joins are not equivalent; producing wrong-but-runnable OCL is worse than blocked | BLOCKED — split into two saved searches and correlate at dashboard level |
| KQL stored function inlining (`invoke FuncName(...)` against `Functions/*.txt` in Sentinel repo) | Reuse of `_im_*` ASIM helpers | Functions are recursive and version-skewed; mechanical inlining produces inconsistent semantics | BLOCKED — manual port when target function adds high value |
| Watchlist hydration via `_GetWatchlist()` | IOC, asset-tier, internal-IP-range lookups | Sentinel watchlists are external state; emulating in OCL would require shipping watchlist contents into the query, which violates the no-PII rule | BLOCKED — use OCI Lookups (separate feature) or hard-code minimal allow-lists in parser side |
| KQL `evaluate pivot(...)` / `evaluate bag_unpack(...)` | Cosmetic shaping in hunting queries | Plugin model has no OCL equivalent and breaks query semantics if removed silently | BLOCKED |
| Auto-detection of cross-tenant references (`workspace("xyz").Table`) | Multi-workspace Sentinel queries | OCI compartments are not Sentinel workspaces; rewriting is unsafe | BLOCKED |
| Sentinel `materialize()` caching | Performance hint in source queries | No OCL equivalent; safe to strip | Strip silently |
| Free-form Markdown ingest of Sentinel rule YAML `description` into the saved-search note | Looks nice in OCI UI | Sentinel descriptions sometimes contain Microsoft customer names, tenant IDs, or internal IPs → violates global hard rule | Use only `title`, `tactics`, `relevantTechniques`, and `severity` |
| Auto-create OCI scheduled-search detection rules from every promoted Sentinel query | "Why not turn them into alerts?" | Triggers actual alarms in tenancies; out of scope per PROJECT.md | Keep specs in `queries/detection_rule_specs.json` as metadata only |

## Feature Dependencies

```
[D. CI dry-run on every PR]
    └──requires──> [C1. Triage / next-queries / status --strict] (DONE)
    └──requires──> [convert_sigma.py + generate_catalog.py local gates] (DONE)

[E. Conversion drift detector]
    └──requires──> [Live OCI parser validation gate] (DONE)
    └──requires──> [B. Field-mapping completeness] (in flight)
    └──enhances──> [D. CI dry-run] (drift becomes a PR check)

[A2. extend + iff/tostring/toint/tolower]
    └──unblocks──> ~15-30% of skipped Defender XDR rules

[A3. parse_command_line + array indexing]
    └──HARD; blocks BITS-family rules
    └──alternative──> parser-side CommandLine token fields

[A1. column_ifexists]
    └──requires──> [B. Field-mapping completeness] (so most fields stop being optional)

[F. MITRE coverage scoring on backlog]
    └──requires──> [queries/catalog.json MITRE join] (DONE)
    └──requires──> [Sentinel candidate metadata (relevantTechniques)] (DONE in sync step)
    └──enhances──> [next-queries] backlog ordering

[B. Field mapping completeness — Subject*, InitiatingProcess*, EventData children]
    └──requires──> SOC parser exposes the fields (some need parser change, not just YAML)

[A4. let-binding inline (single-use, constants)]
    └──enables──> ~25% of hunting queries that start with `let lookback = 7d;`

[A5. bin(TimeGenerated, 1h) → timestats span=1h]
    └──enables──> hunting `summarize ... by bin(TimeGenerated, 1h)` pattern
```

### Dependency Notes

- **Operator support presupposes field support.** Even after `extend Direction = iff(ProcessCommandLine has "/Upload", ...)` parses, the rule still fails if `ProcessCommandLine` is unmapped on the target table. Phase Sentinel parity work as **mapping-first, then operators**.
- **Drift detector presupposes mapping completeness.** Re-validating today would just re-confirm the same 8/4452. The drift detector earns its keep once mappings stop being the dominant blocker.
- **CI dry-run is independent of operator/mapping work.** It can ship in any phase. It should ship as early as possible because it locks the gates that all later phases depend on.
- **Anti-features are hard constraints.** ML, geo, dynamic-bag, and stored-function expansion must be explicit BLOCKED with structured reasons so MITRE coverage scoring can correctly mark them "not addressable in v2.0."

## MVP Definition

### v2.0 Launch (Phase 6–7)

Minimum to claim "Sentinel KQL parity for table-stake operators and mappings."

- [ ] **A1+A2 — extend with iff/tostring/toint/tolower/toupper** (unblocks the largest cluster of single-rule skips)
- [ ] **A4 — single-use `let` constant inlining** (unblocks ~25% of hunting queries)
- [ ] **A5 — `bin(TimeGenerated, span)` → `timestats span=`** (unblocks recurring hunting summarize-by-time pattern)
- [ ] **B — field-mapping completeness for Subject* and InitiatingProcess*** (closes 7 of the 10 current live failures)
- [ ] **B — alias `Logon_Type` → `LogonType`** (trivial; eliminate the false-failure)
- [ ] **B — strip KQL `set timeout=...` / `set truncationmaxsize=...` directives** (eliminate the spurious `timeout` field mapping error)
- [ ] **D — CI dry-run** (converter + catalog + release-checklist local gates on every PR)
- [ ] **Operator-level gap report + field-mapping gap report** (free given the existing skip-reason inventory)

### v2.x Add After Validation (Phase 8–9)

- [ ] **E — Conversion drift detector** (re-validates `queries/sentinel/*.json` against live parser whenever mapping changes)
- [ ] **F — MITRE coverage scoring on backlog** (orders `next-queries` by ATT&CK gap rather than insertion order)
- [ ] **A — column_ifexists** (gated on B; mostly removes guard predicates around optional fields)
- [ ] **A — countif aggregate** translation to `eval+stats sum` (low-frequency but cheap)
- [ ] **B — `EventData` child extraction for Directory Service rules** (only if SOC parser is extended to expose ObjectDN, ObjectClass, etc.; otherwise stays BLOCKED)
- [ ] **Promotable-next-N generator** (which candidates does this PR's diff actually unblock?)

### Future Consideration (post v2.0)

- [ ] **A — `parse Field with ...` inline parse** (HARD; depends on whether we expose a parser-extraction helper)
- [ ] **A — `parse_command_line` + array indexing** (HARD; alternative path is parser-side tokenization)
- [ ] **A — `union T1, T2`** (only if cross-source detections become an explicit demand)
- [ ] **Per-table promotion velocity dashboard** (nice-to-have internal metric)
- [ ] **OCI Lookups-backed watchlist replacement** (separate epic; large scope)

## Feature Prioritization Matrix

| Feature | User Value | Implementation Cost | Priority |
|---|---|---|---|
| `extend` + scalar funcs (`iff`, `tostring`, `tolower`, `toupper`, `toint`) | HIGH (unblocks most Defender XDR skips) | LOW–MEDIUM | **P1** |
| Field mapping completeness — `Subject*`, `InitiatingProcess*` | HIGH (closes 7 of 10 live failures) | LOW | **P1** |
| Strip KQL `set ...` directives | MEDIUM (eliminates false skip) | TRIVIAL | **P1** |
| `Logon_Type` alias | LOW | TRIVIAL | **P1** |
| `let` constant inline (single-use) | HIGH (~25% of hunting queries) | MEDIUM | **P1** |
| `bin(TimeGenerated, span)` → `timestats span=` | HIGH (hunting summarize chain) | MEDIUM | **P1** |
| CI dry-run on every PR | HIGH (locks gates) | LOW | **P1** |
| Operator + field gap report (markdown rollup) | MEDIUM (planning ergonomics) | LOW | **P1** |
| Conversion drift detector | HIGH (correctness over time) | MEDIUM | **P2** |
| MITRE coverage scoring on backlog | HIGH (prioritization quality) | MEDIUM | **P2** |
| `column_ifexists` | MEDIUM | MEDIUM | **P2** |
| `countif` aggregate translation | LOW | MEDIUM | **P2** |
| `project`, `project-away`, `top N by`, `distinct` | MEDIUM | LOW | **P2** |
| `matches regex` (only trivial → `like`) | LOW | MEDIUM | **P2** |
| `parse_command_line` + array indexing | MEDIUM (BITS family) | HARD | **P3** |
| `parse Field with ...` | LOW | HARD | **P3** |
| `union` | LOW | HARD | **P3** |
| ML operators (`series_*`, `autocluster`) | — | — | **NEVER (anti-feature)** |
| Watchlist hydration `_GetWatchlist` | — | — | **NEVER (anti-feature)** |
| Dynamic bag expansion (`parse_json`, `bag_unpack`) | — | — | **NEVER (anti-feature)** |
| Cross-table joins | — | — | **NEVER (anti-feature; split into two saved searches)** |
| `geo_*` functions | — | — | **NEVER (anti-feature)** |
| Auto-create OCI alarms from Sentinel rules | — | — | **NEVER (anti-feature; out of scope per PROJECT.md)** |

## Competitor / Comparable Approach Analysis

| Approach | Coverage strategy | Validation | Where we differ |
|---|---|---|---|
| `sigmac` / `pySigma` Sentinel backend | Sigma → KQL output; no live validation | Syntactic | We go the opposite direction (KQL → OCL) and gate on live OCI parser response |
| Uncoder.io (SOC Prime) — multi-SIEM transpiler | Web-form-based KQL ↔ Splunk ↔ Sentinel ↔ Elastic | None | Closed source; we own the mapping table and the validation loop |
| Splunk SPL2 transpiler patterns | Operator-by-operator translation with a documented "unsupported" list | Some have unit-test corpora | Our skip-reason inventory + `next-queries` backlog classifier is the same pattern done in repo |
| Repository's own Sigma → OCL converter (`convert_sigma.py`) | Source-rule allow-list, generated catalog, no manual edits | Live OCI dashboard verification at deploy time | Sentinel converter inherits the same shape — live validation gate is the unifying contract |

## Sources

- Repo: `scripts/convert_sentinel_kql.py` lines 129–189 (SUPPORTED_AGGREGATIONS, UNSUPPORTED_PATTERNS, LOGAN_UNSUPPORTED_PATTERNS)
- Repo: `scripts/sentinel_conversion_workflow.py` (`build_triage`, `build_next_query_backlog`, `classify_next_query_candidate`)
- Repo: `config/sentinel_oci_mapping.yaml` (tables + fields allow-list as of 2026-05-14)
- Repo: `queries/sentinel_conversion_report.json` (4452 candidates, 8 promoted, concrete `unsupported_features` counter)
- Repo: `.planning/PROJECT.md` (v2.0 Sentinel KQL Parity milestone definition)
- Repo: `CLAUDE.md` (hard rules: no placeholder fields, live validation gate, no PII)
- Microsoft KQL reference: https://learn.microsoft.com/azure/data-explorer/kusto/query/ (operator semantics for `extend`, `parse`, `mv-expand`, `bin`, `summarize`, `let`, `union`, `join`)
- Sentinel ASIM normalization schemas: https://learn.microsoft.com/azure/sentinel/normalization (table `imProcessCreate`, `imAuthentication` field contracts)
- Azure-Sentinel content repo (canonical KQL corpus): https://github.com/Azure/Azure-Sentinel (commit `63ff8eedc58e7df0d22eba05ca73c92b59a66634` pinned in current conversion report)

---
*Feature research for: Sentinel KQL → Logan QL parity (v2.0 milestone, Phase 6 onward)*
*Researched: 2026-05-15*
