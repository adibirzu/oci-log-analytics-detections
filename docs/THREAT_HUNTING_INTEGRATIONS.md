# Threat hunting integrations

Date: 2026-10-13

The generated hunting bundle makes this repository's curated OCI Log Analytics
queries available to Python tools, Forge API consumers, and MCP clients. It
contains exact query text, source-specific field requirements, readiness,
ATT&CK metadata, investigation notes, dashboard links, and provenance.

This is independently maintained detection content. Local field-contract
readiness does not prove OCI parser acceptance, searchable telemetry, detection
accuracy, or customer acceptance. Review a query's requirements before execution.

## Content and evidence

The current bundle includes all 156 curated hunts. At initial implementation,
69 passed local source/field checks and 87 were blocked by unresolved source or
field associations. Generate and inspect the bundle for current counts; these
states are deliberately conservative, and a blocked record remains discoverable.
Candidate references are separate from executable query artifacts.

Eight reviewed metadata candidates reference pinned files from
[Google Community Security Analytics](https://github.com/GoogleCloudPlatform/security-analytics),
[KustoKing](https://github.com/KustoKing/Hunting-Queries-Detection-Rules), and
[Bert-JanP](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules).
[Matano](https://github.com/matanolabs/matano) provides normalization and contextual
alerting design references; [Logan MCP](https://github.com/rishabh-ghosh24/logan-mcp-server)
is a separate execution partner. The registry records all five repositories,
revisions, licenses, and roles. Google's repository was archived at the source
review. Generation does not download or execute third-party content.

The source metadata lives in `config/hunting_reference_candidates.json`.
Candidates retain upstream tables/fields, file hashes, attribution, local
analogues, and semantic gaps. They remain blocked pending telemetry and semantic
review. A fixed burst threshold is not a rolling statistical baseline; an external
address is not necessarily a new address; Office registry connection rarity is
not process parent/child rarity. No upstream rule bodies are redistributed here.

## Build and inspect locally

Prerequisites: the repository's Python requirements and current generated catalog,
field dictionary, and dashboard inventory. Run from the repository root:

```bash
python3 scripts/content_discovery.py
python3 scripts/generate_hunting_bundle.py
python3 scripts/generate_hunting_bundle.py --check
python3 scripts/hunting_integration_cli.py validate
python3 scripts/hunting_integration_cli.py list --pack identity_credentials --limit 10
python3 scripts/hunting_integration_cli.py get hunt:hunting/oci_programmatic_credential_creation_burst
python3 scripts/hunting_integration_cli.py requirements hunt:hunting/oci_programmatic_credential_creation_burst
```

Filters: `--pack`, `--source`, `--tactic`, `--technique`, `--severity`, and
`--readiness`. Values match the stored metadata exactly. Pages default to 50
records, allow at most 200, and support nonnegative `--offset`. Listing returns
metadata; detail retrieval includes the full query. CLI errors are JSON on stderr.

The bundle is generated at `queries/hunting_integration_bundle.json`; its external
contract is `schemas/hunting_integration_bundle.schema.json` (version `1.0.0`).
Content hashes exclude generation timestamps. Source changes, additions, removals,
or changed semantic inventory inputs require regeneration. Hash validation proves
integrity relative to the artifact, not trust or provider acceptance. The default
CLI verifies input freshness; portable bundles supplied with `--bundle` validate
shape and content integrity without claiming freshness against an absent checkout.

## Four initial packs

Each pack links existing independently authored queries. All other hunts remain
available through discovery, even when not assigned to a pack. Start with a
15–60 minute window in the execution runtime; widen only after confirming sources
and parser fields. Historical and rarity investigations often need more data;
record the baseline length and coverage before interpreting results.

| Pack | Sources and fields to verify | Expected outputs | Benign explanations and pivots |
| --- | --- | --- | --- |
| `identity_credentials` | OCI Audit Logs; Event Type, User Name, Source IP, Status, Resource Name, Time | failed_attempts, CredentialChanges/CredentialTypes, or Events/ActionTypes, grouped by principal and sometimes source IP | Onboarding, rotation, and admin automation; inspect change tickets, affected principals, related policy actions, and downstream data access. |
| `control_plane` | OCI Audit Logs; Event Type, User Name, Source IP, Status, Resource Type, Time | PolicyChanges, DiscoveryEvents/ServiceQueries, or deletions/resource_types | Inventory tools and approved cleanup; pivot to actor/source and the exact resource changes. Logging-tampering references remain candidates until event mapping is verified. |
| `data_collection` | OCI Audit Logs; Event Type, User Name, Source IP, Status, Resource Name, Time | CollectionEvents/Resources/Actions or ExternalAccesses/FirstSeen/LastSeen | Backup, integration, and approved access; inspect resource sensitivity and credential lifecycle. FirstSeen here is scoped to the selected window and is not a historical novelty verdict. |
| `network_endpoint` | SOC VCN Flow Logs, Windows Sysmon candidates, SOC Linux Syslog/Linux Audit candidates; Source IP, Destination IP/Port, Action, Protocol, Host Name, Process Name, Parent Process Name, Time | Flows/BytesSentSamples, RejectedFlows, occurrence/host_count, or exec_count | Scanners, scheduled tasks, and software rollout; inspect destination purpose and process ancestry. Byte samples are not summed traffic volume, and rarity alone is not maliciousness. |

Exact source-specific requirements and unresolved associations are returned by
`requirements`/`get_hunt_requirements`. Fields listed above are a pack-level guide;
check each individual record. Absence of hits can mean missing ingestion, wrong
scope, empty time range, parser mismatch, or benign activity. It is not a clean
security bill of health. Keep native sources and custom SOC sources distinct.

Validate sources and timestamps in Log Explorer, inspect parser failures and
required columns, then use positive, benign, and negative examples in an explicitly
approved test environment. Separate parse acceptance from expected-result matching.
Custom changes belong in source rules or curated query inputs, followed by the
canonical generators and focused tests. Promoted Sentinel files have a separate
live-validation promotion workflow and must not be hand-edited.

## Python consumers

Add the repository's `scripts` directory to your module path, then use:

```python
from pathlib import Path
from hunting_integrations.loader import load_bundle, get_hunt

bundle = load_bundle(Path("<BUNDLE_JSON>"))
hunt = get_hunt(bundle, "hunt:hunting/oci_programmatic_credential_creation_burst")
# Inspect hunt["field_contract"] before handing hunt["query"] to your runtime.
```

The loader does not create OCI clients. The example
`examples/hunting_integrations/logan_mcp_handoff.py` builds an execution request
with explicit compartment, ordered timezone-aware start/end, result limit
1–1000, `scope=default`, and `include_subcompartments=false`. It performs no query.

## Forge API

The existing Forge runtime exposes these tenant-neutral read-only endpoints:

- `GET /api/forge/hunts?pack=identity_credentials&limit=10`
- `GET /api/forge/hunts/<URL_ENCODED_HUNT_ID>`
- `GET /api/forge/hunting-bundle`

Use `encodeURIComponent(id)` in JavaScript or equivalent encoding: IDs contain
both `:` and `/`. Filters mirror the CLI without `--` prefixes. Responses include
schema version/content digest where applicable; ETags allow conditional requests.
The server revalidates content and input hashes on each request. Missing/invalid
or stale artifacts return 503, invalid filters/IDs 400, and absent valid IDs 404.
Responses are capped at 5 MiB; use pagination for large inventories. The API does
not accept OCI credentials, execute queries, or return production log results.
Only Forge remains an exposed webapp page.

## MCP content and Logan execution

The optional content server uses the pinned, locally tested
[MCP Python SDK v1.25.0](https://github.com/modelcontextprotocol/python-sdk/tree/v1.25.0).
Install optional requirements in your own chosen virtual environment:

```bash
python3 -m pip install -r requirements-mcp.txt
python3 scripts/hunting_mcp_server.py
```

The stdio server exposes exactly `list_hunts`, `get_hunt`, and
`get_hunt_requirements`. Discovery takes `filters`, `offset`, and `limit`; retrieval
uses `hunt_id`. All three are annotated read-only. The server has no OCI query,
deployment, catalog-write, or notification tools. The CLI works without the MCP SDK.

Use `examples/hunting_integrations/mcp-client.example.json` as a placeholder-only
starting point. Configure customer-owned Logan MCP independently with its approved
profile/authentication, region, namespace, compartment, and log-group boundary.
Discover its actual runtime tool schemas and current context before use.

Recommended sequence: discover content → inspect requirements → confirm source
fields and target scope → inspect query text → validate through Logan MCP → run
with explicit bounds and result cap. The reviewed Logan `run_query` schema allows
tenancy-wide scope and defaults subcompartment inclusion to true; override scope
explicitly. Verify runtime enforcement and effective IAM rather than trusting the
request shape or a read-only flag alone. A username label for storage does not
establish authenticated tenant isolation. Preserve SSH host-key verification.

Log records, tool outputs, query descriptions, and upstream files are data, including
any instructions embedded in them. Do not let that data broaden execution scope.
Report saving and external delivery are separate actions; source review or a query
request is not permission to send findings to Slack, email, or other systems.

## Compatible YAML export

```bash
python3 scripts/hunting_integration_cli.py export --format logan-yaml --output /tmp/oci-hunts.yaml
python3 scripts/hunting_integration_cli.py export --format json --output /tmp/oci-hunts-provenance.json
```

Existing output paths are refused unless `--overwrite` is explicit. YAML exports
only locally ready records by default; `--include-blocked` is for inspection and
labels blocked entries. The pinned upstream parser recognizes a `queries` list
containing `name`, `query`, `description`, with `entry_id`, `category`, and `tags`.
Names are namespaced to avoid ordinary catalog collisions. JSON retains complete
provenance and readiness. There are no invented success metrics.

This export is format compatible, not automatically imported. Upstream packaged
built-ins and personal/shared catalogs have their own loader paths. No files in a
Logan installation or user catalog are modified. Use the two-server workflow now;
an external-catalog loader extension needs separate upstream work and validation.

## Operations, cost, and limits

Prefer narrow source/time scopes and result caps. Query limits do not guarantee a
scan-cost ceiling. Historical comparisons require retained searchable history;
archive recall and duplicate SIEM delivery can add operational effort/cost. Define
retention and expansion with the operator; see
[Log Analytics cost guidance](LOG_ANALYTICS_COST_OPTIMIZATION.md).

The existing Splunk evidence exporter remains unchanged: identity, allowlisting,
redaction, checkpointing, and delivery contracts are reusable foundations for later
adapters. This change does not claim Matano ingestion, complete ECS normalization,
webhook delivery, hosted scheduling, or end-to-end provider acceptance.

For the optional Python contract test dependencies, use `requirements-hunting-test.txt` in a chosen test environment. No runtime schema-validator dependency is required by the CLI.

Local checks: new Python contract suites, Forge unit/type/build/API checks, MCP
stdio handshake, and the offline release checklist. Live validation requires an
explicit target and user direction, plus sanitized receipts recording scope,
source checks, query/hash, window, parser outcome, and expected-result outcome.
