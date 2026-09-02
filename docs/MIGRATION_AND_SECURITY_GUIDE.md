# OCI Log Analytics Migration and Security Guide

## Purpose

Use this guide to migrate security telemetry and detection content into OCI Log Analytics, or to place OCI Log Analytics in front of an existing SIEM. The target outcome is a governed security-data path: collect the right telemetry, parse it into known fields, correlate and prioritize in Log Analytics, then forward only the evidence and detections that a downstream tool needs.

This repository supplies detection content, parser contracts, redacted parser examples, dashboard definitions, synthetic validation data, and a customer-controlled Resource Manager package. It does not host a SIEM, retain customer credentials, or perform tenancy changes from Forge.

## Recommended target architecture

```text
OCI Audit / Cloud Guard / VCN / WAF / LB / OKE / hosts / applications
                              |
                              v
                  OCI Logging, Streaming, or agents
                              |
                              v
                    OCI Log Analytics parsers
                              |
              normalize + enrich + correlate + detect
                              |
                 dashboards / saved searches / evidence
                              |
                              v
             selected alert and evidence export to SIEM
```

Keep the authoritative raw-log retention, routing, and privacy requirements in the customer's tenancy. Use the repository's field dictionary and parser examples to make source contracts explicit before enabling detections.

### Choose the Splunk delivery mode per source

| Mode | Flow | Use when | Acceptance |
|---|---|---|---|
| Mode 1 — raw | OCI Logging → separate Connector Hub → Streaming → pinned `oci-splunk` → HEC | Splunk requires the approved raw source | Same fresh record searchable in Log Analytics and Splunk, plus connector/consumer/HEC receipts |
| Mode 2 — evidence | Log Analytics detection → Monitoring → alarm → Notifications → Function → bounded query → HEC | Splunk needs governed detection evidence | Parsed hit, metric, alarm, Function, confirmed HEC, checkpoint, and Splunk search |
| Hybrid | Either/both, recorded per source and detection | Raw compliance retention and selected SOC evidence differ | Each enabled path passes independently |

Production raw delivery must use a reviewed tag or commit and must not track mutable `main`. Current migration provenance is `adibirzu/oci-splunk` tag `2.2.0` at commit `a98167404f19be6d18235bccbf1113b59a259c4c`. On-premises Management Agent/optional Management Gateway sources can use Mode 2 directly from Log Analytics; they do not need Streaming.

Use [Splunk Parallel Operations](SPLUNK_PARALLEL_OPERATIONS.md) for the decision/ownership model, [Splunk Rule Migration](SPLUNK_RULE_MIGRATION.md) for analytic translation, [Evidence Export Runbook](SPLUNK_EVIDENCE_EXPORT_RUNBOOK.md) for manual/scripted deployment, and [E2E Validation](SPLUNK_E2E_VALIDATION.md) for evidence gates.

## Migration workflow

### 1. Discover and classify telemetry

Create a source inventory with owner, region, compartment, log source, retention requirement, parser status, and downstream destination. Prioritize sources that support identity, control-plane, endpoint, network, workload, and web investigations.

Recommended first wave:

- OCI Audit and IAM activity for control-plane changes
- Cloud Guard problems for cloud posture and risk context
- Linux secure/syslog and Windows/Sysmon for endpoint behavior
- WAF, Load Balancer, and application telemetry for internet-facing attacks
- OKE/Kubernetes and application traces for workload-to-service correlation

Do not treat a source as onboarded merely because events arrive. It is ready only when its expected fields are extracted and a representative detection returns the expected result.

### 2. Establish parser contracts

Use these repository artifacts before configuring a production forwarder:

- `queries/log_source_field_dictionary.json` for known sources and display fields
- `queries/siem_log_examples.json` for redacted OCI Logging envelopes and normalized detection-event examples
- `scripts/setup_log_sources.py --validate` to verify supported custom-source expectations

Examples use placeholders such as `<COMPARTMENT_OCID>` and names such as `<USER_NAME>`. Replace them only in the customer-controlled runtime configuration; never commit live values back to the repository.

### 3. Select a detection baseline

Start with a small set of high-value use cases, tune them against the customer's normal behavior, then expand. The catalog contains many source-derived, curated, and converted queries; it is not necessary or advisable to enable every detection on day one.

| Use case | Typical evidence | Initial value |
| --- | --- | --- |
| Privileged IAM and policy changes | OCI Audit, identity context | Detects governance and persistence changes |
| Public exposure and network-control changes | OCI Audit, VCN/WAF/LB | Identifies unexpected internet-facing risk |
| Cloud Guard high-risk problems | Cloud Guard | Turns posture findings into investigation-ready context |
| Suspicious API and credential use | Audit, application, endpoint logs | Detects anomalous access and possible key abuse |
| Linux privilege escalation and persistence | Secure/syslog, audit, EDR | Covers sudo, SSH, cron, shells, and persistence |
| Windows credential access and lateral movement | Windows events, Sysmon | Covers suspicious process, authentication, and remote execution activity |
| Web exploitation and bot behavior | WAF/LB/application logs | Covers SQLi, XSS, SSRF, traversal, and abuse patterns |
| OKE and container compromise | Kubernetes/application telemetry | Covers workload execution, suspicious service interaction, and cluster signals |
| Command-and-control and exfiltration | DNS, proxy, endpoint, network logs | Supports beaconing, rare destinations, and unusual transfer patterns |
| Multi-stage correlation | Multiple sources, shared entity/trace fields | Reduces isolated low-confidence alerts into actionable investigations |

Map each enabled use case to a business owner, data source, MITRE technique where applicable, severity policy, expected false positives, and response playbook.

### 4. Deploy through customer-controlled Resource Manager

Use Forge **Deploy to OCI** or build the package locally:

```bash
python3 scripts/build_orm_stack.py --out /tmp/oci-log-analytics-deployment.zip
unzip -t /tmp/oci-log-analytics-deployment.zip
```

Create an OCI Resource Manager stack from the package, select the target compartment and region, run a plan, and approve an apply only after reviewing every proposed resource. See [Deployment Guide](DEPLOYMENT.md) and [stack package guide](../stack/README.md).

The package excludes credentials, Terraform state, ignored caches, and generated test data. Forge does not accept OCI credentials, tenancy IDs, profile names, or target-compartment values.

### 5. Validate before operationalizing

Run local artifact validation in every change cycle:

```bash
python3 scripts/convert_sigma.py
python3 scripts/generate_catalog.py
python3 scripts/export_for_multicloud.py --manifest-only
python3 scripts/audit_rule_quality.py --report docs/RULE_QUALITY_REPORT.md
python3 -m pytest -q
```

For live OCI work, follow the customer change process and use representative data. Validate log-source extraction, query behavior, dashboard references, routing, retention, and alert ownership before enabling broad forwarding or automated response.

## Log Analytics before an expensive SIEM

OCI Log Analytics can serve as the initial analytics layer instead of forwarding every raw event downstream. This design is useful when a SIEM is licensed by ingestion volume, when teams need OCI-aware parsing, or when multiple signals must be correlated before an analyst needs them.

| Raw-forwarding model | Log Analytics first model |
| --- | --- |
| Sends every source event to the SIEM | Retains/routs raw logs according to customer policy and forwards selected detection evidence |
| Downstream parser owners maintain every OCI shape | Parser and field contracts are validated close to OCI sources |
| Correlation often happens after expensive ingestion | Enrichment and multi-source correlation happen before export |
| High-volume routine events compete with security signals | Forwarded events can include rule, severity, entity, evidence, and correlation context |
| SIEM alert tuning is disconnected from OCI dashboards | OCI dashboards and saved searches provide first-line validation and hunting pivots |

This is not a claim that all raw logs should be discarded or that Log Analytics replaces every SIEM capability. Retention, compliance, incident response, and integration requirements remain customer decisions. Establish an explicit export policy for raw, normalized, detected, and enriched events.

## Downstream SIEM integration contract

Use `queries/siem_log_examples.json` to give parser developers two separate test surfaces:

1. **OCI Logging source envelope**: representative source-shaped JSON with placeholders, suitable for raw-parser development.
2. **Log Analytics detection event**: a source-shaped alarm event plus a stable normalized event, suitable for detection/event parsers.

The normalized contract helps downstream systems map a consistent set of security fields even where individual OCI services use different payload shapes. Keep source provenance, event time, severity, rule identity, entities, and evidence intact. Treat the examples as parser fixtures, not as production data.

For implemented Splunk evidence export, [`queries/splunk_detection_registry.json`](../queries/splunk_detection_registry.json) maps nine migrated analytics to canonical LAQL and [`schemas/splunk_evidence_event.schema.json`](../schemas/splunk_evidence_event.schema.json) defines the normalized HEC envelope. The default excludes original content. Neither artifact proves a live OCI query, HEC delivery, or Splunk search.

## Operational guardrails

- Apply least privilege for Resource Manager, Logging, Streaming, Service Connector Hub, and Log Analytics roles.
- Separate development, test, and production compartments and approvals.
- Review Terraform plans and dashboard changes before apply; do not bypass validation to make a dashboard deploy.
- Keep secrets in OCI Vault or approved CI/CD secret stores; never place them in query JSON, test fixtures, browser configuration, or documentation.
- Use placeholders in examples and remove tenancy-specific metadata from diagnostics before sharing.
- Define a rollback owner, alert-routing owner, and false-positive review cadence for every production use case.
- Re-run health checks after source/parser changes and before scheduled releases.

## Expand deliberately

After the first wave is stable, use the catalog and dashboards to add coverage by attack path: cloud identity, endpoint, web entry point, workload, network egress, and cross-source correlation. For Sentinel-derived content, follow [Sentinel Conversion](SENTINEL_CONVERSION.md); promotion is intentionally conservative and live validation is required before generated queries are accepted.

For practical analyst journeys, use [Threat Hunting Walkthrough](THREAT_HUNTING_WALKTHROUGH.md). For detection authoring, use [Contributing](../CONTRIBUTING.md). For the full documentation map, return to the [documentation hub](README.md).
