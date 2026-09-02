# OCI Log Analytics Detections Documentation

This directory is the wiki-style guide to using, operating, extending, and deploying this OCI Log Analytics detection-content repository. Start with the guide that matches your role; generated artifacts remain the authoritative source for current inventory and deployment content.

## Customer and SOC teams

| Need | Read | Outcome |
| --- | --- | --- |
| Onboard Windows access monitoring quickly | [Windows Access Monitoring Fast Onboarding](WINDOWS_ACCESS_FAST_ONBOARDING.md) | Management Agent, native Security/System/Application collection, five alerts, dashboard, and E2E proof |
| Follow the Windows console path | [Windows Access Manual Runbook](WINDOWS_ACCESS_MANUAL_RUNBOOK.md) | Click-by-click IAM, standalone agent install, entity/source association, saved searches, scheduled rules, and alarm canary |
| Follow the Windows automation path | [Windows Access Scripted Runbook](WINDOWS_ACCESS_SCRIPTED_RUNBOOK.md) | Guarded PowerShell, local E2E, OCI CLI bundle, dashboard deployment, and per-resource verification |
| Review the Windows architecture and decisions | [Windows Access Workflow Diagrams](WINDOWS_ACCESS_WORKFLOW_DIAGRAMS.md) | Architecture, parallel paths, alert sequence, troubleshooting tree, and evidence ladder |
| Establish the first Log Analytics data path | [Fast Onboarding Track](FAST_ONBOARDING_TRACK.md) | IAM, ingestion choice, canary sources, validation, and rollout ownership |
| Find, run, customize, and validate queries | [Using Log Analytics Queries](LOG_ANALYTICS_QUERY_USAGE.md) | Console, OCL, repository, and live-validation workflow |
| Plan a migration or SIEM-forwarding design | [Migration and Security Guide](MIGRATION_AND_SECURITY_GUIDE.md) | A phased telemetry, detection, and export plan |
| Choose raw or evidence delivery to Splunk | [Splunk Parallel Operations](SPLUNK_PARALLEL_OPERATIONS.md) | Mode 1, Mode 2, hybrid/on-prem policy, ownership, and steady-state operations |
| Migrate Splunk analytics | [Splunk Rule Migration](SPLUNK_RULE_MIGRATION.md) | Provenance, source/field translation, detection gates, and fidelity |
| Deploy the evidence exporter | [Splunk Evidence Export Runbook](SPLUNK_EVIDENCE_EXPORT_RUNBOOK.md) | Console steps plus separated plan, build, apply, canary, and replay approvals |
| Prove Splunk delivery end to end | [Splunk E2E Validation](SPLUNK_E2E_VALIDATION.md) | Local failure matrix and independent provider/Splunk acceptance layers |
| Deploy the supported package | [Deployment Guide](DEPLOYMENT.md) | Resource Manager plan/apply with customer-owned identity |
| Build third-party SIEM parsers | [`queries/siem_log_examples.json`](../queries/siem_log_examples.json) and [Webapp Guide](WEBAPP.md) | Placeholder-safe OCI envelopes and normalized detection events |
| Investigate and demonstrate attacks | [Threat Hunting Walkthrough](THREAT_HUNTING_WALKTHROUGH.md) | Evidence-driven analyst pivots |
| Operate detection health | [Monitoring](MONITORING.md) | Daily health checks and deployment verification |
| Review demo flows | [Demo Workflow](DEMO_WORKFLOW.md) | Repeatable SOC, APT, web, and compliance scenarios |

## Engineers and content authors

| Need | Read | Outcome |
| --- | --- | --- |
| Understand OCL and query validation | [Using Log Analytics Queries](LOG_ANALYTICS_QUERY_USAGE.md) | Correct field typing, authoring, and validation boundaries |
| Understand repository boundaries | [Architecture](ARCHITECTURE.md) | Correct source/generated/deployment separation |
| Add or change a detection | [Contributing](../CONTRIBUTING.md) | Regenerated and validated content |
| Convert Sentinel content | [Sentinel Conversion](SENTINEL_CONVERSION.md) | Parser-safe, live-validated promotion workflow |
| Understand generated contracts | [Integration Schema](INTEGRATION_SCHEMA.md) | Stable artifact consumption |
| Improve rules | [Rule Quality Report](RULE_QUALITY_REPORT.md) | Quality criteria and current baseline |
| Deploy Forge | [Webapp Guide](WEBAPP.md) | Read-only artifact runtime and security boundary |

## Operational principles

- `rules/**` is the source authoring surface; generated query and inventory artifacts are rebuilt, not hand-maintained.
- OCI tenancy values, credentials, real OCIDs, public IPs, and raw customer logs must not enter committed files or the Forge UI.
- Forge is a preparation and handoff surface. OCI Resource Manager, under the customer's identity, owns plan and apply.
- A detection is deployable only when its source, parser fields, query contract, and dashboard references are validated.
- Export raw events only when required. Prefer forwarding selected, enriched Log Analytics detection events to downstream SIEMs.
- Treat raw fan-out and detection-evidence export as separate products. A connector, Function invocation, or HEC response is not by itself end-to-end acceptance.

## Automation and release workflows

| Workflow | When it runs | What it protects | Credential posture |
| --- | --- | --- | --- |
| `CI` | Push and pull request | Python tests, generated examples, Terraform format/validation, local release gates | Credential-free |
| `Validate Detection Rules` | Detection-content changes | Sigma conversion, OCL validation, catalog and rule-quality checks | Credential-free |
| `Inventory Drift Guard` | Push and pull request | README/STATUS inventory alignment with the generated catalog | Credential-free |
| `Webapp CI` | Forge or parser-sample changes | Typecheck, lint, build, and API-contract E2E | Credential-free |
| `Sentinel Converter` | Relevant changes, manual, and scheduled | Local conversion, report consistency, and guarded live promotion | Local/PR lanes credential-free; live lane requires protected secrets |
| `Live OCI Validation` | Manual trusted-maintainer dispatch | Real OCI parser validation | Protected `live-oci` environment only |
| `Forge GitHub Pages` | Main branch or manual dispatch | Static Forge build and publication | Deployment runs only when Pages is enabled |

The protected live workflows never run from untrusted pull requests. A missing credential is reported as a clear preflight result in the Sentinel scheduled/manual lane; it is not treated as a successful live validation. See [Deployment Guide](DEPLOYMENT.md) for the customer deployment workflow and configuration details.

## Authoritative artifact map

- `queries/catalog.json`: current detection/content catalog
- `queries/dashboard_inventory.json`: dashboards, widgets, and saved searches
- `queries/manifest.json`: integration/export manifest
- `queries/siem_log_examples.json`: redacted source envelopes and normalized SIEM event examples
- `queries/log_source_field_dictionary.json`: parser/source field contract
- `queries/detection_rule_specs.json`: detection-rule specifications
- `queries/splunk_detection_registry.json`: generated Splunk provenance, canonical query, source/field, fidelity, and delivery mapping
- `config/splunk_parallel_delivery.yaml`: source/detection delivery policy and tenant-neutral HEC placeholders
- `schemas/splunk_evidence_event.schema.json`: normalized Mode 2 HEC evidence contract
