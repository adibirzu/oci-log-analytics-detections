# OCI Log Analytics Detections Documentation

This directory is the wiki-style guide to using, operating, extending, and deploying this OCI Log Analytics detection-content repository. Start with the guide that matches your role; generated artifacts remain the authoritative source for current inventory and deployment content.

## Customer and SOC teams

| Need | Read | Outcome |
| --- | --- | --- |
| Find, run, customize, and validate queries | [Using Log Analytics Queries](LOG_ANALYTICS_QUERY_USAGE.md) | Console, OCL, repository, and live-validation workflow |
| Plan a migration or SIEM-forwarding design | [Migration and Security Guide](MIGRATION_AND_SECURITY_GUIDE.md) | A phased telemetry, detection, and export plan |
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
