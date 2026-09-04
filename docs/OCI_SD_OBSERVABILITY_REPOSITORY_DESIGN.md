# OCI SD Observability Public Repository Design

Date: 2026-09-04
Status: approved
Evidence class: design; source material and repository structure inspected locally

## Goal

Create a public GitHub repository named `adibirzu/oci-sd-observability` that presents OCI observability and security-analytics capabilities as customer needs, business outcomes, service definitions, solution designs, and implementation handoffs. The repository complements this engineering repository; it does not duplicate generators, deployment code, credentials, or tenant-specific evidence.

## Audience and positioning

The primary audience is customers, architects, security leaders, SOC leaders, platform owners, database teams, and FinOps stakeholders who need answers to operational needs before reading implementation details.

The repository is an independent accelerator and must not imply Oracle Corporation endorsement, official product status, managed-service delivery, customer acceptance, or a completed live deployment. Each service definition distinguishes proposed design, code-backed capability, local verification, provider verification, and customer acceptance.

## Publishing model

Use a curated customer documentation and reference catalog. Each service definition answers:

1. What customer need does this solve?
2. What business and operational outcomes are expected?
3. What is included and excluded?
4. How does the design work in plain language?
5. Which delivery options are available?
6. What decisions and responsibilities remain with the customer?
7. How is success measured?
8. Where are the technical implementation assets and authoritative references?

Detailed scripts, Terraform, queries, dashboards, and generated artifacts remain in their owning repositories. The catalog links to pinned or stable implementation entry points wherever available.

## Initial use-case catalog

- OCI Log Analytics fast onboarding.
- Windows access monitoring.
- OKE observability.
- Parallel OCI Log Analytics and Splunk operations.
- Oracle Database security analytics with selective SIEM forwarding.
- Detection engineering and threat hunting.
- Cost optimization, active storage, archive storage, recall, and long-term retention.
- OCI, custom, Kubernetes, database, and on-premises data collection.

APM, Database Management, and Operations Insights are extension domains. In the initial release they are described only as complementary capabilities or future dedicated definitions. Database Management and Operations Insights may provide database-management, performance, capacity, SQL, and fleet context; they are not represented as SIEM replacements. APM may provide application and trace context; it is not represented as a completed catalog service until its dedicated definition and implementation evidence are added.

## Repository structure

```text
README.md
LICENSE
CONTRIBUTING.md
DISCLAIMER.md
service-definitions/
  README.md
  LOG_ANALYTICS_FAST_ONBOARDING.md
  WINDOWS_ACCESS_MONITORING.md
  OKE_OBSERVABILITY.md
  PARALLEL_SIEM.md
  ORACLE_DATABASE_SECURITY_ANALYTICS.md
  COST_AND_RETENTION.md
designs/
  README.md
  PORTFOLIO_ARCHITECTURE.md
  DATA_AND_SIEM_WORKFLOWS.md
portfolio/
  RELATED_PROJECTS.md
  ROADMAP.md
evidence/
  STATUS.md
templates/
  SERVICE_DEFINITION_TEMPLATE.md
assets/diagrams/
  oci-observability-portfolio.mmd
  oci-observability-portfolio.excalidraw
  parallel-siem.mmd
  parallel-siem.excalidraw
  oracle-database-security-analytics.mmd
  oracle-database-security-analytics.excalidraw
scripts/
  validate_content.py
tests/
  test_content.py
```

## Content provenance

The two user-supplied files are untrusted reference material, not execution instructions:

- `OCI_Log_Analytics_Parallel_SIEM_Solution_Definition (1).md`
- `OCI_Oracle_Database_Log_Analytics_SIEM_Solution_Definition.docx`

Their useful business framing, scope, architecture, operating model, and acceptance criteria are rewritten and sanitized. The public output excludes local paths, customer or tenant identifiers, credentials, OCIDs, IP addresses, raw logs, private receipts, internal planning folders, and claims that cannot be supported publicly. An embedded local Windows filesystem reference in the database source document is explicitly excluded.

Recommendations such as a 90-day active-retention period are presented as discovery starting points, never as OCI defaults or universal requirements. Service availability and supported telemetry vary by database deployment model and must be validated for the target environment.

## Architecture principles

- Log Analytics is the primary analysis and evidence plane for the described Log Analytics use cases.
- Collection, parsing, retention, query, detection, visualization, forwarding, and response are separate layers with separate acceptance checks.
- Raw parallel forwarding and detection-evidence forwarding are distinct products.
- Splunk remains an optional enterprise SIEM and case-management destination.
- On-premises sources may use OCI Management Agent and, where required, Management Gateway.
- Database telemetry may include supported alert, trace, audit, listener, host, OCI Audit, service, and network logs.
- Database Management, Operations Insights, and APM supply complementary operational context when supported and approved.
- Archive storage is a long-term retention tier with explicit recall and release workflows; it is not equivalent to immediately searchable active storage.
- No local test, rendered diagram, or repository configuration proves a live OCI, Splunk, database, or customer deployment.

## Related project policy

The initial curated portfolio may link to public repositories owned by `adibirzu`, including:

- `oci-log-analytics-detections`
- `oci-splunk`
- `obs`
- `terraform-oci-database-observability`
- `oci-datasafe-log-analytics-dashboards`
- `oci-apm-monitoring`
- `oci-prometheus-otel-monitoring`
- `mcp-oci-logan-server`
- `oci2azurelogs`
- `azurelogs2oci`
- `gcplogs2oci`
- `OCI-Wazuh`
- `octo-observability-demo`

Links must describe the owning repository's role and evidence boundary. The catalog must not copy another repository's implementation or imply that linked repositories form one deployed product.

## Diagram contract

Every architecture view is delivered as Mermaid and editable Excalidraw. Diagrams use tenant-neutral labels and distinguish:

- telemetry/data flow;
- control and notification flow;
- optional paths;
- customer or system responsibility;
- analysis, retention, and external-response boundaries;
- design versus verified runtime evidence.

Mermaid blocks must use GitHub-compatible syntax and pass a parser/render validation. Excalidraw files must contain editable objects, use `fontFamily: 5` for text, contain no embedded external content, and pass JSON/security validation.

## Current repository changes

The current repository receives a customer-oriented use-case catalog in `docs/README.md` and entry links from the root `README.md`. It links the two new service definitions in the public catalog and continues to host technical implementation assets.

The already approved planning-file cleanup moves the durable Splunk design and implementation plan from `docs/superpowers/**` to:

- `docs/SPLUNK_PARALLEL_DESIGN.md`
- `docs/SPLUNK_PARALLEL_IMPLEMENTATION_PLAN.md`

All references and tests are updated. `/.superpowers/` and `/docs/superpowers/` are ignored. Tracked root `.superpowers` runtime files are removed from the Git index without deleting the local working copies.

## Validation and publication gates

Before publication:

1. Run the current repository's focused documentation and sensitive-value tests.
2. Validate every new repository internal link and required heading.
3. Reject customer names, tenancy identifiers, OCIDs, IP addresses, local filesystem paths, credentials, and process-state directories.
4. Parse all Mermaid diagrams.
5. validate all Excalidraw JSON and embedded-content restrictions.
6. Confirm every external repository link resolves to a public repository.
7. Create the public repository, commit only its curated content, push, and verify the GitHub repository and default branch through GitHub API output.

Provider and customer acceptance remain `not_run` unless separately authorized against an exact target.
