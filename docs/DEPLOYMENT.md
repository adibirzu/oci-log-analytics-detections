# Deployment Guide

This is the supported deployment and workflow guide for customer-owned OCI Log Analytics environments. For migration sequencing, source onboarding, security use cases, and SIEM-forwarding guidance, begin with the [Migration and Security Guide](MIGRATION_AND_SECURITY_GUIDE.md).

## Supported Customer Flow

This repository packages OCI Log Analytics detection content; it does not collect customer OCI credentials or apply content directly from the Forge browser. The supported path is:

1. Use Forge **Deploy to OCI** to download the Resource Manager package.
2. Create an OCI Resource Manager stack from that package.
3. Select the target compartment and deployment options in OCI.
4. Review the Terraform plan.
5. Apply with a principal that has the required IAM permissions.

The package contains the committed stack, deployment scripts, queries, mappings, and schemas. It excludes credentials, Terraform state, ignored tooling state, and generated `test_data/` so an ORM upload cannot accidentally carry local tenancy data.

## Before You Apply

Confirm all of the following in the customer tenancy:

- The intended compartment and region are selected in Resource Manager.
- The applying principal has only the IAM permissions required for the planned resources.
- Required log sources and parser fields have been validated with representative events.
- The planned dashboards, saved searches, streaming/service-connector resources, and log sources are understood by the service owner.
- Alert routing, data retention, rollback ownership, and downstream SIEM forwarding policy are defined.

The Forge UI is intentionally not a credential form. It can prepare a package and open OCI Resource Manager, but it cannot select a tenancy, run a plan, or apply changes on the customer's behalf.

## Package Contents and Local Verification

Build the same package that Forge serves in dynamic deployments:

```bash
python3 scripts/build_orm_stack.py --out /tmp/oci-log-analytics-deployment.zip
unzip -t /tmp/oci-log-analytics-deployment.zip
terraform -chdir=stack init -backend=false
terraform -chdir=stack validate
```

The package builder includes committed deployment surfaces only. It rejects an incomplete stack and excludes local state, credentials, caches, and disposable test data.

## GitHub Pages Preflight

The `Forge GitHub Pages` workflow always builds the static export. Its deployment step now performs a GitHub Pages availability check first:

- When Pages is enabled, the workflow deploys normally.
- When Pages is disabled, the build succeeds and the deployment job is skipped with an Actions summary explaining the required repository setting.

To enable the static site, set **Settings → Pages → Build and deployment → Source** to **GitHub Actions**, then rerun the workflow. This setting requires repository administration and cannot be safely enabled by the workflow itself.

## Scheduled Sentinel Live Validation

The scheduled/manual live lane needs the `OCI_CONFIG` and `OCI_API_KEY_PEM` secrets in the `live-oci` GitHub environment. It now runs a non-failing preflight:

- When both secrets are present, live validation and promotion proceed.
- When either secret is absent, the live lane is skipped and the Actions summary explains what to configure.

Pull request and local conversion lanes remain credential-free.

## Workflow Matrix

| Workflow | Trigger | Credential requirement | Expected result |
| --- | --- | --- | --- |
| Rule conversion and catalog generation | Local development / pull request | None | Rebuilds generated artifacts and validates contracts |
| Sentinel local conversion | Local development / pull request | None | Produces reports and candidate validation without promotion |
| Sentinel live promotion | Scheduled or manual | `live-oci` environment secrets | Promotes only parser-passing, live-validated candidates |
| Forge GitHub Pages | Push/workflow dispatch | Repository Pages enabled | Builds static Forge and deploys when Pages is available |
| Forge dynamic deployment package | Customer request in Forge | None in Forge | Produces a committed-content zip; customer plans/applies in OCI |
| Resource Manager plan/apply | Customer action in OCI | Customer OCI session and IAM | Creates/updates only the reviewed tenancy resources |

Do not make a missing environment secret, a disabled GitHub Pages configuration, or a failed live OCI query look like successful deployment. The preflights distinguish a deliberate skip from a genuine validation or apply failure.
