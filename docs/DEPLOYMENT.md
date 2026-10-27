# Deployment Guide

This is the supported deployment and workflow guide for customer-owned OCI Log Analytics environments. For migration sequencing, source onboarding, security use cases, and SIEM-forwarding guidance, begin with the [Migration and Security Guide](MIGRATION_AND_SECURITY_GUIDE.md).

## Supported Customer Flow

This repository packages OCI Log Analytics detection content; it does not collect customer OCI credentials or apply content directly from the Forge browser. The supported path is:

1. Use Forge **Deploy to OCI** to download the Resource Manager package.
2. Create an OCI Resource Manager stack from that package.
3. Select the target compartment and deployment options in OCI.
4. Review the Terraform plan.
5. Apply with a principal that has the required IAM permissions.

The package contains selected tracked working bytes for the stack, deployment
scripts, queries, mappings and schemas, or the same bytes from a verified staged
inventory. It excludes local credential/state formats and generated `test_data/`.
Content review and scanning remain required; selection alone is not proof that
every tracked value is suitable for distribution.

## Before You Apply

Confirm all of the following in the customer tenancy:

- The intended compartment and region are selected in Resource Manager.
- The applying principal has only the IAM permissions required for the planned resources.
- Required log sources and parser fields have been validated with representative events.
- The planned dashboards, saved searches, streaming/service-connector resources, and log sources are understood by the service owner.
- Alert routing, data retention, rollback ownership, and downstream SIEM forwarding policy are defined.
- For Splunk, each source/detection has a reviewed Mode 1 raw, Mode 2 evidence, hybrid, or disabled policy.
- Any Mode 1 production package uses a reviewed `adibirzu/oci-splunk` tag or commit and must not track mutable `main`; the selected immutable ref is commit `a98167404f19be6d18235bccbf1113b59a259c4c` (`2.2.0` is bundled app provenance, not a Git tag).

The Forge UI is intentionally not a credential form. It can prepare a package and open OCI Resource Manager, but it cannot select a tenancy, run a plan, or apply changes on the customer's behalf.

### Optional Splunk evidence exporter

Mode 2 is opt-in. `enable_splunk_evidence_exporter`, `enable_splunk_evidence_exporter_alarm_actions`, and `enable_splunk_evidence_exporter_subscription` all default to `false`. Start with the offline repository CLI plan/preflight and Function-context staging, obtain build approval, initialize dependencies, and create a saved Terraform plan with alarm actions/subscription still disabled. Terraform init may access registries; plan loads credentials and may read OCI/state, though neither applies changes. Obtain separate apply and canary approvals. Replay is another explicit approval and the repository only renders a non-executing replay plan.

The exporter module creates no VCN, subnet, Vault secret, HEC input, or Splunk index. It consumes existing reviewed subnet/NSG IDs, image/digest, Vault secret OCID, Object Storage namespace/buckets, HTTPS HEC event URL, and index. The token must never enter Terraform variables. See the complete [Splunk evidence export runbook](SPLUNK_EVIDENCE_EXPORT_RUNBOOK.md) and [E2E validation guide](SPLUNK_E2E_VALIDATION.md).

## Package Contents and Local Verification

Build the same package that Forge serves in dynamic deployments:

```bash
python3 scripts/build_orm_stack.py --out /tmp/oci-log-analytics-deployment.zip
unzip -t /tmp/oci-log-analytics-deployment.zip
terraform -chdir=stack init -backend=false
terraform -chdir=stack validate
```

### Package source inventory and executable closure

The archive retains sibling `stack/` and `scripts/` directories. Configure the
Resource Manager source working directory as `stack`. Provisioners execute
`../scripts/...` from that directory. The default source/dashboard entry points
are locally exercised from the extracted layout; optional ingestion still needs
operator-supplied synthetic or approved input data because raw `test_data/` is
not distributed.

The owning builder selects tracked working files from the repository root, or
validates a versioned path-to-SHA-256 inventory for a Git-free export. It rejects
noncanonical paths, missing/tampered selected bytes, symlinks, special files and
selected JSON Terraform variable files before replacing output. Validation
covers local Python imports, literal Terraform file/module dependencies and
dashboard query references. Static checks do not prove arbitrary computed imports
or file references. No browser input supplies inventory authority or credentials.

ZIP member ordering, timestamps and modes are deterministic. Package creation
uses a temporary file and atomic replacement; invalid input preserves an existing
archive. Runtime staging prepares its replacement before moving an existing
runtime and retains the inventory used by the unchanged Forge download caller.
If replacement fails or staging receives INT, TERM or HUP before completion, the
stager attempts to restore the previous runtime. If restoration fails or the
destination is occupied, it retains `previous/` inside the staging directory and
prints its recovery path to stderr; preserve that directory for operator recovery.
The executable regression cases are in
[`scripts/test_hunting_runtime_staging.py`](../scripts/test_hunting_runtime_staging.py).
The staging generator also includes required package inputs such as
`requirements.txt`; exported package generation does not require `.git`.

For a standalone Git-free export, run from the repository root:

```bash
python3 scripts/build_orm_stack.py --stage-runtime ./orm-runtime
python3 ./orm-runtime/scripts/build_orm_stack.py --out ./oci-log-analytics-deployment.zip
```

The export destination must be absent. It contains `.orm-source-inventory.json`
with schema version `forge.orm-source-inventory.v1` and a `files` object mapping
selected relative paths to SHA-256 digests. Keep it with the exported sources;
the builder verifies it automatically. `--include-runtime-manifest` requires
`--stage-runtime` and adds only `test_data/manifest.json` for Forge runtime use;
that metadata is outside the package inventory and is not included in the ZIP.

Locally verified: 42 tests plus 24 subtests passed in a coordinator rerun with all
network and operator-credential access denied. Actual extracted default commands
used recording SDK/query/CLI boundaries. Git-free staging, deterministic bytes,
missing dependencies, stale/tampered inventories, path/output safety and private
JSON variable refusal were exercised. Scoped Ruff, ShellCheck, Bash syntax,
whitespace, changed-source sensitive scanning and the final code-diff secret scan
passed. Independent review's JSON variable-file finding was repaired and resolved.

A broader archive diagnostic still reports 148 sensitive-value candidates and
12 generic-key candidates. All were factually classified as synthetic examples,
published indicators, public resolver/control references or verified content
digests; all 31 flagged files match the reviewed public baseline byte-for-byte.
No actual private credential or customer value was established. These scan
statuses remain failed diagnostics; triage is not a clean-scan or release claim.
Canonical detection content and optional operator tooling remain intact.

Full application/image, provider plans/applies, OCI-DEMO snapshot admission,
Marketplace and release acceptance remain separate. No generated archive is
published by this source change.

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
| Forge dynamic deployment package | Customer request in Forge | None in Forge | Produces a zip under the package source contract above; customer plans/applies in OCI |
| Resource Manager plan/apply | Customer action in OCI | Customer OCI session and IAM | Creates/updates only the reviewed tenancy resources |

Do not make a missing environment secret, a disabled GitHub Pages configuration, or a failed live OCI query look like successful deployment. The preflights distinguish a deliberate skip from a genuine validation or apply failure.
