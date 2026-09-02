# Splunk Evidence Export Runbook

## Purpose and supported mode

This runbook deploys and operates **Mode 2**, where OCI Log Analytics is the source of truth and a detection-triggered Function exports bounded, normalized evidence to Splunk HEC. It does not turn Log Analytics into a raw log pump. For Mode 1 raw delivery, use the [parallel operations guide](SPLUNK_PARALLEL_OPERATIONS.md) and a reviewed pinned `oci-splunk` release.

Production must use a pinned, reviewed `oci-splunk` ref for any raw path and must not track mutable `main`. The selected immutable ref is commit `a98167404f19be6d18235bccbf1113b59a259c4c`; `2.2.0` is bundled Splunk-app provenance, not a Git tag.

## Prerequisites and ownership

Record the exact profile/account, region, compartment, Log Analytics namespace/log group, one migrated detection ID, owner-approved canary, change/replay windows, stop conditions, HEC owner/index/sourcetype, Vault secret owner, network owner, IAM reviewer, state/DLQ owner, retention/cost/privacy approver, and rollback owner.

Prerequisites are:

- one parsed source and canonical query already proven in Log Analytics;
- one eligible saved-search detection rule and its first Monitoring metric;
- Python 3 available as `python3` for repository validation;
- Terraform/Resource Manager only for a separately approved deployment;
- a reviewed OCI Registry image produced from the deterministic staging context;
- existing Function subnet(s), optional NSGs, DNS/TLS route to the HEC hostname, and OCI service reachability;
- one existing OCI Vault secret containing only the HEC credential;
- approved Splunk index and HEC input; and
- all three opt-in root variables initially `false`.

The repository never asks for or renders the HEC token.

## Ownership and architecture

The Log Analytics owner owns query correctness and the detection metric. The OCI platform owner owns Function, Notifications, state/DLQ, logging, and Terraform. The IAM/network teams own least privilege and connectivity. The Splunk owner owns the HEC token/input/index and search proof. The change/SOC owner approves canary, replay, rollback, and release acceptance.

See editable [export flow](diagrams/logan-splunk-evidence-export.mmd), [sequence](diagrams/logan-splunk-export-sequence.mmd), [IAM boundaries](diagrams/logan-splunk-iam-boundaries.mmd), and [replay state](diagrams/logan-splunk-replay-state.mmd).

```mermaid
sequenceDiagram
  participant D as Detection rule
  participant M as Monitoring/Notifications
  participant F as Export Function
  participant L as Log Analytics
  participant S as Checkpoint/DLQ
  participant H as Splunk HEC
  D->>M: Metric and alarm transition
  M->>F: Alarm notification
  F->>S: Load checkpoint
  F->>L: Bounded canonical query
  F->>H: Sanitized evidence batch
  alt HEC confirmed
    F->>S: Commit checkpoint
  else failed/quarantined
    F->>S: Write DLQ; no checkpoint advance
  end
```

## IAM and network preflight

Render, save privately, and review the placeholder-only IAM categories:

```bash
python3 scripts/splunk_evidence_exporter_cli.py render-iam
```

Create an exact Function dynamic group from the Terraform output `function_dynamic_group_matching_rule`. Scope Log Analytics query/read, the exact Vault secret bundle, named state/DLQ objects, Notifications invocation of the exact Function, and `post-metric-data` only in the exact Function compartment for exporter operational metrics. Review the broader operator family grants and the regional Object Storage lifecycle service grant; the renderer explicitly does not apply policy.

The Function must have no inbound route. Its reviewed existing subnets need OCI service access and HTTPS egress to the exact HEC host. Validate DNS, hostname, certificate chain/private CA trust, port, route table, NSG, firewall, NAT/FastConnect/VPN, and Splunk allowlists. The accepted URL is exactly `https://<SPLUNK_HEC_HOST>/services/collector/event`; the token lives only in Vault.

## Manual OCI Console and Splunk UI procedure

1. In **Log Analytics → Log Explorer**, run the registry query for the exact detection/window. Confirm a positive canary and negative control.
2. Under **Log Analytics → Administration → Detection Rules**, inspect the scheduled rule and its **Metrics** tab. Record the real metric namespace/name/dimensions; do not infer them from a fixture.
3. Under **Identity & Security → Vault**, create a new secret version containing the HEC credential. Record only the secret OCID in the reviewed private change record.
4. Under **Object Storage**, create/select private versioned state and DLQ buckets and apply approved lifecycle policies.
5. Under **Developer Services → Functions**, create the application in existing subnets/NSGs, select the reviewed image/digest, set the environment rendered by `render-function-config`, and enable Function invocation service logs. Keep all trigger paths disabled.
6. Create the exact dynamic group and reviewed IAM policies. Wait for IAM propagation, then verify only the intended resources are accessible.
7. Under **Developer Services → Application Integration → Notifications**, create the evidence trigger topic and a separate operational-alert topic. Do not yet create/enable the Function subscription.
8. Under **Monitoring → Alarm Definitions**, create the detection alarm disabled. Keep the exporter Function-error alarm actions disabled until its operational destination is reviewed.
9. In Splunk Web **Settings → Data Inputs → HTTP Event Collector**, create/inspect the approved token, index, sourcetype `oci:logan:detection`, TLS, and optional indexer acknowledgment. Store the token in Vault, not in this repository or a receipt.
10. At the approved canary window, create the Function subscription, enable only the reviewed detection alarm/action, generate one safe event, and follow [E2E validation](SPLUNK_E2E_VALIDATION.md).

Expected output after deployment but before canary is a disabled alarm/action, optionally absent Function subscription, versioned private buckets, service logs, a digest-reviewed Function, and no HEC event. After canary, expect a bounded query receipt, HEC confirmation, checkpoint commit, and searchable Splunk event.

## Scripted flow with separate approvals

All commands run from the repository root. Only the repository CLI previews, validators, and deterministic Function context staging are offline. Image build/publish, Terraform dependency initialization, provider read/plan, apply, canary, and replay are separate phases with separate evidence and approvals.

### 1. Offline plan and preflight

```bash
python3 scripts/splunk_evidence_exporter_cli.py plan --json
python3 scripts/splunk_evidence_exporter_cli.py validate-config
python3 scripts/splunk_evidence_exporter_cli.py render-function-config
python3 scripts/splunk_evidence_exporter_cli.py render-iam
```

Expected output includes `offline: true`, `external_calls: []`, two disabled modes, nine detections, `credentials_present: false`, a disabled Function template, and placeholder IAM categories requiring scope review.

### 2. Stage and inspect the offline Function context

Use a new empty temporary destination:

```bash
python3 stack/modules/splunk_evidence_exporter/function/stage_build_context.py --output /tmp/splunk-evidence-exporter-build-context
```

Expected output is a deterministic context and `build-context-manifest.json` with SHA-256 digests. Inspect every staged file/manifest. Staging is offline and is not a build or publish receipt.

Before any image is accepted for Terraform or Function deployment, follow the
[dependency lock and pre-live attestation gate](SPLUNK_FUNCTION_DEPENDENCY_LOCK.md).
The gate checks an externally generated hash lock (including transitives),
SBOM, passing SCA/SAST/IaC/container scans, signature, source-manifest hash,
and the exact immutable image digest. It remains offline and rejects local
examples or missing/mismatched receipts; it does not perform OCI, registry, or
Splunk validation.

### 3. Obtain build approval

**Build approval** is separate. Only then may the image owner run the documented `fn build`, scan/sign the image, push it through the approved OCI Registry pipeline, and return an immutable image reference/digest. These dependency/download/registry actions may use networks and credentials; record their own receipts.

### 4. Initialize Terraform dependencies without changing infrastructure

Keep all three root enable variables `false`. Review the Terraform CLI/provider source and the configured backend before running:

```bash
terraform -chdir=stack init
terraform -chdir=stack validate
```

`terraform init` may contact provider registries; `terraform plan` loads configured credentials and may read OCI or configured state. Neither phase mutates infrastructure, but neither phase is offline or credential-free. Initialization can also access a configured backend and writes dependency metadata locally; validation uses that initialized configuration.

### 5. Create and review a saved Terraform provider plan

Keep these root variables false during the first preview:

```hcl
enable_splunk_evidence_exporter              = false
enable_splunk_evidence_exporter_alarm_actions = false
enable_splunk_evidence_exporter_subscription  = false
```

After target/IAM/network/image review, set only `enable_splunk_evidence_exporter = true` in a private reviewed tfvars file; leave alarm actions and subscription false. Required non-defaults include the existing Vault secret OCID, Object Storage namespace, Function subnet IDs, reviewed image and optional digest, exact HEC event URL, and target index.

```bash
terraform -chdir=stack plan -var-file=<REVIEWED_TFVARS_PATH> -out=<SAVED_PLAN_PATH>
```

The provider plan uses the already reviewed target and credentials. Expected output creates only the scoped exporter resources selected by inputs, creates no VCN/subnet/Vault secret/HEC token, and leaves the Function-error alarm actions and Function subscription disabled. Existing bucket names cause reuse; empty names create private versioned buckets with lifecycle defaults. Treat plan files as sensitive because they can contain identifiers.

### 6. Obtain apply approval and apply the exact saved plan

**Apply approval** must bind the reviewed plan digest, profile/account, region, compartment, resource list, cost, owner, window, and rollback. Only after approval:

```bash
terraform -chdir=stack apply <SAVED_PLAN_PATH>
```

The sensitive outputs identify created resources and the exact dynamic-group matching rule. Do not publish them. Apply proves resources are configured, not that the Function can query, deliver, or be searched.

### 7. Review canary plan and obtain canary approval

```bash
python3 scripts/splunk_evidence_exporter_cli.py canary-plan
```

This command is non-executing. **Canary approval** is a separate target-bound decision. Enable only the reviewed alarm/action and exact Function subscription through Console or an independently reviewed saved Terraform plan, then generate one authorized event. Stop on unexpected volume, unauthorized fields, incorrect target, HEC rejection, missing state, or network/TLS failure.

### 8. Review replay plan and obtain replay approval

```bash
python3 scripts/splunk_evidence_exporter_cli.py replay-plan
```

This command is non-executing. **Replay approval** must name the sanitized DLQ record/batch, remaining event keys, time window, HEC target/capacity, and stop conditions. There is no live replay command in this repository. An operator must use the reviewed deployed exporter path, require HEC confirmation, and commit the checkpoint only after all remaining batches confirm.

## Configuration defaults and boundaries

The root stack exposes only the enable switches, secret reference, namespace/bucket reuse, subnets/NSGs, image/digest, HEC URL, and index. Module defaults are 512 MiB memory, 120-second Function timeout, 30-day Function log retention, 1,000 rows, 100 events/batch, four attempts, 15-minute lookback, 2-minute overlap, 7,200-second maximum window, `oci:logan:detection`, HEC `response` mode, 10-second HEC timeout, 30-day previous checkpoint versions, 90-day current DLQ, and 30-day previous DLQ versions.

Only the module interface exposes alternative HEC acknowledgment and guardrail values. Any root-stack expansion needs code review and tests; do not invent unsupported Resource Manager fields.

## Validation after each layer

| Layer | Required validation | Evidence |
|---|---|---|
| Collection | Fresh authorized record | Log Analytics time/source receipt |
| Parsing | Required display fields | Sanitized field-presence receipt |
| Log Analytics query | Positive and negative controls | Bounded query result/count |
| Detection rule | Scheduled run completed | Rule execution receipt |
| Monitoring metric | Correct namespace/name/dimensions | Metrics Explorer receipt |
| Alarm | Controlled transition | Alarm history |
| Notifications | Exact Function subscription delivery | Topic/subscription receipt |
| Function | Sanitized invocation and bounded query | Function service log |
| Checkpoint/DLQ | Commit only after confirmation; failure retained | Object version metadata |
| HEC confirmation | `response` success or confirmed indexer ack | Sanitized transport receipt |
| Splunk searchability | Correct index/sourcetype/event key | Search job/result receipt |
| Provider acceptance | All layers plus owner decision | Signed evidence packet |

## Failure modes and expected behavior

- Unknown/malformed alarm: fail closed without echoing its identity or payload.
- Zero evidence rows: `no_evidence`; no HEC call and no checkpoint advance.
- HEC timeout, 429, or 5xx: bounded retry up to four attempts by default, then retryable DLQ.
- HEC 400/401/403, oversized event, or missing secret: quarantine without repeated delivery.
- DLQ write failure: fail closed; do not report success.
- Duplicate invocation: stable event keys permit Splunk-side deduplication; at-least-once receipts remain.
- Indexer-ack mode: checkpoint waits for `/services/collector/ack` confirmation, not only `ackId` issuance.

### Alarm and evidence binding guardrails

Use RAW Monitoring alarms only when their exact operator-configured alarm identity,
metric namespace/name/query, allowed dimensions, and Log Analytics namespace match
the governed registry contract. The exporter treats any notification-supplied
custom detection ID as untrusted. It exports only the registry's explicit
`required_fields` plus bounded identity fields; new query columns are withheld
until reviewed. Retry delay is bounded exponential backoff with jitter, and
checkpoint writes use Object Storage conditional writes so an older concurrent
invocation cannot move the watermark backwards.

## Cost, retention, privacy, and cardinality

Monitor bounded Log Analytics query work, Function memory/time/invocations, Notifications, Vault reads, Object Storage versions/DLQ, Logging retention, outbound egress, HEC throughput, Splunk indexing/license, and operational alarm noise. Defaults are starting guardrails, not a sizing promise or OCI/Splunk service limit.

Evidence defaults to `include_original_content: false`, but selected fields can remain personal or security-sensitive. Minimize fields, restrict both buckets and Splunk index, encrypt in transit/at rest, and align Log Analytics, DLQ, Function-log, and Splunk retention. Keep Monitoring dimensions at three or fewer stable values; high-cardinality user, host, or source values need explicit cost/noise approval.

## Rollback, cleanup, and replay safety

First disable the detection alarm/action and exact Notifications Function subscription. Confirm no new invocations, preserve Log Analytics collection/detection, and reconcile the checkpoint/DLQ/HEC results. Roll back the image/config only with a reviewed plan. Do not delete state/DLQ until replay and audit retention are accepted.

Cleanup may remove module-created resources only after ownership review; never destroy reused subnets, NSGs, Vault secrets, buckets, topics, or Splunk resources. A Terraform destroy plan is a new destructive approval. Preserve sanitized receipts and verify no HEC token, raw payload, OCID, IP, hostname, or customer topology is published.

Replay preserves event keys and is at-least-once. Never advance the checkpoint before every remaining HEC batch is confirmed; preserve failed items in DLQ.

## Evidence class and limitations

Offline commands and Terraform source are **code-backed**; passing local tests is **locally verified**. A Terraform plan is neither configured nor provider verified. Apply makes resources **configured**. Provider verification requires authenticated receipts for all table layers; **release accepted** requires Splunk and change-owner acceptance. This runbook performed no provider action and does not claim live readiness.

## Oracle sources

- [Manage Log Analytics detection rules](https://docs.oracle.com/en-us/iaas/log-analytics/doc/manage-detection-rules.html)
- [Create a Function subscription](https://docs.oracle.com/en-us/iaas/Content/Notification/Tasks/create-subscription-function.htm)
- [Functions resource-principal access](https://docs.oracle.com/en-us/iaas/Content/Functions/Tasks/functionsaccessingociresources.htm)
- [Function and network policies](https://docs.oracle.com/en-us/iaas/Content/Functions/Tasks/functionscreatingpolicies.htm)
- [Log Analytics query policy reference](https://docs.oracle.com/en-us/iaas/Content/Identity/policyreference/loganalyticspolicyreference.htm)
- [Splunk HEC in Splunk Web](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/9.0/get-data-with-http-event-collector/set-up-and-use-http-event-collector-in-splunk-web)
- [Splunk indexer acknowledgment](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/9.2/get-data-with-http-event-collector/about-http-event-collector-indexer-acknowledgment)
