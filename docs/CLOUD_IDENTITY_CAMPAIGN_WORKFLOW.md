# Cloud Identity Campaign Hunting Workflow

This workflow turns a recent identity-led cloud intrusion pattern into OCI Log
Analytics hunts without copying vendor-specific queries or assuming that Azure,
OCI, and endpoint schemas are interchangeable. The mapped behavior is:

1. a valid identity signs in from an unexpected origin;
2. the identity enumerates users, groups, policies, compute, network, database,
   and object-storage resources;
3. the actor attempts persistence with a new token, API key, or other credential;
4. the actor retrieves secrets or object data; and
5. the actor may expand into remote access, exfiltration, or destructive actions.

The campaign model is based on Microsoft's published Storm-2949 investigation,
but the Logan queries are independently authored against OCI Audit fields and
are useful for any identity-led control-plane takeover.

## Required telemetry

The three primary hunts require `OCI Audit Logs` with parsed `Event Type`,
`User Name`, `Source IP`, `Resource Name`, and `Status` fields. The broader
dashboard also uses Windows Sysmon and network telemetry for RMM and exfiltration
follow-up. Confirm collection with a source-only query before evaluating a zero
result as evidence of absence.

## Hunt sequence

| Phase | Logan query | Analyst decision |
| --- | --- | --- |
| Identity-to-control-plane correlation | `hunting/cloud_identity_control_plane_takeover.json` | Is one identity spanning sign-in, discovery, persistence, and collection? |
| Discovery | `hunting/cloud_control_plane_discovery_burst.json` | Is the breadth and pace consistent with approved inventory tooling? |
| Collection | `hunting/cloud_secret_and_object_collection.json` | Were sensitive secrets, objects, or pre-authenticated requests accessed? |
| Remote access | `hunting/rmm_post_compromise_activity.json` | Did the actor establish interactive endpoint access? |
| Exfiltration | `hunting/exfiltration_after_initial_access_2025_2026.json` | Did data leave through object, application, or network paths? |
| Impact | `hunting/oci_resource_deletion_wave.json` | Did the same identity begin deleting or terminating resources? |

Run the raw filter first, then the aggregation. Pivot on the identity and source
IP across the same time window. A match is a lead, not proof: compare change
records, automation identities, expected regions, and the principal's normal
administrative role.

## Synthetic validation

The repository's tenant-neutral OCI Audit corpus already contains the necessary
behavioral sequence: multi-service enumeration, sign-in plus token creation,
object retrieval, and creation of a pre-authenticated request. Generate and
validate it locally with:

```bash
python3 scripts/generate_dashboard_data.py --days 21 --validate
python3 -m pytest scripts/test_cross_siem_detection_catalog.py -q
```

This proves the scenario and artifact contracts locally. It does not prove live
parser compatibility or matching rows in a tenancy.

## Controlled live workflow

Use only an explicitly approved profile and compartment. Keep the profile,
namespace, compartment identifier, tenancy identifier, hostnames, users, and
live result payloads out of committed artifacts.

```bash
# Read-only parser and field validation.
OCI_PROFILE="PROFILE_NAME" python3 scripts/parse_validate_all_queries.py \
  --json docs/health/parse-validate-all.json

# Validate the synthetic files before upload.
OCI_PROFILE="PROFILE_NAME" python3 scripts/ingest_test_data.py --validate

# State-changing steps: run only after reviewing the exact target and plan.
OCI_PROFILE="PROFILE_NAME" python3 scripts/ingest_test_data.py --mode direct
OCI_PROFILE="PROFILE_NAME" python3 scripts/deploy_dashboard.py \
  --validate --dashboard-name "SOC: 2025-2026 Threat Hunting Dashboard"
```

After ingestion, execute the three focused query files over `21d`, record only
redacted counts and pass/fail status, and open the dashboard to confirm every new
widget contains representative data. Deployment success alone is not a data-hit
test.

## Response actions

When the sequence is unexplained, revoke suspicious credentials and sessions,
preserve Audit evidence, restrict the identity, review policy and group changes,
rotate exposed secrets, invalidate pre-authenticated requests, and inspect all
resources accessed by the identity. Coordinate containment through the owning
incident-response process; do not automate destructive remediation from a hunt.

## Primary reference

- [Microsoft: How Storm-2949 turned a compromised identity into a cloud-wide breach](https://www.microsoft.com/en-us/security/blog/2026/05/18/storm-2949-turned-compromised-identity-into-cloud-wide-breach/)
