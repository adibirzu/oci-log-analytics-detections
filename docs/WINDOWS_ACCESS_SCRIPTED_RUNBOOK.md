# Windows Access Monitoring: Script-Assisted Runbook

This path uses repository helpers for Windows preflight/install guarding,
synthetic validation, source-association payloads, saved searches/dashboard
deployment, scheduled-task payloads, and disabled alarms. Every live write still
requires an exact reviewed target and explicit approval.

For a console-only procedure, use the
[manual runbook](WINDOWS_ACCESS_MANUAL_RUNBOOK.md). For diagrams, IAM, and the
evidence model, start with the
[fast onboarding overview](WINDOWS_ACCESS_FAST_ONBOARDING.md).

## What is and is not automated

| Stage | Helper | Behavior |
|---|---|---|
| Windows plan/preflight/install/enable | [`management_agent_access_setup.ps1`](../scripts/windows/management_agent_access_setup.ps1) | Plan is offline; preflight is host read-only; install/enable require `-ConfirmInstall` |
| Local event and alert proof | [`windows_eventlog_synthetic.py`](../scripts/windows_eventlog_synthetic.py), [`windows_access_onboarding.py`](../scripts/windows_access_onboarding.py) | Deterministic and tenant-neutral |
| Synthetic fields/parsers/sources | [`setup_log_sources.py`](../scripts/setup_log_sources.py) | Optional lab path; does not replace the three native Windows sources |
| Native source association | [`windows_access_onboarding.py`](../scripts/windows_access_onboarding.py) | Renders OCI CLI JSON; applying it is a separate reviewed mutation |
| Five saved searches and dashboard | [`deploy_dashboard.py`](../scripts/deploy_dashboard.py) | Dry-run by default in this runbook; live import validates queries |
| Scheduled tasks and alarms | [`windows_access_onboarding.py`](../scripts/windows_access_onboarding.py) | Renders five task files and five disabled alarm files; saved-search OCIDs remain blocking placeholders |

The repository does not download the Oracle package or generate an install key.
Those steps remain in the OCI Console because the package digest and response
file are region/identity-specific and the response file contains sensitive
installation material.

## 1. Prepare a clean operator shell

From the repository root, install its normal Python dependencies and confirm the
OCI CLI/profile outside committed files. Set values in the current shell or a
profile-specific untracked `.env.local.<PROFILE>`:

```bash
export OCI_PROFILE='<PROFILE>'
export OCI_REGION='<REGION>'
export OCI_COMPARTMENT_ID='<LA_COMPARTMENT_OCID>'
export LA_NAMESPACE='<LA_NAMESPACE>'
export LOG_ANALYTICS_LOG_GROUP_ID='<LOG_GROUP_OCID>'
```

Never commit these values. Before a live write, independently confirm the
profile, tenancy, region, compartment, agent, entity, and log group.

## 2. Run deterministic local proof

```bash
python3 scripts/windows_access_onboarding.py plan --json
python3 scripts/windows_eventlog_synthetic.py generate
python3 scripts/windows_eventlog_synthetic.py validate
python3 scripts/windows_access_onboarding.py validate-local --json
python3 -m pytest \
  scripts/test_windows_access_onboarding.py \
  scripts/test_windows_eventlog_synthetic.py \
  scripts/test_setup_log_sources.py \
  scripts/test_deploy_dashboard.py -q
```

Expected outcome: all five access-alert contracts trigger against deterministic
fixtures. This is local evidence only.

## 3. Copy and run the guarded Windows helper

Download or copy
[`scripts/windows/management_agent_access_setup.ps1`](../scripts/windows/management_agent_access_setup.ps1)
to the authorized Windows Server. Verify the copied file's digest against the
reviewed repository revision.

Plan mode runs on any PowerShell host and changes nothing:

```powershell
pwsh -NoProfile -File .\management_agent_access_setup.ps1 -Mode Plan
```

Run the full read-only preflight in an elevated session and supply the target
region so both Log Analytics HTTPS endpoints are tested:

```powershell
pwsh -NoProfile -File .\management_agent_access_setup.ps1 `
  -Mode Preflight `
  -Region '<REGION>'
```

Exit code `0` means the helper observed Administrator context, WMIC, JDK/JRE 8
update 281 or newer, at least 300 MB free disk, a working Windows time-service
status call, three enabled channels, and successful TCP 443 tests. Exit code `2`
means review the JSON checks and fix the failed prerequisite. A successful time
service status still does not independently prove OCI clock skew is below five
minutes.

### Install a new standalone agent

After downloading and checksum-verifying Oracle's Windows package, creating an
install key, and adding `Service.plugin.logan.download=true` to the protected
response file:

```powershell
pwsh -NoProfile -File .\management_agent_access_setup.ps1 `
  -Mode Install `
  -Region '<REGION>' `
  -InstallerDirectory 'C:\approved\oracle-management-agent' `
  -ResponseFile 'C:\secure\input.rsp' `
  -ConfirmInstall
```

The wrapper validates paths and the Log Analytics plug-in setting before calling
Oracle's `installer.bat <response-file>`. It never prints the response file.

### Start an existing stopped agent

```powershell
pwsh -NoProfile -File .\management_agent_access_setup.ps1 `
  -Mode Enable `
  -Region '<REGION>' `
  -ConfirmInstall
```

Verify `mgmt_agent`, its runtime log, the OCI agent resource, and the deployed
Log Analytics plug-in. Do not reinstall over an existing agent.

## 4. Run sanitized OCI read-only discovery

List all Oracle-defined sources and confirm the three exact source names:

```bash
oci log-analytics source list-sources \
  --profile "$OCI_PROFILE" --region "$OCI_REGION" \
  --namespace-name "$LA_NAMESPACE" \
  --compartment-id "$OCI_COMPARTMENT_ID" \
  --is-system ALL --all
```

Also list the exact Management Agent, `Host (Windows)` entity, log group, and
existing associations. Treat an empty list as inconclusive until region,
compartment, permissions, and pagination are checked.

## 5. Render a reviewable OCI CLI bundle

Create a restricted temporary directory. The rendered files contain OCIDs and
must never be committed:

```bash
WINDOWS_ACCESS_BUNDLE_DIR="$(mktemp -d)"
chmod 700 "$WINDOWS_ACCESS_BUNDLE_DIR"

python3 scripts/windows_access_onboarding.py render-cli-bundle \
  --output-dir "$WINDOWS_ACCESS_BUNDLE_DIR" \
  --namespace-name "$LA_NAMESPACE" \
  --log-analytics-compartment-id '<LA_COMPARTMENT_OCID>' \
  --metric-compartment-id '<METRIC_COMPARTMENT_OCID>' \
  --alarm-compartment-id '<ALARM_COMPARTMENT_OCID>' \
  --notification-topic-id '<NOTIFICATION_TOPIC_OCID>' \
  --agent-id '<MANAGEMENT_AGENT_OCID>' \
  --entity-id '<WINDOWS_ENTITY_OCID>' \
  --log-group-id '<LOG_GROUP_OCID>'
```

The bundle contains:

- `association.json`
- five `scheduled-task-*.json` files
- five `alarm-*.json` files
- `manifest.json` with the mutation order and verification gates

Rendering does not contact OCI. The command refuses to overwrite an existing
bundle unless `--force` is explicitly supplied.

## 6. Apply and verify native source association

Open `association.json` and verify the exact namespace, compartment, agent,
entity, log group, and these three internal source names:

- `MsftWinEventSecurityLogSource`
- `MsftWinEventSystemLogSource`
- `MsftWinEventApplicationLogSource`

After explicit approval:

```bash
oci log-analytics assoc upsert-assocs \
  --profile "$OCI_PROFILE" --region "$OCI_REGION" \
  --from-json "file://$WINDOWS_ACCESS_BUNDLE_DIR/association.json" \
  --wait-for-state SUCCEEDED
```

Immediately re-list the entity's associations. Then wait for and query one new
record from Security, System, and Application. Do not proceed to alerting if the
association work request fails or collection metrics show upload errors.

## 7. Optional synthetic parser/source lab path

This path proves custom JSON parser/source mechanics and fixture ingestion. It
does not replace native continuous Windows collection:

```bash
python3 scripts/setup_log_sources.py --windows-access-only --dry-run
python3 scripts/windows_eventlog_synthetic.py ingest --dry-run
```

After separate approval in a test compartment:

```bash
python3 scripts/setup_log_sources.py --windows-access-only
python3 scripts/windows_eventlog_synthetic.py ingest
```

Skip this section for a native-only production onboarding.

## 8. Deploy the five saved searches and dashboard

Dry-run first:

```bash
python3 scripts/deploy_dashboard.py \
  --dashboard-name 'SOC: Windows Access Monitoring' \
  --dry-run
```

Review target and live-query validation output. After approval:

```bash
python3 scripts/deploy_dashboard.py \
  --dashboard-name 'SOC: Windows Access Monitoring'
```

Do not use `--skip-live-validation` for customer acceptance. Open the resulting
dashboard with the correct scope filters and verify all five widgets render.

## 9. Resolve saved-search OCIDs and create scheduled tasks

Each generated scheduled-task file deliberately contains a value such as
`<FAILED_LOGON_BURST_SAVED_SEARCH_OCID>`. Resolve every OCID from the exact
saved-search display name created by the dashboard import:

```bash
oci management-dashboard saved-search list \
  --profile "$OCI_PROFILE" --region "$OCI_REGION" \
  --compartment-id '<LA_COMPARTMENT_OCID>' \
  --display-name '<EXACT_SAVED_SEARCH_DISPLAY_NAME>' \
  --all
```

Stop if the display name returns zero or multiple resources. Replace each
placeholder in its corresponding task file and review the complete JSON.

Apply one scheduled task at a time:

```bash
oci log-analytics scheduled-task create-standard-task \
  --profile "$OCI_PROFILE" --region "$OCI_REGION" \
  --from-json "file://$WINDOWS_ACCESS_BUNDLE_DIR/scheduled-task-failed-logon-burst.json" \
  --wait-for-state ACTIVE
```

Repeat only after the prior task is active. For each task, verify
`ScheduledTaskExecutionStatus` and confirm its numeric metric appears under
namespace `logan_windows_access` and resource group `windows_access`.

## 10. Create disabled alarms and test one canary

The generated alarm files have `isEnabled: false`. Create one at a time:

```bash
oci monitoring alarm create \
  --profile "$OCI_PROFILE" --region "$OCI_REGION" \
  --from-json "file://$WINDOWS_ACCESS_BUNDLE_DIR/alarm-failed-logon-burst.json"
```

Verify the alarm exists disabled and points to the approved Notifications topic.
After the notification owner approves a canary and the metric has emitted:

```bash
oci monitoring alarm update \
  --profile "$OCI_PROFILE" --region "$OCI_REGION" \
  --alarm-id '<CANARY_ALARM_OCID>' \
  --is-enabled true
```

Test notification delivery separately from query and metric generation. Enable
the remaining alarms only after the canary path succeeds.

## 11. Provider E2E and cleanup

Use approved historical rows or isolated lab actions to prove the five searches.
Do not create production users or privileged memberships solely for testing.
Record separately:

1. Windows event exists in Event Viewer.
2. Agent collection metrics show upload activity without upload failure.
3. Log Explorer returns the event with expected fields.
4. Saved search and dashboard show it.
5. Scheduled task emits the numeric metric.
6. Alarm evaluates the metric.
7. Approved canary notification reaches its owner.

After handoff, remove the temporary bundle according to the customer's handling
policy. Rollback removes only this entity's three associations and disables this
pack's scheduled tasks/alarms; it does not uninstall a shared agent, delete a log
group, or purge logs.

