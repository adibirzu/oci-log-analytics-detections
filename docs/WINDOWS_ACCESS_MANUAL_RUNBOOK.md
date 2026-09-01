# Windows Access Monitoring: Manual Console Runbook

This runbook is the click-by-click path for operators who prefer the OCI Console
and Windows administrative tools. It creates the same end state as the
[script-assisted runbook](WINDOWS_ACCESS_SCRIPTED_RUNBOOK.md): three native
Windows channels, five saved searches, one dashboard, five scheduled-search
detection rules, and five initially disabled Monitoring alarms.

Return to the [fast onboarding overview](WINDOWS_ACCESS_FAST_ONBOARDING.md) for
architecture, policy templates, workflow diagrams, and evidence definitions.

> This is an operator procedure, not evidence that a customer host is already
> collecting. Record the exact tenancy, region, compartments, host, agent,
> entity, log group, notification owner, and approval before a write.

## Completion record

Fill this in the customer's change record, not in the repository:

| Item | Required value or evidence |
|---|---|
| OCI identity and region | Profile/federated identity and region confirmed |
| Compartments | Agent, Log Analytics, dashboard, metric, and alarm compartments |
| Windows target | One authorized Windows Server and owner |
| Collection target | Management Agent, `Host (Windows)` entity, and log group |
| Detection settings | Business hours, timezone, exclusions, and response owner |
| Notification route | Existing approved Notifications topic and subscriber owner |
| Stop conditions | Target mismatch, unexpected volume, policy denial, or processing errors |

## 1. Confirm the supported Windows path

For Windows Server, use the **standalone Management Agent installation**. The
Oracle Cloud Agent Management Agent plug-in path is currently documented for
supported Linux compute images, not Windows compute instances.

Current Oracle prerequisites for standalone Windows Server include:

- A currently supported 64-bit Windows Server release listed by Oracle.
- At least 300 MB free disk space.
- JDK or JRE 8, update 281 or newer.
- Windows Management Instrumentation Command-line (`WMIC`) enabled.
- Synchronized host time; OCI authentication rejects excessive clock skew.
- Outbound HTTPS 443 to Management Agent services and, for Log Analytics,
  `loganalytics.<region>.oci.oraclecloud.com` and
  `telemetry-ingestion.<region>.oraclecloud.com`.
- An elevated Administrator session for installation.

Verify the current matrix before every customer install in Oracle's
[Management Agent prerequisites](https://docs.oracle.com/en-us/iaas/management-agents/doc/perform-prerequisites-deploying-management-agents.html).

### Manual Windows preflight

Run in elevated PowerShell:

```powershell
(Get-CimInstance Win32_OperatingSystem).Caption
Get-PSDrive -Name $env:SystemDrive.TrimEnd(':')
Get-Command wmic.exe
Get-Command java.exe
java.exe -version
w32tm.exe /query /status
Get-WinEvent -ListLog Security,System,Application |
  Select-Object LogName,IsEnabled,RecordCount
auditpol.exe /get /category:*
Test-NetConnection "loganalytics.<REGION>.oci.oraclecloud.com" -Port 443
Test-NetConnection "telemetry-ingestion.<REGION>.oraclecloud.com" -Port 443
```

Do not continue until the required channels are enabled and the effective audit
policy produces the events needed by the customer. If Group Policy owns the
audit configuration, change the approved GPO rather than a local override.

## 2. Create or verify OCI IAM

1. Open **Identity & Security → Policies**.
2. Confirm the Log Analytics service policy and the operator policies shown in
   the [overview policy section](WINDOWS_ACCESS_FAST_ONBOARDING.md#2-apply-the-minimum-policies).
3. Open **Identity & Security → Dynamic Groups**.
4. Create or verify the compartment-bound Management Agent dynamic group.
5. Create or verify the compartment-bound `loganalyticsscheduledtask` dynamic
   group.
6. Apply Oracle's **Allow continuous log collection using management agent
   dynamic groups** and **Allow detection rule dynamic groups to run** policy
   templates, then review their resolved statements.
7. Confirm the operator can manage Management Dashboards in the dashboard
   compartment and alarms in the alarm compartment.

Do not widen a compartment-bound policy merely to bypass a `404` or empty list.
First confirm region, compartment, resource type, and the exact policy reference.

## 3. Download the agent and create an install key

1. Open **Observability & Management → Management Agent → Administration**.
2. Under **Software downloads**, download **Agent for WINDOWS (X86_64)**.
3. Compare the downloaded file's SHA-256 digest with the digest displayed by
   Oracle. Do not install a package whose digest does not match.
4. Open the **Install keys** tab and select **Create key**.
5. Select the compartment in which the Management Agent resource must exist.
6. Set the smallest practical installation count and validity period.
7. Create the key and select **Download Key to File** to obtain the response-file
   template.
8. Store the response file in a restricted directory. It contains credential
   material and must not be committed, pasted into a ticket, or logged.
9. Add this exact Log Analytics plug-in setting:

```text
Service.plugin.logan.download=true
```

Oracle procedure: [Install Management Agents](https://docs.oracle.com/en-us/iaas/management-agents/doc/install-management-agent-chapter.html).

## 4. Install and verify the Windows agent

1. Extract the Windows agent ZIP into an approved staging directory.
2. Open an elevated **Command Prompt** in the extracted directory.
3. Run Oracle's documented command:

```bat
installer.bat C:\secure\input.rsp
```

4. Confirm the command reports successful installation and configuration.
5. Inspect `C:\Oracle\mgmt_agent\installer-logs` if installation fails.
6. Verify the service and runtime log:

```powershell
sc.exe query mgmt_agent
Get-Content 'C:\Oracle\mgmt_agent\agent_inst\log\mgmt_agent.log' -Tail 100
```

7. Move or securely remove the response file according to the customer's secret
   handling policy.
8. In **Observability & Management → Management Agent → Agents**, confirm the
   exact new agent is `ACTIVE` and that the Log Analytics plug-in is deployed.

An `ACTIVE` agent is installation evidence, not collection evidence.

## 5. Create or map the Windows entity

1. Open **Observability & Management → Log Analytics → Administration**.
2. Select **Entities**.
3. Search for an existing entity representing the exact server.
4. If none exists, select **Create Entity** and choose **Host (Windows)**.
5. Use the approved host identity and select the Management Agent installed in
   the previous step.
6. Save the entity and verify the agent mapping on the entity details page.

Do not create a second entity merely because the expected entity is in another
compartment or region. Resolve the scope first.

## 6. Associate the three Oracle-defined sources

1. In Log Analytics Administration, select **Sources**.
2. Set **Creation Type** so Oracle-defined sources are visible.
3. Locate each exact source and verify its internal name:

| Channel | Display name | Internal name |
|---|---|---|
| Security | `Windows Security Events` | `MsftWinEventSecurityLogSource` |
| System | `Windows System Events` | `MsftWinEventSystemLogSource` |
| Application | `Windows Application Events` | `MsftWinEventApplicationLogSource` |

4. Open a source, go to its associated entities, and configure a **new
   source-entity association**.
5. Select the exact `Host (Windows)` entity and approved log group.
6. Save the association and repeat for the remaining two sources.
7. Do not enable broad auto-association unless onboarding every future Windows
   entity is explicitly intended and approved.

Association starts collection. See Oracle's
[source-entity association procedure](https://docs.oracle.com/iaas/log-analytics/doc/manage-source-entity-association.html).

## 7. Prove collection before creating alerting content

Open **Log Analytics → Log Explorer**, set the correct region, log-group
compartment, entity, and a recent time range, then run:

```text
'Log Source' in ('Windows Security Events', 'Windows System Events', 'Windows Application Events')
| stats count as Events by 'Log Source'
| sort -Events
```

Then verify the required Security IDs:

```text
'Log Source' = 'Windows Security Events'
and 'Event ID' in ('4624', '4625', '4634', '4648', '4672', '4720', '4726', '4732', '4733', '4776')
| stats count as Events by 'Event ID', 'Host Name (Server)'
| sort -Events
```

Inspect representative rows and confirm the fields listed in the
[overview](WINDOWS_ACCESS_FAST_ONBOARDING.md#6-e2e-proof). If rows are missing,
stop here and use the troubleshooting workflow; do not create alarms on an
unproven source.

## 8. Create five saved searches and the dashboard

For each query linked below:

1. Open the JSON file and copy only the value of its `query` property.
2. Paste the query into Log Explorer and run it over a suitable window.
3. Select a summary-table visualization and confirm the numeric metric column
   and grouping fields appear.
4. Select **Save**, enter the query title, description, and target compartment.
5. Select **Add to dashboard**.
6. For the first search, choose **New Dashboard** and name it
   `SOC: Windows Access Monitoring`; for the remaining searches choose the same
   dashboard.

Queries:

- [Failed logon burst](../queries/hunting/windows_access_failed_logon_burst.json)
- [RDP outside business hours](../queries/hunting/windows_access_rdp_after_hours.json)
- [Administrator logon](../queries/hunting/windows_access_administrator_logon.json)
- [New local user](../queries/hunting/windows_access_new_local_user.json)
- [Privileged local group addition](../queries/hunting/windows_access_privileged_group_add.json)

Open the new dashboard, set the correct scope filters and time range, and verify
all five widgets render without parser errors. Oracle procedure:
[Save and Share Log Searches](https://docs.oracle.com/en-us/iaas/log-analytics/doc/save-share-log-searches.html).

## 9. Create scheduled-search detection rules

For each saved search:

1. Open **Log Analytics → Administration → Detection Rules**.
2. Select **Create Rule → Scheduled search detection rule**.
3. Select the saved search and use a 5-minute interval.
4. Select **Monitoring** as the target service.
5. Select the reviewed metric compartment.
6. Use namespace `logan_windows_access` and resource group `windows_access`.
7. Use the numeric query field as the metric name:

| Search | Metric name |
|---|---|
| Failed logon burst | `FailedLogons` |
| RDP outside business hours | `RDPLogons` |
| Administrator logon | `AdministratorLogons` |
| New local user | `UsersCreated` |
| Privileged group addition | `GroupAdds` |

8. Select no more than the three grouping fields produced by the query as
   dimensions.
9. Create the rule and confirm it becomes active/ready.
10. In the rule details, open **Metrics** or **View in Metric Explorer** and
    wait for a numeric data point before creating an enabled alarm.

Custom namespaces beginning with `oci_` or `oracle_` are reserved. See Oracle's
[scheduled-search procedure](https://docs.oracle.com/iaas/log-analytics/doc/create-schedule-run-saved-search.html).

## 10. Create disabled alarm canaries

For each emitted metric:

1. Open **Observability & Management → Monitoring → Alarm Definitions**.
2. Select **Create Alarm** and switch to advanced/MQL mode.
3. Select the metric compartment, namespace `logan_windows_access`, and resource
   group `windows_access`.
4. Use `<MetricName>[5m].sum() > 0` as the MQL expression. The saved-search
   query already performs the event threshold.
5. Select the severity matching the query metadata.
6. Select the approved Notifications topic.
7. Clear **Enable this alarm** so the alarm is created disabled.
8. Save, review the alarm definition, and enable only one approved canary after
   metric and destination ownership are proven.

Alarm procedure: [Creating a Basic Alarm](https://docs.oracle.com/en-us/iaas/Content/Monitoring/Tasks/create-alarm-basic.htm).

## 11. Acceptance and handoff

- [ ] Installation package checksum matched Oracle's value.
- [ ] Agent is active and Log Analytics plug-in is deployed.
- [ ] Entity maps to the intended agent.
- [ ] All three native sources map to the intended entity and log group.
- [ ] Fresh records from all three channels are queryable.
- [ ] Expected Security Event IDs and fields are present or explicitly recorded
      as not safely testable.
- [ ] Five saved searches and five dashboard widgets render.
- [ ] Five scheduled tasks emit numeric metrics.
- [ ] Five alarms exist disabled; one approved canary notification was tested.
- [ ] Business hours, timezone, renamed/localized administrators, service
      accounts, exclusions, retention, and response ownership are documented.
- [ ] Rollback owner knows how to remove only this host's associations and
      disable this pack's scheduled tasks/alarms.

