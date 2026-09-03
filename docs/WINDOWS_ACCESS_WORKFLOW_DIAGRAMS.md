# Windows Access Monitoring Workflow Diagrams

These editable Mermaid diagrams accompany the
[Windows access fast onboarding overview](WINDOWS_ACCESS_FAST_ONBOARDING.md).
They are tenant-neutral design artifacts; they contain no customer topology or
provider acceptance claim.

The logical architecture also has an offline-generated
[JSON diagram specification](diagrams/windows-access-architecture.json) and
[Mermaid source](diagrams/windows-access-architecture.mmd). The Mermaid source
passed the OCI diagramming skill's structural and active-content validation.

For a Windows source that also delivers detection evidence to Splunk, continue with the full editable [on-prem Management Agent path](diagrams/logan-splunk-onprem-agent.mmd), [evidence-export sequence](diagrams/logan-splunk-export-sequence.mmd), [validation layers](diagrams/logan-splunk-validation.mmd), and [replay state](diagrams/logan-splunk-replay-state.mmd). The [Splunk operations guide](SPLUNK_PARALLEL_OPERATIONS.md) owns raw-versus-evidence decisions; this page keeps the Windows collection and detection workflow focused.

## 1. Collection, detection, and response architecture

```mermaid
flowchart LR
  subgraph WIN["Authorized Windows Server"]
    EVENTS["Windows Event Log<br/>Security · System · Application"]
    AGENT["Oracle Management Agent<br/>Log Analytics plug-in"]
    EVENTS -. telemetry .-> AGENT
  end

  subgraph OCI["OCI operational plane"]
    ASSOC["Host (Windows) entity<br/>3 native source associations"]
    LOGAN["OCI Log Analytics<br/>parse · fields · log group"]
    CONTENT["5 saved searches<br/>Windows access dashboard"]
    TASKS["5-minute scheduled searches<br/>numeric metric · ≤3 dimensions"]
    MON["OCI Monitoring<br/>logan_windows_access"]
    ALARMS["Disabled alarm canaries<br/>reviewed enablement"]
    ONS["OCI Notifications<br/>approved SOC destination"]
  end

  AGENT -. "HTTPS 443" .-> ASSOC
  ASSOC -. control .-> LOGAN
  LOGAN --> CONTENT
  LOGAN --> TASKS
  TASKS -. metric .-> MON
  MON -. evaluation .-> ALARMS
  ALARMS -. response .-> ONS
  CONTENT -. "analyst validates first" .-> ALARMS

  classDef source fill:#f3f4f6,stroke:#4b5563,color:#161513;
  classDef telemetry fill:#eff6ff,stroke:#2563eb,color:#161513;
  classDef analysis fill:#fff7ed,stroke:#c74634,color:#161513;
  classDef response fill:#ecfdf5,stroke:#15803d,color:#161513;
  class EVENTS source;
  class AGENT,ASSOC,LOGAN telemetry;
  class CONTENT,TASKS,MON analysis;
  class ALARMS,ONS response;
```

Line semantics: solid arrows are query/data use; short-dashed arrows are
telemetry; control/evaluation and response paths remain explicitly labeled.
Source association, dashboard import, scheduled-task creation, alarm creation,
and alarm enablement are separate mutations.

## 2. Manual and script-assisted paths

```mermaid
flowchart TB
  START["Record target, owner, approval, and stop conditions"]
  PATH{"Choose operating path"}

  subgraph MANUAL["Manual OCI Console path"]
    M1["Verify IAM policies and dynamic groups"]
    M2["Download/checksum Windows agent<br/>create install key and response file"]
    M3["Run installer.bat as Administrator"]
    M4["Create/map Host (Windows) entity"]
    M5["Associate three native Windows sources"]
    M6["Run OCL, save five searches,<br/>add to dashboard"]
    M7["Create five scheduled rules<br/>then five disabled alarms"]
    M1 --> M2 --> M3 --> M4 --> M5 --> M6 --> M7
  end

  subgraph SCRIPT["Script-assisted path"]
    S1["Plan + local synthetic E2E"]
    S2["PowerShell Preflight<br/>then guarded Install/Enable"]
    S3["Render restricted OCI CLI bundle"]
    S4["Apply reviewed association JSON"]
    S5["Deploy saved searches/dashboard<br/>with live query validation"]
    S6["Resolve saved-search OCIDs<br/>apply tasks one at a time"]
    S7["Create disabled alarms<br/>enable one canary"]
    S1 --> S2 --> S3 --> S4 --> S5 --> S6 --> S7
  end

  PROOF{"Fresh Security, System, and<br/>Application rows queryable?"}
  ACCEPT["Provider E2E receipt and operator handoff"]
  FIX["Troubleshoot audit → agent → plug-in →<br/>association → IAM/network → processing"]

  START --> PATH
  PATH -->|Console| M1
  PATH -->|Scripts| S1
  M5 --> PROOF
  S4 --> PROOF
  PROOF -->|No| FIX --> PROOF
  PROOF -->|Yes| M6
  PROOF -->|Yes| S5
  M7 --> ACCEPT
  S7 --> ACCEPT

  classDef gate fill:#fff7ed,stroke:#c74634,stroke-width:2px,color:#161513;
  classDef manual fill:#f9fafb,stroke:#6b7280,color:#161513;
  classDef script fill:#eff6ff,stroke:#2563eb,color:#161513;
  classDef success fill:#ecfdf5,stroke:#15803d,color:#161513;
  classDef failure fill:#fef2f2,stroke:#b91c1c,color:#161513;
  class PATH,PROOF gate;
  class M1,M2,M3,M4,M5,M6,M7 manual;
  class S1,S2,S3,S4,S5,S6,S7 script;
  class ACCEPT success;
  class FIX failure;
```

Both paths converge on the same collection proof gate. Scripts reduce typing;
they do not lower IAM, target confirmation, evidence, or approval requirements.

## 3. Saved search to notification sequence

```mermaid
sequenceDiagram
  autonumber
  participant W as Windows Server
  participant A as Management Agent
  participant L as Log Analytics
  participant S as Scheduled Search
  participant M as Monitoring
  participant R as Alarm
  participant N as Notifications
  participant O as SOC Operator

  W->>A: New approved Windows event
  A-->>L: Upload through associated native source
  O->>L: Confirm parsed event and required fields
  O->>L: Save query and validate dashboard widget
  L-->>S: Saved-search OCID and query output contract
  O->>S: Create 5-minute rule after source proof
  S-->>M: Numeric metric plus up to 3 dimensions
  O->>M: Confirm first metric data point
  O->>R: Create alarm disabled
  O->>R: Enable one approved canary
  R-->>N: Fire only when MQL condition is met
  N-->>O: Deliver to approved destination
  O->>L: Pivot back using dimensions and time window
```

The sequence prevents a common failure: enabling a notification before proving
the saved search produces a numeric metric in Monitoring.

## 4. Troubleshooting decision workflow

```mermaid
flowchart TD
  ZERO["No expected rows or alert"]
  EVENT{"Event exists in<br/>Windows Event Viewer?"}
  AUDIT["Fix approved audit policy/channel<br/>and generate or await a safe event"]
  SERVICE{"mgmt_agent running and<br/>Log Analytics plug-in deployed?"}
  AGENTFIX["Inspect installer/runtime logs,<br/>JDK8, WMIC, time, disk, service"]
  NETWORK{"Regional HTTPS 443<br/>endpoints reachable?"}
  NETFIX["Review proxy, DNS, TLS inspection,<br/>firewall, clock, and certificates"]
  ASSOC{"Correct agent/entity/source/<br/>log-group association?"}
  ASSOCFIX["Correct only the target mapping;<br/>avoid duplicate native sources"]
  METRICS{"Upload size present and<br/>upload failures clear?"}
  IAMFIX["Inspect errorCode, IAM upload policy,<br/>processing errors, and target scope"]
  QUERY{"Broad source query returns<br/>fresh rows and fields?"}
  QUERYFIX["Widen time; verify scope, source,<br/>field types, parser, and retention"]
  TASK{"Saved search returns numeric<br/>metric and task is READY?"}
  TASKFIX["Check query limits, saved-search OCID,<br/>task IAM, delay, and dimensions"]
  ALARM{"Metric visible and alarm<br/>definition/destination correct?"}
  ALARMFIX["Keep disabled; correct MQL, compartment,<br/>namespace, resource group, and ONS"]
  DONE["Record provider evidence and hand off"]

  ZERO --> EVENT
  EVENT -->|No| AUDIT --> EVENT
  EVENT -->|Yes| SERVICE
  SERVICE -->|No| AGENTFIX --> SERVICE
  SERVICE -->|Yes| NETWORK
  NETWORK -->|No| NETFIX --> NETWORK
  NETWORK -->|Yes| ASSOC
  ASSOC -->|No| ASSOCFIX --> ASSOC
  ASSOC -->|Yes| METRICS
  METRICS -->|No| IAMFIX --> METRICS
  METRICS -->|Yes| QUERY
  QUERY -->|No| QUERYFIX --> QUERY
  QUERY -->|Yes| TASK
  TASK -->|No| TASKFIX --> TASK
  TASK -->|Yes| ALARM
  ALARM -->|No| ALARMFIX --> ALARM
  ALARM -->|Yes| DONE

  classDef gate fill:#fff7ed,stroke:#c74634,stroke-width:2px,color:#161513;
  classDef failure fill:#fef2f2,stroke:#b91c1c,color:#161513;
  classDef success fill:#ecfdf5,stroke:#15803d,color:#161513;
  class EVENT,SERVICE,NETWORK,ASSOC,METRICS,QUERY,TASK,ALARM gate;
  class AUDIT,AGENTFIX,NETFIX,ASSOCFIX,IAMFIX,QUERYFIX,TASKFIX,ALARMFIX failure;
  class DONE success;
```

An empty query never skips directly to “no activity.” Each layer must either be
verified or recorded as unavailable/inconclusive.

## 5. Evidence progression

```mermaid
stateDiagram-v2
  [*] --> CodeBacked: queries, scripts, policies, diagrams
  CodeBacked --> LocallyVerified: deterministic fixtures and tests pass
  LocallyVerified --> Configured: exact agent/entity/sources/content exist
  Configured --> ProviderVerified: fresh event traverses every required layer
  ProviderVerified --> ReleaseAccepted: customer owner accepts handoff
  Configured --> Inconclusive: missing rows, metric, or destination proof
  Inconclusive --> ProviderVerified: gap corrected and canary rerun
```

Do not infer a higher state from a lower one. In particular, `ACTIVE` agent,
successful dashboard import, or HTTP success does not prove native Windows event
collection and notification delivery.

When Mode 2 is enabled, extend the ladder after notification: exact Function invocation → bounded Log Analytics query → HEC confirmation → checkpoint commit or DLQ → Splunk searchability. None of those steps is implied by the earlier metric/alarm receipt; validate with [Splunk E2E Validation](SPLUNK_E2E_VALIDATION.md).
