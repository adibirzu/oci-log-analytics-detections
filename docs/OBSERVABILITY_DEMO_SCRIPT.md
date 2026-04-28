# Observability Demo Script

Date: 2026-04-23
Audience: Platform leaders, SREs, observability architects, security stakeholders
Length: 12-15 minutes
Primary goal: show that OCI Log Analytics is being used as one operational surface for multicloud health, application performance, trace-style correlation, and security context

## What is live right now

- Time range to use: `Last 7 days`
- Dashboards deployed: `16`
- Saved searches configured in the current repo: `264`
- Last live refresh on `2026-04-23`: `255` saved searches deployed
- Demo-readiness status: green for multicloud, application, and security-correlation flows
- Detection-rule-compatible audit status: `51/51` eligible queries return rows in OCI Log Analytics

## One-sentence narrative

"This is not a security-only console. It is one workflow that starts with cross-cloud health, moves into application performance and transaction correlation, and then brings security signals in as operational context."

## Before you start

Open these dashboards in separate tabs:

1. `SOC: Geographic Health Dashboard`
2. `OCI-DEMO: Application 360 Monitoring Dashboard`
3. `SOC: Browser Attack Detection Dashboard`
4. `SOC: APT Detection Dashboard`

Keep `Log Explorer` ready in one more tab in case you want to pivot from a widget into query view.

## Demo flow

## 1. Open with multicloud operations (2-3 min)

Dashboard: `SOC: Geographic Health Dashboard`

Start here:

"I want to start with operations, not threats. The point of this demo is that we have one view across OCI, Azure, AWS, and GCP instead of four separate telemetry islands."

Click in this order:

1. `Geo: Regional Health Map`
2. `Geo: Cloud Provider Summary`
3. `Geo: Unhealthy Regions`
4. `Geo: Service Tier Status`

What to say:

- "The first question an operations team asks is simple: where are we degraded right now?"
- "From the map, I can pivot into provider summary, then into unhealthy regions, then into tier-level status."
- "This gives me regional context before I ever drill into a single service."

What to point at visually:

- provider distribution across `OCI`, `Azure`, `AWS`, `GCP`
- unhealthy or degraded regions
- tier-level view that separates customer-facing impact from lower-priority services

Transition line:

"Once I know where the platform is degraded, the next question is whether this is capacity, latency, dependency, or application behavior."

## 2. Move into application performance (4-5 min)

Dashboard: `OCI-DEMO: Application 360 Monitoring Dashboard`

Click in this order:

1. `App: Request Rate by Endpoint`
2. `App: Error Rate by Service`
3. `App: Slow Requests (>2s)`
4. `App: Service Health Timeline`

What to say:

- "Now I am no longer looking at cloud regions. I am looking at service behavior."
- "Request rate tells me whether traffic actually moved."
- "Error rate tells me whether the user experience broke."
- "Slow requests tells me where the system is technically alive but operationally unhealthy."
- "The service timeline is useful because it compresses a lot of activity into one view instead of forcing me to inspect raw logs."

Short operator line:

"This is the part of the story most security demos miss. We can show why users are unhappy, not just whether something malicious happened."

## 3. Show transaction and dependency correlation (3-4 min)

Stay on: `OCI-DEMO: Application 360 Monitoring Dashboard`

Click in this order:

1. `App: Cross-Service Trace Correlation`
2. `App: DB Performance Correlation`
3. `App: Order Sync Pipeline`

What to say:

- "This is where the demo stops being dashboard theater."
- "I can follow the same business transaction across services instead of treating each service as a separate mystery."
- "The database view is especially important because it connects backend performance to application behavior."
- "If an order-sync path is degraded, I can explain whether that is a traffic issue, an error issue, or a dependency issue."

Suggested phrasing:

"For the audience, the important takeaway is that this is one incident narrative: degraded region, then service impact, then transaction path, then backend correlation."

## 4. Bring security in as context, not as the whole story (2-3 min)

Stay on App 360, then pivot once.

Click in this order:

1. `App: WAF Signal Correlation`
2. `App: OWASP Attack Detection`
3. `App: Security Attack by IP`
4. Switch to `SOC: Browser Attack Detection Dashboard`
5. Open `Hunt: Browser Attack Frequency`

What to say:

- "Now I can ask a harder question: is this purely a performance problem, or is hostile traffic contributing to the symptoms?"
- "WAF correlation shows security as part of the same operational view."
- "OWASP and source-IP analysis let me separate random noise from meaningful attack concentration."
- "The browser telemetry dashboard extends the picture into the client side, which is where traditional server-side logging often stops."

One useful line:

"Security is not a separate console in this demo. It is a correlated signal layered into the same operational story."

## 5. Optional close for technical audiences (1-2 min)

If the audience wants a sharper technical ending, go to `SOC: APT Detection Dashboard` and open:

1. `APT37: Graph API C2`
2. `APT37: OneDrive Exfiltration`
3. `Hunt: BLUELIGHT Kill Chain`

What to say:

"The same platform that helps explain operational degradation can also correlate multi-stage behavior across endpoints, network activity, and cloud-facing API traffic."

If you need to stay observability-first, keep this section short. Treat it as proof that the telemetry model supports both SRE and detection use cases.

## Exact closer

"The core point is not that we built a lot of dashboards. The point is that in one OCI Log Analytics workflow we can move from multicloud posture, to service degradation, to transaction correlation, to backend dependency, to security context without resetting the investigation."

## Fallback route if time is tight

If you only have 5-7 minutes:

1. `SOC: Geographic Health Dashboard`
2. `OCI-DEMO: Application 360 Monitoring Dashboard`
3. `App: DB Performance Correlation`
4. `App: WAF Signal Correlation`

Use this compressed line:

"One dashboard for where the platform is unhealthy, one dashboard for why the application is unhealthy, and one correlation step to show whether hostile traffic is part of the cause."

## Fallback route if a widget is slow

If a chart takes too long to load:

1. Stay on the same dashboard
2. Move to the next populated widget
3. Do not wait in silence
4. Say: "The important part is the correlation path, so I will use the next view to show the same operational relationship."

Safe backup widgets:

- `Geo: Cloud Provider Summary`
- `App: Error Rate by Service`
- `App: Service Health Timeline`
- `App: DB Performance Correlation`
- `App: WAF Signal Correlation`

## Q&A answers

### If they ask: "Why use charts instead of raw query output?"

Answer:

"Because the Visualize panel is where OCI Log Analytics becomes operationally useful. It lets us move between fields, query edits, and visualization choices without leaving the investigation flow."

### If they ask: "How do you preserve context while pivoting?"

Answer:

"The scope filter and time range carry the investigation context across dashboards and Log Explorer, so the pivot is operationally consistent rather than a context reset."

### If they ask: "How would you compress this for an exec dashboard?"

Answer:

"OCI Log Analytics supports tiles-in-link visualizations for summary views. That lets us consolidate multiple tiles into one component and improve dashboard load performance when we want a tighter overview page."

### If they ask: "How does this become alerting?"

Answer:

"Detection rules can capture events at ingest time or from saved-search-style queries, publish a metric into OCI Monitoring, and then alarms can notify on that metric."

### If they ask about Ask AI

Use this only if Ask AI is enabled in the tenancy you are presenting from:

"As a final step, I can use Ask AI to summarize what changed, explain the likely root cause chain, or translate a technical chart into a plain-English incident summary for a broader audience."

If Ask AI is not enabled, skip it. Do not introduce it as a dependency for the demo.

## Operator notes

- Keep the demo at `Last 7 days`
- Lead with operations, not threat hunting
- Do not open with Sigma, rules, or MITRE unless the audience asks
- Use security as a pivot off performance, not as the first act
- If someone asks whether non-OCI CSP data is live-native, answer honestly that the current cross-cloud demo visibility is synthetic multicloud telemetry flowing into OCI Log Analytics for the showcase environment

## Optional Log Explorer pivot

If you want one product-centric moment:

1. Open a widget in `OCI-DEMO: Application 360 Monitoring Dashboard`
2. Pivot into `Log Explorer`
3. Keep the same time range and scope
4. Show the query bar and visualization panel

Say this:

"This is useful because I can go from dashboard signal to query refinement without changing tools. I can keep the same scope and time context and change only the question I am asking."
