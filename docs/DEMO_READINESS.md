# Demo Readiness

This is the shortest path to a reliable demo when the goal is broader than security.

## Fast Path

For the current dashboard-first demo state, use the 24-hour generation, ingest, smoke, and deploy flow:

```bash
python3 scripts/setup_log_sources.py
python3 scripts/generate_test_logs.py --days 1 --validate
python3 scripts/generate_geo_health_logs.py --duration 60 --interval 5
python3 scripts/ingest_test_data.py --validate
python3 scripts/ingest_test_data.py --mode direct
python3 scripts/smoke_test_bluelight.py --lookback 24h
python3 scripts/deploy_dashboard.py --cleanup
```

This is the canonical refresh path because it:

- regenerates the synthetic datasets for the dashboard default `l24h` window
- validates the dataset contracts
- uploads all demo data into OCI Log Analytics
- cleans up and redeploys the dashboards and saved searches
- runs live readiness checks against the same 24-hour window
- validates dashboard queries in OCI Log Analytics before dashboards or embedded saved searches are imported

## Current Verified State

Validated on `2026-04-23` in the OCI demo tenancy:

- `164,766` total synthetic events across `14` JSONL datasets
- `14/14` dataset uploads completed successfully
- `16` dashboards imported
- `255` saved searches created or found
- `demo_readiness.py --lookback 14d`: `OK`
- `query_audit.py --lookback 14d --eligible-only`: `51/51` queries with rows, `0` empty, `0` errors

Repository update on `2026-04-28`: the current dashboard configuration resolves to `16` dashboards and `264` saved searches after adding the APM/WAF browser showcase widgets. Dashboard widgets default to `l24h`, and the latest local generated dataset contains `2,837` events across `14` JSONL datasets. Use `populate_dashboard_data_14d.py --validate` only when you intentionally need the extended 14-day demo dataset.

## Demo Story

Lead with three connected views:

1. `SOC: Geographic Health Dashboard`
   Show real multicloud visibility across OCI, Azure, AWS, and GCP.
   Use this as the opening proof that the platform sees all CSPs, not just one telemetry island.

2. `OCI-DEMO: Application 360 Monitoring Dashboard`
   Show performance and availability before security:
   - request rate
   - error rate
   - slow requests
   - service lifecycle timeline
   - DB performance correlation
   - cross-service trace correlation

3. Security correlation views
   Use them as pivots off the performance story, not as the whole demo:
   - `App: WAF Signal Correlation`
   - `App: OWASP Attack Detection`
   - `Browser Attack Detection Dashboard`

## Pre-demo checks

Run these in order:

```bash
python3 scripts/generate_test_logs.py --days 1 --validate
python3 scripts/generate_geo_health_logs.py --duration 60 --interval 5
python3 scripts/ingest_test_data.py --validate
python3 scripts/smoke_test_bluelight.py --lookback 24h
python3 -m unittest discover -s scripts -p 'test_*.py'
```

If you only need a dry check before touching OCI, run:

```bash
python3 scripts/validate_synthetic_logs.py
python3 scripts/deploy_dashboard.py --dry-run
python3 scripts/demo_readiness.py --dry-run
```

## What must be true for tomorrow

- Multicloud health data is present for `OCI`, `Azure`, `AWS`, and `GCP`
- App 360 queries return rows for:
  - throughput
  - error rate
  - slow requests
  - cross-service traces
  - DB correlation
- At least one correlation path is demoable end to end:
  - slow request -> trace correlation -> DB target
  - app request -> WAF signal -> attack source IP
  - degraded region -> provider summary -> unhealthy region detail

## Recommended sequence

1. Start with `SOC: Geographic Health Dashboard`
   Message: "We have one operational view across all CSPs."

2. Move to `OCI-DEMO: Application 360 Monitoring Dashboard`
   Message: "We can explain why users are unhappy, not just whether attackers are active."

3. Show `App: Cross-Service Trace Correlation`
   Message: "The same transaction can be followed across services."

4. Show `App: DB Performance Correlation`
   Message: "Database context is tied back to application traces and logs."

5. Show `App: WAF Signal Correlation`
   Message: "Security is part of the same operational story, not a separate console."

## Hard limit

Synthetic datasets now pass explicit schema contracts and the 24-hour dashboard smoke path in OCI. The extended 14-day eligible query audit remains available when that larger dataset is intentionally generated, but perfect fidelity to every real tenant log format still requires captured raw samples from the target OCI, Azure, AWS, and GCP environments. Use `scripts/validate_synthetic_logs.py` and the live OCI audits as confidence checks, not as proof of 100 percent production parity.
