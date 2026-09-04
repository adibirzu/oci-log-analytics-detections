# Wazuh → OCI Log Analytics Integration

Forward live Wazuh telemetry (GOAD endpoint data) into OCI Log Analytics so the
visibility the Wazuh dashboard provides — MITRE ATT&CK, Vulnerability Detection,
System Inventory, and Security Configuration Assessment (SCA) — is also queryable
in OCI LA, alongside the rest of the SOC detection content in this repo.

The forwarder is `scripts/wazuh_to_oci_la.py`. It reuses this repo's OCI auth,
namespace, log-group resolution and the tenant-neutral production write guard from
`scripts/oci_config.py` (the same machinery as `scripts/ingest_test_data.py`).

> All hostnames/IPs below use `<PLACEHOLDER>` tokens or the synthetic GOAD lab
> range `192.168.56.0/24`. Never inline real OCIDs, public IPs, tenancy
> namespaces, or credentials.

---

## Architecture

```
┌──────────────────────────────────────────┐
│ Wazuh manager  oci-wazuh-demo-wazuh-aio   │
│  agents: winterfell (192.168.56.11),      │
│          kingslanding (192.168.56.10)     │
│                                           │
│  ┌─────────────┐      ┌────────────────┐  │
│  │ rule engine │─────▶│ Wazuh indexer  │  │
│  │ (alerts)    │      │ (OpenSearch)   │  │
│  │ vuln/sca/   │      │ wazuh-alerts-* │  │
│  │ syscollector│      │ wazuh-states-* │  │
│  └──────┬──────┘      └───────┬────────┘  │
│         │ integrator hook     │ REST API  │
└─────────┼─────────────────────┼───────────┘
          │ (b) real-time       │ (a) periodic pull
          ▼                     ▼
   ┌──────────────────────────────────────┐
   │      scripts/wazuh_to_oci_la.py       │
   │  classify → batch → Upload API        │
   └──────────────────┬───────────────────┘
                      ▼
        ┌──────────────────────────────┐
        │   OCI Log Analytics sources   │
        │   • SOC Wazuh Alerts          │
        │   • SOC Wazuh Vulnerabilities │
        │   • SOC Wazuh Inventory       │
        │   • SOC Wazuh SCA             │
        └──────────────────────────────┘
```

Two deployment patterns share the same script:

- **(a) Periodic indexer pull** — `--mode indexer` reads the indexer (OpenSearch)
  REST API over a lookback window using a Point-in-Time + `search_after` cursor.
  Run on a cron job or systemd timer on the Wazuh host.
- **(b) Real-time integrator hook** — `--mode stdin` (or `--mode file`) reads the
  newline-delimited JSON alerts that the Wazuh `integrator`/`integratord` daemon
  pipes as each alert fires.

---

## Source mappings

The forwarded JSON is passed through **unmodified** so it matches the
`*_EXAMPLE` shapes / JSONPaths declared in
`scripts/logsources/wazuh_sources.py`. Each Wazuh document is classified to one
of four OCI LA sources:

| OCI LA source                | Wazuh origin                              | Classified by |
|------------------------------|-------------------------------------------|---------------|
| `SOC Wazuh Alerts`           | rule-engine alerts (MITRE, FIM/syscheck)  | index `wazuh-alerts-*`; fallback for any rule-engine doc |
| `SOC Wazuh Vulnerabilities`  | Vulnerability Detector (CVE/CVSS/package) | index `wazuh-states-vulnerabilities-*`; or a `vulnerability` block; or `rule.groups` ~ `vulnerability-detector` |
| `SOC Wazuh Inventory`        | Syscollector (hardware/OS/packages)       | index `wazuh-states-inventory-*`; or a `data.{cpu,ram,os,program,hotfix}` block (and no `data.win`); or `rule.groups` ~ `syscollector` |
| `SOC Wazuh SCA`              | Security Configuration Assessment         | index containing `sca`; or a `data.sca` block; or `rule.groups` ~ `sca` |

Classification logic lives in `classify_document()`. Index name wins when
present (indexer mode); for integrator/stdin docs with no `_index` it falls back
to payload shape, then `rule.groups`, then defaults to `SOC Wazuh Alerts`.

---

## Prerequisites

1. **The four OCI LA sources + parsers must exist.** Create them once via the
   repo's source-setup script (it registers the Wazuh parsers, custom fields,
   and sources from `scripts/logsources/wazuh_sources.py`):

   ```bash
   OCI_PROFILE=<OCI_STAGING_PROFILE> python3 scripts/setup_log_sources.py
   ```

   Verify the four `SOC Wazuh *` sources are listed in
   OCI Console → Log Analytics → Administration → Sources.

2. **OCI auth configured** — `~/.oci/config` profile (e.g. `cap`), or instance
   principal / resource principal on the host. Resolution is handled by
   `scripts/oci_config.py`.

3. **A reachable Wazuh indexer** (for pattern a) — the OpenSearch endpoint of
   `oci-wazuh-demo-wazuh-aio`, typically `https://<WAZUH_INDEXER_HOST>:9200`.

4. **Python `requests`** on the Wazuh host for indexer mode:
   `pip install requests` (file/stdin modes need only the OCI SDK + stdlib).

---

## Environment variables

| Variable | Required for | Purpose |
|----------|--------------|---------|
| `WAZUH_INDEXER_URL` | `--mode indexer` | OpenSearch base URL, e.g. `https://<WAZUH_INDEXER_HOST>:9200` |
| `WAZUH_INDEXER_USER` | `--mode indexer` | Indexer username (e.g. `admin`) |
| `WAZUH_INDEXER_PASSWORD` | `--mode indexer` | Indexer password — **never hardcode**; export at runtime |
| `WAZUH_INDEXER_VERIFY_TLS` | optional | `false`/`0`/`no` to skip TLS verification for self-signed lab certs (default `true`) |
| `OCI_PROFILE` | all live runs | OCI CLI profile, e.g. `cap` (staging). `production` is production and write-guarded |
| `OCI_ALLOW_PROD_WRITE` | production only | `1` to acknowledge a deliberate write to production outside the LogAnalytics subtree (or pass `--i-understand-prod`) |
| `LA_NAMESPACE`, `LOG_ANALYTICS_LOG_GROUP_ID` | optional | Pin namespace / log group; otherwise auto-discovered (see `oci_config.py`) |
| `OCI_LOG_LEVEL`, `OCI_LOG_FORMAT` | optional | `INFO`/`DEBUG`; `plain` for human-friendly stderr logs |

Credentials are read from the environment only — the script never accepts them
as CLI flags and never writes them to disk.

---

## CLI

```
python3 scripts/wazuh_to_oci_la.py \
  --mode {indexer,stdin,file} \
  [--lookback 15m] \
  [--index-pattern "wazuh-alerts-*,wazuh-states-*"] \
  [--batch-size 500] \
  [--file PATH] \
  [--dry-run] \
  [--i-understand-prod]
```

- `--dry-run` classifies the input and prints per-source counts, batch counts,
  and a one-line sample for each source **without calling OCI**.
- `--batch-size` controls how many documents go in each Upload API call.

---

## Deployment pattern (a): periodic indexer pull

Pull everything written to the indexer in the last lookback window and forward
it. Schedule the interval to match (or slightly exceed) the lookback so no gap
forms. A small overlap is harmless — OCI LA dedupes on content + time.

### Manual / cron

```bash
# /etc/cron.d/wazuh-to-oci-la  — pull the last 15 minutes, every 15 minutes
*/15 * * * * ossec  WAZUH_INDEXER_URL=https://<WAZUH_INDEXER_HOST>:9200 \
  WAZUH_INDEXER_USER=admin WAZUH_INDEXER_PASSWORD="$(cat /var/ossec/.indexer_pw)" \
  OCI_PROFILE=<OCI_STAGING_PROFILE> \
  /usr/bin/python3 /opt/oci-log-analytics-detections/scripts/wazuh_to_oci_la.py \
  --mode indexer --lookback 15m >> /var/log/wazuh_to_oci_la.log 2>&1
```

Store the indexer password in a `chmod 600` file owned by the run user
(`/var/ossec/.indexer_pw` above) — do not put it inline in the crontab.

### systemd timer

`/etc/systemd/system/wazuh-to-oci-la.service`:

```ini
[Unit]
Description=Forward Wazuh telemetry to OCI Log Analytics
After=network-online.target

[Service]
Type=oneshot
User=ossec
EnvironmentFile=/etc/wazuh-to-oci-la.env
ExecStart=/usr/bin/python3 /opt/oci-log-analytics-detections/scripts/wazuh_to_oci_la.py --mode indexer --lookback 15m
```

`/etc/systemd/system/wazuh-to-oci-la.timer`:

```ini
[Unit]
Description=Run Wazuh→OCI LA forwarder every 15 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=15min
AccuracySec=1min

[Install]
WantedBy=timers.target
```

`/etc/wazuh-to-oci-la.env` (mode `0600`, owned by `ossec`):

```
WAZUH_INDEXER_URL=https://<WAZUH_INDEXER_HOST>:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASSWORD=<INDEXER_PASSWORD>
OCI_PROFILE=<OCI_STAGING_PROFILE>
```

Enable:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-to-oci-la.timer
systemctl list-timers wazuh-to-oci-la.timer
```

---

## Deployment pattern (b): real-time integrator hook

Wazuh's `integrator` daemon runs a custom integration program every time an
alert matching the `<integration>` block fires, passing the alert file path as
`$1`. A thin wrapper reads that file and pipes it to the forwarder on stdin.

### Wrapper: `/var/ossec/integrations/custom-oci-la`

```bash
#!/bin/sh
# Wazuh integrator wrapper: forward a single alert to OCI Log Analytics.
# $1 = path to the alert JSON file written by integratord.
ALERT_FILE="$1"
export OCI_PROFILE=<OCI_STAGING_PROFILE>
# Source OCI + any required env (chmod 600, owned by root/ossec).
. /etc/wazuh-to-oci-la.env 2>/dev/null || true
/usr/bin/python3 /opt/oci-log-analytics-detections/scripts/wazuh_to_oci_la.py \
  --mode file --file "$ALERT_FILE" >> /var/log/wazuh_to_oci_la.log 2>&1
```

```bash
sudo chmod 750 /var/ossec/integrations/custom-oci-la
sudo chown root:ossec /var/ossec/integrations/custom-oci-la
```

> The integration program name **must** start with `custom-` for Wazuh to run it.
> `--mode file` is used because integratord writes the alert to a file and passes
> its path; `--mode stdin` is available if you wire a hook that pipes the alert
> directly.

### `ossec.conf` `<integration>` block

Add inside `<ossec_config>` on the Wazuh manager:

```xml
<integration>
  <name>custom-oci-la</name>
  <level>3</level>
  <alert_format>json</alert_format>
</integration>
```

`<level>3</level>` forwards alerts at rule level 3 and above; tune to taste, or
add `<group>vulnerability-detector,sca,syscollector</group>` to also forward
those modules. Restart the manager:

```bash
sudo systemctl restart wazuh-manager
```

> Real-time mode forwards each alert as its own Upload API call. For high alert
> volumes prefer pattern (a) (batched pulls) to stay within OCI upload limits;
> pattern (b) is ideal for low-volume, latency-sensitive detections.

---

## Verification (Logan QL)

After forwarding, wait 2–3 minutes for OCI LA processing, then run these in
OCI Console → Log Analytics → Log Explorer (set the time range to cover the
forward window):

```
* | where 'Log Source' in ('SOC Wazuh Alerts', 'SOC Wazuh Vulnerabilities', 'SOC Wazuh Inventory', 'SOC Wazuh SCA') | stats count by 'Log Source'
```

```
'Log Source' = 'SOC Wazuh Alerts' | stats count by 'MITRE Tactic'
```

```
'Log Source' = 'SOC Wazuh Alerts' | stats count by 'Host Name', 'MITRE Technique ID' | sort -count
```

```
'Log Source' = 'SOC Wazuh Vulnerabilities' | stats count by 'Vulnerability Severity', 'CVE ID' | sort -count
```

```
'Log Source' = 'SOC Wazuh Inventory' | stats count by 'Host Name', 'OS Name'
```

```
'Log Source' = 'SOC Wazuh SCA' | where 'SCA Check Result' = 'failed' | stats count by 'SCA Policy', 'Host Name'
```

You can also confirm the raw uploads landed:

```bash
OCI_PROFILE=<OCI_STAGING_PROFILE> python3 -c "
import sys; sys.path.insert(0,'scripts')
from oci_config import get_la_client, get_namespace
c=get_la_client(); ns=get_namespace(c)
for u in c.list_uploads(namespace_name=ns, name_contains='wazuh').data.items:
    print(u.name, u.time_created)
"
```

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| `Missing Wazuh indexer credentials` | Export `WAZUH_INDEXER_URL/USER/PASSWORD` before running indexer mode. |
| Upload error mentioning the source | The `SOC Wazuh *` source doesn't exist — run `scripts/setup_log_sources.py`. |
| `REFUSING mutating OCI call ... PRODUCTION` | You're on the `production` profile outside the LogAnalytics subtree. Use `OCI_PROFILE=<OCI_STAGING_PROFILE>`, or pass `--i-understand-prod` / `OCI_ALLOW_PROD_WRITE=1` deliberately. |
| TLS verify failure to the indexer | Lab self-signed cert: set `WAZUH_INDEXER_VERIFY_TLS=false` (lab only). |
| Documents classified as Alerts when they should be Vuln/SCA/Inventory | In stdin/file mode there is no `_index`; ensure the payload carries the expected `vulnerability` / `data.sca` / syscollector block, or forward from the indexer where the index name is authoritative. |
| No data in Log Explorer | Wait 2–3 minutes; confirm the Log Group and time range; check `list_uploads` (above). |
```
