# Wazuh → OCI Log Analytics — host deployment kit

Turnkey assets to run `scripts/wazuh_to_oci_la.py` on the **Wazuh manager host**
(`oci-wazuh-demo-wazuh-aio`) and forward live GOAD telemetry into the four
`SOC Wazuh *` OCI Log Analytics sources. Pairs with the architecture/reference
in [`docs/WAZUH_INTEGRATION.md`](../../docs/WAZUH_INTEGRATION.md).

| File | Purpose |
|---|---|
| `setup-wazuh-forwarder.sh` | one-shot installer (user, sync, deps, env, systemd timer) |
| `wazuh-to-oci-la.env.example` | env template → `/etc/wazuh-to-oci-la.env` (chmod 600) |
| `wazuh-to-oci-la.service` | systemd oneshot — indexer pull, last 20 min |
| `wazuh-to-oci-la.timer` | runs the service every 15 min |
| `custom-oci-la` | Wazuh integrator hook for real-time per-alert forwarding |

## Quick start (periodic indexer pull)

```bash
# on the Wazuh host, with a checkout of this repo at $REPO:
sudo ./deploy/wazuh/setup-wazuh-forwarder.sh "$REPO"
sudoedit /etc/wazuh-to-oci-la.env          # set WAZUH_INDEXER_* + OCI_PROFILE
# dry-run, then enable:
sudo -u wazuh-forwarder python3 /opt/wazuh-to-oci-la/scripts/wazuh_to_oci_la.py --mode indexer --lookback 15m --dry-run
sudo systemctl enable --now wazuh-to-oci-la.timer
```

## Real-time (Wazuh integrator hook)

```bash
sudo install -m 750 -o root -g wazuh deploy/wazuh/custom-oci-la /var/ossec/integrations/custom-oci-la
# add to /var/ossec/etc/ossec.conf:
#   <integration>
#     <name>custom-oci-la</name>
#     <alert_format>json</alert_format>
#     <level>3</level>
#   </integration>
sudo systemctl restart wazuh-manager
```

## Prerequisites
- The 4 `SOC Wazuh *` sources must exist in the target OCI LA tenancy — create
  with `OCI_PROFILE=<target> python3 scripts/setup_log_sources.py` (already done
  on `cap`).
- OCI auth on the host: an `~/.oci/config` profile **or** instance-principal
  (`OCI_AUTH_MODE=instance_principal`). The `production` prod write-guard applies.

## Verify
```text
'Log Source' = 'SOC Wazuh Alerts'         | stats count by 'MITRE Tactic'
'Log Source' = 'SOC Wazuh Vulnerabilities'| stats count by 'Vulnerability Severity'
'Log Source' = 'SOC Wazuh SCA'            | stats count by 'SCA Check Result'
```
Once data lands, the four `SOC: Wazuh *` dashboards populate with live
winterfell/kingslanding data instead of synthetic.

## Security
- Never commit a filled `/etc/wazuh-to-oci-la.env`; it holds the indexer password (0600, owned by `wazuh-forwarder`).
- All hosts/IPs here are placeholders or the RFC1918 lab range.
