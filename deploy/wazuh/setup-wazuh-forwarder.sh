#!/usr/bin/env bash
# Turnkey installer for the Wazuh -> OCI Log Analytics forwarder.
# Run as root ON THE WAZUH MANAGER HOST (oci-wazuh-demo-wazuh-aio).
#
# What it does (idempotent):
#   1. creates a low-priv 'wazuh-forwarder' user + /opt/wazuh-to-oci-la
#   2. syncs the repo's scripts/ (the forwarder + its deps) into INSTALL_DIR
#   3. installs python deps (oci, requests)
#   4. installs the env template to /etc/wazuh-to-oci-la.env (0600) if absent
#   5. installs + enables the systemd timer (periodic indexer pull)
#
# It does NOT fill in secrets — edit /etc/wazuh-to-oci-la.env afterwards, then:
#   systemctl enable --now wazuh-to-oci-la.timer
#
# Usage:
#   sudo ./setup-wazuh-forwarder.sh /path/to/oci-log-analytics-detections
set -euo pipefail

REPO_SRC="${1:?Usage: setup-wazuh-forwarder.sh <path-to-repo-checkout>}"
INSTALL_DIR="/opt/wazuh-to-oci-la"
SVC_USER="wazuh-forwarder"
ENV_DST="/etc/wazuh-to-oci-la.env"
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "[1/5] user + install dir"
id -u "$SVC_USER" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
mkdir -p "$INSTALL_DIR/scripts"

echo "[2/5] sync forwarder + dependencies from $REPO_SRC"
# Only the scripts/ tree is needed (forwarder imports oci_config, obs_logging,
# query_artifacts, oci_support/, logsources/).
rsync -a --delete \
  --exclude '__pycache__' --exclude '*.pyc' --exclude 'test_*' \
  "$REPO_SRC/scripts/" "$INSTALL_DIR/scripts/"
chown -R "$SVC_USER:$SVC_USER" "$INSTALL_DIR"

echo "[3/5] python deps"
python3 -m pip install --quiet --upgrade oci requests

echo "[4/5] env file"
if [ ! -f "$ENV_DST" ]; then
  install -m 0600 "$HERE/wazuh-to-oci-la.env.example" "$ENV_DST"
  chown "$SVC_USER:$SVC_USER" "$ENV_DST"
  echo "    -> wrote $ENV_DST (EDIT IT: set WAZUH_INDEXER_* + OCI auth)"
else
  echo "    -> $ENV_DST exists, leaving as-is"
fi

echo "[5/5] systemd units"
install -m 0644 "$HERE/wazuh-to-oci-la.service" /etc/systemd/system/wazuh-to-oci-la.service
install -m 0644 "$HERE/wazuh-to-oci-la.timer"   /etc/systemd/system/wazuh-to-oci-la.timer
systemctl daemon-reload

cat <<EOF

Done. Next steps:
  1. Edit $ENV_DST  (WAZUH_INDEXER_URL/USER/PASSWORD, OCI_PROFILE or instance-principal)
  2. Dry-run once:
       sudo -u $SVC_USER OCI_PROFILE=... python3 $INSTALL_DIR/scripts/wazuh_to_oci_la.py --mode indexer --lookback 15m --dry-run
  3. Enable periodic pull:
       systemctl enable --now wazuh-to-oci-la.timer
       systemctl list-timers wazuh-to-oci-la.timer
  4. (optional) Real-time hook: install deploy/wazuh/custom-oci-la into
     /var/ossec/integrations/ and add the <integration> block (see README.md).
  5. Verify in OCI LA:
       'Log Source' = 'SOC Wazuh Alerts' | stats count by 'MITRE Tactic'
EOF
