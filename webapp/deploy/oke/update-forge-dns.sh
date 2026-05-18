#!/usr/bin/env bash
set -euo pipefail

PROFILE="${OCI_PROFILE:-cap}"
ZONE_NAME="${OCI_DNS_ZONE_NAME:-octodemo.cloud}"
RECORD_NAME="${FORGE_RECORD_NAME:-convert.octodemo.cloud}"
NAMESPACE="${FORGE_NAMESPACE:-logan-forge}"
INGRESS_NAME="${FORGE_INGRESS_NAME:-logan-forge}"
TTL="${FORGE_DNS_TTL:-60}"
LB_OCID="${FORGE_LB_OCID:-}"
LB_PROFILE="${FORGE_LB_PROFILE:-emdemo}"

if ! command -v kubectl >/dev/null 2>&1; then
  echo "kubectl is required" >&2
  exit 1
fi
if ! command -v oci >/dev/null 2>&1; then
  echo "oci CLI is required" >&2
  exit 1
fi

ADDRESS="${FORGE_LB_ADDRESS:-}"
if [[ -z "${ADDRESS}" && -n "${LB_OCID}" ]]; then
  if ! command -v jq >/dev/null 2>&1; then
    echo "jq is required when FORGE_LB_OCID is set" >&2
    exit 1
  fi
  ADDRESS="$(oci --profile "${LB_PROFILE}" lb load-balancer get \
    --load-balancer-id "${LB_OCID}" \
    --output json |
    jq -r '.data."ip-addresses"[] | select(."is-public" == true) | ."ip-address"' |
    head -1)"
fi
if [[ -z "${ADDRESS}" ]]; then
  ADDRESS="$(kubectl get ingress "${INGRESS_NAME}" -n "${NAMESPACE}" -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || true)"
fi
if [[ -z "${ADDRESS}" ]]; then
  ADDRESS="$(kubectl get ingress "${INGRESS_NAME}" -n "${NAMESPACE}" -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null || true)"
fi
if [[ -z "${ADDRESS}" ]]; then
  echo "Could not resolve load balancer address. Set FORGE_LB_ADDRESS explicitly." >&2
  exit 1
fi
if [[ "${ADDRESS}" =~ ^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.) ]]; then
  echo "Refusing to publish documentation/test-net address ${ADDRESS}; set FORGE_LB_ADDRESS from the live OCI Load Balancer." >&2
  exit 1
fi

TMP_ITEMS="$(mktemp)"
trap 'rm -f "${TMP_ITEMS}"' EXIT

cat > "${TMP_ITEMS}" <<JSON
[
  {
    "domain": "${RECORD_NAME}",
    "rdata": "${ADDRESS}",
    "rtype": "A",
    "ttl": ${TTL}
  }
]
JSON

oci --profile "${PROFILE}" dns record rrset update \
  --zone-name-or-id "${ZONE_NAME}" \
  --domain "${RECORD_NAME}" \
  --rtype A \
  --items "file://${TMP_ITEMS}" \
  --force >/dev/null

echo "Updated ${RECORD_NAME} -> ${ADDRESS} in ${ZONE_NAME} using OCI profile ${PROFILE}"
