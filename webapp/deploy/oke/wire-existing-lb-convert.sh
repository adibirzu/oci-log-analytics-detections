#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DEFAULT_OUTPUTS_FILE="$(cd "${APP_ROOT}/../.." && pwd)/octo-apm-demo/credentials/emdemo/outputs.json"

: "${OCI_PROFILE:=emdemo}"
: "${OUTPUTS_FILE:=${DEFAULT_OUTPUTS_FILE}}"
: "${FORGE_BACKEND_SET:=logan_forge_nodeport}"
: "${FORGE_HOSTNAME_NAME:=convert}"
: "${FORGE_HOSTNAME:=convert.octodemo.cloud}"
: "${FORGE_NODEPORT:=30082}"
: "${LISTENER_NAME:=http}"
: "${ROUTING_POLICY_NAME:=host_routing}"
: "${OKE_CLUSTER_NAME:=octo-apm-demo-oke}"
: "${SKIP_CONTEXT_CHECK:=false}"

APPLY=false

usage() {
  cat <<EOF
Usage: $0 [--apply]

Creates or updates the existing Octo APM OCI Load Balancer wiring for
${FORGE_HOSTNAME}. Dry-run is the default.

Environment:
  OCI_PROFILE=${OCI_PROFILE}
  OUTPUTS_FILE=${OUTPUTS_FILE}
  FORGE_BACKEND_SET=${FORGE_BACKEND_SET}
  FORGE_HOSTNAME_NAME=${FORGE_HOSTNAME_NAME}
  FORGE_HOSTNAME=${FORGE_HOSTNAME}
  FORGE_NODEPORT=${FORGE_NODEPORT}
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply)
      APPLY=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

require_tool() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required tool: $1" >&2
    exit 1
  }
}

oci_json() {
  oci "$@" --profile "${OCI_PROFILE}" --output json
}

oci_plain() {
  oci "$@" --profile "${OCI_PROFILE}"
}

require_tool jq
require_tool kubectl
require_tool oci

if [[ "${SKIP_CONTEXT_CHECK}" != "true" ]]; then
  current_context="$(kubectl config current-context 2>/dev/null || true)"
  if [[ "${current_context}" != "${OKE_CLUSTER_NAME}" ]]; then
    echo "Current kubectl context is '${current_context:-unset}', expected '${OKE_CLUSTER_NAME}'." >&2
    exit 1
  fi
fi

if [[ ! -f "${OUTPUTS_FILE}" ]]; then
  echo "Missing outputs file: ${OUTPUTS_FILE}" >&2
  exit 1
fi

LB_ID="${LB_ID:-$(jq -r '.load_balancer.value.id' "${OUTPUTS_FILE}")}"
if [[ -z "${LB_ID}" || "${LB_ID}" == "null" ]]; then
  echo "Could not read load balancer id from ${OUTPUTS_FILE}." >&2
  exit 1
fi

NODE_IPS=()
while IFS= read -r node_ip; do
  NODE_IPS+=("${node_ip}")
done < <(
  kubectl get nodes -o json |
    jq -r '.items[]
      | select((.status.conditions[]? | select(.type == "Ready") | .status) == "True")
      | .status.addresses[]
      | select(.type == "InternalIP")
      | .address' |
    sort -u
)

if [[ "${#NODE_IPS[@]}" -eq 0 ]]; then
  echo "No Ready OKE node InternalIP values found in the current kubectl context." >&2
  exit 1
fi

backend_json() {
  printf '%s\n' "${NODE_IPS[@]}" |
    jq -R -s --argjson port "${FORGE_NODEPORT}" 'split("\n") | map(select(length > 0) | {
      ipAddress: .,
      port: $port,
      weight: 1,
      backup: false,
      drain: false,
      offline: false
    })'
}

backend_set_exists() {
  oci_json lb backend-set get \
    --load-balancer-id "${LB_ID}" \
    --backend-set-name "${FORGE_BACKEND_SET}" >/dev/null 2>&1
}

hostname_exists() {
  oci_json lb hostname get \
    --load-balancer-id "${LB_ID}" \
    --name "${FORGE_HOSTNAME_NAME}" >/dev/null 2>&1
}

ensure_backend_set() {
  local backends
  backends="$(backend_json)"

  echo "Planned ${FORGE_BACKEND_SET} backends on NodePort ${FORGE_NODEPORT}:"
  printf '%s\n' "${NODE_IPS[@]}" | sed "s/$/:${FORGE_NODEPORT}/" | sed 's/^/  - /'

  if [[ "${APPLY}" != "true" ]]; then
    return
  fi

  if backend_set_exists; then
    oci_plain lb backend-set update \
      --load-balancer-id "${LB_ID}" \
      --backend-set-name "${FORGE_BACKEND_SET}" \
      --policy ROUND_ROBIN \
      --backends "${backends}" \
      --health-checker-protocol HTTP \
      --health-checker-port "${FORGE_NODEPORT}" \
      --health-checker-url-path /api/health \
      --health-checker-return-code 200 \
      --health-checker-response-body-regex '.*' \
      --health-checker-interval-in-ms 10000 \
      --health-checker-timeout-in-ms 3000 \
      --health-checker-retries 3 \
      --force \
      --wait-for-state SUCCEEDED \
      --max-wait-seconds 600 >/dev/null
    echo "Updated backend set ${FORGE_BACKEND_SET}"
  else
    oci_plain lb backend-set create \
      --load-balancer-id "${LB_ID}" \
      --name "${FORGE_BACKEND_SET}" \
      --policy ROUND_ROBIN \
      --backends "${backends}" \
      --health-checker-protocol HTTP \
      --health-checker-port "${FORGE_NODEPORT}" \
      --health-checker-url-path /api/health \
      --health-checker-return-code 200 \
      --health-checker-response-body-regex '.*' \
      --health-checker-interval-in-ms 10000 \
      --health-checker-timeout-in-ms 3000 \
      --health-checker-retries 3 \
      --wait-for-state SUCCEEDED \
      --max-wait-seconds 600 >/dev/null
    echo "Created backend set ${FORGE_BACKEND_SET}"
  fi
}

ensure_hostname() {
  echo "Planned hostname resource ${FORGE_HOSTNAME_NAME}: ${FORGE_HOSTNAME}"
  if [[ "${APPLY}" != "true" ]]; then
    return
  fi

  if hostname_exists; then
    oci_plain lb hostname update \
      --load-balancer-id "${LB_ID}" \
      --name "${FORGE_HOSTNAME_NAME}" \
      --hostname "${FORGE_HOSTNAME}" \
      --wait-for-state SUCCEEDED \
      --max-wait-seconds 600 >/dev/null
    echo "Updated hostname ${FORGE_HOSTNAME_NAME}"
  else
    oci_plain lb hostname create \
      --load-balancer-id "${LB_ID}" \
      --name "${FORGE_HOSTNAME_NAME}" \
      --hostname "${FORGE_HOSTNAME}" \
      --wait-for-state SUCCEEDED \
      --max-wait-seconds 600 >/dev/null
    echo "Created hostname ${FORGE_HOSTNAME_NAME}"
  fi
}

update_routing_policy() {
  local tmp_rules condition
  tmp_rules="$(mktemp)"
  condition="any(http.request.headers[(i 'Host')] eq (i '${FORGE_HOSTNAME}'))"

  oci_json lb routing-policy get \
    --load-balancer-id "${LB_ID}" \
    --routing-policy-name "${ROUTING_POLICY_NAME}" |
    jq --arg name "forge_host" --arg condition "${condition}" --arg backend "${FORGE_BACKEND_SET}" '
      .data.rules
      | map(select(.name != $name))
      + [{
          name: $name,
          condition: $condition,
          actions: [{name: "FORWARD_TO_BACKENDSET", "backend-set-name": $backend}]
        }]
    ' > "${tmp_rules}"

  echo "Planned routing policy rule forge_host -> ${FORGE_BACKEND_SET}"
  if [[ "${APPLY}" == "true" ]]; then
    oci_plain lb routing-policy update \
      --load-balancer-id "${LB_ID}" \
      --routing-policy-name "${ROUTING_POLICY_NAME}" \
      --condition-language-version V1 \
      --rules "file://${tmp_rules}" \
      --force \
      --wait-for-state SUCCEEDED \
      --max-wait-seconds 600 >/dev/null
    echo "Updated routing policy ${ROUTING_POLICY_NAME}"
  fi

  rm -f "${tmp_rules}"
}

update_listener_hostnames() {
  local listener tmp_names tmp_certs tmp_protocols tmp_rulesets hostname_names cert_ids protocols rule_set_names
  listener="$(oci_json lb load-balancer get --load-balancer-id "${LB_ID}" | jq --arg listener "${LISTENER_NAME}" '.data.listeners[$listener]')"
  tmp_names="$(mktemp)"
  tmp_certs="$(mktemp)"
  tmp_protocols="$(mktemp)"
  tmp_rulesets="$(mktemp)"

  hostname_names="$(jq --arg hostname "${FORGE_HOSTNAME_NAME}" '."hostname-names" // [] | if index($hostname) then . else . + [$hostname] end' <<< "${listener}")"
  cert_ids="$(jq '."ssl-configuration"."certificate-ids" // []' <<< "${listener}")"
  protocols="$(jq '."ssl-configuration".protocols // ["TLSv1.2"]' <<< "${listener}")"
  rule_set_names="$(jq '."rule-set-names" // []' <<< "${listener}")"

  printf '%s\n' "${hostname_names}" > "${tmp_names}"
  printf '%s\n' "${cert_ids}" > "${tmp_certs}"
  printf '%s\n' "${protocols}" > "${tmp_protocols}"
  printf '%s\n' "${rule_set_names}" > "${tmp_rulesets}"

  echo "Planned listener ${LISTENER_NAME} hostname names: ${hostname_names}"
  if [[ "${APPLY}" == "true" ]]; then
    oci_plain lb listener update \
      --load-balancer-id "${LB_ID}" \
      --listener-name "${LISTENER_NAME}" \
      --default-backend-set-name "$(jq -r '.["default-backend-set-name"]' <<< "${listener}")" \
      --port "$(jq -r '.port' <<< "${listener}")" \
      --protocol "$(jq -r '.protocol' <<< "${listener}")" \
      --hostname-names "file://${tmp_names}" \
      --routing-policy-name "${ROUTING_POLICY_NAME}" \
      --rule-set-names "file://${tmp_rulesets}" \
      --ssl-certificate-ids "file://${tmp_certs}" \
      --protocols "file://${tmp_protocols}" \
      --cipher-suite-name "$(jq -r '.["ssl-configuration"]["cipher-suite-name"]' <<< "${listener}")" \
      --server-order-preference "$(jq -r '.["ssl-configuration"]["server-order-preference"]' <<< "${listener}")" \
      --ssl-verify-depth "$(jq -r '.["ssl-configuration"]["verify-depth"]' <<< "${listener}")" \
      --ssl-verify-peer-certificate "$(jq -r '.["ssl-configuration"]["verify-peer-certificate"]' <<< "${listener}")" \
      --connection-configuration-idle-timeout "$(jq -r '.["connection-configuration"]["idle-timeout"] // 60' <<< "${listener}")" \
      --force \
      --wait-for-state SUCCEEDED \
      --max-wait-seconds 600 >/dev/null
    echo "Updated listener ${LISTENER_NAME}"
  fi

  rm -f "${tmp_names}" "${tmp_certs}" "${tmp_protocols}" "${tmp_rulesets}"
}

backend_set_health_status() {
  oci_json lb backend-set-health get \
    --load-balancer-id "${LB_ID}" \
    --backend-set-name "${FORGE_BACKEND_SET}" |
    jq -r '.data.status // "UNKNOWN"'
}

wait_backend_set_healthy() {
  local status attempt
  if [[ "${APPLY}" != "true" ]]; then
    return
  fi
  for attempt in $(seq 1 30); do
    status="$(backend_set_health_status)"
    if [[ "${status}" == "OK" ]]; then
      echo "Backend set ${FORGE_BACKEND_SET} health: OK"
      return
    fi
    sleep 10
  done
  echo "Backend set ${FORGE_BACKEND_SET} did not become healthy; last status was ${status}." >&2
  exit 1
}

echo "================================================================"
echo " Existing OCI LB wiring for Logan Forge"
echo "   Host:        ${FORGE_HOSTNAME}"
echo "   Backend set: ${FORGE_BACKEND_SET}"
echo "   NodePort:    ${FORGE_NODEPORT}"
echo "   Listener:    ${LISTENER_NAME}"
echo "   Apply:       ${APPLY}"
echo "================================================================"

ensure_backend_set
ensure_hostname
update_routing_policy
update_listener_hostnames
wait_backend_set_healthy

echo
echo "Current host routing:"
oci_json lb routing-policy get \
  --load-balancer-id "${LB_ID}" \
  --routing-policy-name "${ROUTING_POLICY_NAME}" |
  jq -r '.data.rules[] | "\(.name): \(.actions[] | select(.name == "FORWARD_TO_BACKENDSET") | .["backend-set-name"])"'
