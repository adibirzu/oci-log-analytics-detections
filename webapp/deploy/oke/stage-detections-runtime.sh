#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DETECTIONS_REPO="${LOGAN_DETECTIONS_REPO:-$(cd "${APP_ROOT}/.." && pwd)}"
RUNTIME_DIR="${APP_ROOT}/.logan-detections-runtime"

require_file() {
  if [[ ! -f "$1" ]]; then
    echo "Missing required detections artifact: $1" >&2
    exit 1
  fi
}

require_file "${DETECTIONS_REPO}/queries/logan_ql_reference_catalog.json"
require_file "${DETECTIONS_REPO}/queries/cross_ql_mapping_patterns.json"
require_file "${DETECTIONS_REPO}/queries/conversion_examples.json"
require_file "${DETECTIONS_REPO}/queries/forge_detection_catalog.json"
require_file "${DETECTIONS_REPO}/queries/catalog.json"
require_file "${DETECTIONS_REPO}/queries/hunting_integration_bundle.json"
for metadata in hunting_packs.json hunting_reference_candidates.json threat_intel_sources.json; do
  require_file "${DETECTIONS_REPO}/config/${metadata}"
done
require_file "${DETECTIONS_REPO}/queries/dashboard_inventory.json"
require_file "${DETECTIONS_REPO}/queries/siem_log_examples.json"
require_file "${DETECTIONS_REPO}/test_data/manifest.json"
require_file "${DETECTIONS_REPO}/scripts/logan_workbench_convert.py"
require_file "${DETECTIONS_REPO}/scripts/build_orm_stack.py"
require_file "${DETECTIONS_REPO}/config/sigma_oci_mapping.yaml"
require_file "${DETECTIONS_REPO}/config/mapping/_root.yaml"
require_file "${DETECTIONS_REPO}/stack/main.tf"

# Generate the same reviewed byte inventory consumed by the .git-free API image.
# Prepare the replacement fully before touching an existing runtime export.
if [[ -L "${RUNTIME_DIR}" ]]; then
  echo "Refusing symlink runtime destination" >&2
  exit 1
fi
STAGING_DIR="$(mktemp -d "${APP_ROOT}/.logan-detections-stage.XXXXXX")"
COMMITTED=false
cleanup() {
  local status=$?
  trap - EXIT
  if [[ -e "${STAGING_DIR}/previous" && "${COMMITTED}" != true ]]; then
    if [[ -e "${RUNTIME_DIR}" || -L "${RUNTIME_DIR}" ]] ||
       ! mv -- "${STAGING_DIR}/previous" "${RUNTIME_DIR}"; then
      echo "Previous runtime retained for recovery at ${STAGING_DIR}/previous" >&2
      return 1
    fi
  fi
  rm -rf -- "${STAGING_DIR}"
  return "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
python3 "${DETECTIONS_REPO}/scripts/build_orm_stack.py" \
  --stage-runtime "${STAGING_DIR}/runtime" --include-runtime-manifest
if [[ -e "${RUNTIME_DIR}" ]]; then
  mv -- "${RUNTIME_DIR}" "${STAGING_DIR}/previous"
fi
if ! mv -- "${STAGING_DIR}/runtime" "${RUNTIME_DIR}"; then
  exit 1
fi
COMMITTED=true

echo "Staged Logan detections runtime artifacts at ${RUNTIME_DIR}"
