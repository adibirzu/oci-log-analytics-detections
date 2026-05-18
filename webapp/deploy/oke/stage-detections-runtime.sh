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

if ! command -v rsync >/dev/null 2>&1; then
  echo "rsync is required to stage the runtime artifact bundle" >&2
  exit 1
fi

require_file "${DETECTIONS_REPO}/queries/logan_ql_reference_catalog.json"
require_file "${DETECTIONS_REPO}/queries/cross_ql_mapping_patterns.json"
require_file "${DETECTIONS_REPO}/queries/conversion_examples.json"
require_file "${DETECTIONS_REPO}/queries/catalog.json"
require_file "${DETECTIONS_REPO}/queries/dashboard_inventory.json"
require_file "${DETECTIONS_REPO}/test_data/manifest.json"
require_file "${DETECTIONS_REPO}/scripts/logan_workbench_convert.py"
require_file "${DETECTIONS_REPO}/config/sigma_oci_mapping.yaml"
require_file "${DETECTIONS_REPO}/config/mapping/_root.yaml"

rm -rf "${RUNTIME_DIR}"
mkdir -p "${RUNTIME_DIR}/config/mapping" "${RUNTIME_DIR}/scripts/kql" "${RUNTIME_DIR}/test_data"

cp "${DETECTIONS_REPO}/scripts/__init__.py" "${RUNTIME_DIR}/scripts/__init__.py"
cp "${DETECTIONS_REPO}/scripts/logan_workbench_convert.py" "${RUNTIME_DIR}/scripts/logan_workbench_convert.py"
cp "${DETECTIONS_REPO}/scripts/convert_sigma.py" "${RUNTIME_DIR}/scripts/convert_sigma.py"
cp "${DETECTIONS_REPO}/scripts/query_artifacts.py" "${RUNTIME_DIR}/scripts/query_artifacts.py"
cp "${DETECTIONS_REPO}/scripts/sync_sentinel_kql.py" "${RUNTIME_DIR}/scripts/sync_sentinel_kql.py"
rsync -a --delete --exclude "__pycache__/" --exclude "*.pyc" "${DETECTIONS_REPO}/scripts/kql/" "${RUNTIME_DIR}/scripts/kql/"
rsync -a --delete "${DETECTIONS_REPO}/queries/" "${RUNTIME_DIR}/queries/"
cp "${DETECTIONS_REPO}/config/sigma_oci_mapping.yaml" "${RUNTIME_DIR}/config/sigma_oci_mapping.yaml"
cp "${DETECTIONS_REPO}/config/sentinel_oci_mapping.yaml" "${RUNTIME_DIR}/config/sentinel_oci_mapping.yaml"
rsync -a --delete "${DETECTIONS_REPO}/config/mapping/" "${RUNTIME_DIR}/config/mapping/"
rsync -a --delete "${DETECTIONS_REPO}/schemas/" "${RUNTIME_DIR}/schemas/"
cp "${DETECTIONS_REPO}/test_data/manifest.json" "${RUNTIME_DIR}/test_data/manifest.json"

echo "Staged Logan detections runtime artifacts at ${RUNTIME_DIR}"
