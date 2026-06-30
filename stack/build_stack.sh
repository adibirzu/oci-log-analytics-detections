#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

python3 "$PROJECT_ROOT/scripts/build_orm_stack.py" \
  --out "$PROJECT_ROOT/oci-log-analytics-deployment.zip"

echo "Upload oci-log-analytics-deployment.zip to OCI Resource Manager to review and apply the selected deployment options."
