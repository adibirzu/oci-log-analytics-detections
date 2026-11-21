#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${REPO_ROOT}"

HOST_ARCH="${GATE_HOST_ARCH_OVERRIDE:-$(uname -m)}"
case "${HOST_ARCH}" in
  arm64|aarch64)
    IS_ARM64=true
    ;;
  *)
    IS_ARM64=false
    ;;
esac

if [[ "${GATE_FORCE_CONTAINER:-0}" == "1" && "${IS_ARM64}" == "true" ]]; then
  echo "ERROR: Refusing local linux/amd64 container execution on arm64 host (${HOST_ARCH}); run on the amd64 container executor tier." >&2
  exit 1
fi

if [[ -n "${PYTHON_BIN:-}" ]]; then
  PYTHON="${PYTHON_BIN}"
elif command -v python3.11 >/dev/null 2>&1; then
  PYTHON="python3.11"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON="python3"
else
  echo "ERROR: python3.11 or python3 is required" >&2
  exit 1
fi

echo "[gate] Host arch=${HOST_ARCH} mode=non-container-workstation python=${PYTHON}"

echo "[gate] 1/7 Running deterministic conversion, provenance, Dockerfile pin, delivery, SBOM, and content-manifest tests"
"${PYTHON}" -m pytest -q \
  scripts/test_sentinel_conversion_workflow.py \
  scripts/test_dockerfile_pinning.py \
  scripts/test_delivery_pipeline.py \
  scripts/test_generate_sbom.py \
  scripts/test_generate_content_manifest.py \
  scripts/test_parser_contract.py \
  scripts/test_sentinel_compatibility.py \
  scripts/test_sentinel_drift_check.py \
  scripts/test_query_artifacts.py

echo "[gate] 2/7 Verifying CycloneDX SBOM freshness"
"${PYTHON}" scripts/generate_sbom.py --check

echo "[gate] 3/7 Verifying Log Analytics content manifest freshness"
"${PYTHON}" scripts/generate_content_manifest.py --check

echo "[gate] 4/7 Verifying hunting integration bundle freshness"
"${PYTHON}" scripts/generate_hunting_bundle.py --check

echo "[gate] 5/7 Checking Python module size and sensitive values"
"${PYTHON}" scripts/check_module_size.py
"${PYTHON}" scripts/scan_sensitive_values.py --json >/dev/null

echo "[gate] 6/7 Running ruff lint on gate-owned scripts"
if ! command -v ruff >/dev/null 2>&1; then
  echo "ERROR: ruff is required for scripts/ci/gate.sh" >&2
  exit 1
fi
ruff check \
  scripts/generate_content_manifest.py \
  scripts/sentinel_workflow_tests/provenance.py \
  scripts/test_dockerfile_pinning.py \
  scripts/test_delivery_pipeline.py \
  scripts/test_generate_content_manifest.py
ruff check --select E,F,W --ignore E501,E402 \
  scripts/sentinel_converter_reporting.py \
  scripts/sentinel_workflow/html_report.py \
  scripts/test_sentinel_conversion_workflow.py \
  scripts/generate_sbom.py \
  scripts/query_artifacts.py

echo "[gate] 7/7 Running shellcheck on scripts/ci/gate.sh"
if ! command -v shellcheck >/dev/null 2>&1; then
  echo "ERROR: shellcheck is required for scripts/ci/gate.sh" >&2
  exit 1
fi
shellcheck scripts/ci/gate.sh

echo "[gate] PASS: all non-container workstation gates passed"
