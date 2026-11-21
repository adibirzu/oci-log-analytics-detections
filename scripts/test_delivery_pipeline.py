"""Contract tests for delivery/pipeline.yaml and scripts/ci/gate.sh."""

from __future__ import annotations

import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PIPELINE_PATH = ROOT / "delivery" / "pipeline.yaml"
GATE_PATH = ROOT / "scripts" / "ci" / "gate.sh"
SHA256_REF_RE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")


def test_delivery_pipeline_schema_and_policy():
    assert PIPELINE_PATH.is_file(), "delivery/pipeline.yaml must exist"
    pipeline = yaml.safe_load(PIPELINE_PATH.read_text(encoding="utf-8"))
    assert isinstance(pipeline, dict)
    assert pipeline.get("schema_version") == "1.0"
    assert pipeline.get("service") == "oci-log-analytics-detections"

    policy = pipeline.get("policy", {})
    assert policy.get("digest_only") is True
    assert policy.get("disallow_unpinned_base_images") is True
    assert policy.get("allow_local_amd64_emulation_on_arm64") is False

    tiers = pipeline.get("tiers", {})
    assert "workstation" in tiers
    assert "container_executor" in tiers
    workstation = tiers["workstation"]
    executor = tiers["container_executor"]
    assert workstation.get("container_execution") is False
    assert workstation.get("gate_script") == "scripts/ci/gate.sh"
    assert "arm64" in workstation.get("architectures", [])
    assert executor.get("container_execution") is True
    assert executor.get("platform") == "linux/amd64"

    images = pipeline.get("images", [])
    assert isinstance(images, list) and len(images) >= 2
    by_dockerfile = {img.get("dockerfile"): img for img in images}
    assert {"webapp/Dockerfile", "webapp/Dockerfile.lean"} <= set(by_dockerfile)
    for dockerfile_rel, image in by_dockerfile.items():
        assert (ROOT / dockerfile_rel).is_file()
        assert image.get("target_platform") == "linux/amd64"
        assert SHA256_REF_RE.match(str(image.get("base_image", "")))


def test_ci_gate_script_is_executable():
    assert GATE_PATH.is_file(), "scripts/ci/gate.sh must exist"
    mode = GATE_PATH.stat().st_mode
    assert mode & stat.S_IXUSR, "scripts/ci/gate.sh must be executable"


def test_ci_gate_script_refuses_forced_container_execution_on_arm64():
    result = subprocess.run(
        ["bash", str(GATE_PATH)],
        cwd=ROOT,
        env={
            **os.environ,
            "GATE_FORCE_CONTAINER": "1",
            "GATE_HOST_ARCH_OVERRIDE": "arm64",
        },
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode != 0
    assert "arm64" in (result.stderr + result.stdout).lower()


def test_resolve_generated_at_rejects_non_numeric_source_date_epoch(monkeypatch):
    sys.path.insert(0, str(ROOT / "scripts"))
    from sentinel_converter_reporting import resolve_generated_at

    monkeypatch.setenv("SOURCE_DATE_EPOCH", "0")
    assert resolve_generated_at() == "1970-01-01T00:00:00+00:00"
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "abc")
    try:
        resolve_generated_at()
    except ValueError as error:
        assert "SOURCE_DATE_EPOCH" in str(error)
    else:
        raise AssertionError("expected ValueError")
