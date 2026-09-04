"""Documentation contracts for the tenant-neutral OKE monitoring one-pager."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PAGE = ROOT / "docs" / "OKE_MONITORING_ONE_PAGER.md"


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_one_pager_is_linked_from_operator_entry_points() -> None:
    for relative in (
        "README.md",
        "docs/README.md",
        "docs/FAST_ONBOARDING_TRACK.md",
        "docs/OKE_OBSERVABILITY_RUNBOOK.md",
        "docs/ARCHITECTURE.md",
    ):
        assert "OKE_MONITORING_ONE_PAGER.md" in _read(relative), relative


def test_one_pager_names_upstream_pin_and_operational_boundaries() -> None:
    text = PAGE.read_text(encoding="utf-8")
    assert "oracle-quickstart/oci-kubernetes-monitoring" in text
    assert "oci-onm-4.3.0" in text
    assert "do not deploy mutable `main`" in text
    for heading in (
        "## What the solution collects",
        "## Prerequisites and ownership",
        "## IAM review — least privilege first",
        "## Choose one installation path",
        "## Acceptance checks",
        "## Evidence status",
    ):
        assert heading in text
    for component in (
        "OCI Log Analytics",
        "OCI Monitoring",
        "OCI Management Agent",
        "Fluentd",
        "Kubernetes RBAC",
        "OCI Resource Manager",
        "Optional Splunk evidence path",
    ):
        assert component in text


def test_one_pager_is_tenant_neutral_and_mermaid_is_safe() -> None:
    text = PAGE.read_text(encoding="utf-8")
    assert not re.search(r"(?i)ocid1\.|octodemo\.cloud|\bemdemo\b", text)
    assert not re.search(r"(?im)^\s*click\s+|<script|javascript:|%%\{\s*init", text)
    assert text.count("```mermaid") == 1
    assert text.count("```bash") == 2


def test_one_pager_bash_examples_parse_without_execution() -> None:
    text = PAGE.read_text(encoding="utf-8")
    blocks = re.findall(r"```bash\n(.*?)\n```", text, flags=re.DOTALL)
    assert blocks
    for block in blocks:
        result = subprocess.run(
            ["bash", "-n"], input=block, text=True, capture_output=True, check=False
        )
        assert result.returncode == 0, result.stderr
