#!/usr/bin/env python3
"""Operator-facing documentation contracts for Splunk parallel delivery."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
GUIDES = (
    ROOT / "docs/SPLUNK_PARALLEL_OPERATIONS.md",
    ROOT / "docs/SPLUNK_RULE_MIGRATION.md",
    ROOT / "docs/SPLUNK_EVIDENCE_EXPORT_RUNBOOK.md",
    ROOT / "docs/SPLUNK_E2E_VALIDATION.md",
)
NAVIGATION_PAGES = (
    README,
    ROOT / "docs/README.md",
    ROOT / "docs/ARCHITECTURE.md",
    ROOT / "docs/MIGRATION_AND_SECURITY_GUIDE.md",
    ROOT / "docs/FAST_ONBOARDING_TRACK.md",
    ROOT / "docs/DEPLOYMENT.md",
    ROOT / "docs/WINDOWS_ACCESS_FAST_ONBOARDING.md",
    ROOT / "docs/WINDOWS_ACCESS_WORKFLOW_DIAGRAMS.md",
    *GUIDES,
)
MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")


def _read(path: Path) -> str:
    assert path.is_file(), f"missing documentation: {path.relative_to(ROOT)}"
    return path.read_text(encoding="utf-8")


def _local_target(page: Path, raw_target: str) -> Path | None:
    target = raw_target.strip().split(maxsplit=1)[0].strip("<>")
    parsed = urlsplit(target)
    if parsed.scheme or target.startswith(("#", "mailto:")):
        return None
    path = unquote(parsed.path)
    if not path:
        return None
    return (page.parent / path).resolve()


def test_operator_guides_cover_required_execution_contract() -> None:
    required_concepts = (
        "prerequisites",
        "ownership",
        "iam",
        "network",
        "manual",
        "script",
        "validation",
        "expected output",
        "failure modes",
        "cost",
        "retention",
        "privacy",
        "rollback",
        "cleanup",
        "replay",
        "evidence class",
        "oracle sources",
    )

    for guide in GUIDES:
        text = _read(guide).lower()
        for concept in required_concepts:
            assert concept in text, f"{guide.name} does not cover {concept}"
        assert "pinned" in text and "oci-splunk" in text
        assert "https://docs.oracle.com/" in text


def test_navigation_pages_only_link_to_existing_local_artifacts() -> None:
    for page in NAVIGATION_PAGES:
        text = _read(page)
        for raw_target in MARKDOWN_LINK.findall(text):
            target = _local_target(page, raw_target)
            if target is not None:
                assert target.exists(), (
                    f"broken local link in {page.relative_to(ROOT)}: {raw_target}"
                )


def test_readme_explains_both_modes_with_renderable_mermaid_and_full_guides() -> None:
    text = _read(README)
    assert "Mode 1" in text and "raw" in text.lower()
    assert "Mode 2" in text and "evidence" in text.lower()
    assert re.search(r"```mermaid\s+flowchart\s", text)
    for guide in GUIDES:
        assert f"docs/{guide.name}" in text
    assert "docs/diagrams/logan-splunk-architecture.mmd" in text
    assert "docs/diagrams/project-content-architecture.mmd" in text


def test_production_guidance_requires_reviewed_pinned_oci_splunk_ref() -> None:
    operations = _read(GUIDES[0])
    deployment = _read(ROOT / "docs/DEPLOYMENT.md")
    migration = _read(ROOT / "docs/MIGRATION_AND_SECURITY_GUIDE.md")
    combined = "\n".join((operations, deployment, migration)).lower()

    assert "2.2.0" in combined
    assert "a98167404f19be6d18235bccbf1113b59a259c4c" in combined
    assert "production" in combined
    assert "reviewed tag or commit" in combined
    assert "must not track" in combined and "main" in combined


def test_scripted_runbook_keeps_offline_and_mutating_gates_separate() -> None:
    text = _read(ROOT / "docs/SPLUNK_EVIDENCE_EXPORT_RUNBOOK.md")
    commands = (
        "splunk_evidence_exporter_cli.py plan --json",
        "splunk_evidence_exporter_cli.py validate-config",
        "stage_build_context.py --output",
        "terraform -chdir=stack plan",
        "terraform -chdir=stack apply",
        "splunk_evidence_exporter_cli.py canary-plan",
        "splunk_evidence_exporter_cli.py replay-plan",
    )
    offsets = [text.index(command) for command in commands]
    assert offsets == sorted(offsets)
    for approval in ("build approval", "apply approval", "canary approval", "replay approval"):
        assert approval in text.lower()


def test_guides_keep_acceptance_layers_distinct() -> None:
    combined = "\n".join(_read(guide).lower() for guide in GUIDES)
    for layer in (
        "collection",
        "parsing",
        "log analytics query",
        "detection rule",
        "monitoring metric",
        "alarm",
        "notifications",
        "function",
        "checkpoint",
        "dlq",
        "hec confirmation",
        "splunk searchability",
        "provider acceptance",
    ):
        assert layer in combined
