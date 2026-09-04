#!/usr/bin/env python3
"""Operator-facing documentation contracts for Splunk parallel delivery."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
PINNED_OCI_SPLUNK_COMMIT = "a98167404f19be6d18235bccbf1113b59a259c4c"
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
    ROOT / "docs/LOG_ANALYTICS_COST_OPTIMIZATION.md",
    ROOT / "docs/DEPLOYMENT.md",
    ROOT / "docs/WINDOWS_ACCESS_FAST_ONBOARDING.md",
    ROOT / "docs/WINDOWS_ACCESS_WORKFLOW_DIAGRAMS.md",
    *GUIDES,
)
LOCAL_EVIDENCE_EXAMPLE = ROOT / "docs/health/splunk-parallel-local-evidence.example.json"
COST_GUIDE = ROOT / "docs/LOG_ANALYTICS_COST_OPTIMIZATION.md"
IMPLEMENTATION_PLAN = (
    ROOT / "docs/SPLUNK_PARALLEL_IMPLEMENTATION_PLAN.md"
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


def _subsection(text: str, heading: str) -> str:
    match = re.search(
        rf"^### {re.escape(heading)}\s*$\n(?P<body>.*?)(?=^#{{2,3}} |\Z)",
        text,
        re.MULTILINE | re.DOTALL,
    )
    assert match, f"missing subsection: {heading}"
    return match.group("body")


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


def test_navigation_exposes_implementation_assets_and_plan_status() -> None:
    navigation = "\n".join((_read(README), _read(ROOT / "docs/README.md")))
    for relative_path in (
        "config/splunk_parallel_delivery.yaml",
        "scripts/generate_splunk_detection_registry.py",
        "scripts/splunk_evidence_exporter_cli.py",
        "stack/modules/splunk_evidence_exporter",
        "docs/health/splunk-parallel-local-evidence.example.json",
        "docs/SPLUNK_PARALLEL_IMPLEMENTATION_PLAN.md",
    ):
        assert relative_path in navigation

    plan = _read(IMPLEMENTATION_PLAN)
    assert "Implementation status" in plan
    assert "Tasks 1-10" in plan and "complete" in plan.lower()
    assert "Provider validation remains not run" in plan


def test_production_guidance_requires_reviewed_pinned_oci_splunk_ref() -> None:
    operations = _read(GUIDES[0])
    deployment = _read(ROOT / "docs/DEPLOYMENT.md")
    migration = _read(ROOT / "docs/MIGRATION_AND_SECURITY_GUIDE.md")
    combined = "\n".join((operations, deployment, migration)).lower()

    assert PINNED_OCI_SPLUNK_COMMIT in combined
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


def test_customer_facing_commands_use_a_portable_python_interpreter() -> None:
    pages = (
        README,
        *(
            page
            for page in sorted(ROOT.rglob("*.md"))
                if ".superpowers" not in page.parts
                and not {
                    "node_modules",
                    "playwright-report",
                    "test-results",
                    ".next",
                }.intersection(page.parts)
            and not (
                "docs" in page.parts and "superpowers" in page.parts
            )
        ),
    )
    for page in pages:
        text = _read(page)
        assert "/Users/" not in text, f"developer-local path in {page.relative_to(ROOT)}"
    for guide in GUIDES:
        assert "python3" in _read(guide)


def test_cost_optimization_guide_covers_archive_workflow_and_sources() -> None:
    text = _read(COST_GUIDE)
    normalized = text.lower()

    for concept in (
        "active storage",
        "archive storage",
        "recall",
        "release",
        "purge",
        "mode 1",
        "mode 2",
        "management agent",
        "active storage used",
        "archival storage used",
        "recalledstorageinactivestorageused",
        "object storage archive",
        "splunk",
        "1 tb",
        "30 days",
    ):
        assert concept in normalized, concept
    assert "```mermaid" in text
    assert "https://docs.oracle.com/" in text
    assert "https://www.ateam-oracle.com/oci-logging-analytics-best-practices-series-cost-optimization" in text


def test_cost_guide_has_operational_anchors_and_authoritative_sources() -> None:
    text = _read(COST_GUIDE)
    for anchor in (
        "## Ownership and prerequisites",
        "## IAM boundary",
        "## Manual Console workflow",
        "## Read-only OCI CLI inspection",
        "## Approval-gated CLI templates",
        "## Validation and evidence",
        "## Failure modes",
        "## Rollback and cleanup",
        "## Security and privacy",
    ):
        assert anchor in text
    for url in (
        "https://docs.oracle.com/en-us/iaas/log-analytics/doc/manage-storage.html",
        "https://docs.oracle.com/en-us/iaas/log-analytics/doc/administer-other-actions.html",
        "https://docs.oracle.com/en-us/iaas/log-analytics/doc/iam-policies-catalog-logging-analytics.html",
        "https://docs.oracle.com/en-us/iaas/log-analytics/doc/security-your-logs-logging-analytics.html",
        "https://www.oracle.com/cloud/price-list/",
        "https://www.ateam-oracle.com/oci-logging-analytics-best-practices-series-cost-optimization",
    ):
        assert url in text


def test_cost_guide_labels_evidence_and_keeps_archive_claims_conservative() -> None:
    text = _read(COST_GUIDE)
    normalized = text.lower()
    assert "evidence class: locally verified" in normalized
    assert "provider validation: not_run" in normalized
    assert "customer acceptance: unverified" in normalized
    assert "not immediately searchable" in normalized
    assert "not an operator-managed object storage archive bucket" in normalized
    assert "no guaranteed savings" in normalized
    assert "recheck" in normalized
    assert "price" in normalized and "numeric" in normalized
    assert "/users/" not in normalized
    forbidden = (
        "archive data is immediately searchable",
        "archive data is instantly searchable",
        "archive guarantees savings",
        "object storage archive bucket is the log analytics archive",
    )
    for claim in forbidden:
        assert claim not in normalized


def test_cost_guide_cli_mutations_are_explicitly_approval_gated() -> None:
    text = _read(COST_GUIDE)
    inspection = text.index("## Read-only OCI CLI inspection")
    templates = text.index("## Approval-gated CLI templates")
    assert inspection < templates
    for command in (
        "oci log-analytics storage get-storage-usage",
        "oci log-analytics storage enable-archiving",
        "oci log-analytics storage estimate-recall-data-size",
        "oci log-analytics storage recall-archived-data",
        "oci log-analytics storage release-recalled-data",
    ):
        assert command in text
    gated = text[templates:]
    assert "explicit written approval" in gated.lower()
    assert "purge" not in gated.lower() or "not provided" in gated.lower()


def test_cost_guide_uses_supported_cli_parameters_and_monitoring_namespace() -> None:
    text = _read(COST_GUIDE)
    inspection = text[text.index("## Read-only OCI CLI inspection") : text.index("## Approval-gated CLI templates")]
    assert "oci log-analytics storage get-storage-usage" in inspection
    assert '--namespace-name "$LOG_ANALYTICS_NAMESPACE"' in inspection
    assert "--compartment-id \"$COMPARTMENT_OCID\"" not in inspection.split("oci monitoring", 1)[0]
    assert '--namespace "oci_logging_analytics"' in inspection
    templates = text[text.index("## Approval-gated CLI templates") : text.index("## Validation and evidence")]
    for option in ("--time-data-started", "--time-data-ended"):
        assert option in templates
    assert "--time-interval-start" not in templates
    assert "--time-interval-end" not in templates


def test_cost_guide_iam_boundaries_and_command_outputs_are_distinct() -> None:
    text = _read(COST_GUIDE)
    normalized = text.lower()
    assert "read loganalytics-storage" in normalized
    assert "use loganalytics-storage" in normalized
    assert "manage loganalytics-storage-work-request" in normalized
    assert "manage loganalytics-storage" in normalized
    assert "recall and release use\n`use loganalytics-storage`" in normalized
    assert "recall and release use\n`manage loganalytics-storage`" not in normalized
    assert "purge execution" in normalized
    assert "log_analytics_storage_purge" in normalized
    assert "not every operation returns a work-request" in normalized
    assert "`enable-archiving` returns" in normalized
    assert "`recall-archived-data` and `release-recalled-data` return" in normalized


def test_contributor_release_guidance_links_classified_local_evidence_example() -> None:
    contributing = _read(ROOT / "CONTRIBUTING.md")
    evidence = json.loads(_read(LOCAL_EVIDENCE_EXAMPLE))

    assert "release_checklist.py --splunk-parallel-offline-stage" in contributing
    assert "docs/health/splunk-parallel-local-evidence.example.json" in contributing
    assert "does not call OCI, Splunk HEC, Vault, or external endpoints" in contributing
    assert evidence["example"] is True
    assert evidence["receipt_type"] == "local_example"
    assert evidence["offline"] is True
    assert evidence["external_calls"] == []
    assert evidence["evidence_class"] == "locally_verified"
    assert evidence["provider_validation"] == "not_run"
    assert evidence["provider_verified"] is False
    assert "git_head_at_execution" in evidence["evidence_manifest"]
    assert "git_head_tree_at_execution" in evidence["evidence_manifest"]
    assert "working_tree_dirty" in evidence["evidence_manifest"]
    assert evidence["evidence_manifest"]["working_tree_dirty"] in (True, False)
    assert evidence["status"] == "PASS"
    assert evidence["scenario_counts"]["passed"] == 5
    assert evidence["artifact_hashes"]
    assert "docs/health/splunk-parallel-local-evidence.example.json" not in evidence["artifact_hashes"]
    assert evidence["artifact_hashes"] == evidence["evidence_manifest"]["files"]
    assert "generated_at" not in evidence
    for relative_path, expected_hash in evidence["artifact_hashes"].items():
        artifact = ROOT / relative_path
        assert artifact.is_file(), relative_path
        assert hashlib.sha256(artifact.read_bytes()).hexdigest() == expected_hash


def test_terraform_phases_are_not_misclassified_as_offline() -> None:
    runbook = _read(ROOT / "docs/SPLUNK_EVIDENCE_EXPORT_RUNBOOK.md")
    operations = _read(ROOT / "docs/SPLUNK_PARALLEL_OPERATIONS.md")
    e2e = _read(ROOT / "docs/SPLUNK_E2E_VALIDATION.md")
    combined = "\n".join((runbook, operations, e2e)).lower()

    assert "only the repository cli previews, validators, and deterministic function context staging are offline" in combined
    for page in (runbook, operations, e2e):
        normalized = page.replace("`", "").lower()
        assert "terraform init may contact provider registries" in normalized
        assert "terraform plan loads configured credentials and may read oci" in normalized
        assert "neither phase mutates infrastructure" in normalized
        assert "neither phase is offline or credential-free" in normalized
    assert "steps 1–3 are offline" not in combined
    assert "offline terraform" not in combined


def test_mode1_has_executable_pinned_preview_and_explicit_apply_gate() -> None:
    text = _read(ROOT / "docs/SPLUNK_PARALLEL_OPERATIONS.md")
    pinned_root = f"https://github.com/adibirzu/oci-splunk/blob/{PINNED_OCI_SPLUNK_COMMIT}"

    assert f"{pinned_root}/README.md" in text
    assert f"{pinned_root}/docs/DEPLOYMENT.md" in text
    commands = (
        "git clone https://github.com/adibirzu/oci-splunk.git oci-splunk",
        f"git -C oci-splunk checkout --detach {PINNED_OCI_SPLUNK_COMMIT}",
        "terraform -chdir=oci-splunk/terraform init -backend=false",
        "terraform -chdir=oci-splunk/terraform validate",
        "terraform -chdir=oci-splunk/terraform plan",
        "terraform -chdir=oci-splunk/terraform show -no-color",
        "terraform -chdir=oci-splunk/terraform apply",
    )
    offsets = [text.index(command) for command in commands]
    assert offsets == sorted(offsets)
    assert "Required variable categories and defaults" in text
    assert "Expected preview output" in text
    assert "Mode 1 preview failure handling" in text
    assert "Mode 1 apply approval" in text


def test_common_and_mode_prerequisites_do_not_cross_impose_services() -> None:
    for page in (
        ROOT / "docs/SPLUNK_PARALLEL_OPERATIONS.md",
        ROOT / "docs/SPLUNK_E2E_VALIDATION.md",
    ):
        text = _read(page)
        common = _subsection(text, "Common prerequisites")
        mode1 = _subsection(text, "Mode 1 prerequisites")
        mode2 = _subsection(text, "Mode 2 prerequisites")

        assert "explicit" in common.lower() and "approval" in common.lower()
        assert "Streaming" in mode1 and "oci-splunk" in mode1
        assert not re.search(r"\b(?:Vault|Function|alarm|subscription)\b", mode1, re.I)
        assert "Vault" in mode2 and "Function" in mode2 and "alarm" in mode2.lower()
        assert "Direct HEC" in mode2
        assert "OCI Streaming" in mode2 and "oci-splunk" in mode2
