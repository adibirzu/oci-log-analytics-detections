#!/usr/bin/env python3
"""Static contracts for the opt-in Splunk evidence exporter Terraform module."""

from __future__ import annotations

import re
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STACK = ROOT / "stack"
MODULE = STACK / "modules/splunk_evidence_exporter"
CLI = ROOT / "scripts/splunk_evidence_exporter_cli.py"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _block(text: str, kind: str, name: str) -> str:
    match = re.search(
        rf'{kind}\s+"{re.escape(name)}"\s*\{{(?P<body>.*?)\n\}}',
        text,
        re.DOTALL,
    )
    assert match, f"missing {kind} {name}"
    return match.group("body")


def test_exporter_is_opt_in_at_root_and_module_boundary() -> None:
    root_variables = _read(STACK / "variables.tf")
    root_main = _read(STACK / "main.tf")
    schema = _read(STACK / "schema.yaml")
    module_variables = _read(MODULE / "variables.tf")

    for text in (root_variables, module_variables):
        enable = _block(text, "variable", "enable_splunk_evidence_exporter")
        assert re.search(r"\btype\s*=\s*bool\b", enable)
        assert re.search(r"\bdefault\s*=\s*false\b", enable)

    module = _block(root_main, "module", "splunk_evidence_exporter")
    assert re.search(
        r"\benable_splunk_evidence_exporter\s*=\s*var\.enable_splunk_evidence_exporter\b",
        module,
    )
    assert re.search(
        r"\benable_alarm_actions\s*=\s*var\.enable_splunk_evidence_exporter_alarm_actions\b",
        module,
    )
    assert re.search(
        r"\benable_notification_subscription\s*=\s*var\.enable_splunk_evidence_exporter_subscription\b",
        module,
    )
    assert re.search(
        r"enable_splunk_evidence_exporter:\s*.*?default:\s*false",
        schema,
        re.DOTALL,
    )
    assert re.search(
        r"enable_splunk_evidence_exporter_alarm_actions:\s*.*?default:\s*false",
        schema,
        re.DOTALL,
    )
    assert re.search(
        r"enable_splunk_evidence_exporter_subscription:\s*.*?default:\s*false",
        schema,
        re.DOTALL,
    )


def test_existing_vault_secret_reference_is_the_only_secret_interface() -> None:
    terraform = "\n".join(
        _read(path) for path in sorted(STACK.rglob("*.tf"))
    )
    module_variables = _read(MODULE / "variables.tf")
    secret = _block(module_variables, "variable", "splunk_hec_secret_id")

    assert re.search(r"\bsensitive\s*=\s*true\b", secret)
    assert "existing OCI Vault secret OCID" in secret
    assert re.search(
        r'can\(regex\(\"\^ocid1\\\\\.vaultsecret\\\\\.\"\s*,\s*var\.splunk_hec_secret_id\)\)',
        secret,
    )
    assert not re.search(
        r'variable\s+"[^\"]*(?:hec_)?(?:token|secret_value)[^\"]*"',
        terraform,
        re.IGNORECASE,
    )
    assert not re.search(
        r'output\s+"[^\"]*(?:hec_)?(?:token|secret_value)[^\"]*"',
        terraform,
        re.IGNORECASE,
    )
    assert 'resource "oci_vault_secret"' not in terraform


def test_module_wires_only_the_scoped_exporter_path_with_logging_and_lifecycle() -> None:
    main = _read(MODULE / "main.tf")

    assert re.search(
        r'required_providers\s*\{.*?oci\s*=\s*\{.*?source\s*=\s*"oracle/oci"',
        main,
        re.DOTALL,
    )
    assert 'resource "oci_core_vcn"' not in main
    assert 'resource "oci_core_subnet"' not in main
    assert 'resource "oci_functions_application" "exporter"' in main
    assert re.search(r"\bsubnet_ids\s*=\s*var\.function_subnet_ids\b", main)
    assert "line_format = \"JSON\"" in main

    assert 'resource "oci_functions_function" "exporter"' in main
    assert re.search(
        r"\bapplication_id\s*=\s*oci_functions_application\.exporter\[0\]\.id\b",
        main,
    )
    assert "SPLUNK_HEC_SECRET_ID" in main
    assert "var.splunk_hec_secret_id" in main
    assert "SPLUNK_EVIDENCE_STATE_BUCKET" in main
    assert "SPLUNK_EVIDENCE_DLQ_BUCKET" in main
    assert "SPLUNK_EVIDENCE_MAX_ROWS" in main

    assert 'resource "oci_ons_notification_topic" "evidence"' in main
    assert 'resource "oci_ons_subscription" "function"' in main
    assert re.search(
        r"\bcount\s*=\s*local\.enabled\s*&&\s*var\.enable_notification_subscription\s*\?\s*1\s*:\s*0",
        main,
    )
    assert re.search(r'\bprotocol\s*=\s*"ORACLE_FUNCTIONS"', main)
    assert re.search(
        r"\btopic_id\s*=\s*oci_ons_notification_topic\.evidence\[0\]\.id\b",
        main,
    )
    assert re.search(
        r"\bendpoint\s*=\s*oci_functions_function\.exporter\[0\]\.id\b",
        main,
    )

    assert 'resource "oci_logging_log" "function_invocation"' in main
    assert re.search(r'\bcategory\s*=\s*"invoke"', main)
    assert re.search(r'\bservice\s*=\s*"functions"', main)
    assert re.search(
        r"\bresource\s*=\s*oci_functions_application\.exporter\[0\]\.id\b",
        main,
    )
    assert re.search(r"\bis_enabled\s*=\s*true\b", main)

    for name in ("state", "dlq"):
        assert f'resource "oci_objectstorage_bucket" "{name}"' in main
        assert f'resource "oci_objectstorage_object_lifecycle_policy" "{name}"' in main
    assert len(re.findall(r'\baccess_type\s*=\s*"NoPublicAccess"', main)) == 2
    assert len(re.findall(r'\bversioning\s*=\s*"Enabled"', main)) == 2
    assert len(re.findall(r'\baction\s*=\s*"DELETE"', main)) >= 2

    assert 'resource "oci_monitoring_alarm" "function_errors"' in main
    assert 'resource "oci_ons_notification_topic" "operational_alerts"' in main
    assert re.search(r"\bis_enabled\s*=\s*var\.enable_alarm_actions\b", main)
    assert re.search(r'\bnamespace\s*=\s*"oci_faas"', main)
    assert re.search(
        r"\bdestinations\s*=\s*\[oci_ons_notification_topic\.operational_alerts\[0\]\.id\]",
        main,
    )
    assert 'FunctionResponseCount[5m]' in main
    assert "oci_functions_function.exporter[0].id" in main


def test_identifier_outputs_are_explicitly_sensitive_and_never_include_secrets() -> None:
    module_outputs = _read(MODULE / "outputs.tf")
    root_outputs = _read(STACK / "outputs.tf")

    for text, names in (
        (
            module_outputs,
            ("resource_identifiers", "function_dynamic_group_matching_rule"),
        ),
        (root_outputs, ("splunk_evidence_exporter_resource_identifiers",)),
    ):
        for name in names:
            body = _block(text, "output", name)
            assert re.search(r"\bsensitive\s*=\s*true\b", body)
            assert not re.search(r"token|secret_value", body, re.IGNORECASE)

    identifiers = _block(module_outputs, "output", "resource_identifiers")
    for name in (
        "application_id",
        "function_id",
        "topic_id",
        "operational_topic_id",
        "subscription_id",
        "log_group_id",
        "state_bucket_name",
        "dlq_bucket_name",
    ):
        assert name in identifiers


def test_iam_preview_separates_eight_reviewable_policy_boundaries() -> None:
    result = subprocess.run(
        [sys.executable, str(CLI), "render-iam"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    preview = json.loads(result.stdout)
    categories = {entry["id"]: entry for entry in preview["policy_categories"]}
    assert set(categories) == {
        "operator",
        "connector-hub-mode-1",
        "function-log-analytics-query",
        "function-vault-secret",
        "function-state-dlq",
        "notifications-function-invocation",
        "monitoring",
        "logging",
    }
    assert all(entry["statements"] for entry in categories.values())
    rendered = json.dumps(preview, sort_keys=True)
    for placeholder in (
        "<OPERATOR_GROUP_NAME>",
        "<FUNCTION_DYNAMIC_GROUP_NAME>",
        "<FUNCTION_COMPARTMENT_NAME>",
        "<FUNCTION_OCID>",
        "<LOG_ANALYTICS_COMPARTMENT_NAME>",
        "<VAULT_COMPARTMENT_NAME>",
        "<EXISTING_VAULT_SECRET_OCID>",
        "<STATE_COMPARTMENT_NAME>",
        "<STATE_BUCKET_NAME>",
        "<DLQ_BUCKET_NAME>",
        "<MODE1_CONNECTOR_OCID>",
        "<MODE1_LOG_COMPARTMENT_NAME>",
        "<MODE1_STREAM_COMPARTMENT_NAME>",
    ):
        assert placeholder in rendered
    assert "resource-family shortcuts broaden access" in preview["warnings"]
    assert preview["apply_supported"] is False
    assert preview["requires_scope_review"] is True


def test_function_build_metadata_points_to_existing_handler_without_credentials() -> None:
    manifest = _read(MODULE / "function/func.yaml")
    requirements = _read(MODULE / "function/requirements.txt")

    assert "runtime: python" in manifest
    assert "scripts/splunk_evidence_exporter/handler.py handler" in manifest
    assert "memory: 512" in manifest
    assert re.search(r"^fdk[^\n]*$", requirements, re.MULTILINE)
    assert re.search(r"^oci[^\n]*$", requirements, re.MULTILINE)
    combined = f"{manifest}\n{requirements}"
    assert not re.search(r"hec[_-]?(?:token|secret_value)", combined, re.IGNORECASE)
