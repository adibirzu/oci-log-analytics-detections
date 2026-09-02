#!/usr/bin/env python3
"""Static contracts for the opt-in Splunk evidence exporter Terraform module."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
STACK = ROOT / "stack"
MODULE = STACK / "modules/splunk_evidence_exporter"
CLI = ROOT / "scripts/splunk_evidence_exporter_cli.py"
FUNCTION_SOURCE = MODULE / "function"


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
    assert re.search(
        r"splunk_evidence_exporter_alarm_ids:\s*.*?type:\s*object",
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

    assert 'resource "oci_monitoring_alarm" "governed_detection"' in main
    assert "governed_detection_alarm_ids" in main
    assert "windows-access-rdp-after-hours" in main
    governed = main.split('resource "oci_monitoring_alarm" "governed_detection"', 1)[1]
    assert re.search(r'\bis_enabled\s*=\s*false\b', governed)
    assert 'resource "oci_monitoring_alarm" "exporter_delivery_failures"' in main
    assert "oci_log_analytics_splunk_exporter" in _read(MODULE / "variables.tf")


def test_exporter_enablement_requires_complete_governed_alarm_bindings() -> None:
    main = _read(MODULE / "main.tf")
    variables = _read(MODULE / "variables.tf")
    outputs = _read(MODULE / "outputs.tf")
    root_outputs = _read(STACK / "outputs.tf")

    # The Function is the exporter enablement boundary.  It must not be
    # possible to deploy it with an empty, partial, or typoed binding map.
    function_match = re.search(
        r'resource\s+"oci_functions_function"\s+"exporter"\s*\{(?P<body>.*?)\n\}',
        main,
        re.DOTALL,
    )
    assert function_match, "missing oci_functions_function exporter"
    function = function_match.group("body")
    assert "set(keys(var.splunk_alarm_ids)) == local.governed_detection_alarm_ids" in function
    assert "alltrue(" in function
    assert "for alarm_id in values(var.splunk_alarm_ids)" in function
    assert 'regex("^ocid1\\\\.alarm\\\\.", alarm_id)' in function

    subscription_match = re.search(
        r'resource\s+"oci_ons_subscription"\s+"function"\s*\{(?P<body>.*?)\n\}',
        main,
        re.DOTALL,
    )
    assert subscription_match, "missing oci_ons_subscription function"
    subscription = subscription_match.group("body")
    assert "set(keys(var.splunk_alarm_ids)) == local.governed_detection_alarm_ids" in subscription

    assert 'output "governed_alarm_bindings"' in outputs
    binding_output = _block(outputs, "output", "governed_alarm_bindings")
    assert "var.splunk_alarm_ids" in binding_output
    assert re.search(r"\bsensitive\s*=\s*true\b", binding_output)
    assert 'output "splunk_evidence_exporter_governed_alarm_bindings"' in root_outputs

    alarm_variable = _block(variables, "variable", "splunk_alarm_ids")
    assert "governed detection binding keys" in alarm_variable


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

    operator_statements = "\n".join(categories["operator"]["statements"])
    assert (
        "Allow group <OPERATOR_GROUP_NAME> to manage buckets in compartment "
        "<STATE_COMPARTMENT_NAME> where any {target.bucket.name="
        "'<STATE_BUCKET_NAME>', target.bucket.name='<DLQ_BUCKET_NAME>'}"
        in operator_statements
    )
    assert (
        "Allow group <OPERATOR_GROUP_NAME> to manage objects in compartment "
        "<STATE_COMPARTMENT_NAME> where any {target.bucket.name="
        "'<STATE_BUCKET_NAME>', target.bucket.name='<DLQ_BUCKET_NAME>'}"
        in operator_statements
    )
    state_statements = "\n".join(categories["function-state-dlq"]["statements"])
    assert (
        "Allow service objectstorage-<REGION_IDENTIFIER> to manage object-family "
        "in compartment <STATE_COMPARTMENT_NAME> where any {target.bucket.name="
        "'<STATE_BUCKET_NAME>', target.bucket.name='<DLQ_BUCKET_NAME>'}"
        in state_statements
    )
    assert "<REGION_IDENTIFIER>" in rendered
    assert "object-family" in categories["function-state-dlq"]["warning"]


def test_function_build_metadata_points_to_existing_handler_without_credentials() -> None:
    manifest = _read(MODULE / "function/func.yaml")
    requirements = _read(MODULE / "function/requirements.txt")

    assert "runtime: python" in manifest
    assert "/function/func.py handler" in manifest
    assert "memory: 512" in manifest
    assert re.search(r"^fdk[^\n]*$", requirements, re.MULTILINE)
    assert re.search(r"^oci[^\n]*$", requirements, re.MULTILINE)
    combined = f"{manifest}\n{requirements}"
    assert not re.search(r"hec[_-]?(?:token|secret_value)", combined, re.IGNORECASE)


def _hcl_regex(block: str) -> str:
    match = re.search(r'can\(regex\("(?P<pattern>(?:\\.|[^"\\])+)"', block)
    assert match, "missing URL validation regex"
    return json.loads(f'"{match.group("pattern")}"')


@pytest.mark.parametrize(
    "url",
    [
        "http://splunk.example.invalid:8088/services/collector/event",
        "https://user:credential@splunk.example.invalid:8088/services/collector/event",
        "https://splunk.example.invalid:8088/services/collector/event?token=credential",
        "https://splunk.example.invalid:8088/services/collector/event#credential",
        "https://splunk.example.invalid:8088/services/collector",
        "https://splunk.example.invalid:8088/services/collector/event/",
        "https:///services/collector/event",
        "https://splunk_example.invalid:8088/services/collector/event",
        "https://splunk.example.invalid:0/services/collector/event",
        "https://splunk.example.invalid:65536/services/collector/event",
    ],
)
def test_hec_url_contract_rejects_unsafe_or_unsupported_urls(url: str) -> None:
    root_block = _block(
        _read(STACK / "variables.tf"),
        "variable",
        "splunk_evidence_exporter_hec_url",
    )
    child_block = _block(_read(MODULE / "variables.tf"), "variable", "splunk_hec_url")
    root_pattern = _hcl_regex(root_block)
    child_pattern = _hcl_regex(child_block)
    schema = yaml.safe_load(_read(STACK / "schema.yaml"))
    schema_pattern = schema["variables"]["splunk_evidence_exporter_hec_url"][
        "pattern"
    ]

    assert root_pattern == child_pattern
    assert re.fullmatch(root_pattern, url) is None
    assert re.fullmatch(schema_pattern, url) is None


@pytest.mark.parametrize(
    "url",
    [
        "https://splunk.example.invalid/services/collector/event",
        "https://splunk.example.invalid:8088/services/collector/event",
        "https://10.0.0.8:443/services/collector/event",
    ],
)
def test_hec_url_contract_accepts_only_supported_https_event_endpoint(url: str) -> None:
    root_block = _block(
        _read(STACK / "variables.tf"),
        "variable",
        "splunk_evidence_exporter_hec_url",
    )
    child_block = _block(_read(MODULE / "variables.tf"), "variable", "splunk_hec_url")
    schema = yaml.safe_load(_read(STACK / "schema.yaml"))
    schema_pattern = schema["variables"]["splunk_evidence_exporter_hec_url"][
        "pattern"
    ]

    assert re.fullmatch(_hcl_regex(root_block), url)
    assert re.fullmatch(_hcl_regex(child_block), url)
    assert re.fullmatch(schema_pattern, url)


def test_stage_command_builds_complete_context_from_canonical_sources(tmp_path: Path) -> None:
    stage_script = FUNCTION_SOURCE / "stage_build_context.py"
    documentation = _read(FUNCTION_SOURCE / "README.md")
    context = tmp_path / "function-context"

    assert "stage_build_context.py --output" in documentation
    result = subprocess.run(
        [sys.executable, str(stage_script), "--output", str(context)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["status"] == "staged"
    manifest = json.loads(_read(context / "build-context-manifest.json"))
    registry = json.loads(_read(ROOT / "queries/splunk_detection_registry.json"))
    expected = {
        "func.py",
        "func.yaml",
        "requirements.txt",
        "config/splunk_parallel_delivery.yaml",
        "queries/splunk_detection_registry.json",
        "schemas/splunk_evidence_event.schema.json",
        "scripts/__init__.py",
        *{
            path.relative_to(ROOT).as_posix()
            for path in (ROOT / "scripts/splunk_evidence_exporter").glob("*.py")
        },
        *{entry["oci_query_file"] for entry in registry["detections"]},
    }
    assert set(manifest["files"]) == expected
    for relative, digest in manifest["files"].items():
        staged = context / relative
        assert staged.is_file()
        assert hashlib.sha256(staged.read_bytes()).hexdigest() == digest
        source = ROOT / relative
        if relative.startswith(("config/", "queries/", "schemas/", "scripts/")):
            assert staged.read_bytes() == source.read_bytes()

    import_result = subprocess.run(
        [sys.executable, "-c", "import func; assert callable(func.handler)"],
        cwd=context,
        text=True,
        capture_output=True,
        check=False,
    )
    assert import_result.returncode == 0, import_result.stderr
    staged_text = "\n".join(
        path.read_text(encoding="utf-8", errors="ignore")
        for path in context.rglob("*")
        if path.is_file()
    )
    assert "ocid1." not in staged_text
    assert "Authorization: Splunk " not in staged_text
