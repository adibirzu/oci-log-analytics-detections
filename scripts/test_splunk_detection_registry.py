#!/usr/bin/env python3
"""Contract tests for Splunk parallel evidence delivery artifacts."""

import json
from pathlib import Path

import jsonschema
import yaml
from scripts.splunk_delivery_contracts import registry_validation_errors
from scripts.generate_splunk_detection_registry import build_registry, validate_registry


ROOT = Path(__file__).resolve().parents[1]
POLICY = yaml.safe_load((ROOT / "config/splunk_parallel_delivery.yaml").read_text())
REGISTRY_SCHEMA = json.loads(
    (ROOT / "schemas/splunk_detection_registry.schema.json").read_text()
)
EVIDENCE_SCHEMA = json.loads(
    (ROOT / "schemas/splunk_evidence_event.schema.json").read_text()
)
REGISTRY_VALIDATOR = jsonschema.Draft202012Validator(REGISTRY_SCHEMA)
EVIDENCE_VALIDATOR = jsonschema.Draft202012Validator(EVIDENCE_SCHEMA)


def delivery_config_with_migration(tmp_path: Path, **overrides) -> Path:
    """Write a minimal delivery policy with one portable migration entry."""
    migration = {
        "id": "oci-console-login-failure",
        "title": "OCI Console Login Failure",
        "splunk": {
            "repository": "adibirzu/oci-splunk",
            "app": "oci-splunk",
            "version": "v1.0.0",
            "saved_search": "OCI Audit failures",
        },
        "oci_query_file": "queries/oci_console_login_failure.json",
        "required_sources": ["OCI Audit Logs"],
        "required_fields": ["Event Type", "Status"],
        "fidelity": "evidence",
        "detection": {"severity": "medium", "mitre_techniques": ["T1078"]},
    }
    migration.update(overrides)
    policy = {
        "version": 1,
        "defaults": POLICY["defaults"],
        "detections": {"enabled": True, "migrations": [migration]},
        "splunk_target": POLICY["splunk_target"],
    }
    path = tmp_path / "splunk_parallel_delivery.yaml"
    path.write_text(yaml.safe_dump(policy), encoding="utf-8")
    return path


def test_registry_is_deterministic(tmp_path: Path):
    config = delivery_config_with_migration(tmp_path)
    first = build_registry(config)
    second = build_registry(config)
    first.pop("generated_at", None)
    second.pop("generated_at", None)
    assert first == second
    assert [x["id"] for x in first["detections"]] == sorted(
        x["id"] for x in first["detections"]
    )


def test_registry_preserves_splunk_provenance(tmp_path: Path):
    registry = build_registry(delivery_config_with_migration(tmp_path))
    provenance = registry["splunk_provenance"]["oci-console-login-failure"]
    assert provenance == {
        "repository": "adibirzu/oci-splunk",
        "app": "oci-splunk",
        "version": "v1.0.0",
        "saved_search": "OCI Audit failures",
    }


def test_registry_rejects_missing_query_files_and_fields(tmp_path: Path):
    missing_query = build_registry(
        delivery_config_with_migration(tmp_path, oci_query_file="queries/missing.json")
    )
    missing_field = build_registry(
        delivery_config_with_migration(tmp_path, required_fields=["Definitely Missing Field"])
    )
    assert any("canonical query" in error for error in validate_registry(missing_query))
    assert any("required field" in error for error in validate_registry(missing_field))


def test_registry_rejects_ineligible_scheduled_detection_and_secret_keys(tmp_path: Path):
    registry = build_registry(delivery_config_with_migration(tmp_path))
    registry["splunk_provenance"]["oci-console-login-failure"]["hec_token"] = "not-a-token"
    errors = validate_registry(registry)
    assert any("not scheduled-detection eligible" in error for error in errors)
    assert any("forbidden secret or tenant key" in error for error in errors)


def test_registry_requires_complete_splunk_provenance(tmp_path: Path):
    registry = build_registry(delivery_config_with_migration(tmp_path))
    del registry["splunk_provenance"]["oci-console-login-failure"]["version"]
    assert any("provenance is missing version" in error for error in validate_registry(registry))


def valid_registry_entry():
    return {
        "id": "oci-console-login-failure",
        "title": "OCI Console Login Failure",
        "splunk": {
            "index": "${SPLUNK_HEC_INDEX}",
            "sourcetype": POLICY["defaults"]["sourcetype"],
            "dimensions": ["rule_id", "severity"],
        },
        "oci_query_file": "queries/oci_console_login_failure.json",
        "required_sources": ["OCI Audit Logs"],
        "required_fields": ["Event Type", "Status", "Time"],
        "fidelity": "evidence",
        "detection": {"severity": "medium", "mitre_techniques": ["T1078"]},
        "delivery": {
            "delivery_mode": POLICY["defaults"]["delivery_mode"],
            "lookback": POLICY["defaults"]["lookback"],
            "overlap": POLICY["defaults"]["overlap"],
            "max_rows": POLICY["defaults"]["max_rows"],
            "max_batch_events": POLICY["defaults"]["max_batch_events"],
            "max_attempts": POLICY["defaults"]["max_attempts"],
        },
        "evidence": {
            "include_original_content": POLICY["defaults"]["include_original_content"],
            "redaction_profile": None,
        },
    }


def valid_evidence_event():
    return {
        "schema_version": "oci.logan.splunk.evidence.v1",
        "event_key": "oci-console-login-failure:2026-09-02T00:00:00Z",
        "batch_id": "batch-20260902-0001",
        "detection": {
            "id": "oci-console-login-failure",
            "title": "OCI Console Login Failure",
            "severity": "medium",
        },
        "evidence": {
            "include_original_content": False,
            "fields": [
                {"name": "Event Type", "value": "com.oraclecloud.consolesignon.login"}
            ],
        },
        "provenance": {
            "product": "OCI Log Analytics",
            "query_file": "queries/oci_console_login_failure.json",
            "window_start": "2026-09-02T00:00:00Z",
            "window_end": "2026-09-02T00:15:00Z",
        },
    }


def valid_original_content_event():
    event = valid_evidence_event()
    event["evidence"]["include_original_content"] = True
    event["evidence"]["original_content"] = {
        "redaction_profile": "oci-log-content-v1",
        "records": [
            {
                "source_field": "Original Log Content",
                "redacted_content": "<REDACTED>",
            }
        ],
    }
    return event


def test_contract_schemas_are_valid_draft_2020_12():
    jsonschema.Draft202012Validator.check_schema(REGISTRY_SCHEMA)
    jsonschema.Draft202012Validator.check_schema(EVIDENCE_SCHEMA)


def test_registry_schema_accepts_policy_derived_entry():
    entry = valid_registry_entry()
    assert not registry_validation_errors(entry, ROOT)


def test_evidence_schema_accepts_valid_event():
    assert not list(EVIDENCE_VALIDATOR.iter_errors(valid_evidence_event()))


def test_evidence_schema_accepts_bounded_redacted_original_content_opt_in():
    assert not list(EVIDENCE_VALIDATOR.iter_errors(valid_original_content_event()))


def test_registry_schema_rejects_unknown_query_path():
    entry = valid_registry_entry()
    entry["oci_query_file"] = "queries/does_not_exist.json"
    assert registry_validation_errors(entry, ROOT)


def test_registry_schema_rejects_more_than_three_dimensions():
    entry = valid_registry_entry()
    entry["splunk"]["dimensions"].extend(["source", "entity"])
    assert list(REGISTRY_VALIDATOR.iter_errors(entry))


def test_registry_schema_requires_redaction_profile_for_original_content():
    entry = valid_registry_entry()
    entry["evidence"]["include_original_content"] = True
    errors = list(REGISTRY_VALIDATOR.iter_errors(entry))
    assert errors


def test_evidence_schema_requires_event_key():
    event = valid_evidence_event()
    del event["event_key"]
    assert list(EVIDENCE_VALIDATOR.iter_errors(event))


def test_evidence_schema_rejects_original_log_content_by_default():
    event = valid_evidence_event()
    event["evidence"]["fields"].append(
        {"name": "Original Log Content", "value": "unredacted"}
    )
    assert list(EVIDENCE_VALIDATOR.iter_errors(event))


def test_evidence_schema_rejects_unbounded_original_content_records():
    event = valid_original_content_event()
    event["evidence"]["original_content"]["records"] *= 11
    assert list(EVIDENCE_VALIDATOR.iter_errors(event))


def test_evidence_schema_rejects_hec_token():
    event = valid_evidence_event()
    event["hec_token"] = "secret"
    errors = list(EVIDENCE_VALIDATOR.iter_errors(event))
    assert any("Additional properties" in error.message for error in errors)
