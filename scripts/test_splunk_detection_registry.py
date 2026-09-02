#!/usr/bin/env python3
"""Contract tests for Splunk parallel evidence delivery artifacts."""

import json
from pathlib import Path

import jsonschema
import yaml


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


def test_contract_schemas_are_valid_draft_2020_12():
    jsonschema.Draft202012Validator.check_schema(REGISTRY_SCHEMA)
    jsonschema.Draft202012Validator.check_schema(EVIDENCE_SCHEMA)


def test_registry_schema_accepts_policy_derived_entry():
    entry = valid_registry_entry()
    assert not list(REGISTRY_VALIDATOR.iter_errors(entry))
    assert (ROOT / entry["oci_query_file"]).is_file()


def test_evidence_schema_accepts_valid_event():
    assert not list(EVIDENCE_VALIDATOR.iter_errors(valid_evidence_event()))


def test_registry_schema_rejects_unknown_query_path():
    entry = valid_registry_entry()
    entry["oci_query_file"] = "queries/does_not_exist.json"
    assert not (ROOT / entry["oci_query_file"]).is_file()


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


def test_evidence_schema_rejects_hec_token():
    event = valid_evidence_event()
    event["hec_token"] = "secret"
    errors = list(EVIDENCE_VALIDATOR.iter_errors(event))
    assert any("Additional properties" in error.message for error in errors)
