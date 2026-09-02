#!/usr/bin/env python3
"""Contract tests for Splunk parallel evidence delivery artifacts."""

import json
import re
from pathlib import Path

import jsonschema
import yaml
from scripts.splunk_delivery_contracts import registry_validation_errors
from scripts.generate_splunk_detection_registry import (
    EVIDENCE_SCHEMA,
    build_registry,
    validate_registry,
)
from scripts.detection_rule_creator import build_detection_rule_spec
from scripts.testlogs import network, oci_audit


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

INITIAL_MIGRATION_IDS = {
    "vcn-rejected-traffic-spike",
    "oci-audit-failures",
    "oci-iam-policy-change",
    "object-storage-new-external-source",
    "windows-access-administrator-logon",
    "windows-access-failed-logon-burst",
    "windows-access-new-local-user",
    "windows-access-privileged-group-add",
    "windows-access-rdp-after-hours",
}

WINDOWS_ACCESS_QUERY_FILES = {
    "windows-access-administrator-logon": "queries/hunting/windows_access_administrator_logon.json",
    "windows-access-failed-logon-burst": "queries/hunting/windows_access_failed_logon_burst.json",
    "windows-access-new-local-user": "queries/hunting/windows_access_new_local_user.json",
    "windows-access-privileged-group-add": "queries/hunting/windows_access_privileged_group_add.json",
    "windows-access-rdp-after-hours": "queries/hunting/windows_access_rdp_after_hours.json",
}


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
            "source_url": "https://github.com/adibirzu/oci-splunk/blob/v1.0.0/savedsearches.conf",
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


def test_initial_migration_pack_is_complete_and_valid():
    assert POLICY["detections"]["registry_file"] == "queries/splunk_detection_registry.json"
    registry = build_registry()
    by_id = {entry["id"]: entry for entry in registry["detections"]}

    assert set(by_id) == INITIAL_MIGRATION_IDS
    assert validate_registry(registry) == []

    for identifier, entry in by_id.items():
        query_path = ROOT / entry["oci_query_file"]
        provenance = registry["splunk_provenance"][identifier]

        assert query_path.is_file()
        assert provenance["source_url"].startswith("https://")
        assert provenance["repository"]
        assert provenance["version"]
        assert provenance["saved_search"]
        assert entry["required_sources"]
        assert entry["required_fields"]
        assert entry["fidelity"] in {"evidence", "raw"}
        assert entry["delivery"]["delivery_mode"] in {"evidence", "raw"}


def test_initial_migration_pack_is_scheduled_detection_eligible():
    registry = build_registry()

    for entry in registry["detections"]:
        query_payload = json.loads((ROOT / entry["oci_query_file"]).read_text())
        spec = build_detection_rule_spec(entry["oci_query_file"], query_payload)
        numeric_metric_aliases = re.findall(
            r"\b(?:count|sum|max|min|avg|average|distinctcount)\s+as\s+[A-Za-z_][A-Za-z0-9_]*",
            query_payload["query"],
            flags=re.IGNORECASE,
        )

        assert spec["eligible"], f"{entry['id']}: {spec['reasons']}"
        assert len(numeric_metric_aliases) == 1, entry["id"]
        assert spec["metric_name"]
        assert len(spec["dimensions"]) <= 3


def test_windows_access_migrations_reuse_the_existing_five_minute_queries():
    registry = build_registry()
    by_id = {entry["id"]: entry for entry in registry["detections"]}

    for identifier, query_file in WINDOWS_ACCESS_QUERY_FILES.items():
        assert by_id[identifier]["oci_query_file"] == query_file
        payload = json.loads((ROOT / query_file).read_text())
        spec = build_detection_rule_spec(query_file, payload)
        assert spec["schedule"] == "5m"
        assert spec["lookback"] == "5m"
        assert by_id[identifier]["delivery"]["lookback"] == "5m"


def test_initial_migration_pack_has_positive_and_negative_synthetic_records():
    vcn_events = network.generate_splunk_migration_vcn_flow_events()
    rejected_by_source = {
        source: sum(
            event["Action"] == "REJECT" and event["Source IP"] == source
            for event in vcn_events
        )
        for source in {event["Source IP"] for event in vcn_events}
    }
    assert sorted(rejected_by_source.values()) == [100, 101]

    audit_events = oci_audit.generate_splunk_migration_audit_events()
    by_resource = {event["Resource Name"]: event for event in audit_events}

    assert by_resource["splunk-migration-audit-failure-positive"]["Status"] == "Failure"
    assert by_resource["splunk-migration-audit-failure-negative"]["Status"] == "Success"
    assert by_resource["splunk-migration-iam-change-positive"]["Event Type"].endswith("updatepolicy")
    assert by_resource["splunk-migration-iam-change-negative"]["Event Type"].endswith("listpolicies")
    assert by_resource["splunk-migration-object-external-positive"]["Source IP"].startswith("203.0.113.")
    assert by_resource["splunk-migration-object-external-negative"]["Source IP"].startswith("10.")


def test_registry_preserves_splunk_provenance(tmp_path: Path):
    registry = build_registry(delivery_config_with_migration(tmp_path))
    provenance = registry["splunk_provenance"]["oci-console-login-failure"]
    assert provenance == {
        "repository": "adibirzu/oci-splunk",
        "app": "oci-splunk",
        "version": "v1.0.0",
        "saved_search": "OCI Audit failures",
        "source_url": "https://github.com/adibirzu/oci-splunk/blob/v1.0.0/savedsearches.conf",
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

    registry = build_registry(delivery_config_with_migration(tmp_path))
    del registry["splunk_provenance"]["oci-console-login-failure"]["source_url"]
    assert any("provenance is missing source_url" in error for error in validate_registry(registry))


def test_registry_rejects_sensitive_values_but_allows_documented_placeholders(tmp_path: Path):
    registry = build_registry(delivery_config_with_migration(tmp_path))
    provenance = registry["splunk_provenance"]["oci-console-login-failure"]
    for sensitive_value in (
        "ocid1.tenancy.oc1..example",
        "10.20.30.40",
        "splunk.private.example.com",
        "https://splunk.example.com/services/search",
        "namespace=customer-a",
        "token=not-a-real-token",
    ):
        provenance["saved_search"] = sensitive_value
        assert any("forbidden sensitive value" in error for error in validate_registry(registry))

    provenance["saved_search"] = "<SPLUNK_SAVED_SEARCH>"
    assert not any("forbidden sensitive value" in error for error in validate_registry(registry))
    provenance["topology"] = "not-permitted"
    assert any("forbidden secret or tenant key" in error for error in validate_registry(registry))


def test_registry_allows_only_approved_public_provenance_urls(tmp_path: Path):
    registry = build_registry(delivery_config_with_migration(tmp_path))
    provenance = registry["splunk_provenance"]["oci-console-login-failure"]

    provenance["source_url"] = "https://github.com/adibirzu/oci-splunk/blob/ref/file.conf"
    assert not any("source_url" in error for error in validate_registry(registry))

    for invalid_url in (
        "not-a-url",
        "http://github.com/adibirzu/oci-splunk/blob/ref/file.conf",
        "https://splunk.private.example.com/savedsearches.conf",
    ):
        provenance["source_url"] = invalid_url
        assert any("source_url" in error for error in validate_registry(registry))


def test_registry_requires_migration_title_to_match_canonical_query(tmp_path: Path):
    registry = build_registry(delivery_config_with_migration(tmp_path, title="Incorrect title"))
    assert any("title does not match canonical query title" in error for error in validate_registry(registry))


def test_generator_loads_and_validates_the_evidence_event_schema():
    jsonschema.Draft202012Validator.check_schema(EVIDENCE_SCHEMA)
    assert not any(
        "evidence event schema invalid" in error
        for error in validate_registry({"version": 1, "detections": [], "splunk_provenance": {}})
    )


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
