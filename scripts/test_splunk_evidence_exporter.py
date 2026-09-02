#!/usr/bin/env python3
"""Public-contract tests for the pure Splunk evidence exporter domain."""

import json
import ast
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jsonschema
import pytest

from scripts.splunk_evidence_exporter import (
    AlarmTrigger,
    ExportBatch,
    QueryWindow,
    batch_events,
    build_evidence_event,
    calculate_window,
    classify_hec_failure,
    event_key,
)
from scripts.splunk_evidence_exporter.ports import (
    CheckpointPort,
    EvidenceQueryPort,
    HecDeliveryPort,
    QuarantinePort,
)


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_VALIDATOR = jsonschema.Draft202012Validator(
    json.loads((ROOT / "schemas/splunk_evidence_event.schema.json").read_text())
)


def alarm_payload(**overrides):
    data = {
        "detectionId": "oci-audit-failures",
        "alarmEndTime": "2026-09-02T07:15:00Z",
        "namespace": "oci_log_analytics_detections",
        "metricName": "AuditFailures",
        "dimensions": {
            "Event Type": "com.oraclecloud.identitycontrolplane.updatepolicy",
            "User Name": "operator@example.invalid",
            "Status": "Failure",
        },
    }
    data.update(overrides)
    return {"type": "com.oraclecloud.monitoring.alarm", "data": data}


def test_alarm_trigger_decodes_sanitized_notification():
    trigger = AlarmTrigger.from_payload(alarm_payload())

    assert trigger.detection_id == "oci-audit-failures"
    assert trigger.alarm_end == datetime(2026, 9, 2, 7, 15, tzinfo=timezone.utc)
    assert trigger.namespace == "oci_log_analytics_detections"
    assert trigger.metric_name == "AuditFailures"
    assert dict(trigger.dimensions) == {
        "Event Type": "com.oraclecloud.identitycontrolplane.updatepolicy",
        "User Name": "operator@example.invalid",
        "Status": "Failure",
    }


@pytest.mark.parametrize(
    "overrides",
    [
        {"detectionId": ""},
        {
            "dimensions": {
                "one": "1",
                "two": "2",
                "three": "3",
                "four": "4",
            }
        },
    ],
)
def test_alarm_trigger_rejects_unsafe_identity_or_cardinality(overrides):
    with pytest.raises(ValueError):
        AlarmTrigger.from_payload(alarm_payload(**overrides))


def test_query_window_includes_lookback_and_overlap_without_checkpoint():
    alarm_end = datetime(2026, 9, 2, 7, 15, tzinfo=timezone.utc)

    window = calculate_window(
        alarm_end,
        lookback=timedelta(minutes=15),
        overlap=timedelta(minutes=2),
        checkpoint=None,
        maximum=timedelta(hours=1),
    )

    assert window.start == datetime(2026, 9, 2, 6, 58, tzinfo=timezone.utc)
    assert window.end == alarm_end
    assert window.duration == timedelta(minutes=17)


def test_query_window_starts_at_checkpoint_minus_overlap():
    alarm_end = datetime(2026, 9, 2, 7, 15, tzinfo=timezone.utc)
    checkpoint = datetime(2026, 9, 2, 7, 10, tzinfo=timezone.utc)

    window = calculate_window(
        alarm_end,
        lookback=timedelta(minutes=15),
        overlap=timedelta(minutes=2),
        checkpoint=checkpoint,
        maximum=timedelta(hours=1),
    )

    assert window.start == datetime(2026, 9, 2, 7, 8, tzinfo=timezone.utc)


def test_query_window_rejects_invalid_order_and_excessive_duration():
    alarm_end = datetime(2026, 9, 2, 7, 15, tzinfo=timezone.utc)

    with pytest.raises(ValueError, match="start cannot be after end"):
        calculate_window(
            alarm_end,
            lookback=timedelta(minutes=15),
            overlap=timedelta(minutes=2),
            checkpoint=datetime(2026, 9, 2, 7, 20, tzinfo=timezone.utc),
            maximum=timedelta(hours=1),
        )

    with pytest.raises(ValueError, match="exceeds configured maximum"):
        calculate_window(
            alarm_end,
            lookback=timedelta(minutes=15),
            overlap=timedelta(minutes=2),
            checkpoint=None,
            maximum=timedelta(minutes=16),
        )


def test_query_window_rejects_naive_datetimes():
    with pytest.raises(ValueError, match="timezone-aware"):
        calculate_window(
            datetime(2026, 9, 2, 7, 15),
            lookback=timedelta(minutes=15),
            overlap=timedelta(minutes=2),
            maximum=timedelta(hours=1),
        )


def test_event_key_is_stable_across_mapping_order():
    first = {
        "Time": datetime(2026, 9, 2, 7, 14, tzinfo=timezone.utc),
        "Entity": {"type": "host", "name": "demo-host"},
        "Status": "Failure",
    }
    reordered = {
        "Status": "Failure",
        "Entity": {"name": "demo-host", "type": "host"},
        "Time": datetime(2026, 9, 2, 10, 14, tzinfo=timezone(timedelta(hours=3))),
    }

    assert event_key("oci-audit-failures", first) == event_key(
        "oci-audit-failures", reordered
    )


def test_event_key_discriminates_rule_time_entity_and_row_changes():
    row = {
        "Time": "2026-09-02T07:14:00Z",
        "Entity": "demo-host",
        "Status": "Failure",
    }
    baseline = event_key("oci-audit-failures", row)

    variants = [
        ("another-rule", row),
        ("oci-audit-failures", {**row, "Time": "2026-09-02T07:14:01Z"}),
        ("oci-audit-failures", {**row, "Entity": "another-host"}),
        ("oci-audit-failures", {**row, "Status": "Success"}),
    ]

    assert all(event_key(rule_id, variant) != baseline for rule_id, variant in variants)


def registry_entry():
    return {
        "id": "oci-audit-failures",
        "title": "OCI Audit Failures",
        "oci_query_file": "queries/hunting/oci_audit_failures.json",
        "detection": {"severity": "medium", "mitre_techniques": ["T1078"]},
        "evidence": {"include_original_content": False, "redaction_profile": None},
    }


def test_evidence_event_is_schema_valid_excludes_original_and_redacts_secrets():
    row = {
        "Time": "2026-09-02T07:14:00Z",
        "Event Type": "com.oraclecloud.identitycontrolplane.updatepolicy",
        "Original Log Content": "must never escape by default",
        "api_token": "token-value",
        "Password Hash": "hash-value",
        "Authorization": "header-value",
        "clientSecret": "secret-value",
        "Resource OCID": "tenant-value",
        "Customer Field": "configured-value",
        "Details": {"authorization": "nested-header", "operation": "update"},
    }
    window = QueryWindow(
        start=datetime(2026, 9, 2, 6, 58, tzinfo=timezone.utc),
        end=datetime(2026, 9, 2, 7, 15, tzinfo=timezone.utc),
    )

    event = build_evidence_event(
        registry_entry(),
        row,
        window,
        batch_id="batch-20260902-0001",
        sensitive_fields={"Customer Field"},
    )
    payload = event.to_dict()
    fields = {field["name"]: field["value"] for field in payload["evidence"]["fields"]}

    assert not list(EVIDENCE_VALIDATOR.iter_errors(payload))
    assert "Original Log Content" not in fields
    assert fields["Event Type"] == row["Event Type"]
    for name in (
        "api_token",
        "Password Hash",
        "Authorization",
        "clientSecret",
        "Resource OCID",
        "Customer Field",
    ):
        assert fields[name] == "[REDACTED]"
    assert fields["Details"] == '{"authorization":"[REDACTED]","operation":"update"}'
    with pytest.raises(FrozenInstanceError):
        event.batch_id = "different"


def test_batch_events_builds_bounded_immutable_batches():
    window = QueryWindow(
        start=datetime(2026, 9, 2, 6, 58, tzinfo=timezone.utc),
        end=datetime(2026, 9, 2, 7, 15, tzinfo=timezone.utc),
    )
    events = [
        build_evidence_event(
            registry_entry(),
            {"Time": f"2026-09-02T07:14:0{second}Z", "Entity": f"host-{second}"},
            window,
            batch_id="batch-20260902-0001",
        )
        for second in range(3)
    ]

    batches = batch_events(events, max_batch_events=2)

    assert all(isinstance(batch, ExportBatch) for batch in batches)
    assert [len(batch.events) for batch in batches] == [2, 1]
    assert {batch.batch_id for batch in batches} == {"batch-20260902-0001"}
    assert isinstance(batches[0].events, tuple)
    with pytest.raises(FrozenInstanceError):
        batches[0].batch_id = "different"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("severity", "informational"),
        ("query_file", "../outside.json"),
    ],
)
def test_evidence_builder_rejects_values_that_cannot_satisfy_the_schema(field, value):
    entry = registry_entry()
    if field == "severity":
        entry["detection"]["severity"] = value
    else:
        entry["oci_query_file"] = value

    with pytest.raises(ValueError):
        build_evidence_event(
            entry,
            {"Event Type": "demo"},
            QueryWindow(
                start=datetime(2026, 9, 2, 6, 58, tzinfo=timezone.utc),
                end=datetime(2026, 9, 2, 7, 15, tzinfo=timezone.utc),
            ),
            batch_id="batch-20260902-0001",
        )


@pytest.mark.parametrize("status_code", [408, 429, 500, 503, 599])
def test_hec_timeout_rate_limit_and_server_failures_are_retryable(status_code):
    assert classify_hec_failure(status_code) == "retryable"


def test_hec_timeout_exception_is_retryable():
    assert classify_hec_failure(TimeoutError("sanitized timeout")) == "retryable"


@pytest.mark.parametrize("status_code", [400, 401, 403, 404, 413, 422])
def test_hec_client_contract_failures_are_quarantined(status_code):
    assert classify_hec_failure(status_code) == "quarantine"


def test_hec_success_requires_configured_acknowledgement_semantics():
    accepted = {"text": "Success", "code": 0}
    indexer_acceptance = {"text": "Success", "code": 0, "ackId": 42}

    assert classify_hec_failure(200) != "success"
    assert classify_hec_failure(200, response={"code": 4}) == "quarantine"
    assert classify_hec_failure(200, response=accepted) == "success"
    assert (
        classify_hec_failure(
            200,
            acknowledgement_mode="indexer_ack",
            response=indexer_acceptance,
            acknowledgement_confirmed=False,
        )
        == "retryable"
    )
    assert (
        classify_hec_failure(
            200,
            acknowledgement_mode="indexer_ack",
            response=indexer_acceptance,
            acknowledgement_confirmed=True,
        )
        == "success"
    )


def test_adapter_ports_are_runtime_checkable_structural_protocols():
    class QueryAdapter:
        def query_evidence(
            self, *, namespace, query_file, window, dimensions, max_rows
        ):
            return []

    class HecAdapter:
        def deliver(self, batch):
            return {"status": 200, "response": {"code": 0}}

    class Checkpoints:
        def load_checkpoint(self, detection_id, dimensions):
            return None

        def save_checkpoint(self, detection_id, dimensions, checkpoint):
            return None

    class Quarantine:
        def quarantine(self, batch, reason):
            return None

    assert isinstance(QueryAdapter(), EvidenceQueryPort)
    assert isinstance(HecAdapter(), HecDeliveryPort)
    assert isinstance(Checkpoints(), CheckpointPort)
    assert isinstance(Quarantine(), QuarantinePort)


def test_domain_modules_have_no_infrastructure_or_implicit_clock_dependencies():
    package = ROOT / "scripts/splunk_evidence_exporter"
    domain_files = [
        package / name
        for name in ("models.py", "window.py", "envelope.py", "retry.py", "ports.py")
    ]
    forbidden_import_roots = {
        "oci",
        "os",
        "requests",
        "socket",
        "subprocess",
        "urllib",
    }
    forbidden_calls = {
        "datetime.now",
        "datetime.utcnow",
        "open",
        "os.getenv",
        "os.environ",
        "Path.write_text",
        "Path.write_bytes",
    }

    for path in domain_files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        imports = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        calls = {
            ast.unparse(node.func)
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
        }
        assert imports.isdisjoint(forbidden_import_roots), path.name
        assert calls.isdisjoint(forbidden_calls), path.name
