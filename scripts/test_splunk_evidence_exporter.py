#!/usr/bin/env python3
"""Public-contract tests for the pure Splunk evidence exporter domain."""

import json
import ast
import io
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jsonschema
import pytest

from scripts.splunk_evidence_exporter.adapters import (
    OciLogAnalyticsQueryAdapter,
    OciVaultSecretAdapter,
    ObjectStorageDeadLetterAdapter,
    ObjectStorageStateAdapter,
    SplunkHecAdapter,
)

from scripts.splunk_evidence_exporter import (
    AlarmTrigger,
    EvidenceEvent,
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
from scripts.splunk_evidence_exporter.service import (
    EvidenceExportService,
    EvidenceReplayService,
)
from scripts.splunk_evidence_exporter import handler as handler_module


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


def test_alarm_trigger_decodes_oci_raw_monitoring_alarm_without_trusting_detection_id():
    """The provider payload identity is bound later to the governed registry."""
    payload = {
        "version": "1.0",
        "type": "com.oraclecloud.monitoring.alarm",
        "data": {
            "alarmMetaData": [{
                "id": "ocid1.alarm.oc1..fixture",
                "namespace": "oci_log_analytics_detections",
                "query": "AuditFailures[5m].sum() > 0",
                "dimensions": {"Status": "Failure"},
            }],
            "timestamp": "2026-09-02T07:15:00Z",
            "metricName": "AuditFailures",
            "detectionId": "attacker-controlled-id",
        },
    }

    trigger = AlarmTrigger.from_payload(payload)

    assert trigger.alarm_id == "ocid1.alarm.oc1..fixture"
    assert trigger.detection_id is None
    assert trigger.query == "AuditFailures[5m].sum() > 0"


def test_raw_alarm_contract_rejects_namespace_metric_dimension_and_query_mismatch():
    entry = registry_entry()
    entry["alarm_contract"] = {
        "binding_key": "oci-audit-failures",
        "metric_namespace": "oci_log_analytics_detections",
        "metric_name": "AuditFailures",
        "query": "AuditFailures[5m].sum() > 0",
        "allowed_dimensions": {"Status": "Failure"},
    }
    trigger = AlarmTrigger.from_payload({"data": {
        "alarmMetaData": [{"id": "ocid1.alarm.oc1..fixture", "namespace": "oci_log_analytics_detections", "query": "different", "dimensions": {"Status": "Failure"}}],
        "timestamp": "2026-09-02T07:15:00Z", "metricName": "AuditFailures",
    }})
    with pytest.raises(ValueError, match="alarm contract mismatch"):
        EvidenceExportService._validate_alarm_contract(entry, trigger)


def test_provider_raw_alarm_routes_by_bound_identity_but_queries_trusted_la_namespace_without_routing_dimensions():
    raw = json.loads((ROOT / "scripts/fixtures/splunk_evidence/oci_raw_alarm.json").read_text())
    entry = registry_entry()
    entry["alarm_contract"] = {
        "binding_key": "oci-audit-failures", "metric_namespace": "oci_log_analytics_detections",
        "metric_name": "DetectionSignal", "query": 'DetectionSignal[5m]{detectionId = "oci-audit-failures"}.sum() > 0',
        "allowed_dimensions": {"detectionId": "oci-audit-failures"}, "alarm_dimension_to_log_field": {},
    }
    seen = {}
    class Registry:
        def load(self): return {"detections": [entry]}
    class State:
        def load_checkpoint(self, *_): return None
        def save_checkpoint(self, *_): seen["checkpoint"] = True
    class Query:
        def query_evidence(self, **request):
            seen.update(request); assert request["namespace"] == "trusted-la-namespace"; assert request["dimensions"] == {}; return [{"Status": "Failure"}]
    class Hec:
        def deliver(self, _): return {"status": 200, "response": {"code": 0}}
    receipt = EvidenceExportService(registry=Registry(), query=Query(), checkpoint=State(), hec=Hec(), dead_letter=object(), clock=lambda: datetime(2026,9,2,7,16,tzinfo=timezone.utc), lookback=timedelta(minutes=15), overlap=timedelta(minutes=2), maximum_window=timedelta(hours=1), max_rows=100, max_batch_events=10, alarm_bindings={"redacted-alarm-id": "oci-audit-failures"}, log_analytics_namespace="trusted-la-namespace").export(AlarmTrigger.from_payload(raw))
    assert receipt.status == "delivered" and seen["checkpoint"] is True


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


def test_event_key_ignores_moving_query_window_but_keeps_source_occurrence_bounds():
    source = {
        "Time": "2026-09-02T07:14:00Z",
        "FirstSeen": "2026-09-02T07:14:00Z",
        "LastSeen": "2026-09-02T07:14:03Z",
        "Entity": "demo-host",
        "Status": "Failure",
        "Query Window Start": "2026-09-02T06:59:00Z",
        "Query Window End": "2026-09-02T07:15:00Z",
    }
    moved = {**source, "Query Window Start": "2026-09-02T07:00:00Z", "Query Window End": "2026-09-02T07:16:00Z"}
    distinct_occurrence = {**source, "FirstSeen": "2026-09-02T07:15:00Z", "LastSeen": "2026-09-02T07:15:03Z"}

    assert event_key("oci-audit-failures", source) == event_key("oci-audit-failures", moved)
    assert event_key("oci-audit-failures", source) != event_key("oci-audit-failures", distinct_occurrence)


def registry_entry():
    return {
        "id": "oci-audit-failures",
        "title": "OCI Audit Failures",
        "oci_query_file": "queries/hunting/oci_audit_failures.json",
        "required_fields": [
            "Event Type", "Status", "Evidence Version", "api_token", "Password Hash", "Authorization",
            "clientSecret", "Resource OCID", "Customer Field", "Details",
        ],
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


def test_evidence_export_is_allowlisted_and_ignores_unreviewed_query_columns():
    entry = registry_entry()
    entry["required_fields"] = ["Status"]
    window = QueryWindow(
        start=datetime(2026, 9, 2, 7, 8, tzinfo=timezone.utc),
        end=datetime(2026, 9, 2, 7, 15, tzinfo=timezone.utc),
    )
    event = build_evidence_event(entry, {"Status": "Failure", "new_column": "must-not-export"}, window, "batch")
    assert event.to_dict()["evidence"]["fields"] == [{"name": "Status", "value": "Failure"}]


def test_evidence_event_rejects_direct_construction_with_empty_schema_sections():
    with pytest.raises(TypeError, match="must be created by build_evidence_event"):
        EvidenceEvent("event-key", "batch-id", {}, {}, {})


def test_evidence_event_rejects_direct_construction_with_non_json_field_value():
    valid = build_evidence_event(
        registry_entry(),
        {"Event Type": "demo"},
        QueryWindow(
            start=datetime(2026, 9, 2, 6, 58, tzinfo=timezone.utc),
            end=datetime(2026, 9, 2, 7, 15, tzinfo=timezone.utc),
        ),
        batch_id="batch-20260902-0001",
    ).to_dict()
    valid["evidence"]["fields"][0]["value"] = object()

    with pytest.raises(TypeError, match="must be created by build_evidence_event"):
        EvidenceEvent(
            event_key=valid["event_key"],
            batch_id=valid["batch_id"],
            detection=valid["detection"],
            evidence=valid["evidence"],
            provenance=valid["provenance"],
        )


def test_batch_events_accepts_factory_events_and_builds_bounded_immutable_batches():
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


def test_export_service_delivers_all_batches_before_committing_checkpoint():
    operations = []

    class Registry:
        def load(self):
            operations.append("load_registry")
            return {"detections": [registry_entry()]}

    class State:
        def load_checkpoint(self, detection_id, dimensions):
            operations.append("read_checkpoint")
            return datetime(2026, 9, 2, 7, 10, tzinfo=timezone.utc)

        def save_checkpoint(self, detection_id, dimensions, checkpoint):
            operations.append("commit_checkpoint")
            assert checkpoint == datetime(2026, 9, 2, 7, 15, tzinfo=timezone.utc)

    class Query:
        def query_evidence(self, **request):
            operations.append("query")
            assert request["window"].start == datetime(
                2026, 9, 2, 7, 8, tzinfo=timezone.utc
            )
            return [
                {"Time": "2026-09-02T07:14:00Z", "Entity": "host-a"},
                {"Time": "2026-09-02T07:14:01Z", "Entity": "host-b"},
                {"Time": "2026-09-02T07:14:01Z", "Entity": "host-b"},
            ]

    class Hec:
        def deliver(self, batch):
            operations.append(f"deliver:{len(batch.events)}")
            return {"status": 200, "response": {"code": 0}}

    class Dlq:
        def quarantine(self, batch, reason, **metadata):
            raise AssertionError("successful export must not write a DLQ record")

    service = EvidenceExportService(
        registry=Registry(),
        query=Query(),
        checkpoint=State(),
        hec=Hec(),
        dead_letter=Dlq(),
        clock=lambda: datetime(2026, 9, 2, 7, 16, tzinfo=timezone.utc),
        lookback=timedelta(minutes=15),
        overlap=timedelta(minutes=2),
        maximum_window=timedelta(hours=1),
        max_rows=1000,
        max_batch_events=1,
    )

    receipt = service.export(AlarmTrigger.from_payload(alarm_payload()))

    assert operations == [
        "load_registry",
        "read_checkpoint",
        "query",
        "deliver:1",
        "deliver:1",
        "commit_checkpoint",
    ]
    assert receipt.to_dict() == {
        "status": "delivered",
        "detection_id": "oci-audit-failures",
        "window_start": "2026-09-02T07:08:00Z",
        "window_end": "2026-09-02T07:15:00Z",
        "row_count": 3,
        "event_count": 2,
        "batch_count": 2,
        "delivered_count": 2,
        "checkpoint_committed": True,
        "completed_at": "2026-09-02T07:16:00Z",
    }


def test_export_service_returns_no_evidence_without_hec_or_checkpoint_commit():
    class Registry:
        def load(self):
            return {"detections": [registry_entry()]}

    class State:
        def load_checkpoint(self, detection_id, dimensions):
            return None

        def save_checkpoint(self, detection_id, dimensions, checkpoint):
            raise AssertionError("no-evidence result must not advance checkpoint")

    class Query:
        def query_evidence(self, **request):
            return []

    class Hec:
        def deliver(self, batch):
            raise AssertionError("zero rows must not call HEC")

    service = EvidenceExportService(
        registry=Registry(),
        query=Query(),
        checkpoint=State(),
        hec=Hec(),
        dead_letter=object(),
        clock=lambda: datetime(2026, 9, 2, 7, 16, tzinfo=timezone.utc),
        lookback=timedelta(minutes=15),
        overlap=timedelta(minutes=2),
        maximum_window=timedelta(hours=1),
        max_rows=1000,
        max_batch_events=100,
    )

    receipt = service.export(AlarmTrigger.from_payload(alarm_payload()))

    assert receipt.status == "no_evidence"
    assert receipt.event_count == 0
    assert receipt.delivered_count == 0
    assert receipt.checkpoint_committed is False


def test_export_service_honors_registry_delivery_bounds():
    entry = registry_entry()
    entry["delivery"] = {
        "lookback": "5m",
        "overlap": "1m",
        "max_rows": 7,
        "max_batch_events": 2,
    }
    observed = {}

    class Registry:
        def load(self):
            return {"detections": [entry]}

    class State:
        def load_checkpoint(self, detection_id, dimensions):
            return None

        def save_checkpoint(self, detection_id, dimensions, checkpoint):
            pass

    class Query:
        def query_evidence(self, **request):
            observed.update(request)
            return [{"Status": "Failure", "row": number} for number in range(3)]

    class Hec:
        def deliver(self, batch):
            observed.setdefault("batch_sizes", []).append(len(batch.events))
            return {"status": 200, "response": {"code": 0}}

    service = EvidenceExportService(
        registry=Registry(),
        query=Query(),
        checkpoint=State(),
        hec=Hec(),
        dead_letter=object(),
        clock=lambda: datetime(2026, 9, 2, 7, 16, tzinfo=timezone.utc),
        lookback=timedelta(minutes=15),
        overlap=timedelta(minutes=2),
        maximum_window=timedelta(hours=1),
        max_rows=1000,
        max_batch_events=100,
    )

    service.export(AlarmTrigger.from_payload(alarm_payload()))

    assert observed["window"].start == datetime(2026, 9, 2, 7, 9, tzinfo=timezone.utc)
    assert observed["max_rows"] == 7
    assert observed["batch_sizes"] == [1]


@pytest.mark.parametrize(
    "delivery",
    [
        {"max_rows": 1001},
        {"max_batch_events": 101},
    ],
)
def test_export_service_rejects_registry_volume_above_runtime_ceiling(delivery):
    entry = registry_entry()
    entry["delivery"] = delivery

    class Registry:
        def load(self):
            return {"detections": [entry]}

    class NeverCalled:
        def __getattr__(self, name):
            raise AssertionError(f"{name} must not run after unsafe registry bounds")

    service = EvidenceExportService(
        registry=Registry(),
        query=NeverCalled(),
        checkpoint=NeverCalled(),
        hec=NeverCalled(),
        dead_letter=NeverCalled(),
        clock=lambda: datetime(2026, 9, 2, 7, 16, tzinfo=timezone.utc),
        lookback=timedelta(minutes=15),
        overlap=timedelta(minutes=2),
        maximum_window=timedelta(hours=1),
        max_rows=1000,
        max_batch_events=100,
    )

    with pytest.raises(ValueError, match="runtime maximum"):
        service.export(AlarmTrigger.from_payload(alarm_payload()))


def test_partial_hec_failure_writes_one_replay_safe_dlq_and_never_commits():
    quarantines = []

    class Registry:
        def load(self):
            return {"detections": [registry_entry()]}

    class State:
        def load_checkpoint(self, detection_id, dimensions):
            return None

        def save_checkpoint(self, detection_id, dimensions, checkpoint):
            raise AssertionError("HEC failure must not advance checkpoint")

    class Query:
        def query_evidence(self, **request):
            return [
                {"Time": f"2026-09-02T07:14:0{second}Z", "Entity": f"host-{second}"}
                for second in range(3)
            ]

    class Hec:
        attempts = 0

        def deliver(self, batch):
            self.attempts += 1
            if self.attempts >= 2:
                raise TimeoutError("sanitized timeout")
            return {"status": 200, "response": {"code": 0}}

    class Dlq:
        def quarantine(self, batch, reason, *, delivered_event_keys=(), **metadata):
            quarantines.append(
                {
                    "reason": reason,
                    "delivered_event_keys": tuple(delivered_event_keys),
                    "remaining_events": tuple(batch.events),
                    "metadata": metadata,
                }
            )

    service = EvidenceExportService(
        registry=Registry(),
        query=Query(),
        checkpoint=State(),
        hec=Hec(),
        dead_letter=Dlq(),
        clock=lambda: datetime(2026, 9, 2, 7, 16, tzinfo=timezone.utc),
        lookback=timedelta(minutes=15),
        overlap=timedelta(minutes=2),
        maximum_window=timedelta(hours=1),
        max_rows=1000,
        max_batch_events=1,
    )

    receipt = service.export(AlarmTrigger.from_payload(alarm_payload()))

    assert receipt.status == "delivery_failed"
    assert receipt.delivered_count == 1
    assert receipt.checkpoint_committed is False
    assert len(quarantines) == 1
    assert len(quarantines[0]["delivered_event_keys"]) == 1
    assert len(quarantines[0]["remaining_events"]) == 2
    assert quarantines[0]["reason"] == "retryable"
    assert quarantines[0]["metadata"]["checkpoint"] == datetime(
        2026, 9, 2, 7, 15, tzinfo=timezone.utc
    )


def test_log_analytics_adapter_binds_scope_window_dimensions_and_row_limit():
    calls = []

    class Response:
        data = type("Data", (), {"items": [{"Status": "Failure"}]})()

    class Client:
        def query(self, namespace_name, query_details, **kwargs):
            calls.append((namespace_name, query_details, kwargs))
            return Response()

    adapter = OciLogAnalyticsQueryAdapter(
        client=Client(),
        compartment_id="compartment-under-test",
        compartment_id_in_subtree=True,
        max_rows_ceiling=500,
        query_loader=lambda path: {
            "query": "'Log Source' = 'OCI Audit Logs' | stats count by Status"
        },
        query_details_factory=lambda **values: values,
        time_range_factory=lambda **values: values,
    )
    window = QueryWindow(
        start=datetime(2026, 9, 2, 7, 8, tzinfo=timezone.utc),
        end=datetime(2026, 9, 2, 7, 15, tzinfo=timezone.utc),
    )

    rows = adapter.query_evidence(
        namespace="logan-namespace",
        query_file="queries/hunting/oci_audit_failures.json",
        window=window,
        dimensions={"Status": "Failure"},
        max_rows=321,
    )

    assert rows == ({"Status": "Failure"},)
    namespace, details, kwargs = calls[0]
    assert namespace == "logan-namespace"
    assert details["compartment_id"] == "compartment-under-test"
    assert details["compartment_id_in_subtree"] is True
    assert details["max_total_count"] == 321
    assert details["sub_system"] == "LOG"
    assert details["time_filter"] == {
        "time_start": window.start,
        "time_end": window.end,
        "time_zone": "UTC",
    }
    assert "and 'Status' = 'Failure'" in details["query_string"]
    assert kwargs == {"limit": 321}


def test_log_analytics_adapter_rejects_rows_above_runtime_ceiling():
    class Client:
        def query(self, *args, **kwargs):
            raise AssertionError("unsafe query must not reach OCI client")

    adapter = OciLogAnalyticsQueryAdapter(
        client=Client(),
        compartment_id="compartment-under-test",
        compartment_id_in_subtree=True,
        max_rows_ceiling=100,
        query_loader=lambda path: {"query": "*"},
        query_details_factory=lambda **values: values,
        time_range_factory=lambda **values: values,
    )

    with pytest.raises(ValueError, match="runtime maximum"):
        adapter.query_evidence(
            namespace="logan-namespace",
            query_file="queries/hunting/oci_audit_failures.json",
            window=QueryWindow(
                start=datetime(2026, 9, 2, 7, 8, tzinfo=timezone.utc),
                end=datetime(2026, 9, 2, 7, 15, tzinfo=timezone.utc),
            ),
            dimensions={},
            max_rows=101,
        )


def test_vault_adapter_never_represents_or_logs_the_decoded_token(caplog):
    import base64

    token = "placeholder-hec-token"
    content = base64.b64encode(token.encode("utf-8")).decode("ascii")
    bundle_content = type("BundleContent", (), {"content": content})()
    bundle = type("Bundle", (), {"secret_bundle_content": bundle_content})()
    response = type("Response", (), {"data": bundle})()

    class Client:
        def get_secret_bundle(self, secret_id):
            return response

    adapter = OciVaultSecretAdapter(
        client=Client(), secret_id="placeholder-vault-secret-reference"
    )

    assert adapter.get_token() == token
    assert token not in repr(adapter)
    assert token not in caplog.text

    class FailingClient:
        def get_secret_bundle(self, secret_id):
            raise RuntimeError(token)

    failing = OciVaultSecretAdapter(
        client=FailingClient(), secret_id="placeholder-vault-secret-reference"
    )
    with pytest.raises(RuntimeError) as error:
        failing.get_token()
    assert token not in str(error.value)


def test_object_storage_state_and_dlq_names_expose_no_dimensions_or_event_content():
    writes = []

    class Client:
        def put_object(self, **request):
            writes.append(request)

    client = Client()
    state = ObjectStorageStateAdapter(
        client=client, namespace="namespace-under-test", bucket="bucket-under-test"
    )
    dimensions = {"User Name": "private-user@example.invalid"}
    state.save_checkpoint(
        "OCI Audit/Failures",
        dimensions,
        datetime(2026, 9, 2, 7, 15, tzinfo=timezone.utc),
    )

    window = QueryWindow(
        start=datetime(2026, 9, 2, 7, 8, tzinfo=timezone.utc),
        end=datetime(2026, 9, 2, 7, 15, tzinfo=timezone.utc),
    )
    event = build_evidence_event(
        registry_entry(),
        {"Time": "2026-09-02T07:14:00Z", "Entity": "private-hostname"},
        window,
        batch_id="oci-audit-failures-20260902t071500z-0123456789ab",
    )
    batch = ExportBatch(batch_id=event.batch_id, events=(event,))
    dlq = ObjectStorageDeadLetterAdapter(
        client=client,
        namespace="namespace-under-test",
        bucket="bucket-under-test",
        clock=lambda: datetime(2026, 9, 2, 7, 16, tzinfo=timezone.utc),
    )
    dlq.quarantine(
        batch,
        "retryable",
        delivered_event_keys=("confirmed-key",),
        detection_id="oci-audit-failures",
        dimensions=dimensions,
        checkpoint=datetime(2026, 9, 2, 7, 15, tzinfo=timezone.utc),
    )

    object_names = [write["object_name"] for write in writes]
    assert len(object_names) == 2
    assert all(
        __import__("re").fullmatch(r"[a-z0-9-]+\.json", name) for name in object_names
    )
    assert all("private-user" not in name for name in object_names)
    assert all("private-hostname" not in name for name in object_names)
    dlq_record = json.loads(writes[1]["put_object_body"])
    assert dlq_record["delivered_event_keys"] == ["confirmed-key"]
    assert dlq_record["detection_id"] == "oci-audit-failures"
    assert dlq_record["dimensions"] == dimensions
    assert dlq_record["checkpoint"] == "2026-09-02T07:15:00Z"
    assert [item["event_key"] for item in dlq_record["remaining_events"]] == [
        event.event_key
    ]


def test_checkpoint_names_do_not_collide_after_rule_sanitization_or_truncation():
    names = []

    class Client:
        def put_object(self, **request):
            names.append(request["object_name"])

    adapter = ObjectStorageStateAdapter(
        client=Client(), namespace="namespace-under-test", bucket="bucket-under-test"
    )
    for detection_id in (
        "rule/a",
        "rule-a",
        f"{'x' * 80}a",
        f"{'x' * 80}b",
    ):
        adapter.save_checkpoint(
            detection_id,
            {"Status": "Failure"},
            datetime(2026, 9, 2, 7, 15, tzinfo=timezone.utc),
        )

    assert len(set(names)) == 4
    assert all(__import__("re").fullmatch(r"[a-z0-9-]+\.json", name) for name in names)


def test_hec_adapter_posts_json_events_to_https_endpoint_with_bounded_timeout():
    calls = []

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b'{"text":"Success","code":0}'

    def opener(request, timeout):
        calls.append((request, timeout))
        return Response()

    window = QueryWindow(
        start=datetime(2026, 9, 2, 7, 8, tzinfo=timezone.utc),
        end=datetime(2026, 9, 2, 7, 15, tzinfo=timezone.utc),
    )
    event = build_evidence_event(
        registry_entry(),
        {"Status": "Failure"},
        window,
        batch_id="oci-audit-failures-20260902t071500z-0123456789ab",
    )
    adapter = SplunkHecAdapter(
        hec_url="https://splunk.example.invalid:8088",
        token_provider=lambda: "token-under-test",
        index="oci_detection_evidence",
        sourcetype="oci:logan:detection",
        timeout_seconds=5,
        acknowledgement_mode="response",
        opener=opener,
    )

    result = adapter.deliver(ExportBatch(batch_id=event.batch_id, events=(event,)))

    request, timeout = calls[0]
    assert (
        request.full_url
        == "https://splunk.example.invalid:8088/services/collector/event"
    )
    assert request.method == "POST"
    assert timeout == 5
    assert request.get_header("Content-type") == "application/json"
    assert request.get_header("Authorization") == "Splunk token-under-test"
    hec_event = json.loads(request.data)
    assert hec_event["index"] == "oci_detection_evidence"
    assert hec_event["sourcetype"] == "oci:logan:detection"
    assert hec_event["event"]["event_key"] == event.event_key
    assert result == {
        "status": 200,
        "response": {"text": "Success", "code": 0},
        "acknowledgement_mode": "response",
        "acknowledgement_confirmed": True,
    }


def test_hec_adapter_rejects_insecure_or_unbounded_configuration():
    with pytest.raises(ValueError, match="HTTPS"):
        SplunkHecAdapter(
            hec_url="http://splunk.example.invalid:8088",
            token_provider=lambda: "token",
            index="index",
            sourcetype="sourcetype",
            timeout_seconds=5,
        )
    with pytest.raises(ValueError, match="timeout"):
        SplunkHecAdapter(
            hec_url="https://splunk.example.invalid:8088",
            token_provider=lambda: "token",
            index="index",
            sourcetype="sourcetype",
            timeout_seconds=61,
        )


def test_hec_indexer_ack_mode_confirms_the_returned_ack_id():
    calls = []
    responses = [
        (200, b'{"text":"Success","code":0,"ackId":42}'),
        (200, b'{"acks":{"42":true}}'),
    ]

    class Response:
        def __init__(self, status, body):
            self.status = status
            self._body = body

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return self._body

    def opener(request, timeout):
        calls.append(request)
        return Response(*responses.pop(0))

    window = QueryWindow(
        start=datetime(2026, 9, 2, 7, 8, tzinfo=timezone.utc),
        end=datetime(2026, 9, 2, 7, 15, tzinfo=timezone.utc),
    )
    event = build_evidence_event(
        registry_entry(),
        {"Status": "Failure"},
        window,
        batch_id="oci-audit-failures-20260902t071500z-0123456789ab",
    )
    adapter = SplunkHecAdapter(
        hec_url="https://splunk.example.invalid:8088/services/collector/event",
        token_provider=lambda: "token-under-test",
        index="oci_detection_evidence",
        sourcetype="oci:logan:detection",
        timeout_seconds=5,
        acknowledgement_mode="indexer_ack",
        opener=opener,
    )

    result = adapter.deliver(ExportBatch(batch_id=event.batch_id, events=(event,)))

    assert [request.full_url for request in calls] == [
        "https://splunk.example.invalid:8088/services/collector/event",
        "https://splunk.example.invalid:8088/services/collector/ack",
    ]
    assert result["acknowledgement_mode"] == "indexer_ack"
    assert result["acknowledgement_confirmed"] is True


def test_hec_indexer_ack_polls_pending_status_with_bounded_backoff():
    calls = []
    sleeps = []
    monotonic = [100.0]
    responses = [
        (200, b'{"text":"Success","code":0,"ackId":42}'),
        (200, b'{"acks":{"42":false}}'),
        (200, b'{"acks":{"42":false}}'),
        (200, b'{"acks":{"42":true}}'),
    ]

    class Response:
        def __init__(self, status, body):
            self.status = status
            self._body = body

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return self._body

    def opener(request, timeout):
        calls.append((request.full_url, timeout))
        return Response(*responses.pop(0))

    def sleep(seconds):
        sleeps.append(seconds)
        monotonic[0] += seconds

    window = QueryWindow(
        start=datetime(2026, 9, 2, 7, 8, tzinfo=timezone.utc),
        end=datetime(2026, 9, 2, 7, 15, tzinfo=timezone.utc),
    )
    event = build_evidence_event(
        registry_entry(),
        {"Status": "Failure"},
        window,
        batch_id="oci-audit-failures-20260902t071500z-0123456789ab",
    )
    adapter = SplunkHecAdapter(
        hec_url="https://splunk.example.invalid:8088",
        token_provider=lambda: "placeholder-token",
        index="oci_detection_evidence",
        sourcetype="oci:logan:detection",
        timeout_seconds=5,
        acknowledgement_mode="indexer_ack",
        opener=opener,
        clock=lambda: monotonic[0],
        sleep=sleep,
        ack_poll_initial_seconds=0.25,
    )

    result = adapter.deliver(ExportBatch(batch_id=event.batch_id, events=(event,)))

    assert result["acknowledgement_confirmed"] is True
    assert sleeps == [0.25, 0.5]
    assert len(calls) == 4
    assert all(0 < timeout <= 5 for _, timeout in calls)


def test_hec_indexer_ack_pending_status_fails_closed_at_timeout():
    monotonic = [0.0]
    calls = []

    class Response:
        status = 200

        def __init__(self, body):
            self._body = body

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return self._body

    def opener(request, timeout):
        calls.append((request.full_url, timeout))
        if request.full_url.endswith("/event"):
            return Response(b'{"text":"Success","code":0,"ackId":42}')
        return Response(b'{"acks":{"42":false}}')

    window = QueryWindow(
        start=datetime(2026, 9, 2, 7, 8, tzinfo=timezone.utc),
        end=datetime(2026, 9, 2, 7, 15, tzinfo=timezone.utc),
    )
    event = build_evidence_event(
        registry_entry(),
        {"Status": "Failure"},
        window,
        batch_id="oci-audit-failures-20260902t071500z-0123456789ab",
    )
    adapter = SplunkHecAdapter(
        hec_url="https://splunk.example.invalid:8088",
        token_provider=lambda: "placeholder-token",
        index="oci_detection_evidence",
        sourcetype="oci:logan:detection",
        timeout_seconds=1,
        acknowledgement_mode="indexer_ack",
        opener=opener,
        clock=lambda: monotonic[0],
        sleep=lambda seconds: monotonic.__setitem__(0, monotonic[0] + seconds),
        ack_poll_initial_seconds=0.25,
    )

    result = adapter.deliver(ExportBatch(batch_id=event.batch_id, events=(event,)))

    assert result["acknowledgement_confirmed"] is False
    assert monotonic[0] == 1.0
    assert len(calls) == 4


def test_service_requires_selected_indexer_ack_before_checkpoint_commit():
    class Registry:
        def load(self):
            return {"detections": [registry_entry()]}

    class State:
        def load_checkpoint(self, detection_id, dimensions):
            return None

        def save_checkpoint(self, detection_id, dimensions, checkpoint):
            raise AssertionError("unconfirmed indexer acknowledgement must not commit")

    class Query:
        def query_evidence(self, **request):
            return [{"Status": "Failure"}]

    class Hec:
        def deliver(self, batch):
            return {
                "status": 200,
                "response": {"code": 0, "ackId": 42},
                "acknowledgement_mode": "indexer_ack",
                "acknowledgement_confirmed": False,
            }

    class Dlq:
        calls = 0

        def quarantine(self, batch, reason, **metadata):
            self.calls += 1

    dlq = Dlq()
    service = EvidenceExportService(
        registry=Registry(),
        query=Query(),
        checkpoint=State(),
        hec=Hec(),
        dead_letter=dlq,
        clock=lambda: datetime(2026, 9, 2, 7, 16, tzinfo=timezone.utc),
        lookback=timedelta(minutes=15),
        overlap=timedelta(minutes=2),
        maximum_window=timedelta(hours=1),
        max_rows=1000,
        max_batch_events=100,
    )

    receipt = service.export(AlarmTrigger.from_payload(alarm_payload()))

    assert receipt.status == "delivery_failed"
    assert receipt.checkpoint_committed is False
    assert dlq.calls == 1


def test_export_service_retries_each_batch_and_commits_after_later_success():
    entry = registry_entry()
    entry["delivery"] = {"max_attempts": 3}
    operations = []

    class Registry:
        def load(self):
            return {"detections": [entry]}

    class State:
        def load_checkpoint(self, detection_id, dimensions):
            return None

        def save_checkpoint(self, detection_id, dimensions, checkpoint):
            operations.append("checkpoint")

    class Query:
        def query_evidence(self, **request):
            return [{"Status": "Failure"}]

    class Hec:
        attempts = 0

        def deliver(self, batch):
            self.attempts += 1
            operations.append(f"hec:{self.attempts}")
            if self.attempts == 1:
                return {"status": 500, "response": {"code": 8}}
            if self.attempts == 2:
                raise TimeoutError("sanitized timeout")
            return {"status": 200, "response": {"code": 0}}

    class Dlq:
        def quarantine(self, *args, **kwargs):
            raise AssertionError("eventually successful delivery must not quarantine")

    hec = Hec()
    service = EvidenceExportService(
        registry=Registry(),
        query=Query(),
        checkpoint=State(),
        hec=hec,
        dead_letter=Dlq(),
        clock=lambda: datetime(2026, 9, 2, 7, 16, tzinfo=timezone.utc),
        lookback=timedelta(minutes=15),
        overlap=timedelta(minutes=2),
        maximum_window=timedelta(hours=1),
        max_rows=1000,
        max_batch_events=100,
        max_attempts=4,
    )

    receipt = service.export(AlarmTrigger.from_payload(alarm_payload()))

    assert receipt.status == "delivered"
    assert receipt.checkpoint_committed is True
    assert hec.attempts == 3
    assert operations == ["hec:1", "hec:2", "hec:3", "checkpoint"]


def test_export_service_rejects_registry_attempts_above_runtime_ceiling():
    entry = registry_entry()
    entry["delivery"] = {"max_attempts": 5}

    class Registry:
        def load(self):
            return {"detections": [entry]}

    class NeverCalled:
        def __getattr__(self, name):
            raise AssertionError(f"{name} must not run after unsafe retry bounds")

    service = EvidenceExportService(
        registry=Registry(),
        query=NeverCalled(),
        checkpoint=NeverCalled(),
        hec=NeverCalled(),
        dead_letter=NeverCalled(),
        clock=lambda: datetime(2026, 9, 2, 7, 16, tzinfo=timezone.utc),
        lookback=timedelta(minutes=15),
        overlap=timedelta(minutes=2),
        maximum_window=timedelta(hours=1),
        max_rows=1000,
        max_batch_events=100,
        max_attempts=4,
    )

    with pytest.raises(ValueError, match="max_attempts exceeds the runtime maximum"):
        service.export(AlarmTrigger.from_payload(alarm_payload()))


def test_replay_delivers_stored_remaining_evidence_and_excludes_confirmed_keys():
    window = QueryWindow(
        start=datetime(2026, 9, 2, 7, 8, tzinfo=timezone.utc),
        end=datetime(2026, 9, 2, 7, 15, tzinfo=timezone.utc),
    )
    stored_events = [
        build_evidence_event(
            registry_entry(),
            {"Status": status, "Evidence Version": "stored"},
            window,
            batch_id="replay-batch",
        )
        for status in ("Already delivered", "Still pending")
    ]
    record = {
        "schema_version": "oci.logan.splunk.dead-letter.v1",
        "reason": "retryable",
        "batch_id": "replay-batch",
        "detection_id": "oci-audit-failures",
        "dimensions": {"Status": "Failure"},
        "checkpoint": "2026-09-02T07:15:00Z",
        "delivered_event_keys": [stored_events[0].event_key],
        "remaining_events": [event.to_dict() for event in stored_events],
    }
    delivered = []
    commits = []

    class Hec:
        def deliver(self, batch):
            delivered.extend(event.to_dict() for event in batch.events)
            return {"status": 200, "response": {"code": 0}}

    class State:
        def load_checkpoint(self, detection_id, dimensions):
            return None

        def save_checkpoint(self, detection_id, dimensions, checkpoint):
            commits.append((detection_id, dict(dimensions), checkpoint))

    class Dlq:
        def quarantine(self, *args, **kwargs):
            raise AssertionError("successful replay must not quarantine")

    receipt = EvidenceReplayService(
        checkpoint=State(),
        hec=Hec(),
        dead_letter=Dlq(),
        clock=lambda: datetime(2026, 9, 2, 7, 16, tzinfo=timezone.utc),
        max_batch_events=100,
        max_attempts=4,
    ).replay(record)

    assert receipt.status == "delivered"
    assert receipt.excluded_confirmed_count == 1
    assert receipt.delivered_count == 1
    assert delivered[0]["event_key"] == stored_events[1].event_key
    assert {field["value"] for field in delivered[0]["evidence"]["fields"]} >= {
        "stored",
        "Still pending",
    }
    assert commits == [
        (
            "oci-audit-failures",
            {"Status": "Failure"},
            datetime(2026, 9, 2, 7, 15, tzinfo=timezone.utc),
        )
    ]


@pytest.mark.parametrize(
    ("current_checkpoint", "checkpoint_status", "expected_saves"),
    [
        (
            datetime(2026, 9, 2, 7, 20, tzinfo=timezone.utc),
            "preserved_newer",
            [],
        ),
        (
            datetime(2026, 9, 2, 7, 15, tzinfo=timezone.utc),
            "already_current",
            [],
        ),
        (
            datetime(2026, 9, 2, 7, 10, tzinfo=timezone.utc),
            "advanced",
            [datetime(2026, 9, 2, 7, 15, tzinfo=timezone.utc)],
        ),
    ],
)
def test_confirmed_replay_advances_checkpoint_monotonically(
    current_checkpoint, checkpoint_status, expected_saves
):
    operations = []
    window = QueryWindow(
        start=datetime(2026, 9, 2, 7, 8, tzinfo=timezone.utc),
        end=datetime(2026, 9, 2, 7, 15, tzinfo=timezone.utc),
    )
    event = build_evidence_event(
        registry_entry(),
        {"Status": "stored"},
        window,
        batch_id="monotonic-replay-batch",
    )
    record = {
        "schema_version": "oci.logan.splunk.dead-letter.v1",
        "reason": "retryable",
        "batch_id": "monotonic-replay-batch",
        "detection_id": "oci-audit-failures",
        "dimensions": {"Status": "Failure"},
        "checkpoint": "2026-09-02T07:15:00Z",
        "delivered_event_keys": [],
        "remaining_events": [event.to_dict()],
    }
    saves = []

    class Hec:
        def deliver(self, batch):
            operations.append("hec_confirmed")
            return {"status": 200, "response": {"code": 0}}

    class State:
        def load_checkpoint(self, detection_id, dimensions):
            operations.append("checkpoint_loaded")
            return current_checkpoint

        def save_checkpoint(self, detection_id, dimensions, checkpoint):
            operations.append("checkpoint_saved")
            saves.append(checkpoint)

    class Dlq:
        def quarantine(self, *args, **kwargs):
            raise AssertionError("confirmed replay must not quarantine")

    receipt = EvidenceReplayService(
        checkpoint=State(),
        hec=Hec(),
        dead_letter=Dlq(),
        clock=lambda: datetime(2026, 9, 2, 7, 21, tzinfo=timezone.utc),
        max_batch_events=100,
        max_attempts=4,
    ).replay(record)

    assert receipt.status == "delivered"
    assert receipt.checkpoint_status == checkpoint_status
    assert receipt.checkpoint_committed is (checkpoint_status == "advanced")
    assert saves == expected_saves
    assert operations[:2] == ["hec_confirmed", "checkpoint_loaded"]


def test_partial_replay_failure_updates_dlq_and_never_commits_checkpoint():
    window = QueryWindow(
        start=datetime(2026, 9, 2, 7, 8, tzinfo=timezone.utc),
        end=datetime(2026, 9, 2, 7, 15, tzinfo=timezone.utc),
    )
    events = [
        build_evidence_event(
            registry_entry(),
            {"Status": f"pending-{number}"},
            window,
            batch_id="partial-replay-batch",
        )
        for number in range(3)
    ]
    record = {
        "schema_version": "oci.logan.splunk.dead-letter.v1",
        "reason": "retryable",
        "batch_id": "partial-replay-batch",
        "detection_id": "oci-audit-failures",
        "dimensions": {},
        "checkpoint": "2026-09-02T07:15:00Z",
        "delivered_event_keys": ["previously-confirmed"],
        "remaining_events": [event.to_dict() for event in events],
    }
    attempts = []
    quarantines = []
    state_accesses = []

    class Hec:
        def deliver(self, batch):
            attempts.append(batch.events[0].event_key)
            if len(attempts) == 1:
                return {"status": 200, "response": {"code": 0}}
            return {"status": 500, "response": {"code": 8}}

    class State:
        def load_checkpoint(self, *args, **kwargs):
            state_accesses.append("load")
            return None

        def save_checkpoint(self, *args, **kwargs):
            state_accesses.append("save")

    class Dlq:
        def quarantine(self, batch, reason, **metadata):
            quarantines.append((batch, reason, metadata))

    receipt = EvidenceReplayService(
        checkpoint=State(),
        hec=Hec(),
        dead_letter=Dlq(),
        clock=lambda: datetime(2026, 9, 2, 7, 16, tzinfo=timezone.utc),
        max_batch_events=1,
        max_attempts=2,
    ).replay(record)

    assert receipt.status == "delivery_failed"
    assert receipt.delivered_count == 1
    assert receipt.checkpoint_committed is False
    assert receipt.checkpoint_status == "not_evaluated"
    assert state_accesses == []
    assert len(attempts) == 3
    batch, reason, metadata = quarantines[0]
    assert reason == "retryable"
    assert [event.event_key for event in batch.events] == [
        events[1].event_key,
        events[2].event_key,
    ]
    assert metadata["delivered_event_keys"] == (
        "previously-confirmed",
        events[0].event_key,
    )


def test_handler_decodes_one_notification_and_returns_only_sanitized_receipt(
    monkeypatch, caplog
):
    captured = []

    class Service:
        def export(self, trigger):
            captured.append(trigger)
            return handler_module.ExportReceipt(
                status="delivered",
                detection_id=trigger.detection_id,
                window_start=datetime(2026, 9, 2, 7, 8, tzinfo=timezone.utc),
                window_end=trigger.alarm_end,
                row_count=1,
                event_count=1,
                batch_count=1,
                delivered_count=1,
                checkpoint_committed=True,
                completed_at=datetime(2026, 9, 2, 7, 16, tzinfo=timezone.utc),
            )

    monkeypatch.setattr(handler_module, "build_service", lambda: Service())
    provider_raw = json.loads((ROOT / "scripts/fixtures/splunk_evidence/oci_raw_alarm.json").read_text())
    notification = {
        "type": "com.oraclecloud.notificationservice.publishmessage",
        "data": {
            "messageDetails": {
                "type": "RAW",
                "body": json.dumps(provider_raw),
            },
            "topicId": "provider-identifier-must-not-escape",
        },
    }

    result = handler_module.handler(
        object(), io.BytesIO(json.dumps(notification).encode("utf-8"))
    )

    assert len(captured) == 1
    assert result == {
        "status": "delivered",
        "detection_id": None,
        "window_start": "2026-09-02T07:08:00Z",
        "window_end": "2026-09-02T07:15:00Z",
        "row_count": 1,
        "event_count": 1,
        "batch_count": 1,
        "delivered_count": 1,
        "checkpoint_committed": True,
        "completed_at": "2026-09-02T07:16:00Z",
    }
    serialized_output = json.dumps(result) + caplog.text
    assert "provider-identifier-must-not-escape" not in serialized_output
    assert "operator@example.invalid" not in serialized_output
    assert "identitycontrolplane" not in serialized_output


def test_production_handler_rejects_legacy_synthetic_identity(monkeypatch):
    monkeypatch.setattr(handler_module, "build_service", lambda: object())
    with pytest.raises(RuntimeError, match="evidence export failed"):
        handler_module.handler(object(), io.BytesIO(json.dumps(alarm_payload()).encode()))
    # Offline/test adapters may still decode fixture payloads explicitly.
    assert handler_module._decode_notification(json.dumps(alarm_payload()).encode()).detection_id == "oci-audit-failures"


def test_function_service_uses_one_resource_principal_for_all_oci_clients(
    monkeypatch,
):
    import oci

    signer = object()
    clients = []

    def client_factory(*args, **kwargs):
        clients.append(kwargs)
        return object()

    monkeypatch.setattr(
        oci.auth.signers, "get_resource_principals_signer", lambda: signer
    )
    monkeypatch.setattr(oci.log_analytics, "LogAnalyticsClient", client_factory)
    monkeypatch.setattr(oci.secrets, "SecretsClient", client_factory)
    monkeypatch.setattr(oci.object_storage, "ObjectStorageClient", client_factory)
    monkeypatch.setattr(oci.monitoring, "MonitoringClient", client_factory)
    for name, value in {
        "OBJECT_STORAGE_NAMESPACE": "namespace-under-test",
        "SPLUNK_EVIDENCE_STATE_BUCKET": "state-bucket-under-test",
        "SPLUNK_EVIDENCE_DLQ_BUCKET": "dlq-bucket-under-test",
        "SPLUNK_HEC_SECRET_ID": "secret-reference-under-test",
        "OCI_LOG_ANALYTICS_COMPARTMENT_ID": "compartment-under-test",
        "OCI_LOG_ANALYTICS_NAMESPACE": "trusted-log-analytics-namespace",
        "SPLUNK_HEC_URL": "https://splunk.example.invalid:8088",
        "SPLUNK_HEC_INDEX": "evidence-index",
            "SPLUNK_HEC_SOURCETYPE": "oci:logan:detection",
            "SPLUNK_EXPORTER_TELEMETRY_NAMESPACE": "oci_log_analytics_splunk_exporter",
    }.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("SPLUNK_ALARM_BINDINGS", json.dumps({"redacted-alarm-id": "oci-audit-failures"}))

    service = handler_module.build_service()

    assert isinstance(service, EvidenceExportService)
    assert len(clients) == 3
    assert all(call == {"config": {}, "signer": signer} for call in clients)


def test_handler_has_no_oci_sdk_import_client_or_model_construction():
    source = (ROOT / "scripts/splunk_evidence_exporter/handler.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    imports = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }

    assert "oci" not in imports
    assert "LogAnalyticsClient" not in source
    assert "SecretsClient" not in source
    assert "ObjectStorageClient" not in source
    assert "oci.log_analytics.models" not in source
