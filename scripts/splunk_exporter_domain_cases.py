from scripts.splunk_exporter_cases_common import *  # noqa: F403
from scripts.splunk_evidence_exporter.adapters import _validated_streaming_endpoint

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
                "id": "ocid1.alarm.demo.eu-frankfurt-1.aaaaaaaaaaaaaaaa",  # scanner-fixture
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

    assert trigger.alarm_id == "ocid1.alarm.demo.eu-frankfurt-1.aaaaaaaaaaaaaaaa"  # scanner-fixture
    assert trigger.detection_id is None
    assert trigger.query == "AuditFailures[5m].sum() > 0"


def test_raw_alarm_contract_rejects_namespace_metric_dimension_and_query_mismatch():
    entry = registry_entry()
    entry["alarm_contract"] = {
        "binding_key": "oci-audit-failures",
        "metric_namespace": "oci_log_analytics_detections",
        "metric_name": "AuditFailures",
        "metric_dimensions": ["Event Type", "User Name", "Status"],
        "query": "AuditFailures[5m].sum() > 0",
        "allowed_dimensions": {"Status": "Failure"},
    }
    trigger = AlarmTrigger.from_payload({"data": {
        "alarmMetaData": [{"id": "ocid1.alarm.demo.eu-frankfurt-1.aaaaaaaaaaaaaaaa", "namespace": "oci_log_analytics_detections", "query": "different", "dimensions": {"Status": "Failure"}}],  # scanner-fixture
        "timestamp": "2026-09-02T07:15:00Z", "metricName": "AuditFailures",
    }})
    with pytest.raises(ValueError, match="alarm contract mismatch"):
        EvidenceExportService._validate_alarm_contract(entry, trigger)


def test_provider_raw_alarm_routes_by_bound_identity_but_queries_trusted_la_namespace_without_routing_dimensions():
    raw = json.loads((ROOT / "scripts/fixtures/splunk_evidence/oci_raw_alarm.json").read_text())
    entry = registry_entry()
    entry["alarm_contract"] = {
        "binding_key": "oci-audit-failures", "metric_namespace": "oci_log_analytics_detections",
        "metric_name": "AuditFailures", "metric_dimensions": ["Event Type", "User Name", "Status"],
        "query": "AuditFailures[15m].sum() > 0",
        "allowed_dimensions": {}, "alarm_dimension_to_log_field": {},
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


def test_event_key_includes_resolved_source_and_entity_context():
    row = {"FirstSeen": "2026-09-02T07:14:00Z", "Status": "Failure"}

    baseline = event_key(
        "oci-audit-failures", row, log_source="OCI Audit Logs", entity="host-a"
    )

    assert baseline != event_key(
        "oci-audit-failures", row, log_source="Windows Security Events", entity="host-a"
    )
    assert baseline != event_key(
        "oci-audit-failures", row, log_source="OCI Audit Logs", entity="host-b"
    )


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
        "query_version": "a" * 64,
        "required_sources": ["OCI Audit Logs"],
        "required_fields": [
            "Event Type", "Status", "Evidence Version", "api_token", "Password Hash", "Authorization",
            "clientSecret", "Resource OCID", "Customer Field", "Details",
        ],
        "detection": {"severity": "medium", "mitre_techniques": ["T1078"], "mechanism": "scheduled"},
        "delivery": {"evidence_targets": ["hec", "streaming"]},
        "alarm_contract": {
            "metric_namespace": "oci_log_analytics_detections",
            "metric_dimensions": ["Event Type", "Status"],
        },
        "evidence": {"include_original_content": False, "redaction_profile": None},
    }


def test_evidence_event_is_schema_valid_excludes_original_and_redacts_secrets():
    row = {
        "Time": "2026-09-02T07:14:00Z",
        "Event Type": "com.oraclecloud.identitycontrolplane.updatepolicy",
        "Status": "Failure",
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
    assert payload["detection"]["metric_namespace"] == "oci_log_analytics_detections"
    assert payload["detection"]["dimensions"] == {
        "Event Type": row["Event Type"],
        "Status": row["Status"],
    }
    assert payload["evidence"]["event_time"] == row["Time"]
    assert payload["evidence"]["log_source"] == "OCI Audit Logs"
    assert payload["evidence"]["entity"] is None
    assert payload["provenance"]["analytics_plane"] == "oci_log_analytics"
    assert payload["provenance"]["query_version"] == "a" * 64
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


def test_streaming_evidence_adapter_emits_one_keyed_json_message_per_event():
    calls = []

    class Client:
        def put_messages(self, stream_id, details):
            calls.append((stream_id, details))
            entry = type("Entry", (), {"error": None})()
            data = type("Data", (), {"entries": [entry], "failures": 0})()
            return type("Response", (), {"data": data})()

    adapter = OciStreamingEvidenceAdapter(
        client=Client(),
        stream_id="ocid1.stream.demo.eu-frankfurt-1.aaaaaaaaaaaaaaaa",  # scanner-fixture
        message_factory=lambda **values: values,
        details_factory=lambda **values: values,
    )
    event = build_evidence_event(
        registry_entry(),
        {"Time": "2026-09-02T07:14:00Z", "Event Type": "demo", "Status": "Failure"},
        QueryWindow(
            start=datetime(2026, 9, 2, 6, 58, tzinfo=timezone.utc),
            end=datetime(2026, 9, 2, 7, 15, tzinfo=timezone.utc),
        ),
        "batch",
    )

    result = adapter.deliver(ExportBatch(batch_id="batch", events=(event,)))

    assert result == {"status": 200, "response": {"code": 0}}
    assert calls[0][0].startswith("ocid1.stream.demo.")  # scanner-fixture
    message = calls[0][1]["messages"][0]
    assert json.loads(base64.b64decode(message["value"])) == event.to_dict()
    assert base64.b64decode(message["key"]).decode() == event.event_key


def test_streaming_evidence_adapter_rejects_partial_provider_confirmation():
    class Client:
        def put_messages(self, *_args):
            data = type("Data", (), {"entries": [], "failures": 0})()
            return type("Response", (), {"data": data})()

    adapter = OciStreamingEvidenceAdapter(
        client=Client(),
        stream_id="ocid1.stream.demo.eu-frankfurt-1.aaaaaaaaaaaaaaaa",  # scanner-fixture
        message_factory=lambda **values: values,
        details_factory=lambda **values: values,
    )
    event = build_evidence_event(
        registry_entry(),
        {"Time": "2026-09-02T07:14:00Z", "Event Type": "demo"},
        QueryWindow(
            start=datetime(2026, 9, 2, 6, 58, tzinfo=timezone.utc),
            end=datetime(2026, 9, 2, 7, 15, tzinfo=timezone.utc),
        ),
        "batch",
    )

    assert adapter.deliver(ExportBatch(batch_id="batch", events=(event,))) == {
        "status": 500,
        "response": {},
    }


def test_streaming_endpoint_is_restricted_to_oci_streaming_hosts():
    assert (
        _validated_streaming_endpoint(
            "https://cell-1.streaming.eu-frankfurt-1.oci.oraclecloud.com/"
        )
        == "https://cell-1.streaming.eu-frankfurt-1.oci.oraclecloud.com"
    )
    for endpoint in (
        "https://example.invalid",
        "https://streaming.example.invalid",
        "https://cell-1.streaming.eu-frankfurt-1.oci.oraclecloud.com.evil.invalid",
        "https://cell-1.streaming.eu-frankfurt-1.oci.oraclecloud.com/path",
    ):
        with pytest.raises(ValueError):
            _validated_streaming_endpoint(endpoint)


def test_streaming_evidence_adapter_returns_retryable_status_without_payload_leak():
    class Client:
        def put_messages(self, *_args):
            error = RuntimeError("provider detail must not escape")
            error.status = 429
            raise error

    adapter = OciStreamingEvidenceAdapter(
        client=Client(),
        stream_id="ocid1.stream.demo.eu-frankfurt-1.aaaaaaaaaaaaaaaa",  # scanner-fixture
        message_factory=lambda **values: values,
        details_factory=lambda **values: values,
    )
    event = build_evidence_event(
        registry_entry(),
        {"Time": "2026-09-02T07:14:00Z", "Event Type": "demo", "Status": "Failure"},
        QueryWindow(
            start=datetime(2026, 9, 2, 6, 58, tzinfo=timezone.utc),
            end=datetime(2026, 9, 2, 7, 15, tzinfo=timezone.utc),
        ),
        "batch",
    )
    result = adapter.deliver(ExportBatch(batch_id="batch", events=(event,)))
    assert result == {"status": 429, "response": {}}


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


def test_domain_modules_have_no_infrastructure_or_implicit_clock_dependencies(monkeypatch):
    import datetime as datetime_module
    import importlib
    from types import ModuleType

    class ExplicitDatetime(datetime):
        @classmethod
        def now(cls, *args, **kwargs):
            raise AssertionError("implicit clock attempted")

        utcnow = today = now

    package_name = "_splunk_pure_domain_contract"
    package = ModuleType(package_name)
    package.__path__ = [str(ROOT / "scripts/splunk_evidence_exporter")]
    payload = alarm_payload()
    entry = registry_entry()
    try:
        with monkeypatch.context() as isolated:
            isolated.setitem(sys.modules, package_name, package)
            isolated.setattr(datetime_module, "datetime", ExplicitDatetime)
            with runtime_side_effect_guard(isolated, domain=True) as attempts:
                for operation in (
                    lambda: __import__("oci", fromlist=["client"]),
                    lambda: __import__("oci.client"),
                    lambda: open("credential-under-test"),
                    lambda: socket.create_connection(("example.invalid", 443)),
                    lambda: os.getenv("OCI_CONFIG_FILE"),
                ):
                    with pytest.raises(AssertionError):
                        operation()
                attempts.clear()
                modules = {
                    name: importlib.import_module(f"{package_name}.{name}")
                    for name in ("models", "window", "envelope", "retry", "ports")
                }
                trigger = modules["models"].AlarmTrigger.from_payload(payload)
                window = modules["window"].calculate_window(
                    trigger.alarm_end, timedelta(minutes=5), timedelta(minutes=2),
                    maximum=timedelta(hours=1),
                )
                event = modules["envelope"].build_evidence_event(
                    entry, {"Status": "Failure", "api_token": "synthetic-value"},
                    window, batch_id="pure-domain-batch",
                )
                batches = modules["envelope"].batch_events([event, event], 1)
                assert window.duration == timedelta(minutes=7)
                fields = {field["name"]: field["value"] for field in event.to_dict()["evidence"]["fields"]}
                assert fields == {"Status": "Failure", "api_token": "[REDACTED]"}
                assert [batch.events for batch in batches] == [(event,), (event,)]
                assert modules["envelope"].event_key("oci-audit-failures", {"Status": "Failure"}) == modules["envelope"].event_key("oci-audit-failures", {"Status": "Failure"})
                assert modules["retry"].classify_hec_failure(200, response={"code": 0}) == "success"
                assert modules["retry"].classify_hec_failure(503) == "retryable"
                assert modules["retry"].classify_hec_failure(401) == "quarantine"
                assert isinstance(SimpleNamespace(query_evidence=lambda **kwargs: []), modules["ports"].EvidenceQueryPort)
                with pytest.raises(ValueError, match="positive"):
                    modules["window"].calculate_window(trigger.alarm_end, timedelta(0), timedelta(0))
                assert attempts == []
    finally:
        for name in tuple(sys.modules):
            if name.startswith(f"{package_name}."):
                sys.modules.pop(name)
