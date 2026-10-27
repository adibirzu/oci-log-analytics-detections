from scripts.splunk_exporter_cases_common import *  # noqa: F403

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
        "delivery_target": "hec",
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


def test_function_service_selects_streaming_sink_without_hec_credentials(monkeypatch):
    sink = object()
    bundle = SimpleNamespace(
        query=object(),
        checkpoint=object(),
        dead_letter=object(),
        ledger=object(),
        metrics=object(),
        vault=None,
    )
    monkeypatch.setattr(
        handler_module.OciResourcePrincipalAdapterFactory,
        "create",
        lambda **_kwargs: bundle,
    )
    observed = {}

    def streaming_factory(**values):
        observed.update(values)
        return sink

    monkeypatch.setattr(
        handler_module.OciStreamingEvidenceAdapter,
        "from_resource_principal",
        streaming_factory,
    )
    for name, value in {
        "SPLUNK_EVIDENCE_TARGET": "streaming",
        "OBJECT_STORAGE_NAMESPACE": "namespace-under-test",
        "SPLUNK_EVIDENCE_STATE_BUCKET": "state-bucket-under-test",
        "SPLUNK_EVIDENCE_DLQ_BUCKET": "dlq-bucket-under-test",
        "OCI_LOG_ANALYTICS_COMPARTMENT_ID": "compartment-under-test",
        "OCI_LOG_ANALYTICS_NAMESPACE": "trusted-log-analytics-namespace",
        "SPLUNK_EVIDENCE_STREAM_ID": "stream-reference-under-test",
        "SPLUNK_EVIDENCE_STREAM_MESSAGES_ENDPOINT": "https://streaming.example.invalid",
        "SPLUNK_EXPORTER_TELEMETRY_NAMESPACE": "oci_log_analytics_splunk_exporter",
        "SPLUNK_ALARM_BINDINGS": json.dumps(
            {"redacted-alarm-id": "oci-audit-failures"}
        ),
    }.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("SPLUNK_HEC_SECRET_ID", raising=False)
    monkeypatch.delenv("SPLUNK_HEC_URL", raising=False)

    service = handler_module.build_service()

    assert service._hec is sink
    assert observed == {
        "stream_id": "stream-reference-under-test",
        "messages_endpoint": "https://streaming.example.invalid",
    }


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
