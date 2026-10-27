from scripts.splunk_exporter_cases_common import *  # noqa: F403

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
        delivery_target="hec",
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
    assert dlq_record["delivery_target"] == "hec"
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
