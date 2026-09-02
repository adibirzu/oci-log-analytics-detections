"""RED contracts for durable delivery, telemetry, and production supply chain."""

from __future__ import annotations

import re
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from scripts.splunk_evidence_exporter.adapters import (
    OciMonitoringMetricsAdapter,
    ObjectStorageDeliveryLedgerAdapter,
)
from scripts.splunk_evidence_exporter.models import AlarmTrigger
from scripts.splunk_evidence_exporter.service import EvidenceExportService


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "stack/modules/splunk_evidence_exporter"
NOW = datetime(2026, 9, 2, 7, 15, tzinfo=timezone.utc)


def alarm_payload():
    return {"data": {"detectionId": "oci-audit-failures", "alarmEndTime": "2026-09-02T07:15:00Z",
                      "namespace": "oci_log_analytics_detections", "metricName": "AuditFailures", "dimensions": {}}}


def registry_entry():
    return {"id": "oci-audit-failures", "title": "OCI Audit Failures", "oci_query_file": "queries/hunting/oci_audit_failures.json",
            "required_fields": ["Event Type", "Status"], "detection": {"severity": "medium"},
            "evidence": {"include_original_content": False}}


class _StatusError(Exception):
    def __init__(self, status: int):
        self.status = status


class _ObjectStore:
    """Small Object Storage CAS simulator used by the adapter integration tests."""

    def __init__(self):
        self._lock = threading.Lock()
        self._objects: dict[str, tuple[str, str]] = {}
        self._version = 0

    def get_object(self, *, object_name, **_kwargs):
        with self._lock:
            if object_name not in self._objects:
                raise _StatusError(404)
            body, etag = self._objects[object_name]
        class Data:
            content = body
        class Response:
            data = Data()
        response = Response()
        response.etag = etag
        return response

    def put_object(self, *, object_name, put_object_body, if_none_match=None, if_match=None, **_kwargs):
        with self._lock:
            current = self._objects.get(object_name)
            if if_none_match == "*" and current is not None:
                raise _StatusError(412)
            if if_match is not None and (current is None or current[1] != if_match):
                raise _StatusError(412)
            self._version += 1
            etag = f"etag-{self._version}"
            self._objects[object_name] = (put_object_body, etag)
        class Response:
            pass
        response = Response()
        response.etag = etag
        return response


def test_shared_durable_ledger_allows_one_concurrent_winner_and_one_delivery():
    store = _ObjectStore()
    first = ObjectStorageDeliveryLedgerAdapter(client=store, namespace="ns", bucket="ledger")
    second = ObjectStorageDeliveryLedgerAdapter(client=store, namespace="ns", bucket="ledger")
    barrier = threading.Barrier(2)
    winners: list[bool] = []

    def reserve(adapter):
        barrier.wait()
        winners.append(adapter.reserve("event-key", now=NOW, lease=timedelta(minutes=5)))

    threads = [threading.Thread(target=reserve, args=(adapter,)) for adapter in (first, second)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(winners) == [False, True]
    winner = first if winners[0] else second
    winner.mark_delivered("event-key", now=NOW + timedelta(seconds=1))
    assert second.reserve("event-key", now=NOW + timedelta(minutes=1), lease=timedelta(minutes=5)) is False
    assert first.reserve("event-key", now=NOW + timedelta(minutes=10), lease=timedelta(minutes=5)) is False


def test_failed_reservation_is_takeover_safe_only_after_lease_expiry():
    store = _ObjectStore()
    ledger = ObjectStorageDeliveryLedgerAdapter(client=store, namespace="ns", bucket="ledger")
    assert ledger.reserve("retry-key", now=NOW, lease=timedelta(minutes=5)) is True
    ledger.release("retry-key")
    assert ledger.reserve("retry-key", now=NOW + timedelta(minutes=4), lease=timedelta(minutes=5)) is False
    assert ledger.reserve("retry-key", now=NOW + timedelta(minutes=5, seconds=1), lease=timedelta(minutes=5)) is True


class _MetricsClient:
    def __init__(self):
        self.payloads = []

    def post_metric_data(self, payload):
        self.payloads.append(payload)


def test_metrics_adapter_rejects_sensitive_and_high_cardinality_dimensions():
    client = _MetricsClient()
    adapter = OciMonitoringMetricsAdapter(
        client=client,
        compartment_id="compartment",
        namespace="oci_log_analytics_splunk_exporter",
        metric_data_factory=lambda **kwargs: kwargs,
    )
    with pytest.raises(ValueError, match="dimensions"):
        adapter.emit("DeliveredEvents", 1, {"token": "secret-value"})
    with pytest.raises(ValueError, match="dimensions"):
        adapter.emit("DeliveredEvents", 1, {"detection": "d", "outcome": "ok", "extra": "x"})


def test_metrics_adapter_sends_documented_namespace_and_service_metric_contract():
    client = _MetricsClient()
    adapter = OciMonitoringMetricsAdapter(
        client=client,
        compartment_id="compartment",
        namespace="oci_log_analytics_splunk_exporter",
        metric_data_factory=lambda **kwargs: kwargs,
    )
    adapter.emit("DeliverySucceeded", 1, {"detection": "rule", "outcome": "DeliverySucceeded"})
    metric = client.payloads[0]["metric_data"][0]
    assert metric["namespace"] == "oci_log_analytics_splunk_exporter"
    assert metric["name"] == "DeliverySucceeded"
    assert set(metric["dimensions"]) == {"detection", "outcome"}


class _MetricSink:
    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail

    def emit(self, name, value, dimensions):
        self.calls.append((name, value, dict(dimensions)))
        if self.fail:
            raise RuntimeError("metrics backend unavailable")


def _metric_service(metrics, hec_result, dead_letter=None, delivery_ledger=None, hec_override=None):
    class Registry:
        def load(self):
            return {"detections": [registry_entry()]}
    class State:
        def load_checkpoint(self, *_):
            return None
        def save_checkpoint(self, *_):
            self.saved = True
    class Query:
        def query_evidence(self, **_):
            return [{"Event Type": "com.oraclecloud.identitycontrolplane.updatepolicy", "Status": "Failure"}]
    class Hec:
        def deliver(self, _):
            if isinstance(hec_result, Exception):
                raise hec_result
            return hec_result
    class Dlq:
        def quarantine(self, *args, **kwargs):
            if dead_letter is not None:
                dead_letter.append((args, kwargs))
    return EvidenceExportService(
        registry=Registry(), query=Query(), checkpoint=State(), hec=hec_override or Hec(),
        dead_letter=Dlq(), metrics=metrics, delivery_ledger=delivery_ledger,
        clock=lambda: NOW + timedelta(minutes=1), lookback=timedelta(minutes=15),
        overlap=timedelta(minutes=2), maximum_window=timedelta(hours=1),
        max_rows=1000, max_batch_events=100, max_attempts=1,
    )


def test_service_emits_success_metrics_and_delivery_counts():
    metrics = _MetricSink()
    receipt = _metric_service(metrics, {"status": 200, "response": {"code": 0}}).export(
        AlarmTrigger.from_payload(alarm_payload())
    )
    assert receipt.status == "delivered"
    assert [(name, value) for name, value, _ in metrics.calls] == [
        ("DeliverySucceeded", 1), ("DeliveredEvents", 1)
    ]


def test_service_emits_failure_and_dead_letter_metrics_without_making_metrics_fatal():
    metrics = _MetricSink(fail=True)
    dead_letters = []
    receipt = _metric_service(metrics, TimeoutError("timeout"), dead_letters).export(
        AlarmTrigger.from_payload(alarm_payload())
    )
    assert receipt.status == "delivery_failed"
    assert len(dead_letters) == 1
    assert [(name, value) for name, value, _ in metrics.calls] == [
        ("DeliveryFailed", 1), ("DeadLetteredEvents", 1)
    ]


def test_two_service_instances_share_ledger_and_only_first_reaches_hec():
    store = _ObjectStore()
    ledger_a = ObjectStorageDeliveryLedgerAdapter(client=store, namespace="ns", bucket="ledger")
    ledger_b = ObjectStorageDeliveryLedgerAdapter(client=store, namespace="ns", bucket="ledger")
    calls = []

    class Hec:
        def deliver(self, batch):
            calls.append(batch)
            return {"status": 200, "response": {"code": 0}}

    # The two services have independent process-local state but share the durable ledger.
    shared_hec = Hec()
    service_a = _metric_service(_MetricSink(), {"status": 200, "response": {"code": 0}}, delivery_ledger=ledger_a, hec_override=shared_hec)
    service_b = _metric_service(_MetricSink(), {"status": 200, "response": {"code": 0}}, delivery_ledger=ledger_b, hec_override=shared_hec)
    assert service_a.export(AlarmTrigger.from_payload(alarm_payload())).status == "delivered"
    assert service_b.export(AlarmTrigger.from_payload(alarm_payload())).status == "no_evidence"
    assert len(calls) == 1


def test_terraform_alarm_namespace_matches_emitter_and_iam_allows_post_metrics():
    main = (MODULE / "main.tf").read_text()
    iam = (ROOT / "scripts/splunk_evidence_exporter_cli.py").read_text()
    assert re.search(r"SPLUNK_EXPORTER_TELEMETRY_NAMESPACE\s*=\s*var\.exporter_telemetry_namespace", main)
    assert re.search(r'namespace\s*=\s*var\.exporter_telemetry_namespace\s*\n\s*query\s*=\s*"DeliveryFailed', main)
    assert re.search(r"Allow dynamic-group <FUNCTION_DYNAMIC_GROUP_NAME> to (post-metric-data|use metrics|manage metrics)", iam, re.IGNORECASE)


def test_live_enablement_requires_digest_pins_and_supply_chain_evidence():
    terraform = (MODULE / "main.tf").read_text()
    requirements = (MODULE / "function/requirements.txt").read_text()
    docs = (MODULE / "function/README.md").read_text()
    assert re.search(r'image\s*=\s*"\$\{var\.function_image\}@\$\{var\.function_image_digest\}"', terraform)
    assert re.search(r'regex\("\^sha256:\[0-9a-f\]\{64\}\$"', terraform)
    assert all(re.fullmatch(r"[A-Za-z0-9_.-]+==[0-9][^\n]*", line.strip()) for line in requirements.splitlines() if line.strip())
    # A digest-only image receipt is insufficient: dependency resolution must
    # also be reproducible from hashes or a checked-in lock artifact.
    assert "--require-hashes" in docs or "requirements.lock" in docs
    for evidence in ("SBOM", "SCA", "SAST", "IaC", "container scan", "signature"):
        assert evidence.lower() in docs.lower(), evidence
