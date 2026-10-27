from scripts.splunk_exporter_cases_common import *  # noqa: F403

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


def test_export_service_enforces_detection_evidence_target_policy():
    entry = registry_entry()
    entry["delivery"]["evidence_targets"] = ["hec"]

    class Registry:
        def load(self):
            return {"detections": [entry]}

    service = EvidenceExportService(
        registry=Registry(),
        query=object(),
        checkpoint=object(),
        hec=object(),
        dead_letter=object(),
        clock=lambda: datetime(2026, 9, 2, 7, 16, tzinfo=timezone.utc),
        lookback=timedelta(minutes=15),
        overlap=timedelta(minutes=2),
        maximum_window=timedelta(hours=1),
        max_rows=1000,
        max_batch_events=100,
        delivery_target="streaming",
    )

    with pytest.raises(ValueError, match="not allowed"):
        service.export(AlarmTrigger.from_payload(alarm_payload()))


def test_export_service_honors_registry_delivery_bounds():
    entry = registry_entry()
    entry["delivery"] = {
        "evidence_targets": ["hec", "streaming"],
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
    entry["delivery"] = {"evidence_targets": ["hec", "streaming"], **delivery}

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
