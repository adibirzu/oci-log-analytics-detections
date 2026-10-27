from scripts.splunk_exporter_cases_common import *  # noqa: F403

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
    entry["delivery"] = {"evidence_targets": ["hec", "streaming"], "max_attempts": 3}
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
    entry["delivery"] = {"evidence_targets": ["hec", "streaming"], "max_attempts": 5}

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
        "delivery_target": "hec",
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


def test_replay_rejects_record_bound_to_a_different_sink_before_delivery():
    record = {
        "schema_version": "oci.logan.splunk.dead-letter.v1",
        "reason": "retryable",
        "batch_id": "replay-batch",
        "detection_id": "oci-audit-failures",
        "dimensions": {},
        "checkpoint": "2026-09-02T07:15:00Z",
        "delivery_target": "hec",
        "delivered_event_keys": [],
        "remaining_events": [{}],
    }

    class NeverCalled:
        def __getattr__(self, name):
            raise AssertionError(f"{name} must not be called for a sink mismatch")

    service = EvidenceReplayService(
        checkpoint=NeverCalled(),
        hec=NeverCalled(),
        dead_letter=NeverCalled(),
        clock=lambda: datetime(2026, 9, 2, 7, 16, tzinfo=timezone.utc),
        max_batch_events=100,
        max_attempts=4,
        delivery_target="streaming",
    )

    with pytest.raises(ValueError, match="does not match replay sink"):
        service.replay(record)


def test_replay_rejects_target_removed_from_current_registry_policy():
    record = {
        "schema_version": "oci.logan.splunk.dead-letter.v1",
        "reason": "retryable",
        "batch_id": "replay-batch",
        "detection_id": "oci-audit-failures",
        "dimensions": {},
        "checkpoint": "2026-09-02T07:15:00Z",
        "delivery_target": "streaming",
        "delivered_event_keys": [],
        "remaining_events": [{}],
    }
    entry = registry_entry()
    entry["delivery"]["evidence_targets"] = ["hec"]

    class Registry:
        def load(self):
            return {"detections": [entry]}

    class NeverCalled:
        def __getattr__(self, name):
            raise AssertionError(f"{name} must not be called for disallowed replay")

    service = EvidenceReplayService(
        checkpoint=NeverCalled(),
        hec=NeverCalled(),
        dead_letter=NeverCalled(),
        clock=lambda: datetime(2026, 9, 2, 7, 16, tzinfo=timezone.utc),
        max_batch_events=100,
        max_attempts=4,
        delivery_target="streaming",
        registry=Registry(),
    )

    with pytest.raises(ValueError, match="no longer allowed"):
        service.replay(record)


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
        "delivery_target": "hec",
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
