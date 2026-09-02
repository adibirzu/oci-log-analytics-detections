"""Application orchestration for bounded OCI Log Analytics evidence export."""

from __future__ import annotations

import hashlib
import json
import re
import random
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Mapping

from .envelope import (
    batch_events,
    build_evidence_event,
    event_key,
    restore_evidence_event,
)
from .models import AlarmTrigger, ExportBatch
from .ports import CheckpointPort, EvidenceQueryPort, HecDeliveryPort, QuarantinePort
from .retry import classify_hec_failure
from .window import calculate_window


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _duration(value: object, fallback: timedelta, label: str) -> timedelta:
    if value is None:
        return fallback
    if not isinstance(value, str):
        raise ValueError(f"registry {label} must be a duration string")
    match = re.fullmatch(r"([1-9][0-9]*)([smhd])", value)
    if match is None:
        raise ValueError(f"registry {label} must use seconds, minutes, hours, or days")
    amount = int(match.group(1))
    return timedelta(
        seconds=amount * {"s": 1, "m": 60, "h": 3600, "d": 86400}[match.group(2)]
    )


def _bounded_int(value: object, runtime_maximum: int, label: str) -> int:
    if value is None:
        return runtime_maximum
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"registry {label} must be a positive integer")
    if value > runtime_maximum:
        raise ValueError(f"registry {label} exceeds the runtime maximum")
    return value


def _runtime_maximum(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"runtime {label} must be a positive integer")
    return value


def _delivery_outcome(
    hec: HecDeliveryPort, batch: ExportBatch, max_attempts: int,
    *, sleep: Callable[[float], None] = time.sleep,
    random_fraction: Callable[[], float] = random.random,
) -> str:
    """Run service-visible HEC attempts; one adapter call is one attempt."""

    outcome = "retryable"
    for attempt in range(max_attempts):
        try:
            result = hec.deliver(batch)
            outcome = classify_hec_failure(
                result.get("status"),
                acknowledgement_mode=result.get("acknowledgement_mode", "response"),
                response=result.get("response"),
                acknowledgement_confirmed=result.get(
                    "acknowledgement_confirmed", False
                ),
            )
        except Exception as exc:
            sanitized_failure = (
                TimeoutError("HEC delivery timed out")
                if isinstance(exc, TimeoutError)
                else RuntimeError("HEC delivery failed")
            )
            outcome = classify_hec_failure(sanitized_failure)
        if outcome != "retryable":
            return outcome
        if attempt + 1 < max_attempts:
            jitter = max(0.0, min(1.0, float(random_fraction())))
            sleep(min(4.0, 0.25 * (2**attempt)) * (0.5 + jitter))
    return outcome


@dataclass(frozen=True)
class ExportReceipt:
    """Sanitized invocation result; never contains evidence or provider identifiers."""

    status: str
    detection_id: str
    window_start: datetime
    window_end: datetime
    row_count: int
    event_count: int
    batch_count: int
    delivered_count: int
    checkpoint_committed: bool
    completed_at: datetime

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "detection_id": self.detection_id,
            "window_start": _utc_text(self.window_start),
            "window_end": _utc_text(self.window_end),
            "row_count": self.row_count,
            "event_count": self.event_count,
            "batch_count": self.batch_count,
            "delivered_count": self.delivered_count,
            "checkpoint_committed": self.checkpoint_committed,
            "completed_at": _utc_text(self.completed_at),
        }


class EvidenceExportService:
    """Run one export through injected registry, OCI, state, DLQ, and HEC seams."""

    def __init__(
        self,
        *,
        registry: object,
        query: EvidenceQueryPort,
        checkpoint: CheckpointPort,
        hec: HecDeliveryPort,
        dead_letter: QuarantinePort,
        clock: Callable[[], datetime],
        lookback: timedelta,
        overlap: timedelta,
        maximum_window: timedelta,
        max_rows: int,
        max_batch_events: int,
        max_attempts: int = 4,
        sleep: Callable[[float], None] = time.sleep,
        random_fraction: Callable[[], float] = random.random,
        alarm_bindings: Mapping[str, str] | None = None,
        log_analytics_namespace: str | None = None,
    ) -> None:
        self._registry = registry
        self._query = query
        self._checkpoint = checkpoint
        self._hec = hec
        self._dead_letter = dead_letter
        self._clock = clock
        self._lookback = lookback
        self._overlap = overlap
        self._maximum_window = maximum_window
        self._max_rows = max_rows
        self._max_batch_events = max_batch_events
        self._max_attempts = _runtime_maximum(max_attempts, "max_attempts")
        self._sleep = sleep
        self._random_fraction = random_fraction
        self._alarm_bindings = dict(alarm_bindings or {})
        self._log_analytics_namespace = log_analytics_namespace
        # Invocation-local duplicate guard.  Persistent checkpoint/CAS prevents
        # out-of-order watermarks; an externally durable delivery ledger is a
        # separate deployment concern and is deliberately not implied here.
        self._delivered_event_keys: set[str] = set()

    def export(self, trigger: AlarmTrigger) -> ExportReceipt:
        registry_document = self._registry.load()
        entry = self._find_entry(registry_document, trigger, self._alarm_bindings)
        detection_id = entry["id"]
        self._validate_alarm_contract(entry, trigger)
        delivery = entry.get("delivery", {})
        if not isinstance(delivery, Mapping):
            raise ValueError("registry delivery configuration must be an object")
        lookback = _duration(delivery.get("lookback"), self._lookback, "lookback")
        overlap = _duration(delivery.get("overlap"), self._overlap, "overlap")
        max_rows = _bounded_int(delivery.get("max_rows"), self._max_rows, "max_rows")
        max_batch_events = _bounded_int(
            delivery.get("max_batch_events"),
            self._max_batch_events,
            "max_batch_events",
        )
        max_attempts = _bounded_int(
            delivery.get("max_attempts"), self._max_attempts, "max_attempts"
        )
        checkpoint = self._checkpoint.load_checkpoint(
            detection_id, trigger.dimensions
        )
        window = calculate_window(
            trigger.alarm_end,
            lookback=lookback,
            overlap=overlap,
            checkpoint=checkpoint,
            maximum=self._maximum_window,
        )
        rows = tuple(
            self._query.query_evidence(
                namespace=self._log_analytics_namespace or trigger.namespace,
                query_file=entry["oci_query_file"],
                window=window,
                dimensions=trigger.dimensions,
                max_rows=max_rows,
            )
        )
        batch_id = self._batch_id(trigger, detection_id)
        # Build/allowlist/redact before deduplication; a new unreviewed query
        # column must never cause a second export of the same governed evidence.
        unique_events: dict[str, object] = {}
        for row in rows:
            event = build_evidence_event(entry, row, window, batch_id)
            unique_events.setdefault(event.event_key, event)
        events = tuple(unique_events.values())
        events = tuple(event for event in events if event.event_key not in self._delivered_event_keys)
        batches = batch_events(events, max_batch_events)

        if not events:
            return ExportReceipt(
                status="no_evidence",
                detection_id=detection_id,
                window_start=window.start,
                window_end=window.end,
                row_count=len(rows),
                event_count=0,
                batch_count=0,
                delivered_count=0,
                checkpoint_committed=False,
                completed_at=self._clock(),
            )

        delivered_count = 0
        delivered_event_keys: list[str] = []
        for batch_index, batch in enumerate(batches):
            outcome = _delivery_outcome(self._hec, batch, max_attempts, sleep=self._sleep, random_fraction=self._random_fraction)
            if outcome != "success":
                remaining_events = tuple(
                    event
                    for remaining_batch in batches[batch_index:]
                    for event in remaining_batch.events
                )
                self._dead_letter.quarantine(
                    ExportBatch(batch_id=batch_id, events=remaining_events),
                    outcome,
                    delivered_event_keys=tuple(delivered_event_keys),
                    detection_id=detection_id,
                    dimensions=trigger.dimensions,
                    checkpoint=window.end,
                )
                return ExportReceipt(
                    status="delivery_failed",
                    detection_id=detection_id,
                    window_start=window.start,
                    window_end=window.end,
                    row_count=len(rows),
                    event_count=len(events),
                    batch_count=len(batches),
                    delivered_count=delivered_count,
                    checkpoint_committed=False,
                    completed_at=self._clock(),
                )
            delivered_count += len(batch.events)
            delivered_event_keys.extend(event.event_key for event in batch.events)
            self._delivered_event_keys.update(event.event_key for event in batch.events)

        self._checkpoint.save_checkpoint(
            detection_id, trigger.dimensions, window.end
        )
        return ExportReceipt(
            status="delivered",
            detection_id=detection_id,
            window_start=window.start,
            window_end=window.end,
            row_count=len(rows),
            event_count=len(events),
            batch_count=len(batches),
            delivered_count=delivered_count,
            checkpoint_committed=True,
            completed_at=self._clock(),
        )

    @staticmethod
    def _find_entry(document: object, trigger: AlarmTrigger, alarm_bindings: Mapping[str, str]) -> Mapping[str, object]:
        if not isinstance(document, Mapping):
            raise ValueError("registry document must be an object")
        detections = document.get("detections")
        if not isinstance(detections, list):
            raise ValueError("registry detections must be a list")
        for entry in detections:
            if not isinstance(entry, Mapping):
                continue
            contract = entry.get("alarm_contract")
            bound_key = alarm_bindings.get(trigger.alarm_id or "")
            if trigger.alarm_id is not None and isinstance(contract, Mapping) and contract.get("binding_key") == bound_key:
                return entry
            if trigger.alarm_id is None and trigger.detection_id is not None and entry.get("id") == trigger.detection_id:
                return entry
        raise ValueError("alarm identity is not present in the registry")

    @staticmethod
    def _validate_alarm_contract(entry: Mapping[str, object], trigger: AlarmTrigger) -> None:
        if trigger.alarm_id is None:
            return
        contract = entry.get("alarm_contract")
        required = ("binding_key", "metric_namespace", "metric_name", "query", "allowed_dimensions")
        if not isinstance(contract, Mapping) or any(key not in contract for key in required):
            raise ValueError("governed alarm contract is incomplete")
        if (contract["metric_namespace"] != trigger.namespace or contract["metric_name"] != trigger.metric_name or contract["query"] != trigger.query):
            raise ValueError("alarm contract mismatch")
        if not isinstance(contract["allowed_dimensions"], Mapping) or dict(contract["allowed_dimensions"]) != dict(trigger.dimensions):
            raise ValueError("alarm dimensions do not match the governed contract")

    @staticmethod
    def _batch_id(trigger: AlarmTrigger, detection_id: str) -> str:
        time_id = trigger.alarm_end.strftime("%Y%m%dT%H%M%SZ").lower()
        dimension_hash = hashlib.sha256(
            json.dumps(
                dict(trigger.dimensions), sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()[:12]
        return f"{detection_id}-{time_id}-{dimension_hash}"


@dataclass(frozen=True)
class ReplayReceipt:
    """Sanitized result for delivery of normalized evidence already in the DLQ."""

    status: str
    detection_id: str
    window_start: datetime
    window_end: datetime
    row_count: int
    event_count: int
    excluded_confirmed_count: int
    batch_count: int
    delivered_count: int
    checkpoint_committed: bool
    checkpoint_status: str
    completed_at: datetime

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "detection_id": self.detection_id,
            "window_start": _utc_text(self.window_start),
            "window_end": _utc_text(self.window_end),
            "row_count": self.row_count,
            "event_count": self.event_count,
            "excluded_confirmed_count": self.excluded_confirmed_count,
            "batch_count": self.batch_count,
            "delivered_count": self.delivered_count,
            "checkpoint_committed": self.checkpoint_committed,
            "checkpoint_status": self.checkpoint_status,
            "completed_at": _utc_text(self.completed_at),
        }


class EvidenceReplayService:
    """Replay normalized remaining events from one persisted DLQ record."""

    def __init__(
        self,
        *,
        checkpoint: CheckpointPort,
        hec: HecDeliveryPort,
        dead_letter: QuarantinePort,
        clock: Callable[[], datetime],
        max_batch_events: int,
        max_attempts: int,
    ) -> None:
        self._checkpoint = checkpoint
        self._hec = hec
        self._dead_letter = dead_letter
        self._clock = clock
        self._max_batch_events = _runtime_maximum(max_batch_events, "max_batch_events")
        self._max_attempts = _runtime_maximum(max_attempts, "max_attempts")

    def replay(self, record: Mapping[str, object]) -> ReplayReceipt:
        if not isinstance(record, Mapping):
            raise ValueError("dead-letter record must be an object")
        required_fields = {
            "schema_version",
            "reason",
            "batch_id",
            "detection_id",
            "dimensions",
            "checkpoint",
            "delivered_event_keys",
            "remaining_events",
        }
        if not required_fields.issubset(record) or not set(record).issubset(
            required_fields | {"created_at"}
        ):
            raise ValueError("dead-letter record shape is invalid")
        if record.get("schema_version") != "oci.logan.splunk.dead-letter.v1":
            raise ValueError("dead-letter schema version is unsupported")
        if record.get("reason") not in ("retryable", "quarantine"):
            raise ValueError("dead-letter reason is unsupported")
        batch_id = self._required_text(record.get("batch_id"), "batch_id")
        detection_id = self._required_text(record.get("detection_id"), "detection_id")
        if re.fullmatch(r"[a-z0-9][a-z0-9-]*", detection_id) is None:
            raise ValueError("dead-letter detection_id is invalid")
        dimensions = self._dimensions(record.get("dimensions"))
        checkpoint = self._checkpoint_time(record.get("checkpoint"))
        delivered_event_keys = self._event_keys(record.get("delivered_event_keys"))
        raw_events = record.get("remaining_events")
        if not isinstance(raw_events, list) or not raw_events:
            raise ValueError("dead-letter remaining_events must be a non-empty list")
        restored = tuple(restore_evidence_event(item) for item in raw_events)
        checkpoint_text = _utc_text(checkpoint)
        for event in restored:
            if event.batch_id != batch_id:
                raise ValueError("dead-letter event batch does not match its record")
            if event.detection.get("id") != detection_id:
                raise ValueError(
                    "dead-letter event detection does not match its record"
                )
            if event.provenance.get("window_end") != checkpoint_text:
                raise ValueError(
                    "dead-letter checkpoint does not match event provenance"
                )
        confirmed = set(delivered_event_keys)
        remaining_by_key = {
            event.event_key: event
            for event in restored
            if event.event_key not in confirmed
        }
        remaining = tuple(remaining_by_key.values())
        excluded_count = len(restored) - len(remaining)
        window_start = min(
            self._checkpoint_time(event.provenance["window_start"])
            for event in restored
        )
        batches = batch_events(remaining, self._max_batch_events)
        delivered_count = 0
        newly_delivered_keys: list[str] = []
        for batch_index, batch in enumerate(batches):
            outcome = _delivery_outcome(self._hec, batch, self._max_attempts)
            if outcome != "success":
                pending_events = tuple(
                    event
                    for pending_batch in batches[batch_index:]
                    for event in pending_batch.events
                )
                self._dead_letter.quarantine(
                    ExportBatch(batch_id=batch_id, events=pending_events),
                    outcome,
                    delivered_event_keys=tuple(
                        [*delivered_event_keys, *newly_delivered_keys]
                    ),
                    detection_id=detection_id,
                    dimensions=dimensions,
                    checkpoint=checkpoint,
                )
                return self._receipt(
                    status="delivery_failed",
                    detection_id=detection_id,
                    window_start=window_start,
                    checkpoint=checkpoint,
                    event_count=len(remaining),
                    excluded_count=excluded_count,
                    batch_count=len(batches),
                    delivered_count=delivered_count,
                    committed=False,
                    checkpoint_status="not_evaluated",
                )
            delivered_count += len(batch.events)
            newly_delivered_keys.extend(event.event_key for event in batch.events)
        current_checkpoint = self._checkpoint.load_checkpoint(detection_id, dimensions)
        if current_checkpoint is None or current_checkpoint < checkpoint:
            self._checkpoint.save_checkpoint(detection_id, dimensions, checkpoint)
            checkpoint_status = "advanced"
            checkpoint_committed = True
        elif current_checkpoint == checkpoint:
            checkpoint_status = "already_current"
            checkpoint_committed = False
        else:
            checkpoint_status = "preserved_newer"
            checkpoint_committed = False
        return self._receipt(
            status="delivered" if remaining else "already_delivered",
            detection_id=detection_id,
            window_start=window_start,
            checkpoint=checkpoint,
            event_count=len(remaining),
            excluded_count=excluded_count,
            batch_count=len(batches),
            delivered_count=delivered_count,
            committed=checkpoint_committed,
            checkpoint_status=checkpoint_status,
        )

    def _receipt(
        self,
        *,
        status: str,
        detection_id: str,
        window_start: datetime,
        checkpoint: datetime,
        event_count: int,
        excluded_count: int,
        batch_count: int,
        delivered_count: int,
        committed: bool,
        checkpoint_status: str,
    ) -> ReplayReceipt:
        return ReplayReceipt(
            status=status,
            detection_id=detection_id,
            window_start=window_start,
            window_end=checkpoint,
            row_count=0,
            event_count=event_count,
            excluded_confirmed_count=excluded_count,
            batch_count=batch_count,
            delivered_count=delivered_count,
            checkpoint_committed=committed,
            checkpoint_status=checkpoint_status,
            completed_at=self._clock(),
        )

    @staticmethod
    def _required_text(value: object, label: str) -> str:
        if not isinstance(value, str) or not value:
            raise ValueError(f"dead-letter {label} is invalid")
        return value

    @classmethod
    def _dimensions(cls, value: object) -> dict[str, str]:
        if not isinstance(value, Mapping) or len(value) > 3:
            raise ValueError("dead-letter dimensions are invalid")
        dimensions: dict[str, str] = {}
        for name, item in value.items():
            dimensions[cls._required_text(name, "dimension name")] = cls._required_text(
                item, "dimension value"
            )
        return dimensions

    @classmethod
    def _event_keys(cls, value: object) -> tuple[str, ...]:
        if not isinstance(value, list):
            raise ValueError("dead-letter delivered_event_keys are invalid")
        keys = tuple(cls._required_text(item, "event key") for item in value)
        if len(set(keys)) != len(keys):
            raise ValueError("dead-letter delivered_event_keys contain duplicates")
        return keys

    @staticmethod
    def _checkpoint_time(value: object) -> datetime:
        if not isinstance(value, str) or not value:
            raise ValueError("dead-letter checkpoint is invalid")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("dead-letter checkpoint is invalid") from None
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("dead-letter checkpoint is invalid")
        return parsed.astimezone(timezone.utc)
