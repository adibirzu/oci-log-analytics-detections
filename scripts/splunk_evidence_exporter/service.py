"""Application orchestration for bounded OCI Log Analytics evidence export."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Mapping

from .envelope import batch_events, build_evidence_event, event_key
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


def _positive_int(value: object, fallback: int, label: str) -> int:
    if value is None:
        return fallback
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"registry {label} must be a positive integer")
    return value


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

    def export(self, trigger: AlarmTrigger) -> ExportReceipt:
        registry_document = self._registry.load()
        entry = self._find_entry(registry_document, trigger.detection_id)
        delivery = entry.get("delivery", {})
        if not isinstance(delivery, Mapping):
            raise ValueError("registry delivery configuration must be an object")
        lookback = _duration(delivery.get("lookback"), self._lookback, "lookback")
        overlap = _duration(delivery.get("overlap"), self._overlap, "overlap")
        max_rows = _positive_int(delivery.get("max_rows"), self._max_rows, "max_rows")
        max_batch_events = _positive_int(
            delivery.get("max_batch_events"),
            self._max_batch_events,
            "max_batch_events",
        )
        checkpoint = self._checkpoint.load_checkpoint(
            trigger.detection_id, trigger.dimensions
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
                namespace=trigger.namespace,
                query_file=entry["oci_query_file"],
                window=window,
                dimensions=trigger.dimensions,
                max_rows=max_rows,
            )
        )
        batch_id = self._batch_id(trigger)
        unique_rows: dict[str, Mapping[str, object]] = {}
        for row in rows:
            unique_rows.setdefault(event_key(trigger.detection_id, row), row)
        events = tuple(
            build_evidence_event(entry, row, window, batch_id)
            for row in unique_rows.values()
        )
        batches = batch_events(events, max_batch_events)

        if not events:
            return ExportReceipt(
                status="no_evidence",
                detection_id=trigger.detection_id,
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
            try:
                result = self._hec.deliver(batch)
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
                )
                return ExportReceipt(
                    status="delivery_failed",
                    detection_id=trigger.detection_id,
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

        self._checkpoint.save_checkpoint(
            trigger.detection_id, trigger.dimensions, window.end
        )
        return ExportReceipt(
            status="delivered",
            detection_id=trigger.detection_id,
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
    def _find_entry(document: object, detection_id: str) -> Mapping[str, object]:
        if not isinstance(document, Mapping):
            raise ValueError("registry document must be an object")
        detections = document.get("detections")
        if not isinstance(detections, list):
            raise ValueError("registry detections must be a list")
        for entry in detections:
            if isinstance(entry, Mapping) and entry.get("id") == detection_id:
                return entry
        raise ValueError("alarm detection is not present in the registry")

    @staticmethod
    def _batch_id(trigger: AlarmTrigger) -> str:
        time_id = trigger.alarm_end.strftime("%Y%m%dT%H%M%SZ").lower()
        dimension_hash = hashlib.sha256(
            json.dumps(
                dict(trigger.dimensions), sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()[:12]
        return f"{trigger.detection_id}-{time_id}-{dimension_hash}"
