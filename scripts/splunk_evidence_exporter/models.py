"""Immutable value objects for Splunk evidence export.

This module is deliberately infrastructure-free.  It accepts already decoded
Python values and never consults an SDK, environment, clock, network, or disk.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Mapping


_EVIDENCE_SCHEMA_VERSION = "oci.logan.splunk.evidence.v1"
_EVIDENCE_EVENT_FACTORY = object()


def _required_text(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value.strip()


def _payload_data(payload: Mapping[str, object]) -> Mapping[str, object]:
    data = payload.get("data", payload)
    if not isinstance(data, Mapping):
        raise ValueError("alarm data must be an object")
    return data


def _first(data: Mapping[str, object], *names: str) -> object:
    for name in names:
        if name in data:
            return data[name]
    return None


def _parse_alarm_time(value: object) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        parsed = datetime.fromtimestamp(value / 1000, tz=timezone.utc)
    elif isinstance(value, str) and value.strip():
        text = value.strip()
        if text.endswith("Z"):
            text = f"{text[:-1]}+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ValueError("alarm_end must be an ISO 8601 date-time") from exc
    else:
        raise ValueError("alarm_end is required")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("alarm_end must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _parse_dimensions(value: object) -> Mapping[str, str]:
    if value is None:
        dimensions: dict[str, object] = {}
    elif isinstance(value, Mapping):
        dimensions = dict(value)
    elif isinstance(value, (list, tuple)):
        dimensions = {}
        for item in value:
            if not isinstance(item, Mapping):
                raise ValueError("each alarm dimension must be an object")
            for key, item_value in item.items():
                if key in dimensions:
                    raise ValueError(f"duplicate alarm dimension: {key}")
                dimensions[key] = item_value
    else:
        raise ValueError("alarm dimensions must be an object or list of objects")

    if len(dimensions) > 3:
        raise ValueError("alarm dimensions cannot contain more than three entries")
    normalized: dict[str, str] = {}
    for key, item_value in dimensions.items():
        normalized[_required_text(key, "dimension name")] = _required_text(
            item_value, "dimension value"
        )
    return MappingProxyType(normalized)


def _freeze(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): _freeze(item) for key, item in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


@dataclass(frozen=True)
class AlarmTrigger:
    """Sanitized Monitoring alarm data used to initiate one evidence query."""

    detection_id: str | None
    alarm_end: datetime
    namespace: str
    metric_name: str
    dimensions: Mapping[str, str]
    alarm_id: str | None = None
    query: str | None = None

    def __post_init__(self) -> None:
        if self.detection_id is not None:
            object.__setattr__(
                self, "detection_id", _required_text(self.detection_id, "detection_id")
            )
        if self.alarm_id is not None:
            object.__setattr__(self, "alarm_id", _required_text(self.alarm_id, "alarm_id"))
        if self.query is not None:
            object.__setattr__(self, "query", _required_text(self.query, "alarm query"))
        object.__setattr__(self, "alarm_end", _parse_alarm_time(self.alarm_end))
        object.__setattr__(
            self, "namespace", _required_text(self.namespace, "namespace")
        )
        object.__setattr__(
            self, "metric_name", _required_text(self.metric_name, "metric_name")
        )
        object.__setattr__(self, "dimensions", _parse_dimensions(self.dimensions))

    @classmethod
    def from_payload(cls, payload: Mapping[str, object]) -> "AlarmTrigger":
        """Decode a sanitized OCI alarm notification without any SDK dependency."""

        if not isinstance(payload, Mapping):
            raise ValueError("alarm payload must be an object")
        data = _payload_data(payload)
        metadata = _first(data, "alarmMetaData", "alarm_metadata")
        if isinstance(metadata, (list, tuple)):
            metadata = metadata[0] if len(metadata) == 1 else None
        if not isinstance(metadata, Mapping):
            metadata = {}
        # A provider RAW payload has no governed detection identity.  Never map
        # its optional custom detectionId; the service binds alarm_id to registry.
        raw_provider = bool(metadata)
        return cls(
            detection_id=None if raw_provider else _first(
                data, "detectionId", "detection_id", "ruleId", "rule_id"
            ),
            alarm_end=_first(
                data,
                "alarmEndTime",
                "alarm_end",
                "timestamp",
                "timestampEpochMillis",
            ),
            namespace=_first(metadata, "namespace", "metricNamespace", "metric_namespace")
            or _first(data, "namespace", "metricNamespace", "metric_namespace"),
            metric_name=_first(metadata, "metricName", "metric_name")
            or _first(data, "metricName", "metric_name"),
            dimensions=_first(metadata, "dimensions") or _first(data, "dimensions"),
            alarm_id=_first(metadata, "id", "alarmId", "alarm_id")
            or _first(data, "alarmId", "alarm_id"),
            query=_first(metadata, "query", "metricQuery", "metric_query")
            or _first(data, "query", "metricQuery", "metric_query"),
        )

    decode = from_payload


@dataclass(frozen=True, init=False)
class EvidenceEvent:
    """One immutable, factory-built strict evidence-schema event."""

    event_key: str
    batch_id: str
    detection: Mapping[str, object]
    evidence: Mapping[str, object]
    provenance: Mapping[str, object]
    schema_version: str = _EVIDENCE_SCHEMA_VERSION

    def __init__(
        self,
        event_key: str,
        batch_id: str,
        detection: Mapping[str, object],
        evidence: Mapping[str, object],
        provenance: Mapping[str, object],
        schema_version: str = _EVIDENCE_SCHEMA_VERSION,
        *,
        _factory_token: object = None,  # allow-sensitive-value: internal factory sentinel, never a credential
    ) -> None:
        if _factory_token is not _EVIDENCE_EVENT_FACTORY:
            raise TypeError("EvidenceEvent must be created by build_evidence_event")
        object.__setattr__(self, "event_key", _required_text(event_key, "event_key"))
        object.__setattr__(self, "batch_id", _required_text(batch_id, "batch_id"))
        if schema_version != _EVIDENCE_SCHEMA_VERSION:
            raise ValueError("unsupported evidence schema_version")
        object.__setattr__(self, "schema_version", schema_version)
        for name, value in (
            ("detection", detection),
            ("evidence", evidence),
            ("provenance", provenance),
        ):
            if not isinstance(value, Mapping):
                raise TypeError(f"{name} must be a mapping")
            object.__setattr__(self, name, _freeze(value))

    @classmethod
    def _from_validated_payload(
        cls,
        *,
        event_key: str,
        batch_id: str,
        detection: Mapping[str, object],
        evidence: Mapping[str, object],
        provenance: Mapping[str, object],
    ) -> "EvidenceEvent":
        return cls(
            event_key=event_key,
            batch_id=batch_id,
            detection=detection,
            evidence=evidence,
            provenance=provenance,
            _factory_token=_EVIDENCE_EVENT_FACTORY,  # allow-sensitive-value: internal factory sentinel, never a credential
        )

    def to_dict(self) -> dict[str, object]:
        """Return a detached JSON-serializable schema payload."""

        return {
            "schema_version": self.schema_version,
            "event_key": self.event_key,
            "batch_id": self.batch_id,
            "detection": _thaw(self.detection),
            "evidence": _thaw(self.evidence),
            "provenance": _thaw(self.provenance),
        }


@dataclass(frozen=True)
class ExportBatch:
    """A bounded immutable delivery batch with one shared batch identifier."""

    batch_id: str
    events: tuple[EvidenceEvent, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "batch_id", _required_text(self.batch_id, "batch_id"))
        events = tuple(self.events)
        if not events:
            raise ValueError("an export batch must contain at least one event")
        if not all(isinstance(event, EvidenceEvent) for event in events):
            raise TypeError("export batch events must be EvidenceEvent values")
        if any(event.batch_id != self.batch_id for event in events):
            raise ValueError("all events must share the export batch_id")
        object.__setattr__(self, "events", events)
