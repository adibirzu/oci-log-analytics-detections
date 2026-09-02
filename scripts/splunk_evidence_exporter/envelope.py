"""Deterministic evidence identifiers and schema-shaped envelopes."""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Collection, Iterable, Mapping

from .models import EvidenceEvent, ExportBatch
from .window import QueryWindow


_DEFAULT_SENSITIVE_FRAGMENTS = (
    "token",
    "password",
    "authorization",
    "secret",
    "ocid",
)
_ORIGINAL_CONTENT_FIELD = "original log content"
_REDACTED = "[REDACTED]"
_QUERY_FILE = re.compile(
    r"queries/(?:apps/|hunting/|sentinel/)?[a-z0-9][a-z0-9_-]*\.json"
)
_SEVERITIES = frozenset({"low", "medium", "high", "critical"})


def _normalize_datetime(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetimes used in event keys must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_for_hash(value: object) -> object:
    """Normalize JSON-like Log Analytics rows for stable hashing."""

    if isinstance(value, Mapping):
        normalized: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("event row keys must be strings")
            normalized[key] = normalize_for_hash(item)
        return normalized
    if isinstance(value, (list, tuple)):
        return [normalize_for_hash(item) for item in value]
    if isinstance(value, datetime):
        return _normalize_datetime(value)
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("event rows cannot contain non-finite numbers")
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"unsupported event row value: {type(value).__name__}")


def event_key(rule_id: str, row: Mapping[str, object]) -> str:
    """Return the idempotency key for a rule and complete evidence row."""

    if not isinstance(rule_id, str) or not rule_id.strip():
        raise ValueError("rule_id must be a non-empty string")
    if not isinstance(row, Mapping):
        raise TypeError("row must be a mapping")
    canonical = json.dumps(
        normalize_for_hash(row),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(f"{rule_id}\n{canonical}".encode("utf-8")).hexdigest()


def _field_identifier(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.casefold())


def _is_sensitive(name: str, configured: Collection[str]) -> bool:
    identifier = _field_identifier(name)
    configured_identifiers = {_field_identifier(field) for field in configured}
    return identifier in configured_identifiers or any(
        fragment in identifier for fragment in _DEFAULT_SENSITIVE_FRAGMENTS
    )


def _field_value(value: object) -> str | int | float | bool | None:
    normalized = normalize_for_hash(value)
    if normalized is None or isinstance(normalized, (str, int, float, bool)):
        return normalized
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _redact_nested(value: object, configured: Collection[str]) -> object:
    if isinstance(value, Mapping):
        redacted: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("nested evidence field names must be strings")
            redacted[key] = (
                _REDACTED
                if _is_sensitive(key, configured)
                else _redact_nested(item, configured)
            )
        return redacted
    if isinstance(value, (list, tuple)):
        return [_redact_nested(item, configured) for item in value]
    return value


def _date_time(value: datetime) -> str:
    return _normalize_datetime(value)


def build_evidence_event(
    registry_entry: Mapping[str, object],
    row: Mapping[str, object],
    window: QueryWindow,
    batch_id: str,
    *,
    sensitive_fields: Collection[str] = (),
) -> EvidenceEvent:
    """Build the default, original-content-free evidence envelope."""

    if not isinstance(registry_entry, Mapping):
        raise TypeError("registry_entry must be a mapping")
    if not isinstance(row, Mapping):
        raise TypeError("row must be a mapping")
    if not isinstance(window, QueryWindow):
        raise TypeError("window must be a QueryWindow")

    rule_id = registry_entry.get("id")
    title = registry_entry.get("title")
    query_file = registry_entry.get("oci_query_file")
    detection_config = registry_entry.get("detection")
    if not isinstance(detection_config, Mapping):
        raise ValueError("registry detection metadata is required")
    severity = detection_config.get("severity")
    for value, name in (
        (rule_id, "registry id"),
        (title, "registry title"),
        (query_file, "registry query file"),
        (severity, "registry severity"),
    ):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")
    if severity not in _SEVERITIES:
        raise ValueError("registry severity is not supported by the evidence schema")
    if _QUERY_FILE.fullmatch(query_file) is None:
        raise ValueError("registry query file is not a canonical evidence schema path")

    fields: list[dict[str, object]] = []
    for name in sorted(row):
        if not isinstance(name, str) or not name:
            raise ValueError("evidence field names must be non-empty strings")
        if name.casefold() == _ORIGINAL_CONTENT_FIELD:
            continue
        fields.append(
            {
                "name": name,
                "value": (
                    _REDACTED
                    if _is_sensitive(name, sensitive_fields)
                    else _field_value(_redact_nested(row[name], sensitive_fields))
                ),
            }
        )

    return EvidenceEvent._from_validated_payload(
        event_key=event_key(rule_id, row),
        batch_id=batch_id,
        detection={"id": rule_id, "title": title, "severity": severity},
        evidence={"include_original_content": False, "fields": fields},
        provenance={
            "product": "OCI Log Analytics",
            "query_file": query_file,
            "window_start": _date_time(window.start),
            "window_end": _date_time(window.end),
        },
    )


def batch_events(
    events: Iterable[EvidenceEvent],
    max_batch_events: int,
) -> tuple[ExportBatch, ...]:
    """Partition one logical batch into delivery-size-bounded chunks."""

    if isinstance(max_batch_events, bool) or not isinstance(max_batch_events, int):
        raise TypeError("max_batch_events must be an integer")
    if max_batch_events < 1:
        raise ValueError("max_batch_events must be at least one")
    collected = tuple(events)
    if not collected:
        return ()
    if not all(isinstance(event, EvidenceEvent) for event in collected):
        raise TypeError("events must contain only EvidenceEvent values")
    batch_id = collected[0].batch_id
    if any(event.batch_id != batch_id for event in collected):
        raise ValueError("events with different batch identifiers cannot be combined")
    return tuple(
        ExportBatch(
            batch_id=batch_id, events=collected[offset : offset + max_batch_events]
        )
        for offset in range(0, len(collected), max_batch_events)
    )
