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
_EVENT_KEYS = frozenset(
    {"schema_version", "event_key", "batch_id", "detection", "evidence", "provenance"}
)


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


def event_key(
    rule_id: str, row: Mapping[str, object], window: QueryWindow | None = None
) -> str:
    """Return a deterministic key over governed evidence identity only.

    A query can add columns over time.  The caller supplies an already
    allowlisted row; identity uses event time, never a moving query window.
    """

    if not isinstance(rule_id, str) or not rule_id.strip():
        raise ValueError("rule_id must be a non-empty string")
    if not isinstance(row, Mapping):
        raise TypeError("row must be a mapping")
    if window is not None and not isinstance(window, QueryWindow):
        raise TypeError("window must be a QueryWindow")
    # Query execution bounds are invocation metadata, not source occurrence
    # identity.  Exclude them so an overlapping/replayed window cannot create
    # a new event key.  Source event time and aggregation fields remain part of
    # the key, allowing distinct occurrences with equal aggregates to deliver.
    moving_window_fields = {
        "querywindowstart", "querywindowend", "windowstart", "windowend",
        "querystart", "queryend",
    }
    identity_row = {
        name: value
        for name, value in row.items()
        if _field_identifier(name) not in moving_window_fields
    }
    identity: dict[str, object] = {"detection_id": rule_id, "row": normalize_for_hash(identity_row)}
    canonical = json.dumps(
        identity,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


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

    allowed = registry_entry.get("required_fields")
    if not isinstance(allowed, list) or not all(isinstance(value, str) for value in allowed):
        raise ValueError("registry required_fields must be an explicit export allowlist")
    # Time and common source/entity columns support repeatable evidence identity;
    # every other field must be governed by the registry.
    identity_fields = {"Time", "FirstSeen", "LastSeen", "Log Source", "Entity"}
    allowed_names = set(allowed) | identity_fields
    sanitized_row = {name: row[name] for name in row if name in allowed_names}
    fields: list[dict[str, object]] = []
    for name in sorted(sanitized_row):
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
                    else _field_value(_redact_nested(sanitized_row[name], sensitive_fields))
                ),
            }
        )

    return EvidenceEvent._from_validated_payload(
        event_key=event_key(rule_id, sanitized_row, window),
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


def restore_evidence_event(payload: Mapping[str, object]) -> EvidenceEvent:
    """Restore one strict normalized event from a trusted-store JSON record."""

    if not isinstance(payload, Mapping) or set(payload) != _EVENT_KEYS:
        raise ValueError("stored evidence event shape is invalid")
    if payload.get("schema_version") != "oci.logan.splunk.evidence.v1":
        raise ValueError("stored evidence schema version is unsupported")
    event_key_value = payload.get("event_key")
    batch_id = payload.get("batch_id")
    detection = payload.get("detection")
    evidence = payload.get("evidence")
    provenance = payload.get("provenance")
    if not isinstance(event_key_value, str) or not event_key_value:
        raise ValueError("stored evidence event key is invalid")
    if not isinstance(batch_id, str) or not batch_id:
        raise ValueError("stored evidence batch id is invalid")
    if not isinstance(detection, Mapping) or set(detection) != {
        "id",
        "title",
        "severity",
    }:
        raise ValueError("stored evidence detection metadata is invalid")
    if (
        any(
            not isinstance(detection.get(name), str) or not detection[name]
            for name in ("id", "title", "severity")
        )
        or detection["severity"] not in _SEVERITIES
    ):
        raise ValueError("stored evidence detection metadata is invalid")
    if not isinstance(evidence, Mapping) or set(evidence) != {
        "include_original_content",
        "fields",
    }:
        raise ValueError("stored evidence body is invalid")
    if evidence.get("include_original_content") is not False:
        raise ValueError("stored replay evidence must exclude original content")
    fields = evidence.get("fields")
    if not isinstance(fields, (list, tuple)):
        raise ValueError("stored evidence fields are invalid")
    for field in fields:
        if not isinstance(field, Mapping) or set(field) != {"name", "value"}:
            raise ValueError("stored evidence field is invalid")
        name = field.get("name")
        value = field.get("value")
        if (
            not isinstance(name, str)
            or not name
            or name.casefold() == _ORIGINAL_CONTENT_FIELD
            or not (value is None or isinstance(value, (str, int, float, bool)))
            or isinstance(value, float)
            and not math.isfinite(value)
        ):
            raise ValueError("stored evidence field is invalid")
    expected_provenance = {"product", "query_file", "window_start", "window_end"}
    if not isinstance(provenance, Mapping) or set(provenance) != expected_provenance:
        raise ValueError("stored evidence provenance is invalid")
    if provenance.get("product") != "OCI Log Analytics" or not isinstance(
        provenance.get("query_file"), str
    ):
        raise ValueError("stored evidence provenance is invalid")
    if _QUERY_FILE.fullmatch(provenance["query_file"]) is None:
        raise ValueError("stored evidence query file is invalid")
    parsed_window = []
    for name in ("window_start", "window_end"):
        value = provenance.get(name)
        if not isinstance(value, str) or not value:
            raise ValueError("stored evidence window is invalid")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("stored evidence window is invalid") from None
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("stored evidence window is invalid")
        parsed_window.append(parsed.astimezone(timezone.utc))
    if parsed_window[0] > parsed_window[1]:
        raise ValueError("stored evidence window is invalid")
    return EvidenceEvent._from_validated_payload(
        event_key=event_key_value,
        batch_id=batch_id,
        detection=detection,
        evidence=evidence,
        provenance=provenance,
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
