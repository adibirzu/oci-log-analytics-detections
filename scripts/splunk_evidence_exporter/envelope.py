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
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
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
    rule_id: str,
    row: Mapping[str, object],
    window: QueryWindow | None = None,
    *,
    log_source: str | None = None,
    entity: str | None = None,
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
    identity: dict[str, object] = {
        "detection_id": rule_id,
        "log_source": log_source,
        "entity": entity,
        "row": normalize_for_hash(identity_row),
    }
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


def _event_time(row: Mapping[str, object], window: QueryWindow) -> str:
    """Select a stable source occurrence time, falling back to the query bound."""
    value = next(
        (row[name] for name in ("Time", "FirstSeen", "LastSeen") if row.get(name) is not None),
        window.end,
    )
    if isinstance(value, datetime):
        return _date_time(value)
    if isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("evidence event time must be an ISO 8601 date-time") from exc
        return _date_time(parsed)
    raise ValueError("evidence event time must be an ISO 8601 date-time")


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
    query_version = registry_entry.get("query_version")
    required_sources = registry_entry.get("required_sources")
    detection_config = registry_entry.get("detection")
    alarm_contract = registry_entry.get("alarm_contract")
    if not isinstance(detection_config, Mapping):
        raise ValueError("registry detection metadata is required")
    severity = detection_config.get("severity")
    for value, name in (
        (rule_id, "registry id"),
        (title, "registry title"),
        (query_file, "registry query file"),
        (query_version, "registry query version"),
        (severity, "registry severity"),
    ):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")
    if severity not in _SEVERITIES:
        raise ValueError("registry severity is not supported by the evidence schema")
    if _QUERY_FILE.fullmatch(query_file) is None:
        raise ValueError("registry query file is not a canonical evidence schema path")
    if _SHA256.fullmatch(query_version) is None:
        raise ValueError("registry query version must be a SHA-256 digest")
    if not isinstance(required_sources, list) or not all(
        isinstance(value, str) and value.strip() for value in required_sources
    ) or not required_sources:
        raise ValueError("registry required_sources must be a non-empty list")
    if not isinstance(alarm_contract, Mapping):
        raise ValueError("registry alarm contract is required")
    metric_namespace = alarm_contract.get("metric_namespace")
    metric_dimensions = alarm_contract.get("metric_dimensions")
    if not isinstance(metric_namespace, str) or not metric_namespace.strip():
        raise ValueError("registry metric namespace must be a non-empty string")
    if not isinstance(metric_dimensions, list) or not all(
        isinstance(value, str) and value.strip() for value in metric_dimensions
    ) or len(metric_dimensions) > 3:
        raise ValueError("registry metric dimensions must be a list of at most three fields")

    allowed = registry_entry.get("required_fields")
    if not isinstance(allowed, list) or not all(isinstance(value, str) for value in allowed):
        raise ValueError("registry required_fields must be an explicit export allowlist")
    # Time and common source/entity columns support repeatable evidence identity;
    # every other field must be governed by the registry.
    identity_fields = {"Time", "FirstSeen", "LastSeen", "Log Source", "Entity"}
    allowed_names = set(allowed) | identity_fields
    sanitized_row = {name: row[name] for name in row if name in allowed_names}
    dimensions = {
        name: _field_value(sanitized_row[name])
        for name in metric_dimensions
        if name in sanitized_row
    }
    log_source = row.get("Log Source") or required_sources[0]
    if not isinstance(log_source, str) or not log_source.strip():
        raise ValueError("evidence log source must be a non-empty string")
    entity_value = row.get("Entity")
    entity = str(entity_value) if entity_value is not None else None
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
        event_key=event_key(
            rule_id,
            sanitized_row,
            window,
            log_source=log_source,
            entity=entity,
        ),
        batch_id=batch_id,
        detection={
            "id": rule_id,
            "title": title,
            "severity": severity,
            "metric_namespace": metric_namespace,
            "dimensions": dimensions,
        },
        evidence={
            "include_original_content": False,
            "event_time": _event_time(row, window),
            "log_source": log_source,
            "entity": entity,
            "fields": fields,
        },
        provenance={
            "product": "OCI Log Analytics",
            "analytics_plane": "oci_log_analytics",
            "query_file": query_file,
            "query_version": query_version,
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
        "id", "title", "severity", "metric_namespace", "dimensions",
    }:
        raise ValueError("stored evidence detection metadata is invalid")
    if (
        any(
            not isinstance(detection.get(name), str) or not detection[name]
            for name in ("id", "title", "severity", "metric_namespace")
        )
        or detection["severity"] not in _SEVERITIES
    ):
        raise ValueError("stored evidence detection metadata is invalid")
    dimensions = detection.get("dimensions")
    if not isinstance(dimensions, Mapping) or len(dimensions) > 3 or any(
        not isinstance(name, str)
        or not name
        or not (value is None or isinstance(value, (str, int, float, bool)))
        or isinstance(value, float) and not math.isfinite(value)
        for name, value in dimensions.items()
    ):
        raise ValueError("stored evidence detection dimensions are invalid")
    if not isinstance(evidence, Mapping) or set(evidence) != {
        "include_original_content", "event_time", "log_source", "entity", "fields",
    }:
        raise ValueError("stored evidence body is invalid")
    if evidence.get("include_original_content") is not False:
        raise ValueError("stored replay evidence must exclude original content")
    if not isinstance(evidence.get("log_source"), str) or not evidence["log_source"]:
        raise ValueError("stored evidence log source is invalid")
    if evidence.get("entity") is not None and not isinstance(evidence["entity"], str):
        raise ValueError("stored evidence entity is invalid")
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
    expected_provenance = {
        "product", "analytics_plane", "query_file", "query_version", "window_start", "window_end"
    }
    if not isinstance(provenance, Mapping) or set(provenance) != expected_provenance:
        raise ValueError("stored evidence provenance is invalid")
    if provenance.get("product") != "OCI Log Analytics" or provenance.get("analytics_plane") != "oci_log_analytics" or not isinstance(
        provenance.get("query_file"), str
    ):
        raise ValueError("stored evidence provenance is invalid")
    if _QUERY_FILE.fullmatch(provenance["query_file"]) is None:
        raise ValueError("stored evidence query file is invalid")
    if not isinstance(provenance.get("query_version"), str) or _SHA256.fullmatch(provenance["query_version"]) is None:
        raise ValueError("stored evidence query version is invalid")
    parsed_window = []
    for section, name in ((evidence, "event_time"), (provenance, "window_start"), (provenance, "window_end")):
        value = section.get(name)
        if not isinstance(value, str) or not value:
            raise ValueError("stored evidence window is invalid")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("stored evidence window is invalid") from None
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("stored evidence window is invalid")
        if name != "event_time":
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
