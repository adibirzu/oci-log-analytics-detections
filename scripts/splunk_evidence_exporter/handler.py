"""OCI Functions entry point for one Notifications-triggered evidence export."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Mapping

from .adapters import (
    OciResourcePrincipalAdapterFactory,
    OciStreamingEvidenceAdapter,
    SplunkHecAdapter,
)
from .models import AlarmTrigger
from .service import EvidenceExportService, ExportReceipt


LOGGER = logging.getLogger(__name__)
_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_MAX_NOTIFICATION_BYTES = 256 * 1024


class _JsonRegistry:
    def __init__(self, path: Path) -> None:
        self._path = path

    def load(self) -> Mapping[str, object]:
        try:
            document = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            raise RuntimeError("detection registry is unavailable") from None
        if not isinstance(document, Mapping):
            raise RuntimeError("detection registry is invalid")
        return document


def _load_query(relative_path: str) -> Mapping[str, object]:
    if not isinstance(relative_path, str):
        raise ValueError("query path is invalid")
    candidate = (_REPOSITORY_ROOT / relative_path).resolve()
    query_root = (_REPOSITORY_ROOT / "queries").resolve()
    if query_root not in candidate.parents or candidate.suffix != ".json":
        raise ValueError("query path is outside the canonical query tree")
    try:
        document = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise RuntimeError("canonical query is unavailable") from None
    if not isinstance(document, Mapping):
        raise RuntimeError("canonical query is invalid")
    return document


def _required_environment(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not value.strip():
        raise RuntimeError(f"required exporter configuration is missing: {name}")
    return value.strip()


def _environment_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError:
        raise RuntimeError(f"exporter configuration is invalid: {name}") from None
    if not minimum <= value <= maximum:
        raise RuntimeError(f"exporter configuration is out of bounds: {name}")
    return value


def build_service() -> EvidenceExportService:
    """Build production adapters with a single OCI Function resource principal."""

    namespace = _required_environment("OBJECT_STORAGE_NAMESPACE")
    state_bucket = _required_environment("SPLUNK_EVIDENCE_STATE_BUCKET")
    dlq_bucket = _required_environment("SPLUNK_EVIDENCE_DLQ_BUCKET")
    max_rows = _environment_int(
        "SPLUNK_EVIDENCE_MAX_ROWS", 1000, minimum=1, maximum=10000
    )
    max_batch_events = _environment_int(
        "SPLUNK_HEC_MAX_BATCH_EVENTS", 100, minimum=1, maximum=1000
    )
    delivery_target = os.environ.get("SPLUNK_EVIDENCE_TARGET", "hec").strip().casefold()
    if delivery_target not in {"hec", "streaming"}:
        raise RuntimeError("exporter evidence target is invalid")
    oci_adapters = OciResourcePrincipalAdapterFactory.create(
        compartment_id=_required_environment("OCI_LOG_ANALYTICS_COMPARTMENT_ID"),
        compartment_id_in_subtree=os.environ.get(
            "OCI_LOG_ANALYTICS_COMPARTMENT_IN_SUBTREE", "true"
        ).casefold()
        == "true",
        max_rows_ceiling=max_rows,
        secret_id=(
            _required_environment("SPLUNK_HEC_SECRET_ID")
            if delivery_target == "hec"
            else None
        ),
        namespace=namespace,
        state_bucket=state_bucket,
        dlq_bucket=dlq_bucket,
        telemetry_namespace=_required_environment("SPLUNK_EXPORTER_TELEMETRY_NAMESPACE"),
        query_loader=_load_query,
        clock=lambda: datetime.now(timezone.utc),
    )
    try:
        alarm_bindings = json.loads(os.environ.get("SPLUNK_ALARM_BINDINGS", "{}"))
    except json.JSONDecodeError:
        raise RuntimeError("exporter alarm bindings are invalid") from None
    if not isinstance(alarm_bindings, Mapping) or not alarm_bindings or not all(isinstance(key, str) and key.strip() and isinstance(value, str) and value.strip() for key, value in alarm_bindings.items()):
        raise RuntimeError("exporter alarm bindings are invalid")
    if delivery_target == "hec":
        if oci_adapters.vault is None:
            raise RuntimeError("HEC credential adapter is unavailable")
        delivery = SplunkHecAdapter(
            hec_url=_required_environment("SPLUNK_HEC_URL"),
            token_provider=oci_adapters.vault,  # allow-sensitive-value
            index=_required_environment("SPLUNK_HEC_INDEX"),
            sourcetype=_required_environment("SPLUNK_HEC_SOURCETYPE"),
            timeout_seconds=_environment_int(
                "SPLUNK_HEC_TIMEOUT_SECONDS", 10, minimum=1, maximum=60
            ),
            acknowledgement_mode=os.environ.get(
                "SPLUNK_HEC_ACKNOWLEDGEMENT_MODE", "response"
            ),
            allow_insecure_local_test=os.environ.get(
                "SPLUNK_HEC_LOCAL_TEST_MODE", "false"
            ).casefold()
            == "true",
        )
    else:
        delivery = OciStreamingEvidenceAdapter.from_resource_principal(
            stream_id=_required_environment("SPLUNK_EVIDENCE_STREAM_ID"),
            messages_endpoint=_required_environment(
                "SPLUNK_EVIDENCE_STREAM_MESSAGES_ENDPOINT"
            ),
        )
    return EvidenceExportService(
        registry=_JsonRegistry(
            Path(
                os.environ.get(
                    "SPLUNK_DETECTION_REGISTRY",
                    str(_REPOSITORY_ROOT / "queries/splunk_detection_registry.json"),
                )
            )
        ),
        query=oci_adapters.query,
        checkpoint=oci_adapters.checkpoint,
        hec=delivery,
        dead_letter=oci_adapters.dead_letter,
        clock=lambda: datetime.now(timezone.utc),
        lookback=timedelta(
            seconds=_environment_int(
                "SPLUNK_EVIDENCE_LOOKBACK_SECONDS", 900, minimum=1, maximum=86400
            )
        ),
        overlap=timedelta(
            seconds=_environment_int(
                "SPLUNK_EVIDENCE_OVERLAP_SECONDS", 120, minimum=0, maximum=3600
            )
        ),
        maximum_window=timedelta(
            seconds=_environment_int(
                "SPLUNK_EVIDENCE_MAX_WINDOW_SECONDS",
                7200,
                minimum=1,
                maximum=86400,
            )
        ),
        max_rows=max_rows,
        max_batch_events=max_batch_events,
        max_attempts=_environment_int(
            "SPLUNK_EVIDENCE_MAX_ATTEMPTS", 4, minimum=1, maximum=10
        ),
        alarm_bindings=alarm_bindings,
        log_analytics_namespace=_required_environment("OCI_LOG_ANALYTICS_NAMESPACE"),
        delivery_ledger=oci_adapters.ledger,
        metrics=oci_adapters.metrics,
        delivery_target=delivery_target,
    )


def _decode_notification(data: object, *, allow_legacy_synthetic: bool = True) -> AlarmTrigger:
    if data is None:
        raise ValueError("one Notifications message is required")
    raw = data.read(_MAX_NOTIFICATION_BYTES + 1) if hasattr(data, "read") else data
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > _MAX_NOTIFICATION_BYTES:
        raise ValueError("Notifications message is invalid or too large")
    try:
        notification = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("Notifications message is not valid JSON") from None
    if not isinstance(notification, Mapping):
        raise ValueError("Notifications message must be one object")
    data_section = notification.get("data")
    body: object = None
    if isinstance(data_section, Mapping):
        details = data_section.get("messageDetails")
        if isinstance(details, Mapping):
            body = details.get("body")
        elif "message" in data_section:
            body = data_section.get("message")
    if body is None:
        body = notification.get("message", notification)
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            raise ValueError("Notifications alarm body is not valid JSON") from None
    if not isinstance(body, Mapping):
        raise ValueError("exactly one Notifications alarm object is required")
    trigger = AlarmTrigger.from_payload(body)
    if not allow_legacy_synthetic and trigger.alarm_id is None:
        raise ValueError("provider RAW alarm_id is required")
    return trigger


def handler(ctx: object, data: object = None) -> dict[str, object]:
    """Decode one alarm notification and return a sanitized receipt summary."""

    try:
        trigger = _decode_notification(data, allow_legacy_synthetic=False)
        receipt = build_service().export(trigger)
    except Exception as exc:
        LOGGER.error(
            "splunk_evidence_export_failed %s",
            json.dumps({"error_type": type(exc).__name__}, sort_keys=True),
        )
        raise RuntimeError("evidence export failed") from None
    summary = receipt.to_dict()
    LOGGER.info(
        "splunk_evidence_export_complete %s",
        json.dumps(
            {
                key: summary[key]
                for key in (
                    "status",
                    "detection_id",
                    "event_count",
                    "batch_count",
                    "delivered_count",
                    "checkpoint_committed",
                )
            },
            sort_keys=True,
        ),
    )
    return summary
