"""Object Storage checkpoint, delivery ledger, and dead-letter adapters."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Callable, Mapping, Sequence
from urllib import error as urllib_error
from urllib import request as urllib_request
from urllib.parse import urlsplit, urlunsplit

from .models import ExportBatch
from .adapter_utils import _dimension_hash, _identifier_hash, _required_text, _safe_identifier

class ObjectStorageStateAdapter:
    """Store per-rule checkpoints under deterministic, non-sensitive names."""

    def __init__(self, *, client: object, namespace: str, bucket: str) -> None:
        self._client = client
        self._namespace = _required_text(namespace, "Object Storage namespace")
        self._bucket = _required_text(bucket, "Object Storage bucket")
        self._etags: dict[str, str | None] = {}

    def _object_name(self, detection_id: str, dimensions: Mapping[str, str]) -> str:
        return (
            f"state-{_safe_identifier(detection_id, maximum=48)}-"
            f"{_identifier_hash(detection_id)}-{_dimension_hash(dimensions)}.json"
        )

    def load_checkpoint(
        self, detection_id: str, dimensions: Mapping[str, str]
    ) -> datetime | None:
        object_name = self._object_name(detection_id, dimensions)
        try:
            response = self._client.get_object(
                namespace_name=self._namespace,
                bucket_name=self._bucket,
                object_name=object_name,
            )
        except Exception as exc:
            if getattr(exc, "status", None) == 404:
                self._etags[object_name] = None
                return None
            raise RuntimeError("checkpoint state is unavailable") from None
        content = getattr(response.data, "content", None)
        if hasattr(content, "read"):
            content = content.read()
        try:
            document = json.loads(content)
            checkpoint_text = document["checkpoint"]
            checkpoint = datetime.fromisoformat(checkpoint_text.replace("Z", "+00:00"))
        except (AttributeError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            raise RuntimeError("checkpoint state is invalid") from None
        if checkpoint.tzinfo is None or checkpoint.utcoffset() is None:
            raise RuntimeError("checkpoint state is invalid")
        self._etags[object_name] = getattr(response, "etag", None) or getattr(getattr(response, "headers", {}), "get", lambda _key: None)("etag")
        return checkpoint.astimezone(timezone.utc)

    def save_checkpoint(
        self,
        detection_id: str,
        dimensions: Mapping[str, str],
        checkpoint: datetime,
    ) -> None:
        if checkpoint.tzinfo is None or checkpoint.utcoffset() is None:
            raise ValueError("checkpoint must be timezone-aware")
        body = json.dumps(
            {
                "schema_version": "oci.logan.splunk.checkpoint.v1",
                "checkpoint": checkpoint.astimezone(timezone.utc)
                .isoformat()
                .replace("+00:00", "Z"),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        object_name = self._object_name(detection_id, dimensions)
        # Retry a bounded read/compare/CAS loop.  This prevents a slower alarm
        # invocation from replacing a later checkpoint.
        for _ in range(3):
            known = self._etags.get(object_name, "__unloaded__")
            if known == "__unloaded__":
                # The production SDK always implements get_object.  The
                # fallback keeps the pure local adapter seam usable while
                # still issuing create-only conditional writes.
                current = self.load_checkpoint(detection_id, dimensions) if hasattr(self._client, "get_object") else None
                if current is not None and current >= checkpoint:
                    return
                known = self._etags.get(object_name)
            request = {
                "namespace_name": self._namespace,
                "bucket_name": self._bucket,
                "object_name": object_name,
                "put_object_body": body,
                "content_type": "application/json",
            }
            if known is None:
                request["if_none_match"] = "*"
            else:
                request["if_match"] = known
            try:
                response = self._client.put_object(**request)
                self._etags[object_name] = getattr(response, "etag", None) or getattr(getattr(response, "headers", {}), "get", lambda _key: None)("etag")
                return
            except Exception as exc:
                if getattr(exc, "status", None) != 412:
                    raise RuntimeError("checkpoint state could not be committed") from None
                # A concurrent writer won. Reload its watermark and only retry
                # if this invocation can move it forward.
                current = self.load_checkpoint(detection_id, dimensions)
                if current is not None and current >= checkpoint:
                    return
        raise RuntimeError("checkpoint state could not be committed")

    @classmethod
    def from_resource_principal(
        cls, *, namespace: str, bucket: str
    ) -> "ObjectStorageStateAdapter":
        import oci

        signer = oci.auth.signers.get_resource_principals_signer()
        client = oci.object_storage.ObjectStorageClient(config={}, signer=signer)
        return cls(client=client, namespace=namespace, bucket=bucket)


class ObjectStorageDeliveryLedgerAdapter:
    """Object Storage CAS ledger for cross-instance at-least-once delivery.

    Each opaque event-key hash has a tiny state object.  A reservation may be
    taken over only after its lease expires; a delivered record is permanent.
    Conditional create/update makes this safe across cold starts.
    """

    def __init__(self, *, client: object, namespace: str, bucket: str) -> None:
        self._client = client
        self._namespace = _required_text(namespace, "Object Storage namespace")
        self._bucket = _required_text(bucket, "Object Storage bucket")

    @staticmethod
    def _name(event_key: str) -> str:
        return "delivery-ledger/" + hashlib.sha256(event_key.encode("utf-8")).hexdigest() + ".json"

    def _get(self, name: str) -> tuple[dict[str, object] | None, str | None]:
        try:
            response = self._client.get_object(namespace_name=self._namespace, bucket_name=self._bucket, object_name=name)
        except Exception as exc:
            if getattr(exc, "status", None) == 404:
                return None, None
            raise RuntimeError("delivery ledger is unavailable") from None
        content = response.data.content.read() if hasattr(response.data.content, "read") else response.data.content
        try:
            document = json.loads(content)
        except (TypeError, json.JSONDecodeError):
            raise RuntimeError("delivery ledger is invalid") from None
        if not isinstance(document, dict):
            raise RuntimeError("delivery ledger is invalid")
        return document, getattr(response, "etag", None) or getattr(getattr(response, "headers", {}), "get", lambda _key: None)("etag")

    def _put(self, name: str, document: Mapping[str, object], etag: str | None) -> bool:
        request = {"namespace_name": self._namespace, "bucket_name": self._bucket, "object_name": name,
                   "put_object_body": json.dumps(document, sort_keys=True, separators=(",", ":")), "content_type": "application/json"}
        request["if_none_match" if etag is None else "if_match"] = "*" if etag is None else etag
        try:
            self._client.put_object(**request)
            return True
        except Exception as exc:
            if getattr(exc, "status", None) == 412:
                return False
            raise RuntimeError("delivery ledger could not be committed") from None

    def reserve(self, event_key: str, *, now: datetime, lease: timedelta) -> bool:
        if now.tzinfo is None or now.utcoffset() is None or lease.total_seconds() <= 0:
            raise ValueError("delivery reservation is invalid")
        name = self._name(_required_text(event_key, "event key"))
        for _ in range(4):
            current, etag = self._get(name)
            if current and current.get("state") == "delivered":
                return False
            if current and current.get("state") == "reserved":
                try:
                    expires = datetime.fromisoformat(str(current["lease_expires_at"]).replace("Z", "+00:00"))
                except (KeyError, ValueError):
                    raise RuntimeError("delivery ledger is invalid") from None
                if expires > now:
                    return False
            document = {"schema_version": "oci.logan.splunk.delivery-ledger.v1", "state": "reserved",
                        "lease_expires_at": (now + lease).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")}
            if self._put(name, document, etag):
                return True
        return False

    def mark_delivered(self, event_key: str, *, now: datetime) -> None:
        name = self._name(_required_text(event_key, "event key"))
        for _ in range(4):
            current, etag = self._get(name)
            if current is None:
                raise RuntimeError("delivery reservation is missing")
            if current.get("state") == "delivered":
                return
            if self._put(name, {"schema_version": "oci.logan.splunk.delivery-ledger.v1", "state": "delivered",
                                "delivered_at": now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")}, etag):
                return
        raise RuntimeError("delivery ledger could not be committed")

    def release(self, event_key: str) -> None:
        # A failed delivery remains reserved until lease expiry.  This avoids a
        # concurrent redelivery race; a crash is recoverable by lease takeover.
        return None


class ObjectStorageDeadLetterAdapter:
    """Persist one replay-safe record for a failed logical export."""

    def __init__(
        self,
        *,
        client: object,
        namespace: str,
        bucket: str,
        clock: Callable[[], datetime],
    ) -> None:
        self._client = client
        self._namespace = _required_text(namespace, "Object Storage namespace")
        self._bucket = _required_text(bucket, "Object Storage bucket")
        self._clock = clock

    def quarantine(
        self,
        batch: ExportBatch,
        reason: str,
        *,
        delivered_event_keys: Sequence[str] = (),
        detection_id: str | None = None,
        dimensions: Mapping[str, str] | None = None,
        checkpoint: datetime | None = None,
        delivery_target: str | None = None,
    ) -> None:
        if reason not in ("retryable", "quarantine"):
            raise ValueError("unsupported dead-letter reason")
        created_at = self._clock()
        if created_at.tzinfo is None or created_at.utcoffset() is None:
            raise ValueError("dead-letter clock must return a timezone-aware datetime")
        created_text = (
            created_at.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ").lower()
        )
        remaining = [event.to_dict() for event in batch.events]
        digest = hashlib.sha256(
            "\n".join(event.event_key for event in batch.events).encode("utf-8")
        ).hexdigest()[:16]
        object_name = (
            f"dlq-{_safe_identifier(batch.batch_id)}-{created_text}-{digest}.json"
        )
        record: dict[str, object] = {
            "schema_version": "oci.logan.splunk.dead-letter.v1",
            "reason": reason,
            "created_at": created_at.astimezone(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "batch_id": batch.batch_id,
            "delivered_event_keys": list(delivered_event_keys),
            "remaining_events": remaining,
        }
        context = (detection_id, dimensions, checkpoint, delivery_target)
        if any(item is not None for item in context):
            if (
                detection_id is None
                or dimensions is None
                or checkpoint is None
                or delivery_target not in {"hec", "streaming"}
            ):
                raise ValueError("complete replay context is required")
            if checkpoint.tzinfo is None or checkpoint.utcoffset() is None:
                raise ValueError("dead-letter checkpoint must be timezone-aware")
            record.update(
                {
                    "detection_id": _required_text(detection_id, "detection id"),
                    "dimensions": dict(dimensions),
                    "checkpoint": checkpoint.astimezone(timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "delivery_target": delivery_target,
                }
            )
        body = json.dumps(
            record,
            sort_keys=True,
            separators=(",", ":"),
        )
        try:
            self._client.put_object(
                namespace_name=self._namespace,
                bucket_name=self._bucket,
                object_name=object_name,
                put_object_body=body,
                content_type="application/json",
            )
        except Exception:
            raise RuntimeError("dead-letter record could not be written") from None

    @classmethod
    def from_resource_principal(
        cls,
        *,
        namespace: str,
        bucket: str,
        clock: Callable[[], datetime],
    ) -> "ObjectStorageDeadLetterAdapter":
        import oci

        signer = oci.auth.signers.get_resource_principals_signer()
        client = oci.object_storage.ObjectStorageClient(config={}, signer=signer)
        return cls(client=client, namespace=namespace, bucket=bucket, clock=clock)
