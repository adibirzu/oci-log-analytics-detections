"""OCI SDK, Object Storage, Vault, and Splunk HEC infrastructure adapters.

The OCI SDK is imported only by the explicit resource-principal factories so
the module remains importable and testable without cloud dependencies.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Mapping, Sequence
from urllib import error as urllib_error
from urllib import request as urllib_request
from urllib.parse import urlsplit, urlunsplit

from .models import ExportBatch
from .window import QueryWindow


class OciLogAnalyticsQueryAdapter:
    """Execute a canonical query using an injected OCI Log Analytics client."""

    def __init__(
        self,
        *,
        client: object,
        compartment_id: str,
        compartment_id_in_subtree: bool,
        max_rows_ceiling: int,
        query_loader: Callable[[str], Mapping[str, object]],
        query_details_factory: Callable[..., object],
        time_range_factory: Callable[..., object],
    ) -> None:
        if not isinstance(compartment_id, str) or not compartment_id.strip():
            raise ValueError("Log Analytics compartment is required")
        self._client = client
        self._compartment_id = compartment_id
        self._compartment_id_in_subtree = bool(compartment_id_in_subtree)
        if (
            isinstance(max_rows_ceiling, bool)
            or not isinstance(max_rows_ceiling, int)
            or max_rows_ceiling < 1
        ):
            raise ValueError("Log Analytics row ceiling must be a positive integer")
        self._max_rows_ceiling = max_rows_ceiling
        self._query_loader = query_loader
        self._query_details_factory = query_details_factory
        self._time_range_factory = time_range_factory

    def query_evidence(
        self,
        *,
        namespace: str,
        query_file: str,
        window: QueryWindow,
        dimensions: Mapping[str, str],
        max_rows: int,
    ) -> tuple[Mapping[str, object], ...]:
        if isinstance(max_rows, bool) or not isinstance(max_rows, int) or max_rows < 1:
            raise ValueError("max_rows must be a positive integer")
        if max_rows > self._max_rows_ceiling:
            raise ValueError("max_rows exceeds the runtime maximum")
        query_document = self._query_loader(query_file)
        query_string = query_document.get("query")
        if not isinstance(query_string, str) or not query_string.strip():
            raise ValueError("canonical query file does not contain a query")
        bound_query = self._bind_dimensions(query_string, dimensions)
        time_filter = self._time_range_factory(
            time_start=window.start, time_end=window.end, time_zone="UTC"
        )
        details = self._query_details_factory(
            compartment_id=self._compartment_id,
            compartment_id_in_subtree=self._compartment_id_in_subtree,
            query_string=bound_query,
            sub_system="LOG",
            max_total_count=max_rows,
            time_filter=time_filter,
            should_run_async=False,
        )
        response = self._client.query(namespace, details, limit=max_rows)
        items = getattr(getattr(response, "data", None), "items", None)
        if items is None:
            raise RuntimeError("Log Analytics query returned no result collection")
        return tuple(items)

    @staticmethod
    def _bind_dimensions(query: str, dimensions: Mapping[str, str]) -> str:
        predicates = "".join(
            f" and '{name.replace(chr(39), chr(39) * 2)}' = "
            f"'{value.replace(chr(39), chr(39) * 2)}'"
            for name, value in sorted(dimensions.items())
        )
        before_pipe, separator, after_pipe = query.partition("|")
        return f"{before_pipe.rstrip()}{predicates} {separator}{after_pipe}".rstrip()

    @classmethod
    def from_resource_principal(
        cls,
        *,
        compartment_id: str,
        compartment_id_in_subtree: bool,
        max_rows_ceiling: int,
        query_loader: Callable[[str], Mapping[str, object]],
    ) -> "OciLogAnalyticsQueryAdapter":
        import oci

        signer = oci.auth.signers.get_resource_principals_signer()
        client = oci.log_analytics.LogAnalyticsClient(config={}, signer=signer)
        return cls(
            client=client,
            compartment_id=compartment_id,
            compartment_id_in_subtree=compartment_id_in_subtree,
            max_rows_ceiling=max_rows_ceiling,
            query_loader=query_loader,
            query_details_factory=oci.log_analytics.models.QueryDetails,
            time_range_factory=oci.log_analytics.models.TimeRange,
        )


class OciVaultSecretAdapter:
    """Read one HEC token from an existing OCI Vault secret bundle."""

    def __init__(self, *, client: object, secret_id: str) -> None:
        if not isinstance(secret_id, str) or not secret_id.strip():
            raise ValueError("Vault secret reference is required")
        self._client = client
        self._secret_id = secret_id

    def __repr__(self) -> str:
        return "OciVaultSecretAdapter(secret_id=<redacted>)"

    def get_token(self) -> str:
        try:
            response = self._client.get_secret_bundle(
                secret_id=self._secret_id  # allow-sensitive-value
            )
            encoded = response.data.secret_bundle_content.content
            decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
        except (AttributeError, binascii.Error, UnicodeDecodeError, ValueError):
            raise RuntimeError("Vault secret is unavailable or invalid") from None
        except Exception:
            raise RuntimeError("Vault secret is unavailable") from None
        if not decoded:
            raise RuntimeError("Vault secret is empty")
        return decoded

    @classmethod
    def from_resource_principal(cls, *, secret_id: str) -> "OciVaultSecretAdapter":
        import oci

        signer = oci.auth.signers.get_resource_principals_signer()
        client = oci.secrets.SecretsClient(config={}, signer=signer)
        return cls(client=client, secret_id=secret_id)  # allow-sensitive-value


def _required_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} is required")
    return value.strip()


def _safe_identifier(value: str, *, maximum: int = 64) -> str:
    sanitized = re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")
    return sanitized[:maximum].rstrip("-") or "rule"


def _dimension_hash(dimensions: Mapping[str, str]) -> str:
    canonical = json.dumps(
        dict(dimensions), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def _identifier_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


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


class OciMonitoringMetricsAdapter:
    """Sanitized bounded Monitoring emission using the Function principal."""
    _ALLOWED_DIMENSIONS = frozenset({"detection", "outcome"})
    _ALLOWED_METRICS = frozenset(
        {"DeliveryFailed", "DeliverySucceeded", "DeliveredEvents", "DeadLetteredEvents"}
    )
    _SENSITIVE_MARKERS = frozenset(
        {"token", "secret", "password", "credential", "authorization", "cookie", "email"}
    )

    def __init__(
        self,
        *,
        client: object | Callable[[], object],
        compartment_id: str,
        namespace: str,
        metric_data_factory: Callable[..., object],
        metric_details_factory: Callable[..., object] | None = None,
        datapoint_factory: Callable[..., object] | None = None,
    ) -> None:
        self._client = client
        self._compartment_id = _required_text(compartment_id, "compartment")
        self._namespace = _required_text(namespace, "metric namespace")
        self._factory = metric_data_factory
        self._details_factory = metric_details_factory
        self._datapoint_factory = datapoint_factory

    def emit(self, name: str, value: int, dimensions: Mapping[str, str]) -> None:
        if name not in {"DeliveryFailed", "DeliverySucceeded", "DeliveredEvents", "DeadLetteredEvents"} or not isinstance(value, int) or value < 0:
            raise ValueError("metric is not governed")
        if not isinstance(dimensions, Mapping):
            raise ValueError("metric dimensions are invalid")
        if set(dimensions) - self._ALLOWED_DIMENSIONS:
            raise ValueError("metric dimensions are invalid")
        if len(dimensions) > len(self._ALLOWED_DIMENSIONS):
            raise ValueError("metric dimensions are invalid")
        for key, item in dimensions.items():
            if not isinstance(key, str) or not isinstance(item, str):
                raise ValueError("metric dimensions are invalid")
            lowered = f"{key}:{item}".casefold()
            if any(marker in lowered for marker in self._SENSITIVE_MARKERS):
                raise ValueError("metric dimensions are invalid")
            # Keep dimensions bounded and stable: no opaque IDs, addresses, or
            # arbitrary user-controlled strings may become Monitoring series.
            if not item or len(item) > 64 or not re.fullmatch(r"[A-Za-z0-9_.:-]+", item):
                raise ValueError("metric dimensions are invalid")
            if key == "outcome" and item not in self._ALLOWED_METRICS:
                raise ValueError("metric dimensions are invalid")
            if re.fullmatch(r"(?:[0-9a-f]{8}-){3,}[0-9a-f-]+|ocid1\.[A-Za-z0-9.:-]+|\d{1,3}(?:\.\d{1,3}){3}", item, re.IGNORECASE):
                raise ValueError("metric dimensions are invalid")
        safe = dict(dimensions)
        try:
            client = self._client() if callable(self._client) else self._client
            self._client = client
            timestamp = datetime.now(timezone.utc)
            datapoint = {"timestamp": timestamp, "value": value}
            if self._datapoint_factory is not None:
                datapoint = self._datapoint_factory(timestamp=timestamp, value=value)
            metric = {
                "namespace": self._namespace,
                "name": name,
                "compartment_id": self._compartment_id,
                "dimensions": safe,
                "datapoints": [datapoint],
            }
            if self._details_factory is not None:
                metric = self._details_factory(**metric)
            # Monitoring's PostMetricDataDetails accepts only metric_data and
            # batch_atomicity. The compartment belongs to MetricDataDetails.
            client.post_metric_data(self._factory(metric_data=[metric]))
        except Exception:
            raise RuntimeError("operational metric could not be emitted") from None


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
        context = (detection_id, dimensions, checkpoint)
        if any(item is not None for item in context):
            if detection_id is None or dimensions is None or checkpoint is None:
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


class SplunkHecAdapter:
    """Deliver normalized events to the Splunk HEC JSON event endpoint."""

    _MAX_TIMEOUT_SECONDS = 60
    _MAX_ACK_POLLS = 32
    _MAX_ACK_POLL_INTERVAL_SECONDS = 2.0

    def __init__(
        self,
        *,
        hec_url: str,
        token_provider: Callable[[], str] | object,
        index: str,
        sourcetype: str,
        timeout_seconds: float,
        acknowledgement_mode: str = "response",
        opener: Callable[..., object] = urllib_request.urlopen,
        allow_insecure_local_test: bool = False,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        ack_poll_initial_seconds: float = 0.25,
    ) -> None:
        self._event_url, self._ack_url = self._validated_urls(
            hec_url, allow_insecure_local_test
        )
        self._token_provider = token_provider
        self._index = _required_text(index, "Splunk index")
        self._sourcetype = _required_text(sourcetype, "Splunk sourcetype")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not 0 < timeout_seconds <= self._MAX_TIMEOUT_SECONDS
        ):
            raise ValueError(
                "HEC timeout must be greater than zero and at most 60 seconds"
            )
        if acknowledgement_mode not in ("response", "indexer_ack"):
            raise ValueError("unsupported HEC acknowledgement mode")
        if (
            isinstance(ack_poll_initial_seconds, bool)
            or not isinstance(ack_poll_initial_seconds, (int, float))
            or not 0 < ack_poll_initial_seconds <= timeout_seconds
        ):
            raise ValueError(
                "HEC acknowledgement poll interval must be within the timeout"
            )
        self._timeout_seconds = timeout_seconds
        self._acknowledgement_mode = acknowledgement_mode
        self._opener = opener
        self._clock = clock
        self._sleep = sleep
        self._ack_poll_initial_seconds = float(ack_poll_initial_seconds)

    def __repr__(self) -> str:
        return (
            "SplunkHecAdapter(endpoint=<redacted>, token=<redacted>, "
            f"acknowledgement_mode={self._acknowledgement_mode!r})"
        )

    @staticmethod
    def _validated_urls(
        hec_url: str, allow_insecure_local_test: bool
    ) -> tuple[str, str]:
        value = _required_text(hec_url, "Splunk HEC URL")
        parsed = urlsplit(value)
        local_host = parsed.hostname in ("localhost", "127.0.0.1", "::1")
        if parsed.scheme != "https" and not (
            allow_insecure_local_test and parsed.scheme == "http" and local_host
        ):
            raise ValueError("Splunk HEC URL must use HTTPS")
        if not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Splunk HEC URL is invalid")
        if parsed.query or parsed.fragment:
            raise ValueError("Splunk HEC URL cannot contain a query or fragment")
        base_path = parsed.path.rstrip("/")
        if base_path in ("", "/services/collector"):
            event_path = "/services/collector/event"
        elif base_path == "/services/collector/event":
            event_path = base_path
        else:
            raise ValueError("Splunk HEC URL must target the JSON event endpoint")
        event_url = urlunsplit((parsed.scheme, parsed.netloc, event_path, "", ""))
        ack_url = urlunsplit(
            (parsed.scheme, parsed.netloc, "/services/collector/ack", "", "")
        )
        return event_url, ack_url

    def _token(self) -> str:
        try:
            provider = self._token_provider
            token = provider() if callable(provider) else provider.get_token()
        except Exception:
            raise RuntimeError("HEC credential is unavailable") from None
        if not isinstance(token, str) or not token:
            raise RuntimeError("HEC credential is unavailable")
        return token

    def deliver(self, batch: ExportBatch) -> Mapping[str, object]:
        token = self._token()
        headers = {
            "Authorization": f"Splunk {token}",
            "Content-Type": "application/json",
        }
        if self._acknowledgement_mode == "indexer_ack":
            headers["X-Splunk-Request-Channel"] = batch.batch_id
        body = b"\n".join(
            json.dumps(
                {
                    "event": event.to_dict(),
                    "index": self._index,
                    "sourcetype": self._sourcetype,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            for event in batch.events
        )
        response_result = self._post(self._event_url, body, headers)
        status = response_result["status"]
        response = response_result["response"]
        confirmed = self._acknowledgement_mode == "response"
        if (
            self._acknowledgement_mode == "indexer_ack"
            and isinstance(response, Mapping)
            and isinstance(response.get("ackId"), int)
        ):
            confirmed = self._confirm_indexer_ack(response["ackId"], headers)
        return {
            "status": status,
            "response": response,
            "acknowledgement_mode": self._acknowledgement_mode,
            "acknowledgement_confirmed": confirmed,
        }

    def _confirm_indexer_ack(self, ack_id: int, headers: Mapping[str, str]) -> bool:
        ack_body = json.dumps({"acks": [ack_id]}, separators=(",", ":")).encode("utf-8")
        deadline = self._clock() + self._timeout_seconds
        interval = self._ack_poll_initial_seconds
        for _ in range(self._MAX_ACK_POLLS):
            remaining = deadline - self._clock()
            if remaining <= 0:
                return False
            ack_result = self._post(
                self._ack_url,
                ack_body,
                headers,
                timeout_seconds=remaining,
            )
            ack_response = ack_result["response"]
            acknowledgements = (
                ack_response.get("acks") if isinstance(ack_response, Mapping) else None
            )
            if isinstance(acknowledgements, Mapping) and (
                acknowledgements.get(str(ack_id)) is True
                or acknowledgements.get(ack_id) is True
            ):
                return True
            status = ack_result["status"]
            if isinstance(status, int) and 400 <= status <= 499:
                return False
            remaining = deadline - self._clock()
            sleep_for = min(interval, remaining)
            if sleep_for <= 0:
                return False
            self._sleep(sleep_for)
            interval = min(interval * 2, self._MAX_ACK_POLL_INTERVAL_SECONDS)
        return False

    def _post(
        self,
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        *,
        timeout_seconds: float | None = None,
    ) -> Mapping[str, object]:
        request = urllib_request.Request(
            url=url, data=body, headers=dict(headers), method="POST"
        )
        try:
            with self._opener(
                request,
                timeout=(
                    self._timeout_seconds
                    if timeout_seconds is None
                    else min(timeout_seconds, self._timeout_seconds)
                ),
            ) as response:
                status = response.status
                raw = response.read()
        except urllib_error.HTTPError as exc:
            return {"status": exc.code, "response": {}}
        except (TimeoutError, urllib_error.URLError) as exc:
            is_timeout = isinstance(exc, TimeoutError) or isinstance(
                getattr(exc, "reason", None), TimeoutError
            )
            return {
                "status": (
                    TimeoutError("HEC request timed out")
                    if is_timeout
                    else RuntimeError("HEC request failed")
                ),
                "response": {},
            }
        except Exception:
            return {"status": RuntimeError("HEC request failed"), "response": {}}
        try:
            decoded = json.loads(raw)
        except (TypeError, UnicodeDecodeError, json.JSONDecodeError):
            decoded = {}
        return {
            "status": status,
            "response": decoded if isinstance(decoded, Mapping) else {},
        }


@dataclass(frozen=True)
class OciAdapterBundle:
    """Resource-principal-backed OCI adapters for one Function invocation."""

    query: OciLogAnalyticsQueryAdapter
    vault: OciVaultSecretAdapter
    checkpoint: ObjectStorageStateAdapter
    dead_letter: ObjectStorageDeadLetterAdapter
    ledger: ObjectStorageDeliveryLedgerAdapter
    metrics: OciMonitoringMetricsAdapter


class OciResourcePrincipalAdapterFactory:
    """Own all OCI SDK imports, models, signing, clients, and adapter wiring."""

    @staticmethod
    def create(
        *,
        compartment_id: str,
        compartment_id_in_subtree: bool,
        max_rows_ceiling: int,
        secret_id: str,
        namespace: str,
        state_bucket: str,
        dlq_bucket: str,
        telemetry_namespace: str,
        query_loader: Callable[[str], Mapping[str, object]],
        clock: Callable[[], datetime],
    ) -> OciAdapterBundle:
        import oci

        signer = oci.auth.signers.get_resource_principals_signer()
        log_client = oci.log_analytics.LogAnalyticsClient(config={}, signer=signer)
        secrets_client = oci.secrets.SecretsClient(config={}, signer=signer)
        object_client = oci.object_storage.ObjectStorageClient(config={}, signer=signer)
        return OciAdapterBundle(
            query=OciLogAnalyticsQueryAdapter(
                client=log_client,
                compartment_id=compartment_id,
                compartment_id_in_subtree=compartment_id_in_subtree,
                max_rows_ceiling=max_rows_ceiling,
                query_loader=query_loader,
                query_details_factory=oci.log_analytics.models.QueryDetails,
                time_range_factory=oci.log_analytics.models.TimeRange,
            ),
            vault=OciVaultSecretAdapter(
                client=secrets_client,
                secret_id=secret_id,  # allow-sensitive-value
            ),
            checkpoint=ObjectStorageStateAdapter(
                client=object_client, namespace=namespace, bucket=state_bucket
            ),
            dead_letter=ObjectStorageDeadLetterAdapter(
                client=object_client,
                namespace=namespace,
                bucket=dlq_bucket,
                clock=clock,
            ),
            ledger=ObjectStorageDeliveryLedgerAdapter(
                client=object_client, namespace=namespace, bucket=state_bucket
            ),
            metrics=OciMonitoringMetricsAdapter(
                client=lambda: oci.monitoring.MonitoringClient(config={}, signer=signer),
                compartment_id=compartment_id,
                namespace=telemetry_namespace,
                metric_data_factory=oci.monitoring.models.PostMetricDataDetails,
                metric_details_factory=oci.monitoring.models.MetricDataDetails,
                datapoint_factory=oci.monitoring.models.Datapoint,
            ),
        )
