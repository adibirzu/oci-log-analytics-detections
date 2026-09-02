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
from datetime import datetime, timezone
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
        query_loader: Callable[[str], Mapping[str, object]],
        query_details_factory: Callable[..., object],
        time_range_factory: Callable[..., object],
    ) -> None:
        if not isinstance(compartment_id, str) or not compartment_id.strip():
            raise ValueError("Log Analytics compartment is required")
        self._client = client
        self._compartment_id = compartment_id
        self._compartment_id_in_subtree = bool(compartment_id_in_subtree)
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
        query_loader: Callable[[str], Mapping[str, object]],
    ) -> "OciLogAnalyticsQueryAdapter":
        import oci

        signer = oci.auth.signers.get_resource_principals_signer()
        client = oci.log_analytics.LogAnalyticsClient(config={}, signer=signer)
        return cls(
            client=client,
            compartment_id=compartment_id,
            compartment_id_in_subtree=compartment_id_in_subtree,
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


class ObjectStorageStateAdapter:
    """Store per-rule checkpoints under deterministic, non-sensitive names."""

    def __init__(self, *, client: object, namespace: str, bucket: str) -> None:
        self._client = client
        self._namespace = _required_text(namespace, "Object Storage namespace")
        self._bucket = _required_text(bucket, "Object Storage bucket")

    def _object_name(self, detection_id: str, dimensions: Mapping[str, str]) -> str:
        return (
            f"state-{_safe_identifier(detection_id)}-{_dimension_hash(dimensions)}.json"
        )

    def load_checkpoint(
        self, detection_id: str, dimensions: Mapping[str, str]
    ) -> datetime | None:
        try:
            response = self._client.get_object(
                namespace_name=self._namespace,
                bucket_name=self._bucket,
                object_name=self._object_name(detection_id, dimensions),
            )
        except Exception as exc:
            if getattr(exc, "status", None) == 404:
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
        try:
            self._client.put_object(
                namespace_name=self._namespace,
                bucket_name=self._bucket,
                object_name=self._object_name(detection_id, dimensions),
                put_object_body=body,
                content_type="application/json",
            )
        except Exception:
            raise RuntimeError("checkpoint state could not be committed") from None

    @classmethod
    def from_resource_principal(
        cls, *, namespace: str, bucket: str
    ) -> "ObjectStorageStateAdapter":
        import oci

        signer = oci.auth.signers.get_resource_principals_signer()
        client = oci.object_storage.ObjectStorageClient(config={}, signer=signer)
        return cls(client=client, namespace=namespace, bucket=bucket)


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
        body = json.dumps(
            {
                "schema_version": "oci.logan.splunk.dead-letter.v1",
                "reason": reason,
                "created_at": created_at.astimezone(timezone.utc)
                .isoformat()
                .replace("+00:00", "Z"),
                "batch_id": batch.batch_id,
                "delivered_event_keys": list(delivered_event_keys),
                "remaining_events": remaining,
            },
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
        self._timeout_seconds = timeout_seconds
        self._acknowledgement_mode = acknowledgement_mode
        self._opener = opener

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
            ack_id = response["ackId"]
            ack_body = json.dumps({"acks": [ack_id]}, separators=(",", ":")).encode(
                "utf-8"
            )
            ack_result = self._post(self._ack_url, ack_body, headers)
            ack_response = ack_result["response"]
            acknowledgements = (
                ack_response.get("acks") if isinstance(ack_response, Mapping) else None
            )
            confirmed = isinstance(acknowledgements, Mapping) and (
                acknowledgements.get(str(ack_id)) is True
                or acknowledgements.get(ack_id) is True
            )
        return {
            "status": status,
            "response": response,
            "acknowledgement_mode": self._acknowledgement_mode,
            "acknowledgement_confirmed": confirmed,
        }

    def _post(
        self, url: str, body: bytes, headers: Mapping[str, str]
    ) -> Mapping[str, object]:
        request = urllib_request.Request(
            url=url, data=body, headers=dict(headers), method="POST"
        )
        try:
            with self._opener(request, timeout=self._timeout_seconds) as response:
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
