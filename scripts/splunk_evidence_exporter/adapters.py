"""Compatibility exports and OCI resource-principal adapter factory."""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Mapping

from .adapter_utils import _required_text
from .hec_adapter import SplunkHecAdapter
from .models import ExportBatch
from .object_storage_adapters import (
    ObjectStorageDeadLetterAdapter,
    ObjectStorageDeliveryLedgerAdapter,
    ObjectStorageStateAdapter,
)
from .streaming_adapter import OciStreamingEvidenceAdapter, _validated_streaming_endpoint
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


@dataclass(frozen=True)
class OciAdapterBundle:
    """Resource-principal-backed OCI adapters for one Function invocation."""

    query: OciLogAnalyticsQueryAdapter
    vault: OciVaultSecretAdapter | None
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
        secret_id: str | None,
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
            vault=(
                OciVaultSecretAdapter(
                    client=secrets_client,
                    secret_id=secret_id,  # allow-sensitive-value
                )
                if secret_id
                else None
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
