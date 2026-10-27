"""OCI Streaming evidence delivery adapter."""

from __future__ import annotations

import base64
import json
from typing import Callable, Mapping
from urllib.parse import urlsplit

from .adapter_utils import _required_text
from .models import ExportBatch

class OciStreamingEvidenceAdapter:
    """Publish normalized evidence to a reviewed OCI Stream for `oci-splunk`."""

    def __init__(
        self,
        *,
        client: object,
        stream_id: str,
        message_factory: Callable[..., object],
        details_factory: Callable[..., object],
    ) -> None:
        self._client = client
        self._stream_id = _required_text(stream_id, "evidence stream")
        self._message_factory = message_factory
        self._details_factory = details_factory

    def __repr__(self) -> str:
        return "OciStreamingEvidenceAdapter(stream_id=<redacted>)"

    def deliver(self, batch: ExportBatch) -> Mapping[str, object]:
        messages = [
            self._message_factory(
                key=base64.b64encode(event.event_key.encode("utf-8")).decode("ascii"),
                value=base64.b64encode(
                    json.dumps(
                        event.to_dict(), sort_keys=True, separators=(",", ":")
                    ).encode("utf-8")
                ).decode("ascii"),
            )
            for event in batch.events
        ]
        try:
            response = self._client.put_messages(
                self._stream_id, self._details_factory(messages=messages)
            )
        except Exception as exc:
            status = getattr(exc, "status", None)
            return {
                "status": status if isinstance(status, int) else RuntimeError("Streaming delivery failed"),
                "response": {},
            }
        entries = getattr(getattr(response, "data", None), "entries", None)
        failures = getattr(getattr(response, "data", None), "failures", None)
        if (
            not isinstance(entries, list)
            or len(entries) != len(messages)
            or failures != 0
        ):
            return {"status": 500, "response": {}}
        if any(getattr(entry, "error", None) for entry in entries):
            return {"status": 500, "response": {}}
        # Normalize a confirmed Streaming write to the existing delivery-port
        # response contract. Consumer-to-HEC searchability remains a later gate.
        return {"status": 200, "response": {"code": 0}}

    @classmethod
    def from_resource_principal(
        cls, *, stream_id: str, messages_endpoint: str
    ) -> "OciStreamingEvidenceAdapter":
        import oci

        endpoint = _validated_streaming_endpoint(messages_endpoint)
        signer = oci.auth.signers.get_resource_principals_signer()
        client = oci.streaming.StreamClient(
            config={}, signer=signer, service_endpoint=endpoint
        )
        return cls(
            client=client,
            stream_id=stream_id,
            message_factory=oci.streaming.models.PutMessagesDetailsEntry,
            details_factory=oci.streaming.models.PutMessagesDetails,
        )


def _validated_streaming_endpoint(value: str) -> str:
    """Allow resource-principal signing only for an OCI Streaming service host."""
    endpoint = _required_text(value, "Streaming messages endpoint")
    parsed = urlsplit(endpoint)
    hostname = (parsed.hostname or "").casefold()
    allowed_suffixes = (
        ".oci.oraclecloud.com",
        ".oci.oraclecloud8.com",
        ".oci.oraclecloud9.com",
        ".oci.customer-oci.com",
    )
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or ".streaming." not in hostname
        or not hostname.endswith(allowed_suffixes)
    ):
        raise ValueError(
            "Streaming messages endpoint must be an OCI Streaming HTTPS host"
        )
    return f"https://{hostname}"
