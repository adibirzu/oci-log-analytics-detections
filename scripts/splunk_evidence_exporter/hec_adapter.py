"""Bounded Splunk HEC delivery adapter."""

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
