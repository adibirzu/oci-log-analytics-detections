"""Pure Splunk HEC delivery outcome classification."""

from __future__ import annotations

from typing import Literal, Mapping


HecOutcome = Literal["success", "retryable", "quarantine"]
AcknowledgementMode = Literal["response", "indexer_ack"]

_QUARANTINE_STATUSES = frozenset({400, 401, 403, 404, 413, 422})


def classify_hec_failure(
    status: int | BaseException | None,
    *,
    acknowledgement_mode: AcknowledgementMode = "response",
    response: Mapping[str, object] | None = None,
    acknowledgement_confirmed: bool = False,
) -> HecOutcome:
    """Classify a HEC attempt without performing retries or reading config."""

    if isinstance(status, TimeoutError):
        return "retryable"
    if isinstance(status, BaseException):
        return "quarantine"
    if status is None:
        return "retryable"
    if isinstance(status, bool) or not isinstance(status, int):
        raise TypeError("status must be an integer, exception, or None")
    if status in (408, 429) or 500 <= status <= 599:
        return "retryable"
    if status in _QUARANTINE_STATUSES:
        return "quarantine"
    if 200 <= status <= 299:
        return _classify_success(
            acknowledgement_mode,
            response,
            acknowledgement_confirmed,
        )
    return "quarantine"


def _classify_success(
    mode: AcknowledgementMode,
    response: Mapping[str, object] | None,
    acknowledgement_confirmed: bool,
) -> HecOutcome:
    if mode not in ("response", "indexer_ack"):
        raise ValueError(f"unsupported acknowledgement mode: {mode}")
    if response is None:
        return "retryable"
    if not isinstance(response, Mapping):
        return "quarantine"
    response_code = response.get("code")
    valid_response_code = (
        isinstance(response_code, int)
        and not isinstance(response_code, bool)
        and response_code == 0
    )
    if not valid_response_code:
        return "quarantine"
    if mode == "response":
        return "success"
    ack_id = response.get("ackId")
    valid_ack_id = (
        isinstance(ack_id, int) and not isinstance(ack_id, bool) and ack_id >= 0
    )
    if valid_ack_id and acknowledgement_confirmed is True:
        return "success"
    return "retryable" if valid_ack_id else "quarantine"
