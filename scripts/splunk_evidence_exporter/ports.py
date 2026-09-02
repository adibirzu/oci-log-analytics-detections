"""Infrastructure ports for the evidence-export application service.

Only structural contracts live here; adapters own SDKs, HTTP, persistence,
credentials, environment configuration, and clocks. Application services own
the bounded retry and checkpoint policy around adapter delivery attempts.
"""

from __future__ import annotations

from datetime import datetime
from typing import Mapping, Protocol, Sequence, runtime_checkable

from .models import ExportBatch
from .window import QueryWindow


@runtime_checkable
class EvidenceQueryPort(Protocol):
    """Execute one bounded canonical OCI Log Analytics query."""

    def query_evidence(
        self,
        *,
        namespace: str,
        query_file: str,
        window: QueryWindow,
        dimensions: Mapping[str, str],
        max_rows: int,
    ) -> Sequence[Mapping[str, object]]: ...


@runtime_checkable
class HecDeliveryPort(Protocol):
    """Deliver an immutable batch and return sanitized response metadata."""

    def deliver(self, batch: ExportBatch) -> Mapping[str, object]: ...


@runtime_checkable
class CheckpointPort(Protocol):
    """Load and commit per-detection, per-dimension watermarks."""

    def load_checkpoint(
        self, detection_id: str, dimensions: Mapping[str, str]
    ) -> datetime | None: ...

    def save_checkpoint(
        self,
        detection_id: str,
        dimensions: Mapping[str, str],
        checkpoint: datetime,
    ) -> None: ...


@runtime_checkable
class QuarantinePort(Protocol):
    """Persist a failed batch for operator review without silent loss."""

    def quarantine(
        self,
        batch: ExportBatch,
        reason: str,
        *,
        delivered_event_keys: Sequence[str] = (),
        detection_id: str | None = None,
        dimensions: Mapping[str, str] | None = None,
        checkpoint: datetime | None = None,
    ) -> None: ...


# Vocabulary aliases keep later adapters readable without adding behavior.
LogAnalyticsPort = EvidenceQueryPort
SplunkHecPort = HecDeliveryPort
DeadLetterPort = QuarantinePort
