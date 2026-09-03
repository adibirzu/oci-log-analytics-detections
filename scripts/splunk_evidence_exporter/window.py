"""Timezone-safe evidence query-window calculation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


def _aware_utc(value: datetime, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"{field_name} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(timezone.utc)


@dataclass(frozen=True)
class QueryWindow:
    """Inclusive query boundaries represented as aware UTC datetimes."""

    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        start = _aware_utc(self.start, "start")
        end = _aware_utc(self.end, "end")
        if start > end:
            raise ValueError("query window start cannot be after end")
        object.__setattr__(self, "start", start)
        object.__setattr__(self, "end", end)

    @property
    def duration(self) -> timedelta:
        return self.end - self.start


def calculate_window(
    alarm_end: datetime,
    lookback: timedelta,
    overlap: timedelta,
    checkpoint: datetime | None = None,
    maximum: timedelta | None = None,
    *,
    max_window: timedelta | None = None,
) -> QueryWindow:
    """Return a bounded query window, honoring checkpoint replay overlap.

    ``maximum`` is the preferred parameter name. ``max_window`` is accepted as
    an explicit alias for adapters whose configuration uses that vocabulary.
    """

    end = _aware_utc(alarm_end, "alarm_end")
    if not isinstance(lookback, timedelta) or lookback <= timedelta(0):
        raise ValueError("lookback must be a positive duration")
    if not isinstance(overlap, timedelta) or overlap < timedelta(0):
        raise ValueError("overlap must be a non-negative duration")
    if maximum is not None and max_window is not None and maximum != max_window:
        raise ValueError("maximum and max_window cannot disagree")
    configured_maximum = maximum if maximum is not None else max_window
    if configured_maximum is not None and (
        not isinstance(configured_maximum, timedelta)
        or configured_maximum <= timedelta(0)
    ):
        raise ValueError("maximum must be a positive duration")

    if checkpoint is None:
        start = end - lookback - overlap
    else:
        start = _aware_utc(checkpoint, "checkpoint") - overlap

    window = QueryWindow(start=start, end=end)
    if configured_maximum is not None and window.duration > configured_maximum:
        raise ValueError("query window exceeds configured maximum")
    return window
