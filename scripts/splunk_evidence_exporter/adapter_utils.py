"""Shared deterministic naming and validation helpers for exporter adapters."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Mapping

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
