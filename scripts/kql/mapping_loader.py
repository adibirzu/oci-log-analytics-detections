"""Mapping config loader (Phase 6 delegation).

Behavior-preserving wrapper around ``load_mapping_config`` in the legacy
facade so callers can migrate import paths gradually.
"""

from __future__ import annotations


def load_mapping(path=None):
    """Load the Sentinel→OCI mapping config.

    Forwards to ``scripts.convert_sentinel_kql.load_mapping_config``.
    """

    from scripts import convert_sentinel_kql as _legacy

    if path is None:
        return _legacy.load_mapping_config()
    return _legacy.load_mapping_config(path)


__all__ = ["load_mapping"]
