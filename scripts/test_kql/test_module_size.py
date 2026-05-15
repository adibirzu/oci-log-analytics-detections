"""Module-size gate for the ``convert_sentinel_kql`` facade (D-14).

Asserts ``scripts/convert_sentinel_kql.py`` is <=800 lines per the CLAUDE.md
file-size ceiling. Marked ``xfail(strict=True)`` during Phase 6 migration;
plan 06-10 removes the xfail mark once the facade reaches the limit.
``strict=True`` flips an accidental early shrink into XPASS so the cutover
signal is unambiguous.
"""

from __future__ import annotations

from pathlib import Path

import pytest

FACADE = Path(__file__).resolve().parents[1] / "convert_sentinel_kql.py"
LIMIT = 800


@pytest.mark.xfail(
    strict=True,
    reason="Phase 6 migration in progress; legacy helpers still inline. Plan 06-10 removes this xfail.",
)
def test_facade_under_line_limit() -> None:
    line_count = sum(1 for _ in FACADE.open())
    assert line_count <= LIMIT, f"{FACADE.name} is {line_count} lines, exceeds {LIMIT}"
