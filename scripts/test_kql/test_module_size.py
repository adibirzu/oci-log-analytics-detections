"""Module-size gate for the ``convert_sentinel_kql`` facade (D-14).

Asserts ``scripts/convert_sentinel_kql.py`` is <=800 lines per the CLAUDE.md
file-size ceiling. Phase 6 migration is complete; xfail removed in plan
06-10. Future PRs that grow the facade past 800 lines fail this gate.
"""

from __future__ import annotations

from pathlib import Path

FACADE = Path(__file__).resolve().parents[1] / "convert_sentinel_kql.py"
LIMIT = 800


def test_facade_under_line_limit() -> None:
    line_count = sum(1 for _ in FACADE.open())
    assert line_count <= LIMIT, f"{FACADE.name} is {line_count} lines, exceeds {LIMIT}"
