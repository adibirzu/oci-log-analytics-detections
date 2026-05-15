"""Snapshot regression for promoted and synthetic operator-coverage fixtures."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_DIR = Path(__file__).resolve().parents[2]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from scripts.kql.canonical import CanonicalizationError, canonical  # noqa: E402

FIXTURE_KQL_DIR = Path(__file__).resolve().parent / "fixtures" / "kql"
FIXTURE_EXPECTED_DIR = Path(__file__).resolve().parent / "fixtures" / "expected"

KQL_FIXTURES = sorted(FIXTURE_KQL_DIR.glob("*.kql"))


@pytest.mark.parametrize("kql_path", KQL_FIXTURES, ids=lambda p: p.stem)
def test_canonical_matches_snapshot(kql_path: Path) -> None:
    expected_path = FIXTURE_EXPECTED_DIR / f"{kql_path.stem}.logan"
    assert expected_path.exists(), f"missing expected snapshot for {kql_path.stem}"
    actual = canonical(kql_path.read_text())
    expected = expected_path.read_text()
    assert actual == expected, f"{kql_path.stem} drifted from snapshot"


def test_canonical_raises_on_unterminated_quote() -> None:
    with pytest.raises(CanonicalizationError):
        canonical("'unterminated")


def test_canonical_raises_on_unrecognized_char() -> None:
    with pytest.raises(CanonicalizationError):
        canonical("a `bad`")


def test_canonical_normalizes_double_quotes_to_single() -> None:
    assert canonical('"foo"') == "'foo'"
