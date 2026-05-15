#!/usr/bin/env python3
"""Regenerate canonical-form snapshots for the promoted Sentinel queries.

Reads every ``queries/sentinel/*.json``, extracts the converted ``query``
string, and writes:

- ``scripts/test_kql/fixtures/kql/<slug>.kql``      — verbatim query body
- ``scripts/test_kql/fixtures/expected/<slug>.logan`` — ``canonical(body)``

Usage:
    python scripts/test_kql/regen_promoted.py          # rewrite fixtures
    python scripts/test_kql/regen_promoted.py --check  # CI mode (fail on drift)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[2]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from scripts.kql.canonical import canonical  # noqa: E402

PROMOTED_DIR = PROJECT_DIR / "queries" / "sentinel"
FIXTURE_KQL_DIR = PROJECT_DIR / "scripts" / "test_kql" / "fixtures" / "kql"
FIXTURE_EXPECTED_DIR = PROJECT_DIR / "scripts" / "test_kql" / "fixtures" / "expected"


def slug_for(path: Path) -> str:
    """Return a filename-safe slug derived from the promoted JSON file."""

    return path.stem.replace("-", "_")


def extract_query(payload: dict) -> str:
    """Return the converted Logan QL body from a promoted-Sentinel payload."""

    query = payload.get("query")
    if isinstance(query, str):
        return query
    if isinstance(query, dict):
        # Some payload shapes nest the string under ``body``/``text``.
        for key in ("body", "text", "logan", "query"):
            value = query.get(key)
            if isinstance(value, str):
                return value
    raise RuntimeError("could not locate query string in promoted payload")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Compare on-disk fixtures against canonical(body) and exit non-zero on drift.",
    )
    args = parser.parse_args(argv)

    FIXTURE_KQL_DIR.mkdir(parents=True, exist_ok=True)
    FIXTURE_EXPECTED_DIR.mkdir(parents=True, exist_ok=True)

    drift: list[str] = []
    for promoted_path in sorted(PROMOTED_DIR.glob("*.json")):
        payload = json.loads(promoted_path.read_text())
        slug = slug_for(promoted_path)
        body = extract_query(payload)
        expected = canonical(body)

        kql_path = FIXTURE_KQL_DIR / f"{slug}.kql"
        expected_path = FIXTURE_EXPECTED_DIR / f"{slug}.logan"

        if args.check:
            current_kql = kql_path.read_text() if kql_path.exists() else None
            current_expected = expected_path.read_text() if expected_path.exists() else None
            if current_kql != body:
                drift.append(f"{slug}: kql fixture drift")
            if current_expected != expected:
                drift.append(f"{slug}: expected fixture drift")
        else:
            kql_path.write_text(body)
            expected_path.write_text(expected)
            print(f"[wrote] {slug}")

    if args.check and drift:
        for line in drift:
            print(f"DRIFT: {line}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
