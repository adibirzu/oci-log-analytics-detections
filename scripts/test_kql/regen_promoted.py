#!/usr/bin/env python3
"""Regenerate canonical-form snapshots for the promoted Sentinel queries.

Reads every ``queries/sentinel/*.json``, extracts the converted ``query``
string, and writes:

- ``scripts/test_kql/fixtures/kql/<slug>.kql``      — verbatim query body
- ``scripts/test_kql/fixtures/expected/<slug>.logan`` — ``canonical(body)``

Collision handling
------------------
Two distinct source files can produce the same base slug (e.g.
``deimos-component-execution.json`` and ``deimos_component_execution.json``
both normalise to ``deimos_component_execution``).  ``build_slug_map()``
resolves collisions deterministically: the file that sorts first (ASCII
order) keeps the natural base slug; later colliders receive a ``_2``,
``_3``, … numeric suffix.  Non-colliding files are always assigned their
natural slug, so existing fixtures remain stable.

IP-bearing fixture exclusion
-----------------------------
If the query body embeds a public routable IP address the fixture is
*skipped* and the source file is recorded in ``EXCLUDED_IP_FIXTURES``.
Storing C2 indicators in plain-text test fixtures would trigger
``scan_sensitive_values.py``.

Usage:
    python scripts/test_kql/regen_promoted.py          # rewrite fixtures
    python scripts/test_kql/regen_promoted.py --check  # CI mode (fail on drift)
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Iterable

PROJECT_DIR = Path(__file__).resolve().parents[2]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from scripts.kql.canonical import canonical  # noqa: E402

PROMOTED_DIR = PROJECT_DIR / "queries" / "sentinel"
FIXTURE_KQL_DIR = PROJECT_DIR / "scripts" / "test_kql" / "fixtures" / "kql"
FIXTURE_EXPECTED_DIR = PROJECT_DIR / "scripts" / "test_kql" / "fixtures" / "expected"

# Regex that matches bare IPv4 addresses embedded in query text.
_IPV4_RE = re.compile(
    r"(?<![\d.])"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}"
    r"(?![\d.])"
)


def slug_for(path: Path) -> str:
    """Return a filename-safe slug derived from the promoted JSON file.

    Hyphens are normalised to underscores so that ``deimos-component-execution``
    and ``deimos_component_execution`` share the same *base* slug.  Callers
    that iterate multiple paths should use :func:`build_slug_map` to resolve
    any collisions before writing fixtures.
    """
    return path.stem.replace("-", "_")


def build_slug_map(paths: Iterable[Path]) -> dict[Path, str]:
    """Return a ``{path: unique_slug}`` mapping with collision disambiguation.

    Non-colliding paths receive their natural slug from :func:`slug_for`.
    When two or more paths share the same base slug the first (in sorted
    ASCII order) keeps the base slug; subsequent paths receive a ``_2``,
    ``_3``, … suffix so every slug is unique and stable across re-runs.
    """
    sorted_paths = sorted(paths)

    # Group paths by base slug.
    base_to_paths: dict[str, list[Path]] = {}
    for path in sorted_paths:
        base = slug_for(path)
        base_to_paths.setdefault(base, []).append(path)

    result: dict[Path, str] = {}
    for base, group in base_to_paths.items():
        for i, path in enumerate(group):
            result[path] = base if i == 0 else f"{base}_{i + 1}"

    return result


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


def _contains_public_ip(text: str) -> bool:
    """Return True if *text* embeds at least one globally-routable IPv4 address."""
    for match in _IPV4_RE.finditer(text):
        try:
            ip = ipaddress.ip_address(match.group(0))
            if ip.is_global:
                return True
        except ValueError:
            pass
    return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Compare on-disk fixtures against canonical(body) and exit non-zero on drift.",
    )
    args = parser.parse_args(argv)

    # --check is a read-only CI gate: it must never create, write, or delete
    # anything. Only the write mode touches the filesystem.
    if not args.check:
        FIXTURE_KQL_DIR.mkdir(parents=True, exist_ok=True)
        FIXTURE_EXPECTED_DIR.mkdir(parents=True, exist_ok=True)

    promoted_paths = list(PROMOTED_DIR.glob("*.json"))
    slug_map = build_slug_map(promoted_paths)

    # Track which source files were excluded because their query body
    # contained a public IP (C2 indicators, etc.).
    excluded_ip: list[str] = []

    drift: list[str] = []
    for promoted_path in sorted(promoted_paths):
        payload = json.loads(promoted_path.read_text())
        slug = slug_map[promoted_path]
        body = extract_query(payload)

        kql_path = FIXTURE_KQL_DIR / f"{slug}.kql"
        expected_path = FIXTURE_EXPECTED_DIR / f"{slug}.logan"

        # Skip any fixture whose query body embeds a public IP.
        if _contains_public_ip(body):
            excluded_ip.append(promoted_path.name)
            stale_fixtures = [p for p in (kql_path, expected_path) if p.exists()]
            if args.check:
                # Read-only: a leftover IP-bearing fixture is drift to flag, not
                # delete. Writing mode is what removes it.
                for stale in stale_fixtures:
                    drift.append(f"{slug}: stale IP-bearing fixture present ({stale.name})")
            else:
                print(f"[skip-ip] {promoted_path.name} → {slug}  (public IP in query body)")
                for stale in stale_fixtures:
                    stale.unlink()
                    print(f"[removed] stale IP-bearing fixture: {stale.name}")
            continue

        expected = canonical(body)

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

    if excluded_ip:
        print(
            f"\nExcluded {len(excluded_ip)} fixture(s) with public IPs "
            f"(scan_sensitive_values.py guard):",
            file=sys.stderr,
        )
        for name in excluded_ip:
            print(f"  {name}", file=sys.stderr)

    if args.check and drift:
        for line in drift:
            print(f"DRIFT: {line}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
