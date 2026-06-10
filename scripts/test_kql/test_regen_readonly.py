"""Regression fence: `regen_promoted.py --check` must be read-only.

The byte-identity gate runs in CI and pre-commit hooks; it must never create,
write, or delete fixture files (an IP-bearing promoted query must be *reported*
as drift, not silently deleted). This test snapshots the fixtures tree, runs the
check, and asserts the tree is byte-identical afterwards.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PROJECT_DIR = _HERE.parent.parent
for _p in (str(_PROJECT_DIR), str(_HERE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import regen_promoted  # noqa: E402


def _snapshot(root: Path) -> dict[str, str]:
    """Map every file under root to a content hash."""
    snap: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            snap[str(path.relative_to(root))] = hashlib.md5(path.read_bytes()).hexdigest()
    return snap


def test_check_mode_does_not_mutate_fixtures() -> None:
    fixtures_root = regen_promoted.FIXTURE_KQL_DIR.parent
    before = _snapshot(fixtures_root)

    exit_code = regen_promoted.main(["--check"])

    after = _snapshot(fixtures_root)
    # The invariant under test is no-mutation. --check returns 0 on a fully
    # fixtured tree and 1 when promoted queries lack fixtures (e.g. after a bulk
    # promotion that didn't regenerate every fixture); either way it must not
    # write, create, or delete anything.
    assert exit_code in (0, 1), f"unexpected exit code {exit_code}"
    assert before == after, (
        "regen_promoted.py --check mutated the fixtures tree "
        f"(added/removed/changed: {set(before) ^ set(after) or 'content changed'})"
    )
