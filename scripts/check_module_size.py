#!/usr/bin/env python3
"""Module-size gate for scripts/**/*.py.

CI gate that fails if any scripts/**/*.py file NOT in ALLOWLIST exceeds 800 lines.
Files in ALLOWLIST are pre-existing violations that existed when this gate was
introduced (2025-06-10). They do NOT block the build, but are printed as
warnings so contributors know they need to shrink.

The ALLOWLIST MUST SHRINK over time — do not add new entries.  When a file is
refactored below the 800-line ceiling, remove it from the allowlist so the gate
enforces the limit going forward.

Exit codes:
  0 — all non-allowlisted files are within the 800-line limit
  1 — one or more new (non-allowlisted) files exceed the limit
"""

from __future__ import annotations

import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
LIMIT = 800

# Pre-existing oversized files as of 2025-06-10.
# DO NOT ADD NEW ENTRIES — shrink this list instead.
ALLOWLIST: frozenset[str] = frozenset(
    {
        # This allowlist is currently empty. Keep it that way; split oversized
        # modules into focused packages instead of adding new exceptions.
    }
)


def check() -> int:
    violations: list[tuple[str, int]] = []
    allowlist_warnings: list[tuple[str, int]] = []

    for py_file in sorted(SCRIPTS_DIR.rglob("*.py")):
        name = py_file.relative_to(SCRIPTS_DIR).as_posix()
        lines = sum(1 for _ in py_file.open())
        if lines <= LIMIT:
            continue
        if name in ALLOWLIST:
            allowlist_warnings.append((name, lines))
        else:
            violations.append((name, lines))

    if allowlist_warnings:
        print(
            f"WARNING: {len(allowlist_warnings)} pre-existing oversized file(s) "
            "(ALLOWLIST in check_module_size.py — please refactor to shrink the list):"
        )
        for name, lines in allowlist_warnings:
            print(f"  {name}: {lines} lines  [ALLOWLISTED — must shrink over time]")

    if violations:
        print(
            f"\nERROR: {len(violations)} file(s) exceed the {LIMIT}-line ceiling "
            "and are not in the allowlist:"
        )
        for name, lines in violations:
            print(f"  {name}: {lines} lines")
        print(
            "\nSplit the file into focused modules or add it to the ALLOWLIST "
            "only if it pre-dates this gate and a refactor ticket has been filed."
        )
        return 1

    print(
        f"Module-size gate: PASS  "
        f"({len(allowlist_warnings)} allowlisted violation(s) pending refactor, "
        "0 new violations)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(check())
