"""Contract tests enforcing sha256 base-image digest pinning in Dockerfiles."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PINNED_FROM_RE = re.compile(
    r"^FROM\s+(?:--platform=\S+\s+)?[^\s:@]+(?:/[^\s:@]+)*(?::[^\s@]+)?@sha256:[0-9a-f]{64}(?:\s+AS\s+[A-Za-z0-9._-]+)?\s*$",
    re.IGNORECASE,
)


def test_webapp_dockerfiles_exist():
    dockerfiles = sorted(ROOT.glob("webapp/Dockerfile*"))
    names = {path.name for path in dockerfiles}
    assert {"Dockerfile", "Dockerfile.lean"} <= names


def test_webapp_dockerfiles_have_zero_unpinned_from_lines():
    dockerfiles = sorted(ROOT.glob("webapp/Dockerfile*"))
    unpinned: list[str] = []
    stage_count = 0

    for dockerfile in dockerfiles:
        for line_no, raw_line in enumerate(dockerfile.read_text(encoding="utf-8").splitlines(), start=1):
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.upper().startswith("FROM "):
                stage_count += 1
                if not PINNED_FROM_RE.match(stripped):
                    unpinned.append(f"{dockerfile.relative_to(ROOT)}:{line_no}: {stripped}")

    assert stage_count >= 4
    assert not unpinned, f"Unpinned Dockerfile FROM lines found: {unpinned}"
