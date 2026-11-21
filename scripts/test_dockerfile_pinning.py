"""Contract tests enforcing sha256 base-image digest pinning in Dockerfiles."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PIPELINE_PATH = ROOT / "delivery" / "pipeline.yaml"
FROM_LINE_RE = re.compile(r"^FROM\s+", re.IGNORECASE)
PINNED_FROM_RE = re.compile(
    r"^FROM\s+(?:--platform=\S+\s+)?(?P<image>[^\s:@]+(?:/[^\s:@]+)*(?::[^\s@]+)?@(?P<digest>sha256:[0-9a-f]{64}))(?:\s+AS\s+[A-Za-z0-9._-]+)?\s*$",
    re.IGNORECASE,
)


def extract_from_lines(dockerfile_text: str) -> list[tuple[int, str]]:
    """Return 1-based line numbers and stripped FROM instructions."""
    lines: list[tuple[int, str]] = []
    for line_no, raw_line in enumerate(dockerfile_text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if FROM_LINE_RE.match(stripped):
            lines.append((line_no, stripped))
    return lines


def find_unpinned_from_lines(dockerfile_text: str) -> list[tuple[int, str]]:
    """Return unpinned FROM instructions from a Dockerfile string."""
    return [
        (line_no, line)
        for line_no, line in extract_from_lines(dockerfile_text)
        if not PINNED_FROM_RE.match(line)
    ]


def test_webapp_dockerfiles_exist():
    dockerfiles = sorted(ROOT.glob("webapp/Dockerfile*"))
    names = {path.name for path in dockerfiles}
    assert {"Dockerfile", "Dockerfile.lean"} <= names


def test_webapp_dockerfiles_have_zero_unpinned_from_lines():
    dockerfiles = sorted(ROOT.glob("webapp/Dockerfile*"))
    unpinned: list[str] = []
    stage_count = 0

    for dockerfile in dockerfiles:
        from_lines = extract_from_lines(dockerfile.read_text(encoding="utf-8"))
        stage_count += len(from_lines)
        for line_no, line in from_lines:
            if not PINNED_FROM_RE.match(line):
                unpinned.append(f"{dockerfile.relative_to(ROOT)}:{line_no}: {line}")

    assert stage_count >= 4
    assert not unpinned, f"Unpinned Dockerfile FROM lines found: {unpinned}"


def test_tab_delimited_from_lines_are_checked_by_pin_validator():
    unpinned_tab = "FROM\tnode:22-alpine AS runner\n"
    pinned_tab = (
        "FROM\tnode:22-alpine@sha256:"
        "1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a AS runner\n"
    )
    assert find_unpinned_from_lines(unpinned_tab) == [(1, "FROM\tnode:22-alpine AS runner")]
    assert find_unpinned_from_lines(pinned_tab) == []


def test_pipeline_base_image_digests_match_dockerfiles():
    pipeline = yaml.safe_load(PIPELINE_PATH.read_text(encoding="utf-8"))
    images = pipeline.get("images", [])
    assert images, "delivery/pipeline.yaml must declare images"

    for image in images:
        dockerfile_rel = image["dockerfile"]
        expected_base = str(image["base_image"])
        expected_digest = expected_base.split("@", 1)[1]
        from_lines = extract_from_lines((ROOT / dockerfile_rel).read_text(encoding="utf-8"))
        assert from_lines, f"No FROM lines found in {dockerfile_rel}"
        for _, line in from_lines:
            match = PINNED_FROM_RE.match(line)
            assert match is not None, f"Unpinned FROM in {dockerfile_rel}: {line}"
            assert match.group("image") == expected_base
            assert match.group("digest") == expected_digest
