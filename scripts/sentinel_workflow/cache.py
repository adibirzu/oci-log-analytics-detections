"""Deterministic cache-key helpers for Sentinel live conversion lanes."""

from __future__ import annotations

import hashlib
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[2]
DEFAULT_CANDIDATES_FILE = PROJECT_DIR / "queries" / "sentinel_candidates.json"
DEFAULT_REPORT_PATH = PROJECT_DIR / "queries" / "sentinel_conversion_report.json"
DEFAULT_FIELD_DICTIONARY = PROJECT_DIR / "queries" / "log_source_field_dictionary.json"
DEFAULT_MAPPING_ROOT = PROJECT_DIR / "config" / "mapping"


def _project_relative(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT_DIR))
    except ValueError:
        return str(path)


def _hash_file(path: Path, digest: "hashlib._Hash") -> None:
    digest.update(_project_relative(path).encode("utf-8"))
    digest.update(b"\0")
    if not path.exists():
        digest.update(b"<missing>")
        digest.update(b"\0")
        return
    digest.update(path.read_bytes())
    digest.update(b"\0")


def _hash_tree(root: Path, digest: "hashlib._Hash", patterns: tuple[str, ...]) -> None:
    if not root.exists():
        digest.update(_project_relative(root).encode("utf-8"))
        digest.update(b"<missing-tree>\0")
        return
    files: list[Path] = []
    for pattern in patterns:
        files.extend(path for path in root.rglob(pattern) if path.is_file())
    for path in sorted(set(files)):
        _hash_file(path, digest)


def build_live_cache_key(
    *,
    lookback: str,
    profile: str,
    candidates_file: Path = DEFAULT_CANDIDATES_FILE,
    report_path: Path = DEFAULT_REPORT_PATH,
    field_dictionary_path: Path = DEFAULT_FIELD_DICTIONARY,
    mapping_root: Path = DEFAULT_MAPPING_ROOT,
) -> str:
    """Return a deterministic live-validation cache key for CI.

    The key intentionally changes when any input that can affect live promotion
    semantics changes: candidate intake/report state, parser schema, mapping
    shards, converter/workflow code, runtime profile, or live lookback.
    """
    digest = hashlib.sha256()
    digest.update(b"sentinel-live-v2\0")
    digest.update(f"lookback={lookback}\0profile={profile}\0".encode("utf-8"))
    for path in (
        candidates_file,
        report_path,
        field_dictionary_path,
        PROJECT_DIR / "scripts" / "convert_sentinel_kql.py",
        PROJECT_DIR / "scripts" / "sentinel_conversion_workflow.py",
        PROJECT_DIR / "scripts" / "sentinel_drift_check.py",
    ):
        _hash_file(path, digest)
    _hash_tree(PROJECT_DIR / "scripts" / "kql", digest, ("*.py",))
    _hash_tree(mapping_root, digest, ("*.yaml", "*.yml"))
    return f"sentinel-live-{digest.hexdigest()[:32]}"

