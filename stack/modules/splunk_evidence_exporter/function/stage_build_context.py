#!/usr/bin/env python3
"""Stage a deterministic OCI Functions build context from canonical repo files."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path
from typing import Mapping, Sequence


FUNCTION_SOURCE = Path(__file__).resolve().parent
ROOT = FUNCTION_SOURCE.parents[3]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _registry_queries(registry_path: Path) -> dict[str, Path]:
    try:
        registry = json.loads(registry_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise RuntimeError("canonical detection registry is unavailable") from None
    detections = registry.get("detections") if isinstance(registry, Mapping) else None
    if not isinstance(detections, list) or not detections:
        raise RuntimeError("canonical detection registry is invalid")
    query_root = (ROOT / "queries").resolve()
    queries: dict[str, Path] = {}
    for entry in detections:
        relative = entry.get("oci_query_file") if isinstance(entry, Mapping) else None
        if not isinstance(relative, str):
            raise RuntimeError("canonical detection query reference is invalid")
        source = (ROOT / relative).resolve()
        if query_root not in source.parents or source.suffix != ".json":
            raise RuntimeError("canonical detection query is outside the query tree")
        queries[relative] = source
    return queries


def _canonical_sources() -> dict[str, Path]:
    registry = ROOT / "queries/splunk_detection_registry.json"
    sources = {
        "func.py": FUNCTION_SOURCE / "func.py",
        "func.yaml": FUNCTION_SOURCE / "func.yaml",
        "requirements.txt": FUNCTION_SOURCE / "requirements.txt",
        "config/splunk_parallel_delivery.yaml": (
            ROOT / "config/splunk_parallel_delivery.yaml"
        ),
        "queries/splunk_detection_registry.json": registry,
        "schemas/splunk_evidence_event.schema.json": (
            ROOT / "schemas/splunk_evidence_event.schema.json"
        ),
        "scripts/__init__.py": ROOT / "scripts/__init__.py",
    }
    for source in sorted((ROOT / "scripts/splunk_evidence_exporter").glob("*.py")):
        sources[source.relative_to(ROOT).as_posix()] = source
    sources.update(_registry_queries(registry))
    missing = [relative for relative, source in sources.items() if not source.is_file()]
    if missing:
        raise RuntimeError("required canonical Function source is unavailable")
    return dict(sorted(sources.items()))


def stage(output: Path) -> dict[str, object]:
    target = output.expanduser().resolve()
    if target == ROOT or ROOT in target.parents:
        raise ValueError("build context must be outside the repository")
    if target.exists() and any(target.iterdir()):
        raise RuntimeError("build context directory must be empty")
    sources = _canonical_sources()
    target.mkdir(parents=True, exist_ok=True)
    hashes: dict[str, str] = {}
    for relative, source in sources.items():
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        hashes[relative] = _sha256(destination)
    manifest = {
        "schema_version": "oci.logan.splunk.function-build-context.v1",
        "source_policy": "canonical-repository-files-only",
        "files": hashes,
    }
    (target / "build-context-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return {
        "status": "staged",
        "file_count": len(hashes),
        "manifest": "build-context-manifest.json",
        "external_calls": [],
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        receipt = stage(arguments.output)
    except Exception as exc:
        print(
            json.dumps(
                {"status": "failed_closed", "error_type": type(exc).__name__},
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
