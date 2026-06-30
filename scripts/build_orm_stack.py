#!/usr/bin/env python3
"""Build a customer-safe OCI Resource Manager deployment package.

The package intentionally contains deployment code and generated detection content,
but never disposable test data, local credentials, or Terraform working state.
"""

from __future__ import annotations

import argparse
import json
import zipfile
from pathlib import Path
from typing import Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_SCHEMA_VERSION = "1.0.0"
REQUIRED_PATHS = (
    "requirements.txt",
    "stack/main.tf",
    "stack/provider.tf",
    "stack/provisioners.tf",
    "stack/schema.yaml",
    "stack/variables.tf",
    "scripts/deploy_dashboard.py",
    "scripts/setup_log_sources.py",
)
PACKAGE_DIRECTORIES = ("stack", "scripts", "queries", "config", "schemas")
EXCLUDED_DIRECTORY_NAMES = {
    ".git",
    ".sentinel",
    ".sigmahq",
    ".terraform",
    ".venv",
    "__pycache__",
    "node_modules",
    "test_data",
    "venv",
}
EXCLUDED_SUFFIXES = {".pyc", ".zip"}


def _validate_required_paths(project_root: Path) -> None:
    for relative_path in REQUIRED_PATHS:
        if not (project_root / relative_path).is_file():
            raise FileNotFoundError(f"Required deployment package file is missing: {relative_path}")


def _is_included_file(path: Path, project_root: Path) -> bool:
    relative = path.relative_to(project_root)
    if path.is_symlink() or not path.is_file():
        return False
    if any(part in EXCLUDED_DIRECTORY_NAMES for part in relative.parts):
        return False
    return path.suffix not in EXCLUDED_SUFFIXES


def _iter_package_files(project_root: Path) -> Iterable[Path]:
    required = [project_root / relative_path for relative_path in REQUIRED_PATHS]
    yielded: set[Path] = set()
    for path in required:
        yielded.add(path)
        yield path

    for directory_name in PACKAGE_DIRECTORIES:
        directory = project_root / directory_name
        if not directory.is_dir():
            continue
        for path in sorted(directory.rglob("*")):
            if path not in yielded and _is_included_file(path, project_root):
                yielded.add(path)
                yield path


def build_package(project_root: Path, output_path: Path) -> dict[str, object]:
    """Create a deterministic ORM zip and return its non-sensitive manifest."""
    _validate_required_paths(project_root)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    files = list(_iter_package_files(project_root))

    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            archive.write(path, path.relative_to(project_root).as_posix())

    return {
        "schema_version": PACKAGE_SCHEMA_VERSION,
        "output": output_path.name,
        "file_count": len(files),
        "included_roots": list(PACKAGE_DIRECTORIES),
        "excluded_roots": sorted(EXCLUDED_DIRECTORY_NAMES),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=PROJECT_ROOT / "oci-log-analytics-deployment.zip")
    args = parser.parse_args()
    manifest = build_package(PROJECT_ROOT, args.out.resolve())
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
