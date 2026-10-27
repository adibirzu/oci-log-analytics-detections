#!/usr/bin/env python3
"""Build a customer-safe OCI Resource Manager deployment package.

The package intentionally contains deployment code and generated detection content,
but never disposable test data, local credentials, or Terraform working state.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import posixpath
import re
import stat
import subprocess
import sys
import sysconfig
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Mapping


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_SCHEMA_VERSION = "1.0.0"
SOURCE_INVENTORY = ".orm-source-inventory.json"
SOURCE_INVENTORY_SCHEMA = "forge.orm-source-inventory.v1"
STANDARD_MODULES = getattr(sys, "stdlib_module_names", None)
if STANDARD_MODULES is None:  # The staged CLI also runs on system Python 3.9.
    STANDARD_MODULES = set(sys.builtin_module_names) | {
        path.stem for path in Path(sysconfig.get_path("stdlib")).iterdir()
        if path.suffix == ".py" or path.is_dir()
    }
REQUIRED_PATHS = (
    "requirements.txt",
    "stack/main.tf",
    "stack/provider.tf",
    "stack/provisioners.tf",
    "stack/schema.yaml",
    "stack/variables.tf",
    "scripts/deploy_dashboard.py",
    "scripts/setup_log_sources.py",
    "scripts/ingest_test_data.py",
    "queries/dashboard_inventory.json",
    "queries/splunk_detection_registry.json",
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
        _checked_source(project_root, relative_path)


def _relative_source(name: str) -> PurePosixPath:
    if not isinstance(name, str) or not name or "\0" in name or "\\" in name:
        raise ValueError("Invalid deployment source path")
    relative = PurePosixPath(name)
    if relative.is_absolute() or ".." in relative.parts or relative.as_posix() != name or not relative.parts:
        raise ValueError("Deployment source path must be canonical and relative")
    return relative


def _checked_source(project_root: Path, name: str) -> Path:
    relative = _relative_source(name)
    current = project_root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"Deployment source symlink refused: {name}")
    try:
        mode = current.stat().st_mode
    except FileNotFoundError:
        raise FileNotFoundError(f"Selected deployment dependency is missing: {name}") from None
    if not stat.S_ISREG(mode):
        raise ValueError(f"Deployment source must be a regular file: {name}")
    return current


def _is_included_file(path: Path, project_root: Path) -> bool:
    relative = path.relative_to(project_root)
    if path.is_symlink() or not path.is_file():
        return False
    if any(part in EXCLUDED_DIRECTORY_NAMES for part in relative.parts):
        return False
    if any(part.startswith(".env") or ".local." in part for part in relative.parts):
        return False
    if (path.suffix in {".pem", ".key", ".p12", ".pfx", ".tfstate", ".tfvars"}
            or ".tfstate." in path.name or path.name.endswith(".tfvars.json")):
        return False
    return path.suffix not in EXCLUDED_SUFFIXES


def _package_contents(project_root: Path, source_inventory: Mapping | None = None) -> dict[str, bytes]:
    if project_root.is_symlink():
        raise ValueError("Deployment source root must not be a symlink")
    inventory_path = project_root / SOURCE_INVENTORY
    if source_inventory is None and (inventory_path.exists() or inventory_path.is_symlink()):
        path = _checked_source(project_root, SOURCE_INVENTORY)
        if path.stat().st_size > 2 * 1024 * 1024:
            raise ValueError("Deployment source inventory exceeds size limit")
        source_inventory = json.loads(path.read_bytes())
    if source_inventory is None:
        top = subprocess.run(["git", "-C", str(project_root), "rev-parse", "--show-toplevel"],
                             check=True, capture_output=True, text=True)
        if Path(top.stdout.strip()).resolve() != project_root.resolve():
            raise ValueError("Deployment source must be the tracked repository root")
        result = subprocess.run(
            ["git", "-C", str(project_root), "ls-files", "--cached", "-z"],
            check=True, capture_output=True,
        )
        selected = dict.fromkeys(result.stdout.decode("utf-8").rstrip("\0").split("\0"))
    else:
        if (not isinstance(source_inventory, Mapping) or set(source_inventory) != {"schema_version", "files"}
                or source_inventory["schema_version"] != SOURCE_INVENTORY_SCHEMA
                or not isinstance(source_inventory["files"], dict)):
            raise ValueError("Invalid deployment source inventory")
        selected = source_inventory["files"]
        if any(not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest) for digest in selected.values()):
            raise ValueError("Invalid deployment source digest")
    if not selected or len(selected) > 30000:
        raise ValueError("Invalid deployment source inventory size")
    if set(REQUIRED_PATHS) - set(selected):
        raise FileNotFoundError("Required deployment package file is not in the reviewed source inventory")
    contents = {}
    size = 0
    for name in sorted(selected):
        relative = _relative_source(name)
        if relative.parts[0] not in PACKAGE_DIRECTORIES and name not in REQUIRED_PATHS:
            if source_inventory is not None:
                raise ValueError("Source inventory contains an unsupported deployment root")
            continue
        path = _checked_source(project_root, name)
        if not _is_included_file(path, project_root):
            if source_inventory is not None or path.name.endswith(".tfvars.json"):
                raise ValueError("Source inventory contains a private or excluded deployment file")
            continue
        if path.stat().st_size > 16 * 1024 * 1024:
            raise ValueError("Deployment source file exceeds size limit")
        with path.open("rb") as source:
            data = source.read(16 * 1024 * 1024 + 1)
        size += len(data)
        if len(data) > 16 * 1024 * 1024 or size > 256 * 1024 * 1024:
            raise ValueError("Deployment source contents exceed size limit")
        if selected[name] is not None and hashlib.sha256(data).hexdigest() != selected[name]:
            raise ValueError(f"Deployment source digest mismatch: {name}")
        contents[name] = data
    _validate_executable_closure(contents, project_root)
    return contents


def _validate_executable_closure(contents: dict[str, bytes], project_root: Path) -> None:
    """Check local imports and literal Terraform dependencies without importing code."""
    def require_query(reference):
        name = "queries/" + _relative_source(reference).as_posix()
        if name not in contents:
            raise FileNotFoundError(f"Unpackaged dashboard query dependency: {name}")

    def check_query_references(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "query_file":
                    require_query(item)
                else:
                    check_query_references(item)
        elif isinstance(value, list):
            for item in value:
                check_query_references(item)

    check_query_references(json.loads(contents["queries/dashboard_inventory.json"]))
    pending = [name for name in REQUIRED_PATHS if name.endswith(".py")]
    seen = set()
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        tree = ast.parse(contents[name], filename=name)
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values):
                    if (isinstance(key, ast.Constant) and key.value == "query_file"
                            and isinstance(value, ast.Constant) and isinstance(value.value, str)):
                        require_query(value.value)
            modules = []
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                parts = []
                if node.level:
                    parts = list(PurePosixPath(name).parts[1:-1])
                    if node.level > len(parts) + 1:
                        raise ValueError("Deployment import escapes the scripts root")
                    parts = parts[:len(parts) - node.level + 1]
                if node.module:
                    parts.extend(node.module.split("."))
                base = ".".join(parts)
                modules = [base] if base else []
                modules.extend(".".join(parts + [alias.name]) for alias in node.names)
            for module in modules:
                path = "scripts/" + module.replace(".", "/")
                candidates = (path + ".py", path + "/__init__.py")
                local = next((candidate for candidate in candidates
                              if candidate in contents or (project_root / candidate).exists()), None)
                if local:
                    parent = PurePosixPath(local).parent
                    dependencies = [local]
                    while parent.as_posix() != "scripts":
                        dependencies.append((parent / "__init__.py").as_posix())
                        parent = parent.parent
                    for dependency in dependencies:
                        if dependency not in contents:
                            raise FileNotFoundError(f"Unpackaged deployment import dependency: {dependency}")
                        pending.append(dependency)
                elif module.split(".")[0] not in STANDARD_MODULES | {"oci", "yaml", "dotenv"}:
                    # Names imported from a known local module can be attributes.
                    if not any(module.startswith(parent_module + ".") for parent_module in modules
                               if parent_module != module):
                        raise FileNotFoundError(f"Unresolved deployment import: {module}")

    for name, data in contents.items():
        if not name.endswith(".tf"):
            continue
        text = data.decode("utf-8")
        references = re.findall(r'(?:file|templatefile)\s*\(\s*"\$\{path.module\}/([^"\n]+)"', text)
        for reference in references:
            resolved = posixpath.normpath(posixpath.join(posixpath.dirname(name), reference))
            if resolved.startswith("../") or resolved.startswith("/") or resolved not in contents:
                raise FileNotFoundError(f"Unpackaged Terraform file dependency: {resolved}")
        for module in re.findall(r'\bsource\s*=\s*"(\.[^"\n]+)"', text):
            resolved = posixpath.normpath(posixpath.join(posixpath.dirname(name), module))
            if resolved.startswith("../") or not any(path.startswith(resolved + "/") and path.endswith(".tf") for path in contents):
                raise FileNotFoundError(f"Unpackaged Terraform module dependency: {resolved}")


def build_package(project_root: Path, output_path: Path, *, source_inventory: Mapping | None = None) -> dict[str, object]:
    """Package tracked working bytes or a hash-bound exported-tree inventory."""
    if output_path.is_symlink():
        raise ValueError("Deployment output must not be a symlink")
    _validate_required_paths(project_root)
    contents = _package_contents(project_root, source_inventory)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".orm-", suffix=".zip", dir=output_path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
                for name, data in sorted(contents.items()):
                    member = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                    member.create_system = 3
                    member.external_attr = 0o100644 << 16
                    member.compress_type = zipfile.ZIP_DEFLATED
                    archive.writestr(member, data, compresslevel=9)
        os.replace(temporary_path, output_path)
    finally:
        temporary_path.unlink(missing_ok=True)

    return {
        "schema_version": PACKAGE_SCHEMA_VERSION,
        "output": output_path.name,
        "file_count": len(contents),
        "included_roots": list(PACKAGE_DIRECTORIES),
        "excluded_roots": sorted(EXCLUDED_DIRECTORY_NAMES),
    }


def stage_runtime(project_root: Path, destination: Path, *, include_runtime_manifest: bool = False) -> dict[str, object]:
    """Export selected deployment sources and their verified byte inventory for Forge."""
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("Runtime export destination must be absent")
    _validate_required_paths(project_root)
    contents = _package_contents(project_root)
    metadata = None
    if include_runtime_manifest:
        manifest_path = _checked_source(project_root, "test_data/manifest.json")
        if manifest_path.stat().st_size > 16 * 1024 * 1024:
            raise ValueError("Runtime metadata exceeds size limit")
        metadata = manifest_path.read_bytes()
    destination.mkdir(parents=True, mode=0o700)
    for name, data in contents.items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    inventory = {"schema_version": SOURCE_INVENTORY_SCHEMA,
                 "files": {name: hashlib.sha256(data).hexdigest() for name, data in sorted(contents.items())}}
    (destination / SOURCE_INVENTORY).write_text(json.dumps(inventory, sort_keys=True, separators=(",", ":")))
    if metadata is not None:
        (destination / "test_data").mkdir()
        (destination / "test_data/manifest.json").write_bytes(metadata)
    return {"schema_version": SOURCE_INVENTORY_SCHEMA, "file_count": len(contents)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=PROJECT_ROOT / "oci-log-analytics-deployment.zip")
    parser.add_argument("--stage-runtime", type=Path)
    parser.add_argument("--include-runtime-manifest", action="store_true")
    args = parser.parse_args()
    if args.include_runtime_manifest and not args.stage_runtime:
        parser.error("--include-runtime-manifest requires --stage-runtime")
    manifest = (stage_runtime(PROJECT_ROOT, args.stage_runtime.absolute(), include_runtime_manifest=args.include_runtime_manifest) if args.stage_runtime
                else build_package(PROJECT_ROOT, args.out.absolute()))
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
