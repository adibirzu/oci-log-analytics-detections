#!/usr/bin/env python3
"""Generate or verify the deterministic OCI Log Analytics content import manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from query_artifacts import is_saved_search_query_file

ROOT = SCRIPTS_DIR.parent
DEFAULT_OUTPUT_REL = Path("queries/content_manifest.json")
SCHEMA_REL = Path("schemas/content_manifest.schema.json")
SCHEMA_VERSION = "1.0.0"
MANIFEST_ID = "oci-log-analytics-detections-content"
GENERATOR = "scripts/generate_content_manifest.py"


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_canonical(value: object) -> str:
    return _sha256_bytes(_canonical_bytes(value))


def _query_surface(rel_to_queries: Path) -> str:
    if len(rel_to_queries.parts) > 1 and rel_to_queries.parts[0] in {"apps", "hunting", "sentinel"}:
        return rel_to_queries.parts[0]
    return "base"


def _collect_queries(root: Path) -> list[dict[str, Any]]:
    queries_dir = root / "queries"
    if not queries_dir.exists():
        return []
    entries: list[dict[str, Any]] = []
    for path in sorted(queries_dir.rglob("*.json")):
        if not path.is_file() or not is_saved_search_query_file(path):
            continue
        raw = path.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
        rel_queries = path.relative_to(queries_dir)
        logsource = payload.get("logsource")
        product = logsource.get("product", "") if isinstance(logsource, dict) else ""
        entries.append(
            {
                "path": path.relative_to(root).as_posix(),
                "surface": _query_surface(rel_queries),
                "title": str(payload.get("title", "")),
                "level": str(payload.get("level", "")),
                "logsource_product": str(product or ""),
                "sha256": _sha256_bytes(raw),
            }
        )
    return entries


def _collect_rules(root: Path) -> list[dict[str, Any]]:
    rules_dir = root / "rules"
    if not rules_dir.exists():
        return []
    entries: list[dict[str, Any]] = []
    for path in sorted(rules_dir.rglob("*")):
        if not path.is_file() or path.suffix not in {".yaml", ".yml"}:
            continue
        raw = path.read_bytes()
        payload = yaml.safe_load(raw.decode("utf-8")) or {}
        if not isinstance(payload, dict):
            msg = f"Expected YAML mapping in {path.relative_to(root).as_posix()}"
            raise TypeError(msg)
        rel_rules = path.relative_to(rules_dir)
        domain = rel_rules.parts[0] if rel_rules.parts else "unknown"
        entries.append(
            {
                "path": path.relative_to(root).as_posix(),
                "domain": domain,
                "id": str(payload.get("id", "")),
                "title": str(payload.get("title", "")),
                "level": str(payload.get("level", "")),
                "sha256": _sha256_bytes(raw),
            }
        )
    return entries


def _collect_packs(root: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []

    hunting_packs_path = root / "config" / "hunting_packs.json"
    if hunting_packs_path.is_file():
        payload = json.loads(hunting_packs_path.read_text(encoding="utf-8"))
        for pack in payload.get("packs", []):
            entries.append(
                {
                    "id": str(pack.get("id", "")),
                    "title": str(pack.get("title", "")),
                    "source_type": "hunting_pack",
                    "path": "config/hunting_packs.json",
                    "query_paths": sorted(str(item) for item in pack.get("query_paths", [])),
                    "sha256": _sha256_canonical(pack),
                }
            )

    packs_dir = root / "packs"
    if packs_dir.exists():
        for manifest_path in sorted(packs_dir.glob("*/manifest.json")):
            raw = manifest_path.read_bytes()
            payload = json.loads(raw.decode("utf-8"))
            query_paths = sorted(
                str(cap.get("query_file", ""))
                for cap in payload.get("capabilities_replicated", [])
                if isinstance(cap, dict) and cap.get("query_file")
            )
            entries.append(
                {
                    "id": str(payload.get("pack_id", manifest_path.parent.name)),
                    "title": str(payload.get("title", "")),
                    "source_type": "pack_manifest",
                    "path": manifest_path.relative_to(root).as_posix(),
                    "query_paths": query_paths,
                    "sha256": _sha256_bytes(raw),
                }
            )

        for report_pack in sorted(packs_dir.rglob("*")):
            if not report_pack.is_file() or report_pack.suffix not in {".yaml", ".yml"}:
                continue
            raw = report_pack.read_bytes()
            payload = yaml.safe_load(raw.decode("utf-8")) or {}
            if not isinstance(payload, dict):
                msg = f"Expected YAML mapping in {report_pack.relative_to(root).as_posix()}"
                raise TypeError(msg)
            title = str(payload.get("title") or payload.get("name") or report_pack.stem)
            query_path_set: set[str] = set()
            for section in ("hunts", "queries", "days"):
                items = payload.get(section)
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, dict) and item.get("query_file"):
                            query_path_set.add(str(item["query_file"]))
            query_paths = sorted(query_path_set)
            entries.append(
                {
                    "id": str(payload.get("pack_id") or payload.get("id") or report_pack.stem),
                    "title": title,
                    "source_type": "threat_report_pack",
                    "path": report_pack.relative_to(root).as_posix(),
                    "query_paths": query_paths,
                    "sha256": _sha256_bytes(raw),
                }
            )

    entries.sort(key=lambda item: (item["source_type"], item["id"], item["path"]))
    return entries


def _collect_dashboards(root: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []

    inventory_path = root / "queries" / "dashboard_inventory.json"
    if inventory_path.is_file():
        inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
        for dashboard in inventory.get("dashboards", []):
            widgets = dashboard.get("widgets", [])
            query_files = sorted(
                {
                    str(widget["query_file"])
                    for widget in widgets
                    if isinstance(widget, dict) and widget.get("query_file")
                }
            )
            entries.append(
                {
                    "name": str(dashboard.get("name", "")),
                    "source": "queries/dashboard_inventory.json",
                    "widget_count": int(dashboard.get("widget_count", len(widgets))),
                    "query_files": query_files,
                    "sha256": _sha256_canonical(dashboard),
                }
            )

    dashboards_dir = root / "dashboards"
    if dashboards_dir.exists():
        for path in sorted(dashboards_dir.glob("*.json")):
            raw = path.read_bytes()
            payload = json.loads(raw.decode("utf-8"))
            raw_widgets = payload.get("widgets")
            if isinstance(raw_widgets, list):
                widgets = raw_widgets
            elif isinstance(payload.get("tiles"), list):
                widgets = payload["tiles"]
            else:
                widgets = []
            query_files = sorted(
                {
                    str(widget.get("query_file") or widget.get("queryFile"))
                    for widget in widgets
                    if isinstance(widget, dict)
                    and (widget.get("query_file") or widget.get("queryFile"))
                }
            )
            entries.append(
                {
                    "name": str(payload.get("name") or payload.get("displayName") or path.stem),
                    "source": path.relative_to(root).as_posix(),
                    "widget_count": len(widgets),
                    "query_files": query_files,
                    "sha256": _sha256_bytes(raw),
                }
            )

    entries.sort(key=lambda item: (item["source"], item["name"]))
    return entries


def build_content_manifest(root: Path = ROOT) -> dict[str, Any]:
    """Build the deterministic Log Analytics content import manifest."""
    queries = _collect_queries(root)
    rules = _collect_rules(root)
    packs = _collect_packs(root)
    dashboards = _collect_dashboards(root)

    queries_by_surface = dict(sorted(Counter(item["surface"] for item in queries).items()))
    rules_by_domain = dict(sorted(Counter(item["domain"] for item in rules).items()))

    manifest: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "manifest_id": MANIFEST_ID,
        "generator": GENERATOR,
        "summary": {
            "total_queries": len(queries),
            "queries_by_surface": queries_by_surface,
            "total_rules": len(rules),
            "rules_by_domain": rules_by_domain,
            "total_packs": len(packs),
            "total_dashboards": len(dashboards),
            "total_dashboard_widgets": sum(item["widget_count"] for item in dashboards),
        },
        "surface_digests": {
            "queries": _sha256_canonical(queries),
            "rules": _sha256_canonical(rules),
            "packs": _sha256_canonical(packs),
            "dashboards": _sha256_canonical(dashboards),
        },
        "queries": queries,
        "rules": rules,
        "packs": packs,
        "dashboards": dashboards,
    }
    manifest["content_digest"] = compute_content_digest(manifest)
    return manifest


def compute_content_digest(manifest: dict[str, Any]) -> str:
    """Compute the deterministic top-level SHA-256 digest excluding content_digest."""
    return _sha256_canonical({key: value for key, value in manifest.items() if key != "content_digest"})


def validate_content_manifest(manifest: object, *, schema: dict[str, Any] | None = None) -> list[str]:
    """Validate a content manifest against the repository schema and digest contract."""
    if schema is None:
        schema = json.loads((ROOT / SCHEMA_REL).read_text(encoding="utf-8"))
    errors: list[str] = []

    def visit(value: object, rule: dict[str, Any], location: str) -> None:
        kind = rule.get("type")
        type_map = {"object": dict, "array": list, "string": str, "integer": int}
        if kind:
            expected_type = type_map[kind]
            if kind == "integer":
                if isinstance(value, bool) or not isinstance(value, int):
                    errors.append(f"{location}: invalid integer")
                    return
            elif not isinstance(value, expected_type):
                errors.append(f"{location}: invalid type")
                return
        if "const" in rule and value != rule["const"]:
            errors.append(f"{location}: invalid constant")
        if "enum" in rule and value not in rule["enum"]:
            errors.append(f"{location}: invalid enum")
        if isinstance(value, int) and not isinstance(value, bool) and "minimum" in rule and value < rule["minimum"]:
            errors.append(f"{location}: below minimum")
        if isinstance(value, str) and "pattern" in rule and not re.search(rule["pattern"], value):
            errors.append(f"{location}: invalid pattern")
        if isinstance(value, dict):
            props = rule.get("properties", {})
            for req in rule.get("required", []):
                if req not in value:
                    errors.append(f"{location}: missing {req}")
            for key, item in value.items():
                if key in props:
                    visit(item, props[key], f"{location}.{key}")
                elif rule.get("additionalProperties") is False:
                    errors.append(f"{location}: unexpected {key}")
                elif isinstance(rule.get("additionalProperties"), dict):
                    visit(item, rule["additionalProperties"], f"{location}.{key}")
        if isinstance(value, list) and "items" in rule:
            for idx, item in enumerate(value):
                visit(item, rule["items"], f"{location}[{idx}]")

    visit(manifest, schema, "manifest")
    if isinstance(manifest, dict) and not errors and manifest.get("content_digest") != compute_content_digest(manifest):
        errors.append("manifest.content_digest: digest mismatch")
    return errors


def encoded_manifest(manifest: dict[str, Any]) -> bytes:
    """Serialize the manifest deterministically with sorted keys and trailing newline."""
    return (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="Write deterministic content manifest.")
    mode.add_argument("--check", action="store_true", help="Verify checked-in content manifest matches repo state.")
    parser.add_argument("--root", type=Path, default=ROOT, help="Repository root directory.")
    parser.add_argument("--output", type=Path, default=None, help="Override manifest output path.")
    args = parser.parse_args(argv)

    root = args.root.resolve()
    output_path = args.output.resolve() if args.output else root / DEFAULT_OUTPUT_REL
    schema_path = root / SCHEMA_REL if (root / SCHEMA_REL).is_file() else ROOT / SCHEMA_REL
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    try:
        manifest = build_content_manifest(root)
        errors = validate_content_manifest(manifest, schema=schema)
        if errors:
            raise ValueError("; ".join(errors))
        data = encoded_manifest(manifest)
        if args.write:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(data)
        elif not output_path.is_file() or output_path.read_bytes() != data:
            print(
                "Content manifest missing or out of date. Run python3 scripts/generate_content_manifest.py --write.",
                file=sys.stderr,
            )
            return 1
    except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError) as error:
        print(f"Content manifest generation failed: {error}", file=sys.stderr)
        return 1

    action = "generated" if args.write else "verified"
    print(
        f"Content manifest {action}: {output_path.relative_to(root) if output_path.is_relative_to(root) else output_path} "
        f"(queries={manifest['summary']['total_queries']}, rules={manifest['summary']['total_rules']}, "
        f"packs={manifest['summary']['total_packs']}, dashboards={manifest['summary']['total_dashboards']}, "
        f"digest={manifest['content_digest'][:16]})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
