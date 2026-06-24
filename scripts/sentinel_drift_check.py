#!/usr/bin/env python3
"""Detect drift across promoted Sentinel files, report metadata, and parser schema.

This is an offline gate. It does not call OCI; it verifies that promoted
``queries/sentinel/*.json`` files remain reconciled with the conversion report
and the current parser/display-field dictionary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_DIR = Path(__file__).resolve().parent.parent
SENTINEL_DIR = PROJECT_DIR / "queries" / "sentinel"
REPORT_PATH = PROJECT_DIR / "queries" / "sentinel_conversion_report.json"
DICTIONARY_PATH = PROJECT_DIR / "queries" / "log_source_field_dictionary.json"
OUTPUT_PATH = PROJECT_DIR / "queries" / "sentinel_drift.json"
SYNTHETIC_LIVE_RESULTS_PATH = PROJECT_DIR / "queries" / "sentinel_synthetic_live_results.json"
SYNTHETIC_PLAN_PATH = PROJECT_DIR / "queries" / "sentinel_synthetic_plan.json"


def _read_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def stable_json_hash(payload: Any) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def parser_schema_hash(dictionary_path: Path = DICTIONARY_PATH) -> str:
    payload = {
        key: value
        for key, value in _read_json(dictionary_path).items()
        if key != "generated_at"
    }
    return stable_json_hash(payload)


def query_body_hash(query: str) -> str:
    return hashlib.sha256(query.encode("utf-8")).hexdigest()


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(PROJECT_DIR))
    except ValueError:
        return str(path.relative_to(root.parent))


def load_promoted_files(sentinel_dir: Path = SENTINEL_DIR) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in sorted(sentinel_dir.glob("*.json")):
        payload = _read_json(path)
        records.append({
            "path": _relative(path, sentinel_dir),
            "title": payload.get("title", ""),
            "sentinel_id": payload.get("sentinel_id", ""),
            "output_file": f"sentinel/{path.name}",
            "live_validation_status": payload.get("live_validation_status", ""),
            "parser_schema_hash": payload.get("parser_schema_hash", ""),
            "query_hash": query_body_hash(str(payload.get("query", ""))),
        })
    return records


def load_report_promotions(report_path: Path = REPORT_PATH) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    report = _read_json(report_path)
    promoted: dict[str, dict[str, Any]] = {}
    for item in report.get("attempted", []):
        output_file = item.get("output_file")
        if output_file:
            promoted[str(output_file)] = item
    return report, promoted


def load_baseline(path: Path | None) -> dict[str, dict[str, Any]]:
    if not path or not path.exists():
        return {}
    payload = _read_json(path)
    records = payload.get("current", [])
    if not isinstance(records, list):
        return {}
    return {str(item.get("path", "")): item for item in records if item.get("path")}


def load_synthetic_hits(path: Path | None) -> set[str]:
    if not path or not path.exists():
        return set()
    payload = _read_json(path)
    return {
        str(item.get("sentinel_id", ""))
        for item in payload.get("results", [])
        if item.get("ok") and int(item.get("rows", 0) or 0) > 0 and item.get("sentinel_id")
    }


def load_synthetic_plan_statuses(path: Path | None) -> dict[str, dict[str, Any]]:
    if not path or not path.exists():
        return {}
    payload = _read_json(path)
    statuses: dict[str, dict[str, Any]] = {}
    for item in payload.get("candidates", []):
        sentinel_id = item.get("sentinel_id")
        if sentinel_id:
            statuses[str(sentinel_id)] = item
    return statuses


def try_load_git_baseline(ref: str) -> dict[str, dict[str, Any]]:
    if not ref:
        return {}
    try:
        result = subprocess.run(
            ["git", "show", f"{ref}:queries/sentinel_drift.json"],
            cwd=PROJECT_DIR,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    if result.returncode != 0 or not result.stdout.strip():
        return {}
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {}
    return {
        str(item.get("path", "")): item
        for item in payload.get("current", [])
        if item.get("path")
    }


def build_drift_report(
    *,
    sentinel_dir: Path = SENTINEL_DIR,
    report_path: Path = REPORT_PATH,
    dictionary_path: Path = DICTIONARY_PATH,
    baseline_path: Path | None = None,
    baseline_ref: str = "",
    synthetic_live_results_path: Path | None = SYNTHETIC_LIVE_RESULTS_PATH,
    synthetic_plan_path: Path | None = SYNTHETIC_PLAN_PATH,
    require_synthetic_hits: bool = False,
) -> dict[str, Any]:
    current_hash = parser_schema_hash(dictionary_path)
    current = load_promoted_files(sentinel_dir)
    report, report_promotions = load_report_promotions(report_path)
    baseline = load_baseline(baseline_path) or try_load_git_baseline(baseline_ref)
    synthetic_hits = load_synthetic_hits(synthetic_live_results_path)
    synthetic_plan_statuses = load_synthetic_plan_statuses(synthetic_plan_path)

    file_by_output = {item["output_file"]: item for item in current}
    file_by_path = {item["path"]: item for item in current}
    drift: list[dict[str, Any]] = []
    synthetic_hit_gaps: list[dict[str, Any]] = []

    summary = report.get("summary", {})
    if int(summary.get("promoted_count", 0) or 0) != len(current):
        drift.append({
            "severity": "error",
            "type": "promoted_count_mismatch",
            "detail": f"report promoted_count={summary.get('promoted_count')} files={len(current)}",
        })

    if int(summary.get("live_validation_passed", 0) or 0) != len(current):
        drift.append({
            "severity": "error",
            "type": "live_passed_count_mismatch",
            "detail": f"report live_validation_passed={summary.get('live_validation_passed')} files={len(current)}",
        })

    for output_file in sorted(set(report_promotions) - set(file_by_output)):
        drift.append({
            "severity": "error",
            "type": "report_promoted_file_missing",
            "path": f"queries/{output_file}",
        })

    for output_file in sorted(set(file_by_output) - set(report_promotions)):
        drift.append({
            "severity": "error",
            "type": "sentinel_file_missing_from_report",
            "path": f"queries/{output_file}",
        })

    for record in current:
        if record["live_validation_status"] != "passed":
            drift.append({
                "severity": "error",
                "type": "promoted_file_not_live_passed",
                "path": record["path"],
                "live_validation_status": record["live_validation_status"],
            })
        if not record["parser_schema_hash"]:
            drift.append({
                "severity": "error",
                "type": "missing_parser_schema_hash",
                "path": record["path"],
            })
        elif record["parser_schema_hash"] != current_hash:
            drift.append({
                "severity": "error",
                "type": "parser_schema_hash_mismatch",
                "path": record["path"],
                "expected": current_hash,
                "actual": record["parser_schema_hash"],
            })
        if require_synthetic_hits and record["sentinel_id"] not in synthetic_hits:
            drift.append({
                "severity": "error",
                "type": "missing_synthetic_live_hit",
                "path": record["path"],
                "sentinel_id": record["sentinel_id"],
            })
        if record["sentinel_id"] not in synthetic_hits:
            report_record = report_promotions.get(record["output_file"], {})
            plan_record = synthetic_plan_statuses.get(record["sentinel_id"], {})
            synthetic_hit_gaps.append({
                "path": record["path"],
                "title": record["title"],
                "sentinel_id": record["sentinel_id"],
                "source_path": report_record.get("source_path", ""),
                "synthetic_plan_status": plan_record.get("status", "not_planned"),
                "selected_source": plan_record.get("selected_source", ""),
                "required_fields": plan_record.get("required_fields", []),
                "gap_reasons": plan_record.get("gap_reasons", plan_record.get("skip_reasons", [])),
            })

    for path, baseline_record in sorted(baseline.items()):
        current_record = file_by_path.get(path)
        if not current_record:
            drift.append({"severity": "error", "type": "baseline_promoted_file_removed", "path": path})
            continue
        if baseline_record.get("live_validation_status") == "passed" and current_record.get("live_validation_status") != "passed":
            drift.append({
                "severity": "error",
                "type": "baseline_live_status_regressed",
                "path": path,
                "baseline": baseline_record.get("live_validation_status"),
                "current": current_record.get("live_validation_status"),
            })
        if baseline_record.get("query_hash") and baseline_record.get("query_hash") != current_record.get("query_hash"):
            drift.append({
                "severity": "error",
                "type": "baseline_query_hash_changed",
                "path": path,
                "baseline": baseline_record.get("query_hash"),
                "current": current_record.get("query_hash"),
            })

    error_count = sum(1 for item in drift if item.get("severity") == "error")
    return {
        "version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "parser_schema_hash": current_hash,
        "summary": {
            "promoted_files": len(current),
            "report_promoted_count": int(summary.get("promoted_count", 0) or 0),
            "report_live_validation_passed": int(summary.get("live_validation_passed", 0) or 0),
            "baseline_records": len(baseline),
            "synthetic_live_hit_count": len(synthetic_hits),
            "promoted_without_synthetic_hit": max(0, len(current) - len(synthetic_hits)),
            "synthetic_hit_gate_required": require_synthetic_hits,
            "drift_count": len(drift),
            "error_count": error_count,
        },
        "current": current,
        "synthetic_hit_gaps": synthetic_hit_gaps,
        "drift": drift,
    }


def write_parser_schema_hashes(
    *,
    sentinel_dir: Path = SENTINEL_DIR,
    dictionary_path: Path = DICTIONARY_PATH,
) -> int:
    current_hash = parser_schema_hash(dictionary_path)
    changed = 0
    for path in sorted(sentinel_dir.glob("*.json")):
        payload = _read_json(path)
        if payload.get("parser_schema_hash") == current_hash:
            continue
        payload = {**payload, "parser_schema_hash": current_hash}
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        changed += 1
    return changed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sentinel-dir", default=str(SENTINEL_DIR))
    parser.add_argument("--report", default=str(REPORT_PATH))
    parser.add_argument("--dictionary", default=str(DICTIONARY_PATH))
    parser.add_argument("--output", default=str(OUTPUT_PATH))
    parser.add_argument("--baseline", default="", help="Optional previous sentinel_drift.json path")
    parser.add_argument("--baseline-ref", default="", help="Optional git ref containing queries/sentinel_drift.json")
    parser.add_argument("--synthetic-live-results", default=str(SYNTHETIC_LIVE_RESULTS_PATH))
    parser.add_argument("--synthetic-plan", default=str(SYNTHETIC_PLAN_PATH))
    parser.add_argument("--require-synthetic-hits", action="store_true", help="Require every promoted Sentinel file to have non-empty synthetic live-hit evidence")
    parser.add_argument("--write-hashes", action="store_true", help="Stamp promoted Sentinel files with current parser_schema_hash before checking")
    parser.add_argument("--json", action="store_true", help="Print the full drift report JSON")
    args = parser.parse_args()

    sentinel_dir = Path(args.sentinel_dir)
    dictionary_path = Path(args.dictionary)
    if args.write_hashes:
        changed = write_parser_schema_hashes(sentinel_dir=sentinel_dir, dictionary_path=dictionary_path)
        print(f"Stamped parser_schema_hash on {changed} promoted Sentinel file(s).")

    report = build_drift_report(
        sentinel_dir=sentinel_dir,
        report_path=Path(args.report),
        dictionary_path=dictionary_path,
        baseline_path=Path(args.baseline) if args.baseline else None,
        baseline_ref=args.baseline_ref,
        synthetic_live_results_path=Path(args.synthetic_live_results),
        synthetic_plan_path=Path(args.synthetic_plan),
        require_synthetic_hits=args.require_synthetic_hits,
    )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        summary = report["summary"]
        print(
            "Sentinel drift check: "
            f"files={summary['promoted_files']} "
            f"drift={summary['drift_count']} errors={summary['error_count']} "
            f"output={output_path}"
        )
        for item in report["drift"][:20]:
            path = f" {item.get('path')}" if item.get("path") else ""
            print(f"  [{item['severity']}] {item['type']}{path}")

    return 1 if report["summary"]["error_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
