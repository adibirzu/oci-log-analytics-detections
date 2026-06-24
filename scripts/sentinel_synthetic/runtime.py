"""Runtime upload, live validation, and promotion helpers for Sentinel synthetic logs."""

from __future__ import annotations

import io
import json
import os
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
PROJECT_DIR = SCRIPTS_DIR.parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from convert_sentinel_kql import (  # noqa: E402
    ConversionResult,
    _clean_output_dir,
    _write_query_payload,
    build_conversion_report,
    convert_candidate,
    load_mapping_config,
    slugify_title,
)
from oci_config import (  # noqa: E402
    LOG_GROUP_ID,
    ensure_log_group,
    get_la_client,
    get_namespace,
    list_available_log_sources,
    resolve_compartment_id,
    resolve_source_from_candidates,
)

from sentinel_synthetic.planning import (  # noqa: E402
    DEFAULT_CANDIDATES_FILE,
    _emit_progress,
    _read_json,
    _safe_live_error,
    load_candidates,
)

DEFAULT_LIVE_RESULTS_PATH = PROJECT_DIR / "queries" / "sentinel_synthetic_live_results.json"
DEFAULT_SENTINEL_OUTPUT_DIR = PROJECT_DIR / "queries" / "sentinel"
DEFAULT_CONVERSION_REPORT_PATH = PROJECT_DIR / "queries" / "sentinel_conversion_report.json"


def _upload_file(la_client, namespace: str, log_group_id: str, file_path: Path, source_name: str) -> dict[str, Any]:
    with file_path.open("rb") as handle:
        body = io.BytesIO(handle.read())
    response = la_client.upload_log_file(
        namespace_name=namespace,
        upload_name=f"sentinel-synthetic-{file_path.stem}",
        log_source_name=source_name,
        filename=file_path.name,
        opc_meta_loggrpid=log_group_id,
        upload_log_file_body=body,
        content_type="application/octet-stream",
        char_encoding="UTF-8",
    )
    return {
        "filename": file_path.name,
        "source": source_name,
        "status": response.status,
    }


def upload_synthetic_plan(plan_path: Path, data_dir: Path, dry_run: bool = False) -> dict[str, Any]:
    """Upload generated synthetic files using their selected source contracts."""
    plan = _read_json(plan_path)
    ready_by_file: dict[str, set[str]] = defaultdict(set)
    for candidate in plan.get("candidates", []):
        if candidate.get("status") == "synthetic_ready" and candidate.get("synthetic_file"):
            ready_by_file[candidate["synthetic_file"]].add(candidate.get("selected_source", ""))

    if dry_run:
        return {
            "dry_run": True,
            "files": [
                {"filename": filename, "sources": sorted(sources)}
                for filename, sources in sorted(ready_by_file.items())
            ],
        }

    _emit_progress("upload-stage client")
    try:
        la_client = get_la_client(timeout=(10, 60))
    except Exception as exc:
        return {"dry_run": False, "stage": "client", "ok": False, "error": _safe_live_error(exc), "uploads": []}

    _emit_progress("upload-stage namespace")
    try:
        namespace = get_namespace(la_client)
    except Exception as exc:
        return {"dry_run": False, "stage": "namespace", "ok": False, "error": _safe_live_error(exc), "uploads": []}

    _emit_progress("upload-stage log-group")
    try:
        log_group_id = LOG_GROUP_ID or ensure_log_group(la_client, namespace)
    except Exception as exc:
        return {"dry_run": False, "stage": "log_group", "ok": False, "error": _safe_live_error(exc), "uploads": []}

    _emit_progress("upload-stage source-discovery")
    try:
        available_sources = list_available_log_sources(la_client, namespace, resolve_compartment_id())
    except Exception as exc:
        return {"dry_run": False, "stage": "source_discovery", "ok": False, "error": _safe_live_error(exc), "uploads": []}

    uploads = []
    for filename, sources in sorted(ready_by_file.items()):
        source_candidates = sorted(source for source in sources if source)
        resolved_source = resolve_source_from_candidates(available_sources, source_candidates)
        if not resolved_source:
            uploads.append({
                "filename": filename,
                "ok": False,
                "error": f"none of the candidate sources exist in OCI: {source_candidates}",
            })
            continue
        file_path = data_dir / filename
        try:
            _emit_progress(f"upload-file filename={filename} source=\"{resolved_source}\"")
            outcome = _upload_file(la_client, namespace, log_group_id, file_path, resolved_source)
            uploads.append({**outcome, "ok": True})
        except Exception as exc:
            uploads.append({"filename": filename, "source": resolved_source, "ok": False, "error": _safe_live_error(exc)})
    return {"dry_run": False, "stage": "upload", "ok": all(item.get("ok") for item in uploads), "uploads": uploads}


def select_ready_candidates(
    plan: dict[str, Any],
    sentinel_ids: set[str] | None = None,
    target_keys: set[tuple[str, str]] | None = None,
) -> list[dict[str, Any]]:
    """Return synthetic-ready plan candidates, optionally limited to IDs or exact candidate keys."""
    selected_ids = sentinel_ids or set()
    selected_keys = target_keys or set()
    ready = [candidate for candidate in plan.get("candidates", []) if candidate.get("status") == "synthetic_ready"]
    if selected_keys:
        return [candidate for candidate in ready if _candidate_key(candidate) in selected_keys]
    if not selected_ids:
        return ready
    return [candidate for candidate in ready if str(candidate.get("sentinel_id", "")) in selected_ids]


def load_sentinel_target_keys_file(path: Path | None) -> set[tuple[str, str]]:
    if not path:
        return set()
    payload = _read_json(path)
    if isinstance(payload.get("synthetic_hit_gaps"), list):
        return {
            (str(item.get("sentinel_id")), str(item.get("source_path", "")))
            for item in payload["synthetic_hit_gaps"]
            if item.get("sentinel_id") and item.get("synthetic_plan_status") == "synthetic_ready"
        }
    return set()


def load_sentinel_ids_file(path: Path | None) -> set[str]:
    if not path:
        return set()
    payload = _read_json(path)
    if isinstance(payload.get("sentinel_ids"), list):
        return {str(item) for item in payload["sentinel_ids"] if item}
    if isinstance(payload.get("synthetic_hit_gaps"), list):
        return {
            str(item.get("sentinel_id"))
            for item in payload["synthetic_hit_gaps"]
            if item.get("sentinel_id") and item.get("synthetic_plan_status") == "synthetic_ready"
        }
    if isinstance(payload.get("drift"), list):
        return {
            str(item.get("sentinel_id"))
            for item in payload["drift"]
            if item.get("sentinel_id") and item.get("type") == "missing_synthetic_live_hit"
        }
    return set()


def export_target_plan(
    *,
    plan_path: Path,
    data_dir: Path,
    out_plan_path: Path,
    out_data_dir: Path,
    sentinel_ids: set[str],
    target_keys: set[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    """Write a filtered synthetic plan and NDJSON files for selected ready IDs."""
    plan = _read_json(plan_path)
    selected = select_ready_candidates(plan, sentinel_ids, target_keys)
    out_data_dir.mkdir(parents=True, exist_ok=True)

    selected_ids = {str(candidate.get("sentinel_id")) for candidate in selected}
    selected_by_file: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for candidate in selected:
        if candidate.get("synthetic_file"):
            selected_by_file[str(candidate["synthetic_file"])].add(_candidate_key(candidate))

    manifest_files = []
    missing_rows = []
    for filename, keys in sorted(selected_by_file.items()):
        source_path = data_dir / filename
        rows = []
        if source_path.exists():
            for line in source_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                row = json.loads(line)
                row_key = (str(row.get("sentinelId", "")), str(row.get("sourcePath", "")))
                if row_key in keys:
                    rows.append(row)
        found_keys = {(str(row.get("sentinelId", "")), str(row.get("sourcePath", ""))) for row in rows}
        missing_rows.extend(f"{sentinel_id}|{source_path}" for sentinel_id, source_path in sorted(keys - found_keys))
        if rows:
            (out_data_dir / filename).write_text(
                "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
                encoding="utf-8",
            )
            manifest_files.append({"filename": filename, "events": len(rows)})

    manifest = {
        "version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "files": manifest_files,
    }
    (out_data_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    report = {
        "version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": plan.get("source", {}),
        "summary": {
            "selected_candidates": len(selected),
            "requested_sentinel_ids": len(sentinel_ids),
            "requested_target_keys": len(target_keys or set()),
            "synthetic_ready": len(selected),
            "missing_rows": len(missing_rows),
            "data_dir": str(out_data_dir.relative_to(PROJECT_DIR) if out_data_dir.is_relative_to(PROJECT_DIR) else out_data_dir),
        },
        "files": manifest_files,
        "missing_rows": missing_rows,
        "candidates": selected,
    }
    out_plan_path.parent.mkdir(parents=True, exist_ok=True)
    out_plan_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return {
        "selected": len(selected),
        "requested_sentinel_ids": len(sentinel_ids),
        "missing_rows": missing_rows,
        "files": manifest_files,
        "plan": str(out_plan_path),
        "data_dir": str(out_data_dir),
        "sentinel_ids": sorted(selected_ids),
    }


def validate_live_plan(
    plan_path: Path,
    *,
    lookback: str,
    timeout: int,
    limit: int,
    sentinel_ids: set[str] | None = None,
    target_keys: set[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    """Run live OCI validation for synthetic-ready candidates in a plan."""
    from deploy_dashboard import resolve_validation_namespace, validate_query_in_oci_isolated

    plan = _read_json(plan_path)
    ready = select_ready_candidates(plan, sentinel_ids, target_keys)
    if limit > 0:
        ready = ready[:limit]
    namespace = resolve_validation_namespace(timeout)
    results = []
    for index, candidate in enumerate(ready, start=1):
        query_file = f"sentinel/{slugify_title(candidate.get('title', 'sentinel-query'))}.json"
        _emit_progress(f"live-start {index}/{len(ready)} title=\"{candidate.get('title', '')[:96]}\"")
        started_at = time.monotonic()
        result = validate_query_in_oci_isolated(
            namespace=namespace,
            query_file=query_file,
            query_string=candidate.get("query", ""),
            lookback=lookback,
            query_timeout=timeout,
        )
        results.append({
            "title": candidate.get("title", ""),
            "sentinel_id": candidate.get("sentinel_id", ""),
            "source_path": candidate.get("source_path", ""),
            "selected_source": candidate.get("selected_source", ""),
            "ok": bool(result.get("ok")),
            "rows": result.get("rows", 0),
            "empty": result.get("empty", False),
            "error": result.get("error", ""),
            "duration_seconds": round(time.monotonic() - started_at, 2),
        })
        _emit_progress(
            f"live-done {index}/{len(ready)} ok={bool(result.get('ok'))} rows={result.get('rows', 0)}"
        )
    return {
        "lookback": lookback,
        "timeout": timeout,
        "tested": len(results),
        "passed": sum(1 for result in results if result["ok"] and not result["empty"]),
        "empty": sum(1 for result in results if result["ok"] and result["empty"]),
        "failed": sum(1 for result in results if not result["ok"]),
        "results": results,
    }


def summarize_live_results(results: list[dict[str, Any]], *, lookback: str = "", timeout: int = 0) -> dict[str, Any]:
    return {
        "lookback": lookback,
        "timeout": timeout,
        "tested": len(results),
        "passed": sum(1 for result in results if result.get("ok") and not result.get("empty")),
        "empty": sum(1 for result in results if result.get("ok") and result.get("empty")),
        "failed": sum(1 for result in results if not result.get("ok")),
        "results": results,
    }


def merge_live_results(*, base_path: Path, new_path: Path, out_path: Path) -> dict[str, Any]:
    """Merge live synthetic results by Sentinel ID and source path, with new results winning."""
    base = _read_json(base_path) if base_path.exists() else {"results": []}
    new = _read_json(new_path)
    merged_by_key = {
        _live_result_key(result): result
        for result in base.get("results", [])
        if result.get("sentinel_id")
    }
    for result in new.get("results", []):
        if result.get("sentinel_id"):
            merged_by_key[_live_result_key(result)] = result
    results = [
        merged_by_key[key]
        for key in sorted(merged_by_key)
    ]
    merged = summarize_live_results(
        results,
        lookback=str(new.get("lookback") or base.get("lookback") or ""),
        timeout=int(new.get("timeout") or base.get("timeout") or 0),
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
    return {
        "base_results": len(base.get("results", [])),
        "new_results": len(new.get("results", [])),
        "merged_results": len(results),
        "passed": merged["passed"],
        "empty": merged["empty"],
        "failed": merged["failed"],
        "output": str(out_path),
    }


def _candidate_key(item: dict[str, Any]) -> tuple[str, str]:
    return (str(item.get("sentinel_id", "")), str(item.get("source_path", "")))


def _live_result_key(item: dict[str, Any]) -> tuple[str, str]:
    return (str(item.get("sentinel_id", "")), str(item.get("source_path", "")))


def promote_live_results(
    *,
    plan_path: Path,
    live_results_path: Path,
    candidates_file: Path,
    output_dir: Path,
    report_path: Path,
    clean_output: bool = False,
) -> dict[str, Any]:
    """Write only non-empty live-passing synthetic plan items as promoted queries."""
    plan = _read_json(plan_path)
    live_results = _read_json(live_results_path)
    candidates, source = load_candidates(candidates_file)
    mapping = load_mapping_config()
    candidates_by_key = {_candidate_key(candidate): candidate for candidate in candidates}
    live_by_key = {_live_result_key(item): item for item in live_results.get("results", [])}
    plan_candidates = plan.get("candidates", [])

    if clean_output:
        _clean_output_dir(output_dir)

    results: list[ConversionResult] = []
    promoted_files = []
    for plan_candidate in plan_candidates:
        key = _candidate_key(plan_candidate)
        original = candidates_by_key.get(key)
        if not original:
            results.append(ConversionResult(plan_candidate, None, ["candidate not found in candidates file"], []))
            continue

        conversion = convert_candidate(original, mapping)
        live_result = live_by_key.get(key)
        if not conversion.promoted_candidate:
            results.append(conversion)
            continue

        if not live_result:
            results.append(ConversionResult(
                candidate=conversion.candidate,
                query_payload=conversion.query_payload,
                skip_reasons=["synthetic live validation not run"],
                local_validation_errors=conversion.local_validation_errors,
                live_validation_result={"ok": False, "rows": 0, "empty": False, "error": "synthetic live validation not run"},
            ))
            continue

        live_ok_with_rows = bool(live_result.get("ok")) and int(live_result.get("rows", 0)) > 0
        payload = {
            **(conversion.query_payload or {}),
            "live_validation_status": "passed" if live_ok_with_rows else "failed",
            "test_data_coverage": "synthetic_live_hit" if live_ok_with_rows else "synthetic_live_miss",
        }
        validation_result = {
            "ok": live_ok_with_rows,
            "rows": int(live_result.get("rows", 0)),
            "empty": bool(live_result.get("empty", False)),
            "error": live_result.get("error", ""),
        }
        if not live_ok_with_rows:
            results.append(ConversionResult(
                candidate=conversion.candidate,
                query_payload=payload,
                skip_reasons=["synthetic live validation did not return rows"],
                local_validation_errors=conversion.local_validation_errors,
                live_validation_result=validation_result,
            ))
            continue

        output_file = _write_query_payload(output_dir, payload)
        promoted_files.append(output_file)
        results.append(ConversionResult(
            candidate=conversion.candidate,
            query_payload=payload,
            skip_reasons=[],
            local_validation_errors=conversion.local_validation_errors,
            live_validation_result=validation_result,
            output_file=output_file,
        ))

    report = build_conversion_report(
        candidates=candidates,
        attempted=plan_candidates,
        results=results,
        source=source,
        validate_live=True,
    )
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return {
        "promoted": len(promoted_files),
        "promoted_files": promoted_files,
        "report": str(report_path),
        "output_dir": str(output_dir),
    }
