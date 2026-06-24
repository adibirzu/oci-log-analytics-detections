#!/usr/bin/env python3
"""Plan, generate, upload, and live-check Sentinel synthetic log batches.

The conversion pipeline only promotes Sentinel queries after live OCI parser
validation. This compatibility entrypoint keeps the historical public import
surface while implementation lives in focused ``sentinel_synthetic`` modules.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sentinel_synthetic import (  # noqa: F401
    DEFAULT_CANDIDATES_FILE,
    DEFAULT_CONVERSION_REPORT_PATH,
    DEFAULT_DATA_DIR,
    DEFAULT_DICTIONARY_PATH,
    DEFAULT_LIVE_RESULTS_PATH,
    DEFAULT_PLAN_PATH,
    DEFAULT_SENTINEL_OUTPUT_DIR,
    OCI_GAP_STEPS,
    PROJECT_DIR,
    RUNTIME_FIELDS,
    SourceContract,
    _candidate_key,
    _default_value_for_field,
    _emit_progress,
    _gap,
    _iter_single_quoted_values,
    _live_result_key,
    _match_value_for_operator,
    _merge_predicate_value,
    _progress_enabled,
    _read_json,
    _safe_live_error,
    _set_json_path,
    _should_merge_predicate,
    _strip_single_quoted_literals,
    _unquote_field,
    _unquote_value,
    _upload_file,
    build_synthetic_event,
    build_synthetic_plan,
    choose_source_contract,
    export_target_plan,
    extract_predicate_values,
    extract_query_aliases,
    extract_query_sources,
    extract_required_fields,
    extract_unquoted_operator_fields,
    load_candidates,
    load_sentinel_ids_file,
    load_sentinel_target_keys_file,
    load_source_contracts,
    merge_live_results,
    promote_live_results,
    select_ready_candidates,
    summarize_live_results,
    upload_synthetic_plan,
    validate_live_plan,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate and validate synthetic logs for converted Sentinel KQL.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan = subparsers.add_parser("plan", help="Build synthetic logs and parser/source gap report.")
    plan.add_argument("--top", type=int, default=25, help="Top quality-ranked Sentinel candidates to attempt.")
    plan.add_argument("--candidates-file", default=str(DEFAULT_CANDIDATES_FILE))
    plan.add_argument("--data-dir", default=str(DEFAULT_DATA_DIR))
    plan.add_argument("--out", default=str(DEFAULT_PLAN_PATH))
    plan.add_argument("--progress-interval", type=float, default=30.0)
    plan.add_argument("--progress-every", type=int, default=100)

    upload = subparsers.add_parser("upload", help="Upload synthetic files from a generated plan.")
    upload.add_argument("--plan", default=str(DEFAULT_PLAN_PATH))
    upload.add_argument("--data-dir", default=str(DEFAULT_DATA_DIR))
    upload.add_argument("--dry-run", action="store_true")

    export_targets = subparsers.add_parser("export-targets", help="Write a filtered synthetic plan/data batch for selected Sentinel IDs.")
    export_targets.add_argument("--plan", default=str(DEFAULT_PLAN_PATH))
    export_targets.add_argument("--data-dir", default=str(DEFAULT_DATA_DIR))
    export_targets.add_argument("--out-plan", required=True)
    export_targets.add_argument("--out-data-dir", required=True)
    export_targets.add_argument("--sentinel-id", action="append", default=[], help="Sentinel ID to include; repeatable.")
    export_targets.add_argument("--sentinel-ids-file", default="", help="JSON file containing sentinel_ids or sentinel_drift synthetic_hit_gaps.")

    live = subparsers.add_parser("validate-live", help="Run live OCI validation for synthetic-ready plan items.")
    live.add_argument("--plan", default=str(DEFAULT_PLAN_PATH))
    live.add_argument("--out", default=str(DEFAULT_LIVE_RESULTS_PATH))
    live.add_argument("--lookback", default="24h")
    live.add_argument("--timeout", type=int, default=60)
    live.add_argument("--limit", type=int, default=5, help="Maximum ready candidates to validate; 0 means all.")
    live.add_argument("--sentinel-id", action="append", default=[], help="Limit validation to a promoted Sentinel ID; repeatable.")
    live.add_argument("--sentinel-ids-file", default="", help="JSON file containing sentinel_ids or sentinel_drift synthetic_hit_gaps.")

    merge_live = subparsers.add_parser("merge-live-results", help="Merge new live-result evidence into the canonical synthetic-live results.")
    merge_live.add_argument("--base", default=str(DEFAULT_LIVE_RESULTS_PATH))
    merge_live.add_argument("--new", required=True)
    merge_live.add_argument("--out", default=str(DEFAULT_LIVE_RESULTS_PATH))

    promote = subparsers.add_parser("promote-validated", help="Promote only non-empty live-passing synthetic plan items.")
    promote.add_argument("--plan", default=str(DEFAULT_PLAN_PATH))
    promote.add_argument("--live-results", default=str(DEFAULT_LIVE_RESULTS_PATH))
    promote.add_argument("--candidates-file", default=str(DEFAULT_CANDIDATES_FILE))
    promote.add_argument("--output-dir", default=str(DEFAULT_SENTINEL_OUTPUT_DIR))
    promote.add_argument("--report", default=str(DEFAULT_CONVERSION_REPORT_PATH))
    promote.add_argument("--clean-output", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "plan":
        report = build_synthetic_plan(
            top=args.top,
            candidates_file=Path(args.candidates_file),
            data_dir=Path(args.data_dir),
            plan_path=Path(args.out),
            progress_interval=args.progress_interval,
            progress_every=args.progress_every,
        )
        print(json.dumps(report["summary"], indent=2))
        return 0
    if args.command == "upload":
        result = upload_synthetic_plan(Path(args.plan), Path(args.data_dir), dry_run=args.dry_run)
        print(json.dumps(result, indent=2))
        failed = [item for item in result.get("uploads", []) if not item.get("ok")]
        return 1 if failed else 0
    if args.command == "export-targets":
        sentinel_ids_path = Path(args.sentinel_ids_file) if args.sentinel_ids_file else None
        target_keys = load_sentinel_target_keys_file(sentinel_ids_path)
        sentinel_ids = set(args.sentinel_id) | (set() if target_keys else load_sentinel_ids_file(sentinel_ids_path))
        result = export_target_plan(
            plan_path=Path(args.plan),
            data_dir=Path(args.data_dir),
            out_plan_path=Path(args.out_plan),
            out_data_dir=Path(args.out_data_dir),
            sentinel_ids=sentinel_ids,
            target_keys=target_keys,
        )
        print(json.dumps(result, indent=2))
        return 1 if result["missing_rows"] else 0
    if args.command == "validate-live":
        sentinel_ids_path = Path(args.sentinel_ids_file) if args.sentinel_ids_file else None
        target_keys = load_sentinel_target_keys_file(sentinel_ids_path)
        result = validate_live_plan(
            Path(args.plan),
            lookback=args.lookback,
            timeout=args.timeout,
            limit=args.limit,
            sentinel_ids=set(args.sentinel_id) | (set() if target_keys else load_sentinel_ids_file(sentinel_ids_path)),
            target_keys=target_keys,
        )
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result, indent=2))
        return 1 if result["failed"] else 0
    if args.command == "merge-live-results":
        result = merge_live_results(
            base_path=Path(args.base),
            new_path=Path(args.new),
            out_path=Path(args.out),
        )
        print(json.dumps(result, indent=2))
        return 0
    if args.command == "promote-validated":
        result = promote_live_results(
            plan_path=Path(args.plan),
            live_results_path=Path(args.live_results),
            candidates_file=Path(args.candidates_file),
            output_dir=Path(args.output_dir),
            report_path=Path(args.report),
            clean_output=args.clean_output,
        )
        print(json.dumps(result, indent=2))
        return 0
    raise AssertionError(f"unhandled command: {args.command}")
