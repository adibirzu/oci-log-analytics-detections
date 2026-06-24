#!/usr/bin/env python3
"""Operator workflow wrapper for Microsoft Sentinel KQL conversion."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from sentinel_workflow.cache import build_live_cache_key
from sentinel_workflow.reporting import (
    NEXT_QUERY_STRATEGIES,
    NEXT_QUERY_WORK_TYPES,
    build_next_query_backlog,
    build_status,
    build_triage,
    classify_next_query_candidate,
    load_promoted_query_counts,
    load_sentinel_dashboard_counts,
    print_next_query_backlog,
    print_status,
    print_triage,
    _print_report_summary,
)
from sentinel_workflow.html_report import render_report_html, write_report_html

# scripts/ is sys.path[0] when run directly; tests put scripts/ on the path too.
# obs_logging is a sibling module. Guard the import so importing this workflow in
# a context without scripts/ on the path degrades to a no-op logger rather than
# an ImportError.
try:
    from obs_logging import get_logger, bind  # noqa: E402
    log = get_logger("sentinel_conversion_workflow")
except ImportError:  # pragma: no cover - defensive
    import logging as _logging
    log = _logging.getLogger("sentinel_conversion_workflow")

    def bind(_logger, **_fields):  # type: ignore[misc]
        return _logger

PROJECT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_CANDIDATES_FILE = PROJECT_DIR / "queries" / "sentinel_candidates.json"
DEFAULT_REPORT_PATH = PROJECT_DIR / "queries" / "sentinel_conversion_report.json"
DEFAULT_LOCAL_REPORT_PATH = Path("/tmp/sentinel_conversion_local.json")
DEFAULT_SENTINEL_DIR = PROJECT_DIR / "queries" / "sentinel"
DEFAULT_DASHBOARD_INVENTORY = PROJECT_DIR / "queries" / "dashboard_inventory.json"
DEFAULT_HTML_PATH = PROJECT_DIR / "docs" / "sentinel_converter.html"
DEFAULT_MIGRATION_PLAN = PROJECT_DIR / "queries" / "migration_plan_sentinel.json"
DEFAULT_PROFILE_NAME = "azure_as_is"


def _project_relative(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT_DIR))
    except ValueError:
        return str(path)


def _read_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def resolve_top(value: str, candidates_file: Path = DEFAULT_CANDIDATES_FILE) -> int:
    """Resolve --top, accepting either an integer or 'all'."""
    normalized = str(value).strip().lower()
    if normalized != "all":
        try:
            top = int(normalized)
        except ValueError as exc:
            raise argparse.ArgumentTypeError("--top must be an integer or 'all'") from exc
        if top <= 0:
            raise argparse.ArgumentTypeError("--top must be positive")
        return top

    if not candidates_file.exists():
        raise FileNotFoundError(
            f"Cannot resolve --top all because {candidates_file} does not exist. "
            "Run sync first or pass an explicit --top value."
        )
    payload = _read_json(candidates_file)
    return len(payload.get("candidates", []))


def build_convert_command(
    *,
    mode: str,
    top: int,
    timeout: int,
    lookback: str,
    report_path: Path,
    no_sync: bool,
    progress_interval: float | None = None,
    progress_every: int | None = None,
    profile: str = DEFAULT_PROFILE_NAME,
    discovery_report: Path | None = None,
    migration_plan_out: Path | None = None,
    workers: int = 1,
) -> list[str]:
    """Build the low-level converter command for a workflow mode."""
    command = [
        sys.executable,
        "scripts/convert_sentinel_kql.py",
        "--top",
        str(top),
        "--report",
        str(report_path),
        "--query-lookback",
        lookback,
        "--query-timeout",
        str(timeout),
        "--profile",
        profile,
    ]
    if discovery_report:
        command.extend(["--discovery-report", str(discovery_report)])
    if migration_plan_out:
        command.extend(["--migration-plan-out", str(migration_plan_out)])
    if no_sync:
        command.append("--no-sync")
    if progress_interval is not None:
        command.extend(["--progress-interval", str(progress_interval)])
    if progress_every is not None:
        command.extend(["--progress-every", str(progress_every)])
    if workers != 1:
        command.extend(["--workers", str(workers)])

    if mode == "local":
        command.append("--validate-local")
    elif mode == "promote":
        command.extend(["--validate-live", "--write-working", "--clean-output"])
    else:
        raise ValueError(f"unsupported converter mode: {mode}")
    return command


def run_command(command: list[str], dry_run: bool = False) -> None:
    """Run one workflow command, or print it in dry-run mode."""
    printable = " ".join(command)
    print(f"$ {printable}")
    if dry_run:
        return
    subprocess.run(command, cwd=PROJECT_DIR, check=True)


def run_convert_mode(args, mode: str, report_path: Path) -> None:
    top = resolve_top(args.top, Path(args.candidates_file))
    command = build_convert_command(
        mode=mode,
        top=top,
        timeout=args.timeout,
        lookback=args.lookback,
        report_path=report_path,
        no_sync=args.no_sync,
        progress_interval=args.progress_interval,
        progress_every=args.progress_every,
        profile=args.profile,
        discovery_report=Path(args.discovery_report) if args.discovery_report else None,
        migration_plan_out=Path(args.migration_plan_out) if args.migration_plan_out else None,
        workers=args.workers,
    )
    if args.candidates_file != str(DEFAULT_CANDIDATES_FILE):
        command.extend(["--candidates-file", args.candidates_file])
    run_command(command, dry_run=args.dry_run)
    if not args.dry_run:
        _print_report_summary(report_path)


def refresh_artifacts(args) -> None:
    commands = [
        [sys.executable, "scripts/generate_catalog.py"],
        [sys.executable, "scripts/deploy_dashboard.py", "--export-inventory"],
        [sys.executable, "scripts/deploy_dashboard.py", "--validate"],
    ]
    for command in commands:
        run_command(command, dry_run=args.dry_run)


def run_synthetic_plan(args) -> None:
    """Build parser-aware synthetic logs for a Sentinel candidate batch."""
    top = resolve_top(args.top, Path(args.candidates_file))
    command = [
        sys.executable,
        "scripts/sentinel_synthetic_logs.py",
        "plan",
        "--top",
        str(top),
        "--candidates-file",
        args.candidates_file,
        "--data-dir",
        args.synthetic_data_dir,
        "--out",
        args.synthetic_plan,
        "--progress-interval",
        str(args.progress_interval),
        "--progress-every",
        str(args.progress_every),
    ]
    run_command(command, dry_run=args.dry_run)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the Microsoft Sentinel to Logan QL conversion workflow."
    )
    parser.add_argument(
        "command",
        choices=[
            "local",
            "promote",
            "refresh-artifacts",
            "page",
            "status",
            "triage",
            "next-queries",
            "synthetic-plan",
            "live-cache-key",
            "all",
        ],
        help="Workflow step to run.",
    )
    parser.add_argument("--top", default="all", help="Candidates to attempt: integer or 'all'.")
    parser.add_argument("--timeout", type=int, default=20, help="Per-query live validation timeout.")
    parser.add_argument("--lookback", default="24h", help="Live validation query lookback.")
    parser.add_argument("--no-sync", action="store_true", default=True, help="Use cached Sentinel intake.")
    parser.add_argument("--sync", dest="no_sync", action="store_false", help="Allow converter sync if needed.")
    parser.add_argument("--dry-run", action="store_true", help="Print commands without running them.")
    parser.add_argument(
        "--progress-interval",
        type=float,
        default=30.0,
        help="Seconds between converter progress lines; set 0 for every candidate, -1 to disable.",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=100,
        help="Emit converter candidate progress at least every N attempted candidates.",
    )
    parser.add_argument("--candidates-file", default=str(DEFAULT_CANDIDATES_FILE))
    parser.add_argument("--local-report", default=str(DEFAULT_LOCAL_REPORT_PATH))
    parser.add_argument("--report", default=str(DEFAULT_REPORT_PATH))
    parser.add_argument("--profile", default=DEFAULT_PROFILE_NAME, help="Runtime mapping profile name or YAML path.")
    parser.add_argument("--discovery-report", default="", help="Optional SIEM discovery inventory/report for ranking.")
    parser.add_argument("--migration-plan-out", default="", help="Optional migration plan JSON output.")
    parser.add_argument("--html", default=str(DEFAULT_HTML_PATH))
    parser.add_argument("--sentinel-dir", default=str(DEFAULT_SENTINEL_DIR))
    parser.add_argument("--dashboard-inventory", default=str(DEFAULT_DASHBOARD_INVENTORY))
    parser.add_argument("--synthetic-plan", default=str(PROJECT_DIR / "queries" / "sentinel_synthetic_plan.json"))
    parser.add_argument("--synthetic-data-dir", default=str(PROJECT_DIR / "test_data" / "sentinel_synthetic"))
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON for status, triage, or next-queries.")
    parser.add_argument("--strict", action="store_true", help="Return non-zero when status checks need attention.")
    parser.add_argument("--limit", type=int, default=10, help="Maximum rows for triage or next-queries sections.")
    parser.add_argument(
        "--work-type",
        choices=["all", *NEXT_QUERY_WORK_TYPES.keys()],
        default="all",
        help="Filter next-queries output by work type.",
    )
    parser.add_argument(
        "--strategy",
        choices=sorted(NEXT_QUERY_STRATEGIES.keys()),
        default="default",
        help="Prioritization strategy for next-queries output.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=min(8, os.cpu_count() or 1),
        help=(
            "Parallel conversion worker threads for the CPU-bound convert_candidate phase "
            "(local and promote commands only). 1 = serial. Default: min(8, cpu_count)."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report_path = Path(args.report)
    local_report_path = Path(args.local_report)
    html_path = Path(args.html)
    sentinel_dir = Path(args.sentinel_dir)
    dashboard_inventory = Path(args.dashboard_inventory)
    if args.command != "live-cache-key":
        bind(
            log,
            command=args.command,
            dry_run=getattr(args, "dry_run", False),
            workers=getattr(args, "workers", 1),
        ).info("sentinel_workflow.start")

    if args.command == "local":
        run_convert_mode(args, "local", local_report_path)
        if not args.dry_run:
            print(f"Local report: {_project_relative(local_report_path)}")
        return 0

    if args.command == "promote":
        run_convert_mode(args, "promote", report_path)
        if not args.dry_run:
            output_path = write_report_html(
                report_path=report_path,
                output_path=html_path,
                sentinel_dir=sentinel_dir,
                dashboard_inventory=dashboard_inventory,
            )
            print(f"HTML report: {_project_relative(output_path)}")
        return 0

    if args.command == "refresh-artifacts":
        refresh_artifacts(args)
        if not args.dry_run:
            output_path = write_report_html(
                report_path=report_path,
                output_path=html_path,
                sentinel_dir=sentinel_dir,
                dashboard_inventory=dashboard_inventory,
            )
            print(f"HTML report: {_project_relative(output_path)}")
        return 0

    if args.command == "page":
        if not args.dry_run:
            output_path = write_report_html(
                report_path=report_path,
                output_path=html_path,
                sentinel_dir=sentinel_dir,
                dashboard_inventory=dashboard_inventory,
            )
            print(f"HTML report: {_project_relative(output_path)}")
        else:
            print(f"Would render HTML report to {_project_relative(html_path)}")
        return 0

    if args.command == "status":
        if args.dry_run:
            print("Would load Sentinel report, promoted query files, and dashboard inventory.")
        else:
            status = build_status(
                report_path=report_path,
                sentinel_dir=sentinel_dir,
                dashboard_inventory=dashboard_inventory,
            )
            print_status(status, as_json=args.json)
            if args.strict and status.get("status") != "ok":
                return 1
        return 0

    if args.command == "triage":
        if args.dry_run:
            print("Would load Sentinel report and summarize skip, local-validation, and live-failure blockers.")
        else:
            print_triage(build_triage(report_path=report_path, limit=args.limit), as_json=args.json)
        return 0

    if args.command == "next-queries":
        if args.dry_run:
            print("Would load Sentinel report and build a prioritized next-query development backlog.")
        else:
            print_next_query_backlog(
                build_next_query_backlog(
                    report_path=report_path,
                    limit=args.limit,
                    work_type=args.work_type,
                    strategy=args.strategy,
                ),
                as_json=args.json,
            )
        return 0

    if args.command == "synthetic-plan":
        run_synthetic_plan(args)
        return 0

    if args.command == "live-cache-key":
        key = build_live_cache_key(
            lookback=args.lookback,
            profile=args.profile,
            candidates_file=Path(args.candidates_file),
            report_path=report_path,
        )
        if args.json:
            print(json.dumps({"cache_key": key, "lookback": args.lookback, "profile": args.profile}, indent=2))
        else:
            print(key)
        return 0

    if args.command == "all":
        run_convert_mode(args, "promote", report_path)
        refresh_artifacts(args)
        if not args.dry_run:
            output_path = write_report_html(
                report_path=report_path,
                output_path=html_path,
                sentinel_dir=sentinel_dir,
                dashboard_inventory=dashboard_inventory,
            )
            print(f"HTML report: {_project_relative(output_path)}")
        return 0

    raise AssertionError(f"unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
