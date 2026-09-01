#!/usr/bin/env python3
"""Prepare local threat-hunting demo artifacts for OCI Log Analytics.

This script is intentionally local-first. It generates synthetic logs, refreshes
generated repository artifacts, and dry-runs dashboard packaging. It does not
upload logs, import dashboards, create saved searches, or mutate OCI resources.
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_DIR = Path(__file__).parent.parent
SCRIPTS_DIR = PROJECT_DIR / "scripts"
DEFAULT_REPORT_JSON = PROJECT_DIR / "docs" / "health" / "threat-hunting-demo-readiness.json"

DEFAULT_TH_DASHBOARDS = [
    "SOC: 2025-2026 Threat Hunting Dashboard",
    "SOC: Web-to-Cloud Threat Hunting Dashboard",
    "SOC: Threat Hunting Dashboard",
    "C2 & Beaconing Detection",
    "OCI-DEMO: Octo APM Demo Dashboard",
]


def positive_int(value: str) -> int:
    """Parse a strictly positive integer argument."""
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be greater than 0")
    return parsed


def build_commands(args: argparse.Namespace) -> list[list[str]]:
    """Build local preparation commands for a reusable threat-hunting demo."""
    commands: list[list[str]] = [
        [
            sys.executable,
            str(SCRIPTS_DIR / "generate_dashboard_data.py"),
            "--days",
            str(args.days),
            "--geo-interval",
            str(args.geo_interval),
            "--validate",
        ],
    ]

    if not args.skip_octo_apm:
        commands.append([
            sys.executable,
            str(SCRIPTS_DIR / "octo_apm_workshop.py"),
            "--generate-data",
            "--days",
            str(args.days),
            "--export-bundle",
            "--validate-bundle",
        ])

    commands.extend([
        [sys.executable, str(SCRIPTS_DIR / "generate_catalog.py")],
        [sys.executable, str(SCRIPTS_DIR / "deploy_dashboard.py"), "--export-inventory"],
        [sys.executable, str(SCRIPTS_DIR / "detection_rule_creator.py"), "--write-default"],
    ])

    for dashboard in args.dashboard_name:
        commands.append([
            sys.executable,
            str(SCRIPTS_DIR / "deploy_dashboard.py"),
            "--dry-run",
            "--dashboard-name",
            dashboard,
        ])

    commands.append([
        sys.executable,
        "-m",
        "unittest",
        "scripts.test_deploy_dashboard",
        "scripts.test_app_query_contract",
        "scripts.test_validate_synthetic_logs",
        "scripts.test_generate_dashboard_data",
        "scripts.test_prepare_threat_hunting_demo",
        "-q",
    ])

    if args.strict:
        commands.extend([
            [sys.executable, str(SCRIPTS_DIR / "query_performance_audit.py"), "--strict"],
            [sys.executable, str(SCRIPTS_DIR / "parse_validate_all_queries.py")],
            [sys.executable, "-m", "pytest", "-q"],
        ])

    return commands


def run_commands(commands: list[list[str]]) -> None:
    """Run each preparation command from the repository root."""
    for command in commands:
        print(f"$ {format_command(command)}")
        subprocess.run(command, check=True, cwd=PROJECT_DIR)


def format_command(command: list[str]) -> str:
    """Format a command as a portable repo-relative shell string."""
    display_parts: list[str] = []
    for index, part in enumerate(command):
        value = "python3" if index == 0 and part == sys.executable else part
        try:
            path = Path(value)
            if path.is_absolute() and path.is_relative_to(PROJECT_DIR):
                value = str(path.relative_to(PROJECT_DIR))
        except ValueError:
            pass
        display_parts.append(shlex.quote(value))
    return " ".join(display_parts)


def load_json(path: Path) -> dict:
    """Load a JSON object if it exists."""
    if not path.exists():
        return {}
    with path.open() as handle:
        payload = json.load(handle)
    return payload if isinstance(payload, dict) else {}


def summarize_manifest(manifest: dict) -> dict:
    """Summarize the generated synthetic log manifest."""
    files = manifest.get("files", {})
    return {
        "path": "test_data/manifest.json",
        "generated_at": manifest.get("generated_at"),
        "total_events": manifest.get("total_events", 0),
        "file_count": len(files) if isinstance(files, dict) else 0,
        "files": files if isinstance(files, dict) else {},
    }


def summarize_catalog(catalog: dict) -> dict:
    """Summarize query catalog counts used by the demo."""
    return {
        "path": "queries/catalog.json",
        "generated_at": catalog.get("generated_at"),
        "total_content_items": catalog.get("total_content_items", 0),
        "total_rules": catalog.get("total_rules", 0),
        "total_base_rules": catalog.get("total_base_rules", 0),
        "total_sentinel_queries": catalog.get("total_sentinel_queries", 0),
        "total_app_queries": catalog.get("total_app_queries", 0),
        "total_hunting": catalog.get("total_hunting", 0),
    }


def summarize_dashboard_inventory(inventory: dict, requested_dashboards: list[str]) -> dict:
    """Summarize dashboard inventory and the requested demo dashboards."""
    dashboards = inventory.get("dashboards", [])
    if not isinstance(dashboards, list):
        dashboards = []
    by_name = {
        dashboard.get("name"): dashboard
        for dashboard in dashboards
        if isinstance(dashboard, dict) and dashboard.get("name")
    }
    requested = []
    for name in requested_dashboards:
        dashboard = by_name.get(name, {})
        widgets = dashboard.get("widgets", []) if isinstance(dashboard, dict) else []
        if not isinstance(widgets, list):
            widgets = []
        requested.append({
            "name": name,
            "present": bool(dashboard),
            "widget_count": dashboard.get("widget_count", 0),
            "advanced_visualization_widgets": sum(
                1
                for widget in widgets
                if isinstance(widget, dict)
                and widget.get("visualization_type") not in (None, "", "table")
            ),
        })

    return {
        "path": "queries/dashboard_inventory.json",
        "generated_at": inventory.get("generated_at"),
        "summary": inventory.get("summary", {}),
        "requested_dashboards": requested,
    }


def build_readiness_report(args: argparse.Namespace, commands: list[list[str]]) -> dict:
    """Build a reusable local readiness report for the threat-hunting demo."""
    manifest = load_json(PROJECT_DIR / "test_data" / "manifest.json")
    catalog = load_json(PROJECT_DIR / "queries" / "catalog.json")
    dashboard_inventory = load_json(PROJECT_DIR / "queries" / "dashboard_inventory.json")

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "evidence_class": "locally_verified",
        "local_only": True,
        "live_oci_mutation_performed": False,
        "days": args.days,
        "geo_interval_minutes": args.geo_interval,
        "strict": args.strict,
        "skip_octo_apm": args.skip_octo_apm,
        "dashboards": summarize_dashboard_inventory(dashboard_inventory, args.dashboard_name),
        "synthetic_logs": summarize_manifest(manifest),
        "catalog": summarize_catalog(catalog),
        "commands": [format_command(command) for command in commands],
        "operator_boundary": (
            "Live ingestion or dashboard import requires explicit approval for the OCI profile, "
            "compartment, Log Analytics namespace, log group, source/entity mapping, time window, "
            "and stop conditions."
        ),
    }


def write_readiness_report(args: argparse.Namespace, commands: list[list[str]]) -> None:
    """Write the readiness report unless disabled."""
    if args.report_json is None:
        return
    report_path = Path(args.report_json)
    if not report_path.is_absolute():
        report_path = PROJECT_DIR / report_path
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(build_readiness_report(args, commands), indent=2) + "\n")
    print(f"Wrote threat-hunting demo readiness report to {report_path}")


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Prepare local OCI Log Analytics threat-hunting demo content. "
            "No live OCI upload or dashboard import is performed."
        )
    )
    parser.add_argument(
        "--days",
        type=positive_int,
        default=7,
        help="Number of trailing synthetic days to generate (default: 7)",
    )
    parser.add_argument(
        "--geo-interval",
        type=positive_int,
        default=15,
        help="Minutes between multicloud health samples (default: 15)",
    )
    parser.add_argument(
        "--dashboard-name",
        action="append",
        default=None,
        help=(
            "Dashboard to dry-run. Repeat for multiple dashboards. "
            "Defaults to the threat-hunting and Octo APM demo dashboards."
        ),
    )
    parser.add_argument(
        "--skip-octo-apm",
        action="store_true",
        help="Skip Octo APM workshop data and bundle generation.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Also run strict query performance audit, full parser sweep, and pytest.",
    )
    parser.add_argument(
        "--report-json",
        default=str(DEFAULT_REPORT_JSON),
        help=(
            "Write a local readiness report after preparation "
            f"(default: {DEFAULT_REPORT_JSON.relative_to(PROJECT_DIR)})"
        ),
    )
    parser.add_argument(
        "--no-report",
        action="store_const",
        const=None,
        dest="report_json",
        help="Do not write a readiness report.",
    )
    args = parser.parse_args()
    if args.dashboard_name is None:
        args.dashboard_name = list(DEFAULT_TH_DASHBOARDS)
    return args


def main() -> None:
    """Entry point."""
    args = parse_args()
    commands = build_commands(args)
    run_commands(commands)
    write_readiness_report(args, commands)


if __name__ == "__main__":
    main()
