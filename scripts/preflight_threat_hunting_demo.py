#!/usr/bin/env python3
"""Preflight a threat-hunting demo before any live OCI mutation.

This script is intentionally read-only. It inspects local generated artifacts and
environment readiness, then writes a sanitized preflight report that can be
reviewed before running ingestion or dashboard import commands.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_DIR = Path(__file__).parent.parent
DEFAULT_READINESS_JSON = PROJECT_DIR / "docs" / "health" / "threat-hunting-demo-readiness.json"
DEFAULT_PREFLIGHT_JSON = PROJECT_DIR / "docs" / "health" / "threat-hunting-live-preflight.json"

REQUIRED_LOCAL_FILES = [
    PROJECT_DIR / "test_data" / "manifest.json",
    PROJECT_DIR / "queries" / "catalog.json",
    PROJECT_DIR / "queries" / "dashboard_inventory.json",
    PROJECT_DIR / "queries" / "detection_rule_specs.json",
]

DEFAULT_REQUIRED_DASHBOARDS = [
    "SOC: 2025-2026 Threat Hunting Dashboard",
    "SOC: Web-to-Cloud Threat Hunting Dashboard",
    "SOC: Threat Hunting Dashboard",
    "C2 & Beaconing Detection",
    "OCI-DEMO: Octo APM Demo Dashboard",
]

REQUIRED_ENV_VARS = ["OCI_PROFILE", "OCI_COMPARTMENT_ID"]
OPTIONAL_ENV_VARS = ["LA_NAMESPACE", "LOG_ANALYTICS_LOG_GROUP_ID"]


def rel(path: Path) -> str:
    """Return a repository-relative path for reports."""
    try:
        return str(path.relative_to(PROJECT_DIR))
    except ValueError:
        return str(path)


def load_json(path: Path) -> dict:
    """Load a JSON object if it exists and is valid."""
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def check_required_files(paths: list[Path]) -> list[dict]:
    """Check required generated files."""
    checks = []
    for path in paths:
        checks.append({
            "name": f"file:{rel(path)}",
            "status": "PASS" if path.exists() else "FAIL",
            "path": rel(path),
            "message": "present" if path.exists() else "missing",
        })
    return checks


def check_environment(env: dict[str, str], required: list[str], optional: list[str]) -> list[dict]:
    """Check environment variables without printing their values."""
    checks = []
    for name in required:
        configured = bool(env.get(name))
        checks.append({
            "name": f"env:{name}",
            "status": "PASS" if configured else "WARN",
            "variable": name,
            "configured": configured,
            "message": "configured" if configured else "not configured in current shell",
        })
    for name in optional:
        configured = bool(env.get(name))
        checks.append({
            "name": f"env:{name}",
            "status": "PASS" if configured else "WARN",
            "variable": name,
            "configured": configured,
            "message": "configured" if configured else "not configured; may be auto-discovered or created",
        })
    return checks


def check_readiness_report(readiness: dict, minimum_events: int) -> list[dict]:
    """Check reusable local readiness report content."""
    synthetic = readiness.get("synthetic_logs", {}) if isinstance(readiness, dict) else {}
    catalog = readiness.get("catalog", {}) if isinstance(readiness, dict) else {}
    dashboards = readiness.get("dashboards", {}) if isinstance(readiness, dict) else {}
    total_events = synthetic.get("total_events", 0) or 0
    total_queries = catalog.get("total_content_items", 0) or 0
    total_dashboards = dashboards.get("summary", {}).get("total_dashboards", 0) or 0

    return [
        {
            "name": "readiness:local_only",
            "status": "PASS" if readiness.get("local_only") is True else "FAIL",
            "message": "readiness report is local-only" if readiness.get("local_only") is True else "readiness report missing local-only marker",
        },
        {
            "name": "readiness:no_live_mutation",
            "status": "PASS" if readiness.get("live_oci_mutation_performed") is False else "FAIL",
            "message": "no live OCI mutation recorded" if readiness.get("live_oci_mutation_performed") is False else "readiness report indicates live mutation",
        },
        {
            "name": "readiness:synthetic_events",
            "status": "PASS" if total_events >= minimum_events else "FAIL",
            "actual": total_events,
            "minimum": minimum_events,
            "message": f"{total_events} local events available",
        },
        {
            "name": "readiness:query_catalog",
            "status": "PASS" if total_queries > 0 else "FAIL",
            "actual": total_queries,
            "message": f"{total_queries} query catalog entries available",
        },
        {
            "name": "readiness:dashboard_inventory",
            "status": "PASS" if total_dashboards > 0 else "FAIL",
            "actual": total_dashboards,
            "message": f"{total_dashboards} dashboards in generated inventory",
        },
    ]


def check_dashboards(readiness: dict, required_dashboards: list[str]) -> list[dict]:
    """Check that the requested demo dashboards are present in readiness metadata."""
    requested = (
        readiness.get("dashboards", {})
        .get("requested_dashboards", [])
        if isinstance(readiness, dict)
        else []
    )
    by_name = {
        item.get("name"): item
        for item in requested
        if isinstance(item, dict) and item.get("name")
    }
    checks = []
    for name in required_dashboards:
        item = by_name.get(name, {})
        present = bool(item.get("present"))
        checks.append({
            "name": f"dashboard:{name}",
            "status": "PASS" if present else "FAIL",
            "dashboard": name,
            "widget_count": item.get("widget_count", 0),
            "advanced_visualization_widgets": item.get("advanced_visualization_widgets", 0),
            "message": "present in readiness report" if present else "missing from readiness report",
        })
    return checks


def live_command_plan(days: int, report_json: str) -> list[str]:
    """Return the reviewed live command sequence with placeholders only."""
    return [
        "OCI_PROFILE='<OCI_PROFILE>' OCI_COMPARTMENT_ID='<OCI_COMPARTMENT_OCID>' python3 scripts/setup_log_sources.py",
        f"python3 scripts/prepare_threat_hunting_demo.py --days {days} --strict --report-json {report_json}",
        "OCI_PROFILE='<OCI_PROFILE>' OCI_COMPARTMENT_ID='<OCI_COMPARTMENT_OCID>' python3 scripts/ingest_test_data.py --validate",
        "OCI_PROFILE='<OCI_PROFILE>' OCI_COMPARTMENT_ID='<OCI_COMPARTMENT_OCID>' python3 scripts/ingest_test_data.py --mode direct",
        f"OCI_PROFILE='<OCI_PROFILE>' OCI_COMPARTMENT_ID='<OCI_COMPARTMENT_OCID>' python3 scripts/deploy_dashboard.py --cleanup --skip-live-validation --query-lookback {days}d --query-timeout 90",
        f"OCI_PROFILE='<OCI_PROFILE>' OCI_COMPARTMENT_ID='<OCI_COMPARTMENT_OCID>' python3 scripts/verify_deployed_dashboards.py --lookback {days}d --query-timeout 90 --max-workers 4 --json docs/health/verify-<profile>-{days}d-threat-hunting.json",
    ]


def build_preflight_report(args: argparse.Namespace, env: dict[str, str] | None = None) -> dict:
    """Build a local live-readiness preflight report."""
    env = os.environ if env is None else env
    readiness_path = Path(args.readiness_json)
    if not readiness_path.is_absolute():
        readiness_path = PROJECT_DIR / readiness_path
    readiness = load_json(readiness_path)

    checks = []
    checks.extend(check_required_files(REQUIRED_LOCAL_FILES + [readiness_path]))
    checks.extend(check_environment(env, REQUIRED_ENV_VARS, OPTIONAL_ENV_VARS))
    checks.extend(check_readiness_report(readiness, args.minimum_events))
    checks.extend(check_dashboards(readiness, args.dashboard_name))

    failed = sum(1 for check in checks if check["status"] == "FAIL")
    warnings = sum(1 for check in checks if check["status"] == "WARN")
    status = "FAIL" if failed else "WARN" if warnings else "PASS"

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "evidence_class": "configured" if status != "FAIL" else "unavailable",
        "status": status,
        "local_only": True,
        "live_oci_mutation_performed": False,
        "readiness_report": rel(readiness_path),
        "summary": {
            "checks": len(checks),
            "passed": sum(1 for check in checks if check["status"] == "PASS"),
            "warnings": warnings,
            "failed": failed,
        },
        "checks": checks,
        "live_command_plan": live_command_plan(args.days, rel(readiness_path)),
        "operator_boundary": (
            "This preflight is read-only. Do not run the live command plan until the OCI profile, "
            "compartment, Log Analytics namespace, log group, source/entity mapping, upload/deploy "
            "window, and stop conditions are approved."
        ),
    }


def write_report(report: dict, path_arg: str | None) -> None:
    """Write a preflight report unless disabled."""
    if path_arg is None:
        return
    path = Path(path_arg)
    if not path.is_absolute():
        path = PROJECT_DIR / path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Wrote threat-hunting live preflight report to {path}")


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Read-only preflight for OCI Log Analytics threat-hunting demo deployment."
    )
    parser.add_argument("--days", type=int, default=21, help="Live demo lookback window in days (default: 21)")
    parser.add_argument(
        "--minimum-events",
        type=int,
        default=1,
        help="Minimum local synthetic events expected in the readiness report (default: 1)",
    )
    parser.add_argument(
        "--dashboard-name",
        action="append",
        default=None,
        help="Required dashboard name. Repeat for multiple dashboards. Defaults to the core TH demo dashboards.",
    )
    parser.add_argument(
        "--readiness-json",
        default=rel(DEFAULT_READINESS_JSON),
        help="Input readiness report from prepare_threat_hunting_demo.py",
    )
    parser.add_argument(
        "--json",
        default=rel(DEFAULT_PREFLIGHT_JSON),
        help="Output preflight report path",
    )
    parser.add_argument("--no-report", action="store_const", const=None, dest="json", help="Do not write a report.")
    parser.add_argument("--strict-env", action="store_true", help="Treat missing environment variables as failures.")
    args = parser.parse_args()
    if args.days <= 0:
        parser.error("--days must be greater than 0")
    if args.minimum_events < 0:
        parser.error("--minimum-events must be greater than or equal to 0")
    if args.dashboard_name is None:
        args.dashboard_name = list(DEFAULT_REQUIRED_DASHBOARDS)
    return args


def main() -> int:
    """Entry point."""
    args = parse_args()
    report = build_preflight_report(args)
    if args.strict_env:
        for check in report["checks"]:
            if check["name"].startswith("env:") and check["status"] == "WARN":
                check["status"] = "FAIL"
                check["message"] = f"{check['variable']} is required by --strict-env"
        failed = sum(1 for check in report["checks"] if check["status"] == "FAIL")
        warnings = sum(1 for check in report["checks"] if check["status"] == "WARN")
        report["summary"]["failed"] = failed
        report["summary"]["warnings"] = warnings
        report["summary"]["passed"] = sum(1 for check in report["checks"] if check["status"] == "PASS")
        report["status"] = "FAIL" if failed else "WARN" if warnings else "PASS"
        report["evidence_class"] = "configured" if report["status"] != "FAIL" else "unavailable"

    write_report(report, args.json)
    print(
        "Threat-hunting live preflight: "
        f"{report['status']} "
        f"({report['summary']['passed']} pass, {report['summary']['warnings']} warn, "
        f"{report['summary']['failed']} fail)"
    )
    return 1 if report["status"] == "FAIL" else 0


if __name__ == "__main__":
    raise SystemExit(main())
