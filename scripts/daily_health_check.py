#!/usr/bin/env python3
"""Daily health check for the SOC detection deployment.

Runs the full pre-flight cycle and prints a one-page status banner suitable
for a scheduled task or on-demand sanity check:

1. Inventory deployed dashboards (count, broken, duplicates, missing).
2. Smoke-test the BLUELIGHT showcase widgets via ``smoke_test_bluelight``.
3. Run ``verify_deployed_dashboards`` to query every embedded saved search.
4. Emit a JSON report under ``docs/health/`` and a human-readable banner.

Exit codes:
    0 = all dashboards present, all queries returning rows
    1 = at least one MISS (zero-row query) but no errors
    2 = at least one query / dashboard ERROR or missing
    3 = OCI auth or namespace lookup failed before checks completed
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = PROJECT_DIR / "scripts"
HEALTH_DIR = PROJECT_DIR / "docs" / "health"


def _run_subprocess(cmd: list[str]) -> tuple[int, str]:
    try:
        result = subprocess.run(
            cmd, cwd=PROJECT_DIR, capture_output=True, text=True,
            check=False, timeout=2400,
        )
        return result.returncode, result.stdout + result.stderr
    except subprocess.TimeoutExpired as exc:
        return 124, f"TIMEOUT after 2400s: {exc}"
    except Exception as exc:  # noqa: BLE001
        return 99, f"EXEC ERROR: {exc}"


def _section(title: str) -> str:
    return f"\n{'=' * 70}\n{title}\n{'=' * 70}\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Daily SOC detection health check")
    parser.add_argument("--lookback", default="21d",
                        help="Lookback for live queries (default: 21d)")
    parser.add_argument("--skip-verify", action="store_true",
                        help="Skip the per-saved-search verification (slow, ~15min)")
    parser.add_argument("--query-timeout", type=int, default=60,
                        help="Per-widget OCI query timeout for the verifier")
    parser.add_argument("--report-dir", default=str(HEALTH_DIR),
                        help="Directory for JSON output. Default: docs/health/")
    args = parser.parse_args()

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    report_dir = Path(args.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / f"health-{timestamp.replace(':', '')}.json"

    overall_status = "OK"
    sections: list[dict] = []

    print(_section(f"SOC Health Check — {timestamp}"))

    print(_section("[1/3] Dashboard inventory"))
    inventory_json = report_dir / f"inventory-{timestamp.replace(':', '')}.json"
    rc, out = _run_subprocess([
        sys.executable, str(SCRIPTS_DIR / "inventory_dashboards.py"),
        "--json", str(inventory_json),
    ])
    print(out)
    sections.append({"name": "inventory", "exit_code": rc, "output": out[-2000:]})
    if rc != 0:
        overall_status = "ERROR"

    print(_section(f"[2/3] BLUELIGHT smoke test (lookback={args.lookback})"))
    rc, out = _run_subprocess([
        sys.executable, str(SCRIPTS_DIR / "smoke_test_bluelight.py"),
        "--lookback", args.lookback,
    ])
    print(out)
    sections.append({"name": "bluelight_smoke", "exit_code": rc,
                     "output": out[-2000:]})
    if rc == 1 and overall_status == "OK":
        overall_status = "MISS"
    elif rc == 2:
        overall_status = "ERROR"
    elif rc not in (0, 1):
        overall_status = "ERROR"

    if args.skip_verify:
        print(_section("[3/3] Per-widget verifier — SKIPPED"))
        sections.append({"name": "verifier", "exit_code": None,
                         "output": "skipped via --skip-verify"})
    else:
        print(_section(f"[3/3] Per-widget verifier (lookback={args.lookback})"))
        verify_json = report_dir / f"verify-{timestamp.replace(':', '')}.json"
        rc, out = _run_subprocess([
            sys.executable, str(SCRIPTS_DIR / "verify_deployed_dashboards.py"),
            "--lookback", args.lookback,
            "--query-timeout", str(args.query_timeout),
            "--json", str(verify_json),
        ])
        print(out)
        sections.append({"name": "verifier", "exit_code": rc,
                         "output": out[-2000:]})
        if rc == 1 and overall_status == "OK":
            overall_status = "MISS"
        elif rc == 2:
            overall_status = "ERROR"

    report = {
        "timestamp": timestamp,
        "lookback": args.lookback,
        "overall_status": overall_status,
        "sections": sections,
    }
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(_section(f"Overall status: {overall_status}  (report: {report_path})"))

    return {"OK": 0, "MISS": 1, "ERROR": 2}.get(overall_status, 3)


if __name__ == "__main__":
    raise SystemExit(main())
