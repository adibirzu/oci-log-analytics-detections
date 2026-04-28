#!/usr/bin/env python3
"""Verify each redeployed SOC dashboard has the expected widgets and that
embedded saved-search queries return rows from live OCI Log Analytics.

For every dashboard in ``deploy_dashboard.DASHBOARDS``:

1. Fetch the deployed Management Dashboard by display name.
2. Compare the widget count against the expected count from the source.
3. For each embedded saved search, run its queryString against live OCI LA
   over the configured lookback window and report HIT / MISS / ERROR.

Usage:
    python3 scripts/verify_deployed_dashboards.py [--lookback 14d] [--json out.json]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR / "scripts"))

from deploy_dashboard import DASHBOARDS  # noqa: E402
from oci_config import (  # noqa: E402
    COMPARTMENT_ID,
    LA_NAMESPACE,
    TENANCY_ID,
    get_dashboard_client,
    get_la_client,
    require_oci_config,
)


@dataclass
class WidgetVerification:
    dashboard: str
    widget: str
    row_count: int
    status: str  # HIT | MISS | ERROR
    error: str | None = None


def _parse_lookback(value: str) -> timedelta:
    units = {"m": "minutes", "h": "hours", "d": "days"}
    return timedelta(**{units[value[-1]]: int(value[:-1])})


def _run_query(la, namespace, query, start, end):
    import oci

    try:
        result = la.query(
            namespace_name=namespace,
            query_details=oci.log_analytics.models.QueryDetails(
                compartment_id=COMPARTMENT_ID,
                query_string=query,
                sub_system="LOG",
                max_total_count=10,
                time_filter=oci.log_analytics.models.TimeRange(
                    time_start=start, time_end=end, time_zone="UTC",
                ),
            ),
        )
        return len(getattr(result.data, "items", []) or []), None
    except Exception as exc:  # noqa: BLE001
        return -1, str(exc)


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify redeployed SOC dashboards")
    parser.add_argument("--lookback", default="14d")
    parser.add_argument("--json", help="JSON report path")
    args = parser.parse_args()

    require_oci_config()
    md = get_dashboard_client()
    la = get_la_client()
    namespace = LA_NAMESPACE
    if not namespace:
        ns = la.list_namespaces(compartment_id=TENANCY_ID).data.items
        namespace = ns[0].namespace_name

    end = datetime.now(timezone.utc)
    start = end - _parse_lookback(args.lookback)

    dashboard_records = []
    widget_records: list[WidgetVerification] = []

    for name, cfg in DASHBOARDS.items():
        expected_count = len(cfg["widgets"])
        try:
            resp = md.list_management_dashboards(
                compartment_id=COMPARTMENT_ID, display_name=name, limit=5,
            )
            items = resp.data.items
        except Exception as exc:  # noqa: BLE001
            dashboard_records.append({
                "name": name, "exists": False, "error": str(exc)[:120],
            })
            continue

        if not items:
            dashboard_records.append({
                "name": name, "exists": False, "expected_widgets": expected_count,
            })
            continue

        d = items[0]
        try:
            full = md.get_management_dashboard(d.dashboard_id).data
            saved_searches = full.saved_searches or []
        except Exception as exc:  # noqa: BLE001
            dashboard_records.append({
                "name": name, "exists": True, "error": str(exc)[:120],
            })
            continue

        actual_count = len(full.tiles or [])
        dashboard_records.append({
            "name": name,
            "exists": True,
            "expected_widgets": expected_count,
            "actual_widgets": actual_count,
            "saved_search_count": len(saved_searches),
            "match": actual_count == expected_count,
            "dashboard_id": d.dashboard_id,
        })

        for ss in saved_searches:
            ui_config = ss.ui_config if isinstance(ss.ui_config, dict) \
                else getattr(ss, "ui_config", {}) or {}
            query_string = ui_config.get("queryString") if isinstance(ui_config, dict) \
                else None
            if not query_string:
                widget_records.append(WidgetVerification(
                    name, ss.display_name, 0, "ERROR",
                    "no queryString in saved search ui_config"))
                continue
            count, err = _run_query(la, namespace, query_string, start, end)
            viz = ui_config.get("visualizationType", "table") if isinstance(ui_config, dict) \
                else "table"
            if err:
                status = "ERROR"
            elif count > 0 or viz == "link":
                status = "HIT"
            else:
                status = "MISS"
            widget_records.append(WidgetVerification(
                name, ss.display_name, max(count, 0), status, err))

    print("=" * 78)
    print("Dashboard Health Verification")
    print("=" * 78)
    missing = [d for d in dashboard_records if not d.get("exists")]
    mismatched = [d for d in dashboard_records if d.get("exists") and not d.get("match", True)]
    print(f"Total expected dashboards: {len(DASHBOARDS)}")
    print(f"Missing dashboards:        {len(missing)}")
    print(f"Widget-count mismatch:     {len(mismatched)}")
    if missing:
        print("\nMissing dashboards:")
        for d in missing:
            print(f"  - {d['name']}")
    if mismatched:
        print("\nMismatched widget counts:")
        for d in mismatched:
            print(f"  - {d['name']}: expected={d['expected_widgets']}  actual={d['actual_widgets']}")

    print()
    print("Per-dashboard widget HIT/MISS/ERROR:")
    by_dash: dict[str, Counter] = defaultdict(Counter)
    for w in widget_records:
        by_dash[w.dashboard][w.status] += 1
    for d in sorted(by_dash):
        c = by_dash[d]
        total = sum(c.values())
        print(f"  {d:55s}  HIT={c.get('HIT',0):>2d}  "
              f"MISS={c.get('MISS',0):>2d}  ERR={c.get('ERROR',0):>2d}  "
              f"({total} widgets)")

    totals = Counter(w.status for w in widget_records)
    print("-" * 78)
    print(f"{'OVERALL':57s}  HIT={totals.get('HIT',0):>2d}  "
          f"MISS={totals.get('MISS',0):>2d}  ERR={totals.get('ERROR',0):>2d}  "
          f"({sum(totals.values())} widgets)")

    if args.json:
        Path(args.json).write_text(json.dumps({
            "dashboards": dashboard_records,
            "widgets": [asdict(w) for w in widget_records],
        }, indent=2), encoding="utf-8")
        print(f"\nJSON report written to: {args.json}")

    if missing or any(w.status == "ERROR" for w in widget_records):
        return 2
    if any(w.status == "MISS" for w in widget_records) or mismatched:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
