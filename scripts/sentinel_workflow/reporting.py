"""Status, triage, backlog, and report rendering for Sentinel conversion."""

from __future__ import annotations

import ast
import json
import re
from collections import Counter
from pathlib import Path
from typing import Iterable

PROJECT_DIR = Path(__file__).resolve().parents[2]
DEFAULT_REPORT_PATH = PROJECT_DIR / "queries" / "sentinel_conversion_report.json"
DEFAULT_SENTINEL_DIR = PROJECT_DIR / "queries" / "sentinel"
DEFAULT_DASHBOARD_INVENTORY = PROJECT_DIR / "queries" / "dashboard_inventory.json"
DEFAULT_HTML_PATH = PROJECT_DIR / "docs" / "sentinel_converter.html"
SENTINEL_DASHBOARD_PREFIX = "SOC: Microsoft Sentinel "
NEXT_QUERY_WORK_TYPES = {
    "live_environment": {
        "priority": 0,
        "guidance": (
            "Rerun live validation after OCI auth, tenancy, or clock-skew issues are fixed; do not edit "
            "the query before confirming the environment is healthy."
        ),
    },
    "live_validation": {
        "priority": 1,
        "guidance": (
            "Fix generated Logan QL or parser-field usage, then rerun live promotion. "
            "Do not write this candidate manually under queries/sentinel/."
        ),
    },
    "local_validation": {
        "priority": 2,
        "guidance": "Fix converter output so local guardrails pass before any live validation attempt.",
    },
    "field_mapping": {
        "priority": 3,
        "guidance": (
            "Verify the field exists in queries/log_source_field_dictionary.json or approved built-ins "
            "before extending config/sentinel_oci_mapping.yaml."
        ),
    },
    "table_mapping": {
        "priority": 4,
        "guidance": (
            "Add a Sentinel table/source mapping only when there is a real OCI Log Analytics source "
            "and parser-field contract."
        ),
    },
    "kql_support": {
        "priority": 5,
        "guidance": (
            "Add deterministic converter support only when Logan QL has equivalent semantics; otherwise "
            "leave the candidate skipped with a clear reason."
        ),
    },
    "unsupported": {
        "priority": 6,
        "guidance": "Keep skipped unless a real mapping or deterministic converter implementation is added.",
    },
}
NEXT_QUERY_STRATEGIES = {
    "default": [
        "live_environment",
        "live_validation",
        "local_validation",
        "field_mapping",
        "table_mapping",
        "kql_support",
        "unsupported",
    ],
    "foundational": [
        "field_mapping",
        "table_mapping",
        "kql_support",
        "local_validation",
        "live_validation",
        "live_environment",
        "unsupported",
    ],
}
OCI_GAP_STEPS = [
    "confirm OCI source",
    "define parser or parser mapping",
    "define fields and aliases",
    "ingest representative sample logs",
    "validate in CAP tenancy",
    "update field dictionary",
    "add allow-list mapping",
    "add converter tests",
]


def _project_relative(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT_DIR))
    except ValueError:
        return str(path)


def _read_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def load_report(report_path: Path = DEFAULT_REPORT_PATH) -> dict:
    """Load a Sentinel conversion report."""
    if not report_path.exists():
        raise FileNotFoundError(f"Sentinel conversion report not found: {report_path}")
    return _read_json(report_path)


def load_promoted_query_counts(sentinel_dir: Path = DEFAULT_SENTINEL_DIR) -> dict:
    """Return count breakdowns for promoted Sentinel query JSON files."""
    categories = Counter()
    levels = Counter()
    live_status = Counter()
    source_tables = Counter()
    files = sorted(sentinel_dir.glob("*.json")) if sentinel_dir.exists() else []
    for path in files:
        try:
            payload = _read_json(path)
        except (OSError, json.JSONDecodeError):
            continue
        categories[payload.get("sentinel_category", "unknown")] += 1
        levels[payload.get("level", "unknown")] += 1
        live_status[payload.get("live_validation_status", "unknown")] += 1
        for table in payload.get("sentinel_tables", []):
            source_tables[table] += 1
    return {
        "files": len(files),
        "categories": dict(categories),
        "levels": dict(levels),
        "live_status": dict(live_status),
        "source_tables": dict(source_tables),
    }


def load_sentinel_dashboard_counts(inventory_path: Path = DEFAULT_DASHBOARD_INVENTORY) -> dict[str, int]:
    """Return Sentinel dashboard names and widget counts from dashboard inventory."""
    if not inventory_path.exists():
        return {}
    try:
        inventory = _read_json(inventory_path)
    except (OSError, json.JSONDecodeError):
        return {}
    dashboards = {}
    for dashboard in inventory.get("dashboards", []):
        name = dashboard.get("name", "")
        if name.startswith(SENTINEL_DASHBOARD_PREFIX):
            dashboards[name] = int(dashboard.get("widget_count", 0))
    return dict(sorted(dashboards.items()))


def build_status(
    *,
    report_path: Path = DEFAULT_REPORT_PATH,
    sentinel_dir: Path = DEFAULT_SENTINEL_DIR,
    dashboard_inventory: Path = DEFAULT_DASHBOARD_INVENTORY,
) -> dict:
    """Build a compact status summary across Sentinel report and artifacts."""
    report = load_report(report_path)
    summary = report.get("summary", {})
    runtime_profile = report.get("runtime_profile", {})
    promoted_counts = load_promoted_query_counts(sentinel_dir)
    dashboard_counts = load_sentinel_dashboard_counts(dashboard_inventory)
    promoted_files = promoted_counts.get("files", 0)
    live_status = promoted_counts.get("live_status", {})
    checks = {
        "promoted_count_matches_files": summary.get("promoted_count", 0) == promoted_files,
        "live_passed_matches_files": summary.get("live_validation_passed", 0) == promoted_files,
        "all_promoted_files_live_passed": set(live_status) <= {"passed"} and promoted_files > 0,
        "sentinel_dashboards_present": len(dashboard_counts) > 0,
    }
    return {
        "status": "ok" if all(checks.values()) else "attention",
        "summary": summary,
        "runtime_profile": runtime_profile,
        "promoted_files": promoted_files,
        "promoted_categories": promoted_counts.get("categories", {}),
        "promoted_live_status": live_status,
        "sentinel_dashboards": dashboard_counts,
        "checks": checks,
    }


def _top_items(counter_like: dict[str, int], limit: int = 12) -> list[tuple[str, int]]:
    return sorted(counter_like.items(), key=lambda item: (-item[1], item[0]))[:limit]


def _live_failures(report: dict, limit: int = 8) -> list[dict]:
    failures = [
        item for item in report.get("attempted", [])
        if item.get("live_validation_status") == "failed"
    ]
    return failures[:limit]


def _count_list_field(items: Iterable[dict], field_name: str) -> Counter:
    counter: Counter = Counter()
    for item in items:
        values = item.get(field_name, [])
        if isinstance(values, list):
            counter.update(str(value) for value in values if value)
        elif values:
            counter[str(values)] += 1
    return counter


def _as_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if item]
    if value:
        return [str(value)]
    return []


def _safe_error_summary(error: object, limit: int = 220) -> str:
    """Return a compact, redacted validation error for static docs."""
    parsed = error
    if isinstance(error, str):
        try:
            parsed = ast.literal_eval(error)
        except (SyntaxError, ValueError):
            parsed = error
    if isinstance(parsed, dict):
        status = parsed.get("status", "")
        code = parsed.get("code", "")
        message = parsed.get("message", "")
        text = f"status={status} code={code} message={message}".strip()
    else:
        text = str(parsed)
    text = re.sub(r"['\"]?opc-request-id['\"]?\s*:\s*['\"][^'\"]+['\"],?\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def _first_reason_with_prefix(reasons: list[str], prefix: str) -> str:
    for reason in reasons:
        if reason.startswith(prefix):
            return reason
    return ""


def classify_next_query_candidate(item: dict) -> dict:
    """Classify a non-promoted Sentinel candidate into an actionable work type."""
    skip_reasons = _as_list(item.get("skip_reasons"))
    local_errors = _as_list(item.get("local_validation_errors"))
    live_status = item.get("live_validation_status", "")
    if live_status == "failed":
        reason = _safe_error_summary(item.get("live_validation_error", "")) or "live OCI validation failed"
        if (
            "status=401" in reason
            or "status=429" in reason
            or "code=NotAuthenticated" in reason
            or "code=RequestThrottled" in reason
            or "TooManyRequests" in reason
            or "clock skew" in reason
        ):
            work_type = "live_environment"
        else:
            work_type = "live_validation"
    elif local_errors:
        work_type = "local_validation"
        reason = local_errors[0]
    elif field_reason := _first_reason_with_prefix(skip_reasons, "unsupported Sentinel field mapping:"):
        work_type = "field_mapping"
        reason = field_reason
    elif table_reason := _first_reason_with_prefix(skip_reasons, "unsupported Sentinel table:"):
        work_type = "table_mapping"
        reason = table_reason
    elif any(
        marker in reason
        for reason in skip_reasons
        for marker in (
            "unsupported KQL",
            "unsupported function",
            "unsupported aggregate",
            "JSON",
            "regex",
        )
    ):
        work_type = "kql_support"
        reason = skip_reasons[0] if skip_reasons else "unsupported KQL feature"
    else:
        work_type = "unsupported"
        reason = skip_reasons[0] if skip_reasons else "not promoted"

    return {
        "work_type": work_type,
        "reason": reason,
        "next_step": NEXT_QUERY_WORK_TYPES[work_type]["guidance"],
        "all_reasons": skip_reasons + local_errors,
    }


def _extract_mapping_blocker(reason: str, prefix: str) -> str:
    """Extract the missing Sentinel table or field from a skip reason."""
    if reason.startswith(prefix):
        return reason[len(prefix):].strip()
    return reason.strip()


def _build_oci_gap(work_type: str, reason: str) -> dict | None:
    """Build OCI parser/source follow-up details for mapping backlog entries."""
    if work_type == "field_mapping":
        blocked_on = _extract_mapping_blocker(reason, "unsupported Sentinel field mapping:")
    elif work_type == "table_mapping":
        blocked_on = _extract_mapping_blocker(reason, "unsupported Sentinel table:")
    else:
        return None
    return {
        "gap_type": work_type,
        "blocked_on": blocked_on,
        "oci_steps": list(OCI_GAP_STEPS),
    }


def build_next_query_backlog(
    report_path: Path = DEFAULT_REPORT_PATH,
    *,
    limit: int = 20,
    work_type: str = "all",
    strategy: str = "default",
) -> dict:
    """Build a prioritized backlog of specific Sentinel candidates to develop next."""
    report = load_report(report_path)
    requested_type = work_type.strip().lower()
    requested_strategy = strategy.strip().lower()
    if requested_strategy not in NEXT_QUERY_STRATEGIES:
        raise ValueError(f"unsupported next-query strategy: {strategy}")
    strategy_priority = {
        work_type_name: index
        for index, work_type_name in enumerate(NEXT_QUERY_STRATEGIES[requested_strategy])
    }
    candidates = []
    for item in report.get("attempted", []):
        if item.get("conversion_status") == "promoted" and item.get("live_validation_status") == "passed":
            continue
        classification = classify_next_query_candidate(item)
        if requested_type != "all" and classification["work_type"] != requested_type:
            continue
        candidate = {
            "title": item.get("title", ""),
            "sentinel_id": item.get("sentinel_id", ""),
            "quality_score": item.get("quality_score", 0),
            "source_path": item.get("source_path", ""),
            "source_url": item.get("source_url", ""),
            "work_type": classification["work_type"],
            "reason": classification["reason"],
            "next_step": classification["next_step"],
            "all_reasons": classification["all_reasons"],
            "_priority": strategy_priority[classification["work_type"]],
        }
        oci_gap = _build_oci_gap(classification["work_type"], classification["reason"])
        if oci_gap:
            candidate["oci_gap"] = oci_gap
        candidates.append(candidate)
    candidates.sort(key=lambda item: (
        item["_priority"],
        -int(item.get("quality_score", 0)),
        item.get("title", ""),
        item.get("source_path", ""),
    ))
    for candidate in candidates:
        candidate.pop("_priority", None)
    return {
        "summary": report.get("summary", {}),
        "work_type": requested_type,
        "strategy": requested_strategy,
        "candidates": candidates[:limit],
        "candidate_count": len(candidates),
        "work_type_counts": dict(Counter(candidate["work_type"] for candidate in candidates)),
    }


def _count_rows(counter_like: dict[str, int], limit: int) -> list[dict]:
    return [
        {"reason": reason, "count": count}
        for reason, count in _top_items(counter_like, limit=limit)
    ]


def _build_next_actions(skip_reasons: Counter, local_errors: Counter, live_failures: list[dict]) -> list[str]:
    actions = []
    field_mapping_count = sum(
        count for reason, count in skip_reasons.items()
        if reason.startswith("unsupported Sentinel field mapping:")
    )
    table_mapping_count = sum(
        count for reason, count in skip_reasons.items()
        if reason.startswith("unsupported Sentinel table:")
    )
    if field_mapping_count:
        actions.append(
            f"Review {field_mapping_count} unsupported field-mapping skips against "
            "queries/log_source_field_dictionary.json before extending config/sentinel_oci_mapping.yaml."
        )
    if table_mapping_count:
        actions.append(
            f"Review {table_mapping_count} unsupported table skips and add source mappings only when "
            "there is a real OCI Log Analytics source/parser target."
        )
    if local_errors:
        actions.append("Fix local validation errors before attempting live promotion for those candidates.")
    if live_failures:
        actions.append(
            "Inspect live validation failures for Logan syntax or parser-field mismatches; they are kept "
            "out of queries/sentinel/ until they pass live validation."
        )
    if not actions:
        actions.append("No conversion blockers found in the current report.")
    return actions


def build_triage(report_path: Path = DEFAULT_REPORT_PATH, limit: int = 10) -> dict:
    """Build a report-first triage summary for skipped and live-failed Sentinel candidates."""
    report = load_report(report_path)
    attempted = report.get("attempted", [])
    skip_reasons = _count_list_field(attempted, "skip_reasons")
    local_errors = _count_list_field(attempted, "local_validation_errors")
    live_failures = _live_failures(report, limit=limit)
    failure_examples = [
        {
            "title": failure.get("title", ""),
            "source_path": failure.get("source_path", ""),
            "error": _safe_error_summary(failure.get("live_validation_error", "")),
        }
        for failure in live_failures
    ]
    unsupported = report.get("unsupported_features", {})
    return {
        "summary": report.get("summary", {}),
        "top_skip_reasons": _count_rows(skip_reasons, limit),
        "top_local_validation_errors": _count_rows(local_errors, limit),
        "top_unsupported_features": _count_rows(unsupported, limit),
        "live_failure_examples": failure_examples,
        "next_actions": _build_next_actions(skip_reasons, local_errors, live_failures),
    }


def _print_report_summary(report_path: Path, sentinel_dir: Path = DEFAULT_SENTINEL_DIR) -> None:
    report = load_report(report_path)
    summary = report.get("summary", {})
    promoted_files = len(list(sentinel_dir.glob("*.json"))) if sentinel_dir.exists() else 0
    print(
        "Sentinel conversion summary: "
        f"promoted={summary.get('promoted_count', 0)}, "
        f"live_passed={summary.get('live_validation_passed', 0)}, "
        f"live_failed={summary.get('live_validation_failed', 0)}, "
        f"files={promoted_files}"
    )


def print_status(status: dict, as_json: bool = False) -> None:
    """Print Sentinel workflow status in human or JSON form."""
    if as_json:
        print(json.dumps(status, indent=2, sort_keys=True))
        return

    summary = status.get("summary", {})
    print(f"Sentinel workflow status: {status.get('status', 'unknown')}")
    print(f"  promoted_count: {summary.get('promoted_count', 0)}")
    print(f"  promoted_files: {status.get('promoted_files', 0)}")
    print(f"  live_passed:    {summary.get('live_validation_passed', 0)}")
    print(f"  live_failed:    {summary.get('live_validation_failed', 0)}")
    profile = status.get("runtime_profile", {})
    if profile:
        print(f"  profile:        {profile.get('name', 'unknown')}")
    print("  checks:")
    for name, ok in status.get("checks", {}).items():
        print(f"    {'OK' if ok else 'ATTN'} {name}")
    dashboards = status.get("sentinel_dashboards", {})
    if dashboards:
        print("  dashboards:")
        for name, count in dashboards.items():
            print(f"    {count:>2} {name}")


def _print_reason_rows(rows: list[dict], empty: str) -> None:
    if not rows:
        print(f"    {empty}")
        return
    for row in rows:
        print(f"    {row.get('count', 0):>4} {row.get('reason', '')}")


def print_triage(triage: dict, as_json: bool = False) -> None:
    """Print Sentinel conversion triage in human or JSON form."""
    if as_json:
        print(json.dumps(triage, indent=2, sort_keys=True))
        return

    summary = triage.get("summary", {})
    print("Sentinel conversion triage")
    print(f"  attempted:     {summary.get('attempted_candidates', 0)}")
    print(f"  promoted:      {summary.get('promoted_count', 0)}")
    print(f"  skipped:       {summary.get('skipped_count', 0)}")
    print(f"  live_failed:   {summary.get('live_validation_failed', 0)}")
    print("  top skip reasons:")
    _print_reason_rows(triage.get("top_skip_reasons", []), "No skip reasons found.")
    print("  top local validation errors:")
    _print_reason_rows(triage.get("top_local_validation_errors", []), "No local validation errors found.")
    failures = triage.get("live_failure_examples", [])
    print("  live failure examples:")
    if not failures:
        print("    No live validation failures found.")
    for failure in failures:
        print(f"    - {failure.get('title', '')} [{failure.get('source_path', '')}]")
        print(f"      {failure.get('error', '')}")
    print("  next actions:")
    for action in triage.get("next_actions", []):
        print(f"    - {action}")


def print_next_query_backlog(backlog: dict, as_json: bool = False) -> None:
    """Print next-query backlog in human or JSON form."""
    if as_json:
        print(json.dumps(backlog, indent=2, sort_keys=True))
        return

    print("Sentinel next-query backlog")
    print(f"  work_type:       {backlog.get('work_type', 'all')}")
    print(f"  strategy:        {backlog.get('strategy', 'default')}")
    print(f"  matching_items:  {backlog.get('candidate_count', 0)}")
    counts = backlog.get("work_type_counts", {})
    if counts:
        print("  work_type_counts:")
        strategy = backlog.get("strategy", "default")
        strategy_priority = {
            work_type_name: index
            for index, work_type_name in enumerate(NEXT_QUERY_STRATEGIES.get(strategy, NEXT_QUERY_STRATEGIES["default"]))
        }
        for name, count in sorted(counts.items(), key=lambda item: (strategy_priority[item[0]], item[0])):
            print(f"    {count:>4} {name}")
    print("  candidates:")
    candidates = backlog.get("candidates", [])
    if not candidates:
        print("    No matching candidates.")
        return
    for candidate in candidates:
        print(
            f"    - [{candidate.get('work_type', '')}] "
            f"score={candidate.get('quality_score', 0)} {candidate.get('title', '')}"
        )
        print(f"      source: {candidate.get('source_path', '')}")
        print(f"      reason: {candidate.get('reason', '')}")
        print(f"      next: {candidate.get('next_step', '')}")
        if oci_gap := candidate.get("oci_gap"):
            print(f"      oci_gap: {oci_gap.get('gap_type', '')} blocked_on={oci_gap.get('blocked_on', '')}")
