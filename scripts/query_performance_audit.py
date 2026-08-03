#!/usr/bin/env python3
"""Audit OCI Log Analytics query artifacts for avoidable performance risks.

This is a static, tenant-neutral check. It does not claim runtime performance:
leading-wildcard searches can be intrinsically scan-bound, and only live query
timings can quantify their cost. The strict gate is intentionally limited to
invalid OCL wildcard syntax and behavior-preserving pipeline ordering issues.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_QUERY_ROOT = PROJECT_DIR / "queries"

LEADING_WILDCARD_RE = re.compile(r"\blike\s+'\*", re.IGNORECASE)
RAW_CONTENT_RE = re.compile(
    r"(?:\bmsg|'Original Log Content')\s+like\s+'\*",
    re.IGNORECASE,
)
REGEX_RE = re.compile(r"\bmatches\s+'", re.IGNORECASE)
SQL_STYLE_WILDCARD_RE = re.compile(r"\blike\s+'%", re.IGNORECASE)
SORT_BEFORE_WHERE_RE = re.compile(
    r"\|\s*sort\b[^|]*\|\s*where\b",
    re.IGNORECASE,
)


def load_query_artifacts(root: Path = DEFAULT_QUERY_ROOT) -> list[dict]:
    """Load top-level saved-search payloads beneath ``root``."""
    artifacts = []
    for path in sorted(root.rglob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        query = payload.get("query") if isinstance(payload, dict) else None
        if not isinstance(query, str) or not query.strip():
            continue
        try:
            display_path = str(path.relative_to(PROJECT_DIR))
        except ValueError:
            display_path = str(path)
        artifacts.append(
            {
                "file": display_path,
                "title": str(payload.get("title", path.stem)),
                "query": query,
            }
        )
    return artifacts


def analyze_query(artifact: dict) -> dict:
    """Return static findings for one query artifact."""
    query = artifact["query"]
    leading_wildcards = len(LEADING_WILDCARD_RE.findall(query))
    raw_content_scans = len(RAW_CONTENT_RE.findall(query))
    regex_predicates = len(REGEX_RE.findall(query))
    findings = []

    if SQL_STYLE_WILDCARD_RE.search(query):
        findings.append(
            {
                "code": "invalid_like_wildcard",
                "severity": "error",
                "message": "OCI Log Analytics like uses * wildcards, not SQL % wildcards.",
            }
        )

    if SORT_BEFORE_WHERE_RE.search(query):
        findings.append(
            {
                "code": "filter_after_sort",
                "severity": "error",
                "message": "Move the post-aggregation where command before sort.",
            }
        )

    if leading_wildcards:
        severity = "high" if leading_wildcards >= 20 else "medium" if leading_wildcards >= 5 else "low"
        findings.append(
            {
                "code": "leading_wildcard_scan",
                "severity": severity,
                "count": leading_wildcards,
                "message": (
                    f"Contains {leading_wildcards} leading-wildcard like predicate(s); "
                    "prefer exact, prefix, or parsed-field filters when semantics allow."
                ),
            }
        )

    if raw_content_scans:
        findings.append(
            {
                "code": "raw_content_scan",
                "severity": "medium",
                "count": raw_content_scans,
                "message": (
                    f"Contains {raw_content_scans} raw-content wildcard predicate(s); "
                    "extract and query a typed field when a stable parser contract exists."
                ),
            }
        )

    if regex_predicates:
        findings.append(
            {
                "code": "regex_predicate_review",
                "severity": "low",
                "count": regex_predicates,
                "message": "Review regex predicates against representative data and live timings.",
            }
        )

    return {
        "file": artifact["file"],
        "title": artifact["title"],
        "metrics": {
            "leading_wildcard_predicates": leading_wildcards,
            "raw_content_scans": raw_content_scans,
            "regex_predicates": regex_predicates,
        },
        "findings": findings,
    }


def build_report(root: Path = DEFAULT_QUERY_ROOT) -> dict:
    """Build a deterministic performance-risk inventory for all queries."""
    results = [analyze_query(item) for item in load_query_artifacts(root)]
    codes = Counter(
        finding["code"]
        for result in results
        for finding in result["findings"]
    )
    severities = Counter(
        finding["severity"]
        for result in results
        for finding in result["findings"]
    )
    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": str(root),
        "summary": {
            "queries": len(results),
            "queries_with_findings": sum(bool(item["findings"]) for item in results),
            "findings_by_code": dict(sorted(codes.items())),
            "findings_by_severity": dict(sorted(severities.items())),
            "strict_errors": severities.get("error", 0),
        },
        "results": [item for item in results if item["findings"]],
    }


def render_markdown(report: dict, top: int = 30) -> str:
    """Render a concise human review surface from ``report``."""
    summary = report["summary"]
    ranked = sorted(
        report["results"],
        key=lambda item: (
            -item["metrics"]["leading_wildcard_predicates"],
            -item["metrics"]["raw_content_scans"],
            item["file"],
        ),
    )[:top]
    lines = [
        "# OCI Log Analytics Query Performance Audit",
        "",
        f"Audited **{summary['queries']}** saved-search artifacts; "
        f"**{summary['queries_with_findings']}** have advisory or strict findings.",
        "",
        "Static findings are risk indicators, not live performance proof. "
        "Leading-wildcard and raw-content searches require representative live timing before promotion.",
        "",
        "| File | Leading wildcard | Raw content | Regex | Strict issue |",
        "|---|---:|---:|---:|---|",
    ]
    for item in ranked:
        metrics = item["metrics"]
        strict = ", ".join(
            finding["code"] for finding in item["findings"] if finding["severity"] == "error"
        ) or "-"
        lines.append(
            f"| `{item['file']}` | {metrics['leading_wildcard_predicates']} | "
            f"{metrics['raw_content_scans']} | {metrics['regex_predicates']} | {strict} |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit OCI Log Analytics query performance risks")
    parser.add_argument("--root", type=Path, default=DEFAULT_QUERY_ROOT)
    parser.add_argument("--json", type=Path, help="Optional JSON report path")
    parser.add_argument("--markdown", type=Path, help="Optional Markdown report path")
    parser.add_argument("--top", type=int, default=30, help="Rows in the Markdown hotspot table")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail on invalid wildcard syntax or avoidable pipeline ordering; scan risks remain advisory",
    )
    args = parser.parse_args()

    report = build_report(args.root)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(render_markdown(report, args.top), encoding="utf-8")

    summary = report["summary"]
    print(
        "Query performance audit: "
        f"{summary['queries']} queries, "
        f"{summary['queries_with_findings']} with advisories, "
        f"{summary['strict_errors']} strict error(s)"
    )
    for code, count in summary["findings_by_code"].items():
        print(f"  {code}: {count}")
    return 1 if args.strict and summary["strict_errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
