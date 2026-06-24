"""Progress and report helpers for Sentinel KQL conversion."""

from __future__ import annotations

import json
import re
from collections import Counter
from datetime import datetime, timezone

from scripts.kql._facade_impl import ConversionResult
from scripts.redaction import redact_text
from scripts.sync_sentinel_kql import SENTINEL_LICENSE_URL, SENTINEL_WEB_URL


def _progress_value(value: object, limit: int = 120) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _format_elapsed(seconds: float) -> str:
    seconds = max(0, int(seconds))
    minutes, second = divmod(seconds, 60)
    hours, minute = divmod(minutes, 60)
    if hours:
        return f"{hours}h{minute:02d}m{second:02d}s"
    if minute:
        return f"{minute}m{second:02d}s"
    return f"{second}s"


def _conversion_status_label(result: ConversionResult, output_file: str = "") -> str:
    if output_file:
        return "promoted"
    if result.live_validation_result and not result.live_validation_result.get("ok"):
        return "live_failed"
    if result.promoted_candidate:
        return "converted"
    if result.local_validation_errors:
        return "local_failed"
    return "skipped"


def _progress_reason(result: ConversionResult) -> str:
    if result.live_validation_result and result.live_validation_result.get("error"):
        return _safe_progress_error(result.live_validation_result.get("error", ""))
    reasons = result.skip_reasons or result.local_validation_errors
    return _progress_value(reasons[0], limit=140) if reasons else ""


def _safe_progress_error(error: object) -> str:
    text = _progress_value(error, limit=180)
    text = re.sub(r"['\"]?opc-request-id['\"]?\s*:\s*['\"][^'\"]+['\"],?\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\bopc-request-id\b[=:]\s*[^,\s]+", "", text, flags=re.IGNORECASE)
    return _progress_value(text, limit=140)


def _progress_context(candidate: dict, index: int, total: int) -> str:
    score = candidate.get("quality_score", "n/a")
    title = _progress_value(candidate.get("title", ""), limit=96)
    source_path = _progress_value(candidate.get("source_path", ""), limit=96)
    return f"{index}/{total} score={score} title=\"{title}\" source=\"{source_path}\""


def _emit_progress(stream, message: str) -> None:
    print(f"[sentinel-convert] {message}", file=stream, flush=True)

def _tier_for_result(result: "ConversionResult") -> str:
    """Phase 6 tier classifier (D-16).

    PR-1 default — tier-3 when the converter flagged skip reasons or local
    validation errors, otherwise tier-1. tier-2 is reserved for transforms
    with a documented rewrite; operator extractions (06-02..06-09) populate
    that bucket once they emit ``StageResult.tier``.
    """

    if result.skip_reasons or result.local_validation_errors:
        return "tier_3"
    return "tier_1"


def build_conversion_report(
    candidates: list[dict],
    attempted: list[dict],
    results: list[ConversionResult],
    source: dict,
    validate_live: bool,
    profile: dict | None = None,
) -> dict:
    """Build the Sentinel conversion report artifact."""
    unsupported_counts = Counter()
    for result in results:
        for reason in result.skip_reasons + result.local_validation_errors:
            unsupported_counts[reason] += 1

    promoted = [result for result in results if result.output_file]
    converted = [result for result in results if result.promoted_candidate]
    skipped = [
        result for result in results
        if result.skip_reasons or result.local_validation_errors
    ]
    live_passed = [
        result for result in results
        if result.live_validation_result and result.live_validation_result.get("ok")
    ]
    live_passed_with_rows = [
        result for result in live_passed
        if int(result.live_validation_result.get("rows", 0) or 0) > 0
    ]
    live_passed_zero_rows = [
        result for result in live_passed
        if "rows" in result.live_validation_result
        and int(result.live_validation_result.get("rows", 0) or 0) == 0
    ]
    live_passed_unknown_rows = [
        result for result in live_passed
        if "rows" not in result.live_validation_result
    ]
    live_failed = [
        result for result in results
        if result.live_validation_result and not result.live_validation_result.get("ok")
    ]

    tier_distribution = {"tier_1": 0, "tier_2": 0, "tier_3": 0}
    result_tiers: list[str] = []
    for result in results:
        tier_key = _tier_for_result(result)
        tier_distribution[tier_key] += 1
        result_tiers.append(tier_key)

    return {
        "version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": source or {
            "name": "Microsoft Sentinel",
            "repository": SENTINEL_WEB_URL,
            "license": "MIT",
            "license_url": SENTINEL_LICENSE_URL,
        },
        "runtime_profile": profile or {},
        "summary": {
            "total_candidates": len(candidates),
            "attempted_candidates": len(attempted),
            "promoted_count": len(promoted),
            "converted_count": len(converted),
            "skipped_count": len(skipped),
            "ranking": "quality-first",
            "live_validation_requested": validate_live,
            "live_validation_passed": len(live_passed),
            "live_validation_passed_with_rows": len(live_passed_with_rows),
            "live_validation_passed_zero_rows": len(live_passed_zero_rows),
            "live_validation_passed_unknown_rows": len(live_passed_unknown_rows),
            "live_validation_failed": len(live_failed),
            "tier_distribution": tier_distribution,
        },
        "unsupported_features": dict(sorted(unsupported_counts.items())),
        "attempted": [
            {
                "sentinel_id": result.candidate.get("sentinel_id", ""),
                "title": result.candidate.get("title", ""),
                "quality_score": result.candidate.get("quality_score"),
                "discovery_evidence_score": result.candidate.get("discovery_evidence_score", 0),
                "discovery_hit_counts_by_lookback": result.candidate.get("discovery_hit_counts_by_lookback", {}),
                "discovery_dashboard_references": result.candidate.get("discovery_dashboard_references", []),
                "source_path": result.candidate.get("source_path", ""),
                "source_url": result.candidate.get("source_url", ""),
                "conversion_status": (
                    "promoted" if result.output_file
                    else "converted_not_written" if result.promoted_candidate
                    else "skipped"
                ),
                "output_file": result.output_file,
                "skip_reasons": result.skip_reasons,
                "local_validation_errors": result.local_validation_errors,
                "tier": tier,
                "live_validation_status": (
                    "passed" if result.live_validation_result and result.live_validation_result.get("ok")
                    else "failed" if result.live_validation_result
                    else "not_run"
                ),
                "live_validation_error": (
                    redact_text(result.live_validation_result.get("error", ""))
                    if result.live_validation_result else ""
                ),
                "live_validation_rows": (
                    int(result.live_validation_result.get("rows", 0) or 0)
                    if result.live_validation_result and "rows" in result.live_validation_result
                    else None
                ),
            }
            for result, tier in zip(results, result_tiers)
        ],
    }
