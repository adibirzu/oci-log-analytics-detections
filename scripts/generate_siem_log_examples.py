#!/usr/bin/env python3
"""Generate customer-safe OCI Logging and Logan detection examples."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config" / "siem_log_examples.json"
DETECTION_SPECS_PATH = ROOT / "queries" / "detection_rule_specs.json"
OUTPUT_PATH = ROOT / "queries" / "siem_log_examples.json"
SCHEMA_PATH = ROOT / "schemas" / "siem_log_examples.schema.json"

SENSITIVE_PATTERNS = (
    re.compile(r"ocid1\.[a-z]+\.oc1", re.IGNORECASE),
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    re.compile(r"\b(?:10\.42|10\.0\.10|130\.61|161\.153|144\.24|129\.153|141\.147)\."),
)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def read_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"Expected JSON object in {path}")
    return payload


def load_config() -> dict[str, Any]:
    return read_json(CONFIG_PATH)


def _load_raw_samples(config: dict[str, Any]) -> list[dict[str, Any]]:
    samples: list[dict[str, Any]] = []
    for item in config["raw_samples"]:
        event = read_json(ROOT / item["template"])
        samples.append({key: value for key, value in item.items() if key != "template"} | {"event": event})
    return samples


def _specs_by_query_file() -> dict[str, dict[str, Any]]:
    payload = read_json(DETECTION_SPECS_PATH)
    return {spec["query_file"]: spec for spec in payload["specs"]}


def _severity_for_alarm(severity: str) -> str:
    return {
        "critical": "CRITICAL",
        "high": "ERROR",
        "medium": "WARNING",
        "low": "INFO",
    }.get(severity.lower(), "INFO")


def _placeholder_for_dimension(dimension: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", dimension).strip("_").upper()
    return f"<{normalized or 'DIMENSION'}>"


def _epoch_millis(timestamp: str) -> int:
    parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    return int(parsed.timestamp() * 1000)


def _native_alarm(item: dict[str, Any], spec: dict[str, Any], generated_at: str) -> dict[str, Any]:
    alarm_severity = _severity_for_alarm(spec["severity"])
    dimensions = {
        dimension: _placeholder_for_dimension(dimension)
        for dimension in spec.get("dimensions", [])
    }
    metric_expression = f"{spec['metric_name']}[5m].sum()"
    return {
        "dedupeKey": f"<ALARM_DEDUPE_KEY_{item['id'].upper()}>",
        "title": item["display_title"],
        "body": "OCI Log Analytics detection metric crossed its configured threshold.",
        "type": "OK_TO_FIRING",
        "severity": alarm_severity,
        "timestampEpochMillis": _epoch_millis(generated_at),
        "timestamp": generated_at,
        "alarmMetaData": [
            {
                "id": "<ALARM_OCID>",
                "status": "FIRING",
                "severity": alarm_severity,
                "namespace": "oci_logging_analytics",
                "query": f"{metric_expression} > 0",
                "totalMetricsFiring": 1,
                "dimensions": [dimensions],
                "metricValues": [{metric_expression: str(item["matched_count"])}],
                "alarmUrl": "<OCI_CONSOLE_ALARM_URL>",
                "alarmSummary": f"{item['display_title']} is in a FIRING state.",
                "notificationType": "Split messages per metric stream",
            }
        ],
        "version": 1.5,
    }


def _normalized_detection(
    item: dict[str, Any],
    spec: dict[str, Any],
    query_payload: dict[str, Any],
    generated_at: str,
) -> dict[str, Any]:
    mitre = query_payload.get("mitre_attack", {})
    return {
        "schema_version": "1.0.0",
        "event_id": f"<DETECTION_EVENT_ID_{item['id'].upper()}>",
        "event_type": "oci.logan.detection",
        "detected_at": generated_at,
        "rule": {
            "id": item["id"],
            "title": item["display_title"],
            "query_ref": item["query_file"],
            "schedule": spec["schedule"],
            "lookback": spec["lookback"],
        },
        "severity": spec["severity"],
        "source": {
            "product": "OCI Log Analytics",
            "log_sources": list(item["log_sources"]),
        },
        "window": {
            "start": "<WINDOW_START_RFC3339>",
            "end": "<WINDOW_END_RFC3339>",
        },
        "matched_count": item["matched_count"],
        "entities": [dict(entity) for entity in item["entities"]],
        "mitre": {
            "tactics": list(mitre.get("tactics", [])),
            "techniques": list(mitre.get("techniques", [])),
        },
        "evidence": dict(item["evidence"]),
        "oci_context": {
            "tenancy_id": "<TENANCY_OCID>",
            "compartment_id": "<COMPARTMENT_OCID>",
            "region": "<OCI_REGION>",
        },
    }


def _load_detection_samples(config: dict[str, Any], generated_at: str) -> list[dict[str, Any]]:
    specs = _specs_by_query_file()
    samples: list[dict[str, Any]] = []
    for item in config["detections"]:
        spec = specs.get(item["query_file"])
        if spec is None:
            raise ValueError(f"Missing detection rule spec for {item['query_file']}")
        query_payload = read_json(ROOT / item["query_file"])
        samples.append(
            {
                "id": item["id"],
                "display_title": item["display_title"],
                "description": query_payload["description"],
                "query_file": item["query_file"],
                "eligible": spec["eligible"],
                "severity": spec["severity"],
                "metric_name": spec["metric_name"],
                "dimensions": list(spec.get("dimensions", [])),
                "primary_raw_sample_ids": list(item["primary_raw_sample_ids"]),
                "native_alarm": _native_alarm(item, spec, generated_at),
                "normalized_detection": _normalized_detection(item, spec, query_payload, generated_at),
            }
        )
    return samples


def build_catalog(generated_at: str | None = None) -> dict[str, Any]:
    config = load_config()
    timestamp = generated_at or now_iso()
    return {
        "schema_version": config["schema_version"],
        "generated_at": timestamp,
        "placeholder_policy": {
            "syntax": "<UPPER_SNAKE_CASE>",
            "description": "Tenant, identity, resource, network, and topology values are replaced while JSON types and service field names remain intact.",
        },
        "raw_log_samples": _load_raw_samples(config),
        "detection_samples": _load_detection_samples(config, timestamp),
        "comparison": {
            "native_path": ["Logan rule", "OCI Monitoring metric", "Alarm or notification"],
            "normalized_path": ["Logan query result", "Detection JSON", "Third-party SIEM"],
            "advantages": [
                "Fewer low-value events leave OCI.",
                "Normalized fields support consistent downstream parsing.",
                "Correlation and enrichment happen before egress.",
                "OCI context and MITRE metadata travel with each detection.",
            ],
            "caution": "Keep raw logs available for forensics, compliance, and detection retuning.",
        },
    }


def validate_catalog(catalog: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if catalog.get("schema_version") != "1.0.0":
        errors.append("schema_version must be 1.0.0")
    if len(catalog.get("raw_log_samples", [])) != 10:
        errors.append("raw_log_samples must contain exactly 10 entries")
    if len(catalog.get("detection_samples", [])) != 10:
        errors.append("detection_samples must contain exactly 10 entries")
    serialized = json.dumps(catalog)
    for pattern in SENSITIVE_PATTERNS:
        if pattern.search(serialized):
            errors.append(f"sensitive value matched {pattern.pattern}")
    for detection in catalog.get("detection_samples", []):
        if not detection.get("eligible"):
            errors.append(f"detection {detection.get('id')} is not scheduled-search eligible")
    return errors


def render_raw_jsonl(catalog: dict[str, Any]) -> str:
    return "\n".join(json.dumps(item["event"], separators=(",", ":")) for item in catalog["raw_log_samples"]) + "\n"


def render_detection_jsonl(catalog: dict[str, Any]) -> str:
    return "\n".join(
        json.dumps(item["normalized_detection"], separators=(",", ":"))
        for item in catalog["detection_samples"]
    ) + "\n"


def write_catalog(output_path: Path = OUTPUT_PATH, generated_at: str | None = None) -> dict[str, Any]:
    catalog = build_catalog(generated_at=generated_at)
    errors = validate_catalog(catalog)
    if errors:
        raise ValueError("Invalid SIEM sample catalog: " + "; ".join(errors))
    output_path.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
    return catalog


def check_catalog(output_path: Path = OUTPUT_PATH) -> list[str]:
    """Return drift errors while preserving the committed generation timestamp."""
    committed = read_json(output_path)
    generated_at = committed.get("generated_at")
    if not isinstance(generated_at, str):
        return ["generated artifact has no valid generated_at timestamp"]
    expected = build_catalog(generated_at=generated_at)
    validation_errors = validate_catalog(expected)
    if validation_errors:
        return validation_errors
    return [] if committed == expected else ["generated artifact is out of date"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=OUTPUT_PATH)
    parser.add_argument("--generated-at", help="Override generated_at for reproducible builds")
    parser.add_argument("--check", action="store_true", help="Fail if the committed artifact has drifted")
    args = parser.parse_args()
    if args.check:
        errors = check_catalog(args.out)
        if errors:
            print("SIEM log example drift: " + "; ".join(errors), file=sys.stderr)
            raise SystemExit(1)
        print(f"OK - {args.out} matches its sources")
        return
    catalog = write_catalog(args.out, generated_at=args.generated_at)
    print(
        f"Wrote {args.out} with {len(catalog['raw_log_samples'])} raw samples "
        f"and {len(catalog['detection_samples'])} detections"
    )


if __name__ == "__main__":
    main()
