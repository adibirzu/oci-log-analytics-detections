#!/usr/bin/env python3
"""Generate the canonical, non-query Splunk detection migration registry."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml
import jsonschema

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

try:  # Support both ``python scripts/...`` and package imports in tests.
    from detection_rule_creator import build_detection_rule_spec
    from splunk_delivery_contracts import REPOSITORY_ROOT, registry_validation_errors
except ImportError:  # pragma: no cover - selected by pytest package imports
    from scripts.detection_rule_creator import build_detection_rule_spec
    from scripts.splunk_delivery_contracts import REPOSITORY_ROOT, registry_validation_errors


DEFAULT_CONFIG = REPOSITORY_ROOT / "config" / "splunk_parallel_delivery.yaml"
DEFAULT_OUTPUT = REPOSITORY_ROOT / "queries" / "splunk_detection_registry.json"
FIELD_DICTIONARY = REPOSITORY_ROOT / "queries" / "log_source_field_dictionary.json"
EVIDENCE_SCHEMA_PATH = REPOSITORY_ROOT / "schemas" / "splunk_evidence_event.schema.json"
EVIDENCE_SCHEMA = json.loads(EVIDENCE_SCHEMA_PATH.read_text(encoding="utf-8"))
FORBIDDEN_KEY_PARTS = (
    "token", "secret", "password", "ocid", "tenancy", "namespace", "hostname",
    "host", "ip_address", "public_ip", "endpoint", "topology", "payload",
)
SENSITIVE_VALUE_PATTERNS = {
    "OCID": re.compile(r"\bocid1\.[a-z0-9._-]+", re.IGNORECASE),
    "IP address": re.compile(r"\b(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}\b"),
    "endpoint URL": re.compile(r"\bhttps?://[^\s]+", re.IGNORECASE),
    "hostname": re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|dev|app|cloud|local|internal|corp)\b", re.IGNORECASE),
    "namespace": re.compile(r"\bnamespace\s*[:=]\s*\S+", re.IGNORECASE),
    "token": re.compile(r"\b(?:token|secret|api[-_ ]?key|bearer)\s*[:=]\s*\S+", re.IGNORECASE),
}
PLACEHOLDER_VALUE_RE = re.compile(r"(?:\$\{[A-Z0-9_]+\}|<[A-Z0-9_ -]+>)")
LOG_SOURCE_RE = re.compile(r"['\"]Log Source['\"]\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
ALLOWED_PUBLIC_SOURCE_HOSTS = frozenset({"github.com", "research.splunk.com"})


def load_delivery_config(path: Path) -> dict[str, Any]:
    """Load the tenant-neutral Splunk delivery policy."""
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"delivery config must be an object: {path}")
    return payload


def load_field_dictionary(path: Path = FIELD_DICTIONARY) -> set[str]:
    """Return approved display fields and built-ins from the generated dictionary."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    names = set(payload.get("approved_builtins", []))
    names.update(
        field["display_name"]
        for field in payload.get("fields", [])
        if isinstance(field, dict) and isinstance(field.get("display_name"), str)
    )
    return names


def _known_sources(dictionary_path: Path = FIELD_DICTIONARY) -> set[str]:
    payload = json.loads(dictionary_path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for values in payload.get("source_candidate_groups", {}).values():
        names.update(value for value in values if isinstance(value, str))
    for field in payload.get("fields", []):
        for source in field.get("sources", []) if isinstance(field, dict) else []:
            if isinstance(source, dict) and isinstance(source.get("source_display"), str):
                names.add(source["source_display"])
    return names


def _migration_entries(config: dict[str, Any]) -> list[dict[str, Any]]:
    detections = config.get("detections", {})
    if not isinstance(detections, dict):
        return []
    entries = detections.get("migrations", detections.get("migration_entries", []))
    if not isinstance(entries, list):
        return []
    return [entry for entry in entries if isinstance(entry, dict)]


def _query_payload(query_file: str) -> dict[str, Any] | None:
    candidate = (REPOSITORY_ROOT / query_file).resolve()
    if not candidate.is_file():
        return None
    try:
        payload = json.loads(candidate.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _query_version(query_file: str) -> str:
    """Return the immutable SHA-256 version of one canonical query artifact."""
    candidate = (REPOSITORY_ROOT / query_file).resolve()
    if not candidate.is_file():
        return ""
    return hashlib.sha256(candidate.read_bytes()).hexdigest()


def _merged_mapping(defaults: dict[str, Any], configured: object) -> dict[str, Any]:
    """Overlay a configured mapping without dropping newly governed defaults."""
    result = dict(defaults)
    if isinstance(configured, dict):
        result.update(configured)
    return result


def _entry_from_migration(migration: dict[str, Any], config: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    defaults = config.get("defaults", {})
    target = config.get("splunk_target", {})
    query_file = migration.get("oci_query_file", "")
    payload = _query_payload(query_file) if isinstance(query_file, str) else None
    eligibility = build_detection_rule_spec(query_file, payload) if payload and payload.get("query") and payload.get("title") else {"dimensions": []}
    delivery_mode = migration.get("delivery", {}).get(
        "delivery_mode", defaults.get("delivery_mode", "evidence")
    ) if isinstance(migration.get("delivery"), dict) else defaults.get("delivery_mode", "evidence")
    false_positives = payload.get("falsepositives", []) if payload else []
    if not isinstance(false_positives, list) or not all(
        isinstance(value, str) and value.strip() for value in false_positives
    ):
        false_positives = []
    if not false_positives:
        false_positives = [
            "No known false positives documented; validate with the source owner."
        ]
    detection_defaults = {
        "severity": payload.get("level", "medium") if payload else "medium",
        "mitre_techniques": payload.get("mitre_attack", {}).get("techniques", []) if payload else [],
        "mechanism": "scheduled",
    }
    delivery_defaults = {
        key: defaults.get(key)
        for key in ("delivery_mode", "lookback", "overlap", "max_rows", "max_batch_events", "max_attempts")
    }
    delivery_defaults.update({
        "delivery_mode": delivery_mode,
        "evidence_targets": defaults.get("evidence_targets", ["hec", "streaming"]),
        "raw_mode": "enabled" if delivery_mode == "raw" else "disabled",
        "evidence_mode": "enabled" if delivery_mode == "evidence" else "disabled",
    })
    provenance = migration.get("splunk_provenance", migration.get("splunk", {}))
    provenance = provenance if isinstance(provenance, dict) else {}
    entry = {
        "id": migration.get("id", ""),
        "title": migration.get("title", payload.get("title", "") if payload else ""),
        "splunk": {
            "index": target.get("index", "${SPLUNK_HEC_INDEX}"),
            "sourcetype": target.get("sourcetype", defaults.get("sourcetype", "")),
            "dimensions": eligibility.get("dimensions", []),
        },
        "oci_query_file": query_file,
        "query_version": _query_version(query_file) if isinstance(query_file, str) else "",
        "required_sources": migration.get("required_sources", []),
        "required_fields": migration.get("required_fields", []),
        "fidelity": migration.get("fidelity", "transformed"),
        "detection": _merged_mapping(detection_defaults, migration.get("detection")),
        "delivery": _merged_mapping(delivery_defaults, migration.get("delivery")),
        "evidence": migration.get("evidence", {
            "include_original_content": defaults.get("include_original_content", False),
            "redaction_profile": None,
        }),
        # The Monitoring alarm is bound to the exact aggregate emitted by the
        # scheduled Log Analytics detection.  Its OCI alarm OCID, rather than
        # an untrusted payload dimension, selects this registry entry.
        "alarm_contract": migration.get("alarm_contract", {
            "binding_key": migration.get("id", ""),
            "metric_namespace": eligibility.get("alarm_template", {}).get(
                "namespace", defaults.get("metric_namespace", "oci_log_analytics_detections")
            ),
            "metric_name": eligibility.get("metric_name", ""),
            "metric_dimensions": eligibility.get("dimensions", []),
            "query": f'{eligibility.get("metric_name", "")}[{eligibility.get("schedule", "5m")}].sum() > 0',
            "allowed_dimensions": {},
            "alarm_dimension_to_log_field": {},
        }),
        "governance": _merged_mapping({
            "security_objective": (
                f"Detect and investigate {migration.get('title', payload.get('title', '') if payload else migration.get('id', 'the governed condition'))}."
            ),
            "expected_results": (
                payload.get("description")
                if payload and isinstance(payload.get("description"), str) and payload["description"].strip()
                else "One or more governed detection aggregates when the query condition matches."
            ),
            "false_positives": false_positives,
            "tuning": "Validate the threshold and schedule against a representative baseline before promotion.",
            "cost_cardinality": "Keep the scheduled metric contract to at most three bounded dimensions.",
        }, migration.get("governance")),
        "evidence_states": _merged_mapping({
            "local": "code_backed",
            "parser": "not_run",
            "data_hit": "not_run",
            "dashboard_render": "not_run",
            "metric": "not_run",
            "hec": "not_run",
            "splunk_search": "not_run",
        }, migration.get("evidence_states")),
    }
    return entry, provenance


def build_registry(config_path: Path = DEFAULT_CONFIG) -> dict[str, Any]:
    """Build stable registry metadata from configured Splunk migration entries."""
    config = load_delivery_config(config_path)
    records = [_entry_from_migration(migration, config) for migration in _migration_entries(config)]
    records.sort(key=lambda record: str(record[0].get("id", "")))
    return {
        "version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "detections": [entry for entry, _ in records],
        "splunk_provenance": {entry["id"]: provenance for entry, provenance in records},
    }


def _is_allowed_public_source_url(value: str) -> bool:
    """Allow provenance links only on reviewed public source hosts."""
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and parsed.hostname in ALLOWED_PUBLIC_SOURCE_HOSTS
        and port is None
        and parsed.username is None
        and parsed.password is None
        and bool(parsed.path and parsed.path != "/")
        and not parsed.query
    )


def _forbidden_keys(value: Any, location: str = "registry") -> list[str]:
    if isinstance(value, dict):
        errors: list[str] = []
        for key, child in value.items():
            key_text = str(key).lower()
            # Metric namespace is a governed public contract name, unlike the
            # tenancy Log Analytics namespace which never belongs in registry.
            allowed_contract_key = key_text == "metric_namespace"
            if not allowed_contract_key and any(part in key_text for part in FORBIDDEN_KEY_PARTS):
                errors.append(f"forbidden secret or tenant key at {location}.{key}")
            errors.extend(_forbidden_keys(child, f"{location}.{key}"))
        return errors
    if isinstance(value, list):
        return [error for index, child in enumerate(value) for error in _forbidden_keys(child, f"{location}[{index}]")]
    if (
        isinstance(value, str)
        and location.endswith(".source_url")
        and _is_allowed_public_source_url(value)
    ):
        return []
    if isinstance(value, str) and not PLACEHOLDER_VALUE_RE.fullmatch(value.strip()):
        return [
            f"forbidden sensitive value at {location}: {label}"
            for label, pattern in SENSITIVE_VALUE_PATTERNS.items()
            if pattern.search(value)
        ]
    return []


def validate_registry(registry: dict[str, Any]) -> list[str]:
    """Return contract, canonical-query, source/field, eligibility, and safety errors."""
    errors = _forbidden_keys(registry)
    try:
        jsonschema.Draft202012Validator.check_schema(EVIDENCE_SCHEMA)
    except jsonschema.SchemaError as error:
        errors.append(f"evidence event schema invalid: {error.message}")
    detections = registry.get("detections")
    if not isinstance(detections, list):
        return [*errors, "detections must be a list"]
    fields = load_field_dictionary()
    sources = _known_sources()
    provenance = registry.get("splunk_provenance")
    if not isinstance(provenance, dict):
        errors.append("splunk_provenance must be an object")

    for entry in detections:
        if not isinstance(entry, dict):
            errors.append("detection entry must be an object")
            continue
        identifier = str(entry.get("id", "<unknown>"))
        errors.extend(f"{identifier}: {error}" for error in registry_validation_errors(entry))
        entry_provenance = provenance.get(identifier) if isinstance(provenance, dict) else None
        if not isinstance(entry_provenance, dict):
            errors.append(f"{identifier}: Splunk provenance is missing")
        else:
            for key in ("repository", "app", "version", "saved_search", "source_url"):
                if not isinstance(entry_provenance.get(key), str) or not entry_provenance[key].strip():
                    errors.append(f"{identifier}: Splunk provenance is missing {key}")
            source_url = entry_provenance.get("source_url")
            if (
                isinstance(source_url, str)
                and source_url.strip()
                and not _is_allowed_public_source_url(source_url)
            ):
                errors.append(
                    f"{identifier}: Splunk provenance source_url must use HTTPS on an approved public source host"
                )
        query_file = entry.get("oci_query_file")
        payload = _query_payload(query_file) if isinstance(query_file, str) else None
        if not payload:
            continue
        if not isinstance(payload.get("title"), str) or not payload["title"].strip():
            errors.append(f"{identifier}: canonical query is missing a title")
        elif entry.get("title") != payload["title"]:
            errors.append(f"{identifier}: title does not match canonical query title")
        query = payload.get("query", "")
        if not isinstance(query, str) or not query.strip():
            errors.append(f"{identifier}: canonical query is missing a query")
            continue
        query_sources = set(LOG_SOURCE_RE.findall(query))
        for source in entry.get("required_sources", []):
            if source not in sources:
                errors.append(f"{identifier}: required source is not in the field dictionary: {source}")
            elif source not in query_sources:
                errors.append(f"{identifier}: required source is not declared by the canonical query: {source}")
        for field in entry.get("required_fields", []):
            if field not in fields:
                errors.append(f"{identifier}: required field is not in the field dictionary: {field}")
            elif field not in query:
                errors.append(f"{identifier}: required field is not declared by the canonical query: {field}")
        spec = build_detection_rule_spec(query_file, payload)
        if not spec["eligible"]:
            errors.append(f"{identifier}: query is not scheduled-detection eligible: {'; '.join(spec['reasons'])}")
    return errors


def write_registry(registry: dict[str, Any], output: Path) -> None:
    """Write the deterministic registry with a trailing newline."""
    output.write_text(json.dumps(registry, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _registry_without_generated_at(serialized: str) -> dict[str, Any] | None:
    """Parse a registry for drift checks while ignoring its generation receipt."""
    try:
        payload = json.loads(serialized)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    payload.pop("generated_at", None)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true", help="Fail when output differs from generated registry")
    parser.add_argument("--json", action="store_true", help="Print generated registry JSON")
    args = parser.parse_args()
    registry = build_registry(args.config)
    errors = validate_registry(registry)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    rendered = json.dumps(registry, indent=2, sort_keys=True) + "\n"
    if args.check:
        existing = args.out.read_text(encoding="utf-8") if args.out.is_file() else ""
        if _registry_without_generated_at(existing) != _registry_without_generated_at(rendered):
            print(f"registry drift: {args.out}", file=sys.stderr)
            return 1
    elif not args.json:
        write_registry(registry, args.out)
        print(f"Wrote Splunk detection registry to {args.out}")
    if args.json:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
