"""Synthetic log planning and parser-contract helpers for Sentinel conversions."""

from __future__ import annotations

import json
import os
import re
import sys
import time
from collections import Counter, defaultdict
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
PROJECT_DIR = SCRIPTS_DIR.parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from convert_sentinel_kql import convert_candidate, load_mapping_config, select_top_candidates, slugify_title  # noqa: E402
from field_dictionary import _default_parser_definitions, extract_query_fields  # noqa: E402

DEFAULT_CANDIDATES_FILE = PROJECT_DIR / "queries" / "sentinel_candidates.json"
DEFAULT_PLAN_PATH = PROJECT_DIR / "queries" / "sentinel_synthetic_plan.json"
DEFAULT_DATA_DIR = PROJECT_DIR / "test_data" / "sentinel_synthetic"
DEFAULT_DICTIONARY_PATH = PROJECT_DIR / "queries" / "log_source_field_dictionary.json"

RUNTIME_FIELDS = {
    "Count",
    "Log Source",
    "Original Log Content",
    "Time",
    "msg",
    "span",
    "time",
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
OCID_RE = re.compile(r"ocid1\.[A-Za-z0-9_.-]+")
OCI_ENDPOINT_RE = re.compile(r"https://[A-Za-z0-9.-]+\.oci\.oraclecloud\.com[^\s'\")]*")
OCI_HOST_RE = re.compile(r"[A-Za-z0-9.-]+\.oci\.oraclecloud\.com")
NAMESPACE_PATH_RE = re.compile(r"/namespaces/[^/\s'\")]+")


def _safe_live_error(error: object, limit: int = 500) -> str:
    """Return a compact live-error string without OCI tenancy identifiers."""
    text = re.sub(r"\s+", " ", str(error)).strip()
    text = OCID_RE.sub("<OCI_OCID>", text)
    text = OCI_ENDPOINT_RE.sub("https://<OCI_ENDPOINT>", text)
    text = OCI_HOST_RE.sub("<OCI_ENDPOINT_HOST>", text)
    text = NAMESPACE_PATH_RE.sub("/namespaces/<OCI_NAMESPACE>", text)
    text = re.sub(r"opc-request-id[=:]\s*[^,\s]+", "opc-request-id=<REDACTED>", text, flags=re.IGNORECASE)
    return text[:limit]


@dataclass(frozen=True)
class SourceContract:
    """Existing parser/source contract details for one OCI Log Analytics source."""

    source_display: str
    parser_name: str
    parser_display: str
    field_paths: dict[str, list[str]]
    example: dict[str, Any]


def _read_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def load_candidates(path: Path = DEFAULT_CANDIDATES_FILE) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Load normalized Microsoft Sentinel candidates."""
    payload = _read_json(path)
    return payload.get("candidates", []), payload.get("source", {})


def load_source_contracts() -> dict[str, SourceContract]:
    """Return parser contracts keyed by OCI Log Analytics source display name."""
    contracts: dict[str, SourceContract] = {}
    for definition in _default_parser_definitions():
        source_display = definition["source_display"]
        field_paths: dict[str, list[str]] = defaultdict(list)
        for field_name, json_path, _sequence in definition["field_mappings"]:
            if json_path not in field_paths[field_name]:
                field_paths[field_name].append(json_path)
        contracts[source_display] = SourceContract(
            source_display=source_display,
            parser_name=definition["parser_name"],
            parser_display=definition["parser_display"],
            field_paths=dict(field_paths),
            example=deepcopy(definition.get("example", {})),
        )
    return contracts


def _iter_single_quoted_values(text: str):
    in_quote = False
    escaped = False
    value: list[str] = []
    start = 0
    for index, char in enumerate(text):
        if escaped:
            value.append(char)
            escaped = False
            continue
        if char == "\\" and in_quote:
            value.append(char)
            escaped = True
            continue
        if char == "'":
            if in_quote:
                yield "".join(value), start, index + 1
                value = []
                in_quote = False
            else:
                in_quote = True
                start = index
            continue
        if in_quote:
            value.append(char)


def _strip_single_quoted_literals(text: str) -> str:
    output = []
    last = 0
    for _value, start, end in _iter_single_quoted_values(text):
        output.append(text[last:start])
        output.append("''")
        last = end
    output.append(text[last:])
    return "".join(output)


def extract_query_sources(query: str) -> list[str]:
    """Extract source names from the generated Logan Log Source filter."""
    return sorted(set(re.findall(r"'Log Source'\s*=\s*'((?:\\'|[^'])*)'", query)))


def extract_unquoted_operator_fields(query: str) -> set[str]:
    """Return unquoted fields used in simple Logan operator expressions."""
    stripped = _strip_single_quoted_literals(query)
    fields = set()
    pattern = re.compile(
        r"\b(?P<field>[A-Za-z_][A-Za-z0-9_]*)\s*(?:=|!=|>=|<=|>|<|\blike\b|\bnot\s+like\b|\bin\b|\bnot\s+in\b|\bis\b)",
        re.IGNORECASE,
    )
    command_words = {
        "and",
        "as",
        "by",
        "count",
        "eval",
        "fields",
        "head",
        "in",
        "not",
        "or",
        "sort",
        "stats",
        "where",
    }
    for match in pattern.finditer(stripped):
        field = match.group("field")
        if field.lower() not in command_words:
            fields.add(field)
    return fields


def extract_query_aliases(query: str) -> set[str]:
    """Return runtime aliases created by Logan pipeline stages."""
    aliases = set(re.findall(r"\bas\s+([A-Za-z_][A-Za-z0-9_]*)\b", query, flags=re.IGNORECASE))
    aliases.update(re.findall(r"\|\s*eval\s+([A-Za-z_][A-Za-z0-9_]*)\s*=", query, flags=re.IGNORECASE))
    return aliases


def extract_required_fields(query: str) -> set[str]:
    """Return OCI display fields that synthetic logs must populate."""
    fields = set(extract_query_fields(query))
    fields.update(extract_unquoted_operator_fields(query))
    fields.difference_update(extract_query_aliases(query))
    fields.difference_update(RUNTIME_FIELDS)
    return fields


def _unquote_field(raw: str) -> str:
    value = raw.strip()
    if len(value) >= 2 and value[0] == "'" and value[-1] == "'":
        return value[1:-1].replace("\\'", "'")
    return value


def _unquote_value(raw: str) -> Any:
    value = raw.strip()
    if len(value) >= 2 and value[0] == "'" and value[-1] == "'":
        return value[1:-1].replace("\\'", "'").replace("\\\\", "\\")
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    if re.fullmatch(r"-?\d+\.\d+", value):
        return float(value)
    if value.lower() == "null":
        return None
    return value


def _default_value_for_field(field_name: str) -> Any:
    lowered = field_name.lower()
    if "ip" in lowered or "address" in lowered:
        return "198.51.100.42"
    if "port" in lowered:
        return 443
    if "status" in lowered:
        return "Failure"
    if "action" in lowered:
        return "blocked"
    if "url" in lowered:
        return "/sentinel/synthetic/payload"
    if "user" in lowered or "account" in lowered:
        return "sentinel.synthetic@example.com"
    if "host" in lowered or "computer" in lowered:
        return "sentinel-synth-01"
    if "command" in lowered:
        return "cmd.exe /c whoami"
    if "process" in lowered or "image" in lowered:
        return "cmd.exe"
    if "event id" in lowered:
        return "4688"
    if "time" in lowered:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return f"sentinel-{slugify_title(field_name)[:32]}"


def _match_value_for_operator(operator: str, raw_value: str) -> Any:
    value = _unquote_value(raw_value)
    if isinstance(value, str):
        value = value.replace("\\'", "'").replace("\\\\", "\\")
    if operator.lower() in {"!=", "not like"}:
        if value in {"Success", "success", "0"}:
            return "Failure"
        if value in {None, ""}:
            return "sentinel-value"
        return f"{value}-other"
    if operator.lower() == "like":
        text = str(value).replace("*", "").strip()
        return text or "sentinel-value"
    if operator in {">", ">="} and isinstance(value, (int, float)):
        return value + 1
    if operator in {"<", "<="} and isinstance(value, (int, float)):
        return value - 1
    return value


def _merge_predicate_value(existing: Any, new_value: Any) -> Any:
    """Combine repeated positive predicates for the same synthetic field."""
    if existing in {None, "", "sentinel-value"}:
        return new_value
    if new_value in {None, ""}:
        return existing
    if isinstance(existing, str) and isinstance(new_value, str):
        if new_value in existing:
            return existing
        return f"{existing} {new_value}".strip()
    return existing


def _should_merge_predicate(query: str, previous_end: int | None, current_start: int) -> bool:
    """Return false when repeated field predicates are disjunctive alternatives."""
    if previous_end is None:
        return True
    if current_start < previous_end:
        return False
    connector = _strip_single_quoted_literals(query[previous_end:current_start]).lower()
    return not re.search(r"\bor\b", connector)


def extract_predicate_values(query: str) -> dict[str, Any]:
    """Derive representative field values from simple Logan predicates."""
    values: dict[str, Any] = {}
    last_field_end: dict[str, int] = {}
    field_token = r"(?:'(?P<quoted>(?:\\'|[^'])+)'|(?P<bare>[A-Za-z_][A-Za-z0-9_]*))"
    value_token = r"(?:'(?P<value>(?:\\'|[^'])*)'|(?P<raw>-?\d+(?:\.\d+)?|null))"

    in_pattern = re.compile(
        rf"{field_token}\s+(?P<op>in|not\s+in)\s*\((?P<values>[^)]*)\)",
        re.IGNORECASE,
    )
    for match in in_pattern.finditer(query):
        field_name = _unquote_field(match.group("quoted") or match.group("bare") or "")
        if field_name == "Log Source":
            continue
        first_value = (match.group("values").split(",", 1)[0] or "").strip()
        if first_value:
            value = _unquote_value(first_value)
            if _should_merge_predicate(query, last_field_end.get(field_name), match.start()):
                values[field_name] = _merge_predicate_value(values.get(field_name), value)
            last_field_end[field_name] = match.end()

    comparison_pattern = re.compile(
        rf"{field_token}\s*(?P<op>=|!=|>=|<=|>|<|\blike\b|\bnot\s+like\b)\s*{value_token}",
        re.IGNORECASE,
    )
    for match in comparison_pattern.finditer(query):
        field_name = _unquote_field(match.group("quoted") or match.group("bare") or "")
        if field_name == "Log Source":
            continue
        raw_value = match.group("value") if match.group("value") is not None else match.group("raw")
        operator = match.group("op")
        if operator in {"!=", "not like"} and str(raw_value).strip().lower() in {"", "null"}:
            continue
        value = _match_value_for_operator(operator, str(raw_value))
        if operator in {"!=", "not like"} and field_name in values:
            continue
        if _should_merge_predicate(query, last_field_end.get(field_name), match.start()):
            values[field_name] = _merge_predicate_value(values.get(field_name), value)
        last_field_end[field_name] = match.end()
    return values


def choose_source_contract(
    sources: Iterable[str],
    required_fields: set[str],
    contracts: dict[str, SourceContract],
) -> tuple[SourceContract | None, list[str], list[str]]:
    """Pick the existing source contract with the best required-field coverage."""
    candidates = []
    missing_sources = []
    for source in sources:
        contract = contracts.get(source)
        if not contract:
            missing_sources.append(source)
            continue
        missing_fields = sorted(field for field in required_fields if field not in contract.field_paths)
        candidates.append((len(missing_fields), source, contract, missing_fields))
    if not candidates:
        return None, sorted(required_fields), sorted(missing_sources)
    _missing_count, _source, contract, missing_fields = sorted(candidates, key=lambda item: (item[0], item[1]))[0]
    return contract, missing_fields, sorted(missing_sources)


def _set_json_path(payload: dict[str, Any], json_path: str, value: Any) -> None:
    if not json_path.startswith("$."):
        return
    parts = json_path[2:].split(".")
    current = payload
    for part in parts[:-1]:
        nested = current.get(part)
        if not isinstance(nested, dict):
            nested = {}
            current[part] = nested
        current = nested
    current[parts[-1]] = value


def build_synthetic_event(
    contract: SourceContract,
    required_fields: set[str],
    predicate_values: dict[str, Any],
    candidate: dict[str, Any],
) -> dict[str, Any]:
    """Build one parser-shaped NDJSON event for a converted Sentinel query."""
    event = deepcopy(contract.example)
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    event.setdefault("sentinelSynthetic", True)
    event.setdefault("sentinelId", candidate.get("sentinel_id", ""))
    event.setdefault("sourcePath", candidate.get("source_path", ""))
    event.setdefault("sentinelTitle", candidate.get("title", ""))
    for timestamp_field in (
        "@timestamp",
        "datetime",
        "eventTime",
        "time",
        "timeCreated",
        "timestamp",
        "TimeCreated",
        "Timestamp",
        "UtcTime",
    ):
        if timestamp_field in event or timestamp_field in {"timestamp", "TimeCreated", "Timestamp"}:
            event[timestamp_field] = timestamp
    for time_field in ("time", "Time"):
        for json_path in contract.field_paths.get(time_field, []):
            _set_json_path(event, json_path, timestamp)
    for field_name in sorted(required_fields):
        value = predicate_values.get(field_name, _default_value_for_field(field_name))
        for json_path in contract.field_paths.get(field_name, []):
            _set_json_path(event, json_path, value)
    return event


def _gap(reason: str, missing_fields: list[str], missing_sources: list[str]) -> dict[str, Any]:
    return {
        "reason": reason,
        "missing_fields": missing_fields,
        "missing_sources": missing_sources,
        "oci_steps": list(OCI_GAP_STEPS),
    }


def _progress_enabled(interval: float) -> bool:
    return interval >= 0


def _emit_progress(message: str, stream=None) -> None:
    print(f"[sentinel-synthetic] {message}", file=stream or sys.stderr, flush=True)


def build_synthetic_plan(
    *,
    top: int,
    candidates_file: Path = DEFAULT_CANDIDATES_FILE,
    data_dir: Path = DEFAULT_DATA_DIR,
    plan_path: Path = DEFAULT_PLAN_PATH,
    progress_interval: float = 30.0,
    progress_every: int = 100,
    progress_stream=None,
) -> dict[str, Any]:
    """Convert a batch and write synthetic NDJSON rows for parser-ready candidates."""
    candidates, source = load_candidates(candidates_file)
    mapping = load_mapping_config()
    contracts = load_source_contracts()
    selected = select_top_candidates(candidates, mapping, top=top)
    data_dir.mkdir(parents=True, exist_ok=True)

    started_at = time.monotonic()
    last_progress_at = started_at
    progress_every = max(1, int(progress_every))

    def maybe_progress(message: str, *, force: bool = False) -> None:
        nonlocal last_progress_at
        if not _progress_enabled(progress_interval):
            return
        now = time.monotonic()
        if force or progress_interval == 0 or now - last_progress_at >= progress_interval:
            _emit_progress(message, stream=progress_stream)
            last_progress_at = now

    maybe_progress(f"start top={top} selected={len(selected)} data_dir={data_dir}", force=True)

    rows_by_source_file: dict[str, list[dict[str, Any]]] = defaultdict(list)
    candidate_reports = []
    status_counts: Counter = Counter()

    for index, candidate in enumerate(selected, start=1):
        result = convert_candidate(candidate, mapping)
        context = f"{index}/{len(selected)} score={candidate.get('quality_score')} title=\"{candidate.get('title', '')[:96]}\""
        if not result.promoted_candidate:
            status_counts["conversion_skipped"] += 1
            candidate_reports.append({
                "title": candidate.get("title", ""),
                "sentinel_id": candidate.get("sentinel_id", ""),
                "quality_score": candidate.get("quality_score"),
                "source_path": candidate.get("source_path", ""),
                "status": "conversion_skipped",
                "skip_reasons": result.skip_reasons,
                "local_validation_errors": result.local_validation_errors,
            })
            maybe_progress(f"skip {context} reason=\"{(result.skip_reasons or result.local_validation_errors or [''])[0]}\"")
            continue

        query_payload = result.query_payload or {}
        query = query_payload.get("query", "")
        sources = extract_query_sources(query)
        required_fields = extract_required_fields(query)
        predicate_values = extract_predicate_values(query)
        contract, missing_fields, missing_sources = choose_source_contract(sources, required_fields, contracts)

        if not contract:
            status_counts["source_gap"] += 1
            candidate_reports.append({
                "title": candidate.get("title", ""),
                "sentinel_id": candidate.get("sentinel_id", ""),
                "quality_score": candidate.get("quality_score"),
                "source_path": candidate.get("source_path", ""),
                "status": "source_gap",
                "query": query,
                "sources": sources,
                "required_fields": sorted(required_fields),
                "gap": _gap("no existing parser/source contract for candidate sources", sorted(required_fields), missing_sources),
            })
            maybe_progress(f"source-gap {context} sources={','.join(sources)}")
            continue

        if missing_fields:
            status_counts["field_gap"] += 1
            candidate_reports.append({
                "title": candidate.get("title", ""),
                "sentinel_id": candidate.get("sentinel_id", ""),
                "quality_score": candidate.get("quality_score"),
                "source_path": candidate.get("source_path", ""),
                "status": "field_gap",
                "query": query,
                "selected_source": contract.source_display,
                "parser": contract.parser_display,
                "sources": sources,
                "required_fields": sorted(required_fields),
                "gap": _gap("selected parser does not expose every query field", missing_fields, missing_sources),
            })
            maybe_progress(f"field-gap {context} source=\"{contract.source_display}\" missing={len(missing_fields)}")
            continue

        event = build_synthetic_event(contract, required_fields, predicate_values, candidate)
        source_slug = slugify_title(contract.source_display)
        synthetic_file = f"{source_slug}.jsonl"
        rows_by_source_file[synthetic_file].append(event)
        status_counts["synthetic_ready"] += 1
        candidate_reports.append({
            "title": candidate.get("title", ""),
            "sentinel_id": candidate.get("sentinel_id", ""),
            "quality_score": candidate.get("quality_score"),
            "source_path": candidate.get("source_path", ""),
            "status": "synthetic_ready",
            "query": query,
            "selected_source": contract.source_display,
            "parser": contract.parser_display,
            "sources": sources,
            "required_fields": sorted(required_fields),
            "synthetic_file": synthetic_file,
        })
        maybe_progress(
            f"ready {context} source=\"{contract.source_display}\" fields={len(required_fields)}",
            force=progress_interval == 0 or index % progress_every == 0,
        )

    manifest_files = []
    for filename, rows in sorted(rows_by_source_file.items()):
        path = data_dir / filename
        path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
        manifest_files.append({"filename": filename, "events": len(rows)})

    manifest = {
        "version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "files": manifest_files,
    }
    (data_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    report = {
        "version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "summary": {
            "selected_candidates": len(selected),
            "synthetic_ready": status_counts["synthetic_ready"],
            "conversion_skipped": status_counts["conversion_skipped"],
            "source_gaps": status_counts["source_gap"],
            "field_gaps": status_counts["field_gap"],
            "data_dir": str(data_dir.relative_to(PROJECT_DIR) if data_dir.is_relative_to(PROJECT_DIR) else data_dir),
        },
        "files": manifest_files,
        "candidates": candidate_reports,
    }
    plan_path.parent.mkdir(parents=True, exist_ok=True)
    plan_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    maybe_progress(
        (
            f"complete ready={status_counts['synthetic_ready']} "
            f"source_gaps={status_counts['source_gap']} field_gaps={status_counts['field_gap']} "
            f"skipped={status_counts['conversion_skipped']} elapsed={int(time.monotonic() - started_at)}s "
            f"plan={plan_path}"
        ),
        force=True,
    )
    return report
