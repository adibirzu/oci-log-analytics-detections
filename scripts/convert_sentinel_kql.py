#!/usr/bin/env python3
"""Convert supported Microsoft Sentinel KQL into OCI Log Analytics Logan QL.

Facade module — public API enumerated in ``__all__`` (D-15). Phase 6 keeps
the full implementation here; plans 06-02..06-09 extract operator helpers
into ``scripts/kql/operators/<op>.py``; plan 06-10 reduces this file to
<=800 lines.
"""

from __future__ import annotations

__all__ = [
    "ConversionResult",
    "_clean_output_dir",
    "_write_query_payload",
    "build_conversion_report",
    "classify_unsupported_kql",
    "convert_candidate",
    "convert_candidates",
    "convert_kql_to_logan",
    "load_mapping_config",
    "rank_candidates",
    "select_top_candidates",
    "slugify_title",
    "validate_logan_query_local",
    # Phase 6 transitional re-exports — new callers should import from
    # ``scripts.kql.canonical`` / ``scripts.kql.types`` directly.
    "canonical",
    "CanonicalizationError",
    "Tier",
]

import argparse
import json
import re
import sys
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import yaml

from sync_sentinel_kql import (
    DEFAULT_CACHE_DIR,
    SENTINEL_LICENSE_URL,
    SENTINEL_WEB_URL,
    build_candidate_export,
    load_sentinel_candidates,
    resolve_sentinel_commit,
    sync_sentinel_repo,
)

PROJECT_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = PROJECT_DIR / "config" / "sentinel_oci_mapping.yaml"
DEFAULT_CANDIDATES_FILE = PROJECT_DIR / "queries" / "sentinel_candidates.json"
DEFAULT_OUTPUT_DIR = PROJECT_DIR / "queries" / "sentinel"
DEFAULT_REPORT_PATH = PROJECT_DIR / "queries" / "sentinel_conversion_report.json"
FIELD_DICTIONARY_PATH = PROJECT_DIR / "queries" / "log_source_field_dictionary.json"

LOGAN_BUILTIN_FIELDS = {
    "Channel",
    "Count",
    "Entity",
    "Event Type",
    "Image",
    "Log Source",
    "Original Log Content",
    "Provider",
    "Resource Name",
    "Severity",
    "Status",
    "Time",
    "Type",
    "User",
    "User Name",
    "msg",
    "time",
}

AZURE_AUDIT_SCHEMA_FIELDS = {
    "App Name",
    "Client IP",
    "Correlation ID",
    "Event Name",
    "Operation",
    "Resource Group",
    "Resource Provider",
    "Subscription ID",
    "Target Type",
    "Target UPN",
    "Tenant ID",
    "Workload",
}

LOGAN_COMMANDS = {
    "and",
    "as",
    "by",
    "count",
    "distinctcount",
    "eval",
    "fields",
    "head",
    "in",
    "like",
    "not",
    "or",
    "sort",
    "stats",
    "where",
}

ENTITY_ENRICHMENT_ALIASES = {
    "AccountName",
    "AccountCustomEntity",
    "AccountNTDomain",
    "AccountUPNSuffix",
    "Account_0_Name",
    "Account_0_NTDomain",
    "DnsDomain",
    "DNSCustomEntity",
    "DnsCustomEntity",
    "DomainIndex",
    "FileCustomEntity",
    "HostName",
    "HostNameDomain",
    "HostCustomEntity",
    "Host_0_DnsDomain",
    "Host_0_HostName",
    "IPCustomEntity",
    "IpCustomEntity",
    "IP_0_Address",
    "MalwareCustomEntity",
    "Name",
    "NTDomain",
    "URLCustomEntity",
    "UrlCustomEntity",
}

ENTITY_ENRICHMENT_ALIASES_NORMALIZED = {
    alias.lower() for alias in ENTITY_ENRICHMENT_ALIASES
}

SEVERITY_SCORE = {
    "critical": 40,
    "high": 35,
    "medium": 25,
    "low": 10,
    "informational": 5,
    "info": 5,
}

SUPPORTED_AGGREGATIONS = {
    "count": "count",
    "dcount": "distinctcount",
    "distinctcount": "distinctcount",
    "sum": "sum",
    "min": "min",
    "max": "max",
    "avg": "avg",
    "average": "average",
    "make_list": "unique",
    "makelist": "unique",
    "make_set": "unique",
    "makeset": "unique",
    "take_any": "unique",
    "any": "unique",
}

NUMERIC_FIELD_TYPES = {
    "DECIMAL",
    "DOUBLE",
    "FLOAT",
    "INTEGER",
    "LONG",
    "NUMBER",
    "SHORT",
}

STRING_FIELD_TYPES = {
    "STRING",
    "TEXT",
}

UNSUPPORTED_PATTERNS = [
    (re.compile(r"\bjoin\b", re.IGNORECASE), "unsupported KQL operator: join"),
    (re.compile(r"\blet\s+\w+\s*=", re.IGNORECASE), "unsupported KQL construct: let variables"),
    (re.compile(r"\bmake-series\b", re.IGNORECASE), "unsupported KQL operator: make-series"),
    (re.compile(r"\bmv-(?:expand|apply)\b", re.IGNORECASE), "unsupported KQL operator: mv-expand/mv-apply"),
    (re.compile(r"\bdatatable\s*\(", re.IGNORECASE), "unsupported KQL construct: datatable"),
    (re.compile(r"\bexternaldata\s*\(", re.IGNORECASE), "unsupported KQL construct: externaldata"),
    (re.compile(r"\b_?GetWatchlist\s*\(", re.IGNORECASE), "unsupported KQL construct: watchlists"),
    (re.compile(r"\bwatchlist\b", re.IGNORECASE), "unsupported KQL construct: watchlists"),
    (re.compile(r"\binvoke\b", re.IGNORECASE), "unsupported KQL construct: custom function invocation"),
    (re.compile(r"\bevaluate\b", re.IGNORECASE), "unsupported KQL operator: evaluate"),
    (re.compile(r"\bmaterialize\s*\(", re.IGNORECASE), "unsupported KQL function: materialize"),
    (re.compile(r"\bstrlen\s*\(", re.IGNORECASE), "unsupported KQL function: strlen"),
    (re.compile(r"\b(parse_json|todynamic|bag_unpack|bag_keys|extractjson)\s*\(", re.IGNORECASE), "unsupported KQL JSON bag expansion"),
    (re.compile(r"\bextract\s*\(", re.IGNORECASE), "unsupported KQL regex extraction"),
    (re.compile(r"\bmatches\s+regex\b", re.IGNORECASE), "unsupported KQL regex predicate"),
    (re.compile(r"\bcountif\s*\(", re.IGNORECASE), "unsupported KQL aggregate: countif"),
    (re.compile(r"\[[^\]]+\]\."), "unsupported KQL JSON/index path"),
]

LOGAN_UNSUPPORTED_PATTERNS = [
    re.compile(r"\b(?:summarize|project|extend|join|let|datatable|externaldata|make-series)\b", re.IGNORECASE),
    re.compile(r"\b(?:has|has_any|has_all|hasprefix|hassuffix|contains|startswith|endswith)\b", re.IGNORECASE),
    re.compile(r"\b(?:TimeGenerated|Timestamp|DeviceId)\b", re.IGNORECASE),
    re.compile(r"\bago\s*\(", re.IGNORECASE),
    re.compile(r"\b(?:bin|strlen|tolower|toupper|tostring|parse_json|toint|int)\s*\(", re.IGNORECASE),
    re.compile(r"==|=~|!~"),
    re.compile(r"\{\{|\}\}"),
]


@dataclass(frozen=True)
class ConversionResult:
    """Result for one Sentinel candidate conversion attempt."""

    candidate: dict
    query_payload: dict | None
    skip_reasons: list[str]
    local_validation_errors: list[str]
    live_validation_result: dict | None = None
    output_file: str = ""

    @property
    def promoted_candidate(self) -> bool:
        return self.query_payload is not None and not self.skip_reasons and not self.local_validation_errors


def load_mapping_config(path: Path = CONFIG_PATH) -> dict:
    """Load Sentinel table/field mapping configuration."""
    with Path(path).open(encoding="utf-8") as handle:
        payload = yaml.safe_load(handle) or {}
    allowed_fields = set(payload.get("allowed_fields", []))
    allowed_fields.update(LOGAN_BUILTIN_FIELDS)
    allowed_fields.update(AZURE_AUDIT_SCHEMA_FIELDS)
    allowed_fields.update(_load_field_dictionary_fields())
    return {
        "tables": payload.get("tables", {}),
        "fields": payload.get("fields", {}),
        "allowed_fields": allowed_fields,
        "field_types": _load_field_dictionary_field_types(),
    }


def _load_field_dictionary_fields(path: Path = FIELD_DICTIONARY_PATH) -> set[str]:
    """Return OCI Log Analytics field display names from the generated dictionary."""
    if not path.exists():
        return set()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    fields = set(payload.get("approved_builtins", []))
    for field in payload.get("fields", []):
        display_name = field.get("display_name")
        if display_name:
            fields.add(display_name)
    return fields


def _load_field_dictionary_field_types(path: Path = FIELD_DICTIONARY_PATH) -> dict[str, str]:
    """Return OCI field display name to field type mappings from the generated dictionary."""
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    field_types: dict[str, str] = {}
    for field in payload.get("fields", []):
        display_name = field.get("display_name")
        field_type = field.get("type") or field.get("data_type")
        if display_name and field_type:
            field_types[display_name] = str(field_type).upper()
    return field_types


def _strip_string_literals(text: str) -> str:
    """Replace quoted strings with empty quotes for safe token scanning."""
    return re.sub(r"'(?:\\'|[^'])*'|\"(?:\\\"|[^\"])*\"", "''", text)


def _strip_single_quoted_literals(text: str) -> str:
    """Remove Logan single-quoted literals while preserving unsafe outside tokens."""
    stripped: list[str] = []
    in_quote = False
    escaped = False
    for char in text:
        if in_quote:
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if char == "'":
                in_quote = False
                stripped.append("''")
            continue
        if char == "'":
            in_quote = True
            escaped = False
            continue
        stripped.append(char)
    return "".join(stripped)


def _strip_kql_comments(kql: str) -> str:
    lines = []
    for line in kql.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("//"):
            continue
        quote: str | None = None
        escaped = False
        cleaned: list[str] = []
        index = 0
        while index < len(line):
            char = line[index]
            if escaped:
                cleaned.append(char)
                escaped = False
                index += 1
                continue
            if quote:
                cleaned.append(char)
                if char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                index += 1
                continue
            if char in ("'", '"'):
                quote = char
                cleaned.append(char)
                index += 1
                continue
            if char == "/" and index + 1 < len(line) and line[index + 1] == "/":
                break
            cleaned.append(char)
            index += 1
        cleaned_line = "".join(cleaned).rstrip()
        if cleaned_line.strip():
            lines.append(cleaned_line)
    return "\n".join(lines).strip()


def _find_top_level_semicolon(text: str) -> int:
    quote: str | None = None
    escaped = False
    depth = 0
    for index, char in enumerate(text):
        if escaped:
            escaped = False
            continue
        if quote:
            if char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in ("'", '"'):
            quote = char
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}" and depth:
            depth -= 1
        elif char == ";" and depth == 0:
            return index
    return -1


def _normalize_simple_let_expression(expression: str) -> str | None:
    value = expression.strip()
    if not value:
        return None
    stripped = _strip_string_literals(value)
    if "|" in stripped or ";" in stripped:
        return None
    if re.search(
        r"\b(?:datatable|externaldata|join|materialize|project|summarize|table|toscalar|union|where)\b",
        stripped,
        re.IGNORECASE,
    ):
        return None

    array_match = re.fullmatch(
        r"(?:dynamic|pack_array)\s*\(\s*\[(?P<values>[\s\S]*)\]\s*\)",
        value,
        flags=re.IGNORECASE,
    )
    if array_match:
        values = array_match.group("values").strip()
        return values or None

    if value.startswith("[") and value.endswith("]"):
        values = value[1:-1].strip()
        return values or None

    if re.fullmatch(r"-?\d+(?:\.\d+)?", value):
        return value
    if re.fullmatch(r"\d+(?:\.\d+)?(?:d|h|m|s|ms)", value, flags=re.IGNORECASE):
        return value
    if re.fullmatch(r"(?:ago|datetime)\s*\([^|;]+\)", value, flags=re.IGNORECASE):
        return value
    if re.fullmatch(r"now\s*\(\s*\)", value, flags=re.IGNORECASE):
        return value
    if re.fullmatch(r"@?(?:'[^']*'|\"[^\"]*\")", value, flags=re.DOTALL):
        return value
    return None


def _replace_unquoted_variables(text: str, variables: dict[str, str]) -> str:
    if not variables:
        return text
    names = set(variables)
    output: list[str] = []
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        if escaped:
            output.append(char)
            escaped = False
            index += 1
            continue
        if quote:
            output.append(char)
            if char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in ("'", '"'):
            quote = char
            output.append(char)
            index += 1
            continue
        if char.isalpha() or char == "_":
            end = index + 1
            while end < len(text) and (text[end].isalnum() or text[end] == "_"):
                end += 1
            token = text[index:end]
            output.append(variables[token] if token in names else token)
            index = end
            continue
        output.append(char)
        index += 1
    return "".join(output)


def _preprocess_simple_lets(kql: str) -> tuple[str, list[str]]:
    text = _strip_kql_comments(kql).strip()
    variables: dict[str, str] = {}
    while True:
        match = re.match(r"\s*let\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=", text, flags=re.IGNORECASE)
        if not match:
            break
        remainder = text[match.end():]
        semicolon = _find_top_level_semicolon(remainder)
        if semicolon < 0:
            return text, ["unsupported KQL construct: let variables"]
        expression = remainder[:semicolon].strip()
        normalized = _normalize_simple_let_expression(expression)
        if normalized is None:
            return text, ["unsupported KQL construct: let variables"]
        variables[match.group("name")] = normalized
        text = remainder[semicolon + 1:].lstrip()

    if re.search(r"\blet\s+\w+\s*=", _strip_string_literals(text), flags=re.IGNORECASE):
        return text, ["unsupported KQL construct: let variables"]
    return _replace_unquoted_variables(text, variables), []


def _split_top_level(text: str, delimiter: str = ",") -> list[str]:
    parts = []
    current = []
    quote: str | None = None
    depth = 0
    for char in text:
        if quote:
            current.append(char)
            if char == quote:
                quote = None
            continue
        if char in ("'", '"'):
            quote = char
            current.append(char)
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}" and depth:
            depth -= 1
        if char == delimiter and depth == 0:
            part = "".join(current).strip()
            if part:
                parts.append(part)
            current = []
            continue
        current.append(char)
    part = "".join(current).strip()
    if part:
        parts.append(part)
    return parts


def _split_kql_stages(kql: str) -> list[str]:
    stages = []
    current = []
    quote: str | None = None
    depth = 0
    for char in _strip_kql_comments(kql):
        if quote:
            current.append(char)
            if char == quote:
                quote = None
            continue
        if char in ("'", '"'):
            quote = char
            current.append(char)
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}" and depth:
            depth -= 1
        if char == "|" and depth == 0:
            part = "".join(current).strip()
            if part:
                stages.append(part)
            current = []
            continue
        current.append(char)
    part = "".join(current).strip()
    if part:
        stages.append(part)
    return stages


def _classify_unsupported_kql_text(kql: str) -> list[str]:
    """Return deterministic skip reasons for unsupported KQL features."""
    stripped = _strip_string_literals(kql)
    reasons = []
    for pattern, reason in UNSUPPORTED_PATTERNS:
        if pattern.search(stripped):
            reasons.append(reason)
    return sorted(set(reasons))


def classify_unsupported_kql(kql: str) -> list[str]:
    """Return deterministic skip reasons for unsupported KQL features."""
    preprocessed, preprocessing_errors = _preprocess_simple_lets(kql)
    return sorted(set(preprocessing_errors + _classify_unsupported_kql_text(preprocessed)))


def _clean_table_name(raw: str) -> str:
    text = raw.strip()
    text = re.sub(r"^\s*\(", "", text)
    text = re.sub(r"\)\s*$", "", text)
    text = text.split()[0] if text.split() else text
    return text.strip("`'\" ")


def extract_source_tables(kql: str) -> list[str]:
    """Extract simple KQL source table names from the first stage."""
    stages = _split_kql_stages(kql)
    if not stages:
        return []
    source = stages[0].strip()
    if source.lower().startswith("union "):
        union_body = source[6:].strip()
        union_body = re.sub(r"\b(?:isfuzzy|kind|withsource)\s*=\s*[^,\s]+", "", union_body, flags=re.IGNORECASE)
        return [_clean_table_name(part) for part in _split_top_level(union_body) if _clean_table_name(part)]
    return [_clean_table_name(source)] if _clean_table_name(source) else []


def _source_filter_for_tables(tables: Iterable[str], mapping: dict) -> tuple[str, list[str], str, str]:
    table_config = mapping["tables"]
    sources: list[str] = []
    categories: list[str] = []
    services: list[str] = []
    for table in tables:
        config = table_config.get(table)
        if not config:
            continue
        for source in config.get("sources", []):
            if source not in sources:
                sources.append(source)
        category = config.get("category", "unknown")
        service = config.get("service", category)
        if category not in categories:
            categories.append(category)
        if service not in services:
            services.append(service)

    if not sources:
        return "", [], "", ""
    filters = [f"'Log Source' = '{_escape_logan_string(source)}'" for source in sources]
    if len(filters) == 1:
        return filters[0], sources, categories[0], services[0]
    return "(" + " or ".join(filters) + ")", sources, categories[0], services[0]


def _escape_logan_string(value) -> str:
    if value is None:
        return ""
    return str(value).replace("\\", "\\\\").replace("'", "\\'")


def _normalize_field_name(field: str) -> str:
    return field.strip().strip("`'\" ")


def _field_is_quoted(field: str) -> bool:
    return len(field) >= 2 and field[0] == "'" and field[-1] == "'"


def _display_field_name(field: str) -> str:
    value = field.strip()
    if _field_is_quoted(value):
        return value[1:-1].replace("\\'", "'")
    return value


def _logan_field_reference(display_name: str) -> str:
    """Return a Logan field reference, quoting display fields that need it."""
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", display_name):
        return display_name
    return f"'{_escape_logan_string(display_name)}'"


def _is_allowed_logan_field(field: str, mapping: dict, allowed_aliases: set[str] | None = None) -> bool:
    display_name = _display_field_name(field)
    if allowed_aliases and display_name in allowed_aliases:
        return True
    return display_name in mapping.get("allowed_fields", set())


def _record_field_error(errors: list[str] | None, reason: str) -> None:
    if errors is not None:
        errors.append(reason)


def map_field(
    field: str,
    mapping: dict,
    errors: list[str] | None = None,
    allowed_aliases: set[str] | None = None,
) -> str:
    """Map a Sentinel/KQL field name into a Logan display field."""
    raw = _normalize_field_name(field)
    if raw in mapping["fields"]:
        mapped = mapping["fields"][raw]
        if not _is_allowed_logan_field(mapped, mapping, allowed_aliases):
            _record_field_error(errors, f"unsupported OCI field reference: {_display_field_name(mapped)}")
        return mapped
    if allowed_aliases and raw in allowed_aliases:
        return raw
    if raw in mapping.get("allowed_fields", set()):
        return _logan_field_reference(raw)
    if raw in {"TimeGenerated", "Timestamp"}:
        return "Time"
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", raw):
        _record_field_error(errors, f"unsupported Sentinel field mapping: {raw}")
        return raw
    _record_field_error(errors, f"unsupported Sentinel field mapping: {raw}")
    return f"'{_escape_logan_string(raw)}'"


def _format_value(value: str) -> str:
    raw = _literal_value(value)
    if raw.lower() == "null":
        return "null"
    if re.fullmatch(r"-?\d+(?:\.\d+)?", raw):
        return raw
    if raw.lower() in {"true", "false"}:
        return f"'{raw.lower()}'"
    return f"'{_escape_logan_string(raw)}'"


def _literal_value(value: str) -> str:
    raw = value.strip()
    if raw.startswith("@"):
        raw = raw[1:].strip()
    if raw.startswith("(") and raw.endswith(")"):
        raw = raw[1:-1].strip()
    if (raw.startswith("'") and raw.endswith("'")) or (raw.startswith('"') and raw.endswith('"')):
        raw = raw[1:-1]
    return raw


def _format_value_for_field(value: str, field: str, mapping: dict) -> str:
    raw = _literal_value(value)
    if raw.lower() == "null":
        return "null"
    field_type = mapping.get("field_types", {}).get(_display_field_name(field), "").upper()
    if field_type in NUMERIC_FIELD_TYPES and re.fullmatch(r"-?\d+(?:\.\d+)?", raw):
        return raw
    if field_type in STRING_FIELD_TYPES:
        if raw.lower() in {"true", "false"}:
            raw = raw.lower()
        return f"'{_escape_logan_string(raw)}'"
    return _format_value(value)


def _cleanup_boolean_expression(expression: str) -> str:
    text = re.sub(r"\bAND\b", "and", expression, flags=re.IGNORECASE)
    text = re.sub(r"\bOR\b", "or", text, flags=re.IGNORECASE)
    text = re.sub(r"\bNOT\b", "not", text, flags=re.IGNORECASE)
    text = re.sub(r"\s+", " ", text).strip()
    text = re.sub(r"^\s*(?:and|or)\s+", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s+(?:and|or)\s*$", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\(\s*\)", "", text)
    text = re.sub(r"\(\s*(and|or)\s+", "(", text, flags=re.IGNORECASE)
    text = re.sub(r"\s+(and|or)\s*\)", ")", text, flags=re.IGNORECASE)
    return text.strip()


def _remove_time_filters(predicate: str) -> str:
    text = predicate
    time_field = r"(?:TimeGenerated|Timestamp|EventCreationTime|EventEndTime|CreationTime|StartTime|EndTime)"
    patterns = [
        rf"(?:\s*(?:and|or)\s*)?\b{time_field}\s+(?:between)\s*\([^)]*\)",
        rf"(?:\s*(?:and|or)\s*)?\b{time_field}\s*(?:>=|>|<=|<|==|=~|=)\s*(?:ago\([^)]*\)|datetime\([^)]*\)|[^\s)]+)",
    ]
    for pattern in patterns:
        text = re.sub(pattern, " ", text, flags=re.IGNORECASE)
    return _cleanup_boolean_expression(text)


def convert_predicate(
    predicate: str,
    mapping: dict,
    allowed_aliases: set[str] | None = None,
) -> tuple[str, list[str]]:
    """Convert a supported KQL predicate into Logan QL."""
    expression = _remove_time_filters(_strip_kql_comments(predicate))
    if not expression:
        return "", []

    errors: list[str] = []
    field_token = r"(?:[A-Za-z_][A-Za-z0-9_]*|`[^`]+`|'[^']+'|\"[^\"]+\")"
    value_token = r"(?:@?'[^']*'|@?\"[^\"]*\"|-?\d+(?:\.\d+)?|true|false|null)"

    def replace_isnotempty(match: re.Match) -> str:
        field = map_field(match.group("field"), mapping, errors, allowed_aliases)
        return f"({field} != null and {field} != '')"

    def replace_isempty(match: re.Match) -> str:
        field = map_field(match.group("field"), mapping, errors, allowed_aliases)
        return f"({field} = null or {field} = '')"

    expression = re.sub(
        rf"\bisnotempty\s*\(\s*(?P<field>{field_token})\s*\)",
        replace_isnotempty,
        expression,
        flags=re.IGNORECASE,
    )
    expression = re.sub(
        rf"\bisempty\s*\(\s*(?P<field>{field_token})\s*\)",
        replace_isempty,
        expression,
        flags=re.IGNORECASE,
    )

    def replace_in(match: re.Match) -> str:
        field = map_field(match.group("field"), mapping, errors, allowed_aliases)
        values = [_format_value_for_field(value, field, mapping) for value in _split_top_level(match.group("values"))]
        operator = "not in" if match.group("op").lower().startswith(("!", "not")) else "in"
        return f"{field} {operator} ({', '.join(values)})"

    expression = re.sub(
        rf"(?P<field>{field_token})\s+(?P<op>in~?|!in~?|not\s+in~?)\s*\((?P<values>[^)]*)\)",
        replace_in,
        expression,
        flags=re.IGNORECASE,
    )

    def replace_collection_string_operator(match: re.Match) -> str:
        field = map_field(match.group("field"), mapping, errors, allowed_aliases)
        op = match.group("op").lower()
        connector = " and " if op == "has_all" else " or "
        clauses = []
        for value in _split_top_level(match.group("values")):
            formatted = _format_value(value)
            raw_value = formatted[1:-1] if formatted.startswith("'") and formatted.endswith("'") else formatted
            clauses.append(f"{field} like '{_escape_logan_string('*' + raw_value + '*')}'")
        clause = connector.join(clauses)
        if len(clauses) > 1:
            clause = f"({clause})"
        return f"not ({clause})" if match.group("neg") else clause

    expression = re.sub(
        rf"(?P<field>{field_token})\s+(?P<neg>!|not\s+)?(?P<op>has_any|has_all)\s*\((?P<values>[^)]*)\)",
        replace_collection_string_operator,
        expression,
        flags=re.IGNORECASE,
    )

    def replace_string_operator(match: re.Match) -> str:
        field = map_field(match.group("field"), mapping, errors, allowed_aliases)
        value = match.group("value").strip()
        if value.startswith("(") and value.endswith(")"):
            value = value[1:-1].strip()
        if value.startswith("@"):
            value = value[1:].strip()
        raw_value = value[1:-1] if value[:1] in {"'", '"'} and value[-1:] == value[:1] else value
        op = match.group("op").lower().replace("_cs", "")
        if op in {"has", "contains"}:
            pattern = f"*{raw_value}*"
        elif op in {"startswith", "hasprefix"}:
            pattern = f"{raw_value}*"
        elif op in {"endswith", "hassuffix"}:
            pattern = f"*{raw_value}"
        else:
            pattern = raw_value
        clause = f"{field} like '{_escape_logan_string(pattern)}'"
        return f"not ({clause})" if match.group("neg") else clause

    expression = re.sub(
        rf"(?P<field>{field_token})\s+(?P<neg>!|not\s+)?(?P<op>has_cs|has|hasprefix|hassuffix|contains_cs|contains|startswith|endswith)\s+(?P<value>(?:\(\s*{value_token}\s*\)|{value_token}))",
        replace_string_operator,
        expression,
        flags=re.IGNORECASE,
    )

    def replace_comparison(match: re.Match) -> str:
        field = map_field(match.group("field"), mapping, errors, allowed_aliases)
        op = match.group("op")
        if op in {"==", "=~"}:
            op = "="
        elif op in {"<>", "!~"}:
            op = "!="
        return f"{field} {op} {_format_value_for_field(match.group('value'), field, mapping)}"

    expression = re.sub(
        rf"(?P<field>{field_token})\s*(?P<op>==|=~|!~|!=|<>|>=|<=|>|<|=)\s*(?P<value>{value_token})",
        replace_comparison,
        expression,
        flags=re.IGNORECASE,
    )

    expression = _cleanup_boolean_expression(expression)
    leftovers = _strip_string_literals(expression)
    if re.search(r"\b(?:has|has_any|has_all|hasprefix|hassuffix|contains|startswith|endswith|in~)\b|==|=~|!~", leftovers, flags=re.IGNORECASE):
        errors.append(f"unsupported predicate expression: {predicate}")
    if re.search(r"\b(?!(?:and|in|not|or)\b)[A-Za-z_][A-Za-z0-9_]*\s*\(", leftovers, flags=re.IGNORECASE):
        errors.append(f"unsupported predicate expression: {predicate}")
    return expression, sorted(set(errors))


def _convert_fields_clause(
    clause: str,
    mapping: dict,
    errors: list[str] | None = None,
    allowed_aliases: set[str] | None = None,
) -> str:
    fields = []
    for field in _split_top_level(clause):
        alias, expression = _split_alias_expression(field)
        bin_match = re.fullmatch(
            r"bin\s*\(\s*(?P<field>[A-Za-z_][A-Za-z0-9_]*)\s*,\s*[^)]+\)",
            expression.strip(),
            flags=re.IGNORECASE,
        )
        if bin_match and bin_match.group("field") in {"TimeGenerated", "Timestamp"}:
            fields.append("Time")
            continue
        if alias and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", expression):
            fields.append(map_field(expression, mapping, errors, allowed_aliases))
            continue
        if alias:
            _record_field_error(errors, f"unsupported project expression: {field}")
            continue
        fields.append(map_field(field, mapping, errors, allowed_aliases))
    return ", ".join(fields)


def _sanitize_alias(alias: str, fallback: str) -> str:
    raw = alias.strip().strip("'\"")
    if not raw:
        raw = fallback
    raw = re.sub(r"[^A-Za-z0-9_]+", "_", raw).strip("_")
    if not raw:
        raw = fallback
    if raw[0].isdigit():
        raw = f"m_{raw}"
    return raw


def _default_aggregate_alias(func: str, field: str, index: int) -> str:
    if func == "count":
        return "count_"
    if _normalize_field_name(field) in {"TimeGenerated", "Timestamp"}:
        field = "Time"
    field_alias = _sanitize_alias(field, f"{func}_{index}")
    if func in {"make_set", "makeset"}:
        return f"set_{field_alias}"
    if func in {"make_list", "makelist"}:
        return f"list_{field_alias}"
    if func in {"take_any", "any"}:
        return f"any_{field_alias}"
    return f"{func}_{index}"


def _unique_alias(alias: str, used_aliases: set[str]) -> str:
    """Return a deterministic alias that does not collide with previous aliases."""
    if alias not in used_aliases:
        used_aliases.add(alias)
        return alias
    suffix = 2
    while f"{alias}_{suffix}" in used_aliases:
        suffix += 1
    unique = f"{alias}_{suffix}"
    used_aliases.add(unique)
    return unique


def _split_alias_expression(raw: str) -> tuple[str, str]:
    depth = 0
    quote: str | None = None
    for index, char in enumerate(raw):
        if quote:
            if char == quote:
                quote = None
            continue
        if char in ("'", '"'):
            quote = char
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}" and depth:
            depth -= 1
        elif char == "=" and depth == 0:
            return raw[:index].strip(), raw[index + 1:].strip()
    return "", raw.strip()


def _convert_summarize(
    stage: str,
    mapping: dict,
    allowed_aliases: set[str] | None = None,
) -> tuple[str, list[str], set[str]]:
    clause = re.sub(r"^\s*summarize\s+", "", stage, flags=re.IGNORECASE).strip()
    parts = re.split(r"\s+by\s+", clause, maxsplit=1, flags=re.IGNORECASE)
    aggregate_clause = parts[0].strip()
    by_clause = parts[1].strip() if len(parts) == 2 else ""
    errors = []
    aggregates = []
    aggregate_aliases: set[str] = set()
    used_aliases = set(allowed_aliases or set())
    for index, raw_aggregate in enumerate(_split_top_level(aggregate_clause), start=1):
        alias, expression = _split_alias_expression(raw_aggregate)
        match = re.fullmatch(r"(?P<func>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<field>[^)]*)\)", expression.strip())
        if not match:
            errors.append(f"unsupported summarize aggregate: {raw_aggregate}")
            continue
        func = match.group("func").lower()
        if func not in SUPPORTED_AGGREGATIONS:
            errors.append(f"unsupported summarize aggregate: {raw_aggregate}")
            continue
        mapped_func = SUPPORTED_AGGREGATIONS[func]
        field = match.group("field").strip()
        field_args = _split_top_level(field)
        field = field_args[0].strip() if field_args else field
        alias = _sanitize_alias(alias, f"{func}_{index}") if alias else _default_aggregate_alias(func, field, index)
        alias = _unique_alias(alias, used_aliases)
        aggregate_aliases.add(alias)
        if func == "count" and not field:
            aggregates.append(f"count as {alias}")
        else:
            aggregates.append(f"{mapped_func}({map_field(field, mapping, errors, allowed_aliases)}) as {alias}")

    if not aggregates:
        errors.append("summarize stage did not produce supported aggregates")
        return "", errors, aggregate_aliases

    if by_clause:
        return (
            f"stats {', '.join(aggregates)} by {_convert_fields_clause(by_clause, mapping, errors, allowed_aliases)}",
            errors,
            aggregate_aliases,
        )
    return f"stats {', '.join(aggregates)}", errors, aggregate_aliases


def _convert_sort(stage: str, mapping: dict, errors: list[str], allowed_aliases: set[str]) -> str:
    clause = re.sub(r"^\s*(?:sort|order)\s+(?:by\s+)?", "", stage, flags=re.IGNORECASE).strip()
    first = _split_top_level(clause)[0] if _split_top_level(clause) else clause
    tokens = first.split()
    field = tokens[0] if tokens else first
    direction = tokens[1].lower() if len(tokens) > 1 else "asc"
    mapped = map_field(field, mapping, errors, allowed_aliases)
    prefix = "-" if direction in {"desc", "descending"} else ""
    return f"sort {prefix}{mapped}"


def _convert_top(stage: str, mapping: dict, errors: list[str], allowed_aliases: set[str]) -> list[str]:
    match = re.match(r"top\s+(?P<count>\d+)(?:\s+by\s+(?P<field>[A-Za-z_][A-Za-z0-9_']*)(?:\s+(?P<direction>asc|desc))?)?", stage, flags=re.IGNORECASE)
    if not match:
        return []
    commands = []
    field = match.group("field")
    if field:
        direction = match.group("direction") or "desc"
        mapped = map_field(field, mapping, errors, allowed_aliases)
        commands.append(f"sort {'-' if direction.lower() == 'desc' else ''}{mapped}")
    commands.append(f"head {match.group('count')}")
    return commands


def _convert_extend(stage: str, mapping: dict, allowed_aliases: set[str]) -> tuple[list[str], list[str], set[str]]:
    clause = re.sub(r"^\s*extend\s+", "", stage, flags=re.IGNORECASE).strip()
    commands = []
    errors = []
    aliases: set[str] = set()
    for assignment in _split_top_level(clause):
        alias, expression = _split_alias_expression(assignment)
        if not alias:
            errors.append(f"unsupported extend expression: {assignment}")
            continue
        sanitized_alias = _sanitize_alias(alias, "extended_field")
        if sanitized_alias.lower() in ENTITY_ENRICHMENT_ALIASES_NORMALIZED:
            continue
        if re.search(r"\w+\s*\(", expression):
            errors.append(f"unsupported extend expression: {assignment}")
            continue
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", expression.strip()):
            rhs = map_field(expression, mapping, errors, allowed_aliases)
        else:
            rhs = _format_value(expression)
        aliases.add(sanitized_alias)
        commands.append(f"eval {sanitized_alias} = {rhs}")
    return commands, errors, aliases


def convert_kql_to_logan(kql: str, mapping: dict) -> tuple[str, dict, list[str]]:
    """Convert a supported KQL query into Logan QL."""
    kql, preprocessing_errors = _preprocess_simple_lets(kql)
    errors = sorted(set(preprocessing_errors + _classify_unsupported_kql_text(kql)))
    if errors:
        return "", {}, errors

    stages = _split_kql_stages(kql)
    if not stages:
        return "", {}, ["empty KQL query"]

    tables = extract_source_tables(kql)
    missing_tables = [table for table in tables if table not in mapping["tables"]]
    if missing_tables:
        return "", {}, [f"unsupported Sentinel table: {table}" for table in missing_tables]

    source_filter, sources, category, service = _source_filter_for_tables(tables, mapping)
    if not source_filter:
        return "", {}, ["query did not resolve to a mapped Logan source"]

    filters = [source_filter]
    commands: list[str] = []
    aliases: set[str] = set()
    for stage in stages[1:]:
        lowered = stage.lower().strip()
        if re.match(r"(?:where|filter)\b", lowered):
            predicate = re.sub(r"^\s*(?:where|filter)\b", "", stage, flags=re.IGNORECASE).strip()
            predicate, predicate_errors = convert_predicate(predicate, mapping, aliases)
            errors.extend(predicate_errors)
            if predicate:
                if commands:
                    commands.append(f"where {predicate}")
                else:
                    filters.append(f"({predicate})")
        elif re.match(r"project-away\b", lowered):
            continue
        elif re.match(r"project(?:-reorder)?\b", lowered):
            project_clause = re.sub(r"^\s*project(?:-reorder)?\s+", "", stage, flags=re.IGNORECASE).strip()
            fields_clause = _convert_fields_clause(project_clause, mapping, errors, aliases)
            if fields_clause:
                commands.append(f"fields {fields_clause}")
        elif re.match(r"extend\b", lowered):
            extend_commands, extend_errors, extend_aliases = _convert_extend(stage, mapping, aliases)
            commands.extend(extend_commands)
            errors.extend(extend_errors)
            aliases.update(extend_aliases)
        elif re.match(r"summarize\b", lowered):
            command, summarize_errors, aggregate_aliases = _convert_summarize(stage, mapping, aliases)
            if command:
                commands.append(command)
            errors.extend(summarize_errors)
            aliases.update(aggregate_aliases)
        elif re.match(r"(?:sort|order)\b", lowered):
            commands.append(_convert_sort(stage, mapping, errors, aliases))
        elif re.match(r"(?:take|limit)\b", lowered):
            count = re.findall(r"\d+", stage)
            if count:
                commands.append(f"head {count[0]}")
            else:
                errors.append(f"unsupported limit stage: {stage}")
        elif re.match(r"top\b", lowered):
            top_commands = _convert_top(stage, mapping, errors, aliases)
            if top_commands:
                commands.extend(top_commands)
            else:
                errors.append(f"unsupported top stage: {stage}")
        elif re.match(r"distinct\b", lowered):
            distinct_clause = re.sub(r"^\s*distinct\b", "", stage, flags=re.IGNORECASE).strip()
            fields_clause = _convert_fields_clause(distinct_clause, mapping, errors, aliases)
            if fields_clause:
                commands.append(f"stats count as Count by {fields_clause}")
                aliases.add("Count")
        elif re.match(r"render\b", lowered):
            continue
        else:
            errors.append(f"unsupported KQL stage: {stage}")

    if errors:
        return "", {}, sorted(set(errors))

    query = " and ".join(filters)
    if commands:
        query = f"{query} | " + " | ".join(commands)
    return query, {
        "tables": tables,
        "sources": sources,
        "category": category,
        "service": service,
    }, []


def _iter_quoted_values(text: str):
    in_quote = False
    escaped = False
    start = 0
    value: list[str] = []
    for index, char in enumerate(text):
        if escaped:
            value.append(char)
            escaped = False
            continue
        if char == "\\" and in_quote:
            escaped = True
            value.append(char)
            continue
        if char == "'":
            if in_quote:
                yield "".join(value), start, index + 1
                in_quote = False
                value = []
            else:
                in_quote = True
                start = index
                value = []
            continue
        if in_quote:
            value.append(char)


def _quote_context_indicates_field(query: str, start: int, end: int) -> bool:
    after = query[end:]
    before = query[:start]
    if re.match(r"\s*(?:=|!=|>=|<=|>|<|\blike\b|\bnot\s+like\b|\bin\b|\bnot\s+in\b|\bis\b)", after, re.IGNORECASE):
        return True
    tail = before[-48:].lower()
    return bool(re.search(r"\b(?:distinctcount|unique|count|sum|max|min|avg|average)\s*\($", tail))


def _extract_query_field_references(query: str) -> set[str]:
    fields: set[str] = set()
    for value, start, end in _iter_quoted_values(query):
        if _quote_context_indicates_field(query, start, end):
            fields.add(value)
    for by_match in re.finditer(
        r"\|\s*(?:stats|eventstats|timestats|link)[^|]*\bby\b(?P<clause>[^|]+)",
        query,
        flags=re.IGNORECASE,
    ):
        fields.update(value for value, _start, _end in _iter_quoted_values(by_match.group("clause")))
    for fields_match in re.finditer(r"\|\s*fields\s+(?P<clause>[^|]+)", query, flags=re.IGNORECASE):
        fields.update(value for value, _start, _end in _iter_quoted_values(fields_match.group("clause")))
    return fields


def _extract_query_aliases(query: str) -> set[str]:
    aliases = set(re.findall(r"\bas\s+([A-Za-z_][A-Za-z0-9_]*)\b", query, flags=re.IGNORECASE))
    aliases.update(re.findall(r"\|\s*eval\s+([A-Za-z_][A-Za-z0-9_]*)\s*=", query, flags=re.IGNORECASE))
    return aliases


def _extract_unquoted_operator_fields(query: str) -> set[str]:
    stripped = _strip_string_literals(query)
    fields: set[str] = set()
    pattern = re.compile(
        r"(?<!['\"])\b(?P<field>[A-Za-z_][A-Za-z0-9_]*)\s*(?:=|!=|>=|<=|>|<|\blike\b|\bnot\s+like\b|\bin\b|\bnot\s+in\b|\bis\b)",
        re.IGNORECASE,
    )
    for match in pattern.finditer(stripped):
        field = match.group("field")
        if field.lower() not in LOGAN_COMMANDS:
            fields.add(field)
    return fields


def validate_logan_query_local(query: str, mapping: dict | None = None) -> list[str]:
    """Run offline safety checks for generated Logan QL."""
    errors = []
    if not query or not query.strip():
        return ["empty Logan query"]
    mapping = mapping or load_mapping_config()
    if query.count("'") % 2 != 0:
        errors.append("unbalanced single quotes")
    if "'Log Source'" not in query:
        errors.append("missing Logan Log Source filter")
    if re.search(r"\{\{|\}\}", query):
        errors.append("query contains unresolved placeholder braces")
    if re.search(r"\b(?:GOES HERE|REPLACE_ME|CHANGE_ME|INSERT_HERE|YOUR_VALUE)\b", query, re.IGNORECASE):
        errors.append("query contains unresolved placeholder text")
    outside_string_literals = _strip_single_quoted_literals(query)
    if '"' in outside_string_literals:
        errors.append("query contains unsafe double quote outside Logan string literal")
    if ";" in outside_string_literals:
        errors.append("query contains unsafe semicolon outside Logan string literal")
    stripped = _strip_string_literals(query)
    for pattern in LOGAN_UNSUPPORTED_PATTERNS:
        if pattern.search(stripped):
            errors.append(f"unsupported Logan output token: {pattern.pattern}")
    for stats_match in re.finditer(r"\|\s*stats\b(?P<body>[^|]*?)\bby\b(?P<fields>[^|]+)", stripped, flags=re.IGNORECASE):
        by_fields = [field.strip() for field in _split_top_level(stats_match.group("fields"))]
        if "Time" in by_fields:
            errors.append("unsupported OCI time grouping: Time")
    if re.search(r"(?<!https):\s*[A-Za-z_][A-Za-z0-9_]*", stripped):
        errors.append("query contains colon placeholder syntax")
    allowed_fields = mapping.get("allowed_fields", set())
    aliases = _extract_query_aliases(query)
    for field in sorted(_extract_query_field_references(query)):
        if field not in allowed_fields and field not in aliases:
            errors.append(f"unsupported OCI field reference: {field}")
    for field in sorted(_extract_unquoted_operator_fields(query)):
        if field not in allowed_fields and field not in aliases:
            errors.append(f"unsupported OCI field reference: {field}")
    return sorted(set(errors))


def slugify_title(title: str) -> str:
    """Create a stable filesystem-safe slug."""
    slug = re.sub(r"[^a-z0-9_-]+", "_", title.lower()).strip("_")
    return slug[:96] or "sentinel_query"


def _reference_entries(candidate: dict) -> list[dict]:
    references = []
    if candidate.get("source_url"):
        references.append({"name": "Microsoft Sentinel source rule", "url": candidate["source_url"]})
    references.append({"name": "Microsoft Sentinel repository", "url": SENTINEL_WEB_URL})
    references.append({"name": "Azure/Azure-Sentinel license", "url": SENTINEL_LICENSE_URL})
    return references


def _dashboard_metadata(query: str) -> dict:
    visualization = "summary_table" if "| stats " in query else "table"
    return {
        "visualizationType": visualization,
        "timeSelection": {"timePeriod": "l24h"},
        "ask_ai_prompts": [
            "Summarize the Microsoft Sentinel converted detection results and identify the highest-risk pivots."
        ],
    }


def build_query_payload(candidate: dict, query: str, source_info: dict, live_validation_status: str) -> dict:
    """Build a saved-search JSON payload for one promoted Sentinel conversion."""
    level = candidate.get("severity", "medium")
    return {
        "title": candidate.get("title", "Microsoft Sentinel Converted Detection"),
        "description": candidate.get("description", ""),
        "query": query,
        "level": level,
        "source_type": "microsoft_sentinel",
        "sentinel_id": candidate.get("sentinel_id", ""),
        "sentinel_source_path": candidate.get("source_path", ""),
        "sentinel_source_url": candidate.get("source_url", ""),
        "required_data_connectors": candidate.get("required_data_connectors", []),
        "conversion_status": "promoted",
        "conversion_confidence": "medium",
        "source_confidence": "high",
        "live_validation_status": live_validation_status,
        "sentinel_tables": source_info.get("tables", []),
        "sentinel_category": source_info.get("category", "unknown"),
        "tags": ["microsoft_sentinel", f"sentinel.{source_info.get('category', 'unknown')}"],
        "mitre_attack": candidate.get("mitre_attack", {"tactics": [], "techniques": []}),
        "logsource": {
            "product": "microsoft_sentinel",
            "service": source_info.get("service", "unknown"),
            "candidates": source_info.get("sources", []),
            "original_tables": source_info.get("tables", []),
        },
        "references": _reference_entries(candidate),
        "attribution": candidate.get("attribution", {
            "source": "Microsoft Sentinel",
            "repository": "Azure/Azure-Sentinel",
            "license": "MIT",
            "license_url": SENTINEL_LICENSE_URL,
        }),
        "dashboard": _dashboard_metadata(query),
        "detection_maturity": "source_converted",
        "field_coverage": "mapped_subset",
        "test_data_coverage": "not_evaluated",
        "scheduled_rule_eligibility": "not_evaluated",
    }


def convert_candidate(candidate: dict, mapping: dict, live_validation_status: str = "not_run") -> ConversionResult:
    """Convert one Sentinel candidate, returning skip reasons on failure."""
    query, source_info, errors = convert_kql_to_logan(candidate.get("query", ""), mapping)
    if errors:
        return ConversionResult(candidate, None, errors, [])

    local_errors = validate_logan_query_local(query)
    payload = build_query_payload(candidate, query, source_info, live_validation_status)
    return ConversionResult(candidate, payload, [], local_errors)


def rank_candidate(candidate: dict, mapping: dict) -> int:
    """Quality-first candidate scoring."""
    score = SEVERITY_SCORE.get(str(candidate.get("severity", "medium")).lower(), 20)
    if candidate.get("description"):
        score += min(len(candidate["description"]) // 80, 10)
    mitre = candidate.get("mitre_attack", {})
    score += len(mitre.get("tactics", [])) * 5
    score += len(mitre.get("techniques", [])) * 5
    if candidate.get("required_data_connectors"):
        score += 8
    if candidate.get("kind") == "analytics_rule":
        score += 5

    unsupported = classify_unsupported_kql(candidate.get("query", ""))
    if unsupported:
        score -= 1000
    tables = extract_source_tables(candidate.get("query", ""))
    if tables and all(table in mapping["tables"] for table in tables):
        score += 20
    else:
        score -= 300
    if len(candidate.get("query", "")) > 5000:
        score -= 25
    return score


def rank_candidates(candidates: list[dict], mapping: dict) -> list[dict]:
    """Return candidates sorted by deterministic quality score."""
    ranked = []
    for candidate in candidates:
        ranked.append({**candidate, "quality_score": rank_candidate(candidate, mapping)})
    return sorted(
        ranked,
        key=lambda item: (
            -item["quality_score"],
            item.get("source_path", ""),
            item.get("sentinel_id", ""),
        ),
    )


def select_top_candidates(candidates: list[dict], mapping: dict, top: int = 1000) -> list[dict]:
    """Select the top N quality-ranked candidates."""
    return rank_candidates(candidates, mapping)[:top]


def _load_candidates_from_file(path: Path) -> tuple[list[dict], dict]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return payload.get("candidates", []), payload.get("source", {})


def _validate_live(query_file: str, query: str, lookback: str, timeout: int) -> dict:
    from deploy_dashboard import validate_query_in_oci_isolated, resolve_validation_namespace

    namespace = resolve_validation_namespace(timeout)
    return validate_query_in_oci_isolated(
        namespace=namespace,
        query_file=query_file,
        query_string=query,
        lookback=lookback,
        query_timeout=timeout,
    )


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


def _write_query_payload(output_dir: Path, payload: dict) -> str:
    base = slugify_title(payload["title"])
    filename = f"{base}.json"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / filename
    if output_path.exists():
        try:
            existing = json.loads(output_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            existing = {}
        same_source_rule = (
            existing.get("sentinel_id") == payload.get("sentinel_id")
            and existing.get("sentinel_source_path") == payload.get("sentinel_source_path")
        )
        if not same_source_rule:
            suffix = slugify_title(str(payload.get("sentinel_id") or payload.get("sentinel_source_path") or "sentinel"))[:24]
            filename = f"{base}_{suffix}.json"
            output_path = output_dir / filename
            counter = 2
            while output_path.exists():
                filename = f"{base}_{suffix}_{counter}.json"
                output_path = output_dir / filename
                counter += 1
    output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return f"sentinel/{filename}"


def _clean_output_dir(output_dir: Path) -> None:
    if not output_dir.exists():
        return
    for path in output_dir.glob("*.json"):
        path.unlink()


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
        "summary": {
            "total_candidates": len(candidates),
            "attempted_candidates": len(attempted),
            "promoted_count": len(promoted),
            "converted_count": len(converted),
            "skipped_count": len(skipped),
            "ranking": "quality-first",
            "live_validation_requested": validate_live,
            "live_validation_passed": len(live_passed),
            "live_validation_failed": len(live_failed),
            "tier_distribution": tier_distribution,
        },
        "unsupported_features": dict(sorted(unsupported_counts.items())),
        "attempted": [
            {
                "sentinel_id": result.candidate.get("sentinel_id", ""),
                "title": result.candidate.get("title", ""),
                "quality_score": result.candidate.get("quality_score"),
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
                    result.live_validation_result.get("error", "")
                    if result.live_validation_result else ""
                ),
            }
            for result, tier in zip(results, result_tiers)
        ],
    }


def convert_candidates(
    candidates: list[dict],
    mapping: dict,
    top: int = 1000,
    validate_live: bool = False,
    write_working: bool = False,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    report_path: Path = DEFAULT_REPORT_PATH,
    source: dict | None = None,
    lookback: str = "24h",
    timeout: int = 60,
    clean_output: bool = False,
    progress_interval: float = 30.0,
    progress_every: int = 100,
    progress_stream=None,
) -> dict:
    """Rank, convert, optionally live-validate, and optionally write queries."""
    attempted = select_top_candidates(candidates, mapping, top=top)
    if write_working and clean_output:
        _clean_output_dir(output_dir)

    progress_enabled = progress_interval >= 0
    progress_stream = progress_stream or sys.stderr
    progress_every = max(1, int(progress_every))
    started_at = time.monotonic()
    last_progress_at = started_at
    counters: Counter = Counter()

    def maybe_progress(message: str, *, force: bool = False) -> None:
        nonlocal last_progress_at
        if not progress_enabled:
            return
        now = time.monotonic()
        if force or progress_interval == 0 or now - last_progress_at >= progress_interval:
            _emit_progress(progress_stream, message)
            last_progress_at = now

    maybe_progress(
        (
            f"start total_candidates={len(candidates)} attempted={len(attempted)} "
            f"live_validation={validate_live} write_working={write_working} timeout={timeout}s"
        ),
        force=True,
    )

    results: list[ConversionResult] = []
    total_attempted = len(attempted)
    for index, candidate in enumerate(attempted, start=1):
        context = _progress_context(candidate, index, total_attempted)
        if not validate_live:
            maybe_progress(f"candidate-start {context}", force=index == 1)

        result = convert_candidate(candidate, mapping)
        if result.promoted_candidate and validate_live:
            tentative_file = f"sentinel/{slugify_title(result.query_payload['title'])}.json"
            maybe_progress(f"live-start {context} query_file=\"{tentative_file}\"", force=True)
            live_started_at = time.monotonic()
            live_result = _validate_live(tentative_file, result.query_payload["query"], lookback, timeout)
            live_status = "passed" if live_result.get("ok") else "failed"
            payload = {**result.query_payload, "live_validation_status": live_status}
            result = ConversionResult(
                candidate=result.candidate,
                query_payload=payload,
                skip_reasons=[] if live_result.get("ok") else ["live OCI validation failed"],
                local_validation_errors=result.local_validation_errors,
                live_validation_result=live_result,
            )
            duration = _format_elapsed(time.monotonic() - live_started_at)
            live_reason = _safe_progress_error(live_result.get("error", "")) if not live_result.get("ok") else ""
            reason_text = f" reason=\"{live_reason}\"" if live_reason else ""
            maybe_progress(f"live-{live_status} {context} duration={duration}{reason_text}", force=True)

        output_file = ""
        if write_working and result.promoted_candidate:
            output_file = _write_query_payload(output_dir, result.query_payload)
        if output_file:
            result = ConversionResult(
                candidate=result.candidate,
                query_payload=result.query_payload,
                skip_reasons=result.skip_reasons,
                local_validation_errors=result.local_validation_errors,
                live_validation_result=result.live_validation_result,
                output_file=output_file,
            )
        results.append(result)

        status = _conversion_status_label(result, output_file=output_file)
        counters[status] += 1
        if result.live_validation_result and result.live_validation_result.get("ok"):
            counters["live_passed"] += 1
        elif result.live_validation_result and status != "live_failed":
            counters["live_failed"] += 1
        reason = _progress_reason(result)
        reason_text = f" reason=\"{reason}\"" if reason else ""
        maybe_progress(
            (
                f"candidate-done {context} status={status}{reason_text} "
                f"converted={counters['converted']} promoted={counters['promoted']} "
                f"skipped={counters['skipped']} local_failed={counters['local_failed']} "
                f"live_failed={counters['live_failed']}"
            ),
            force=progress_interval == 0 or index % progress_every == 0 or index == total_attempted,
        )

    report = build_conversion_report(
        candidates=candidates,
        attempted=attempted,
        results=results,
        source=source or {},
        validate_live=validate_live,
    )
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    maybe_progress(
        (
            f"complete attempted={total_attempted} converted={report['summary']['converted_count']} "
            f"promoted={report['summary']['promoted_count']} skipped={report['summary']['skipped_count']} "
            f"live_passed={report['summary']['live_validation_passed']} "
            f"live_failed={report['summary']['live_validation_failed']} "
            f"elapsed={_format_elapsed(time.monotonic() - started_at)} report=\"{report_path}\""
        ),
        force=True,
    )
    return report


def _ensure_candidates(args) -> tuple[list[dict], dict]:
    candidates_path = Path(args.candidates_file)
    if candidates_path.exists():
        return _load_candidates_from_file(candidates_path)

    cache_dir = Path(args.source_dir)
    if not args.no_sync:
        commit = sync_sentinel_repo(cache_dir=cache_dir, ref=args.ref, refresh=args.refresh)
    else:
        commit = resolve_sentinel_commit(cache_dir)
        if not cache_dir.exists():
            raise FileNotFoundError(f"Sentinel checkout not found: {cache_dir}")

    candidates = load_sentinel_candidates(cache_dir, commit=commit)
    export = build_candidate_export(candidates, commit=commit)
    candidates_path.parent.mkdir(parents=True, exist_ok=True)
    candidates_path.write_text(json.dumps(export, indent=2) + "\n", encoding="utf-8")
    return candidates, export["source"]


def main() -> int:
    parser = argparse.ArgumentParser(description="Convert Microsoft Sentinel KQL to Logan QL")
    parser.add_argument("--top", type=int, default=1000, help="Number of quality-ranked candidates to attempt")
    parser.add_argument("--validate-local", action="store_true", help="Run local conversion validation")
    parser.add_argument("--validate-live", action="store_true", help="Run live OCI Log Analytics parser validation")
    parser.add_argument("--write-working", action="store_true", help="Write converted queries that pass validation")
    parser.add_argument(
        "--allow-local-write",
        action="store_true",
        help="Allow writing local-only conversions without live validation",
    )
    parser.add_argument("--clean-output", action="store_true", help="Clean queries/sentinel/*.json before writing")
    parser.add_argument("--candidates-file", default=str(DEFAULT_CANDIDATES_FILE))
    parser.add_argument("--source-dir", default=str(DEFAULT_CACHE_DIR), help="Sentinel repo cache directory")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    parser.add_argument("--report", default=str(DEFAULT_REPORT_PATH))
    parser.add_argument("--ref", default="master", help="Sentinel git ref for auto-sync")
    parser.add_argument("--refresh", action="store_true", help="Fetch remote changes during auto-sync")
    parser.add_argument("--no-sync", action="store_true", help="Do not fetch if candidates file is missing")
    parser.add_argument("--query-lookback", default="24h", help="Lookback window for live validation")
    parser.add_argument("--query-timeout", type=int, default=60, help="Per-query live validation timeout")
    parser.add_argument(
        "--progress-interval",
        type=float,
        default=30.0,
        help="Seconds between periodic progress lines; set 0 for every candidate, -1 to disable.",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=100,
        help="Emit a candidate progress line at least every N attempted candidates.",
    )
    args = parser.parse_args()

    if args.write_working and not args.validate_live and not args.allow_local_write:
        parser.error("--write-working requires --validate-live unless --allow-local-write is supplied")

    mapping = load_mapping_config()
    candidates, source = _ensure_candidates(args)
    report = convert_candidates(
        candidates=candidates,
        mapping=mapping,
        top=args.top,
        validate_live=args.validate_live,
        write_working=args.write_working,
        output_dir=Path(args.output_dir),
        report_path=Path(args.report),
        source=source,
        lookback=args.query_lookback,
        timeout=args.query_timeout,
        clean_output=args.clean_output,
        progress_interval=args.progress_interval,
        progress_every=args.progress_every,
    )

    summary = report["summary"]
    print("Microsoft Sentinel conversion")
    print(f"  Candidates: {summary['total_candidates']}")
    print(f"  Attempted:  {summary['attempted_candidates']}")
    print(f"  Converted:  {summary['converted_count']}")
    print(f"  Promoted:   {summary['promoted_count']}")
    print(f"  Skipped:    {summary['skipped_count']}")
    print(f"  Report:     {Path(args.report)}")
    return 0


# Phase 6 transitional re-exports. Import at the bottom to avoid pulling the
# kql subpackage during this module's top-of-file execution (which is where
# legacy helpers used by the subpackage are defined).
from scripts.kql.canonical import (  # noqa: E402,F401
    CanonicalizationError,
    canonical,
)
from scripts.kql.types import Tier  # noqa: E402,F401


if __name__ == "__main__":
    raise SystemExit(main())
