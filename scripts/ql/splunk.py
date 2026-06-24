"""Splunk SPL conversion helpers for Logan Forge.

The converter is intentionally bounded. It supports common SPL pipeline
commands and emits explicit warnings or dependency metadata when SPL semantics
depend on Splunk runtime state, lookup materialization, or event correlation.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


BACKEND_NAME = "scripts/logan_workbench_convert.py"
FIELD_MAP = {
    "_raw": "Original Log Content",
    "_time": "Time",
    "action": "Action",
    "command": "Command Line",
    "commandline": "Command Line",
    "computer": "Host Name",
    "dest": "Destination IP",
    "dest_ip": "Destination IP",
    "dest_port": "Destination Port",
    "destination": "Destination IP",
    "destination_ip": "Destination IP",
    "destination_port": "Destination Port",
    "eventcode": "Event ID",
    "eventid": "Event ID",
    "host": "Host Name",
    "hostname": "Host Name",
    "image": "Process Name",
    "method": "Request Method",
    "parentimage": "Parent Process Name",
    "process": "Process Name",
    "process_name": "Process Name",
    "processname": "Process Name",
    "src": "Source IP",
    "src_ip": "Source IP",
    "source_ip": "Source IP",
    "sourcetype": "Log Source",
    "status": "Response Code",
    "status_code": "Response Code",
    "threat": "Threat Name",
    "uri": "Request URL",
    "url": "Request URL",
    "user": "User Name",
    "username": "User Name",
}

BLOCKED_COMMANDS = {"join"}
DEPENDENCY_COMMANDS = {"inputlookup", "outputlookup", "tstats"}
REVIEW_COMMANDS = {"streamstats", "eventstats", "mvexpand", "append", "appendcols"}
BOOLEAN_TOKENS = {"and", "or", "not"}


@dataclass(frozen=True)
class SplConversion:
    query: str
    support_level: str
    warnings: list[dict[str, str]]
    metadata: dict[str, Any]


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def warning(code: str, message: str, severity: str = "warning") -> dict[str, str]:
    return {"code": code, "message": message, "severity": severity}


def response(
    *,
    source_query: str,
    logan_query: str,
    support_level: str,
    explanation: str,
    warnings: list[dict[str, str]] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "generated_at": now_iso(),
        "source_language": "splunk_spl",
        "source_query": source_query,
        "logan_query": logan_query,
        "support_level": support_level,
        "explanation": explanation,
        "warnings": warnings or [],
        "metadata": metadata or {},
        "backend": BACKEND_NAME,
    }


def quote_field(field: str) -> str:
    return field if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", field) else f"'{field}'"


def quote_value(value: str) -> str:
    normalized = value.strip().strip('"').strip("'")
    return f"'{normalized.replace(chr(39), chr(92) + chr(39))}'"


def display_field(field: str) -> str:
    normalized = field.strip().strip("'\"").lower()
    return FIELD_MAP.get(normalized, field.strip().strip("'\""))


def split_pipeline(query: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    quote = ""
    bracket_depth = 0
    escape = False
    for char in query:
        if escape:
            buf.append(char)
            escape = False
            continue
        if char == "\\":
            buf.append(char)
            escape = True
            continue
        if quote:
            buf.append(char)
            if char == quote:
                quote = ""
            continue
        if char in {"'", '"'}:
            quote = char
            buf.append(char)
            continue
        if char == "[":
            bracket_depth += 1
            buf.append(char)
            continue
        if char == "]" and bracket_depth:
            bracket_depth -= 1
            buf.append(char)
            continue
        if char == "|" and bracket_depth == 0:
            part = "".join(buf).strip()
            if part:
                parts.append(part)
            buf = []
            continue
        buf.append(char)
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return parts


def split_tokens(text: str) -> list[str]:
    tokens: list[str] = []
    buf: list[str] = []
    quote = ""
    paren_depth = 0
    escape = False
    for char in text.strip():
        if escape:
            buf.append(char)
            escape = False
            continue
        if char == "\\":
            buf.append(char)
            escape = True
            continue
        if quote:
            buf.append(char)
            if char == quote:
                quote = ""
            continue
        if char in {"'", '"'}:
            quote = char
            buf.append(char)
            continue
        if char == "(":
            paren_depth += 1
            buf.append(char)
            continue
        if char == ")" and paren_depth:
            paren_depth -= 1
            buf.append(char)
            continue
        if char.isspace() and paren_depth == 0:
            token = "".join(buf).strip()
            if token:
                tokens.append(token)
            buf = []
            continue
        buf.append(char)
    token = "".join(buf).strip()
    if token:
        tokens.append(token)
    return tokens


def source_for_query(query: str) -> str:
    lowered = query.lower()
    if "sysmon" in lowered or re.search(r"\beventcode\s*=\s*1\b", lowered):
        return "Windows Sysmon Events"
    if any(marker in lowered for marker in ("index=network", "src_ip", "dest_ip", "destination_ip", "network_traffic")):
        return "OCI VCN Flow Logs"
    if any(marker in lowered for marker in ("http", "uri", "url", "status=", "status_code")):
        return "SOC Application Logs"
    if "wineventlog:security" in lowered or "eventcode=4688" in lowered:
        return "Windows Security Events"
    return "SOC Application Logs"


def value_predicate(display: str, operator: str, value: str) -> str:
    field = quote_field(display)
    normalized_value = value.strip().strip('"').strip("'")
    if normalized_value in {"*", "%"}:
        return f"{field} is not null"
    if operator in {"!=", "<>"}:
        return f"{field} != {quote_value(value)}"
    if operator in {">", ">=", "<", "<="}:
        return f"{field} {operator} {quote_value(value)}"
    if "*" in normalized_value or "%" in normalized_value:
        return f"{field} like {quote_value(normalized_value.replace('%', '*'))}"
    return f"{field} = {quote_value(value)}"


def in_predicate(field: str, values_text: str) -> str:
    display = quote_field(display_field(field))
    raw_values = [item.strip().strip('"').strip("'") for item in values_text.split(",")]
    values = [quote_value(item) for item in raw_values if item]
    return f"{display} in ({', '.join(values)})" if values else ""


def search_predicates(text: str, warnings: list[dict[str, str]]) -> list[str]:
    predicates: list[str] = []
    consumed_spans: list[tuple[int, int]] = []
    for match in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_.-]*)\s+IN\s*\(([^)]*)\)", text, flags=re.IGNORECASE):
        predicate = in_predicate(match.group(1), match.group(2))
        if predicate:
            predicates.append(predicate)
        consumed_spans.append(match.span())

    reduced = text
    for start, end in reversed(consumed_spans):
        reduced = f"{reduced[:start]} {' ' * (end - start)} {reduced[end:]}"

    for token in split_tokens(reduced):
        lowered = token.lower()
        if lowered in BOOLEAN_TOKENS:
            if lowered != "and":
                warnings.append(warning("spl_boolean_review", f"SPL boolean operator {token} needs manual precedence review."))
            continue
        if lowered.startswith(("index=", "sourcetype=", "source=")):
            continue
        match = re.match(r"^([A-Za-z_][A-Za-z0-9_.-]*)(!?=|<>|>=|<=|>|<)(.+)$", token)
        if match:
            field, operator, value = match.groups()
            predicates.append(value_predicate(display_field(field), operator, value))
            continue
        if token.startswith(("(", ")")):
            warnings.append(warning("spl_group_review", "Grouped SPL search expressions need manual validation."))
            continue
        raw = token.strip('"').strip("'")
        if raw:
            predicates.append(f"'Original Log Content' like {quote_value(f'*{raw}*')}")
    return predicates


def where_predicates(text: str, warnings: list[dict[str, str]]) -> list[str]:
    stripped = re.sub(r"^where\s+", "", text.strip(), flags=re.IGNORECASE)
    predicates: list[str] = []
    for match in re.finditer(r"\bisnotnull\s*\(\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*\)", stripped, flags=re.IGNORECASE):
        predicates.append(f"{quote_field(display_field(match.group(1)))} is not null")
    for match in re.finditer(r"\bisnull\s*\(\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*\)", stripped, flags=re.IGNORECASE):
        predicates.append(f"{quote_field(display_field(match.group(1)))} is null")
    for match in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_.-]*)\s+IN\s*\(([^)]*)\)", stripped, flags=re.IGNORECASE):
        predicate = in_predicate(match.group(1), match.group(2))
        if predicate:
            predicates.append(predicate)
    for token in re.split(r"\s+(?:AND|and)\s+", stripped):
        match = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*(==|=|!=|<>|>=|<=|>|<)\s*(.+?)\s*$", token)
        if match and not match.group(3).lower().startswith(("if(", "case(", "match(", "like(")):
            field, operator, value = match.groups()
            predicates.append(value_predicate(display_field(field), "=" if operator == "==" else operator, value))
    if not predicates:
        warnings.append(warning("unsupported_spl_where", "Only simple SPL where predicates and null checks are converted."))
    return predicates


def stats_step(command: str, time_span: str | None, warnings: list[dict[str, str]]) -> str:
    text = re.sub(r"^stats\s+", "", command.strip(), flags=re.IGNORECASE)
    by_match = re.search(r"\s+by\s+(.+)$", text, flags=re.IGNORECASE)
    group_fields = []
    if by_match:
        group_fields = [quote_field(display_field(token)) for token in split_tokens(by_match.group(1).replace(",", " "))]
        aggregate_text = text[: by_match.start()].strip()
    else:
        aggregate_text = text.strip()

    aggregate = "count as count"
    distinct_match = re.search(r"\b(?:dc|distinct_count|count_distinct)\s*\(\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*\)(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?", aggregate_text, flags=re.IGNORECASE)
    values_match = re.search(r"\bvalues\s*\(\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*\)(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?", aggregate_text, flags=re.IGNORECASE)
    sum_match = re.search(r"\bsum\s*\(\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*\)(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?", aggregate_text, flags=re.IGNORECASE)
    count_match = re.search(r"\bcount(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?", aggregate_text, flags=re.IGNORECASE)
    if distinct_match:
        alias = distinct_match.group(2) or "distinct_count"
        aggregate = f"distinctcount({quote_field(display_field(distinct_match.group(1)))}) as {alias}"
    elif values_match:
        alias = values_match.group(2) or "values"
        aggregate = f"values({quote_field(display_field(values_match.group(1)))}) as {alias}"
        warnings.append(warning("spl_multivalue_review", "Validate values() aggregation syntax against OCI before promotion."))
    elif sum_match:
        alias = sum_match.group(2) or "sum"
        aggregate = f"sum({quote_field(display_field(sum_match.group(1)))}) as {alias}"
    elif count_match:
        alias = count_match.group(1) or "count"
        aggregate = f"count as {alias}"
    else:
        warnings.append(warning("unsupported_spl_stats", "Only count, distinct count, values, and sum SPL stats are converted."))

    command_name = "timestats" if time_span else "stats"
    span = f" span={time_span}" if time_span else ""
    groups = f" by {', '.join(group_fields)}" if group_fields else ""
    return f"{command_name}{span} {aggregate}{groups}"


def timechart_step(command: str, warnings: list[dict[str, str]]) -> str:
    span_match = re.search(r"\bspan\s*=\s*([0-9]+[smhdw])", command, flags=re.IGNORECASE)
    by_match = re.search(r"\s+by\s+([A-Za-z_][A-Za-z0-9_.-]*)", command, flags=re.IGNORECASE)
    alias_match = re.search(r"\bcount(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?", command, flags=re.IGNORECASE)
    if not alias_match:
        warnings.append(warning("unsupported_spl_timechart", "Only count-based SPL timechart commands are converted."))
    span = span_match.group(1) if span_match else "5m"
    alias = alias_match.group(1) if alias_match and alias_match.group(1) else "count"
    group = f" by {quote_field(display_field(by_match.group(1)))}" if by_match else ""
    return f"timestats span={span} count as {alias}{group}"


def fields_step(command: str) -> str:
    text = re.sub(r"^(?:fields|table)\s+", "", command.strip(), flags=re.IGNORECASE)
    fields = [quote_field(display_field(token)) for token in split_tokens(text.replace(",", " ")) if not token.startswith(("+", "-"))]
    return f"fields {', '.join(fields)}" if fields else ""


def rename_step(command: str) -> str:
    pairs = []
    for match in re.finditer(r"([A-Za-z_][A-Za-z0-9_.-]*)\s+as\s+([A-Za-z_][A-Za-z0-9_.-]*)", command, flags=re.IGNORECASE):
        pairs.append(f"{quote_field(display_field(match.group(1)))} as {quote_field(match.group(2))}")
    return f"rename {', '.join(pairs)}" if pairs else ""


def sort_step(command: str) -> str:
    text = re.sub(r"^sort\s+", "", command.strip(), flags=re.IGNORECASE)
    tokens = [token for token in split_tokens(text.replace(",", " ")) if token != "0"]
    fields = []
    skip_next = False
    for index, token in enumerate(tokens):
        if skip_next:
            skip_next = False
            continue
        if token in {"-", "+"} and index + 1 < len(tokens):
            fields.append(f"{'-' if token == '-' else ''}{quote_field(display_field(tokens[index + 1]))}")
            skip_next = True
            continue
        if token.startswith("-"):
            fields.append(f"-{quote_field(display_field(token[1:]))}")
        elif token.startswith("+"):
            fields.append(quote_field(display_field(token[1:])))
        else:
            fields.append(quote_field(display_field(token)))
    return f"sort {', '.join(fields)}" if fields else ""


def lookup_step(command: str, warnings: list[dict[str, str]], dependencies: list[str]) -> str:
    tokens = split_tokens(command)
    if len(tokens) < 2:
        warnings.append(warning("unsupported_spl_lookup", "Lookup command is missing the table name."))
        return ""
    table = tokens[1]
    match_field = ""
    for index, token in enumerate(tokens[2:], start=2):
        if token.lower() == "as" and index + 1 < len(tokens):
            match_field = tokens[index + 1]
            break
    if not match_field and len(tokens) >= 3:
        match_field = tokens[2]
    dependencies.append(f"oci_lookup:{table}")
    warnings.append(warning("lossy_lookup", f"Create or map an OCI lookup table named {table} before promotion."))
    return f"lookup {table} {quote_field(display_field(match_field or 'Source IP'))}"


def rex_step(command: str, warnings: list[dict[str, str]], dependencies: list[str]) -> str:
    field_match = re.search(r"\bfield\s*=\s*([A-Za-z_][A-Za-z0-9_.-]*)", command, flags=re.IGNORECASE)
    regex_match = re.search(r"([\"'])(?P<regex>.*?)(?<!\\)\1", command)
    if not regex_match:
        warnings.append(warning("unsupported_spl_rex", "SPL rex without a quoted expression was not converted."))
        return ""
    regex_text = regex_match.group("regex")
    names = re.findall(r"\(\?<([A-Za-z_][A-Za-z0-9_]*)>", regex_text)
    if not names:
        warnings.append(warning("unsupported_spl_rex", "Only named-capture SPL rex expressions are converted."))
        return ""
    source_field = quote_field(display_field(field_match.group(1) if field_match else "_raw"))
    dependencies.append("parser:rex_named_capture")
    warnings.append(warning("spl_rex_review", "Validate converted rex extraction syntax and parser behavior before promotion."))
    escaped_regex = regex_text.replace("/", "\\/")
    return " | ".join(f"eval {name} = extract({source_field}, /{escaped_regex}/)" for name in names)


def spath_step(command: str, warnings: list[dict[str, str]], dependencies: list[str]) -> str:
    input_match = re.search(r"\binput\s*=\s*([A-Za-z_][A-Za-z0-9_.-]*)", command, flags=re.IGNORECASE)
    path_match = re.search(r"\bpath\s*=\s*([A-Za-z0-9_.{}-]+)", command, flags=re.IGNORECASE)
    output_match = re.search(r"\boutput\s*=\s*([A-Za-z_][A-Za-z0-9_]*)", command, flags=re.IGNORECASE)
    if not path_match or not output_match:
        warnings.append(warning("unsupported_spl_spath", "Only spath commands with path= and output= are converted."))
        return ""
    source_field = quote_field(display_field(input_match.group(1) if input_match else "_raw"))
    dependencies.append("parser:json_path_extraction")
    warnings.append(warning("spl_spath_review", "Validate converted JSON path extraction against the OCI parser."))
    return f"eval {output_match.group(1)} = json_value({source_field}, '{path_match.group(1)}')"


def transaction_step(command: str, warnings: list[dict[str, str]], dependencies: list[str]) -> str:
    text = re.sub(r"^transaction\s+", "", command.strip(), flags=re.IGNORECASE)
    tokens = [token for token in split_tokens(text.replace(",", " ")) if "=" not in token]
    fields = [quote_field(display_field(token)) for token in tokens[:3]]
    if not fields:
        warnings.append(warning("unsupported_spl_transaction", "Transaction conversion requires at least one grouping field."))
        return ""
    dependencies.append("correlation:spl_transaction")
    warnings.append(warning("lossy_transaction", "SPL transaction duration/event-boundary behavior is approximated with Logan link."))
    return f"link {', '.join(fields)}"


def subsearch_dependencies(query: str, warnings: list[dict[str, str]], dependencies: list[str]) -> None:
    for match in re.finditer(r"\[([^\[\]]+)\]", query):
        subquery = match.group(1).strip()
        digest = hashlib.sha256(subquery.encode("utf-8")).hexdigest()[:12]
        inputlookup = re.search(r"\binputlookup\s+([A-Za-z0-9_.-]+)", subquery, flags=re.IGNORECASE)
        if inputlookup:
            dependencies.append(f"oci_lookup:{inputlookup.group(1)}")
            warnings.append(warning("spl_subsearch_lookup", f"Subsearch inputlookup {inputlookup.group(1)} must be modeled as an OCI lookup dependency."))
        else:
            dependencies.append(f"spl_subsearch:{digest}")
            warnings.append(warning("spl_subsearch", "SPL subsearch was retained as a staged dependency instead of being inlined."))


def convert_pipeline(query: str) -> SplConversion:
    parts = split_pipeline(query)
    warnings = [warning("heuristic_spl", "SPL conversion covers common search pipeline commands; validate advanced SPL manually.")]
    dependencies: list[str] = []
    converted_commands: list[str] = []
    source = source_for_query(query)
    predicates = [f"'Log Source' = '{source}'"]
    pipeline: list[str] = []
    time_span: str | None = None
    unsupported: list[str] = []
    lossy = False

    if "`" in query or re.search(r"\$[A-Za-z0-9_.:-]+\$", query):
        warnings.append(warning("spl_macro", "SPL macro or dashboard token syntax must be expanded before conversion."))
    subsearch_dependencies(query, warnings, dependencies)
    if dependencies:
        lossy = any(item.startswith("spl_subsearch:") for item in dependencies)

    for position, part in enumerate(parts):
        command = part.strip()
        command_name = command.split(None, 1)[0].lower() if command.split(None, 1) else "search"
        if position == 0 and command_name not in {"search", "where", "stats", "timechart", "table", "fields", "lookup", "sort", "head", "dedup", "top", "rename", "eval", "bin", "bucket", "rex", "spath", "transaction"}:
            command_name = "search"

        if command_name in BLOCKED_COMMANDS or command_name in DEPENDENCY_COMMANDS:
            unsupported.append(command_name)
            continue
        if command_name in REVIEW_COMMANDS:
            warnings.append(warning("spl_parser_review", f"SPL {command_name} depends on parser/runtime semantics and was not rewritten."))
            lossy = True
            continue

        if command_name == "search":
            text = re.sub(r"^search\s+", "", command, flags=re.IGNORECASE)
            predicates.extend(search_predicates(text, warnings))
        elif command_name == "where":
            where_parts = where_predicates(command, warnings)
            if where_parts:
                pipeline.append(f"where {' and '.join(where_parts)}")
        elif command_name == "stats":
            pipeline.append(stats_step(command, time_span, warnings))
            time_span = None
        elif command_name == "timechart":
            pipeline.append(timechart_step(command, warnings))
        elif command_name in {"table", "fields"}:
            step = fields_step(command)
            if step:
                pipeline.append(step)
        elif command_name == "rename":
            step = rename_step(command)
            if step:
                pipeline.append(step)
        elif command_name == "sort":
            step = sort_step(command)
            if step:
                pipeline.append(step)
        elif command_name == "head":
            match = re.search(r"\bhead\s+([0-9]+)", command, flags=re.IGNORECASE)
            pipeline.append(f"head {match.group(1) if match else 100}")
        elif command_name == "dedup":
            text = re.sub(r"^dedup\s+", "", command, flags=re.IGNORECASE)
            fields = [quote_field(display_field(token)) for token in split_tokens(text.replace(",", " "))]
            if fields:
                pipeline.append(f"distinct {', '.join(fields)}")
            warnings.append(warning("lossy_dedup", "SPL dedup keeps the first event; Logan distinct preserves unique field tuples only."))
            lossy = True
        elif command_name == "top":
            limit_match = re.search(r"\blimit\s*=\s*([0-9]+)", command, flags=re.IGNORECASE)
            cleaned = re.sub(r"\blimit\s*=\s*[0-9]+", "", command, flags=re.IGNORECASE)
            fields = [token for token in split_tokens(re.sub(r"^top\s+", "", cleaned, flags=re.IGNORECASE).replace(",", " ")) if token]
            if fields:
                pipeline.append(f"top {limit_match.group(1) if limit_match else 10} {quote_field(display_field(fields[0]))}")
        elif command_name in {"bin", "bucket"}:
            span_match = re.search(r"\bspan\s*=\s*([0-9]+[smhdw])", command, flags=re.IGNORECASE)
            field_match = re.search(r"\b(_time|Time)\b", command, flags=re.IGNORECASE)
            if span_match and field_match:
                time_span = span_match.group(1)
            else:
                warnings.append(warning("unsupported_spl_bin", "Only _time bin/bucket spans are converted to timestats."))
        elif command_name == "lookup":
            step = lookup_step(command, warnings, dependencies)
            if step:
                pipeline.append(step)
            lossy = True
        elif command_name == "rex":
            step = rex_step(command, warnings, dependencies)
            if step:
                pipeline.append(step)
            lossy = True
        elif command_name == "spath":
            step = spath_step(command, warnings, dependencies)
            if step:
                pipeline.append(step)
            lossy = True
        elif command_name == "transaction":
            step = transaction_step(command, warnings, dependencies)
            if step:
                pipeline.append(step)
            lossy = True
        elif command_name == "eval":
            warnings.append(warning("spl_eval_review", "SPL eval expressions require manual function-by-function validation."))
            lossy = True
        else:
            warnings.append(warning("unsupported_spl_command", f"SPL command {command_name} was not converted."))
            lossy = True
        converted_commands.append(command_name)

    if unsupported:
        return SplConversion(
            query="",
            support_level="unsupported",
            warnings=[
                warning("unsupported_spl_dependency", f"SPL command(s) {', '.join(sorted(set(unsupported)))} are not safely rewritten.", "error"),
                *warnings,
            ],
            metadata={"source": source, "converted_commands": converted_commands, "unsupported_commands": sorted(set(unsupported)), "dependencies": dependencies},
        )

    if not any(step.startswith("head ") for step in pipeline):
        pipeline.append("head 100")

    logan_query = " and ".join(dict.fromkeys(predicates))
    if pipeline:
        logan_query = f"{logan_query} | {' | '.join(pipeline)}"
    return SplConversion(
        query=logan_query,
        support_level="lossy" if lossy else "partial",
        warnings=warnings,
        metadata={"source": source, "converted_commands": converted_commands, "dependencies": list(dict.fromkeys(dependencies))},
    )


def convert_splunk_spl(query: str) -> dict[str, Any]:
    converted = convert_pipeline(query)
    return response(
        source_query=query,
        logan_query=converted.query,
        support_level=converted.support_level,
        explanation="Mapped common SPL search, where, stats/timechart, extraction, lookup, projection, correlation, sort, and limit constructs into Logan QL patterns.",
        warnings=converted.warnings,
        metadata=converted.metadata,
    )
