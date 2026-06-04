"""Elastic-family query conversion helpers for Logan Forge.

This module supports request-time conversion only. It must not persist Elastic
rule bodies, names, descriptions, IDs, or converted detections into generated
repository artifacts.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from scripts.ql.ir import ConversionIR, FieldMapping, FilterPredicate, PipelineStep, SourceDataset
from scripts.ql.logan_emit import emit_logan, quote_value


BACKEND_NAME = "scripts/logan_workbench_convert.py"
FIELD_MAP = {
    "@timestamp": "Time",
    "destination.ip": "Destination IP",
    "destination.port": "Destination Port",
    "event.action": "Event Type",
    "event.code": "Event ID",
    "event.outcome": "Status",
    "event.type": "Event Type",
    "host.name": "Host Name",
    "http.request.method": "Request Method",
    "http.response.status_code": "Response Code",
    "process.args": "Command Line",
    "process.command_line": "Command Line",
    "process.executable": "Process Name",
    "process.name": "Process Name",
    "service.name": "Service Name",
    "source.ip": "Source IP",
    "url.full": "Request URL",
    "url.original": "Request URL",
    "url.path": "Request URL",
    "url.query": "Request URL",
    "user.name": "User Name",
}
RAW_FALLBACK_FIELDS = {"data_stream.dataset", "event.category", "event.dataset", "event.provider"}
UNSUPPORTED_ESQL_COMMANDS = r"\b(enrich|mv_expand|dissect|grok|join)\b"


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def warning(code: str, message: str, severity: str = "warning") -> dict[str, str]:
    return {"code": code, "message": message, "severity": severity}


def response(
    *,
    source_language: str,
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
        "source_language": source_language,
        "source_query": source_query,
        "logan_query": logan_query,
        "support_level": support_level,
        "explanation": explanation,
        "warnings": warnings or [],
        "metadata": metadata or {},
        "backend": BACKEND_NAME,
    }


def load_toml(text: str) -> dict[str, Any]:
    try:
        import tomllib  # type: ignore[attr-defined]
    except ModuleNotFoundError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ModuleNotFoundError as exc:
            raise ValueError("Elastic TOML parsing requires tomli on Python <3.11") from exc
    return tomllib.loads(text)


def elastic_field(source_field: str) -> str:
    return FIELD_MAP.get(source_field.strip(), source_field.strip())


def infer_log_source(query: str, datasets: list[str] | None = None) -> str:
    lowered = " ".join([query.lower(), " ".join(datasets or []).lower()])
    if any(token in lowered for token in ("apm", "http.", "url.", "service.name", "logs-apm", "traces-apm")):
        return "SOC Application Logs"
    if any(token in lowered for token in ("authentication", "event.category:authentication", "event.outcome")):
        return "OCI Audit Logs"
    if any(token in lowered for token in ("source.ip", "destination.ip", "network.", "dns.")):
        return "OCI VCN Flow Logs"
    return "Windows Sysmon Events"


def dataset_for(query: str, language: str, datasets: list[str] | None = None) -> SourceDataset:
    return SourceDataset(
        source_name=", ".join(datasets or []) or language,
        oci_log_source=infer_log_source(query, datasets),
        confidence="medium",
    )


def mappings_for(fields: list[str]) -> tuple[FieldMapping, ...]:
    deduped = list(dict.fromkeys(field for field in fields if field))
    return tuple(
        FieldMapping(source_field=field, oci_field=elastic_field(field), confidence="medium", role="unknown")
        for field in deduped
    )


def source_metadata(ir: ConversionIR, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "datasets": [dataset.__dict__ for dataset in ir.datasets],
        "field_mappings": [mapping.__dict__ for mapping in ir.field_mappings],
        **(extra or {}),
    }


def normalize_value(raw: str) -> str:
    value = raw.strip().strip("'\"")
    return value.replace("\\\"", "\"").replace("\\'", "'")


def raw_fallback_predicate(source_field: str, value: str, *, negated: bool = False) -> str:
    escaped = normalize_value(value)
    rendered = f"'Original Log Content' like '*{escaped}*'"
    return f"not ({rendered})" if negated else rendered


def field_predicate(source_field: str, operator: str, raw_value: str, *, negated: bool = False) -> str:
    value = normalize_value(raw_value)
    if source_field in RAW_FALLBACK_FIELDS:
        return raw_fallback_predicate(source_field, value, negated=negated)

    target = elastic_field(source_field)
    if "*" in value or "?" in value:
        rendered = f"'{target}' like {quote_value(value.replace('?', '*'))}"
    elif operator in {":", "==", "="}:
        rendered = f"'{target}' = {quote_value(value)}"
    elif operator == "!=":
        rendered = f"'{target}' != {quote_value(value)}"
    else:
        rendered = f"'{target}' {operator} {quote_value(value)}"
    return f"not ({rendered})" if negated else rendered


def collect_query_filter_parts(query: str) -> tuple[list[str], list[str], list[dict[str, str]]]:
    lowered = query.lower()
    predicates = [f"'Log Source' = {quote_value(infer_log_source(query))}"]
    fields: list[str] = []
    warnings: list[dict[str, str]] = []

    if "sequence" in lowered:
        warnings.append(warning("elastic_sequence", "EQL sequence semantics require correlation mapping before promotion."))
    if "enrich" in lowered or "lookup" in lowered:
        warnings.append(warning("elastic_lookup_dependency", "Elastic enrich/lookup requires an OCI lookup artifact."))

    grouped = re.finditer(
        r"(?P<field>[A-Za-z_@][A-Za-z0-9_.@-]+)\s*:\s*\((?P<body>[^)]+)\)",
        query,
        flags=re.IGNORECASE,
    )
    consumed_spans: list[tuple[int, int]] = []
    for match in grouped:
        source_field = match.group("field")
        fields.append(source_field)
        values = [
            normalize_value(part)
            for part in re.split(r"\s+or\s+|\s+OR\s+", match.group("body"))
            if normalize_value(part)
        ]
        if values:
            target = elastic_field(source_field)
            fragments = [
                raw_fallback_predicate(source_field, value)
                if source_field in RAW_FALLBACK_FIELDS
                else f"'{target}' like {quote_value(value.replace('?', '*'))}"
                if "*" in value or "?" in value
                else f"'{target}' = {quote_value(value)}"
                for value in values
            ]
            predicates.append(f"({' or '.join(fragments)})")
        consumed_spans.append(match.span())

    def was_consumed(start: int) -> bool:
        return any(span_start <= start < span_end for span_start, span_end in consumed_spans)

    token_pattern = re.compile(
        r"(?P<not>\bnot\s+|\bNOT\s+)?(?P<field>[A-Za-z_@][A-Za-z0-9_.@-]+)\s*"
        r"(?P<op>:|==|!=|>=|<=|>|<)\s*"
        r"(?P<value>\"[^\"]+\"|'[^']+'|[A-Za-z0-9_./*?@:-]+)",
        flags=re.IGNORECASE,
    )
    for match in token_pattern.finditer(query):
        if was_consumed(match.start()):
            continue
        source_field = match.group("field")
        value = match.group("value")
        if value == "*":
            fields.append(source_field)
            predicates.append(f"'{elastic_field(source_field)}' is not null")
            continue
        fields.append(source_field)
        predicates.append(
            field_predicate(source_field, match.group("op"), value, negated=bool(match.group("not")))
        )

    return predicates, fields, warnings


def convert_elastic(query: str, language: str) -> dict[str, Any]:
    warnings = [
        warning(
            "heuristic_elastic",
            "Elastic conversion maps common ECS fields; analyzers and nested-document behavior are not preserved.",
        )
    ]
    predicates, fields, extracted_warnings = collect_query_filter_parts(query)
    warnings.extend(extracted_warnings)
    source = infer_log_source(query)
    logan = " and ".join(dict.fromkeys(predicates))
    if source == "SOC Application Logs":
        logan += " | stats count as hits by 'Service Name', 'Trace ID', 'Source IP' | sort -hits"
    logan += " | head 100"
    return response(
        source_language=language,
        source_query=query,
        logan_query=logan,
        support_level="partial",
        explanation="Mapped common Elastic/ECS fields and wildcard predicates into OCI Log Analytics display fields.",
        warnings=warnings,
        metadata={"field_mappings": [mapping.__dict__ for mapping in mappings_for(fields)]},
    )


def convert_eql_sequence(query: str) -> dict[str, Any] | None:
    if not re.search(r"(?is)^\s*sequence\b", query):
        return None

    by_match = re.search(r"(?i)\bby\s+([A-Za-z0-9_.@-]+)", query)
    link_field = elastic_field(by_match.group(1)) if by_match else "Host Name"
    step_names = [
        normalize_value(match.group(1))
        for match in re.finditer(r"process\.name\s*==\s*['\"]([^'\"]+)['\"]", query, flags=re.IGNORECASE)
    ]
    if len(step_names) < 2:
        return response(
            source_language="elastic_eql",
            source_query=query,
            logan_query="",
            support_level="unsupported",
            explanation="Elastic EQL sequence conversion requires at least two process.name equality steps.",
            warnings=[warning("unsupported_eql_sequence_shape", "No convertible process.name sequence was found.", "error")],
        )

    sequence = ", ".join(f"'Process Name' = {quote_value(name)}" for name in step_names)
    ir = ConversionIR(
        source_language="elastic_eql",
        source_query=query,
        datasets=(dataset_for(query, "elastic_eql"),),
        pipeline=(
            PipelineStep("raw", f"link '{link_field}'"),
            PipelineStep("raw", f"sequence {sequence}"),
        ),
        field_mappings=mappings_for([by_match.group(1) if by_match else "host.name", "process.name"]),
        support_level="partial",
        explanation="Mapped a simple Elastic EQL process sequence to OCI link plus sequence commands.",
    )
    return response(
        source_language="elastic_eql",
        source_query=query,
        logan_query=emit_logan(ir, default_limit=100),
        support_level=ir.support_level,
        explanation=ir.explanation,
        warnings=[warning("eql_sequence_time_window", "Validate maxspan/time-window behavior against the OCI saved-search schedule.")],
        metadata=source_metadata(ir, {"sequence_steps": len(step_names)}),
    )


def convert_elastic_eql(query: str) -> dict[str, Any]:
    sequence = convert_eql_sequence(query)
    if sequence:
        return sequence
    return convert_elastic(query, "elastic_eql")


def esql_datasets(query: str) -> list[str]:
    match = re.search(r"(?im)^\s*from\s+([^\n|]+)", query)
    if not match:
        return []
    return [item.strip() for item in match.group(1).replace("metadata _id", "").split(",") if item.strip()]


def esql_where_text(query: str) -> str:
    return " and ".join(match.group(1).strip() for match in re.finditer(r"(?im)^\s*\|\s*where\s+(.+)$", query))


def esql_predicates(where_text: str) -> tuple[list[FilterPredicate], list[str], list[dict[str, str]]]:
    predicates: list[FilterPredicate] = []
    fields: list[str] = []
    warnings: list[dict[str, str]] = []

    for match in re.finditer(r"([A-Za-z_@][A-Za-z0-9_.@-]+)\s+is\s+not\s+null", where_text, flags=re.IGNORECASE):
        fields.append(match.group(1))
        predicates.append(FilterPredicate(elastic_field(match.group(1)), "exists"))

    for match in re.finditer(
        r"([A-Za-z_@][A-Za-z0-9_.@-]+)\s+in\s+\(([^)]+)\)", where_text, flags=re.IGNORECASE
    ):
        fields.append(match.group(1))
        values = tuple(normalize_value(part) for part in match.group(2).split(",") if normalize_value(part))
        predicates.append(FilterPredicate(elastic_field(match.group(1)), "in", values))

    comparisons = re.finditer(
        r"([A-Za-z_@][A-Za-z0-9_.@-]+)\s*(==|!=|>=|<=|>|<)\s*(\"[^\"]+\"|'[^']+'|[A-Za-z0-9_./*?@:-]+)",
        where_text,
        flags=re.IGNORECASE,
    )
    op_map = {"==": "eq", "!=": "neq", ">=": "gte", "<=": "lte", ">": "gt", "<": "lt"}
    for match in comparisons:
        source_field = match.group(1)
        if source_field in RAW_FALLBACK_FIELDS:
            warnings.append(warning("raw_field_fallback", f"{source_field} was matched through Original Log Content."))
            continue
        fields.append(source_field)
        value = normalize_value(match.group(3))
        converted_value: str | int = int(value) if value.isdigit() else value
        predicates.append(FilterPredicate(elastic_field(source_field), op_map[match.group(2)], converted_value))

    if re.search(r"\bcidr_match\s*\(", where_text, flags=re.IGNORECASE):
        warnings.append(warning("cidr_match_review", "CIDR_MATCH requires OCI parser validation before promotion."))
    return predicates, fields, warnings


def esql_stats_step(query: str, fields: list[str], warnings: list[dict[str, str]]) -> PipelineStep | None:
    stats = re.search(r"(?ims)^\s*\|\s*stats\s+(.+?)(?:\s+by\s+(.+?))?(?=^\s*\||\Z)", query)
    if not stats:
        return None
    expression = " ".join(stats.group(1).split())
    by_fields = []
    if stats.group(2):
        by_fields = [item.strip() for item in stats.group(2).split(",") if item.strip()]
        fields.extend(by_fields)
    by_clause = f" by {', '.join(repr(elastic_field(field)) for field in by_fields)}" if by_fields else ""

    count_match = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*count\(\*\)", expression, flags=re.IGNORECASE)
    if count_match:
        return PipelineStep("stats", f"stats count as {count_match.group(1)}{by_clause}")

    distinct_match = re.match(
        r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*count_distinct\(([A-Za-z0-9_.@-]+)\)",
        expression,
        flags=re.IGNORECASE,
    )
    if distinct_match:
        fields.append(distinct_match.group(2))
        warnings.append(warning("count_distinct_review", "Validate count_distinct syntax in OCI before promotion."))
        return PipelineStep("stats", f"stats count_distinct('{elastic_field(distinct_match.group(2))}') as {distinct_match.group(1)}{by_clause}")

    warnings.append(warning("unsupported_esql_stats", "Only count/count_distinct ES|QL stats expressions are converted."))
    return None


def esql_pipeline_steps(query: str, fields: list[str], warnings: list[dict[str, str]]) -> list[PipelineStep]:
    steps: list[PipelineStep] = []
    stats = esql_stats_step(query, fields, warnings)
    if stats:
        steps.append(stats)

    keep_match = re.search(r"(?ims)^\s*\|\s*keep\s+(.+?)(?=^\s*\||\Z)", query)
    if keep_match:
        keep_fields = [item.strip() for item in keep_match.group(1).replace("\n", " ").split(",") if item.strip()]
        fields.extend(keep_fields)
        steps.append(PipelineStep("fields", f"fields {', '.join(repr(elastic_field(field)) for field in keep_fields)}"))

    sort_match = re.search(r"(?im)^\s*\|\s*sort\s+([A-Za-z_][A-Za-z0-9_]*)\s+(asc|desc)", query)
    if sort_match:
        direction = "-" if sort_match.group(2).lower() == "desc" else ""
        steps.append(PipelineStep("sort", f"sort {direction}{sort_match.group(1)}"))

    limit_match = re.search(r"(?im)^\s*\|\s*limit\s+([0-9]+)", query)
    if limit_match:
        steps.append(PipelineStep("head", f"head {limit_match.group(1)}"))
    return steps


def convert_elastic_esql(query: str) -> dict[str, Any]:
    lowered = query.lower()
    if re.search(UNSUPPORTED_ESQL_COMMANDS, lowered):
        return response(
            source_language="elastic_esql",
            source_query=query,
            logan_query="",
            support_level="unsupported",
            explanation="The ES|QL query uses pipeline commands that require enrichment, expansion, parsing, or join semantics.",
            warnings=[warning("unsupported_esql_pipeline", "enrich/mv_expand/dissect/grok/join are not safely rewritten.", "error")],
        )

    warnings = [
        warning("elastic_esql_partial", "Common ES|QL FROM/WHERE/STATS/KEEP/SORT/LIMIT stages are converted.")
    ]
    fields: list[str] = []
    predicates, predicate_fields, predicate_warnings = esql_predicates(esql_where_text(query))
    fields.extend(predicate_fields)
    warnings.extend(predicate_warnings)
    pipeline = esql_pipeline_steps(query, fields, warnings)

    ir = ConversionIR(
        source_language="elastic_esql",
        source_query=query,
        datasets=(dataset_for(query, "elastic_esql", esql_datasets(query)),),
        predicates=tuple(predicates),
        pipeline=tuple(pipeline),
        field_mappings=mappings_for(fields),
        support_level="partial",
        explanation="Converted common ES|QL pipeline stages into OCI Log Analytics QL through the shared IR emitter.",
    )
    return response(
        source_language="elastic_esql",
        source_query=query,
        logan_query=emit_logan(ir, default_limit=100),
        support_level=ir.support_level,
        explanation=ir.explanation,
        warnings=warnings,
        metadata=source_metadata(ir),
    )


def convert_elastic_toml(query: str) -> dict[str, Any]:
    try:
        data = load_toml(query)
    except Exception as exc:
        return response(
            source_language="elastic_toml",
            source_query=query,
            logan_query="",
            support_level="unsupported",
            explanation="Elastic TOML input could not be parsed.",
            warnings=[warning("elastic_toml_parse_failed", str(exc), "error")],
        )

    rule = data.get("rule", {}) if isinstance(data, dict) else {}
    if not isinstance(rule, dict):
        return response(
            source_language="elastic_toml",
            source_query=query,
            logan_query="",
            support_level="unsupported",
            explanation="Elastic TOML input must contain a [rule] table.",
            warnings=[warning("elastic_toml_missing_rule", "Missing [rule] table.", "error")],
        )

    rule_type = str(rule.get("type") or "query")
    language = str(rule.get("language") or "")
    source_query = str(rule.get("query") or "")
    metadata = {
        "rule_type": rule_type,
        "rule_language": language,
        "third_party_content_policy": "request_only_no_persistence",
    }

    if rule_type == "machine_learning":
        return response(
            source_language="elastic_toml",
            source_query=query,
            logan_query="",
            support_level="unsupported",
            explanation="Elastic machine-learning rules require an ML job and cannot be represented as a standalone Logan QL query.",
            warnings=[warning("unsupported_machine_learning_rule", "ML job semantics are not converted to Logan QL.", "error")],
            metadata=metadata,
        )
    if not source_query:
        return response(
            source_language="elastic_toml",
            source_query=query,
            logan_query="",
            support_level="unsupported",
            explanation="Elastic TOML rule has no query body to convert.",
            warnings=[warning("elastic_toml_missing_query", "Missing rule.query.", "error")],
            metadata=metadata,
        )
    if rule_type == "threshold":
        return convert_threshold_toml(query, source_query, rule, metadata)
    if rule_type == "threat_match":
        return convert_threat_match_toml(query, source_query, metadata)
    if rule_type == "new_terms":
        return convert_new_terms_toml(query, source_query, rule, language, metadata)

    if language == "esql" or rule_type == "esql":
        converted = convert_elastic_esql(source_query)
    elif language == "eql" or rule_type == "eql":
        converted = convert_elastic_eql(source_query)
    else:
        converted = convert_elastic(source_query, "elastic_kuery" if language == "kuery" else "elastic_lucene")
    converted["source_language"] = "elastic_toml"
    converted["source_query"] = query
    converted["metadata"] = {**converted.get("metadata", {}), **metadata}
    return converted


def convert_threshold_toml(query: str, source_query: str, rule: dict[str, Any], metadata: dict[str, Any]) -> dict[str, Any]:
    threshold = rule.get("threshold", {}) if isinstance(rule.get("threshold"), dict) else {}
    raw_fields = threshold.get("field") or []
    threshold_fields = [raw_fields] if isinstance(raw_fields, str) else list(raw_fields)
    threshold_value = int(threshold.get("value") or 1)
    predicates, fields, extracted_warnings = collect_query_filter_parts(source_query)
    group_fields = [elastic_field(str(field)) for field in threshold_fields] or ["Host Name"]
    logan = " and ".join(dict.fromkeys(predicates))
    logan += f" | stats count as event_count by {', '.join(repr(field) for field in group_fields)}"
    logan += f" | where event_count >= {threshold_value} | head 100"
    return response(
        source_language="elastic_toml",
        source_query=query,
        logan_query=logan,
        support_level="lossy",
        explanation="Converted Elastic threshold TOML into a Logan filter plus stats threshold. Validate schedule and lookback windows.",
        warnings=[
            warning("threshold_schedule_dependency", "Elastic schedule/window behavior must be modeled in OCI saved-search scheduling."),
            *extracted_warnings,
        ],
        metadata={
            **metadata,
            "threshold_fields": threshold_fields,
            "field_mappings": [mapping.__dict__ for mapping in mappings_for(fields + threshold_fields)],
        },
    )


def convert_threat_match_toml(query: str, source_query: str, metadata: dict[str, Any]) -> dict[str, Any]:
    base = convert_elastic(source_query, "elastic_kuery")
    logan = base["logan_query"].replace(" | head 100", " | lookup <threat_lookup_name> 'Source IP' | head 100")
    return response(
        source_language="elastic_toml",
        source_query=query,
        logan_query=logan,
        support_level="lossy",
        explanation="Converted the first-stage filter and surfaced the required OCI threat lookup dependency.",
        warnings=[
            warning("threat_match_lookup_required", "Replace <threat_lookup_name> with a configured OCI lookup source before use."),
            *base["warnings"],
        ],
        metadata={**base.get("metadata", {}), **metadata, "dependencies": ["oci_lookup:<threat_lookup_name>"]},
    )


def convert_new_terms_toml(
    query: str,
    source_query: str,
    rule: dict[str, Any],
    language: str,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    base = convert_elastic(source_query, "elastic_kuery" if language == "kuery" else "elastic_lucene")
    new_terms = rule.get("new_terms", {}) if isinstance(rule.get("new_terms"), dict) else {}
    return response(
        source_language="elastic_toml",
        source_query=query,
        logan_query=base["logan_query"],
        support_level="lossy",
        explanation="Converted the first-stage filter, but Elastic new_terms requires baseline state outside a single Logan query.",
        warnings=[
            warning("new_terms_baseline_required", "Baseline/new-term state must be implemented outside the emitted Logan query."),
            *base["warnings"],
        ],
        metadata={**base.get("metadata", {}), **metadata, "new_terms_fields": new_terms.get("fields", [])},
    )


def convert_osquery_sql(query: str) -> dict[str, Any]:
    lowered = query.lower()
    if "osquery" in lowered and "result" in lowered:
        return response(
            source_language="osquery_sql",
            source_query=query,
            logan_query="'Log Source' = 'OSQuery Result Logs' and 'Original Log Content' like '*osquery*' | head 100",
            support_level="partial",
            explanation="Converted an OSQuery result-log search shape. Raw endpoint-state SQL is not executed by OCI Log Analytics.",
            warnings=[warning("osquery_result_log_only", "Validate the OSQuery result parser and display fields before promotion.")],
        )
    return response(
        source_language="osquery_sql",
        source_query=query,
        logan_query="",
        support_level="unsupported",
        explanation="OSQuery SQL runs against endpoint state. Logan Forge converts OSQuery result logs, not raw endpoint SQL.",
        warnings=[warning("unsupported_stateful_query", "Provide OSQuery result logs or a parser-backed result-log query.", "error")],
    )


def convert_yara(query: str) -> dict[str, Any]:
    lowered = query.lower()
    if "yara" in lowered and "match" in lowered and "result" in lowered:
        return response(
            source_language="yara",
            source_query=query,
            logan_query="'Log Source' = 'YARA Match Results' and 'Original Log Content' like '*yara*' | head 100",
            support_level="partial",
            explanation="Converted a YARA match-result log search shape. Logan QL does not scan file bytes.",
            warnings=[warning("yara_result_log_only", "Validate the YARA result log source and fields before promotion.")],
        )
    return response(
        source_language="yara",
        source_query=query,
        logan_query="",
        support_level="unsupported",
        explanation="YARA rules scan file content. Logan Forge converts YARA match result logs, not raw file-content rules.",
        warnings=[warning("unsupported_content_scan", "Provide YARA match result logs or a parser-backed result query.", "error")],
    )
