"""Emit OCI Log Analytics QL from the shared conversion IR."""

from __future__ import annotations

from collections.abc import Iterable

from scripts.ql.ir import ConversionIR, FilterPredicate


def quote_field(name: str) -> str:
    """Return an OCI display field reference."""
    stripped = name.strip().strip("'")
    if not stripped:
        return "''"
    return stripped if stripped in {"msg"} else f"'{stripped}'"


def quote_value(value: object) -> str:
    """Return a conservative Logan literal."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    escaped = str(value).replace("\\", "\\\\").replace("'", "\\'")
    return f"'{escaped}'"


def emit_predicate(predicate: FilterPredicate) -> str:
    """Render one normalized predicate."""
    field = quote_field(predicate.field)
    op = predicate.operator
    value = predicate.value

    if op == "exists":
        rendered = f"{field} is not null"
    elif op == "not_exists":
        rendered = f"{field} is null"
    elif op == "in":
        values: Iterable[object]
        values = value if isinstance(value, tuple) else (() if value is None else (value,))
        rendered = f"{field} in ({', '.join(quote_value(item) for item in values)})"
    elif op == "like":
        rendered = f"{field} like {quote_value(value or '*')}"
    elif op == "regex":
        rendered = f"{field} matches {quote_value(value or '')}"
    else:
        symbols = {
            "eq": "=",
            "neq": "!=",
            "gt": ">",
            "gte": ">=",
            "lt": "<",
            "lte": "<=",
        }
        rendered = f"{field} {symbols[op]} {quote_value(value)}"

    return f"not ({rendered})" if predicate.negated else rendered


def emit_logan(ir: ConversionIR, *, default_limit: int | None = 100) -> str:
    """Render a complete Logan QL query from a conversion IR."""
    source_parts = [f"'Log Source' = {quote_value(dataset.oci_log_source)}" for dataset in ir.datasets]
    base_parts = []
    if source_parts:
        base_parts.append(source_parts[0] if len(source_parts) == 1 else f"({' or '.join(source_parts)})")
    base_parts.extend(emit_predicate(predicate) for predicate in ir.predicates)

    query = " and ".join(base_parts)
    for step in ir.pipeline:
        expression = step.expression.strip()
        if not expression:
            continue
        query = f"{query} | {expression}" if query else expression

    if default_limit and query and "| head " not in query.lower() and "| top " not in query.lower():
        query = f"{query} | head {default_limit}"
    return query
