"""Intermediate representation for source QL to OCI Log Analytics conversion.

The IR is intentionally small. It gives each source-language parser a shared
shape to describe filters, aggregations, dependencies, and support warnings
before the Logan QL emitter renders a final query.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


SupportLevel = Literal["supported", "partial", "lossy", "unsupported"]
PredicateOperator = Literal[
    "eq",
    "neq",
    "gt",
    "gte",
    "lt",
    "lte",
    "in",
    "like",
    "regex",
    "exists",
    "not_exists",
]
PipelineCommand = Literal["where", "eval", "stats", "timestats", "fields", "sort", "head", "lookup", "raw"]


@dataclass(frozen=True)
class SourceDataset:
    """Source dataset selected by the input query and mapped OCI source."""

    source_name: str
    oci_log_source: str
    confidence: Literal["high", "medium", "low"] = "medium"
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class FieldMapping:
    """Mapping from a source field to an OCI Log Analytics display field."""

    source_field: str
    oci_field: str
    confidence: Literal["high", "medium", "low"] = "medium"
    role: str = "unknown"
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class FilterPredicate:
    """A normalized field predicate that can be emitted to Logan QL."""

    field: str
    operator: PredicateOperator
    value: str | int | float | bool | tuple[str | int | float | bool, ...] | None = None
    negated: bool = False


@dataclass(frozen=True)
class PipelineStep:
    """A normalized pipe command or opaque command fragment."""

    command: PipelineCommand
    expression: str


@dataclass(frozen=True)
class ConversionDependency:
    """External dependency required by the converted query."""

    kind: Literal["lookup", "baseline", "parser", "correlation", "ml_job"]
    name: str
    reason: str


@dataclass(frozen=True)
class ConversionWarning:
    """Structured warning carried through backend and UI responses."""

    code: str
    message: str
    severity: Literal["info", "warning", "error"] = "warning"

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message, "severity": self.severity}


@dataclass(frozen=True)
class ConversionIR:
    """Whole-query representation before Logan QL emission."""

    source_language: str
    source_query: str
    datasets: tuple[SourceDataset, ...]
    predicates: tuple[FilterPredicate, ...] = ()
    pipeline: tuple[PipelineStep, ...] = ()
    field_mappings: tuple[FieldMapping, ...] = ()
    dependencies: tuple[ConversionDependency, ...] = ()
    support_level: SupportLevel = "supported"
    explanation: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def with_warning_support(self, support_level: SupportLevel) -> "ConversionIR":
        return ConversionIR(
            source_language=self.source_language,
            source_query=self.source_query,
            datasets=self.datasets,
            predicates=self.predicates,
            pipeline=self.pipeline,
            field_mappings=self.field_mappings,
            dependencies=self.dependencies,
            support_level=support_level,
            explanation=self.explanation,
            metadata=dict(self.metadata),
        )
