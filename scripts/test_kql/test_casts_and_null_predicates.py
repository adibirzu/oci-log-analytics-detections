"""Phase 9 tranche B: numeric/boolean cast unwrap, ``strcat_delim`` concat,
and ``isnull`` / ``isnotnull`` predicate parity.

These additions only ever lower to Logan QL primitives already proven by the
existing converter corpus:

- type casts (``todouble``/``toreal``/``tofloat``/``todecimal``/``tobool``/
  ``toboolean``, alongside the pre-existing ``tostring``/``toint``/``tolong``)
  unwrap to their inner expression — a no-op in Logan's loosely typed ``eval``
  context;
- ``strcat_delim(delim, a, b, ...)`` interleaves the delimiter through the
  proven ``concat`` lowering;
- ``isnull`` / ``isnotnull`` lower to ``<field> = null`` / ``<field> != null``,
  the same comparison shape ``isempty`` / ``isnotempty`` already emit.

Out-of-scope constructs (``coalesce``, ``array_length``, ``ipv4_is_private``,
``substring``, ``countof``) must stay Tier-3; the guard tests at the bottom
lock that boundary in place. Golden assertions run input KQL through the real
stage pipeline and through ``canonical()`` for whole-query round-trips.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_DIR = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = PROJECT_DIR / "scripts"
for path in (PROJECT_DIR, SCRIPTS_DIR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from scripts.kql import _facade_impl as facade  # noqa: E402
from scripts.kql.canonical import canonical  # noqa: E402
from scripts.kql.operators import extend_op, where_op  # noqa: E402
from scripts.kql.types import ConversionContext, KqlStage, Tier  # noqa: E402

from scripts import convert_sentinel_kql as _legacy  # noqa: E402


@pytest.fixture(scope="module")
def mapping() -> dict:
    return _legacy.load_mapping_config()


@pytest.fixture
def ctx(mapping: dict) -> ConversionContext:
    return ConversionContext(
        mapping=mapping,
        allowed_aliases=frozenset(),
        dictionary_fields=frozenset(),
        log_source_tables=(),
    )


def _scalar(expr: str, mapping: dict) -> tuple[str, list[str]]:
    errors: list[str] = []
    out = facade._convert_scalar_expression(expr, mapping, errors, set())
    return out, errors


# ----------------------------------------------------------- numeric casts --


@pytest.mark.parametrize(
    "cast",
    ["todouble", "toreal", "tofloat", "todecimal", "tobool", "toboolean"],
)
def test_numeric_and_bool_casts_unwrap_to_inner_field(cast: str, mapping: dict) -> None:
    out, errors = _scalar(f"{cast}(HttpStatusCode)", mapping)
    assert errors == []
    # The cast is a no-op in Logan; the inner mapped field is all that remains.
    assert out == "'HTTP Status Code'"


def test_cast_unwrap_preserves_existing_string_casts(mapping: dict) -> None:
    # Pre-existing casts must still unwrap (regression fence).
    for cast in ("tostring", "toint", "tolong"):
        out, errors = _scalar(f"{cast}(SourcePort)", mapping)
        assert errors == []
        assert out == "'Source Port'"


def test_cast_via_extend_operator_is_tier_1(ctx: ConversionContext) -> None:
    result = extend_op.convert_extend(
        KqlStage(kind="extend", body="Code = todouble(HttpStatusCode)"), ctx
    )
    assert result.tier == Tier.TIER_1
    assert result.skip_reasons == ()
    assert result.fragments == ("eval Code = 'HTTP Status Code'",)
    assert "Code" in result.new_aliases


def test_cast_unwrap_in_where_predicate(ctx: ConversionContext) -> None:
    result = where_op.convert_where(
        KqlStage(kind="where", body="toint(HttpStatusCode) >= 400"), ctx
    )
    assert result.tier == Tier.TIER_1
    assert result.skip_reasons == ()
    assert result.fragments == ("where 'HTTP Status Code' >= 400",)


# ---------------------------------------------------------------- strcat_delim --


def test_strcat_delim_interleaves_delimiter(mapping: dict) -> None:
    out, errors = _scalar('strcat_delim("@", Account, Process)', mapping)
    assert errors == []
    assert out == "concat(User, '@', 'Process Name')"


def test_strcat_delim_three_values(mapping: dict) -> None:
    out, errors = _scalar('strcat_delim("-", Account, Process, Account)', mapping)
    assert errors == []
    assert out == "concat(User, '-', 'Process Name', '-', User)"


def test_strcat_delim_too_few_args_is_skipped(mapping: dict) -> None:
    out, errors = _scalar('strcat_delim("-", Account)', mapping)
    assert any("strcat_delim" in e for e in errors), errors


def test_strcat_delim_via_extend_operator(ctx: ConversionContext) -> None:
    result = extend_op.convert_extend(
        KqlStage(kind="extend", body="Full = strcat_delim('/', Account, Process)"), ctx
    )
    assert result.tier == Tier.TIER_1
    assert result.skip_reasons == ()
    assert result.fragments == ("eval Full = concat(User, '/', 'Process Name')",)


# ------------------------------------------------------ isnull / isnotnull --


def test_isnull_predicate(mapping: dict) -> None:
    out, errors = facade.convert_predicate("isnull(Account)", mapping)
    assert errors == []
    assert out == "User = null"


def test_isnotnull_predicate(mapping: dict) -> None:
    out, errors = facade.convert_predicate("isnotnull(Account)", mapping)
    assert errors == []
    assert out == "User != null"


def test_null_predicates_combine_with_boolean_chain(mapping: dict) -> None:
    out, errors = facade.convert_predicate(
        "isnotnull(DvcAction) and isnull(Account)", mapping
    )
    assert errors == []
    assert out == "Action != null and User = null"


def test_isnotnull_via_where_operator(ctx: ConversionContext) -> None:
    result = where_op.convert_where(
        KqlStage(kind="where", body="isnotnull(Account)"), ctx
    )
    assert result.tier == Tier.TIER_1
    assert result.skip_reasons == ()
    assert result.fragments == ("where User != null",)


# ---------------------------------------------------- whole-query goldens --


@pytest.mark.parametrize(
    "kql",
    [
        "SecurityEvent | where isnotnull(Account)",
        "SecurityEvent | where toint(HttpStatusCode) >= 400",
        "SecurityEvent | extend Full = strcat_delim('-', Account, Process)",
        "SecurityEvent | extend Code = todouble(HttpStatusCode)",
    ],
)
def test_whole_query_converts_without_skip(kql: str, mapping: dict) -> None:
    query, _meta, errors = facade.convert_kql_to_logan(kql, mapping)
    assert errors == [], errors
    # Output must survive the local Logan guardrails and be idempotent under
    # canonicalization (golden round-trip).
    assert facade.validate_logan_query_local(query, mapping) == []
    assert canonical(query) == canonical(canonical(query))


def test_classifier_does_not_flag_new_supported_constructs() -> None:
    for kql in (
        "SecurityEvent | extend Code = todouble(HttpStatusCode)",
        "SecurityEvent | where isnotnull(Account)",
        "SecurityEvent | extend Full = strcat_delim('-', Account, Process)",
    ):
        reasons = facade.classify_unsupported_kql(kql)
        assert reasons == [], (kql, reasons)


# ------------------------------------------------------- tier-3 boundary --


@pytest.mark.parametrize(
    "expr",
    [
        "coalesce(Account, Process)",
        "array_length(Account)",
        "ipv4_is_private(SrcIpAddr)",
        "substring(Account, 0, 4)",
        "countof(Account, 'x')",
    ],
)
def test_out_of_scope_scalars_stay_skipped(expr: str, mapping: dict) -> None:
    _out, errors = _scalar(expr, mapping)
    assert errors, f"expected {expr!r} to remain unsupported"


# ----------------------------------------------------- function catalog sync --


def test_function_catalog_lists_new_functions() -> None:
    from scripts.kql.functions import (
        SUPPORTED_PREDICATE_FUNCTIONS,
        SUPPORTED_SCALAR_FUNCTIONS,
    )

    for fn in (
        "todouble",
        "toreal",
        "tofloat",
        "todecimal",
        "tobool",
        "toboolean",
        "strcat_delim",
    ):
        assert fn in SUPPORTED_SCALAR_FUNCTIONS, fn
    for fn in ("isnull", "isnotnull"):
        assert fn in SUPPORTED_PREDICATE_FUNCTIONS, fn
