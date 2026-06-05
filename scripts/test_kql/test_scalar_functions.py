"""Phase 9 scalar/predicate function parity tests.

Covers the operator-parity tranche added in Phase 9: the previously
unsupported scalar functions ``materialize``, ``strlen``, ``strcat`` and
``extract`` now emit locally-valid Logan QL through the existing stage
pipeline (``extend`` / ``project`` / ``where``), and the corresponding
whole-query classifier no longer flags them as unsupported.

Out-of-scope constructs (ML ``series_*``/``make-series``/``autocluster``,
``geo_*``, cross-table ``join``, JSON-bag expansion) must stay SKIPPED;
the tier-3 guard tests at the bottom lock that boundary in place.
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
from scripts.kql.operators import extend_op, project_op, where_op  # noqa: E402
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


# --------------------------------------------------------------- materialize --


def test_materialize_unwraps_to_inner_expression(mapping: dict) -> None:
    out, errors = _scalar("materialize(Account)", mapping)
    assert errors == []
    # ``materialize`` is a pure caching hint with no Logan equivalent; the
    # converter must unwrap it to the inner (mapped) expression.
    assert out == "User"


def test_materialize_via_extend_operator(ctx: ConversionContext) -> None:
    result = extend_op.convert_extend(
        KqlStage(kind="extend", body="Cached = materialize(tolower(Account))"), ctx
    )
    assert result.tier == Tier.TIER_1
    assert result.skip_reasons == ()
    assert result.fragments == ("eval Cached = lower(User)",)
    assert "Cached" in result.new_aliases


# -------------------------------------------------------------------- strlen --


def test_strlen_maps_to_length(mapping: dict) -> None:
    out, errors = _scalar("strlen(CommandLine)", mapping)
    assert errors == []
    assert out == "length('Command Line')"


def test_strlen_via_extend_operator(ctx: ConversionContext) -> None:
    result = extend_op.convert_extend(
        KqlStage(kind="extend", body="CmdLen = strlen(CommandLine)"), ctx
    )
    assert result.tier == Tier.TIER_1
    assert result.skip_reasons == ()
    assert result.fragments == ("eval CmdLen = length('Command Line')",)


# -------------------------------------------------------------------- strcat --


def test_strcat_two_args_maps_to_concat(mapping: dict) -> None:
    out, errors = _scalar("strcat(Account, Process)", mapping)
    assert errors == []
    assert out == "concat(User, 'Process Name')"


def test_strcat_with_literal_separator(mapping: dict) -> None:
    out, errors = _scalar("strcat(Account, '\\\\', Process)", mapping)
    assert errors == []
    assert out.startswith("concat(User, ")
    assert out.endswith(", 'Process Name')")


def test_strcat_via_extend_operator(ctx: ConversionContext) -> None:
    result = extend_op.convert_extend(
        KqlStage(kind="extend", body="FullName = strcat(Account, Process)"), ctx
    )
    assert result.tier == Tier.TIER_1
    assert result.skip_reasons == ()
    assert result.fragments == ("eval FullName = concat(User, 'Process Name')",)


# ------------------------------------------------------------------- extract --


def test_extract_maps_to_logan_extract_regex(mapping: dict) -> None:
    out, errors = _scalar('extract("([0-9.]+)", 1, CommandLine)', mapping)
    assert errors == []
    # KQL extract(regex, captureGroup, source) -> Logan extract(source, /regex/)
    assert out == "extract('Command Line', /([0-9.]+)/)"


def test_extract_via_extend_operator(ctx: ConversionContext) -> None:
    result = extend_op.convert_extend(
        KqlStage(kind="extend", body='SrcIp = extract("from ([0-9.]+)", 1, CommandLine)'),
        ctx,
    )
    assert result.tier == Tier.TIER_1
    assert result.skip_reasons == ()
    assert result.fragments == ("eval SrcIp = extract('Command Line', /from ([0-9.]+)/)",)
    assert "SrcIp" in result.new_aliases


# --------------------------------------------------------- whole-query gate --


@pytest.mark.parametrize(
    "kql",
    [
        "SecurityEvent | extend CmdLen = strlen(CommandLine)",
        "SecurityEvent | extend Cached = materialize(Account)",
        "SecurityEvent | extend Full = strcat(Account, Process)",
        'SecurityEvent | extend Src = extract("([0-9.]+)", 1, CommandLine)',
    ],
)
def test_classifier_no_longer_flags_supported_scalars(kql: str) -> None:
    reasons = facade.classify_unsupported_kql(kql)
    blocking = [
        r
        for r in reasons
        if any(
            tok in r
            for tok in (
                "materialize",
                "strlen",
                "regex extraction",
            )
        )
    ]
    assert blocking == [], f"unexpected residual scalar blockers: {blocking}"


# ----------------------------------------------------------- tier-3 boundary --


@pytest.mark.parametrize(
    "kql, expected_token",
    [
        ("SecurityEvent | make-series Count=count() on TimeGenerated", "make-series"),
        ("SecurityEvent | join (Heartbeat) on Computer", "join"),
        ("SecurityEvent | extend B = bag_unpack(Properties)", "JSON bag expansion"),
        ("SecurityEvent | evaluate autocluster()", "evaluate"),
    ],
)
def test_out_of_scope_constructs_stay_skipped(kql: str, expected_token: str) -> None:
    reasons = facade.classify_unsupported_kql(kql)
    assert any(expected_token in r for r in reasons), reasons


def test_extract_capture_group_other_than_one_is_skipped(mapping: dict) -> None:
    out, errors = _scalar('extract("a(b)(c)", 2, CommandLine)', mapping)
    assert any("capture group" in e for e in errors), errors


def test_extract_all_stays_unsupported() -> None:
    reasons = facade.classify_unsupported_kql(
        'SecurityEvent | extend M = extract_all("([0-9]+)", CommandLine)'
    )
    assert any("extract_all" in r for r in reasons), reasons


# ----------------------------------------------------- function catalog sync --


def test_function_catalog_lists_new_scalars() -> None:
    from scripts.kql.functions import SUPPORTED_SCALAR_FUNCTIONS, SKIPPED_SCALAR_FUNCTIONS

    for fn in ("materialize", "strlen", "strcat", "extract"):
        assert fn in SUPPORTED_SCALAR_FUNCTIONS
    # Out-of-scope families must not be advertised as supported.
    for fn in ("bag_unpack", "extract_all", "make_series"):
        assert fn in SKIPPED_SCALAR_FUNCTIONS
        assert fn not in SUPPORTED_SCALAR_FUNCTIONS
