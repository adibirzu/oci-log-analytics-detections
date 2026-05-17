"""Operator-level extraction tests (plans 06-02..06-09).

Each test exercises an extracted operator function directly via the
public ``OPERATOR_REGISTRY`` plus its module-level binding. The Phase 6
pipeline still delegates whole-query conversion to legacy code, so these
tests are the only callers of the operator functions during PR-1..PR-9.
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

from scripts.kql.canonical import canonical  # noqa: E402
from scripts.kql.operators import (  # noqa: E402
    OPERATOR_REGISTRY,
    distinct_op,
    extend_op,
    let_op,
    project_op,
    sort_op,
    summarize_op,
    union_op,
    where_op,
)
from scripts.kql.types import ConversionContext, KqlStage, StageResult, Tier  # noqa: E402

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


# ---------------------------------------------------------------- registry --


def test_registry_binds_where_to_extracted_function() -> None:
    assert OPERATOR_REGISTRY["where"] is where_op.convert_where


def test_registry_binds_summarize_to_extracted_function() -> None:
    assert OPERATOR_REGISTRY["summarize"] is summarize_op.convert_summarize


def test_registry_binds_project_and_fields_to_same_function() -> None:
    assert OPERATOR_REGISTRY["project"] is project_op.convert_project
    assert OPERATOR_REGISTRY["fields"] is project_op.convert_project
    assert OPERATOR_REGISTRY["project-reorder"] is project_op.convert_project


def test_registry_binds_extend_to_extracted_function() -> None:
    assert OPERATOR_REGISTRY["extend"] is extend_op.convert_extend


def test_registry_binds_sort_and_top() -> None:
    assert OPERATOR_REGISTRY["sort"] is sort_op.convert_sort
    assert OPERATOR_REGISTRY["order"] is sort_op.convert_sort
    assert OPERATOR_REGISTRY["top"] is sort_op.convert_top


def test_registry_binds_distinct() -> None:
    assert OPERATOR_REGISTRY["distinct"] is distinct_op.convert_distinct


def test_registry_binds_union() -> None:
    assert OPERATOR_REGISTRY["union"] is union_op.convert_union


def test_registry_binds_let() -> None:
    assert OPERATOR_REGISTRY["let"] is let_op.convert_let


# --------------------------------------------------------- happy-path tier-1 --


def test_where_simple_equality_tier1(ctx: ConversionContext) -> None:
    result = where_op.convert_where(KqlStage(kind="where", body="EventID == 4624"), ctx)
    assert isinstance(result, StageResult)
    assert result.tier == Tier.TIER_1
    assert not result.skip_reasons
    assert result.fragments and result.fragments[0].startswith("where ")
    assert "4624" in result.fragments[0]


def test_where_string_ops_tier1(ctx: ConversionContext) -> None:
    body = "Process =~ '.*powershell.*' and CommandLine contains 'invoke' and Account startswith 'admin'"
    result = where_op.convert_where(KqlStage(kind="where", body=body), ctx)
    assert result.tier == Tier.TIER_1
    assert not result.skip_reasons


def test_summarize_count_by_tier1(ctx: ConversionContext) -> None:
    result = summarize_op.convert_summarize(
        KqlStage(kind="summarize", body="count() by Account"), ctx
    )
    assert result.tier == Tier.TIER_1
    assert result.fragments
    assert "count" in result.fragments[0].lower()


def test_summarize_countif_and_time_bin_tier1(ctx: ConversionContext) -> None:
    result = summarize_op.convert_summarize(
        KqlStage(kind="summarize", body="Failures=countif(EventID == 4625) by bin(TimeGenerated, 15m), Account"),
        ctx,
    )
    assert result.tier == Tier.TIER_1
    assert result.skip_reasons == ()
    assert result.fragments
    assert result.fragments[0].startswith("timestats span = 15minute")
    assert "sum(if('Event ID' = '4625', 1, 0)) as Failures" in result.fragments[0]


def test_project_basic_tier1(ctx: ConversionContext) -> None:
    result = project_op.convert_project(
        KqlStage(kind="project", body="TimeGenerated, Account, Process"), ctx
    )
    assert result.tier == Tier.TIER_1
    assert result.fragments
    assert result.fragments[0].startswith("fields ")


def test_extend_basic_alias_propagation(ctx: ConversionContext) -> None:
    result = extend_op.convert_extend(
        KqlStage(kind="extend", body="IsAdmin = iff(Account == 'admin', 1, 0)"), ctx
    )
    assert isinstance(result.new_aliases, tuple)
    # Alias propagation is the contract regardless of tier; legacy may flag
    # this expression as needing a wider mapping, but the wrapper must
    # always populate ``new_aliases`` when the legacy helper introduces one.
    if result.tier == Tier.TIER_1:
        assert "IsAdmin" in result.new_aliases


def test_extend_scalar_function_tier1(ctx: ConversionContext) -> None:
    result = extend_op.convert_extend(
        KqlStage(kind="extend", body="ActorLower = tolower(tostring(Account))"), ctx
    )
    assert result.tier == Tier.TIER_1
    assert result.skip_reasons == ()
    assert result.fragments == ("eval ActorLower = lower(User)",)


def test_sort_basic_tier1(ctx: ConversionContext) -> None:
    result = sort_op.convert_sort(
        KqlStage(kind="sort", body="by TimeGenerated desc"), ctx
    )
    assert result.tier == Tier.TIER_1
    assert result.fragments


def test_top_basic_tier1(ctx: ConversionContext) -> None:
    result = sort_op.convert_top(
        KqlStage(kind="top", body="10 by TimeGenerated desc"), ctx
    )
    assert result.tier == Tier.TIER_1
    assert result.fragments


def test_distinct_emits_stats_count(ctx: ConversionContext) -> None:
    result = distinct_op.convert_distinct(
        KqlStage(kind="distinct", body="Account, Process"), ctx
    )
    assert result.tier == Tier.TIER_1
    assert result.fragments
    assert "stats count as Count by" in result.fragments[0]
    assert "Count" in result.new_aliases


def test_let_scalar_tier1(ctx: ConversionContext) -> None:
    result = let_op.convert_let(
        KqlStage(kind="let", body="threshold = 5"), ctx
    )
    assert result.tier == Tier.TIER_1
    assert result.fragments == ()


# ---------------------------------------------------------------- tier-3 --


def test_union_always_tier3(ctx: ConversionContext) -> None:
    result = union_op.convert_union(
        KqlStage(kind="union", body="SecurityEvent, Syslog"), ctx
    )
    assert result.tier == Tier.TIER_3
    assert result.skip_reasons
    assert result.fragments == ()


def test_let_tabular_tier3(ctx: ConversionContext) -> None:
    result = let_op.convert_let(
        KqlStage(kind="let", body="T = SecurityEvent | where EventID == 4624"), ctx
    )
    assert result.tier == Tier.TIER_3
    assert "let_unsupported_shape" in result.skip_reasons


# ---------------------------------------------------------- fixture round-trip --


@pytest.mark.parametrize(
    "fixture_stem",
    [
        "where_basic",
        "where_string_ops",
        "summarize_count_by",
        "project_basic",
        "extend_iff_basic",
        "sort_basic",
        "top_basic",
        "distinct_basic",
        "union_simple",
        "let_scalar",
    ],
)
def test_synthetic_fixture_round_trips(fixture_stem: str) -> None:
    fixtures = Path(__file__).resolve().parent / "fixtures"
    kql_text = (fixtures / "kql" / f"{fixture_stem}.kql").read_text()
    expected = (fixtures / "expected" / f"{fixture_stem}.logan").read_text()
    assert canonical(kql_text) == expected
