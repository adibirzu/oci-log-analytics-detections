"""``where`` (and ``filter``) operator extraction (plan 06-02).

Behavior-preserving wrapper around the legacy ``convert_predicate`` so
``OPERATOR_REGISTRY['where']`` dispatches through this module instead of
the Phase 6 stub. The Phase 6 pipeline still routes whole-query
conversion through ``scripts.convert_sentinel_kql.convert_kql_to_logan``;
this function is exercised directly by ``test_kql/test_where_operator.py``
and becomes the actual dispatch target in plan 06-10.
"""

from __future__ import annotations

from . import register
from ..types import ConversionContext, KqlStage, StageResult, Tier


@register("where")
def convert_where(stage: KqlStage, ctx: ConversionContext) -> StageResult:
    from scripts import convert_sentinel_kql as _legacy

    allowed = set(ctx.allowed_aliases)
    fragment, errors = _legacy.convert_predicate(stage.body, ctx.mapping, allowed)
    skip_reasons = tuple(errors)
    tier = Tier.TIER_3 if skip_reasons else Tier.TIER_1
    fragments: tuple[str, ...] = (f"where {fragment}",) if fragment else ()
    return StageResult(
        fragments=fragments,
        tier=tier,
        skip_reasons=skip_reasons,
        new_aliases=(),
    )


__all__ = ["convert_where"]
