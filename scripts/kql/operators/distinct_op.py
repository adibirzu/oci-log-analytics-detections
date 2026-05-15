"""``distinct`` operator extraction (plan 06-07).

Logan QL has no direct ``distinct`` operator; the legacy converter emits
``stats count as Count by <fields>`` (see ``convert_kql_to_logan`` distinct
branch). This wrapper produces the same fragment via the legacy
``_convert_fields_clause`` helper.
"""

from __future__ import annotations

from . import register
from ..types import ConversionContext, KqlStage, StageResult, Tier


@register("distinct")
def convert_distinct(stage: KqlStage, ctx: ConversionContext) -> StageResult:
    from scripts import convert_sentinel_kql as _legacy

    errors: list[str] = []
    allowed = set(ctx.allowed_aliases)
    fields_clause = _legacy._convert_fields_clause(stage.body, ctx.mapping, errors, allowed)
    skip_reasons = tuple(errors)
    tier = Tier.TIER_3 if skip_reasons else Tier.TIER_1
    fragments: tuple[str, ...] = (f"stats count as Count by {fields_clause}",) if fields_clause else ()
    # distinct introduces the synthetic Count alias for downstream stages.
    new_aliases: tuple[str, ...] = ("Count",) if fields_clause and "Count" not in ctx.allowed_aliases else ()
    return StageResult(
        fragments=fragments,
        tier=tier,
        skip_reasons=skip_reasons,
        new_aliases=new_aliases,
    )


__all__ = ["convert_distinct"]
