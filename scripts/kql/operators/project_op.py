"""``project`` / ``project-reorder`` / ``fields`` operator extraction (plan 06-04)."""

from __future__ import annotations

from . import register
from ..types import ConversionContext, KqlStage, StageResult, Tier


@register("project")
@register("project-reorder")
@register("fields")
def convert_project(stage: KqlStage, ctx: ConversionContext) -> StageResult:
    from scripts import convert_sentinel_kql as _legacy

    errors: list[str] = []
    allowed = set(ctx.allowed_aliases)
    fields_clause = _legacy._convert_fields_clause(stage.body, ctx.mapping, errors, allowed)
    skip_reasons = tuple(errors)
    tier = Tier.TIER_3 if skip_reasons else Tier.TIER_1
    fragments: tuple[str, ...] = (f"fields {fields_clause}",) if fields_clause else ()
    return StageResult(
        fragments=fragments,
        tier=tier,
        skip_reasons=skip_reasons,
        new_aliases=(),
    )


__all__ = ["convert_project"]
