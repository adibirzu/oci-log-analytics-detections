"""``extend`` operator extraction (plan 06-05)."""

from __future__ import annotations

from . import register
from ..types import ConversionContext, KqlStage, StageResult, Tier


@register("extend")
def convert_extend(stage: KqlStage, ctx: ConversionContext) -> StageResult:
    from scripts import convert_sentinel_kql as _legacy

    allowed = set(ctx.allowed_aliases)
    extend_commands, errors, extend_aliases = _legacy._convert_extend(
        f"extend {stage.body}", ctx.mapping, allowed
    )
    skip_reasons = tuple(errors)
    tier = Tier.TIER_3 if skip_reasons else Tier.TIER_1
    new_aliases = tuple(sorted(set(extend_aliases) - set(ctx.allowed_aliases)))
    return StageResult(
        fragments=tuple(extend_commands),
        tier=tier,
        skip_reasons=skip_reasons,
        new_aliases=new_aliases,
    )


__all__ = ["convert_extend"]
