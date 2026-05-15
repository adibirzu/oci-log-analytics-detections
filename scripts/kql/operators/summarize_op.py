"""``summarize`` operator extraction (plan 06-03)."""

from __future__ import annotations

from . import register
from ..types import ConversionContext, KqlStage, StageResult, Tier


@register("summarize")
def convert_summarize(stage: KqlStage, ctx: ConversionContext) -> StageResult:
    from scripts import convert_sentinel_kql as _legacy

    allowed = set(ctx.allowed_aliases)
    command, errors, aggregate_aliases = _legacy._convert_summarize(
        f"summarize {stage.body}", ctx.mapping, allowed
    )
    skip_reasons = tuple(errors)
    tier = Tier.TIER_3 if skip_reasons else Tier.TIER_1
    fragments: tuple[str, ...] = (command,) if command else ()
    new_aliases = tuple(sorted(aggregate_aliases - set(ctx.allowed_aliases)))
    return StageResult(
        fragments=fragments,
        tier=tier,
        skip_reasons=skip_reasons,
        new_aliases=new_aliases,
    )


__all__ = ["convert_summarize"]
