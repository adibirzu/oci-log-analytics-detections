"""``sort`` / ``order`` / ``top`` operator extraction (plan 06-06)."""

from __future__ import annotations

from . import register
from ..types import ConversionContext, KqlStage, StageResult, Tier


@register("sort")
@register("order")
def convert_sort(stage: KqlStage, ctx: ConversionContext) -> StageResult:
    from scripts import convert_sentinel_kql as _legacy

    errors: list[str] = []
    allowed = set(ctx.allowed_aliases)
    command = _legacy._convert_sort(
        f"sort {stage.body}", ctx.mapping, errors, allowed
    )
    skip_reasons = tuple(errors)
    tier = Tier.TIER_3 if skip_reasons else Tier.TIER_1
    fragments: tuple[str, ...] = (command,) if command else ()
    return StageResult(
        fragments=fragments,
        tier=tier,
        skip_reasons=skip_reasons,
        new_aliases=(),
    )


@register("top")
def convert_top(stage: KqlStage, ctx: ConversionContext) -> StageResult:
    from scripts import convert_sentinel_kql as _legacy

    errors: list[str] = []
    allowed = set(ctx.allowed_aliases)
    top_commands = _legacy._convert_top(
        f"top {stage.body}", ctx.mapping, errors, allowed
    )
    skip_reasons = tuple(errors)
    tier = Tier.TIER_3 if skip_reasons else Tier.TIER_1
    return StageResult(
        fragments=tuple(top_commands),
        tier=tier,
        skip_reasons=skip_reasons,
        new_aliases=(),
    )


__all__ = ["convert_sort", "convert_top"]
