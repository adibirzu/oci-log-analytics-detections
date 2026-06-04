"""``take`` / ``limit`` / ``sample`` / ``count`` / ``render`` operators."""

from __future__ import annotations

import re

from . import register
from ..types import ConversionContext, KqlStage, StageResult, Tier


@register("count")
def convert_count(stage: KqlStage, ctx: ConversionContext) -> StageResult:
    return StageResult(
        fragments=("stats count as Count",),
        tier=Tier.TIER_1,
        skip_reasons=(),
        new_aliases=("Count",),
    )


@register("take")
@register("limit")
@register("sample")
def convert_limit(stage: KqlStage, ctx: ConversionContext) -> StageResult:
    count = re.findall(r"\d+", stage.body)
    if not count:
        return StageResult(
            fragments=(),
            tier=Tier.TIER_3,
            skip_reasons=(f"unsupported KQL stage: {stage.kind} {stage.body}".strip(),),
            new_aliases=(),
        )
    return StageResult(
        fragments=(f"head {count[0]}",),
        tier=Tier.TIER_1,
        skip_reasons=(),
        new_aliases=(),
    )


@register("render")
def convert_render(stage: KqlStage, ctx: ConversionContext) -> StageResult:
    return StageResult(
        fragments=(),
        tier=Tier.TIER_1,
        skip_reasons=(),
        new_aliases=(),
    )


__all__ = ["convert_count", "convert_limit", "convert_render"]
