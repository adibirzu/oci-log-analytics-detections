"""``union`` operator extraction (plan 06-08).

The Phase 6 legacy converter does not currently support any ``union``
shape — every union flows through the unsupported-stage path. This
wrapper preserves that behavior by returning ``Tier.TIER_3`` with a
structured skip reason, while still being a real registered operator
(so the registry holds a real function, not a shim).
"""

from __future__ import annotations

from . import register
from ..types import ConversionContext, KqlStage, StageResult, Tier


@register("union")
def convert_union(stage: KqlStage, ctx: ConversionContext) -> StageResult:
    return StageResult(
        fragments=(),
        tier=Tier.TIER_3,
        skip_reasons=(f"unsupported KQL stage: union {stage.body}".strip(),),
        new_aliases=(),
    )


__all__ = ["convert_union"]
