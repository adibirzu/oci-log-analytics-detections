"""Tier-3 registrations for KQL operators with no Logan QL equivalent.

These operators have always been SKIPPED by the converter. The registry
holds a real function so that ``OPERATOR_REGISTRY[kind]`` never returns
``None`` for a recognized KQL keyword — callers always get a structured
``Tier.TIER_3`` ``StageResult`` and the report classifier folds them
into the per-candidate ``tier_3`` bucket.
"""

from __future__ import annotations

from . import register
from ..types import ConversionContext, KqlStage, StageResult, Tier

_UNSUPPORTED = (
    "take",
    "count",
    "limit",
    "parse",
    "evaluate",
    "mv-expand",
    "make-series",
    "join",
    "render",
)


def _make_unsupported(kind: str):
    def convert(stage: KqlStage, ctx: ConversionContext) -> StageResult:
        return StageResult(
            fragments=(),
            tier=Tier.TIER_3,
            skip_reasons=(f"unsupported KQL stage: {kind} {stage.body}".strip(),),
        )

    convert.__name__ = f"convert_{kind.replace('-', '_')}_unsupported"
    return convert


for _kind in _UNSUPPORTED:
    register(_kind)(_make_unsupported(_kind))
