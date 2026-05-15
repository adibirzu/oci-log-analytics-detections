"""``let`` operator extraction (plan 06-09).

Phase 6 dispatch shim. Substitution semantics still flow through legacy
``_preprocess_simple_lets`` at the top of ``convert_kql_to_logan``;
``pipeline.convert`` delegates to the legacy entry for end-to-end
behavior. Phase 7+ refactors substitution into ``ConversionContext``.

This wrapper detects whether the let expression is a simple scalar
binding (Tier-1, the only shape the legacy converter currently rewrites)
or a tabular/function-shaped binding (Tier-3 SKIPPED).
"""

from __future__ import annotations

from . import register
from ..types import ConversionContext, KqlStage, StageResult, Tier


@register("let")
def convert_let(stage: KqlStage, ctx: ConversionContext) -> StageResult:
    from scripts import convert_sentinel_kql as _legacy

    # ``stage.body`` is the text after ``let`` (e.g. ``threshold = 5`` or
    # ``threshold = 5;``). Split off the trailing terminator and isolate the
    # right-hand side so we pass an expression to the legacy normalizer.
    body = stage.body.strip().rstrip(";").strip()
    if "=" not in body:
        return StageResult(
            fragments=(), tier=Tier.TIER_3,
            skip_reasons=("let_unsupported_shape",),
        )
    _, expression = body.split("=", 1)
    normalized = _legacy._normalize_simple_let_expression(expression.strip())
    if normalized is None:
        return StageResult(
            fragments=(), tier=Tier.TIER_3,
            skip_reasons=("let_unsupported_shape",),
        )
    return StageResult(fragments=(), tier=Tier.TIER_1)


__all__ = ["convert_let"]
