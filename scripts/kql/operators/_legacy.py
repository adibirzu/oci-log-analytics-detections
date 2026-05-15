"""Phase 6 legacy operator adapters.

Each ``@register("<op>")`` here is a marker that says "the pipeline knows
this operator name, but Phase 6 still routes the full query through the
legacy ``convert_kql_to_logan``." Subsequent plans (06-02..06-09) replace
each marker with a real operator function in its own module; plan 06-10
DELETES this file entirely.
"""

from __future__ import annotations

from . import register
from ..types import ConversionContext, KqlStage, StageResult, Tier


_PHASE_6_SHIM_MESSAGE = (
    "Legacy adapter shim; pipeline.convert() delegates to legacy "
    "convert_kql_to_logan in Phase 6 — operators not yet routed through "
    "registry. See plans 06-02..06-09."
)


def _shim(stage: KqlStage, ctx: ConversionContext) -> StageResult:  # pragma: no cover - never invoked in Phase 6
    raise NotImplementedError(_PHASE_6_SHIM_MESSAGE)


# Supported operator families — extracted in plans 06-02..06-09.
register("where")(_shim)
register("summarize")(_shim)
register("project")(_shim)
register("extend")(_shim)
register("sort")(_shim)
register("order")(_shim)
register("top")(_shim)
register("distinct")(_shim)
register("union")(_shim)
register("let")(_shim)
register("fields")(_shim)

# Currently-unsupported operators (Tier-3 SKIPPED). These never get extracted
# in Phase 6; they get a real Tier-3 module in plan 06-10's unsupported_op.py.
register("take")(_shim)
register("count")(_shim)
register("limit")(_shim)
register("parse")(_shim)
register("evaluate")(_shim)
register("mv-expand")(_shim)
register("make-series")(_shim)
register("join")(_shim)
register("render")(_shim)
