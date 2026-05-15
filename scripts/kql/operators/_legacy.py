"""Phase 6 legacy operator adapters (residual unsupported-only set).

Plans 06-02..06-09 extracted each supported operator family into its own
module; this file now only carries stub registrations for operators that
remain unsupported in Phase 6. Plan 06-10 folds the residual set into a
dedicated ``unsupported_op`` module and deletes this file.
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


# Currently-unsupported operators (Tier-3 SKIPPED). Plan 06-10 moves these
# into ``unsupported_op.py`` and deletes this file.
register("take")(_shim)
register("count")(_shim)
register("limit")(_shim)
register("parse")(_shim)
register("evaluate")(_shim)
register("mv-expand")(_shim)
register("make-series")(_shim)
register("join")(_shim)
register("render")(_shim)
