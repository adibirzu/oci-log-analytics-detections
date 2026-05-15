"""Operator registry for the KQL→Logan QL pipeline (D-05).

Operator modules call ``@register("<op>")`` at import time, populating
``OPERATOR_REGISTRY``. The pipeline dispatches stages by looking up the
stage kind in this dict.

Phase 6 ships every operator as a thin adapter in ``_legacy`` that calls
back into the legacy module. Subsequent plans (06-02..06-09) replace each
adapter with a real implementation; plan 06-10 deletes ``_legacy`` entirely.
"""

from __future__ import annotations

from typing import Callable, Dict

from ..types import ConversionContext, KqlStage, StageResult

OperatorFn = Callable[[KqlStage, ConversionContext], StageResult]

OPERATOR_REGISTRY: Dict[str, OperatorFn] = {}


def register(name: str):
    """Decorator that registers an operator function under ``name``."""

    def _wrap(fn: OperatorFn) -> OperatorFn:
        OPERATOR_REGISTRY[name] = fn
        return fn

    return _wrap


# Adapter registration must happen after ``register`` is defined.
# Order: legacy shims first (unsupported set), then extracted operators
# claim their registry slots.
from . import _legacy  # noqa: E402,F401
from . import where_op  # noqa: E402,F401
from . import summarize_op  # noqa: E402,F401
from . import project_op  # noqa: E402,F401
from . import extend_op  # noqa: E402,F401
from . import sort_op  # noqa: E402,F401
from . import distinct_op  # noqa: E402,F401
from . import union_op  # noqa: E402,F401
from . import let_op  # noqa: E402,F401

__all__ = ["OPERATOR_REGISTRY", "OperatorFn", "register"]
