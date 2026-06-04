"""KQL scalar-function support catalog for the KQL->Logan QL pipeline.

Scalar functions are not pipeline *stages* (those live in
``scripts/kql/operators/``); they are translated inside ``extend`` /
``project`` / ``where`` bodies by ``_facade_impl._convert_scalar_expression``
and ``_facade_impl.convert_predicate``. This module is the single source of
truth for which KQL scalar functions the converter recognises, so operator
modules and tests can introspect coverage without importing the large
facade implementation.

``SUPPORTED_SCALAR_FUNCTIONS`` maps the KQL function name to the Logan QL
form it lowers to. ``SKIPPED_SCALAR_FUNCTIONS`` records functions that are
intentionally Tier-3 (no faithful Logan equivalent) and must stay skipped.
"""

from __future__ import annotations

# KQL scalar function -> Logan QL lowering (documentation / introspection).
SUPPORTED_SCALAR_FUNCTIONS: dict[str, str] = {
    "iff": "if(<predicate>, <true>, <false>)",
    "iif": "if(<predicate>, <true>, <false>)",
    "case": "nested if(...)",
    "tostring": "<arg> (cast removed)",
    "toint": "<arg> (cast removed)",
    "tolong": "<arg> (cast removed)",
    "tolower": "lower(<arg>)",
    "toupper": "upper(<arg>)",
    "column_ifexists": "<field literal>",
    # Phase 9 operator-parity tranche:
    "materialize": "<arg> (caching hint unwrapped)",
    "strlen": "length(<arg>)",
    "strcat": "concat(<arg>, ...)",
    "extract": "extract(<source>, /<regex>/)",
}

# Functions that have no faithful Logan QL equivalent and stay Tier-3.
SKIPPED_SCALAR_FUNCTIONS: frozenset[str] = frozenset(
    {
        "parse_json",
        "todynamic",
        "bag_unpack",
        "bag_keys",
        "extractjson",
        "extract_all",
        "parse_command_line",
        "make_series",
    }
)

__all__ = ["SUPPORTED_SCALAR_FUNCTIONS", "SKIPPED_SCALAR_FUNCTIONS"]
