"""Hypothesis property test for ``canonical()`` idempotence (D-03).

Narrow generators per CONTEXT — only Phase 6 operator shapes (where/fields).
``eval``/``stats``/aggregates are deferred to Phase 9 alongside their
operator extractions and gain their own narrow generators then.
"""

from __future__ import annotations

import sys
from pathlib import Path

from hypothesis import given, settings, strategies as st

PROJECT_DIR = Path(__file__).resolve().parents[2]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from scripts.kql.canonical import canonical  # noqa: E402


_field = st.from_regex(r"[A-Za-z][A-Za-z0-9 ]{0,15}", fullmatch=True).map(
    lambda name: f"'{name}'"
)
_literal_text = st.from_regex(r"[A-Za-z0-9_ %\-]{0,20}", fullmatch=True)
_literal = _literal_text.map(lambda text: f"'{text}'")

_op = st.sampled_from(["=", "!=", "like", "contains", "startswith"])
_clause = st.builds(lambda f, op, v: f"{f} {op} {v}", _field, _op, _literal)
_chain_and = st.lists(_clause, min_size=1, max_size=4).map(" and ".join)
_chain_or = st.lists(_clause, min_size=1, max_size=4).map(" or ".join)
_fields_clause = st.lists(_field, min_size=1, max_size=5).map(
    lambda xs: "fields " + ", ".join(xs)
)
_where_clause = _chain_and.map(lambda body: f"where {body}")

_stage = st.one_of(_where_clause, _chain_or.map(lambda body: f"where {body}"), _fields_clause)

_pipe = st.sampled_from([" | ", "  |  ", "|", " |", "| "])


@st.composite
def _query(draw):
    stages = draw(st.lists(_stage, min_size=1, max_size=4))
    sep = draw(_pipe)
    pad = draw(st.sampled_from(["", " ", "   "]))
    return pad + sep.join(stages) + pad


@settings(max_examples=100, deadline=None)
@given(query=_query())
def test_canonical_is_idempotent(query: str) -> None:
    once = canonical(query)
    twice = canonical(once)
    assert once == twice
