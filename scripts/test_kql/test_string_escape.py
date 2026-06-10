"""Golden tests for Logan QL string / ``LIKE`` literal escaping (bug T7).

When the KQL → Logan converter embeds a KQL string value that contains a
single quote into a Logan QL string / ``LIKE`` literal, it must escape the
interior quote by DOUBLING it (``''``) — the Logan QL convention — never with
a backslash (``\\'``).

The OCI parser tolerates ``\\'``, so such queries can live-validate, but ``''``
is the correct, reliably-matching form and is the only one that survives
``scripts/kql/canonical.py`` (the canonicalizer treats ``\\`` as an
unrecognized character inside a string and would raise on a stray ``\\'``).

The canonical reference for correct escaping is
``scripts/kql/canonical.py:_emit_qstring`` →
``"'" + value.replace("'", "''") + "'"``. ``_escape_logan_string`` mirrors it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_DIR = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = PROJECT_DIR / "scripts"
for path in (PROJECT_DIR, SCRIPTS_DIR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from scripts.kql import _facade_impl as facade  # noqa: E402
from scripts.kql.canonical import canonical  # noqa: E402


@pytest.fixture(scope="module")
def mapping() -> dict:
    return facade.load_mapping_config()


# ------------------------------------------------------- direct emitter --


def test_escape_doubles_interior_single_quote() -> None:
    out = facade._escape_logan_string(".decode('base64')")
    assert out == ".decode(''base64'')"
    assert "\\'" not in out


def test_escape_mirrors_canonical_emit_qstring() -> None:
    # _escape_logan_string is the un-wrapped twin of canonical._emit_qstring.
    from scripts.kql.canonical import _emit_qstring

    value = "a'b'c"
    assert "'" + facade._escape_logan_string(value) + "'" == _emit_qstring(value)


def test_escape_normalizes_stray_backslash_quote() -> None:
    # A backslash-escaped quote that an upstream step may introduce must be
    # normalized back to a doubled quote, never left as \\' in the output.
    out = facade._escape_logan_string("x\\'y")
    assert out == "x''y"
    assert "\\'" not in out


def test_escape_none_is_empty() -> None:
    assert facade._escape_logan_string(None) == ""


# ---------------------------------------------- end-to-end LIKE literal --


def test_contains_with_single_quote_emits_doubled_quote(mapping: dict) -> None:
    out, errors = facade.convert_predicate(
        "CommandLine contains \".decode('base64')\"", mapping
    )
    assert errors == []
    assert out == "'Command Line' like '*.decode(''base64'')*'"
    # The bad backslash form must never appear.
    assert "\\'" not in out


def test_like_literal_is_canonical_stable(mapping: dict) -> None:
    out, errors = facade.convert_predicate(
        "CommandLine contains \".decode('base64')\"", mapping
    )
    assert errors == []
    # canonical() must accept the doubled-quote literal (it would raise
    # CanonicalizationError on a backslash-escaped quote) and be idempotent.
    once = canonical(out)
    assert once == out
    assert canonical(once) == once
