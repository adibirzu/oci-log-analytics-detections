"""Module-size gate contracts.

The gate enforces the repository file-size ceiling recursively across
``scripts/**/*.py``. These tests cover the production checker instead of only
checking one facade by hand, so future package splits remain protected.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
CHECKER_PATH = SCRIPTS_DIR / "check_module_size.py"
FACADE = SCRIPTS_DIR / "convert_sentinel_kql.py"
LIMIT = 800


def _load_checker() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_module_size_for_tests", CHECKER_PATH)
    assert spec is not None
    assert spec.loader is not None
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    return checker


def _write_python_file(path: Path, line_count: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join("value = 1\n" for _ in range(line_count)), encoding="utf-8")


def test_facade_under_line_limit() -> None:
    line_count = sum(1 for _ in FACADE.open())
    assert line_count <= LIMIT, f"{FACADE.name} is {line_count} lines, exceeds {LIMIT}"


def test_recursive_checker_fails_nested_oversized_modules(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    checker = _load_checker()
    _write_python_file(tmp_path / "nested" / "too_large.py", checker.LIMIT + 1)
    _write_python_file(tmp_path / "ok.py", checker.LIMIT)

    monkeypatch.setattr(checker, "SCRIPTS_DIR", tmp_path)
    monkeypatch.setattr(checker, "ALLOWLIST", frozenset())

    assert checker.check() == 1
    captured = capsys.readouterr()
    assert "nested/too_large.py" in captured.out
    assert "ok.py" not in captured.out


def test_recursive_checker_warns_for_allowlisted_nested_modules(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    checker = _load_checker()
    _write_python_file(tmp_path / "nested" / "legacy.py", checker.LIMIT + 1)

    monkeypatch.setattr(checker, "SCRIPTS_DIR", tmp_path)
    monkeypatch.setattr(checker, "ALLOWLIST", frozenset({"nested/legacy.py"}))

    assert checker.check() == 0
    captured = capsys.readouterr()
    assert "nested/legacy.py" in captured.out
    assert "ALLOWLISTED" in captured.out
