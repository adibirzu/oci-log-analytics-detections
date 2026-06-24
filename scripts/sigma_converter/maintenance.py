"""Validation and maintenance helpers for generated Sigma query artifacts."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections.abc import Callable, Iterable
from pathlib import Path


def query_syntax_issues(query):
    """Return a list of OCL syntax issues for a single generated query string."""
    issues = []
    anchor = r"'(Log Source|Trace ID|Client IP|Source IP|Destination IP)'"
    if not re.match(rf"^\(*\s*{anchor}\s*(=|in)\s*", query):
        issues.append("missing Log Source prefix")

    in_quote = False
    paren_depth = 0
    depth_went_negative = False
    backslashes = 0
    prev = ""
    double_space = False
    for ch in query:
        if ch == "'":
            if backslashes % 2 == 0:
                in_quote = not in_quote
            backslashes = 0
        else:
            if not in_quote:
                if ch == "(":
                    paren_depth += 1
                elif ch == ")":
                    paren_depth -= 1
                    if paren_depth < 0:
                        depth_went_negative = True
                elif ch == " " and prev == " ":
                    double_space = True
            backslashes = backslashes + 1 if ch == "\\" else 0
        prev = ch
    if paren_depth != 0 or depth_went_negative:
        issues.append("unbalanced parentheses")
    if in_quote:
        issues.append("unterminated quoted string")
    if double_space:
        issues.append("double spaces")
    return issues


def print_stats(output_path, *, iter_query_files: Callable[[str | Path], Iterable[Path]], level_to_stig_cat: dict):
    """Print statistics about generated queries."""
    queries = []
    for path in iter_query_files(output_path):
        with open(path) as fh:
            data = json.load(fh)
        if not data.get("sigma_id"):
            continue
        queries.append(data)

    print(f"\n{'=' * 60}")
    print("Detection Rule Statistics")
    print(f"{'=' * 60}")
    print(f"  Total rules: {len(queries)}")

    sources = {}
    for query in queries:
        source = query.get("logsource", {}).get("product", "unknown")
        sources[source] = sources.get(source, 0) + 1
    print("\n  By platform:")
    for source, count in sorted(sources.items(), key=lambda item: -item[1]):
        print(f"    {source:20s} {count}")

    levels = {}
    for query in queries:
        level = query.get("level", "unknown")
        levels[level] = levels.get(level, 0) + 1
    print("\n  By severity:")
    for level in ["critical", "high", "medium", "low", "informational"]:
        if level in levels:
            stig = level_to_stig_cat.get(level, "")
            print(f"    {level:15s} ({stig:6s}) {levels[level]}")

    stig_rules = [query for query in queries if query.get("stig_ids")]
    print(f"\n  STIG-tagged rules: {len(stig_rules)}")

    techniques = set()
    tactics = set()
    for query in queries:
        mitre = query.get("mitre_attack", {})
        techniques.update(mitre.get("techniques", []))
        tactics.update(mitre.get("tactics", []))
    print(f"  MITRE ATT&CK techniques: {len(techniques)}")
    print(f"  MITRE ATT&CK tactics: {len(tactics)}")
    for tactic in sorted(tactics):
        print(f"    - {tactic}")


def validate_queries(output_path, *, iter_query_files: Callable[[str | Path], Iterable[Path]]):
    """Validate OCL syntax of generated queries."""
    errors = 0
    total = 0
    for path in iter_query_files(output_path):
        with open(path) as fh:
            query_payload = json.load(fh)
        query = query_payload.get("query", "")
        total += 1
        issues = query_syntax_issues(query)
        if issues:
            rel_path = path.relative_to(output_path).as_posix()
            print(f"  WARN {rel_path}: {', '.join(issues)}")
            errors += 1
    print(f"\n  Validated {total} queries, {errors} warnings")


def refresh_catalogs(project_dir: str | Path) -> None:
    """Re-emit catalog/manifest/dashboard-inventory JSONs after a sweep."""
    base = Path(project_dir)
    failures = []
    for cmd_args, label in (
        (["scripts/generate_catalog.py"], "catalog"),
        (["scripts/export_for_multicloud.py", "--manifest-only"], "manifest"),
        (["scripts/deploy_dashboard.py", "--export-inventory"], "dashboard inventory"),
    ):
        try:
            result = subprocess.run(
                ["python3", *cmd_args],
                cwd=base,
                check=False,
                capture_output=True,
                text=True,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            failures.append((label, f"spawn error: {exc}"))
            print(f"ERROR: {label} refresh could not start: {exc}", file=sys.stderr)
            continue
        if result.returncode != 0:
            stderr_tail = (result.stderr or "").strip().splitlines()[-10:]
            stdout_tail = (result.stdout or "").strip().splitlines()[-10:]
            sys.stdout.flush()
            print(
                f"ERROR: {label} refresh exited {result.returncode}",
                file=sys.stderr,
                flush=True,
            )
            for line in stdout_tail:
                print(f"  stdout: {line}", file=sys.stderr, flush=True)
            for line in stderr_tail:
                print(f"  stderr: {line}", file=sys.stderr, flush=True)
            failures.append((label, f"exit {result.returncode}"))
            continue
        print(f"Refreshed {label}", flush=True)
    if failures:
        raise RuntimeError(
            "Catalog refresh failed: "
            + ", ".join(f"{label}={detail}" for label, detail in failures)
        )


def sweep_stale_duplicates(
    output_root,
    written_by_sigma,
    *,
    iter_query_files: Callable[[str | Path], Iterable[Path]],
):
    """Delete stale duplicate query files that share a refreshed sigma_id."""
    canonical = {sid: os.path.realpath(path) for sid, path in written_by_sigma.items()}
    removed = []
    for path in iter_query_files(output_root):
        try:
            with open(path) as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        sid = data.get("sigma_id")
        if not sid or sid not in canonical:
            continue
        if os.path.realpath(path) == canonical[sid]:
            continue
        if data.get("do_not_overwrite"):
            continue
        try:
            os.remove(path)
            removed.append(str(path))
        except OSError:
            pass
    return removed

