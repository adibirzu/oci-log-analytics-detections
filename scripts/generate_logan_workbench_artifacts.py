#!/usr/bin/env python3
"""Generate OCI Logan workbench reference, pattern, and example artifacts.

The integrated webapp consumes these JSON files. This repository remains the
source of truth for generated conversion guidance and examples.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from analyze_ql_conversion_coverage import build_matrix  # noqa: E402
from logan_workbench_patterns import build_patterns as _build_patterns  # noqa: E402
from logan_workbench_examples import build_examples as _build_examples  # noqa: E402

QUERY_SEARCH_URL = "https://docs.oracle.com/en-us/iaas/log-analytics/doc/query-search.html"
COMMAND_REFERENCE_URL = "https://docs.oracle.com/en-us/iaas/log-analytics/doc/command-reference.html"

REFERENCE_PATH = PROJECT_ROOT / "queries" / "logan_ql_reference_catalog.json"
PATTERNS_PATH = PROJECT_ROOT / "queries" / "cross_ql_mapping_patterns.json"
EXAMPLES_PATH = PROJECT_ROOT / "queries" / "conversion_examples.json"
CAPABILITY_MATRIX_PATH = PROJECT_ROOT / "queries" / "ql_conversion_capability_matrix.json"
FORGE_CATALOG_PATH = PROJECT_ROOT / "queries" / "forge_detection_catalog.json"

REQUIRED_COMMANDS = [
    "search",
    "where",
    "stats",
    "timestats",
    "eval",
    "fields",
    "sort",
    "top",
    "distinct",
    "regex",
    "lookup",
    "link",
    "sequence",
    "rename",
    "head",
]


@dataclass(frozen=True)
class CommandSeed:
    name: str
    category: str
    summary: str
    syntax: str
    examples: list[str]
    notes: list[str]
    source_url: str = COMMAND_REFERENCE_URL


COMMAND_SEEDS = [
    CommandSeed(
        "search",
        "base",
        "Starts an OCI Log Analytics search with source and field predicates.",
        "'Log Source' = '<source>' and 'Field' = 'value'",
        ["'Log Source' = 'OCI Audit Logs' and 'Event Name' = 'ConsoleSignIn'"],
        ["Use quoted display field names for OCI fields that contain spaces."],
        QUERY_SEARCH_URL,
    ),
    CommandSeed(
        "where",
        "filter",
        "Filters the current result set with a boolean expression.",
        "| where <predicate>",
        ["| where attempts > 5 and 'Principal Name' is not null"],
        ["Maps from KQL where, SPL where/search predicates, and Lucene field filters."],
    ),
    CommandSeed(
        "stats",
        "aggregate",
        "Aggregates records and groups by selected dimensions.",
        "| stats count as Count by 'Host Name', 'User Name'",
        ["| stats count as hits by 'Host Name', 'Event Name'"],
        ["Maps from KQL summarize, SPL stats, Elastic aggregations, and Sigma count conditions."],
    ),
    CommandSeed(
        "timestats",
        "aggregate",
        "Aggregates records into time buckets for trend and spike detection.",
        "| timestats span=5m count as failures by src_ip",
        ["| timestats span=5m count as failures by 'Host Name'"],
        ["Prefer timestats when the source query bins or buckets TimeGenerated/_time."],
    ),
    CommandSeed(
        "eval",
        "transform",
        "Calculates a new field from existing fields and expressions.",
        "| eval risk = if(hits > 10, 'high', 'medium')",
        ["| eval src_ip = extract('Message', /from ([0-9.]+)/)"],
        ["Maps from KQL extend/project aliases and SPL eval."],
    ),
    CommandSeed(
        "fields",
        "projection",
        "Keeps or orders the selected fields in the output.",
        "| fields 'Time', 'Host Name', 'User Name'",
        ["| fields 'Time', 'Computer', 'Command Line'"],
        ["Maps from KQL project, SPL table/fields, and Elastic selected columns."],
    ),
    CommandSeed(
        "sort",
        "ordering",
        "Sorts the current result set by one or more fields.",
        "| sort -hits",
        ["| sort -Count | head 100"],
        ["Prefix a field with '-' for descending order and cap broad result sets with head."],
    ),
    CommandSeed(
        "top",
        "aggregate",
        "Returns the most frequent values for a field or aggregation.",
        "| top 20 'Source IP'",
        ["| top 10 'Event Name'"],
        ["Use stats plus sort when the source query needs multi-field ranking."],
    ),
    CommandSeed(
        "distinct",
        "aggregate",
        "Returns unique values for selected fields.",
        "| distinct 'Host Name', 'User Name'",
        ["| distinct 'Principal Name'"],
        ["Maps from KQL distinct and SPL dedup/table patterns."],
    ),
    CommandSeed(
        "regex",
        "extract",
        "Matches or extracts values with a regular expression where supported by Logan QL.",
        "| regex 'Message' = /Failed password/",
        ["| eval src_ip = extract('Message', /from ([0-9.]+)/)"],
        ["Prefer documented extraction functions when the goal is creating a new field."],
    ),
    CommandSeed(
        "lookup",
        "enrichment",
        "Invokes a field-value lookup for enrichment or filtering.",
        "| lookup <lookup_name> <field>",
        ["[searchlookup table=ip_blacklist | distinct ip] | timestats count"],
        ["Sentinel watchlists and Splunk lookups need an explicit OCI lookup/table design."],
    ),
    CommandSeed(
        "link",
        "correlation",
        "Groups related log records into transaction-style linked events.",
        "| link 'Host Name', 'User Name'",
        ["| link 'Host Name' | stats count as Events"],
        ["Elastic EQL sequence conversion should use link groups when a stable entity field exists."],
    ),
    CommandSeed(
        "sequence",
        "correlation",
        "Identifies ordered event patterns inside linked event groups.",
        "| link 'Host Name' | sequence 'Event Name' = 'start', 'Event Name' = 'stop'",
        ["| link 'Host Name' | sequence 'Event ID' = '4624', 'Event ID' = '4688'"],
        ["Only convert source sequence semantics when the ordering, grouping key, and time span are preserved."],
    ),
    CommandSeed(
        "rename",
        "projection",
        "Renames output fields for downstream display or grouping.",
        "| rename 'User Name' as user",
        ["| rename ip as 'host address'"],
        ["Maps from SPL rename and KQL project aliases when the conversion is lossless."],
    ),
    CommandSeed(
        "head",
        "ordering",
        "Limits the result set to the first N rows.",
        "| head 100",
        ["| sort -hits | head 50"],
        ["Use with sort/top conversions to keep UI and saved-search results bounded."],
    ),
]


class CommandReferenceParser(HTMLParser):
    """Small parser for the official command-reference table."""

    def __init__(self) -> None:
        super().__init__()
        self.rows: list[dict[str, str]] = []
        self._in_td = False
        self._td_index = -1
        self._row_cells: list[str] = []
        self._buf: list[str] = []
        self._href = ""
        self._current_href = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = {key: value or "" for key, value in attrs}
        if tag == "tr":
            self._row_cells = []
            self._td_index = -1
        elif tag == "td":
            self._in_td = True
            self._td_index += 1
            self._buf = []
            self._href = ""
        elif tag == "a" and self._in_td:
            self._current_href = attrs_dict.get("href", "")
            if not self._href:
                self._href = self._current_href

    def handle_endtag(self, tag: str) -> None:
        if tag == "td" and self._in_td:
            self._row_cells.append(" ".join("".join(self._buf).split()))
            self._in_td = False
            self._buf = []
        elif tag == "tr" and len(self._row_cells) >= 2:
            command = self._row_cells[0].strip()
            description = self._row_cells[1].strip()
            if re.fullmatch(r"[a-z][a-z0-9_-]*", command):
                self.rows.append({"command": command, "description": description, "href": self._href})
        elif tag == "a":
            self._current_href = ""

    def handle_data(self, data: str) -> None:
        if self._in_td:
            self._buf.append(data)


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def fetch_url(url: str) -> str:
    request = Request(url, headers={"User-Agent": "oci-logan-workbench-artifact-generator/1.0"})
    with urlopen(request, timeout=30) as response:
        return response.read().decode("utf-8", errors="replace")


def parse_official_commands(html: str) -> dict[str, dict[str, str]]:
    parser = CommandReferenceParser()
    parser.feed(html)
    return {row["command"]: row for row in parser.rows}


def build_reference_catalog(refresh_docs: bool) -> dict:
    retrieved_at = now_iso()
    official: dict[str, dict[str, str]] = {}
    fetch_error = ""
    if refresh_docs:
        try:
            official = parse_official_commands(fetch_url(COMMAND_REFERENCE_URL))
        except (OSError, URLError, TimeoutError) as exc:
            fetch_error = str(exc)

    entries = []
    for seed in COMMAND_SEEDS:
        official_row = official.get(seed.name, {})
        source_path = official_row.get("href") or f"{seed.name}.html"
        source_url = seed.source_url
        if seed.source_url == COMMAND_REFERENCE_URL and source_path:
            source_url = f"https://docs.oracle.com/en-us/iaas/log-analytics/doc/{source_path}"
        official_summary = official_row.get("description") or seed.summary
        entries.append(
            {
                "name": seed.name,
                "category": seed.category,
                "source_url": source_url,
                "source_title": "OCI Log Analytics Query Language Command Reference",
                "retrieved_at": retrieved_at,
                "summary": official_summary,
                "syntax": seed.syntax,
                "examples": seed.examples,
                "notes": seed.notes,
                "provenance": {
                    "official_command_reference": COMMAND_REFERENCE_URL,
                    "official_query_search": QUERY_SEARCH_URL,
                    "generated_by": "scripts/generate_logan_workbench_artifacts.py",
                    "live_fetch": bool(official),
                    "fetch_error": fetch_error,
                },
            }
        )

    return {
        "schema_version": "1.0.0",
        "generated_at": retrieved_at,
        "sources": [QUERY_SEARCH_URL, COMMAND_REFERENCE_URL],
        "required_commands": REQUIRED_COMMANDS,
        "commands": entries,
    }


def build_patterns() -> dict:
    """Build mapping patterns with the public generator clock."""
    return _build_patterns(generated_at=now_iso())


def build_examples() -> dict:
    """Build conversion examples with the public generator clock."""
    return _build_examples(generated_at=now_iso())


def _extract_log_sources(logan_ql: str, fallback: list[str] | None = None) -> list[str]:
    found: list[str] = []
    for m in re.finditer(r"'Log Source'\s*=\s*'([^']+)'", logan_ql):
        if m.group(1) not in found:
            found.append(m.group(1))
    for m in re.finditer(r"'Log Source'\s+in\s*\(([^)]+)\)", logan_ql, flags=re.IGNORECASE):
        for s in re.findall(r"'([^']+)'", m.group(1)):
            if s not in found:
                found.append(s)
    for item in fallback or []:
        if item and item not in found:
            found.append(item)
    return found or ["OCI Log Analytics"]


def build_forge_detection_catalog(examples_payload: dict) -> dict:
    import yaml

    generated_at = now_iso()
    items: list[dict] = []
    seen_ids: set[str] = set()

    # 1. Cross-QL Workbench Conversion Examples (20)
    for ex in examples_payload.get("examples", []):
        ex_id = ex["id"]
        seen_ids.add(ex_id)
        items.append(
            {
                "id": ex_id,
                "title": ex["title"],
                "surface": "workbench_example",
                "pack_or_category": "Cross-QL Workbench Examples",
                "severity": "high",
                "source_language": ex["source_language"],
                "source_query": ex["source_query"],
                "expected_logan_ql": ex["expected_logan_ql"],
                "explanation": ex["explanation"],
                "support_level": ex["support_level"],
                "log_sources": _extract_log_sources(ex["expected_logan_ql"]),
                "mitre_techniques": re.findall(r"T\d{4}(?:\.\d{3})?", ex["source_query"], flags=re.IGNORECASE),
                "mitre_tactics": [],
            }
        )

    # 2. 2026 Threat Reports & 7-Day Caldera/GOAD Storyline Packs
    packs_dir = PROJECT_ROOT / "packs" / "2026_threat_reports"
    if packs_dir.is_dir():
        for pack_file in sorted(packs_dir.glob("*.yaml")):
            doc = yaml.safe_load(pack_file.read_text(encoding="utf-8")) or {}
            pack_title = doc.get("title") or pack_file.stem
            entries = (
                doc.get("days")
                or doc.get("detections")
                or doc.get("campaigns")
                or doc.get("hunts")
                or []
            )
            for entry in entries:
                entry_id = str(entry.get("id") or entry.get("hunt_id") or f"{pack_file.stem}").strip()
                if not entry_id or entry_id in seen_ids:
                    continue
                seen_ids.add(entry_id)
                logan_ql = (
                    entry.get("log_analytics_query")
                    or (entry.get("execute") or {}).get("log_analytics_query")
                    or ""
                ).strip()
                title = (
                    entry.get("title")
                    or entry.get("name")
                    or entry_id
                )
                desc = (
                    entry.get("description")
                    or entry.get("perpetrator_narrative")
                    or (entry.get("prepare") or {}).get("hypothesis")
                    or pack_title
                )
                mitre = entry.get("mitre_attack") or []
                tactics = [entry["tactic"]] if entry.get("tactic") else []
                items.append(
                    {
                        "id": entry_id,
                        "title": f"[{entry_id}] {title}",
                        "surface": "threat_report_2026",
                        "pack_or_category": pack_title.split("—")[0].strip(),
                        "severity": "critical" if "DAY-05" in entry_id or "DAY-06" in entry_id or "DAY-07" in entry_id else "high",
                        "source_language": "oci_logan",
                        "source_query": logan_ql,
                        "expected_logan_ql": logan_ql,
                        "explanation": str(desc).strip(),
                        "support_level": "supported",
                        "log_sources": _extract_log_sources(logan_ql, entry.get("log_sources") if isinstance(entry.get("log_sources"), list) else None),
                        "mitre_techniques": [str(m) for m in mitre],
                        "mitre_tactics": [str(t) for t in tactics],
                    }
                )

    # 3. Hunting queries (queries/hunting/*.json)
    hunting_dir = PROJECT_ROOT / "queries" / "hunting"
    if hunting_dir.is_dir():
        for qfile in sorted(hunting_dir.glob("*.json")):
            data = json.loads(qfile.read_text(encoding="utf-8"))
            qid = f"hunting/{qfile.stem}"
            if qid in seen_ids:
                continue
            seen_ids.add(qid)
            logan_ql = str(data.get("query") or "").strip()
            mitre_obj = data.get("mitre_attack") or {}
            logsource_obj = data.get("logsource") or {}
            is_storyline = qfile.stem.startswith("storyline_day")
            is_ac_hunter = qfile.stem.startswith("ac_hunter_")
            items.append(
                {
                    "id": qid,
                    "title": str(data.get("title") or qfile.stem),
                    "surface": "hunting",
                    "pack_or_category": (
                        "7-Day Storyline Hunts"
                        if is_storyline
                        else ("AC-Hunter & Multi-Cloud Hunts" if is_ac_hunter else "Threat Hunting Library")
                    ),
                    "severity": str(data.get("level") or "medium").lower(),
                    "source_language": "oci_logan",
                    "source_query": logan_ql,
                    "expected_logan_ql": logan_ql,
                    "explanation": str(data.get("description") or "OCI Log Analytics threat hunting query.").strip(),
                    "support_level": "supported",
                    "log_sources": _extract_log_sources(logan_ql, logsource_obj.get("candidates") if isinstance(logsource_obj, dict) else None),
                    "mitre_techniques": [str(t) for t in (mitre_obj.get("techniques") or [])],
                    "mitre_tactics": [str(t) for t in (mitre_obj.get("tactics") or [])],
                }
            )

    # 4. Application / APM queries (queries/apps/*.json)
    apps_dir = PROJECT_ROOT / "queries" / "apps"
    if apps_dir.is_dir():
        for qfile in sorted(apps_dir.glob("*.json")):
            data = json.loads(qfile.read_text(encoding="utf-8"))
            qid = f"apps/{qfile.stem}"
            if qid in seen_ids:
                continue
            seen_ids.add(qid)
            logan_ql = str(data.get("query") or "").strip()
            mitre_obj = data.get("mitre_attack") or {}
            logsource_obj = data.get("logsource") or {}
            items.append(
                {
                    "id": qid,
                    "title": str(data.get("title") or qfile.stem),
                    "surface": "application",
                    "pack_or_category": "Application & APM Security",
                    "severity": str(data.get("level") or "high").lower(),
                    "source_language": "oci_logan",
                    "source_query": logan_ql,
                    "expected_logan_ql": logan_ql,
                    "explanation": str(data.get("description") or "Application & APM security detection query.").strip(),
                    "support_level": "supported",
                    "log_sources": _extract_log_sources(logan_ql, logsource_obj.get("candidates") if isinstance(logsource_obj, dict) else None),
                    "mitre_techniques": [str(t) for t in (mitre_obj.get("techniques") or [])],
                    "mitre_tactics": [str(t) for t in (mitre_obj.get("tactics") or [])],
                }
            )

    # 5. All Detection Rules in queries/*.json (excluding generated catalog/workbench artifacts)
    excluded_top_files = {
        "catalog.json",
        "conversion_examples.json",
        "cross_ql_mapping_patterns.json",
        "dashboard_inventory.json",
        "forge_detection_catalog.json",
        "hunting_integration_bundle.json",
        "logan_ql_reference_catalog.json",
        "ql_conversion_capability_matrix.json",
        "siem_log_examples.json",
    }
    queries_dir = PROJECT_ROOT / "queries"
    for qfile in sorted(queries_dir.glob("*.json")):
        if qfile.name in excluded_top_files:
            continue
        data = json.loads(qfile.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or "query" not in data:
            continue
        qid = f"detection/{qfile.stem}"
        if qid in seen_ids:
            continue
        seen_ids.add(qid)
        logan_ql = str(data.get("query") or "").strip()
        mitre_obj = data.get("mitre_attack") or {}
        logsource_obj = data.get("logsource") or {}
        product = str((logsource_obj.get("product") if isinstance(logsource_obj, dict) else "") or "oci").capitalize()
        items.append(
            {
                "id": qid,
                "title": str(data.get("title") or qfile.stem),
                "surface": "detection",
                "pack_or_category": f"{product} Detections",
                "severity": str(data.get("level") or "medium").lower(),
                "source_language": "oci_logan",
                "source_query": logan_ql,
                "expected_logan_ql": logan_ql,
                "explanation": str(data.get("description") or "Production OCI Log Analytics detection rule.").strip(),
                "support_level": "supported",
                "log_sources": _extract_log_sources(logan_ql, logsource_obj.get("candidates") if isinstance(logsource_obj, dict) else None),
                "mitre_techniques": [str(t) for t in (mitre_obj.get("techniques") or [])],
                "mitre_tactics": [str(t) for t in (mitre_obj.get("tactics") or [])],
            }
        )

    # 6. All Sentinel-converted Detection Rules in queries/sentinel/*.json
    sentinel_dir = PROJECT_ROOT / "queries" / "sentinel"
    if sentinel_dir.is_dir():
        for qfile in sorted(sentinel_dir.glob("*.json")):
            data = json.loads(qfile.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or "query" not in data:
                continue
            qid = f"sentinel/{qfile.stem}"
            if qid in seen_ids:
                continue
            seen_ids.add(qid)
            logan_ql = str(data.get("query") or "").strip()
            mitre_obj = data.get("mitre_attack") or {}
            logsource_obj = data.get("logsource") or {}
            items.append(
                {
                    "id": qid,
                    "title": str(data.get("title") or qfile.stem),
                    "surface": "detection",
                    "pack_or_category": "Sentinel Detections",
                    "severity": str(data.get("level") or "medium").lower(),
                    "source_language": "oci_logan",
                    "source_query": logan_ql,
                    "expected_logan_ql": logan_ql,
                    "explanation": str(data.get("description") or "Sentinel-to-OCI Log Analytics detection rule.").strip(),
                    "support_level": "supported",
                    "log_sources": _extract_log_sources(logan_ql, logsource_obj.get("candidates") if isinstance(logsource_obj, dict) else None),
                    "mitre_techniques": [str(t) for t in (mitre_obj.get("techniques") or [])],
                    "mitre_tactics": [str(t) for t in (mitre_obj.get("tactics") or [])],
                }
            )

    surface_counts: dict[str, int] = {}
    for item in items:
        s = item["surface"]
        surface_counts[s] = surface_counts.get(s, 0) + 1

    return {
        "schema_version": "1.0.0",
        "generated_at": generated_at,
        "total_items": len(items),
        "surface_counts": surface_counts,
        "items": items,
    }


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate Logan conversion workbench artifacts")
    parser.add_argument("--refresh-docs", action="store_true", help="Fetch official Oracle docs for command provenance")
    parser.add_argument("--elastic-repo", type=Path, help="Optional local elastic/detection-rules checkout for aggregate counts")
    args = parser.parse_args()

    examples_payload = build_examples()
    write_json(REFERENCE_PATH, build_reference_catalog(refresh_docs=args.refresh_docs))
    write_json(PATTERNS_PATH, build_patterns())
    write_json(EXAMPLES_PATH, examples_payload)
    write_json(CAPABILITY_MATRIX_PATH, build_matrix(args.elastic_repo))
    write_json(FORGE_CATALOG_PATH, build_forge_detection_catalog(examples_payload))
    print(f"wrote {REFERENCE_PATH.relative_to(PROJECT_ROOT)}")
    print(f"wrote {PATTERNS_PATH.relative_to(PROJECT_ROOT)}")
    print(f"wrote {EXAMPLES_PATH.relative_to(PROJECT_ROOT)}")
    print(f"wrote {CAPABILITY_MATRIX_PATH.relative_to(PROJECT_ROOT)}")
    print(f"wrote {FORGE_CATALOG_PATH.relative_to(PROJECT_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
