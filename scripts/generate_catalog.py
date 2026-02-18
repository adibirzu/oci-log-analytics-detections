#!/usr/bin/env python3
"""
Generate a searchable detection rule catalog in Markdown and JSON.

Outputs:
  - CATALOG.md — Human-readable catalog with MITRE ATT&CK matrix, severity breakdown,
                 and full rule table sorted by platform/severity.
  - queries/catalog.json — Machine-readable catalog for integration.

Usage:
  python3 scripts/generate_catalog.py              # Generate both formats
  python3 scripts/generate_catalog.py --json-only   # JSON only
  python3 scripts/generate_catalog.py --md-only     # Markdown only
"""

import json
import os
import sys
from collections import defaultdict
from pathlib import Path

PROJECT_DIR = Path(__file__).parent.parent
QUERIES_DIR = PROJECT_DIR / "queries"
HUNTING_DIR = QUERIES_DIR / "hunting"
OUTPUT_MD = PROJECT_DIR / "CATALOG.md"
OUTPUT_JSON = QUERIES_DIR / "catalog.json"

SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]
SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "informational": "⚪",
}

TACTIC_ORDER = [
    "initial_access", "execution", "persistence", "privilege_escalation",
    "defense_evasion", "credential_access", "discovery", "lateral_movement",
    "collection", "command_and_control", "exfiltration", "impact",
]

TACTIC_DISPLAY = {
    "initial_access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege_escalation": "Privilege Escalation",
    "defense_evasion": "Defense Evasion",
    "credential_access": "Credential Access",
    "discovery": "Discovery",
    "lateral_movement": "Lateral Movement",
    "collection": "Collection",
    "command_and_control": "Command & Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}

PLATFORM_DISPLAY = {
    "oci": "OCI Cloud",
    "linux": "Linux",
    "windows": "Windows",
}


def load_queries():
    """Load all detection queries and hunting queries."""
    queries = []
    for f in sorted(QUERIES_DIR.glob("*.json")):
        if f.name in ("manifest.json", "catalog.json"):
            continue
        with open(f) as fh:
            data = json.load(fh)
            data["_file"] = f.name
            queries.append(data)

    hunting = []
    if HUNTING_DIR.exists():
        for f in sorted(HUNTING_DIR.glob("*.json")):
            with open(f) as fh:
                data = json.load(fh)
                data["_file"] = f"hunting/{f.name}"
                data["_is_hunting"] = True
                hunting.append(data)

    return queries, hunting


def build_mitre_matrix(queries, hunting):
    """Build MITRE ATT&CK tactic-to-technique mapping."""
    matrix = defaultdict(lambda: defaultdict(list))
    for q in queries + hunting:
        ma = q.get("mitre_attack", {})
        techniques = ma.get("techniques", [])
        tactics = ma.get("tactics", [])
        for tactic in tactics:
            for tech in techniques:
                matrix[tactic][tech].append(q["title"])
    return matrix


def generate_markdown(queries, hunting):
    """Generate the CATALOG.md file."""
    lines = []
    w = lines.append

    total = len(queries) + len(hunting)
    w("# Detection Rule Catalog")
    w("")
    w(f"> **{len(queries)} detection rules** + **{len(hunting)} hunting queries** | "
      f"Auto-generated from Sigma YAML sources")
    w("")

    # --- Summary stats ---
    w("## Summary")
    w("")

    # Platform breakdown
    platforms = defaultdict(int)
    for q in queries:
        p = q.get("logsource", {}).get("product", "unknown")
        platforms[p] += 1
    w("| Platform | Rules |")
    w("|----------|-------|")
    for p in ["oci", "linux", "windows"]:
        if p in platforms:
            w(f"| {PLATFORM_DISPLAY.get(p, p)} | {platforms[p]} |")
    w("")

    # Severity breakdown
    severities = defaultdict(int)
    for q in queries:
        severities[q.get("level", "unknown")] += 1
    w("| Severity | Count |")
    w("|----------|-------|")
    for s in SEVERITY_ORDER:
        if s in severities:
            w(f"| {SEVERITY_EMOJI.get(s, '')} {s.title()} | {severities[s]} |")
    w("")

    # ART Coverage
    testable = [q for q in queries
                if q.get("logsource", {}).get("product") in ("windows", "linux")]
    with_art = [q for q in testable if q.get("atomic_red_team", {}).get("has_tests")]
    if testable:
        art_pct = len(with_art) / len(testable) * 100
        total_tests = sum(q.get("atomic_red_team", {}).get("test_count", 0) for q in testable)
        w(f"**Atomic Red Team Coverage:** {len(with_art)}/{len(testable)} testable rules "
          f"have ART tests ({art_pct:.0f}%) | {total_tests} total test mappings")
        w("")

    # STIG
    stig_rules = [q for q in queries if q.get("stig_ids")]
    if stig_rules:
        stig_ids = set()
        for q in stig_rules:
            stig_ids.update(q.get("stig_ids", []))
        w(f"**STIG Coverage:** {len(stig_rules)} rules covering {len(stig_ids)} controls "
          f"({', '.join(sorted(stig_ids))})")
        w("")

    # --- MITRE ATT&CK Matrix ---
    w("## MITRE ATT&CK Coverage")
    w("")
    matrix = build_mitre_matrix(queries, hunting)

    all_techniques = set()
    for tactic_techs in matrix.values():
        all_techniques.update(tactic_techs.keys())
    w(f"**{len(all_techniques)} techniques** across **{len(matrix)} tactics**")
    w("")

    for tactic in TACTIC_ORDER:
        if tactic not in matrix:
            continue
        display = TACTIC_DISPLAY.get(tactic, tactic)
        techs = matrix[tactic]
        w(f"### {display} ({len(techs)} techniques)")
        w("")
        w("| Technique | Rules |")
        w("|-----------|-------|")
        for tech in sorted(techs.keys()):
            rule_names = techs[tech]
            # Truncate long rule lists
            if len(rule_names) <= 3:
                names = ", ".join(rule_names)
            else:
                names = f"{', '.join(rule_names[:2])}, +{len(rule_names)-2} more"
            w(f"| {tech} | {names} |")
        w("")

    # --- Full Rule Table by Platform ---
    w("## All Detection Rules")
    w("")

    for platform in ["oci", "linux", "windows"]:
        plat_rules = [q for q in queries
                      if q.get("logsource", {}).get("product") == platform]
        if not plat_rules:
            continue

        display = PLATFORM_DISPLAY.get(platform, platform)
        w(f"### {display} ({len(plat_rules)} rules)")
        w("")
        has_art = platform in ("windows", "linux")
        if has_art:
            w("| # | Title | Severity | MITRE | ART Tests | STIG |")
            w("|---|-------|----------|-------|-----------|------|")
        else:
            w("| # | Title | Severity | MITRE | STIG |")
            w("|---|-------|----------|-------|------|")

        # Sort by severity then title
        def sev_key(q):
            try:
                return SEVERITY_ORDER.index(q.get("level", "medium"))
            except ValueError:
                return 99
        plat_rules.sort(key=lambda q: (sev_key(q), q["title"]))

        for i, q in enumerate(plat_rules, 1):
            title = q["title"]
            level = q.get("level", "unknown")
            emoji = SEVERITY_EMOJI.get(level, "")
            techniques = ", ".join(q.get("mitre_attack", {}).get("techniques", [])) or "-"
            stig = ", ".join(q.get("stig_ids", [])) or "-"
            if has_art:
                art_count = q.get("atomic_red_team", {}).get("test_count", 0)
                art_str = str(art_count) if art_count else "-"
                w(f"| {i} | {title} | {emoji} {level} | {techniques} | {art_str} | {stig} |")
            else:
                w(f"| {i} | {title} | {emoji} {level} | {techniques} | {stig} |")
        w("")

    # --- Hunting Queries ---
    if hunting:
        w("## Hunting Queries")
        w("")
        w("| # | Title | Method | Severity | MITRE |")
        w("|---|-------|--------|----------|-------|")
        for i, q in enumerate(hunting, 1):
            method = q.get("hunting_type", q.get("cookbook_method", "-"))
            level = q.get("level", "medium")
            emoji = SEVERITY_EMOJI.get(level, "")
            techniques = ", ".join(q.get("mitre_attack", {}).get("techniques", [])) or "-"
            w(f"| {i} | {q['title']} | {method} | {emoji} {level} | {techniques} |")
        w("")

    # --- STIG Compliance Table ---
    if stig_rules:
        w("## STIG Compliance Rules")
        w("")
        w("| Rule | STIG Control | Category | Severity |")
        w("|------|-------------|----------|----------|")
        stig_rules.sort(key=lambda q: (q.get("stig_ids", [""])[0], q["title"]))
        for q in stig_rules:
            stig = ", ".join(q.get("stig_ids", []))
            cat = q.get("stig_category", "-")
            level = q.get("level", "medium")
            w(f"| {q['title']} | {stig} | {cat} | {level} |")
        w("")

    w("---")
    w(f"*Generated from {len(queries)} Sigma rules + {len(hunting)} hunting queries*")

    return "\n".join(lines)


def generate_json_catalog(queries, hunting):
    """Generate machine-readable catalog."""
    catalog = {
        "version": "1.0",
        "total_rules": len(queries),
        "total_hunting": len(hunting),
        "platforms": {},
        "severities": {},
        "mitre_techniques": [],
        "mitre_tactics": [],
        "stig_controls": [],
        "rules": [],
        "hunting_queries": [],
    }

    platforms = defaultdict(int)
    severities = defaultdict(int)
    techniques = set()
    tactics = set()
    stig_controls = set()

    for q in queries:
        p = q.get("logsource", {}).get("product", "unknown")
        platforms[p] += 1
        severities[q.get("level", "unknown")] += 1
        ma = q.get("mitre_attack", {})
        techniques.update(ma.get("techniques", []))
        tactics.update(ma.get("tactics", []))
        stig_controls.update(q.get("stig_ids", []))

        catalog["rules"].append({
            "title": q["title"],
            "description": q.get("description", ""),
            "level": q.get("level", "medium"),
            "platform": p,
            "mitre_techniques": ma.get("techniques", []),
            "mitre_tactics": ma.get("tactics", []),
            "stig_ids": q.get("stig_ids", []),
            "stig_category": q.get("stig_category", ""),
            "file": q.get("_file", ""),
        })

    for q in hunting:
        catalog["hunting_queries"].append({
            "title": q["title"],
            "description": q.get("description", ""),
            "level": q.get("level", "medium"),
            "hunting_type": q.get("hunting_type", ""),
            "cookbook_method": q.get("cookbook_method", ""),
            "mitre_techniques": q.get("mitre_attack", {}).get("techniques", []),
            "file": q.get("_file", ""),
        })

    catalog["platforms"] = dict(platforms)
    catalog["severities"] = dict(severities)
    catalog["mitre_techniques"] = sorted(techniques)
    catalog["mitre_tactics"] = sorted(tactics)
    catalog["stig_controls"] = sorted(stig_controls)

    # ART coverage stats
    testable = [q for q in queries
                if q.get("logsource", {}).get("product") in ("windows", "linux")]
    with_art = [q for q in testable if q.get("atomic_red_team", {}).get("has_tests")]
    total_tests = sum(q.get("atomic_red_team", {}).get("test_count", 0) for q in testable)
    catalog["art_coverage"] = {
        "testable_rules": len(testable),
        "rules_with_tests": len(with_art),
        "coverage_percent": round(len(with_art) / len(testable) * 100, 1) if testable else 0,
        "total_test_mappings": total_tests,
    }

    return catalog


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Generate detection rule catalog")
    parser.add_argument("--json-only", action="store_true", help="Generate JSON only")
    parser.add_argument("--md-only", action="store_true", help="Generate Markdown only")
    args = parser.parse_args()

    queries, hunting = load_queries()
    print(f"Loaded {len(queries)} detection rules, {len(hunting)} hunting queries")

    if not args.json_only:
        md = generate_markdown(queries, hunting)
        OUTPUT_MD.write_text(md)
        print(f"  Catalog: {OUTPUT_MD}")

    if not args.md_only:
        catalog = generate_json_catalog(queries, hunting)
        with open(OUTPUT_JSON, "w") as f:
            json.dump(catalog, f, indent=2)
        print(f"  JSON:    {OUTPUT_JSON}")

    # Print summary
    all_techs = set()
    all_tactics = set()
    for q in queries + hunting:
        ma = q.get("mitre_attack", {})
        all_techs.update(ma.get("techniques", []))
        all_tactics.update(ma.get("tactics", []))

    print(f"\n  Rules: {len(queries)} | Hunting: {len(hunting)}")
    print(f"  MITRE: {len(all_techs)} techniques, {len(all_tactics)} tactics")
    print(f"  STIG: {len([q for q in queries if q.get('stig_ids')])} rules")


if __name__ == "__main__":
    main()
