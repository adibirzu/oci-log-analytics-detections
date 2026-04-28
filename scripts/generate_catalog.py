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
from datetime import datetime, timezone
from pathlib import Path

PROJECT_DIR = Path(__file__).parent.parent
QUERIES_DIR = PROJECT_DIR / "queries"
APPS_DIR = QUERIES_DIR / "apps"
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


def _load_query_files(directory, relative_prefix="", extra_flags=None):
    """Load query JSON files from a directory and annotate them with metadata."""
    extra_flags = extra_flags or {}
    queries = []
    if not directory.exists():
        return queries

    for f in sorted(directory.glob("*.json")):
        if f.name in ("manifest.json", "catalog.json"):
            continue
        with open(f) as fh:
            data = json.load(fh)
        data["_file"] = f"{relative_prefix}{f.name}"
        data.update(extra_flags)
        queries.append(data)
    return queries


def load_query_surfaces(queries_dir=QUERIES_DIR, apps_dir=APPS_DIR, hunting_dir=HUNTING_DIR):
    """Load detection, app/APM, and hunting query surfaces."""
    detections = _load_query_files(queries_dir)
    app_queries = _load_query_files(apps_dir, relative_prefix="apps/", extra_flags={"_is_app": True})
    hunting = _load_query_files(hunting_dir, relative_prefix="hunting/", extra_flags={"_is_hunting": True})
    return detections, app_queries, hunting


def get_inventory_counts(project_dir=PROJECT_DIR, queries_dir=QUERIES_DIR, apps_dir=APPS_DIR, hunting_dir=HUNTING_DIR):
    """Get authoritative on-disk inventory counts for source rules and query outputs."""
    rule_counts = defaultdict(int)
    for path in (project_dir / "rules").rglob("*"):
        if path.suffix not in (".yml", ".yaml"):
            continue
        rel = path.relative_to(project_dir / "rules")
        top = rel.parts[0]
        rule_counts[top] += 1

    apps_count = len(list(apps_dir.glob("*.json"))) if apps_dir.exists() else 0
    hunting_count = len(list(hunting_dir.glob("*.json"))) if hunting_dir.exists() else 0

    return {
        "source_yaml_rules": sum(rule_counts.values()),
        "source_rule_breakdown": dict(sorted(rule_counts.items())),
        "generated_app_queries": apps_count,
        "generated_hunting_queries": hunting_count,
        "legacy_dirs": {
            "logandetectionqueries": len(list((project_dir / "logandetectionqueries").iterdir())) if (project_dir / "logandetectionqueries").exists() else None,
            "logandetectionrules": len(list((project_dir / "logandetectionrules").iterdir())) if (project_dir / "logandetectionrules").exists() else None,
        },
    }


def build_mitre_matrix(*query_groups):
    """Build MITRE ATT&CK tactic-to-technique mapping."""
    matrix = defaultdict(lambda: defaultdict(list))
    for query_group in query_groups:
        for q in query_group:
            ma = q.get("mitre_attack", {})
            techniques = ma.get("techniques", [])
            tactics = ma.get("tactics", [])
            for tactic in tactics:
                for tech in techniques:
                    matrix[tactic][tech].append(q["title"])
    return matrix


def generate_markdown(queries, app_queries, hunting, inventory=None):
    """Generate the CATALOG.md file."""
    lines = []
    w = lines.append
    inventory = inventory or get_inventory_counts()
    source_derived_app_queries = [q for q in app_queries if q.get("sigma_id")]
    curated_app_queries = [q for q in app_queries if not q.get("sigma_id")]

    w("# Detection Rule Catalog")
    w("")
    w(
        f"> **{len(queries)} base detection queries** + **{len(app_queries)} app/APM queries** "
        f"+ **{len(hunting)} hunting queries**"
    )
    w("")

    # --- Summary stats ---
    w("## Summary")
    w("")

    w("| Content Surface | Count | Notes |")
    w("|-----------------|-------|-------|")
    w(f"| Base detection queries | {len(queries)} | Sigma-derived detections in `queries/` |")
    w(
        f"| App/APM queries | {len(app_queries)} | "
        f"{len(source_derived_app_queries)} Sigma-derived browser detections + "
        f"{len(curated_app_queries)} curated analytics in `queries/apps/` |"
    )
    w(f"| Hunting queries | {len(hunting)} | Curated analytics and correlation content in `queries/hunting/` |")
    w("")

    source_breakdown = inventory["source_rule_breakdown"]
    w(
        f"**Source YAML rules:** {inventory['source_yaml_rules']} total "
        f"(cloud: {source_breakdown.get('cloud', 0)}, linux: {source_breakdown.get('linux', 0)}, "
        f"web: {source_breakdown.get('web', 0)}, windows: {source_breakdown.get('windows', 0)})"
    )
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
    stig_rules = [q for q in queries + source_derived_app_queries if q.get("stig_ids")]
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
    matrix = build_mitre_matrix(queries, app_queries, hunting)

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
    if app_queries:
        w("## App / APM Queries")
        w("")
        w("| # | Title | Type | Severity | MITRE |")
        w("|---|-------|------|----------|-------|")
        for i, q in enumerate(app_queries, 1):
            kind = "Source-derived browser detection" if q.get("sigma_id") else "Curated application analytics"
            level = q.get("level", "medium")
            emoji = SEVERITY_EMOJI.get(level, "")
            techniques = ", ".join(q.get("mitre_attack", {}).get("techniques", [])) or "-"
            w(f"| {i} | {q['title']} | {kind} | {emoji} {level} | {techniques} |")
        w("")

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
    w(
        f"*Generated from {inventory['source_yaml_rules']} Sigma source rules routed to "
        f"{len(queries)} top-level detection queries and {len(source_derived_app_queries)} browser app queries, "
        f"plus {len(curated_app_queries)} curated app/APM analytics and {len(hunting)} hunting queries*"
    )

    return "\n".join(lines)


def generate_json_catalog(queries, app_queries, hunting, inventory=None):
    """Generate machine-readable catalog."""
    inventory = inventory or get_inventory_counts()
    source_derived_app_queries = [q for q in app_queries if q.get("sigma_id")]
    curated_app_queries = [q for q in app_queries if not q.get("sigma_id")]
    total_content_items = len(queries) + len(app_queries) + len(hunting)
    catalog = {
        "version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_rules": len(queries),
        "total_app_queries": len(app_queries),
        "total_hunting": len(hunting),
        "total_content_items": total_content_items,
        "inventory": {
            "source_yaml_rules": inventory["source_yaml_rules"],
            "source_rule_breakdown": inventory["source_rule_breakdown"],
            "generated_detection_queries": len(queries),
            "generated_app_queries": inventory["generated_app_queries"],
            "source_derived_app_queries": len(source_derived_app_queries),
            "curated_app_queries": len(curated_app_queries),
            "generated_hunting_queries": len(hunting),
            "generated_sigma_queries": len(queries) + len(source_derived_app_queries),
            "total_query_artifacts": total_content_items,
            "legacy_dirs": inventory["legacy_dirs"],
        },
        "platforms": {},
        "severities": {},
        "mitre_techniques": [],
        "mitre_tactics": [],
        "all_mitre_techniques": [],
        "all_mitre_tactics": [],
        "stig_controls": [],
        "rules": [],
        "app_queries": [],
        "hunting_queries": [],
    }

    platforms = defaultdict(int)
    severities = defaultdict(int)
    techniques = set()
    tactics = set()
    stig_controls = set()
    combined_techniques = set()
    combined_tactics = set()

    for q in queries:
        p = q.get("logsource", {}).get("product", "unknown")
        platforms[p] += 1
        severities[q.get("level", "unknown")] += 1
        ma = q.get("mitre_attack", {})
        techniques.update(ma.get("techniques", []))
        tactics.update(ma.get("tactics", []))
        combined_techniques.update(ma.get("techniques", []))
        combined_tactics.update(ma.get("tactics", []))
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
        combined_techniques.update(q.get("mitre_attack", {}).get("techniques", []))
        combined_tactics.update(q.get("mitre_attack", {}).get("tactics", []))
        catalog["hunting_queries"].append({
            "title": q["title"],
            "description": q.get("description", ""),
            "level": q.get("level", "medium"),
            "hunting_type": q.get("hunting_type", ""),
            "cookbook_method": q.get("cookbook_method", ""),
            "mitre_techniques": q.get("mitre_attack", {}).get("techniques", []),
            "file": q.get("_file", ""),
        })

    for q in app_queries:
        combined_techniques.update(q.get("mitre_attack", {}).get("techniques", []))
        combined_tactics.update(q.get("mitre_attack", {}).get("tactics", []))
        catalog["app_queries"].append({
            "title": q["title"],
            "description": q.get("description", ""),
            "level": q.get("level", "medium"),
            "sigma_id": q.get("sigma_id", ""),
            "source_derived": bool(q.get("sigma_id")),
            "mitre_techniques": q.get("mitre_attack", {}).get("techniques", []),
            "mitre_tactics": q.get("mitre_attack", {}).get("tactics", []),
            "file": q.get("_file", ""),
        })

    catalog["platforms"] = dict(platforms)
    catalog["severities"] = dict(severities)
    catalog["mitre_techniques"] = sorted(techniques)
    catalog["mitre_tactics"] = sorted(tactics)
    catalog["all_mitre_techniques"] = sorted(combined_techniques)
    catalog["all_mitre_tactics"] = sorted(combined_tactics)
    catalog["stig_controls"] = sorted(stig_controls)
    catalog["inventory"]["combined_mitre_techniques"] = len(combined_techniques)
    catalog["inventory"]["combined_mitre_tactics"] = len(combined_tactics)

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

    queries, app_queries, hunting = load_query_surfaces()
    print(
        f"Loaded {len(queries)} detection queries, {len(app_queries)} app/APM queries, "
        f"{len(hunting)} hunting queries"
    )

    if not args.json_only:
        md = generate_markdown(queries, app_queries, hunting)
        OUTPUT_MD.write_text(md)
        print(f"  Catalog: {OUTPUT_MD}")

    if not args.md_only:
        catalog = generate_json_catalog(queries, app_queries, hunting)
        with open(OUTPUT_JSON, "w") as f:
            json.dump(catalog, f, indent=2)
        print(f"  JSON:    {OUTPUT_JSON}")

    # Print summary
    all_techs = set()
    all_tactics = set()
    for q in queries + app_queries + hunting:
        ma = q.get("mitre_attack", {})
        all_techs.update(ma.get("techniques", []))
        all_tactics.update(ma.get("tactics", []))

    print(f"\n  Rules: {len(queries)} | Apps: {len(app_queries)} | Hunting: {len(hunting)}")
    print(f"  MITRE: {len(all_techs)} techniques, {len(all_tactics)} tactics")
    print(f"  STIG: {len([q for q in queries if q.get('stig_ids')])} rules")


if __name__ == "__main__":
    main()
