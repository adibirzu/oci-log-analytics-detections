#!/usr/bin/env python3
"""Build the read-only Pages explorer from the reviewed OCI content manifest."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import shutil
import tomllib
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "webapp/pages-explorer"
VENDORS = {
    "elastic": ("elastic/detection-rules", r"rules/(?!_deprecated/)[\w./-]+\.toml"),
    "splunk": ("splunk/security_content", r"detections/(?!deprecated/)[\w./-]+\.yml"),
}
HEX_SHA = re.compile(r"[a-f0-9]{40}")
SHA256 = re.compile(r"[a-f0-9]{64}")
RULE_ID = re.compile(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}")
QUERY_PATH = re.compile(r"queries/(?:(?:apps|hunting|sentinel)/)?[^/\\]+\.json")
IP_LITERAL = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
ATTACK_TACTICS = (
    "reconnaissance", "resource_development", "initial_access", "execution",
    "persistence", "privilege_escalation", "defense_evasion", "credential_access",
    "discovery", "lateral_movement", "collection", "command_and_control", "exfiltration", "impact",
)
LOG_SOURCE_EQUALS = re.compile(r"'Log Source'\s*=\s*'([^']+)'", re.IGNORECASE)
LOG_SOURCE_IN = re.compile(r"'Log Source'\s+in\s*\(([^)]+)\)", re.IGNORECASE)
METADATA_KEYS = (
    "type", "logsource", "references", "falsepositives", "attribution", "atomic_red_team",
    "stig_category", "stig_ids", "compliance_frameworks", "atlas", "requires_aggregation",
    "detection_maturity", "field_coverage", "test_data_coverage", "live_validation_status",
    "scheduled_rule_eligibility", "source_confidence", "required_data_connectors", "sentinel_tables",
    "conversion_status", "conversion_confidence", "parser_schema_hash", "detection_rule",
    "threat_intel", "yara_source",
)


def load(path: str):
    return json.loads((ROOT / path).read_bytes())


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sensitive_literal(data: str) -> str | None:
    if re.search(r"\bocid1\.", data, re.IGNORECASE):
        return "resource identifier"
    for literal in IP_LITERAL.findall(data):
        try:
            address = ipaddress.ip_address(literal)
        except ValueError:
            continue
        if any(address in network for network in PRIVATE_NETWORKS):
            return "private IPv4 address"
    return None


def encoded_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n"


def public_json(value: object) -> str:
    data = encoded_json(value)
    if reason := sensitive_literal(data):
        raise ValueError(f"Sensitive {reason} in public Pages content")
    return data


def pages_forge_catalog() -> dict:
    # Forge uses this same public catalog in the HTML and the downloadable JSON.
    catalog = load("queries/forge_detection_catalog.json")
    items = [item for item in catalog["items"] if not sensitive_literal(encoded_json(item))]
    counts = Counter(item["surface"] for item in items)
    return {
        **catalog,
        "items": items,
        "total_items": len(items),
        "surface_counts": {surface: counts[surface] for surface in catalog["surface_counts"]},
    }


def verify_upstream(vendor: str, reference: dict, upstream_root: Path) -> None:
    repo, _ = VENDORS[vendor]
    snapshot = upstream_root / f"{repo.split('/')[1]}-{reference['revision']}"
    raw = (snapshot / reference["path"]).read_bytes()
    if vendor == "elastic":
        document = tomllib.loads(raw.decode())["rule"]
        identity = document["rule_id"], document["name"]
    else:
        # PyYAML is a repository dependency used only for this opt-in audit.
        import yaml

        document = yaml.safe_load(raw)
        identity = document["id"], document["name"]
    if sha256(raw) != reference["sha256"] or identity != (reference["id"], reference["title"]):
        raise ValueError(f"Upstream evidence mismatch for {vendor} {reference['id']}")


def upstream_catalog(config: dict, upstream_root: Path | None) -> tuple[dict, dict]:
    upstreams = {}
    for vendor, (repository, path_pattern) in VENDORS.items():
        source = config["sources"][vendor]
        revision = source["revision"]
        if not HEX_SHA.fullmatch(revision):
            raise ValueError(f"Invalid revision for {vendor}")
        rules = {}
        paths = set()
        for record in source["rules"]:
            rule_id, path = record["id"], record["path"]
            if (
                rule_id in rules or path in paths or not RULE_ID.fullmatch(rule_id)
                or not re.fullmatch(path_pattern, path) or ".." in Path(path).parts
                or "//" in path or not SHA256.fullmatch(record["sha256"])
                or not record["title"].strip()
            ):
                raise ValueError(f"Invalid source reference for {vendor} {rule_id}")
            reference = {
                **record, "revision": revision, "repository": repository,
                "url": f"https://github.com/{repository}/blob/{revision}/{path}",
            }
            if upstream_root is not None:
                verify_upstream(vendor, reference, upstream_root)
            rules[rule_id] = reference
            paths.add(path)
        upstreams[vendor] = rules

    links: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    used = set()
    for link in config["links"]:
        oci, vendor, rule_id = link["oci"], link["vendor"], link["id"]
        key = oci, vendor, rule_id
        if (
            key in used or rule_id not in upstreams.get(vendor, {})
            or link["confidence"] not in {"exact", "related"} or not link["rationale"].strip()
        ):
            raise ValueError(f"Invalid vendor mapping for {oci}")
        used.add(key)
        links[oci][vendor].append({key: link[key] for key in ("id", "confidence", "rationale")})
    if {(vendor, rule_id) for _, vendor, rule_id in used} != {
        (vendor, rule_id) for vendor, rules in upstreams.items() for rule_id in rules
    }:
        raise ValueError("Upstream source references must have an OCI mapping")
    return upstreams, links


def log_sources(query: str, source: dict) -> list[str]:
    # These are the sources named by the query when it has a literal selector.
    names = LOG_SOURCE_EQUALS.findall(query)
    for group in LOG_SOURCE_IN.findall(query):
        names.extend(re.findall(r"'([^']+)'", group))
    return sorted(set(names or source.get("candidates", []) or [source.get("service")]) - {None, ""})


def build_catalog(upstream_root: Path | None) -> dict:
    manifest = load("queries/content_manifest.json")
    families: dict[str, list[str]] = defaultdict(list)
    for family in load("config/cross_siem_detection_catalog.json")["detection_families"]:
        for path in family["logan_queries"]:
            families[f"queries/{path}"].append(family["title"])

    upstreams, links = upstream_catalog(load("config/detection_explorer_mappings.json"), upstream_root)
    rules = {}
    for entry in manifest["queries"]:
        path, surface = entry["path"], entry["surface"]
        if surface == "hunting" and path not in families:
            continue
        if path in rules or not QUERY_PATH.fullmatch(path):
            raise ValueError("Invalid or duplicate query inventory path")
        raw = (ROOT / path).read_bytes()
        if sha256(raw) != entry["sha256"]:
            raise ValueError(f"Content manifest mismatch for {path}")
        item = json.loads(raw)
        query = item["query"]
        if not isinstance(query, str) or not query.strip():
            raise ValueError(f"Missing OCL query for {path}")

        source = item.get("logsource") or {}
        sources = log_sources(query, source)
        platform = source.get("product") or "unspecified"
        attack = item.get("mitre_attack", {})
        tactics = {tactic.replace("commandand_control", "command_and_control") for tactic in attack.get("tactics", [])}
        techniques = sorted({
            technique.upper() for technique in attack.get("techniques", [])
            if re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique, re.IGNORECASE)
        })
        kind = {"base": "detection", "sentinel": "sentinel", "apps": "application", "hunting": "hunting"}[surface]
        oci_specific = platform in {"oci", "oci-log-analytics"}
        mappings = {}
        for vendor in VENDORS:
            matches = links.get(path, {}).get(vendor, [])
            confidence = {match["confidence"] for match in matches}
            status = (
                "exact" if "exact" in confidence else "related" if confidence
                else "oci-specific" if oci_specific else "unmapped"
            )
            mappings[vendor] = {"status": status, "references": matches}
        provenance = {"path": path, "sha256": entry["sha256"]}
        provenance.update({
            key: item[key]
            for key in ("source_type", "sigma_id", "sentinel_id", "sentinel_source_path", "sentinel_source_url")
            if item.get(key)
        })
        rules[path] = {
            "id": path, "kind": kind, "title": item["title"], "description": item.get("description", ""),
            "query": query, "severity": item.get("level") or "unspecified", "platform": platform, "sources": sources,
            "category": item.get("sentinel_category") or source.get("category") or kind,
            "tactics": [tactic for tactic in ATTACK_TACTICS if tactic in tactics],
            "techniques": techniques, "tags": item.get("tags", []), "families": families.get(path, []),
            "provenance": provenance, "mappings": mappings,
            "metadata": {key: item[key] for key in METADATA_KEYS if key in item},
            "splunkExample": item.get("splunk_original"),
        }

    if (families.keys() | links.keys()) - rules.keys():
        raise ValueError("Explorer mappings reference a query absent from the published inventory")
    return {
        "schemaVersion": 1,
        "contentDigest": manifest["content_digest"],
        "tactics": ATTACK_TACTICS,
        "upstreams": upstreams,
        "rules": sorted(rules.values(), key=lambda rule: (rule["title"].casefold(), rule["id"])),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="Explorer directory to populate")
    parser.add_argument("--upstream-root", type=Path, help="Audit rule metadata against unpacked pinned snapshots")
    parser.add_argument("--forge-catalog-output", type=Path, help="Stage the tenant-neutral Forge Pages catalog")
    args = parser.parse_args()
    if args.forge_catalog_output:
        forge = public_json(pages_forge_catalog())
        args.forge_catalog_output.parent.mkdir(parents=True, exist_ok=True)
        args.forge_catalog_output.write_text(forge, encoding="utf-8", newline="\n")
    document = public_json(build_catalog(args.upstream_root))
    args.output.mkdir(parents=True, exist_ok=True)
    for filename in ("index.html", "explorer.css", "explorer.js"):
        shutil.copyfile(ASSETS / filename, args.output / filename)
    (args.output / "catalog.json").write_text(document, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
