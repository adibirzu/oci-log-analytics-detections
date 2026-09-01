#!/usr/bin/env python3
"""Generate the tenant-neutral cross-SIEM-to-Logan detection catalog."""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "config/cross_siem_detection_catalog.json"
JSON_OUTPUT = ROOT / "queries/cross_siem_detection_catalog.json"
DOC_OUTPUT = ROOT / "docs/CROSS_SIEM_DETECTION_CATALOG.md"

def load_and_validate() -> dict:
    catalog = json.loads(SOURCE.read_text())
    ids = [item["id"] for item in catalog["products"]]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate product ids")
    for family in catalog["detection_families"]:
        if not family.get("logan_queries"):
            raise ValueError(f"{family['id']} has no Logan mappings")
        for relative in family["logan_queries"]:
            path = ROOT / "queries" / relative
            if not path.is_file():
                raise FileNotFoundError(f"missing Logan query: queries/{relative}")
            payload = json.loads(path.read_text())
            if not payload.get("query") or not payload.get("title"):
                raise ValueError(f"invalid Logan query: queries/{relative}")
    return catalog

def render_markdown(catalog: dict) -> str:
    lines = ["# Cross-SIEM Detection Catalog", "", "This catalog maps familiar SIEM behavioral families to independently authored OCI Log Analytics (Logan) hunts. It does not reproduce third-party rule bodies or claim a vendor-neutral popularity ranking.", "", "## Product libraries", "", "| Product | Language | Repository/catalog | Logan integration |", "| --- | --- | --- | --- |"]
    for product in catalog["products"]:
        link = product.get("official_repository") or product["catalog_url"]
        lines.append(f"| {product['name']} | {product['query_language']} | [Official content]({link}) | {product['integration']} |")
    lines += ["", "## Detection-family mappings", ""]
    for family in catalog["detection_families"]:
        lines += [f"### {family['title']}", "", f"MITRE ATT&CK: {', '.join(family['mitre_techniques'])}", ""]
        for query_file in family["logan_queries"]:
            payload = json.loads((ROOT / "queries" / query_file).read_text())
            lines.append(f"- `{query_file}` — {payload['title']}")
        lines.append("")
    lines += ["## How to use this catalog", "", "1. Choose the behavior, not a vendor rule name.", "2. Open the mapped JSON and copy only its `query` value into Log Explorer.", "3. Select a narrow time window and confirm the required log source.", "4. Review false positives, then widen the time range or tune the threshold.", "5. Validate parser and data matches before promoting a saved search or dashboard.", "", "See [Using OCI Log Analytics Queries](LOG_ANALYTICS_QUERY_USAGE.md) for the full workflow.", ""]
    return "\n".join(lines)

def main() -> None:
    catalog = load_and_validate()
    generated = dict(catalog)
    generated["generated_at"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    JSON_OUTPUT.write_text(json.dumps(generated, indent=2) + "\n")
    DOC_OUTPUT.write_text(render_markdown(catalog))
    print(f"Generated {JSON_OUTPUT.relative_to(ROOT)} and {DOC_OUTPUT.relative_to(ROOT)}")

if __name__ == "__main__":
    main()
