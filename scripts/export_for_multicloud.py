"""
Export detection rules for integration with the multicloudoperations project.

Generates:
  1. A shared manifest (JSON) mapping all rules with metadata
  2. Copies Sigma YAML rules to multicloudoperations/detections/sigma/oci/ format
  3. Generates OCI LA saved search definitions compatible with multicloud deploy

The multicloudoperations project at ~/dev/multicloudoperations uses:
  - detections/sigma/<platform>/ for Sigma YAML rules
  - detection_logs/ for test data (NDJSON)
  - dashboards/ for OCI LA dashboard JSON
  - pipelines/ for parser field definitions

Usage:
  python3 scripts/export_for_multicloud.py                    # Export to multicloud
  python3 scripts/export_for_multicloud.py --manifest-only    # Just generate manifest
  python3 scripts/export_for_multicloud.py --dry-run          # Print plan
  python3 scripts/export_for_multicloud.py --target /path/to  # Custom target dir
"""

import json
import os
import shutil
import sys
import yaml
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from oci_config import SOURCE_CANDIDATE_GROUPS

PROJECT_DIR = Path(__file__).parent.parent
RULES_DIR = PROJECT_DIR / 'rules'
QUERIES_DIR = PROJECT_DIR / 'queries'
TEST_DATA_DIR = PROJECT_DIR / 'test_data'
DEFAULT_TARGET = Path.home() / 'dev' / 'multicloudoperations'


def load_all_queries():
    """Load all generated query JSON files."""
    queries = {}
    for f in sorted(QUERIES_DIR.glob('*.json')):
        if f.name in ('manifest.json', 'catalog.json'):
            continue
        with open(f) as fh:
            data = json.load(fh)
            # Skip non-rule artifacts in queries/ (for example ad-hoc catalog outputs).
            if 'title' in data and 'query' in data:
                queries[f.name] = data
    return queries


def load_all_rules():
    """Load all Sigma YAML rules."""
    rules = {}
    for f in sorted(RULES_DIR.rglob('*.yaml')):
        with open(f) as fh:
            data = yaml.safe_load(fh)
            if data and 'detection' in data:
                rel_path = f.relative_to(RULES_DIR)
                rules[str(rel_path)] = data
    return rules


def generate_manifest(queries, rules):
    """Generate a comprehensive manifest for cross-project integration."""
    manifest = {
        "project": "oci-log-analytics-detections",
        "version": "2.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "stats": {
            "total_rules": len(queries),
            "total_sigma_rules": len(rules),
            "platforms": {},
            "severity": {},
            "stig_tagged": 0,
            "mitre_techniques": [],
            "mitre_tactics": [],
        },
        "rules": [],
        "dashboards": {
            "total": 7,
            "names": [
                "SOC Overview Dashboard",
                "SOC: OCI STIG Compliance Dashboard",
                "SOC: OCI Audit Security Dashboard",
                "SOC: Cloud Guard Security Dashboard",
                "SOC: Linux Security Dashboard",
                "SOC: Windows Security Dashboard",
                "SOC: Threat Hunting Dashboard",
            ],
        },
        "log_sources": {
            "oci_audit": SOURCE_CANDIDATE_GROUPS["oci_audit"],
            "cloud_guard": SOURCE_CANDIDATE_GROUPS["cloud_guard"],
            "linux_syslog": SOURCE_CANDIDATE_GROUPS["linux_syslog"],
            "windows_sysmon": SOURCE_CANDIDATE_GROUPS["windows_sysmon"],
        },
    }

    techniques = set()
    tactics = set()

    for filename, query in queries.items():
        product = query.get('logsource', {}).get('product', 'unknown')
        level = query.get('level', 'medium')

        manifest['stats']['platforms'][product] = \
            manifest['stats']['platforms'].get(product, 0) + 1
        manifest['stats']['severity'][level] = \
            manifest['stats']['severity'].get(level, 0) + 1

        if query.get('stig_ids'):
            manifest['stats']['stig_tagged'] += 1

        ma = query.get('mitre_attack', {})
        techniques.update(ma.get('techniques', []))
        tactics.update(ma.get('tactics', []))

        rule_entry = {
            "filename": filename,
            "title": query['title'],
            "sigma_id": query.get('sigma_id', ''),
            "level": level,
            "stig_category": query.get('stig_category', ''),
            "platform": product,
            "service": query.get('logsource', {}).get('service', ''),
            "mitre_techniques": ma.get('techniques', []),
            "mitre_tactics": ma.get('tactics', []),
            "query": query['query'],
        }
        if query.get('stig_ids'):
            rule_entry['stig_ids'] = query['stig_ids']
        if query.get('compliance_frameworks'):
            rule_entry['compliance_frameworks'] = query['compliance_frameworks']

        manifest['rules'].append(rule_entry)

    manifest['stats']['mitre_techniques'] = sorted(techniques)
    manifest['stats']['mitre_tactics'] = sorted(tactics)

    return manifest


def export_to_multicloud(target_dir, manifest, dry_run=False):
    """Export rules and test data to multicloudoperations project."""
    target = Path(target_dir)
    if not target.exists():
        print(f"  Target directory not found: {target}")
        print(f"  Skipping multicloud export (manifest still generated)")
        return False

    # Define export paths in the multicloud project
    detections_dir = target / 'detections' / 'sigma' / 'oci-stig'
    detection_logs_dir = target / 'detection_logs'

    if dry_run:
        print(f"\n  [DRY RUN] Would export to: {target}")
        print(f"    - Rules: {detections_dir}")
        print(f"    - Test data: {detection_logs_dir}")
        return True

    # Export OCI-specific Sigma rules
    detections_dir.mkdir(parents=True, exist_ok=True)
    oci_rules = list((RULES_DIR / 'cloud' / 'oci').glob('*.yaml'))
    for rule_file in oci_rules:
        dest = detections_dir / rule_file.name
        shutil.copy2(rule_file, dest)
    print(f"  Exported {len(oci_rules)} OCI Sigma rules to {detections_dir}")

    # Export manifest
    manifest_path = target / 'detections' / 'oci_stig_manifest.json'
    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=2)
    print(f"  Exported manifest to {manifest_path}")

    return True


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Export detection rules for multicloudoperations integration"
    )
    parser.add_argument('--manifest-only', action='store_true',
                        help='Only generate the manifest, skip multicloud export')
    parser.add_argument('--dry-run', action='store_true',
                        help='Print plan without executing')
    parser.add_argument('--target', type=str, default=str(DEFAULT_TARGET),
                        help='Target multicloudoperations directory')
    args = parser.parse_args()

    print("=" * 60)
    print("OCI Log Analytics - Multicloud Integration Export")
    print("=" * 60)

    # Load all data
    queries = load_all_queries()
    rules = load_all_rules()
    print(f"\n  Loaded {len(queries)} queries, {len(rules)} Sigma rules")

    # Generate manifest
    manifest = generate_manifest(queries, rules)

    # Write local manifest
    local_manifest_path = PROJECT_DIR / 'queries' / 'manifest.json'
    if not args.dry_run:
        with open(local_manifest_path, 'w') as f:
            json.dump(manifest, f, indent=2)
        print(f"  Local manifest: {local_manifest_path}")
    else:
        print(f"  [DRY RUN] Would write manifest to {local_manifest_path}")

    # Print summary
    stats = manifest['stats']
    print(f"\n  Rules: {stats['total_rules']}")
    print(f"  Platforms: {json.dumps(stats['platforms'])}")
    print(f"  Severity: {json.dumps(stats['severity'])}")
    print(f"  STIG-tagged: {stats['stig_tagged']}")
    print(f"  MITRE techniques: {len(stats['mitre_techniques'])}")
    print(f"  MITRE tactics: {len(stats['mitre_tactics'])}")

    if not args.manifest_only:
        print(f"\n  Exporting to: {args.target}")
        export_to_multicloud(args.target, manifest, args.dry_run)

    print(f"\nDone.")


if __name__ == "__main__":
    main()
