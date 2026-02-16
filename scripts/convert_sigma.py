"""
Convert Sigma YAML detection rules to OCI Log Analytics Query Language (OCL) JSON.

Supports:
  - Field modifiers: |contains, |startswith, |endswith, |re (all with lists)
  - Complex conditions: sel1 and sel2, sel1 or sel2, not, parenthesized groups
  - STIG metadata extraction from tags
  - MITRE ATT&CK technique mapping
  - Integration-ready JSON output for multicloudoperations

Usage:
  python3 scripts/convert_sigma.py                # Convert all rules
  python3 scripts/convert_sigma.py --validate     # Validate generated queries
  python3 scripts/convert_sigma.py --stats        # Print rule statistics
"""

import yaml
import os
import json
import re
import sys

CONFIG_PATH = 'config/sigma_oci_mapping.yaml'
RULES_DIR = 'rules'
OUTPUT_DIR = 'queries'

# ─── STIG severity mapping ──────────────────────────────────────

LEVEL_TO_STIG_CAT = {
    'critical': 'CAT I',
    'high': 'CAT I',
    'medium': 'CAT II',
    'low': 'CAT III',
    'informational': 'CAT III',
}


def load_config():
    if not os.path.exists(CONFIG_PATH):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        config_path = os.path.join(base_dir, CONFIG_PATH)
        if not os.path.exists(config_path):
            return {}, {}
    else:
        config_path = CONFIG_PATH

    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    return config.get('field_mappings', {}), config.get('logsource_mappings', {})


def _strip_outer_single_quotes(value):
    """Normalize config values that may already include surrounding single quotes."""
    if isinstance(value, str) and len(value) >= 2 and value[0] == "'" and value[-1] == "'":
        return value[1:-1]
    return value


def normalize_log_source_candidates(raw_value):
    """Convert a mapping value to an ordered list of log source display names."""
    if raw_value is None:
        return []

    if isinstance(raw_value, list):
        items = raw_value
    else:
        items = [raw_value]

    candidates = []
    for item in items:
        if not isinstance(item, str):
            continue
        normalized = _strip_outer_single_quotes(item.strip())
        if normalized and normalized not in candidates:
            candidates.append(normalized)
    return candidates


def build_log_source_filter(candidates):
    """Build an OCL filter for one or more candidate log sources."""
    if not candidates:
        return "'Log Source' = 'OCI Audit Logs'"
    if len(candidates) == 1:
        return f"'Log Source' = '{candidates[0]}'"
    parts = [f"'Log Source' = '{src}'" for src in candidates]
    return f"({' or '.join(parts)})"


def map_field(field_name, field_map):
    return field_map.get(field_name, field_name)


def parse_selection(selection, field_map):
    """Parse a single Sigma selection block into an OCL query fragment."""
    query_parts = []

    # Selection can be a list of maps (OR of ANDs)
    if isinstance(selection, list):
        list_parts = []
        for item in selection:
            list_parts.append(f"({parse_selection(item, field_map)})")
        return f"({' or '.join(list_parts)})"

    for key, value in selection.items():
        # Handle field modifiers (e.g., field|contains, field|endswith)
        modifier = None
        key_base = key
        if '|' in key:
            key_base, modifier = key.split('|', 1)

        oci_field = map_field(key_base, field_map)

        if modifier == 'contains':
            if isinstance(value, list):
                or_parts = [f"{oci_field} like '*{v}*'" for v in value]
                query_parts.append(f"({' or '.join(or_parts)})")
            else:
                query_parts.append(f"{oci_field} like '*{value}*'")
        elif modifier == 'startswith':
            if isinstance(value, list):
                or_parts = [f"{oci_field} like '{v}*'" for v in value]
                query_parts.append(f"({' or '.join(or_parts)})")
            else:
                query_parts.append(f"{oci_field} like '{value}*'")
        elif modifier == 'endswith':
            if isinstance(value, list):
                or_parts = [f"{oci_field} like '*{v}'" for v in value]
                query_parts.append(f"({' or '.join(or_parts)})")
            else:
                query_parts.append(f"{oci_field} like '*{value}'")
        elif modifier == 're':
            if isinstance(value, list):
                or_parts = [f"{oci_field} REGEX MATCH '{v}'" for v in value]
                query_parts.append(f"({' or '.join(or_parts)})")
            else:
                query_parts.append(f"{oci_field} REGEX MATCH '{value}'")
        else:
            if isinstance(value, str):
                query_parts.append(f"{oci_field} = '{value}'")
            elif isinstance(value, (int, float)):
                query_parts.append(f"{oci_field} = {value}")
            elif isinstance(value, list):
                or_parts = []
                for v in value:
                    if isinstance(v, str):
                        or_parts.append(f"{oci_field} = '{v}'")
                    else:
                        or_parts.append(f"{oci_field} = {v}")
                query_parts.append(f"({' or '.join(or_parts)})")
            elif value is None:
                query_parts.append(f"{oci_field} is null")

    return " and ".join(query_parts)


def parse_condition(condition_str, detection, field_map):
    """Parse a Sigma condition string, replacing selection references with OCL.

    Handles patterns like:
      - selection
      - sel1 or sel2
      - sel1 and sel2
      - sel_target and sel_path
      - (sel1 or sel2) and sel3
      - not sel1
    """
    if not isinstance(condition_str, str):
        return ""

    # Tokenize: split on whitespace but preserve parentheses
    tokens = re.findall(r'\(|\)|[^\s()]+', condition_str)

    result_parts = []
    for token in tokens:
        lower = token.lower()
        if lower in ('and', 'or', 'not'):
            result_parts.append(lower)
        elif token in ('(', ')'):
            result_parts.append(token)
        elif token in detection and token != 'condition':
            result_parts.append(f"({parse_selection(detection[token], field_map)})")
        else:
            # Try as a selection name (may have been lowered)
            result_parts.append(token)

    return " ".join(result_parts)


def extract_stig_tags(tags):
    """Extract STIG IDs, MITRE techniques, and compliance frameworks from tags."""
    stig_ids = []
    mitre_techniques = []
    mitre_tactics = []
    compliance = []

    for tag in (tags or []):
        if tag.startswith('stig.'):
            stig_ids.append(tag[5:])
        elif tag.startswith('compliance.'):
            compliance.append(tag[11:])
        elif tag.startswith('attack.t') and tag[8:9].isdigit():
            mitre_techniques.append(tag[7:].upper())
        elif tag.startswith('attack.'):
            mitre_tactics.append(tag[7:])

    return {
        'stig_ids': stig_ids,
        'mitre_techniques': mitre_techniques,
        'mitre_tactics': mitre_tactics,
        'compliance_frameworks': compliance,
    }


def convert_rule(rule_path, field_map, logsource_map):
    try:
        with open(rule_path, 'r') as f:
            rule = yaml.safe_load(f)
    except Exception as e:
        print(f"Error loading {rule_path}: {e}")
        return None

    if not rule or 'detection' not in rule:
        return None

    title = rule.get('title', 'Untitled')
    logsource = rule.get('logsource', {})
    product = logsource.get('product', '')
    service = logsource.get('service', '')
    category = logsource.get('category', '')

    raw_source_mapping = (
        logsource_map.get(f"{product}_{service}")
        or logsource_map.get(category)
        or logsource_map.get(product)
    )
    source_candidates = normalize_log_source_candidates(raw_source_mapping)
    if not source_candidates:
        source_candidates = ["OCI Audit Logs"]
    source_filter = build_log_source_filter(source_candidates)

    detection = rule.get('detection', {})
    condition = detection.get('condition', '')

    # Parse condition using the improved tokenizer
    query_body = parse_condition(condition, detection, field_map)

    full_query = source_filter
    if query_body:
        # If query_body is just a selection name that didn't get replaced
        if query_body in detection:
            query_body = parse_selection(detection[query_body], field_map)
        full_query += f" and ({query_body})"

    # Extract STIG and MITRE metadata
    tags = rule.get('tags', [])
    level = rule.get('level', 'medium')
    metadata = extract_stig_tags(tags)

    result = {
        "title": title,
        "description": rule.get('description', ''),
        "query": full_query,
        "sigma_id": rule.get('id', ''),
        "level": level,
        "stig_category": LEVEL_TO_STIG_CAT.get(level, 'CAT II'),
        "tags": tags,
        "mitre_attack": {
            "tactics": metadata['mitre_tactics'],
            "techniques": metadata['mitre_techniques'],
        },
        "logsource": {
            "product": product,
            "service": service,
            "candidates": source_candidates,
        },
    }

    # Add STIG/compliance fields only if present
    if metadata['stig_ids']:
        result['stig_ids'] = metadata['stig_ids']
    if metadata['compliance_frameworks']:
        result['compliance_frameworks'] = metadata['compliance_frameworks']
    if rule.get('falsepositives'):
        result['falsepositives'] = rule['falsepositives']

    return result


def print_stats(output_path):
    """Print statistics about generated queries."""
    queries = []
    for f in os.listdir(output_path):
        if f.endswith('.json'):
            with open(os.path.join(output_path, f)) as fh:
                queries.append(json.load(fh))

    print(f"\n{'=' * 60}")
    print(f"Detection Rule Statistics")
    print(f"{'=' * 60}")
    print(f"  Total rules: {len(queries)}")

    # By logsource
    sources = {}
    for q in queries:
        src = q.get('logsource', {}).get('product', 'unknown')
        sources[src] = sources.get(src, 0) + 1
    print(f"\n  By platform:")
    for src, count in sorted(sources.items(), key=lambda x: -x[1]):
        print(f"    {src:20s} {count}")

    # By severity
    levels = {}
    for q in queries:
        lvl = q.get('level', 'unknown')
        levels[lvl] = levels.get(lvl, 0) + 1
    print(f"\n  By severity:")
    for lvl in ['critical', 'high', 'medium', 'low', 'informational']:
        if lvl in levels:
            stig = LEVEL_TO_STIG_CAT.get(lvl, '')
            print(f"    {lvl:15s} ({stig:6s}) {levels[lvl]}")

    # STIG coverage
    stig_rules = [q for q in queries if q.get('stig_ids')]
    print(f"\n  STIG-tagged rules: {len(stig_rules)}")

    # MITRE coverage
    techniques = set()
    tactics = set()
    for q in queries:
        ma = q.get('mitre_attack', {})
        techniques.update(ma.get('techniques', []))
        tactics.update(ma.get('tactics', []))
    print(f"  MITRE ATT&CK techniques: {len(techniques)}")
    print(f"  MITRE ATT&CK tactics: {len(tactics)}")
    for t in sorted(tactics):
        print(f"    - {t}")


def validate_queries(output_path):
    """Validate OCL syntax of generated queries."""
    errors = 0
    for f in sorted(os.listdir(output_path)):
        if not f.endswith('.json'):
            continue
        if f in ('manifest.json', 'catalog.json'):
            continue
        with open(os.path.join(output_path, f)) as fh:
            q = json.load(fh)
        query = q.get('query', '')
        # Basic syntax checks
        issues = []
        if not re.match(r"^\(?\s*'Log Source'\s*=", query):
            issues.append("missing Log Source prefix")
        # Count parentheses outside of quoted strings
        in_quote = False
        paren_depth = 0
        for ch in query:
            if ch == "'" and not in_quote:
                in_quote = True
            elif ch == "'" and in_quote:
                in_quote = False
            elif not in_quote and ch == '(':
                paren_depth += 1
            elif not in_quote and ch == ')':
                paren_depth -= 1
        if paren_depth != 0:
            issues.append("unbalanced parentheses")
        if "  " in query:
            issues.append("double spaces")
        if issues:
            print(f"  WARN {f}: {', '.join(issues)}")
            errors += 1
    total = len([
        f for f in os.listdir(output_path)
        if f.endswith('.json') and f not in ('manifest.json', 'catalog.json')
    ])
    print(f"\n  Validated {total} queries, {errors} warnings")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Convert Sigma rules to OCI Log Analytics queries")
    parser.add_argument('--validate', action='store_true', help='Validate generated OCL syntax')
    parser.add_argument('--stats', action='store_true', help='Print rule statistics')
    args = parser.parse_args()

    field_map, logsource_map = load_config()

    # Determine base directory
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    output_path = os.path.join(base_dir, OUTPUT_DIR)
    rules_path = os.path.join(base_dir, RULES_DIR)

    if not os.path.exists(output_path):
        os.makedirs(output_path)

    count = 0
    for root, dirs, files in os.walk(rules_path):
        for file in sorted(files):
            if file.endswith('.yaml') or file.endswith('.yml'):
                rule_path = os.path.join(root, file)
                print(f"Processing {rule_path}...")

                result = convert_rule(rule_path, field_map, logsource_map)

                if result:
                    safe_title = result['title'].replace(' ', '_').replace(':', '').lower()
                    # Remove characters that are problematic in filenames
                    safe_title = re.sub(r'[^a-z0-9_\-]', '', safe_title)
                    out_filename = f"{safe_title}.json"
                    out_full_path = os.path.join(output_path, out_filename)

                    with open(out_full_path, 'w') as f:
                        json.dump(result, f, indent=2)
                    print(f"Generated {out_full_path}")
                    count += 1

    print(f"\nConverted {count} rules")

    if args.validate:
        print("\nValidating queries...")
        validate_queries(output_path)

    if args.stats:
        print_stats(output_path)


if __name__ == "__main__":
    main()
