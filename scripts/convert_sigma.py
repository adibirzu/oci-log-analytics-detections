"""
Convert Sigma YAML detection rules to OCI Log Analytics Query Language (OCL) JSON.

Supports:
  - Field modifiers: |contains, |startswith, |endswith, |re, |contains|all
  - Wildcard selection references: ``1 of selection*``, ``all of filter*``
  - Complex conditions: sel1 and sel2, sel1 or sel2, not, parenthesized groups
  - Graceful degradation for count()/timeframe conditions
  - Stable output filenames via existing ``sigma_id`` reuse
  - Routing browser APM rules into ``queries/apps/``
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
import fnmatch
from pathlib import Path

CONFIG_PATH = 'config/sigma_oci_mapping.yaml'
RULES_DIR = 'rules'
OUTPUT_DIR = 'queries'
EXCLUDED_QUERY_FILENAMES = {'manifest.json', 'catalog.json'}
NON_PRESERVED_GENERATED_FIELDS = {'logsource_fallback', 'requires_aggregation'}

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


def _escape_like_value(value):
    """Escape backslashes in LIKE pattern values for OCL.

    OCL interprets \\r, \\n, \\t etc. as escape sequences inside LIKE strings.
    Double the backslashes so they are treated as literal characters.
    """
    if isinstance(value, str):
        return value.replace('\\', '\\\\')
    return value


def slugify_title(title):
    """Create a filesystem-safe JSON filename stem from a rule title."""
    safe_title = title.replace(' ', '_').replace(':', '').lower()
    return re.sub(r'[^a-z0-9_\-]', '', safe_title)


def iter_query_files(output_root):
    """Yield all query JSON files beneath the output root, excluding catalogs."""
    for path in sorted(Path(output_root).rglob('*.json')):
        if path.name in EXCLUDED_QUERY_FILENAMES:
            continue
        yield path


def load_existing_query_index(output_root):
    """Index existing generated queries by sigma_id for stable path reuse."""
    index = {}
    for path in iter_query_files(output_root):
        try:
            with open(path) as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        sigma_id = data.get('sigma_id')
        if sigma_id and sigma_id not in index:
            index[sigma_id] = path.relative_to(output_root).as_posix()
    return index


def resolve_output_relative_path(rule_path, result, output_root, rules_root=None, existing_index=None):
    """Resolve the generated output path for a rule relative to the output root.

    Rules under ``rules/web/browser_attacks`` are routed to ``queries/apps``.
    All other rules reuse an existing path when the same ``sigma_id`` is already
    present on disk; otherwise they fall back to a title-derived filename.
    """
    rule_path = Path(rule_path)
    if rules_root is None:
        base_dir = Path(__file__).resolve().parent.parent
        rules_root = base_dir / RULES_DIR
    else:
        rules_root = Path(rules_root)
    rel_rule = rule_path.relative_to(rules_root)

    if len(rel_rule.parts) >= 2 and rel_rule.parts[0] == 'web' and rel_rule.parts[1] == 'browser_attacks':
        return f"apps/{rel_rule.stem}.json"

    sigma_id = result.get('sigma_id')
    if sigma_id and existing_index and sigma_id in existing_index:
        return existing_index[sigma_id]

    return f"{slugify_title(result['title'])}.json"


def _merge_unique(primary, secondary):
    """Return a de-duplicated list preserving the order of both inputs."""
    merged = []
    seen = set()
    for items in (primary or [], secondary or []):
        for item in items:
            if item in seen:
                continue
            merged.append(item)
            seen.add(item)
    return merged


def merge_preserved_fields(result, existing):
    """Preserve curated JSON metadata from an existing generated query file."""
    existing_query = existing.get('query', '')
    if '|' not in result.get('query', '') and '|' in existing_query:
        pipe_idx = existing_query.index('|')
        result['query'] = result['query'] + ' ' + existing_query[pipe_idx:].strip()

    if existing.get('atomic_red_team'):
        result['atomic_red_team'] = existing['atomic_red_team']

    if existing.get('tags'):
        result['tags'] = _merge_unique(result.get('tags', []), existing.get('tags', []))

    if existing.get('falsepositives') and not result.get('falsepositives'):
        result['falsepositives'] = existing['falsepositives']

    existing_mitre = existing.get('mitre_attack', {})
    if existing_mitre:
        result_mitre = result.setdefault('mitre_attack', {"tactics": [], "techniques": []})
        result_mitre['tactics'] = _merge_unique(
            result_mitre.get('tactics', []),
            existing_mitre.get('tactics', []),
        )
        result_mitre['techniques'] = _merge_unique(
            result_mitre.get('techniques', []),
            existing_mitre.get('techniques', []),
        )

    for key, value in existing.items():
        if key in result:
            continue
        if key in {
            'title',
            'description',
            'query',
            'sigma_id',
            'level',
            'logsource',
            'mitre_attack',
            *NON_PRESERVED_GENERATED_FIELDS,
        }:
            continue
        result[key] = value

    return result


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
        # Handle field modifiers (e.g., field|contains, field|endswith, field|contains|all)
        modifier = None
        key_base = key
        if '|' in key:
            parts = key.split('|')
            key_base = parts[0]
            modifier = '|'.join(parts[1:])

        oci_field = map_field(key_base, field_map)

        if modifier == 'contains|all':
            # AND together all values — field must contain every value
            if isinstance(value, list):
                and_parts = [f"{oci_field} like '*{_escape_like_value(v)}*'" for v in value]
                query_parts.append(f"({' and '.join(and_parts)})")
            else:
                query_parts.append(f"{oci_field} like '*{_escape_like_value(value)}*'")
        elif modifier == 'contains':
            if isinstance(value, list):
                or_parts = [f"{oci_field} like '*{_escape_like_value(v)}*'" for v in value]
                query_parts.append(f"({' or '.join(or_parts)})")
            else:
                query_parts.append(f"{oci_field} like '*{_escape_like_value(value)}*'")
        elif modifier == 'startswith':
            if isinstance(value, list):
                or_parts = [f"{oci_field} like '{_escape_like_value(v)}*'" for v in value]
                query_parts.append(f"({' or '.join(or_parts)})")
            else:
                query_parts.append(f"{oci_field} like '{_escape_like_value(value)}*'")
        elif modifier == 'endswith':
            if isinstance(value, list):
                or_parts = [f"{oci_field} like '*{_escape_like_value(v)}'" for v in value]
                query_parts.append(f"({' or '.join(or_parts)})")
            else:
                query_parts.append(f"{oci_field} like '*{_escape_like_value(value)}'")
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
                query_parts.append(f"not ({oci_field} like '*')")

    return " and ".join(query_parts)


def _expand_wildcard_selections(condition_str, detection):
    """Expand ``1 of sel*`` / ``all of filter*`` wildcards in condition strings.

    Returns the condition string with wildcard patterns replaced by explicit
    boolean combinations of matching detection keys.
    """
    detection_keys = [k for k in detection if k != 'condition']
    wildcard_re = re.compile(r'\b(1|all|\d+)\s+of\s+(\w+\*)')

    def _replace(m):
        quantifier = m.group(1)
        pattern = m.group(2)
        matching = [k for k in detection_keys if fnmatch.fnmatch(k, pattern)]
        if not matching:
            return m.group(0)  # leave as-is if nothing matches
        if quantifier == 'all':
            return '(' + ' and '.join(matching) + ')'
        else:
            # "1 of" or any numeric quantifier → OR (true if any match)
            return '(' + ' or '.join(matching) + ')'

    return wildcard_re.sub(_replace, condition_str)


def parse_condition(condition_str, detection, field_map):
    """Parse a Sigma condition string, replacing selection references with OCL.

    Handles patterns like:
      - selection
      - sel1 or sel2
      - sel1 and sel2
      - sel_target and sel_path
      - (sel1 or sel2) and sel3
      - not sel1
      - 1 of selection*
      - all of filter*
    """
    if not isinstance(condition_str, str):
        return ""

    # Expand wildcard selection references before tokenizing
    condition_str = _expand_wildcard_selections(condition_str, detection)

    # Tokenize: split on whitespace but preserve parentheses
    tokens = re.findall(r'\(|\)|[^\s()]+', condition_str)

    result_parts = []
    i = 0
    while i < len(tokens):
        token = tokens[i]
        lower = token.lower()
        if lower in ('and', 'or', 'not'):
            result_parts.append(lower)
        elif token in ('(', ')'):
            result_parts.append(token)
        elif token in detection and token != 'condition':
            result_parts.append(f"({parse_selection(detection[token], field_map)})")
        else:
            # Skip leftover quantifier keywords from unexpanded patterns
            if lower in ('1', 'all', 'of') or (lower.isdigit()):
                i += 1
                continue
            result_parts.append(token)
        i += 1

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
        logsource_map.get(f"{product}_{category}")
        or logsource_map.get(f"{product}_{service}")
        or logsource_map.get(category)
        or logsource_map.get(product)
    )
    source_candidates = normalize_log_source_candidates(raw_source_mapping)
    logsource_fallback = False
    if not source_candidates:
        source_candidates = ["OCI Audit Logs"]
        logsource_key = f"{product}_{service}" if service else (f"{product}_{category}" if category else product)
        if logsource_key and logsource_key != '_':
            print(f"WARN: No logsource mapping for '{logsource_key}' in {rule_path}, "
                  f"falling back to OCI Audit Logs", file=sys.stderr)
        logsource_fallback = True
    source_filter = build_log_source_filter(source_candidates)

    detection = rule.get('detection', {})
    condition = detection.get('condition', '')

    # Detect aggregation conditions (count(), timeframe)
    requires_aggregation = False
    if 'count(' in str(condition) or rule.get('detection', {}).get('timeframe'):
        requires_aggregation = True
        # Strip aggregation parts — emit only the base filter query
        condition = re.sub(r'\|\s*count\([^)]*\)\s*(by\s+\w+)?\s*(>|<|>=|<=|==|!=)\s*\d+', '', str(condition)).strip()
        if not condition:
            condition = 'selection'

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
    if logsource_fallback:
        result['logsource_fallback'] = True
    if requires_aggregation:
        result['requires_aggregation'] = True

    return result


def print_stats(output_path):
    """Print statistics about generated queries."""
    queries = []
    for path in iter_query_files(output_path):
        with open(path) as fh:
            data = json.load(fh)
        if not data.get('sigma_id'):
            continue
        queries.append(data)

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
    total = 0
    for path in iter_query_files(output_path):
        with open(path) as fh:
            q = json.load(fh)
        query = q.get('query', '')
        total += 1
        # Basic syntax checks
        issues = []
        if not re.match(r"^\(?\s*'Log Source'\s*(=|in)\s*", query):
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
            rel_path = path.relative_to(output_path).as_posix()
            print(f"  WARN {rel_path}: {', '.join(issues)}")
            errors += 1
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

    existing_index = load_existing_query_index(output_path)
    count = 0
    for root, dirs, files in os.walk(rules_path):
        for file in sorted(files):
            if file.endswith('.yaml') or file.endswith('.yml'):
                rule_path = os.path.join(root, file)
                print(f"Processing {rule_path}...")

                result = convert_rule(rule_path, field_map, logsource_map)

                if result:
                    out_rel_path = resolve_output_relative_path(
                        rule_path=rule_path,
                        result=result,
                        output_root=output_path,
                        rules_root=rules_path,
                        existing_index=existing_index,
                    )
                    out_full_path = os.path.join(output_path, out_rel_path)
                    os.makedirs(os.path.dirname(out_full_path), exist_ok=True)

                    # Preserve hand-edited fields from existing file
                    if os.path.exists(out_full_path):
                        try:
                            with open(out_full_path) as ef:
                                existing = json.load(ef)
                            result = merge_preserved_fields(result, existing)
                        except (json.JSONDecodeError, KeyError):
                            pass

                    with open(out_full_path, 'w') as f:
                        json.dump(result, f, indent=2)
                    print(f"Generated {out_full_path}")
                    if result.get('sigma_id'):
                        existing_index[result['sigma_id']] = out_rel_path
                    count += 1

    print(f"\nConverted {count} rules")

    if args.validate:
        print("\nValidating queries...")
        validate_queries(output_path)

    if args.stats:
        print_stats(output_path)


if __name__ == "__main__":
    main()
