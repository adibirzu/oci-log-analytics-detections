import yaml
import os
import json

CONFIG_PATH = 'config/sigma_oci_mapping.yaml'
RULES_DIR = 'rules'
OUTPUT_DIR = 'queries'

def load_config():
    if not os.path.exists(CONFIG_PATH):
        # Try relative to script if not in root
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        config_path = os.path.join(base_dir, CONFIG_PATH)
        if not os.path.exists(config_path):
            return {}, {}
    else:
        config_path = CONFIG_PATH

    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    return config.get('field_mappings', {}), config.get('logsource_mappings', {})

def map_field(field_name, field_map):
    return field_map.get(field_name, field_name)

def parse_selection(selection, field_map):
    query_parts = []
    
    # Selection can be a list of maps or a single map
    if isinstance(selection, list):
        list_parts = []
        for item in selection:
            list_parts.append(f"({parse_selection(item, field_map)})")
        return f"({' or '.join(list_parts)})"

    for key, value in selection.items():
        # Handle field modifiers
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
            query_parts.append(f"{oci_field} like '{value}*'")
        elif modifier == 'endswith':
            query_parts.append(f"{oci_field} like '*{value}'")
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
    
    oci_source = logsource_map.get(f"{product}_{service}") or \
                 logsource_map.get(category) or \
                 logsource_map.get(product) or \
                 "'OCI Audit Logs'"

    detection = rule.get('detection', {})
    condition = detection.get('condition', '')
    
    # Simple condition parser for common Sigma patterns
    # Handles: 'selection', 'selection1 and selection2', 'not selection'
    
    query_body = ""
    if isinstance(condition, str):
        # Replace selection names with their parsed OCL equivalents
        parts = condition.split(' ')
        new_parts = []
        for p in parts:
            if p.lower() in ['and', 'or', 'not', '(', ')']:
                new_parts.append(p.lower())
            elif p in detection:
                new_parts.append(f"({parse_selection(detection[p], field_map)})")
            else:
                new_parts.append(p)
        query_body = " ".join(new_parts)
    
    full_query = f"'Log Source' = {oci_source}"
    if query_body:
        # If query_body is just a selection name that didn't get replaced
        if query_body in detection:
             query_body = parse_selection(detection[query_body], field_map)
        full_query += f" | where {query_body}"
        
    return {
        "title": title,
        "description": rule.get('description', ''),
        "query": full_query,
        "sigma_id": rule.get('id', ''),
        "tags": rule.get('tags', [])
    }

def main():
    field_map, logsource_map = load_config()
    
    # Determine base directory
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    output_path = os.path.join(base_dir, OUTPUT_DIR)
    rules_path = os.path.join(base_dir, RULES_DIR)

    if not os.path.exists(output_path):
        os.makedirs(output_path)

    for root, dirs, files in os.walk(rules_path):
        for file in files:
            if file.endswith('.yaml') or file.endswith('.yml'):
                rule_path = os.path.join(root, file)
                print(f"Processing {rule_path}...")
                
                result = convert_rule(rule_path, field_map, logsource_map)
                
                if result:
                    safe_title = result['title'].replace(' ', '_').replace(':', '').lower()
                    out_filename = f"{safe_title}.json"
                    out_full_path = os.path.join(output_path, out_filename)
                    
                    with open(out_full_path, 'w') as f:
                        json.dump(result, f, indent=2)
                    print(f"Generated {out_full_path}")

if __name__ == "__main__":
    main()