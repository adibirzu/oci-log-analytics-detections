"""Deterministic, tenant-neutral hunting content and source-specific field contracts."""
from __future__ import annotations
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from hunting_fields import extract_hunting_fields
from hunting_schema import schema_errors

VERSION = '1.0.0'
INPUTS = ('config/hunting_packs.json', 'config/hunting_reference_candidates.json',
          'config/threat_intel_sources.json', 'queries/catalog.json',
          'queries/log_source_field_dictionary.json', 'queries/dashboard_inventory.json',
          'schemas/hunting_integration_bundle.schema.json', 'scripts/hunting_bundle.py',
          'scripts/field_dictionary.py', 'scripts/hunting_fields.py', 'scripts/hunting_schema.py')
PATH_RE = re.compile(r'hunting/[a-z0-9][a-z0-9_-]*\.json\Z')

def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()

def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()

def _without_timestamps(value: object) -> object:
    if isinstance(value, dict):
        return {k: _without_timestamps(v) for k,v in value.items() if k != 'generated_at'}
    if isinstance(value, list):
        return [_without_timestamps(v) for v in value]
    return value

def input_hash(path: Path) -> str:
    if path.suffix == '.json':
        return digest(_without_timestamps(json.loads(path.read_text())))
    return hashlib.sha256(path.read_bytes()).hexdigest()

def content_digest(bundle: dict) -> str:
    return digest({k:v for k,v in bundle.items() if k not in {'generated_at','content_digest'}})

def field_contract(query: str, sources: list[str], dictionary: dict) -> dict:
    fields, syntax_reasons = extract_hunting_fields(query)
    builtins = set(dictionary.get('approved_builtins', []))
    known_sources = {s['source_display'] for s in dictionary.get('sources', [])}
    by_field = {f['display_name']: {s['source_display'] for s in f.get('sources', [])}
                for f in dictionary.get('fields', [])}
    unknown = [f for f in fields if f not in builtins and not (by_field.get(f,set()) & set(sources))]
    reasons = list(syntax_reasons)
    if not sources: reasons.append('No explicit log source could be resolved')
    missing_sources = sorted(set(sources) - known_sources)
    if missing_sources: reasons.append('Unresolved source associations: '+', '.join(missing_sources))
    if unknown: reasons.append('Fields lack source-specific mappings: '+', '.join(unknown))
    return {'status': 'blocked' if reasons else 'ready', 'required_fields':fields,
            'unmapped_fields':unknown, 'reasons':reasons}

def _sources(query: str, payload: dict, dictionary: dict) -> list[str]:
    # Resolve literal source selectors first; do not replace a requested source with
    # a same-family custom parser merely because that parser has more fields.
    explicit = re.findall(r"'Log Source'\s*=\s*'([^']+)'", query, re.I)
    for match in re.finditer(r"'Log Source'\s+in\s*\(([^)]+)\)", query, re.I):
        explicit.extend(re.findall(r"'([^']+)'", match[1]))
    return sorted(set(explicit))

def build_bundle(root: Path, generated_at: str | None = None) -> dict:
    dictionary = json.loads((root/'queries/log_source_field_dictionary.json').read_text())
    catalog = json.loads((root/'queries/catalog.json').read_text())
    inventory = json.loads((root/'queries/dashboard_inventory.json').read_text())
    packs = json.loads((root/'config/hunting_packs.json').read_text())['packs']
    refs = json.loads((root/'config/hunting_reference_candidates.json').read_text())['candidates']
    paths = sorted((root/'queries/hunting').glob('*.json'))
    if catalog['total_hunting'] != len(paths):
        raise ValueError('Hunting catalog count is stale; regenerate catalog')
    known_paths = {p.relative_to(root/'queries').as_posix() for p in paths}
    for pack in packs:
        if not set(pack['query_paths']) <= known_paths:
            raise ValueError('Pack references missing hunting query')
    queries = []
    for path in paths:
        relative = path.relative_to(root/'queries').as_posix()
        if not PATH_RE.fullmatch(relative): raise ValueError('Invalid hunting source path')
        row = json.loads(path.read_text())
        query = row['query']
        if not isinstance(query,str) or not query.strip(): raise ValueError('Empty hunting query')
        sources = _sources(query,row,dictionary)
        contract = field_contract(query,sources,dictionary)
        queries.append({'id':'hunt:'+relative[:-5], 'source_path':relative,
            'title':row['title'], 'description':row.get('description',''), 'query':query,
            'query_sha256':hashlib.sha256(query.encode()).hexdigest(),
            'severity':row.get('level','informational'), 'mitre_attack':row.get('mitre_attack',{}),
            'tags':row.get('tags',[]), 'source_candidates':sources, 'field_contract':contract,
            'false_positives':row.get('falsepositives',[]), 'investigation_notes':row.get('investigation_notes',[]),
            'pack_ids':[p['id'] for p in packs if relative in p['query_paths']],
            'dashboard_references':sorted({d['name'] for d in inventory.get('dashboards',[])
                for w in d.get('widgets',[]) if w.get('query_file')==relative}),
            'provenance':{'source_path':'queries/'+relative, 'reference_ids':[r['id'] for r in refs if relative in r.get('local_queries',[])]},
            'evidence_class':'code-backed', 'guidance':row.get('operator_guidance',{})})
    hashes = {p:input_hash(root/p) for p in INPUTS}
    hashes.update({'queries/'+p:input_hash(root/'queries'/p) for p in sorted(known_paths)})
    bundle = {'schema_version':VERSION, 'generated_at':generated_at or datetime.now(timezone.utc).isoformat(),
              'generator':'scripts/generate_hunting_bundle.py', 'input_digests':hashes,
              'packs':packs, 'queries':queries}
    bundle['content_digest'] = content_digest(bundle)
    errors = validate_bundle(bundle)
    if errors: raise ValueError('; '.join(errors))
    return bundle

def validate_bundle(bundle: dict) -> list[str]:
    errors = schema_errors(bundle)
    if errors: return errors
    if not isinstance(bundle,dict): return ['Invalid bundle object']
    if bundle.get('schema_version') != VERSION: errors.append('Unsupported schema version')
    if not isinstance(bundle.get('generated_at'),str): errors.append('Missing generated_at')
    if not isinstance(bundle.get('input_digests'),dict): errors.append('Missing input digests')
    if not isinstance(bundle.get('packs'),list): errors.append('Invalid packs')
    if not isinstance(bundle.get('queries'),list): return errors+['Invalid queries']
    ids=set()
    try:
        for row in bundle['queries']:
            path=row['source_path']
            if not PATH_RE.fullmatch(path) or row['id'] != 'hunt:'+path[:-5]: errors.append('Invalid source identity')
            if row['id'] in ids: errors.append('duplicate query ID')
            ids.add(row['id'])
            for name in ['id','title','description','query','query_sha256','severity','evidence_class']:
                if not isinstance(row[name],str): errors.append('Invalid query '+name)
            if not row['query'].strip() or hashlib.sha256(row['query'].encode()).hexdigest()!=row['query_sha256']:
                errors.append('Invalid query digest')
            if row['field_contract']['status'] not in {'ready','blocked'}: errors.append('Invalid readiness')
            if row['evidence_class']!='code-backed': errors.append('Unsupported evidence claim')
            if row['severity'] not in {'informational','low','medium','high','critical'}: errors.append('Invalid severity')
            for name in ['tags','source_candidates','false_positives','investigation_notes','pack_ids','dashboard_references']:
                if not isinstance(row[name],list) or not all(isinstance(x,str) for x in row[name]): errors.append('Invalid query '+name)
            for name in ['mitre_attack','provenance','guidance']:
                if not isinstance(row[name],dict): errors.append('Invalid query '+name)
            for name in ['required_fields','unmapped_fields','reasons']:
                if not isinstance(row['field_contract'][name],list) or not all(isinstance(x,str) for x in row['field_contract'][name]): errors.append('Invalid field contract')
        packs=bundle['packs']
        pids=[p['id'] for p in packs]
        if len(pids)!=len(set(pids)): errors.append('duplicate pack ID')
        paths={q['source_path'] for q in bundle['queries']}
        for pack in packs:
            if not set(pack['query_paths']) <= paths: errors.append('Invalid pack membership')
        for row in bundle['queries']:
            expected=[p['id'] for p in packs if row['source_path'] in p['query_paths']]
            if row['pack_ids']!=expected: errors.append('Invalid query pack membership')
        if content_digest(bundle)!=bundle.get('content_digest'): errors.append('Invalid content digest')
    except (KeyError,TypeError,ValueError,AttributeError):
        errors.append('Malformed bundle record')
    return errors

def check_freshness(bundle: dict, root: Path) -> list[str]:
    errors=[]
    expected=set(INPUTS) | {'queries/'+p.relative_to(root/'queries').as_posix() for p in (root/'queries/hunting').glob('*.json')}
    recorded=bundle.get('input_digests',{})
    if set(recorded)!=expected: errors.append('Input inventory changed')
    for relative in sorted(expected):
        try:
            if recorded.get(relative)!=input_hash(root/relative): errors.append('Stale input: '+relative)
        except (OSError,ValueError): errors.append('Unavailable input: '+relative)
    return errors
