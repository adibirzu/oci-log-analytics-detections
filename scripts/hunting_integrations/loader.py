"""Shared validated artifact lookup, bounded metadata pages, and requirements."""
from __future__ import annotations
import json
import re
from pathlib import Path
from hunting_bundle import validate_bundle,check_freshness

FILTERS={'pack','source','tactic','technique','severity','readiness'}
ID_RE=re.compile(r'hunt:hunting/[a-z0-9][a-z0-9_-]*\Z')

def load_bundle(path: Path, *, root: Path | None = None) -> dict:
    if path.stat().st_size > 5*1024*1024: raise ValueError('Bundle exceeds 5 MiB')
    bundle=json.loads(path.read_text())
    errors=validate_bundle(bundle)
    if root is not None: errors+=check_freshness(bundle,root)
    if errors: raise ValueError('Invalid or stale hunting bundle')
    return bundle

def list_hunts(bundle: dict, *, filters: dict, offset: int = 0, limit: int = 50) -> dict:
    if type(offset) is not int or offset<0 or type(limit) is not int or not 1<=limit<=200:
        raise ValueError('offset must be nonnegative and limit must be between 1 and 200')
    if set(filters)-FILTERS or any(not isinstance(v,str) or not v.strip() for v in filters.values()):
        raise ValueError('Invalid hunt filters')
    if 'readiness' in filters and filters['readiness'] not in {'ready','blocked'}: raise ValueError('Invalid readiness')
    if 'severity' in filters and filters['severity'] not in {'informational','low','medium','high','critical'}: raise ValueError('Invalid severity')
    rows=[]
    for row in sorted(bundle['queries'],key=lambda r:r['id']):
        values={'pack':row['pack_ids'],'source':row['source_candidates'],
                'tactic':row['mitre_attack'].get('tactics',[]), 'technique':row['mitre_attack'].get('techniques',[]),
                'severity':[row['severity']], 'readiness':[row['field_contract']['status']]}
        if all(v in values[k] for k,v in filters.items()):
            rows.append({k:v for k,v in row.items() if k!='query'})
    return {'schema_version':bundle['schema_version'],'content_digest':bundle['content_digest'],
            'total':len(rows),'offset':offset,'limit':limit,'items':rows[offset:offset+limit]}

def get_hunt(bundle: dict, hunt_id: str) -> dict:
    if not isinstance(hunt_id,str) or not ID_RE.fullmatch(hunt_id): raise ValueError('Invalid hunt ID')
    for row in bundle['queries']:
        if row['id']==hunt_id:return row
    raise KeyError(hunt_id)

def get_hunt_requirements(bundle: dict, hunt_id: str) -> dict:
    row=get_hunt(bundle,hunt_id)
    return {k:row[k] for k in ['id','source_candidates','field_contract','evidence_class','guidance','investigation_notes','provenance']}
