"""Export the pinned Logan MCP YAML catalog shape without installing it."""
from __future__ import annotations
import yaml

def export_logan_yaml(bundle: dict, *, include_blocked: bool = False) -> str:
    entries=[]
    for q in bundle['queries']:
        blocked=q['field_contract']['status']=='blocked'
        if blocked and not include_blocked: continue
        description=q['description']
        if blocked: description='BLOCKED — inspect source and field requirements before execution. '+description
        entries.append({'entry_id':q['id'],'name':'oci-hunt:'+q['id'].removeprefix('hunt:'),
            'query':q['query'],'description':description,'category':q['pack_ids'][0] if q['pack_ids'] else 'hunting',
            'tags':sorted(set(q['tags']+['evidence:code-backed','readiness:'+q['field_contract']['status']]))})
    if len({e['name'] for e in entries})!=len(entries): raise ValueError('Catalog name collision')
    return yaml.safe_dump({'queries':entries},sort_keys=False,allow_unicode=True)
