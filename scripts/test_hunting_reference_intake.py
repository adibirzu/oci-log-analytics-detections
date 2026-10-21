import json
from pathlib import Path
import pytest
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))

ROOT = Path(__file__).resolve().parents[1]

def test_registers_all_five_references():
    from hunting_reference_intake import load_hunting_references
    registry = json.loads((ROOT / 'config/threat_intel_sources.json').read_text())
    sources = {s['id']: s for s in registry['sources']}
    assert {'google_csa','matano','kustoking','bertjanp','logan_mcp'} <= sources.keys()
    assert sources['matano']['role'] == 'capability_reference'
    candidates = load_hunting_references(ROOT / 'config/hunting_reference_candidates.json', registry)
    assert len(candidates) == 8
    assert len({c['id'] for c in candidates}) == 8
    assert candidates == load_hunting_references(ROOT / 'config/hunting_reference_candidates.json', registry)
    assert all(c['provenance'] and c['readiness'] == 'blocked' for c in candidates)

def test_invalid_revision_or_missing_license_fails(tmp_path):
    from hunting_reference_intake import load_hunting_references
    registry = json.loads((ROOT / 'config/threat_intel_sources.json').read_text())
    registry['sources'].append({'id':'bad','revision':'main','license':''})
    p=tmp_path/'refs.json'
    p.write_text(json.dumps({'candidates':[{'id':'x','source_ids':['bad']}]}))
    with pytest.raises(ValueError): load_hunting_references(p,registry)

def test_unknown_table_is_blocked():
    from content_discovery import classify_candidate
    c={'title':'x','candidate_log_sources':['OCI Audit Logs'],'required_fields':['User Name'],
       'source_type':'bertjanp','mapping_gaps':['DeviceProcessEvents not ingested'],'readiness':'blocked'}
    result=classify_candidate(c,{'fields':[{'display_name':'User Name'}]})
    assert result['classification']=='needs field mapping'

def test_duplicate_preserves_all_attributions():
    from content_discovery import deduplicate_candidates
    a={'title':'same','source_type':'google_csa','source_url':'https://example.test/a',
       'provenance':[{'source_id':'google_csa'}]}
    b={**a,'source_type':'bertjanp','source_url':'https://example.test/b',
       'provenance':[{'source_id':'bertjanp'}]}
    r=deduplicate_candidates([a,b])[0]
    assert len(r['provenance'])==2
    assert len(r['source_urls'])==2
