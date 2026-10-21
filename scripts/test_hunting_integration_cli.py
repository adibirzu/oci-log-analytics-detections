import json
import sys
import subprocess
from pathlib import Path
import pytest
import yaml
sys.path.insert(0,str(Path(__file__).resolve().parent))
ROOT=Path(__file__).resolve().parents[1]

def bundle():
    from hunting_bundle import build_bundle
    return build_bundle(ROOT)

def test_shared_loader_filters_and_limits():
    from hunting_integrations.loader import list_hunts,get_hunt,get_hunt_requirements,load_bundle
    b=bundle()
    page=list_hunts(b,filters={},limit=1)
    assert len(page['items'])==1 and page['total']==171
    row=get_hunt(b,page['items'][0]['id'])
    assert get_hunt_requirements(b,row['id'])['field_contract']==row['field_contract']
    assert list_hunts(b,filters={'pack':'identity_credentials'})['total']==3
    for f in [{'readiness':'nonsense'},{'unknown':'x'}]:
        with pytest.raises(ValueError):list_hunts(b,filters=f)
    for lim in [0,201,True]:
        with pytest.raises(ValueError):list_hunts(b,filters={},limit=lim)
    with pytest.raises(ValueError):list_hunts(b,filters={},offset=-1)
    with pytest.raises(ValueError):get_hunt(b,'../../config')
    with pytest.raises(KeyError):get_hunt(b,'hunt:hunting/missing')
    assert load_bundle(ROOT/'queries/hunting_integration_bundle.json',root=ROOT)['content_digest']==b['content_digest']

def test_loader_rejects_tampering(tmp_path):
    from hunting_integrations.loader import load_bundle
    b=bundle();b['queries'][0]['title']='tamper'
    p=tmp_path/'b.json';p.write_text(json.dumps(b))
    with pytest.raises(ValueError):load_bundle(p)

def test_logan_yaml_preserves_queries_and_excludes_blocked():
    from hunting_integrations.logan_yaml import export_logan_yaml
    b=bundle();d=yaml.safe_load(export_logan_yaml(b))
    ready={q['id']:q for q in b['queries'] if q['field_contract']['status']=='ready'}
    assert len(d['queries'])==len(ready)>0
    assert all(q['name'].startswith('oci-hunt:') for q in d['queries'])
    assert all(q['query']==ready[q['entry_id']]['query'] for q in d['queries'])
    assert len(yaml.safe_load(export_logan_yaml(b,include_blocked=True))['queries'])==171

def test_cli_missing_id_and_no_overwrite(tmp_path):
    cli=[sys.executable,str(ROOT/'scripts/hunting_integration_cli.py')]
    r=subprocess.run(cli+['get','hunt:hunting/missing'],capture_output=True,text=True)
    assert r.returncode==1 and json.loads(r.stderr)['error']=='not_found'
    p=tmp_path/'x.yaml';p.write_text('keep')
    r=subprocess.run(cli+['export','--format','logan-yaml','--output',str(p)],capture_output=True,text=True)
    assert r.returncode==1 and p.read_text()=='keep'
