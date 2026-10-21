import copy
import json
import sys
from pathlib import Path
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parent))
ROOT=Path(__file__).resolve().parents[1]

def test_complete_coverage_and_hashes():
    from hunting_bundle import build_bundle,validate_bundle
    b=build_bundle(ROOT,'2026-10-13T00:00:00Z')
    assert len(b['queries'])==len(list((ROOT/'queries/hunting').glob('*.json')))
    assert validate_bundle(b)==[]
    assert b['content_digest']==build_bundle(ROOT,'2026-10-14T00:00:00Z')['content_digest']
    for q in b['queries']:
        assert q['query']==json.loads((ROOT/'queries'/q['source_path']).read_text())['query']
        assert q['evidence_class']=='code-backed'

def test_wrong_source_blocks_known_field():
    from hunting_bundle import field_contract
    d={'approved_builtins':['Log Source'], 'sources':[{'source_display':'A'}],
       'fields':[{'display_name':'Secret','sources':[{'source_display':'B'}]}]}
    r=field_contract("'Log Source' = 'A' | stats count by 'Secret'",['A'],d)
    assert r['status']=='blocked'
    assert 'Secret' in r['unmapped_fields']

def test_literals_and_aliases_are_not_fields():
    from hunting_bundle import field_contract
    d={'approved_builtins':['Log Source'], 'sources':[{'source_display':'A'}],
       'fields':[{'display_name':'User Name','sources':[{'source_display':'A'}]}]}
    r=field_contract("'Log Source' = 'A' | stats count as Total by 'User Name' | where Total > 2",['A'],d)
    assert r['required_fields']==['Log Source','User Name']
    assert r['status']=='ready'

def test_digest_tampering_and_duplicate_id_rejected():
    from hunting_bundle import build_bundle,validate_bundle
    b=build_bundle(ROOT)
    b['queries'][0]['query']+=' | head 1'
    assert validate_bundle(b)
    b=build_bundle(ROOT);b['queries'].append(copy.deepcopy(b['queries'][0]))
    assert any('duplicate' in e for e in validate_bundle(b))

def test_changed_or_removed_input_is_stale(tmp_path):
    from hunting_bundle import build_bundle,check_freshness
    b=build_bundle(ROOT)
    assert check_freshness(b,ROOT)==[]
    assert check_freshness(b,tmp_path)
    p=tmp_path/'queries/hunting';p.mkdir(parents=True)
    (p/'extra.json').write_text('{}')
    assert check_freshness(b,tmp_path)

def test_schema_contract():
    import jsonschema
    from hunting_bundle import build_bundle
    s=json.loads((ROOT/'schemas/hunting_integration_bundle.schema.json').read_text())
    jsonschema.validate(build_bundle(ROOT),s)
    with pytest.raises(jsonschema.ValidationError): jsonschema.validate({'schema_version':'2'},s)

def test_bare_fields_function_arguments_and_aliases():
    from hunting_bundle import field_contract
    d={'approved_builtins':['Log Source'], 'sources':[{'source_display':'A'}],
       'fields':[{'display_name':'Secret','sources':[{'source_display':'B'}]},
                 {'display_name':'User Name','sources':[{'source_display':'A'}]}]}
    assert field_contract("'Log Source' = 'A' | stats count by Secret",['A'],d)['status']=='blocked'
    contract=field_contract("'Log Source' = 'A' | stats count as 'Total' by 'User Name' | where 'Total' > 2",['A'],d)
    assert contract['required_fields']==['Log Source','User Name'] and contract['status']=='ready'
    contract=field_contract("'Log Source' = 'A' | stats latest('Secret') as Last by 'User Name'",['A'],d)
    assert 'Secret' in contract['required_fields'] and contract['status']=='blocked'

def test_python_enforces_published_schema():
    from hunting_bundle import build_bundle,validate_bundle,content_digest
    for change in ['generator','pack_title','extra_key','input_hash']:
        b=build_bundle(ROOT)
        if change=='generator':del b['generator']
        elif change=='pack_title':del b['packs'][0]['title']
        elif change=='extra_key':b['surprise']=True
        else:b['input_digests']['scripts/hunting_bundle.py']=None
        b['content_digest']=content_digest(b)
        assert validate_bundle(b),change

def test_extractor_dependency_is_freshness_input():
    from hunting_bundle import build_bundle
    b=build_bundle(ROOT)
    assert 'scripts/field_dictionary.py' in b['input_digests']

def test_unresolved_function_and_dotted_fields_block_readiness():
    from hunting_bundle import field_contract
    d={'approved_builtins':['Log Source'], 'sources':[{'source_display':'A'}], 'fields':[]}
    for text in ["'Log Source' = 'A' | stats count by Unknown.Field", "'Log Source' = 'A' | stats magic('Secret') as X"]:
        assert field_contract(text,['A'],d)['status']=='blocked'
