import asyncio
import copy
import importlib.util
import sys
from pathlib import Path
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parent))
ROOT=Path(__file__).resolve().parents[1]

def test_dispatch_only_content_tools():
    from hunting_bundle import build_bundle
    from hunting_mcp_server import dispatch_tool
    b=build_bundle(ROOT)
    p=dispatch_tool('list_hunts',{'limit':1},b)
    assert p['total']==171
    row=dispatch_tool('get_hunt',{'hunt_id':p['items'][0]['id']},b)
    assert row['query']
    blocked=next(q for q in b['queries'] if q['field_contract']['status']=='blocked')
    assert dispatch_tool('get_hunt_requirements',{'hunt_id':blocked['id']},b)['field_contract']['status']=='blocked'
    for name,args in [('run_query',{}),('get_hunt',{'hunt_id':row['id'],'extra':True}),('list_hunts',{'limit':201})]:
        with pytest.raises(ValueError):dispatch_tool(name,args,b)

def test_pure_runtime_handoff_has_explicit_scope_and_bounds():
    from hunting_bundle import build_bundle
    spec=importlib.util.spec_from_file_location('handoff',ROOT/'examples/hunting_integrations/logan_mcp_handoff.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    b=build_bundle(ROOT);q=next(q for q in b['queries'] if q['field_contract']['status']=='ready')
    kwargs={'compartment_id':'<COMPARTMENT_OCID>','time_start':'2026-10-13T00:00:00Z','time_end':'2026-10-13T01:00:00Z','max_results':100}
    req=module.build_run_query_request(q,**kwargs)
    assert req['scope']=='default' and req['include_subcompartments'] is False
    assert req['query']==q['query']
    for bad in [{'max_results':0},{'max_results':1001},{'time_start':'2026-10-14T00:00:00Z'},{'time_start':'2026-10-13T00:00:00'},{'compartment_id':''}]:
        with pytest.raises(ValueError):module.build_run_query_request(q,**{**kwargs,**bad})
    q=copy.deepcopy(q);q['field_contract']['status']='blocked'
    with pytest.raises(ValueError):module.build_run_query_request(q,**kwargs)

def test_stdio_discovery_and_call():
    pytest.importorskip('mcp')
    from mcp import ClientSession,StdioServerParameters
    from mcp.client.stdio import stdio_client
    async def probe():
        async with stdio_client(StdioServerParameters(command=sys.executable,args=[str(ROOT/'scripts/hunting_mcp_server.py')])) as (read,write):
            async with ClientSession(read,write) as session:
                await session.initialize()
                result=await session.list_tools()
                assert {t.name for t in result.tools}=={'list_hunts','get_hunt','get_hunt_requirements'}
                rows=await session.call_tool('list_hunts',{'limit':1})
                assert not rows.isError
    asyncio.run(asyncio.wait_for(probe(),timeout=20))
