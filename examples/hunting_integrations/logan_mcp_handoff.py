"""Build a bounded Logan MCP request; this example never connects or executes."""
from __future__ import annotations
from datetime import datetime

def build_run_query_request(hunt: dict, *, compartment_id: str, time_start: str,
                            time_end: str, max_results: int) -> dict:
    if hunt['field_contract']['status'] != 'ready':raise ValueError('Hunt is blocked')
    if not isinstance(compartment_id,str) or not compartment_id.strip():raise ValueError('Explicit compartment required')
    if type(max_results) is not int or not 1<=max_results<=1000:raise ValueError('Result limit must be 1–1000')
    start=datetime.fromisoformat(time_start.replace('Z','+00:00'))
    end=datetime.fromisoformat(time_end.replace('Z','+00:00'))
    if start.tzinfo is None or end.tzinfo is None or end<=start:raise ValueError('Ordered timezone-aware bounds required')
    return {'query':hunt['query'],'compartment_id':compartment_id,'scope':'default',
            'include_subcompartments':False,'time_start':time_start,'time_end':time_end,
            'max_results':max_results}
