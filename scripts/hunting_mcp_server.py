#!/usr/bin/env python3
"""Artifact-only hunting MCP server; no OCI credentials or execution tools."""
from __future__ import annotations
import argparse
import sys
from pathlib import Path
from hunting_integrations.loader import load_bundle,list_hunts,get_hunt,get_hunt_requirements
ROOT=Path(__file__).resolve().parents[1]

def dispatch_tool(name: str, arguments: dict, bundle: dict) -> dict:
    if not isinstance(arguments,dict):raise ValueError('Invalid tool arguments')
    if name=='list_hunts':
        if set(arguments)-{'filters','offset','limit'}:raise ValueError('Unknown arguments')
        filters=arguments.get('filters',{})
        if not isinstance(filters,dict):raise ValueError('Invalid filters')
        return list_hunts(bundle,filters=filters,offset=arguments.get('offset',0),limit=arguments.get('limit',50))
    if name in {'get_hunt','get_hunt_requirements'}:
        if set(arguments)!={'hunt_id'}:raise ValueError('hunt_id required; unknown arguments rejected')
        return (get_hunt if name=='get_hunt' else get_hunt_requirements)(bundle,arguments['hunt_id'])
    raise ValueError('Unknown content tool')

def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle',type=Path,default=ROOT/'queries/hunting_integration_bundle.json')
    args=parser.parse_args()
    root=ROOT if args.bundle.resolve()==(ROOT/'queries/hunting_integration_bundle.json').resolve() else None
    try:
        load_bundle(args.bundle,root=root)
        from mcp.server.fastmcp import FastMCP
        from mcp.types import ToolAnnotations
    except ImportError:
        print('Install optional requirements-mcp.txt to run the content server',file=sys.stderr);return 1
    except (OSError,ValueError):
        print('Hunting artifact unavailable or invalid',file=sys.stderr);return 1
    server=FastMCP('OCI Hunting Content')
    annotations=ToolAnnotations(readOnlyHint=True,destructiveHint=False,idempotentHint=True,openWorldHint=False)
    def call(name: str,arguments: dict) -> dict:
        try:return dispatch_tool(name,arguments,load_bundle(args.bundle,root=root))
        except KeyError:raise ValueError('Hunt not found') from None
        except (ValueError,OSError,TypeError):raise ValueError('Invalid request or hunting artifact') from None
    @server.tool(annotations=annotations)
    def list_hunts(filters: dict[str,str] | None = None,offset: int = 0,limit: int = 50) -> dict:
        """Discover bounded hunting metadata; readiness is local, not provider acceptance."""
        return call('list_hunts',{'filters':filters or {},'offset':offset,'limit':limit})
    @server.tool(annotations=annotations)
    def get_hunt(hunt_id: str) -> dict:
        """Read exact query content and readiness; never execute a query."""
        return call('get_hunt',{'hunt_id':hunt_id})
    @server.tool(annotations=annotations)
    def get_hunt_requirements(hunt_id: str) -> dict:
        """Read source fields, gaps, provenance, and investigation guidance."""
        return call('get_hunt_requirements',{'hunt_id':hunt_id})
    server.run(transport='stdio')
    return 0

if __name__=='__main__':raise SystemExit(main())
