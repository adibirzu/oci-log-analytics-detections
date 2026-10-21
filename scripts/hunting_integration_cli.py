#!/usr/bin/env python3
"""List, inspect, validate, and export hunting artifacts without OCI access."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from hunting_integrations.loader import load_bundle,list_hunts,get_hunt,get_hunt_requirements,FILTERS
from hunting_integrations.logan_yaml import export_logan_yaml
ROOT=Path(__file__).resolve().parents[1]

def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle',type=Path,default=ROOT/'queries/hunting_integration_bundle.json')
    commands=parser.add_subparsers(dest='command',required=True)
    listing=commands.add_parser('list')
    for name in sorted(FILTERS):listing.add_argument('--'+name)
    listing.add_argument('--offset',type=int,default=0);listing.add_argument('--limit',type=int,default=50)
    for name in ['get','requirements']:commands.add_parser(name).add_argument('id')
    commands.add_parser('validate')
    export=commands.add_parser('export');export.add_argument('--format',choices=['json','logan-yaml'],default='json')
    export.add_argument('--include-blocked',action='store_true');export.add_argument('--output',type=Path)
    export.add_argument('--overwrite',action='store_true')
    args=parser.parse_args()
    try:
        root=ROOT if args.bundle.resolve()==(ROOT/'queries/hunting_integration_bundle.json').resolve() else None
        bundle=load_bundle(args.bundle,root=root)
        if args.command=='list':value=list_hunts(bundle,filters={k:getattr(args,k) for k in FILTERS if getattr(args,k)},offset=args.offset,limit=args.limit)
        elif args.command=='get':value=get_hunt(bundle,args.id)
        elif args.command=='requirements':value=get_hunt_requirements(bundle,args.id)
        elif args.command=='validate':value={'ok':True,'content_digest':bundle['content_digest'],'hunts':len(bundle['queries'])}
        else:value=bundle
        output=export_logan_yaml(bundle,include_blocked=args.include_blocked) if args.command=='export' and args.format=='logan-yaml' else json.dumps(value,indent=2,ensure_ascii=False)+'\n'
        if args.command=='export' and args.output:
            with args.output.open('w' if args.overwrite else 'x') as stream:stream.write(output)
        else:print(output,end='')
        return 0
    except KeyError:
        print(json.dumps({'error':'not_found'}),file=sys.stderr);return 1
    except (OSError,ValueError,TypeError):
        print(json.dumps({'error':'invalid_request_or_artifact'}),file=sys.stderr);return 1

if __name__=='__main__':raise SystemExit(main())
