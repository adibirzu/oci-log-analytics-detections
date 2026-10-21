#!/usr/bin/env python3
"""Generate or verify the complete hunting integration bundle, offline."""
import argparse
import json
from pathlib import Path
from hunting_bundle import build_bundle, validate_bundle, check_freshness
ROOT=Path(__file__).resolve().parents[1]

def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    path=ROOT/'queries/hunting_integration_bundle.json'
    try:
        if args.check:
            bundle=json.loads(path.read_text())
            errors=validate_bundle(bundle)+check_freshness(bundle,ROOT)
            if errors:
                print('\n'.join(errors));return 1
        else:
            bundle=build_bundle(ROOT)
            path.write_text(json.dumps(bundle,indent=2,ensure_ascii=False)+'\n')
        print(f"Hunting bundle: {len(bundle['queries'])} hunts, digest {bundle['content_digest']}")
        return 0
    except (OSError,ValueError,KeyError) as error:
        print('Hunting bundle invalid: '+str(error));return 1

if __name__=='__main__': raise SystemExit(main())
