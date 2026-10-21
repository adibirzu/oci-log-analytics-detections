"""Validate the small published bundle schema without a runtime dependency.

Only the schema constructs used by this project's versioned contract are
supported. Full JSON Schema validation is also exercised in development tests.
"""
from __future__ import annotations
import json
import re
from datetime import datetime
from pathlib import Path
SCHEMA=Path(__file__).resolve().parents[1]/'schemas/hunting_integration_bundle.schema.json'

def schema_errors(value: object) -> list[str]:
    schema=json.loads(SCHEMA.read_text())
    errors=[]
    def visit(v: object, rule: dict, location: str) -> None:
        kind=rule.get('type')
        types={'object':dict,'array':list,'string':str}
        if kind and not isinstance(v,types[kind]):
            errors.append(location+': invalid type');return
        if 'const' in rule and v!=rule['const']:errors.append(location+': invalid constant')
        if 'enum' in rule and v not in rule['enum']:errors.append(location+': invalid enum')
        if isinstance(v,str):
            if 'pattern' in rule and not re.search(rule['pattern'],v):errors.append(location+': invalid pattern')
            if rule.get('format')=='date-time':
                try:
                    if 'T' not in v or datetime.fromisoformat(v.replace('Z','+00:00')).tzinfo is None:raise ValueError()
                except ValueError:errors.append(location+': invalid timestamp')
        if isinstance(v,dict):
            props=rule.get('properties',{})
            for name in rule.get('required',[]):
                if name not in v:errors.append(location+': missing '+name)
            for name,item in v.items():
                if name in props:visit(item,props[name],location+'.'+name)
                elif rule.get('additionalProperties') is False:errors.append(location+': unexpected '+name)
                elif isinstance(rule.get('additionalProperties'),dict):visit(item,rule['additionalProperties'],location+'.'+name)
        if isinstance(v,list) and 'items' in rule:
            for i,item in enumerate(v):visit(item,rule['items'],location+f'[{i}]')
    visit(value,schema,'bundle')
    return errors
