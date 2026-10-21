"""Conservative hunt field extraction with stage-local aliases.

This is a dependency/readiness check, not an OCI parser or syntax acceptance.
Unknown commands block readiness rather than claiming complete QL support.
"""
from __future__ import annotations
import re
from field_dictionary import extract_query_fields

QUOTED=re.compile(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"")
ALIAS=re.compile(r"\bas\s+(?:'([^']+)'|([A-Za-z_][A-Za-z_0-9]*))|\beval\s+(?:'([^']+)'|([A-Za-z_][A-Za-z_0-9]*))\s*=",re.I)
COMMANDS={'stats','timestats','eventstats','where','eval','fields','sort','head','tail','dedup','search','regex','rex','top','rare','link','cluster','rename'}
KEYWORDS=COMMANDS|{'and','or','not','in','is','like','null','true','false','by','as','asc','desc','count','distinctcount','unique','earliest','latest'}
FIELD_FUNCTIONS='earliest|latest|unique|distinctcount|sum|avg|min|max|median|stddev|length|strlen|lower|upper|tostring|tonumber|formatdate'
FUNCTIONS=set(FIELD_FUNCTIONS.split('|'))|{'if','round','count'}

def _stages(query: str) -> list[str]:
    # Hide quoted strings before splitting; pipes inside patterns are not stages.
    masked=list(query)
    for match in QUOTED.finditer(query):
        masked[match.start():match.end()]=' '*len(match.group())
    positions=[i for i,c in enumerate(masked) if c=='|']
    bounds=[-1,*positions,len(query)]
    return [query[a+1:b] for a,b in zip(bounds,bounds[1:])]

def extract_hunting_fields(query: str) -> tuple[list[str],list[str]]:
    fields=set();aliases=set();reasons=[]
    for index,stage in enumerate(_stages(query)):
        new_aliases={next(v for v in m.groups() if v is not None) for m in ALIAS.finditer(stage)}
        command=re.match(r'\s*([A-Za-z]+)',stage)
        if index>0 and (not command or command[1].lower() not in COMMANDS):
            reasons.append('Unsupported dependency-analysis command')
        # Replace alias declarations before identifying source fields, but retain
        # their defining expressions and source grouping fields.
        expression=ALIAS.sub(lambda m:'eval ' if m.group().lower().startswith('eval ') else '',stage)
        quoted=extract_query_fields(('|' if index else '')+expression)
        for m in re.finditer(r'\b(?:'+FIELD_FUNCTIONS+r")\s*\(\s*'([^']+)'",expression,re.I):
            quoted.add(m[1])
        masked=QUOTED.sub(lambda m:' '*len(m.group()),expression)
        bare=set()
        for m in re.finditer(r'(?<![\w.])[A-Za-z_][A-Za-z_0-9]*(?:\.[A-Za-z_][A-Za-z_0-9]*)*(?![\w.])',masked):
            token=m.group()
            if token.lower() in KEYWORDS:continue
            # Function identifiers and command options are not field names.
            after=masked[m.end():].lstrip()
            if after.startswith('('):
                if token.lower() not in FUNCTIONS: reasons.append('Unsupported dependency-analysis function')
                continue
            if index>0 and after.startswith('=') and stage.lstrip().lower().startswith(('link ','cluster ','top ','rare ')):continue
            bare.add(token)
        fields.update((quoted|bare)-aliases)
        aliases.update(new_aliases)
    return sorted(fields), sorted(set(reasons))
