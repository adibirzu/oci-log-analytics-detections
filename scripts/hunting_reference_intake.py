"""Normalize pinned reference metadata; never import or execute upstream rule bodies."""
from __future__ import annotations
import json
import re
from pathlib import Path


def load_hunting_references(path: Path, registry: dict) -> list[dict]:
    sources = {s['id']: s for s in registry['sources']}
    out = []
    seen = set()
    for row in json.loads(path.read_text())['candidates']:
        if row['id'] in seen:
            raise ValueError('duplicate reference ID')
        seen.add(row['id'])
        provenance = []
        for sid in row['source_ids']:
            source = sources[sid]
            if not re.fullmatch(r'[0-9a-f]{40}', source.get('revision', '')) or not source.get('license'):
                raise ValueError('reference requires pinned revision and license')
            provenance.append({'source_id': sid, 'revision': source['revision'],
                               'license': source['license'], 'source_url': row['source_url'],
                               'source_sha256': row['source_sha256']})
        if not provenance or not re.fullmatch(r'[0-9a-f]{64}', row.get('source_sha256', '')):
            raise ValueError('reference requires source hash and attribution')
        out.append({**row, 'source_type': row['source_ids'][0], 'source_types': row['source_ids'],
                    'affected_platform': 'cross_platform', 'candidate_log_sources': [],
                    'mitre_tactics': [], 'core_indicators': [], 'detection_idea': row['title'],
                    'licensing': {'mode': 'metadata_only', 'licenses': sorted({p['license'] for p in provenance})},
                    'attribution': {'references': [row['source_url']]}, 'provenance': provenance,
                    'readiness': 'blocked', 'evidence_class': 'code-backed', 'review_status': 'candidate'})
    return out
