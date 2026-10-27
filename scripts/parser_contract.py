"""Versioned LOCAL parser structure, never a provider validation receipt."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

VERSION = "forge.parser-contract.v1"
LEGACY_MANIFEST_SHA256 = "5c6a010fdef63879c0bfb3e87cc947296f43f38eb947594bfed66243886e6a26"
TOP = {"version", "generated_at", "summary", "validation", "approved_builtins", "reserved_for_custom_parsers", "source_candidate_groups", "parsers", "sources", "fields"}
FIELD = {"display_name", "kind", "type", "raw_json_paths", "parsers", "sources", "source_candidate_groups", "example_values", "contract_datasets", "queries_using_it", "dashboards_using_it", "reserved_backing_field"}
PARSER = {"parser_name", "parser_display", "source_internal", "source_display", "field_count"}
SOURCE = {"source_internal", "source_display", "parser_name", "candidate_groups"}
FIELD_PARSER = {"parser_name", "parser_display", "sequence", "raw_json_path"}
FIELD_SOURCE = {"source_internal", "source_display"}


class ContractError(ValueError):
    """Errors intentionally exclude untrusted values and operator paths."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def contract_hash(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def raw_schema_hash(dictionary):
    if not isinstance(dictionary, dict):
        raise ContractError("Invalid local JSON structure")
    return contract_hash({k: v for k, v in dictionary.items() if k != "generated_at"})


def _object(value, keys):
    if not isinstance(value, dict) or set(value) != keys:
        raise ContractError("Invalid parser contract structure")


def _strings(value, *, ordered=False):
    if not isinstance(value, list) or any(not isinstance(v, str) for v in value) or len(set(value)) != len(value):
        raise ContractError("Invalid parser contract structure")
    return list(value) if ordered else sorted(value)


def _records(value, keys, identity):
    if not isinstance(value, list):
        raise ContractError("Invalid parser contract structure")
    out = []
    seen = set()
    for record in value:
        _object(record, keys)
        key = record[identity]
        if not isinstance(key, str) or not key or key in seen:
            raise ContractError("Invalid parser contract structure")
        seen.add(key)
        out.append(dict(record))
    return sorted(out, key=lambda record: record[identity])


def parser_contract(dictionary):
    _object(dictionary, TOP)
    if dictionary["version"] != "1.0":
        raise ContractError("Unsupported dictionary version")
    groups = dictionary["source_candidate_groups"]
    reserved = dictionary["reserved_for_custom_parsers"]
    if not isinstance(groups, dict) or not isinstance(reserved, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in reserved.items()):
        raise ContractError("Invalid parser contract structure")
    groups = {key: _strings(value, ordered=True) for key, value in groups.items() if isinstance(key, str)}
    if len(groups) != len(dictionary["source_candidate_groups"]):
        raise ContractError("Invalid parser contract structure")
    parsers = _records(dictionary["parsers"], PARSER, "parser_name")
    for record in parsers:
        if any(not isinstance(record[k], str) for k in PARSER - {"field_count"}) or type(record["field_count"]) is not int or record["field_count"] < 0:
            raise ContractError("Invalid parser contract structure")
    sources = _records(dictionary["sources"], SOURCE, "source_internal")
    for record in sources:
        if any(not isinstance(record[k], str) for k in SOURCE - {"candidate_groups"}):
            raise ContractError("Invalid parser contract structure")
        record["candidate_groups"] = _strings(record["candidate_groups"])
    fields = _records(dictionary["fields"], FIELD, "display_name")
    for record in fields:
        for key in ("example_values", "queries_using_it", "dashboards_using_it"):
            del record[key]
        for key in ("display_name", "kind", "type", "reserved_backing_field"):
            if not isinstance(record[key], str):
                raise ContractError("Invalid parser contract structure")
        for key in ("raw_json_paths", "source_candidate_groups", "contract_datasets"):
            record[key] = _strings(record[key])
        for key, keys in (("parsers", FIELD_PARSER), ("sources", FIELD_SOURCE)):
            if not isinstance(record[key], list):
                raise ContractError("Invalid parser contract structure")
            records = []
            for item in record[key]:
                _object(item, keys)
                if any(not isinstance(item[k], str) for k in keys - {"sequence"}) or ("sequence" in item and type(item["sequence"]) is not int):
                    raise ContractError("Invalid parser contract structure")
                records.append(dict(item))
            if len({canonical(item) for item in records}) != len(records):
                raise ContractError("Invalid parser contract structure")
            record[key] = sorted(records, key=canonical)
    return {"schema_version": VERSION, "approved_builtins": _strings(dictionary["approved_builtins"]), "reserved_for_custom_parsers": dict(reserved), "source_candidate_groups": groups, "parsers": parsers, "sources": sources, "fields": fields}


def identity_hash(payload):
    return contract_hash({key: payload.get(key, "") for key in ("sentinel_id", "sentinel_source_path", "source_type", "conversion_status")})


def bind_query(dictionary, payload):
    return {"schema_version": VERSION, "evidence_class": "local-parser-contract", "schema_sha256": contract_hash(parser_contract(dictionary)), "query_sha256": hashlib.sha256(payload["query"].encode()).hexdigest(), "identity_sha256": identity_hash(payload)}


def require_additive(previous, current):
    """Retain every old mapping and preference; new sources cannot shadow it."""
    if previous.get("schema_version") != VERSION or current.get("schema_version") != VERSION or set(previous) != set(current):
        raise ContractError("Unsupported parser contract")
    if previous["approved_builtins"] != current["approved_builtins"] or previous["reserved_for_custom_parsers"] != current["reserved_for_custom_parsers"]:
        raise ContractError("Incompatible parser contract")
    for key, values in previous["source_candidate_groups"].items():
        if key not in current["source_candidate_groups"] or current["source_candidate_groups"][key][:len(values)] != values:
            raise ContractError("Incompatible parser contract")
    for key in ("parsers", "sources"):
        if any(record not in current[key] for record in previous[key]):
            raise ContractError("Incompatible parser contract")
    now = {record["display_name"]: record for record in current["fields"]}
    for record in previous["fields"]:
        other = now.get(record["display_name"])
        if other is None or set(record) != set(other):
            raise ContractError("Incompatible parser contract")
        for key, value in record.items():
            if isinstance(value, list):
                if any(item not in other[key] for item in value):
                    raise ContractError("Incompatible parser contract")
            elif value != other[key]:
                raise ContractError("Incompatible parser contract")


def load_legacy_manifest(path):
    """Read the reviewed artifact in shallow CI; never manufacture trust there."""
    path = Path(path)
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
            raise ContractError("Invalid legacy compatibility manifest")
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != LEGACY_MANIFEST_SHA256:
            raise ContractError("Invalid legacy compatibility manifest")
        manifest = json.loads(data)
    except (OSError, ValueError):
        raise ContractError("Invalid legacy compatibility manifest") from None
    if manifest.get("schema_version") != "forge.sentinel-legacy-compatibility.v1" or manifest.get("provider_revalidated") is not False:
        raise ContractError("Invalid legacy compatibility manifest")
    bindings = manifest.get("bindings")
    if not isinstance(bindings, list) or len(bindings) != 590 or len({row["output_file"] for row in bindings}) != len(bindings):
        raise ContractError("Invalid legacy compatibility manifest")
    return manifest


def validate_local_binding(payload, file_bytes, output_file, dictionary, report_row, report_bytes, manifest):
    """Validate local byte provenance. Return no provider acceptance decision."""
    if not isinstance(payload.get("query"), str) or not isinstance(payload.get("parser_schema_hash"), str) or not re.fullmatch(r"[0-9a-f]{64}", payload["parser_schema_hash"]):
        raise ContractError("Invalid local query binding")
    current = parser_contract(dictionary)
    if "parser_contract" in payload:
        if payload["parser_contract"] != bind_query(dictionary, payload) or report_row.get("parser_contract") != payload["parser_contract"] or report_row.get("live_validation_status") != "passed" or report_row.get("sentinel_id") != payload.get("sentinel_id") or report_row.get("source_path") != payload.get("sentinel_source_path"):
            raise ContractError("Invalid versioned local binding")
        return "versioned_local_contract"
    if manifest is None:
        raise ContractError("Legacy compatibility binding unavailable")
    binding = next((row for row in manifest["bindings"] if row["output_file"] == output_file), None)
    if binding is None or hashlib.sha256(file_bytes).hexdigest() != binding["reviewed_file_sha256"] or hashlib.sha256(payload["query"].encode()).hexdigest() != binding["query_sha256"] or identity_hash(payload) != binding["identity_sha256"] or contract_hash(report_row) != binding["historical_report_row_sha256"] or hashlib.sha256(report_bytes).hexdigest() != manifest["reviewed_report_sha256"]:
        raise ContractError("Legacy source binding mismatch")
    if payload.get("parser_schema_hash") != manifest["observed_legacy_raw_schema_sha256"] or contract_hash(current) != manifest["reviewed_parser_contract_sha256"]:
        raise ContractError("Legacy parser binding mismatch")
    require_additive(manifest["historical_parser_contract"], current)
    return "legacy_source_compatible"
