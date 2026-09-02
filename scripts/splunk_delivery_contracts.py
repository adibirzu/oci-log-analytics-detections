"""Validation helpers for Splunk parallel delivery contract artifacts."""

import json
from pathlib import Path

import jsonschema


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
REGISTRY_SCHEMA_PATH = REPOSITORY_ROOT / "schemas/splunk_detection_registry.schema.json"
REGISTRY_VALIDATOR = jsonschema.Draft202012Validator(
    json.loads(REGISTRY_SCHEMA_PATH.read_text(encoding="utf-8"))
)


def registry_validation_errors(entry: dict, repository_root: Path = REPOSITORY_ROOT) -> list[str]:
    """Return schema and canonical-query-path errors for a registry entry."""
    errors = [error.message for error in REGISTRY_VALIDATOR.iter_errors(entry)]
    query_file = entry.get("oci_query_file")
    if not isinstance(query_file, str):
        return errors

    root = repository_root.resolve()
    queries_root = (root / "queries").resolve()
    candidate = (root / query_file).resolve()
    if not candidate.is_relative_to(queries_root) or not candidate.is_file():
        errors.append(f"oci_query_file is not a canonical query: {query_file}")
    return errors
