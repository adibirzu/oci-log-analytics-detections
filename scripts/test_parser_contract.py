"""Behavioral contracts for local parser compatibility; no OCI calls."""
import copy
import pytest

from scripts.parser_contract import parser_contract, contract_hash, require_additive


def dictionary():
    return {
        "version": "1.0", "generated_at": "ignored", "summary": {}, "validation": {},
        "approved_builtins": ["Time"], "reserved_for_custom_parsers": {},
        "source_candidate_groups": {"events": ["Example Source"]},
        "parsers": [{"parser_name": "example", "parser_display": "Example", "source_internal": "example", "source_display": "Example Source", "field_count": 1}],
        "sources": [{"source_internal": "example", "source_display": "Example Source", "parser_name": "example", "candidate_groups": ["events"]}],
        "fields": [{"display_name": "User", "kind": "custom", "type": "STRING", "raw_json_paths": ["$.user"], "parsers": [{"parser_name": "example", "parser_display": "Example", "sequence": 1, "raw_json_path": "$.user"}], "sources": [{"source_internal": "example", "source_display": "Example Source"}], "source_candidate_groups": ["events"], "example_values": [], "contract_datasets": [], "queries_using_it": [], "dashboards_using_it": [], "reserved_backing_field": ""}],
    }


def test_usage_and_examples_do_not_change_local_parser_contract():
    original = dictionary()
    changed = copy.deepcopy(original)
    changed["generated_at"] = "later"
    changed["summary"] = {"fields_with_query_usage": 1}
    changed["fields"][0]["queries_using_it"] = ["hunting/example.json"]
    changed["fields"][0]["example_values"] = ["synthetic"]
    assert contract_hash(parser_contract(original)) == contract_hash(parser_contract(changed))


@pytest.mark.parametrize("change", ["type", "mapping", "sequence", "candidate-order", "unknown-key"])
def test_semantic_changes_cannot_inherit_local_compatibility(change):
    original = dictionary()
    changed = copy.deepcopy(original)
    if change == "type": changed["fields"][0]["type"] = "NUMBER"
    if change == "mapping": changed["fields"][0]["raw_json_paths"] = ["$.other"]
    if change == "sequence": changed["fields"][0]["parsers"][0]["sequence"] = 2
    if change == "candidate-order": changed["source_candidate_groups"]["events"].insert(0, "Other Source")
    if change == "unknown-key": changed["fields"][0]["unreviewed_structure"] = "ignored?"
    with pytest.raises(ValueError):
        require_additive(parser_contract(original), parser_contract(changed))
