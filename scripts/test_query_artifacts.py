"""Tests for generated query-artifact classification."""

from scripts.query_artifacts import is_generated_query_artifact, is_saved_search_query_file


def test_splunk_detection_registry_is_not_a_saved_search_query():
    path = "queries/splunk_detection_registry.json"
    assert is_generated_query_artifact(path)
    assert not is_saved_search_query_file(path)
