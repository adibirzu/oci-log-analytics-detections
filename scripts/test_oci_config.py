#!/usr/bin/env python3
"""Unit tests for OCI profile-aware configuration resolution."""

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import oci_config


class TestProfileScopedConfig(unittest.TestCase):
    """Validate profile-scoped config behavior for multi-profile demos."""

    def test_profile_scoped_env_local_overrides_plain_mismatched_profile_value(self):
        env = {"OCI_PROFILE": "DEFAULT"}
        env_file = {
            "OCI_PROFILE": "cap",
            "LA_NAMESPACE": "cap-namespace",
            "DEFAULT_LA_NAMESPACE": "default-namespace",
        }

        value = oci_config._cfg(
            "LA_NAMESPACE",
            "",
            profile_bound=True,
            profile="DEFAULT",
            env=env,
            env_file=env_file,
        )

        self.assertEqual(value, "default-namespace")

    def test_mismatched_env_local_profile_bound_value_is_not_inherited(self):
        env = {"OCI_PROFILE": "DEFAULT"}
        env_file = {
            "OCI_PROFILE": "cap",
            "LA_NAMESPACE": "cap-namespace",
        }

        value = oci_config._cfg(
            "LA_NAMESPACE",
            "",
            profile_bound=True,
            profile="DEFAULT",
            env=env,
            env_file=env_file,
        )

        self.assertEqual(value, "")

    def test_matching_env_local_profile_bound_value_is_used(self):
        env = {}
        env_file = {
            "OCI_PROFILE": "cap",
            "LA_NAMESPACE": "cap-namespace",
        }

        value = oci_config._cfg(
            "LA_NAMESPACE",
            "",
            profile_bound=True,
            env=env,
            env_file=env_file,
        )

        self.assertEqual(value, "cap-namespace")

    def test_profile_scoped_aliases_are_supported(self):
        env = {"OCI_PROFILE": "DEFAULT"}
        env_file = {
            "OCI_PROFILE": "cap",
            "COMP_OBSERVABILITY": "cap-compartment",
            "DEFAULT_COMP_OBSERVABILITY": "default-compartment",
        }

        value = oci_config._cfg(
            "OCI_COMPARTMENT_ID",
            "",
            aliases=("COMP_OBSERVABILITY",),
            profile_bound=True,
            profile="DEFAULT",
            env=env,
            env_file=env_file,
        )

        self.assertEqual(value, "default-compartment")

    def test_non_profile_bound_values_can_fall_back_to_env_local(self):
        env = {"OCI_PROFILE": "DEFAULT"}
        env_file = {
            "OCI_PROFILE": "cap",
            "OCI_REGION": "eu-frankfurt-1",
        }

        value = oci_config._cfg(
            "OCI_REGION",
            "",
            env=env,
            env_file=env_file,
        )

        self.assertEqual(value, "eu-frankfurt-1")

    def test_validate_query_files_ignores_generated_metadata_artifacts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            queries_dir = Path(tmpdir)
            (queries_dir / "valid_detection.json").write_text(
                '{"title": "Valid", "query": "* | stats count"}'
            )
            (queries_dir / "sentinel_backlog_priority.json").write_text(
                '{"ranked": []}'
            )
            (queries_dir / "mapping_collisions.json").write_text(
                '{"collisions": []}'
            )

            original_queries_dir = oci_config.QUERIES_DIR
            try:
                oci_config.QUERIES_DIR = str(queries_dir)
                results = oci_config.validate_query_files()
            finally:
                oci_config.QUERIES_DIR = original_queries_dir

        self.assertEqual(results, [("Query files", True, "1 files OK")])


if __name__ == "__main__":
    unittest.main()
