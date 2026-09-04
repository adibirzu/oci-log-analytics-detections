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


class TestAssertWriteAllowed(unittest.TestCase):
    """Validate the tenant-neutral production write guard."""

    # A syntactically OCID-shaped value standing in for the LogAnalytics root.
    LA_ROOT = "ocid1.compartment.oc1..aaaaloganalyticsroot"
    LA_CHILD = "ocid1.compartment.oc1..aaaaloganalyticschild"
    OTHER = "ocid1.compartment.oc1..aaaasomeother"
    PROTECTED_ENV = {"OCI_PROTECTED_PROFILE": "production"}

    def _production_env_file(self, **extra):
        env_file = {"OCI_PROFILE": "production"}
        env_file.update(extra)
        return env_file

    def test_production_non_la_compartment_raises_without_override(self):
        env_file = self._production_env_file(LOGANALYTICS_COMPARTMENT_OCID=self.LA_ROOT)
        with self.assertRaises(oci_config.ProdWriteGuardError):
            oci_config.assert_write_allowed(
                self.OTHER, profile="production", env=self.PROTECTED_ENV, env_file=env_file
            )

    def test_production_la_root_compartment_passes(self):
        env_file = self._production_env_file(LOGANALYTICS_COMPARTMENT_OCID=self.LA_ROOT)
        # Should not raise.
        oci_config.assert_write_allowed(
            self.LA_ROOT, profile="production", env=self.PROTECTED_ENV, env_file=env_file
        )

    def test_production_configured_child_compartment_passes(self):
        env_file = self._production_env_file(
            LOGANALYTICS_COMPARTMENT_OCID=self.LA_ROOT,
            LOGANALYTICS_COMPARTMENT_IDS=f"{self.LA_CHILD}, {self.OTHER}",
        )
        oci_config.assert_write_allowed(
            self.LA_CHILD, profile="production", env=self.PROTECTED_ENV, env_file=env_file
        )

    def test_production_non_la_compartment_passes_with_override_flag(self):
        env_file = self._production_env_file(LOGANALYTICS_COMPARTMENT_OCID=self.LA_ROOT)
        oci_config.assert_write_allowed(
            self.OTHER, profile="production", override=True, env={}, env_file=env_file
        )

    def test_production_non_la_compartment_passes_with_override_env(self):
        env_file = self._production_env_file(LOGANALYTICS_COMPARTMENT_OCID=self.LA_ROOT)
        oci_config.assert_write_allowed(
            self.OTHER,
            profile="production",
            env={"OCI_ALLOW_PROD_WRITE": "1", **self.PROTECTED_ENV},
            env_file=env_file,
        )

    def test_production_fails_closed_when_la_root_unconfigured(self):
        # No LogAnalytics allow-set configured → production write must be refused.
        env_file = self._production_env_file()
        with self.assertRaises(oci_config.ProdWriteGuardError):
            oci_config.assert_write_allowed(
                self.LA_ROOT, profile="production", env=self.PROTECTED_ENV, env_file=env_file
            )

    def test_production_fails_closed_with_empty_compartment(self):
        env_file = self._production_env_file(LOGANALYTICS_COMPARTMENT_OCID=self.LA_ROOT)
        with self.assertRaises(oci_config.ProdWriteGuardError):
            oci_config.assert_write_allowed(
                "", profile="production", env=self.PROTECTED_ENV, env_file=env_file
            )

    def test_staging_profile_is_always_allowed(self):
        # Staging tenancy: full rights, no LogAnalytics config present.
        env_file = {"OCI_PROFILE": "staging"}
        oci_config.assert_write_allowed(
            self.OTHER, profile="staging", env=self.PROTECTED_ENV, env_file=env_file
        )

    def test_default_profile_is_always_allowed(self):
        env_file = {"OCI_PROFILE": "DEFAULT"}
        oci_config.assert_write_allowed(
            self.OTHER, profile="DEFAULT", env=self.PROTECTED_ENV, env_file=env_file
        )

    def test_unknown_profile_is_always_allowed(self):
        oci_config.assert_write_allowed(
            self.OTHER, profile="somerandomprofile", env=self.PROTECTED_ENV, env_file={}
        )

    def test_profile_resolved_from_env_when_not_passed(self):
        # production selected via env (not the profile arg) is still guarded.
        env = {"OCI_PROFILE": "production", **self.PROTECTED_ENV}
        env_file = {"OCI_PROFILE": "production", "LOGANALYTICS_COMPARTMENT_OCID": self.LA_ROOT}
        with self.assertRaises(oci_config.ProdWriteGuardError):
            oci_config.assert_write_allowed(self.OTHER, env=env, env_file=env_file)

    def test_production_root_via_profile_scoped_env_var(self):
        # Operator exports PRODUCTION_LOGANALYTICS_COMPARTMENT_OCID instead of overlay.
        env = {
            "PRODUCTION_LOGANALYTICS_COMPARTMENT_OCID": self.LA_ROOT,
            **self.PROTECTED_ENV,
        }
        env_file = {"OCI_PROFILE": "production"}
        oci_config.assert_write_allowed(
            self.LA_ROOT, profile="production", env=env, env_file=env_file
        )
        with self.assertRaises(oci_config.ProdWriteGuardError):
            oci_config.assert_write_allowed(
                self.OTHER, profile="production", env=env, env_file=env_file
            )

    def test_missing_protected_profile_fails_closed(self):
        with self.assertRaisesRegex(
            oci_config.ProdWriteGuardError, "OCI_PROTECTED_PROFILE"
        ):
            oci_config.assert_write_allowed(
                self.OTHER, profile="staging", env={}, env_file={}
            )

    def test_protected_profile_comparison_is_case_insensitive(self):
        env_file = self._production_env_file(
            LOGANALYTICS_COMPARTMENT_OCID=self.LA_ROOT
        )
        with self.assertRaises(oci_config.ProdWriteGuardError):
            oci_config.assert_write_allowed(
                self.OTHER,
                profile="production",
                env={"OCI_PROTECTED_PROFILE": "Production"},
                env_file=env_file,
            )


if __name__ == "__main__":
    unittest.main()
