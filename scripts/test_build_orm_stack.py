#!/usr/bin/env python3
"""Tests for the Resource Manager deployment package builder."""

from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_orm_stack import build_package


class TestBuildOrmStack(unittest.TestCase):
    def _write(self, root: Path, relative_path: str, contents: str = "fixture") -> None:
        target = root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents, encoding="utf-8")

    def _create_minimal_project(self, root: Path) -> None:
        for relative_path in (
            "stack/main.tf",
            "stack/schema.yaml",
            "stack/provisioners.tf",
            "stack/provider.tf",
            "stack/variables.tf",
            "scripts/deploy_dashboard.py",
            "scripts/setup_log_sources.py",
            "queries/catalog.json",
            "config/sigma_oci_mapping.yaml",
            "schemas/example.schema.json",
            "requirements.txt",
        ):
            self._write(root, relative_path)

    def test_builds_a_portable_package_without_disposable_test_data(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "project"
            root.mkdir()
            self._create_minimal_project(root)
            self._write(root, "test_data/not-for-package.jsonl")
            output = Path(temp_dir) / "oci-log-analytics-deployment.zip"

            manifest = build_package(root, output)

            self.assertEqual(manifest["schema_version"], "1.0.0")
            self.assertTrue(output.exists())
            with zipfile.ZipFile(output) as archive:
                names = set(archive.namelist())
            self.assertIn("stack/main.tf", names)
            self.assertIn("scripts/deploy_dashboard.py", names)
            self.assertIn("queries/catalog.json", names)
            self.assertNotIn("test_data/not-for-package.jsonl", names)

    def test_fails_when_a_required_stack_surface_is_missing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "project"
            root.mkdir()
            self._create_minimal_project(root)
            (root / "stack" / "schema.yaml").unlink()

            with self.assertRaisesRegex(FileNotFoundError, "stack/schema.yaml"):
                build_package(root, Path(temp_dir) / "package.zip")


if __name__ == "__main__":
    unittest.main()
