#!/usr/bin/env python3
"""Tests for the Resource Manager deployment package builder."""

from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path
import sys
import hashlib
import json
import os
import re
import shlex
import subprocess
import textwrap
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_orm_stack import build_package, stage_runtime


class TestBuildOrmStack(unittest.TestCase):
    def test_selected_json_tfvars_refused_before_archive_or_runtime_write(self):
        for mode in ("git", "export"):
            for filename in ("stack/operator.tfvars.json", "stack/operator.auto.tfvars.json"):
                with self.subTest(mode=mode, filename=filename), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary) / "project"
                    root.mkdir()
                    selected = self._create_minimal_project(root)
                    private_bytes = b'{"operator_value":"SYNTHETIC_PRIVATE_FIXTURE"}'
                    (root / filename).write_bytes(private_bytes)
                    selected.append(filename)
                    if mode == "git":
                        subprocess.run(["git", "-C", str(root), "init", "--quiet"], check=True, capture_output=True)
                        subprocess.run(["git", "-C", str(root), "add", "--all"], check=True, capture_output=True)
                    else:
                        (root / ".orm-source-inventory.json").write_text(json.dumps(self._inventory(root, selected)))
                    output = Path(temporary) / "retained.zip"
                    output.write_bytes(b"previous reviewed artifact")
                    with self.assertRaisesRegex(ValueError, "private"):
                        build_package(root, output)
                    self.assertEqual(output.read_bytes(), b"previous reviewed artifact")
                    self.assertNotIn(private_bytes, output.read_bytes())
                    runtime = Path(temporary) / "runtime"
                    with self.assertRaisesRegex(ValueError, "private"):
                        stage_runtime(root, runtime)
                    self.assertFalse(runtime.exists())

    def test_dashboard_query_asset_omission_is_not_a_complete_archive(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "project"
            root.mkdir()
            selected = self._create_minimal_project(root)
            self._write(root, "queries/dashboard_inventory.json", json.dumps({
                "dashboards": [{"widgets": [{"query_file": "apps/required.json"}]}]}))
            selected.append("queries/dashboard_inventory.json")
            output = Path(temporary) / "package.zip"
            with self.assertRaisesRegex(FileNotFoundError, "required.json"):
                build_package(root, output, source_inventory=self._inventory(root, selected))
            self.assertFalse(output.exists())

    def test_cli_refuses_symlink_output_without_resolving_its_target(self):
        project = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "retained.zip"
            target.write_bytes(b"retained artifact")
            link = root / "output.zip"
            link.symlink_to(target)
            result = subprocess.run([sys.executable, str(project / "scripts/build_orm_stack.py"), "--out", str(link)],
                                    cwd=project, capture_output=True, text=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(target.read_bytes(), b"retained artifact")

    def test_extracted_default_commands_reach_only_recording_provider_boundaries(self):
        project = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "package.zip"
            build_package(project, output)
            extracted = root / "extracted"
            with zipfile.ZipFile(output) as archive:
                archive.extractall(extracted)
            harness = root / "recording_boundary.py"
            harness.write_text(textwrap.dedent('''\
                import hashlib, json, pathlib, runpy, subprocess, sys
                from types import SimpleNamespace as NS
                target = pathlib.Path(sys.argv[1]).resolve()
                sys.path.insert(0, str(target.parent))
                import oci_config as cfg
                import oci  # Load SDK model metadata before recording OCI CLI calls.
                calls = []
                class Client:
                    def __getattr__(self, name):
                        def invoke(*args, **kwargs):
                            calls.append(name)
                            if name == 'upsert_field':
                                label = args[1].display_name
                                return NS(data=NS(name='fixture_' + hashlib.sha256(label.encode()).hexdigest()[:12]))
                            if name == 'upsert_parser':
                                return NS(data=args[1])
                            if name.startswith('list_') or name == 'query':
                                return NS(data=NS(items=[]), headers={})
                            if name == 'get_parser':
                                return NS(headers={})
                            if name == 'import_dashboard' or name.startswith('delete_management_'):
                                return None
                            raise AssertionError('unexpected provider method ' + name)
                        return invoke
                client = Client()
                cfg.get_la_client = lambda **kwargs: client
                cfg.get_dashboard_client = lambda **kwargs: client
                cfg.get_namespace = lambda *args, **kwargs: 'fixture-namespace'
                cfg.resolve_compartment_id = lambda *args, **kwargs: 'fixture-compartment'
                cfg.assert_write_allowed = lambda *args, **kwargs: calls.append('scope_check')
                cfg.list_available_log_sources = lambda *args, **kwargs: set()
                cfg.LA_NAMESPACE = 'fixture-namespace'
                cfg.COMPARTMENT_ID = 'fixture-compartment'
                import dashboards.validation as validation
                def recording_query(**kwargs):
                    return validation.validate_query_in_oci(
                        client, kwargs['namespace'], kwargs['query_file'], kwargs['query_string'], kwargs['lookback'], timeout=1)
                validation.validate_query_in_oci_isolated = recording_query
                def recording_cli(command, **kwargs):
                    assert command[:4] == ['oci', 'log-analytics', 'source', 'upsert-source']
                    calls.append('recording_source_cli')
                    return NS(returncode=0, stdout='{}', stderr='')
                subprocess.run = recording_cli
                sys.argv = [str(target), *sys.argv[2:]]
                runpy.run_path(str(target), run_name='__main__')
                print('RECORDING_BOUNDARY=' + json.dumps(calls))
                '''))
            stack = extracted / "stack"
            commands = re.findall(r'"(python3 [^"\n]+)"', (stack / "provisioners.tf").read_text())
            env = {name: os.environ[name] for name in ("HOME", "PATH") if name in os.environ}
            env.update(PYTHON_DOTENV_DISABLED="true", PYTHONDONTWRITEBYTECODE="1")
            for command in commands:
                if "ingest_test_data.py" in command:
                    continue  # Raw fixture data is deliberately not an ORM package asset.
                argv = shlex.split(command.replace("${path.module}", str(stack)))
                result = subprocess.run([sys.executable, str(harness), *argv[1:]], cwd=stack, env=env,
                                        capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout[-2000:] + result.stderr[-2000:])
                marker = next(line for line in result.stdout.splitlines() if line.startswith("RECORDING_BOUNDARY="))
                calls = json.loads(marker.partition("=")[2])
                self.assertIn("scope_check", calls)
                self.assertIn("recording_source_cli" if "setup_log_sources.py" in command else "import_dashboard", calls)

    def test_git_free_inventory_tampering_never_replaces_previous_archive(self):
        for case in ("tampered_bytes", "missing_file", "missing_inventory", "wrong_schema", "private_selection"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "project"
                root.mkdir()
                selected = self._create_minimal_project(root)
                inventory = self._inventory(root, selected)
                manifest = root / ".orm-source-inventory.json"
                if case == "wrong_schema":
                    inventory["schema_version"] = "unknown"
                elif case == "private_selection":
                    self._write(root, "config/.env", "private fixture")
                    inventory = self._inventory(root, selected + ["config/.env"])
                manifest.write_text(json.dumps(inventory))
                if case == "tampered_bytes":
                    (root / "scripts/setup_log_sources.py").write_text("changed = True\n")
                elif case == "missing_file":
                    (root / "scripts/setup_log_sources.py").unlink()
                elif case == "missing_inventory":
                    manifest.unlink()
                output = Path(temporary) / "package.zip"
                output.write_bytes(b"previous reviewed artifact")
                with self.assertRaises((ValueError, FileNotFoundError, subprocess.CalledProcessError)):
                    build_package(root, output)
                self.assertEqual(output.read_bytes(), b"previous reviewed artifact")

    def test_mid_write_failure_keeps_previous_archive_and_removes_scratch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "project"
            root.mkdir()
            selected = self._create_minimal_project(root)
            output = Path(temporary) / "package.zip"
            output.write_bytes(b"previous reviewed artifact")
            original = zipfile.ZipFile.writestr
            calls = []

            def failing_write(archive, *args, **kwargs):
                calls.append(True)
                if len(calls) == 2:
                    raise OSError("synthetic write failure")
                return original(archive, *args, **kwargs)

            with patch.object(zipfile.ZipFile, "writestr", failing_write), self.assertRaises(OSError):
                build_package(root, output, source_inventory=self._inventory(root, selected))
            self.assertEqual(output.read_bytes(), b"previous reviewed artifact")
            self.assertFalse(list(Path(temporary).glob(".orm-*.zip")))

    def test_literal_terraform_assets_cannot_escape_or_be_omitted(self):
        for expression in ('file("${path.module}/../config/runtime.json")',
                           'file("${path.module}/../../outside.json")',
                           'file("${path.module}/../config/../config/runtime.json")'):
            with self.subTest(expression=expression), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "project"
                root.mkdir()
                selected = self._create_minimal_project(root)
                self._write(root, "stack/main.tf", "locals { content = " + expression + " }")
                output = Path(temporary) / "package.zip"
                with self.assertRaises(FileNotFoundError):
                    build_package(root, output, source_inventory=self._inventory(root, selected))
                self.assertFalse(output.exists())

    def test_actual_stager_supplies_git_free_package_caller(self):
        import shutil
        project = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            stage_runtime(project, source)
            self._write(source, "scripts/operator_notes.py", "unselected private fixture")
            self._write(source, "config/operator.local.json", "unselected private fixture")
            (source / "test_data").mkdir()
            (source / "test_data/manifest.json").write_text('{"synthetic": true}')
            stager = root / "app/deploy/oke/stage-detections-runtime.sh"
            stager.parent.mkdir(parents=True)
            shutil.copyfile(project / "webapp/deploy/oke/stage-detections-runtime.sh", stager)
            env = {name: os.environ[name] for name in ("HOME", "PATH") if name in os.environ}
            env.update(LOGAN_DETECTIONS_REPO=str(source), PYTHON_DOTENV_DISABLED="true", PYTHONDONTWRITEBYTECODE="1")
            result = subprocess.run(["bash", str(stager)], cwd=root, env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            runtime = root / "app/.logan-detections-runtime"
            self.assertFalse((runtime / ".git").exists())
            self.assertFalse((runtime / "scripts/operator_notes.py").exists())
            self.assertFalse((runtime / "config/operator.local.json").exists())
            output = root / "runtime-package.zip"
            result = subprocess.run([sys.executable, str(runtime / "scripts/build_orm_stack.py"), "--out", str(output)],
                                    cwd=runtime, env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            with zipfile.ZipFile(output) as archive:
                self.assertIn("requirements.txt", archive.namelist())
                self.assertIn("queries/splunk_detection_registry.json", archive.namelist())
            exported = json.loads((runtime / ".orm-source-inventory.json").read_text())
            self.assertEqual(exported["schema_version"], "forge.orm-source-inventory.v1")
            frozen = (runtime / ".orm-source-inventory.json").read_bytes()
            (source / "scripts/setup_log_sources.py").write_text("tampered = True\n")
            result = subprocess.run(["bash", str(stager)], cwd=root, env=env, capture_output=True, text=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((runtime / ".orm-source-inventory.json").read_bytes(), frozen)
            self.assertFalse(list((root / "app").glob(".logan-detections-stage.*")))

    def test_malformed_export_inventory_paths_are_rejected(self):
        for invalid in ("", "/private/data", "../private", "scripts/../private", "scripts\\private", "scripts/./private", "scripts//private", "scripts/\0private"):
            with self.subTest(path=invalid), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "project"
                root.mkdir()
                selected = self._create_minimal_project(root)
                selected.append(invalid)
                output = Path(temporary) / "package.zip"
                with self.assertRaises(ValueError):
                    build_package(root, output, source_inventory=self._inventory(root, selected))
                self.assertFalse(output.exists())

    def test_imported_local_module_must_belong_to_reviewed_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "project"
            root.mkdir()
            selected = self._create_minimal_project(root)
            self._write(root, "scripts/setup_log_sources.py", "import required_runtime_helper\n")
            self._write(root, "scripts/required_runtime_helper.py", "value = 1\n")
            output = Path(temporary) / "package.zip"
            with self.assertRaisesRegex(FileNotFoundError, "required_runtime_helper"):
                build_package(root, output, source_inventory=self._inventory(root, selected))
            self.assertFalse(output.exists())

    def test_symlink_escape_and_traversal_are_refused_without_reading_target(self):
        for case in ("required_link", "directory_link", "traversal", "special"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "project"
                root.mkdir()
                selected = self._create_minimal_project(root)
                outside = Path(temporary) / "private.py"
                outside.write_text("private context")
                if case == "required_link":
                    (root / "requirements.txt").unlink()
                    (root / "requirements.txt").symlink_to(outside)
                elif case == "directory_link":
                    (root / "scripts" / "escaped").symlink_to(Path(temporary), target_is_directory=True)
                    selected.append("scripts/escaped/private.py")
                elif case == "special":
                    os.mkfifo(root / "scripts" / "private.py")
                    selected.append("scripts/private.py")
                else:
                    selected.append("scripts/../../private.py")
                output = Path(temporary) / "package.zip"
                with self.assertRaises(ValueError):
                    build_package(root, output, source_inventory=self._inventory(root, selected))
                self.assertFalse(output.exists())

    def test_missing_selected_dependency_refuses_before_replacing_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "project"
            root.mkdir()
            selected = self._create_minimal_project(root)
            selected.append("scripts/runtime_dependency.py")
            output = Path(temporary) / "package.zip"
            output.write_bytes(b"previous reviewed artifact")
            with self.assertRaisesRegex(FileNotFoundError, "runtime_dependency"):
                build_package(root, output, source_inventory=self._inventory(root, selected))
            self.assertEqual(output.read_bytes(), b"previous reviewed artifact")

    def test_unselected_private_assets_never_enter_reviewed_archive(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "project"
            root.mkdir()
            self._create_minimal_project(root)
            selected = [p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()]
            self._write(root, "scripts/operator_notes.py", "private operator context")
            self._write(root, "config/tenant.local.json", "private tenant values")
            self._write(root, "stack/.env", "PRIVATE=not-for-package")
            output = Path(temporary) / "package.zip"
            build_package(root, output, source_inventory=self._inventory(root, selected))
            with zipfile.ZipFile(output) as archive:
                self.assertNotIn("scripts/operator_notes.py", archive.namelist())
                self.assertNotIn("config/tenant.local.json", archive.namelist())
                self.assertNotIn("stack/.env", archive.namelist())

    def test_archive_bytes_do_not_depend_on_source_mtime_or_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "project"
            root.mkdir()
            selected = self._create_minimal_project(root)
            first, second = Path(temporary) / "a.zip", Path(temporary) / "b.zip"
            build_package(root, first, source_inventory=self._inventory(root, selected))
            for path in root.rglob("*"):
                if path.is_file():
                    os.utime(path, (1234567890, 1234567890))
                    path.chmod(0o700)
            build_package(root, second, source_inventory=self._inventory(root, selected))
            self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_extracted_provisioner_entrypoints_execute_without_checkout(self):
        project = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "package.zip"
            build_package(project, output)
            extracted = root / "extracted"
            with zipfile.ZipFile(output) as archive:
                archive.extractall(extracted)
            stack = extracted / "stack"
            commands = re.findall(r'"(python3 [^"\n]+)"', (stack / "provisioners.tf").read_text())
            self.assertEqual(len(commands), 4)
            for command in commands:
                argv = shlex.split(command.replace("${path.module}", str(stack)))
                argv[0] = sys.executable
                argv.append("--help" if "ingest_test_data.py" in command else "--dry-run")
                env = {name: os.environ[name] for name in ("HOME", "PATH") if name in os.environ}
                env.update(PYTHON_DOTENV_DISABLED="true", PYTHONDONTWRITEBYTECODE="1")
                result = subprocess.run(argv, cwd=stack, env=env, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout[-2000:] + result.stderr[-2000:])

    def _inventory(self, root, selected):
        files = {}
        for name in selected:
            path = root / name
            safe = name and not name.startswith("/") and not any(x in name for x in ("..", "\\", "\0"))
            safe = safe and not any(root.joinpath(*Path(name).parts[:index]).is_symlink()
                                    for index in range(1, len(Path(name).parts) + 1))
            files[name] = hashlib.sha256(path.read_bytes()).hexdigest() if safe and path.is_file() else "0" * 64
        return {"schema_version": "forge.orm-source-inventory.v1", "files": files}

    def _write(self, root: Path, relative_path: str, contents: str = "fixture") -> None:
        target = root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents, encoding="utf-8")

    def _create_minimal_project(self, root: Path) -> list[str]:
        for relative_path in (
            "stack/main.tf",
            "stack/schema.yaml",
            "stack/provisioners.tf",
            "stack/provider.tf",
            "stack/variables.tf",
            "scripts/deploy_dashboard.py",
            "scripts/setup_log_sources.py",
            "scripts/ingest_test_data.py",
            "queries/catalog.json",
            "queries/dashboard_inventory.json",
            "queries/splunk_detection_registry.json",
            "config/sigma_oci_mapping.yaml",
            "schemas/example.schema.json",
            "requirements.txt",
        ):
            self._write(root, relative_path, "{}" if relative_path.endswith(".json") else "fixture")

        return [p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()]

    def test_builds_a_portable_package_without_disposable_test_data(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "project"
            root.mkdir()
            selected = self._create_minimal_project(root)
            self._write(root, "test_data/not-for-package.jsonl")
            output = Path(temp_dir) / "oci-log-analytics-deployment.zip"

            manifest = build_package(root, output, source_inventory=self._inventory(root, selected))

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
            selected = self._create_minimal_project(root)
            (root / "stack" / "schema.yaml").unlink()

            with self.assertRaisesRegex(FileNotFoundError, "stack/schema.yaml"):
                build_package(root, Path(temp_dir) / "package.zip", source_inventory=self._inventory(root, selected))


if __name__ == "__main__":
    unittest.main()
