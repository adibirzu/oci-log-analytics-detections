#!/usr/bin/env python3
"""Contract and behavior tests for root orca.yaml, scripts/orca_setup.py, and scripts/orca_setup_env.py."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
ORCA_YAML = REPO_ROOT / "orca.yaml"
SETUP_SCRIPT = REPO_ROOT / "scripts" / "orca_setup.py"
ENV_SCRIPT = REPO_ROOT / "scripts" / "orca_setup_env.py"
CANONICAL_TMP = Path(os.path.realpath(tempfile.gettempdir()))
SECRET_MARKER = "SYNTHETIC_OCI_LA_ORCA_SECRET_DO_NOT_LOG_9f41"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _init_git_repo(directory: Path, gitignore: str | None = None) -> None:
    if gitignore is None:
        gitignore = (
            ".env\n"
            ".env.local\n"
            ".env.local.*\n"
            "!.env.local.example\n"
            ".venv/\n"
            "__pycache__/\n"
            "webapp/node_modules/\n"
            "webapp/.env*\n"
        )
    (directory / ".gitignore").write_text(gitignore, encoding="utf-8")
    r = subprocess.run(["git", "init", "-q", "-b", "main", "."], cwd=directory, capture_output=True, text=True)
    if r.returncode != 0:
        raise AssertionError(f"git init failed: {r.stderr}")
    identity = ["-c", "user.name=Orca Test", "-c", "user.email=orca-test@example.invalid"]
    subprocess.run(["git", "add", ".gitignore"], cwd=directory, check=True, capture_output=True, text=True)
    subprocess.run(
        ["git", *identity, "commit", "-q", "-m", "fixture: init"],
        cwd=directory,
        check=True,
        capture_output=True,
        text=True,
    )


def _has_mkfifo() -> bool:
    if not hasattr(os, "mkfifo"):
        return False
    probe_dir = Path(tempfile.mkdtemp(prefix="ocila-fifo-probe-", dir=CANONICAL_TMP))
    try:
        os.mkfifo(probe_dir / "probe.fifo")
        return True
    except OSError:
        return False
    finally:
        shutil.rmtree(probe_dir, ignore_errors=True)


HAS_MKFIFO = _has_mkfifo()


class OrcaYamlContractTests(unittest.TestCase):
    def test_orca_yaml_exists_and_follows_strict_schema(self) -> None:
        self.assertTrue(ORCA_YAML.is_file(), f"missing {ORCA_YAML}")
        raw = ORCA_YAML.read_text(encoding="utf-8")
        doc = yaml.safe_load(raw)
        self.assertIsInstance(doc, dict)
        self.assertEqual(set(doc.keys()), {"scripts", "setupAgentStartupPolicy"})
        self.assertEqual(doc["setupAgentStartupPolicy"], "start-immediately")
        scripts = doc["scripts"]
        self.assertIsInstance(scripts, dict)
        self.assertIn("setup", scripts)
        self.assertIn("scripts/orca_setup.py", str(scripts["setup"]))

    def test_orca_yaml_never_shares_writable_dependency_dirs(self) -> None:
        self.assertTrue(ORCA_YAML.is_file(), f"missing {ORCA_YAML}")
        raw = ORCA_YAML.read_text(encoding="utf-8")
        doc = yaml.safe_load(raw)
        self.assertNotIn("sharedDirectories", doc)
        self.assertNotIn("worktree", doc)
        self.assertNotIn("sharedDirectories", raw)
        for line in raw.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            self.assertNotIn(".venv", stripped)
            self.assertNotIn("node_modules", stripped)


class OrcaEnvHydrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmps: list[tempfile.TemporaryDirectory[str]] = []

    def tearDown(self) -> None:
        for td in reversed(self._tmps):
            td.cleanup()

    def _tempdir(self, prefix: str) -> Path:
        td = tempfile.TemporaryDirectory(prefix=f"ocila-orca-{prefix}-", dir=str(CANONICAL_TMP))
        self._tmps.append(td)
        return Path(td.name)

    def _run_hydrate(
        self,
        root_path: str | Path | None,
        worktree_path: str | Path,
        *,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        self.assertTrue(SETUP_SCRIPT.is_file(), f"missing {SETUP_SCRIPT}")
        env = dict(os.environ)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["OCI_LA_ORCA_SKIP_INSTALL"] = "1"
        if root_path is None:
            env.pop("ORCA_ROOT_PATH", None)
        else:
            env["ORCA_ROOT_PATH"] = str(root_path)
        env["ORCA_WORKTREE_PATH"] = str(worktree_path)
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            [sys.executable, str(SETUP_SCRIPT), "--hydrate-only"],
            cwd=str(REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

    def test_hydrates_gitignored_env_files_0600_without_logging_values(self) -> None:
        src = self._tempdir("src")
        _init_git_repo(src)
        (src / ".env").write_text(f"TOKEN={SECRET_MARKER}\n", encoding="utf-8")
        (src / ".env.local").write_text(f"LOCAL_VAL={SECRET_MARKER}\n", encoding="utf-8")
        (src / ".env.local.example").write_text("PUBLIC_TEMPLATE=1\n", encoding="utf-8")
        (src / "webapp").mkdir()
        (src / "webapp" / ".env.local").write_text(f"WEB={SECRET_MARKER}\n", encoding="utf-8")

        wt = self._tempdir("wt")
        _init_git_repo(wt)
        (wt / "webapp").mkdir()

        res = self._run_hydrate(src, wt)
        self.assertEqual(res.returncode, 0, res.stderr)

        for rel in (".env", ".env.local", "webapp/.env.local"):
            dest = wt / rel
            st = os.lstat(dest)
            self.assertTrue(stat.S_ISREG(st.st_mode), rel)
            self.assertFalse(stat.S_ISLNK(st.st_mode), rel)
            self.assertEqual(stat.S_IMODE(st.st_mode), 0o600, rel)
            self.assertIn(SECRET_MARKER, dest.read_text(encoding="utf-8"))

        self.assertFalse((wt / ".env.local.example").exists())
        combined = res.stdout + res.stderr
        self.assertNotIn(SECRET_MARKER, combined)
        self.assertNotIn("TOKEN=", combined)
        self.assertNotIn("LOCAL_VAL=", combined)

    def test_missing_orca_root_or_env_is_clean_noop(self) -> None:
        wt = self._tempdir("wt-empty")
        _init_git_repo(wt)

        res1 = self._run_hydrate(None, wt)
        self.assertEqual(res1.returncode, 0, res1.stderr)
        res2 = self._run_hydrate(self._tempdir("missing-parent") / "does-not-exist", wt)
        self.assertEqual(res2.returncode, 0, res2.stderr)
        status = subprocess.run(["git", "status", "--porcelain"], cwd=wt, capture_output=True, text=True, check=True)
        self.assertEqual(status.stdout.strip(), "")

    def test_existing_destination_is_never_overwritten(self) -> None:
        src = self._tempdir("src-keep")
        _init_git_repo(src)
        (src / ".env.local").write_text("NEW=1\n", encoding="utf-8")

        wt = self._tempdir("wt-keep")
        _init_git_repo(wt)
        dest = wt / ".env.local"
        dest.write_text("EXISTING=keep\n", encoding="utf-8")
        os.chmod(dest, 0o640)

        res = self._run_hydrate(src, wt)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(dest.read_text(encoding="utf-8"), "EXISTING=keep\n")
        self.assertEqual(stat.S_IMODE(os.lstat(dest).st_mode), 0o640)

    def test_rejects_symlink_escape_and_traversal_with_o_nofollow(self) -> None:
        env_mod = _load_module("orca_setup_env", ENV_SCRIPT)
        outside = self._tempdir("outside")
        secret_file = outside / "outside-secret.txt"
        secret_file.write_text(f"OUTSIDE={SECRET_MARKER}\n", encoding="utf-8")

        src = self._tempdir("src-sym")
        _init_git_repo(src)
        (src / ".env").symlink_to(secret_file)
        (src / "webapp").symlink_to(outside)

        wt = self._tempdir("wt-sym")
        _init_git_repo(wt)
        (wt / "webapp").mkdir()

        # Direct API check: traversal & symlinked root must raise UnsafePathError
        with self.assertRaises(env_mod.UnsafePathError):
            env_mod.open_verified_dir(f"{src}/../{src.name}", "ORCA_ROOT_PATH")
        sym_root = self._tempdir("sym-root-parent") / "link"
        sym_root.symlink_to(src)
        with self.assertRaises(env_mod.UnsafePathError):
            env_mod.open_verified_dir(str(sym_root), "ORCA_ROOT_PATH")

        # CLI hydration must refuse symlinked .env and symlinked webapp/ without copying
        res = self._run_hydrate(src, wt)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertFalse((wt / ".env").exists())
        self.assertFalse((wt / "webapp" / ".env").exists())
        self.assertNotIn(SECRET_MARKER, res.stdout + res.stderr)
        self.assertIn("refus", (res.stdout + res.stderr).lower())

        # Symlinked ORCA_ROOT_PATH itself must be refused by CLI as well
        res_sym_root = self._run_hydrate(sym_root, wt)
        self.assertEqual(res_sym_root.returncode, 0, res_sym_root.stderr)
        self.assertIn("refus", (res_sym_root.stdout + res_sym_root.stderr).lower())

    @unittest.skipUnless(HAS_MKFIFO, "mkfifo unavailable on platform")
    def test_rejects_fifo_non_regular_source_without_blocking(self) -> None:
        src = self._tempdir("src-fifo")
        _init_git_repo(src)
        os.mkfifo(src / ".env")

        wt = self._tempdir("wt-fifo")
        _init_git_repo(wt)

        res = self._run_hydrate(src, wt)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertFalse((wt / ".env").exists())
        self.assertIn("refus", (res.stdout + res.stderr).lower())

    def test_never_touches_oci_or_kube_home_directories(self) -> None:
        fake_home = self._tempdir("fake-home")
        (fake_home / ".oci").mkdir(mode=0o700)
        (fake_home / ".oci" / "config").write_text("user=ocid1.user.oc1..fake\n", encoding="utf-8")
        (fake_home / ".kube").mkdir(mode=0o700)
        (fake_home / ".kube" / "config").write_text("apiVersion: v1\n", encoding="utf-8")

        src = self._tempdir("src-nohome")
        _init_git_repo(src)
        wt = self._tempdir("wt-nohome")
        _init_git_repo(wt)

        res = self._run_hydrate(src, wt, extra_env={"HOME": str(fake_home)})
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertFalse((wt / ".oci").exists())
        self.assertFalse((wt / ".kube").exists())
        self.assertEqual((fake_home / ".oci" / "config").read_text(encoding="utf-8"), "user=ocid1.user.oc1..fake\n")
        self.assertEqual((fake_home / ".kube" / "config").read_text(encoding="utf-8"), "apiVersion: v1\n")

    def test_rejects_hardlinked_env_source_and_destination(self) -> None:
        env_mod = _load_module("orca_setup_env", ENV_SCRIPT)
        outside = self._tempdir("outside-hardlink")
        outside_secret = outside / "secret.txt"
        outside_secret.write_text(f"OUTSIDE={SECRET_MARKER}\n", encoding="utf-8")

        src = self._tempdir("src-hardlink")
        _init_git_repo(src)
        os.link(outside_secret, src / ".env")
        self.assertGreaterEqual(os.lstat(src / ".env").st_nlink, 2)

        wt = self._tempdir("wt-hardlink")
        _init_git_repo(wt)

        # CLI hydration must refuse hardlinked source without copying or logging secret
        res = self._run_hydrate(src, wt)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertFalse((wt / ".env").exists())
        self.assertNotIn(SECRET_MARKER, res.stdout + res.stderr)
        self.assertIn("refus", (res.stdout + res.stderr).lower())

        # Direct API check must fail closed on hardlinked source and hardlinked destination
        src_fd, _ = env_mod.open_verified_dir(str(src), "src")
        wt_fd, _ = env_mod.open_verified_dir(str(wt), "wt")
        try:
            with self.assertRaises(env_mod.UnsafePathError):
                env_mod._copy_env_file_fd(src_fd, wt_fd, ".env")
        finally:
            os.close(src_fd)
            os.close(wt_fd)

        src2 = self._tempdir("src-hardlink-dst")
        _init_git_repo(src2)
        (src2 / ".env").write_text("SAFE=1\n", encoding="utf-8")

        wt2 = self._tempdir("wt-hardlink-dst")
        _init_git_repo(wt2)
        os.link(outside_secret, wt2 / ".env")
        self.assertGreaterEqual(os.lstat(wt2 / ".env").st_nlink, 2)

        src2_fd, _ = env_mod.open_verified_dir(str(src2), "src2")
        wt2_fd, _ = env_mod.open_verified_dir(str(wt2), "wt2")
        try:
            with self.assertRaises(env_mod.UnsafePathError):
                env_mod._copy_env_file_fd(src2_fd, wt2_fd, ".env")
        finally:
            os.close(src2_fd)
            os.close(wt2_fd)

        res_dst = self._run_hydrate(src2, wt2)
        self.assertEqual(res_dst.returncode, 0, res_dst.stderr)
        self.assertIn("refus", (res_dst.stdout + res_dst.stderr).lower())
        self.assertEqual(outside_secret.read_text(encoding="utf-8"), f"OUTSIDE={SECRET_MARKER}\n")


class OrcaStackSetupTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmps: list[tempfile.TemporaryDirectory[str]] = []

    def tearDown(self) -> None:
        for td in reversed(self._tmps):
            td.cleanup()

    def _tempdir(self, prefix: str) -> Path:
        td = tempfile.TemporaryDirectory(prefix=f"ocila-stack-{prefix}-", dir=str(CANONICAL_TMP))
        self._tmps.append(td)
        return Path(td.name)

    def _create_fixture_worktree(self) -> tuple[Path, Path, Path]:
        base = self._tempdir("wt-fixture")
        main = base / "main"
        main.mkdir()
        _init_git_repo(main)
        for req in ("requirements.txt", "requirements-dev.txt", "requirements-mcp.txt", "requirements-hunting-test.txt"):
            (main / req).write_text("pyyaml>=6.0\n", encoding="utf-8")
        web = main / "webapp"
        web.mkdir()
        (web / "package.json").write_text(
            json.dumps({"name": "fixture-web", "private": True, "dependencies": {"zod": "^3.24.1"}}) + "\n",
            encoding="utf-8",
        )
        (web / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\npackages:\n  zod@3.24.1: {}\n", encoding="utf-8")
        identity = ["-c", "user.name=Orca Test", "-c", "user.email=orca-test@example.invalid"]
        subprocess.run(["git", "add", "."], cwd=main, check=True, capture_output=True, text=True)
        subprocess.run(["git", *identity, "commit", "-q", "-m", "fixture: manifests"], cwd=main, check=True, capture_output=True, text=True)

        linked = base / "linked"
        subprocess.run(["git", "worktree", "add", "-q", "-b", "feat/test", str(linked)], cwd=main, check=True, capture_output=True, text=True)

        bindir = base / "bin"
        bindir.mkdir()
        return main, linked, bindir

    def _install_fake_toolchains(self, bindir: Path, counter_dir: Path) -> None:
        # Fake uv that creates a real venv using sys.executable and drops sentinel marker modules
        uv_script = bindir / "uv"
        uv_script.write_text(
            f"""#!{sys.executable}
import os, sys, subprocess
from pathlib import Path

args = sys.argv[1:]
counter = Path({str(counter_dir)!r}) / "uv_calls.txt"
with counter.open("a", encoding="utf-8") as fh:
    fh.write(" ".join(args) + "\\n")

if args[:1] == ["venv"]:
    venv_dir = Path(args[-1])
    subprocess.run([{sys.executable!r}, "-m", "venv", "--without-pip", str(venv_dir)], check=True)
elif args[:2] == ["pip", "install"]:
    py = Path(args[args.index("--python") + 1])
    venv_root = py.parent.parent
    site = next(venv_root.glob("lib/python*/site-packages"))
    for mod in ("oci", "yaml", "dotenv", "jsonschema", "pytest", "hypothesis", "mcp"):
        (site / f"{{mod}}.py").write_text("__version__ = '1.0'\\n", encoding="utf-8")
else:
    sys.exit(2)
""",
            encoding="utf-8",
        )
        os.chmod(uv_script, 0o755)

        node_script = bindir / "node"
        node_script.write_text("#!/bin/sh\necho 'v22.22.3'\n", encoding="utf-8")
        os.chmod(node_script, 0o755)

        pnpm_script = bindir / "pnpm"
        pnpm_script.write_text(
            f"""#!{sys.executable}
import sys
from pathlib import Path

args = sys.argv[1:]
if args == ["--version"]:
    print("10.26.1")
    sys.exit(0)

counter = Path({str(counter_dir)!r}) / "pnpm_calls.txt"
with counter.open("a", encoding="utf-8") as fh:
    fh.write(" ".join(args) + "\\n")

if "install" in args:
    nm = Path.cwd() / "node_modules"
    nm.mkdir(exist_ok=True)
    (nm / ".modules.yaml").write_text("storeDir: /tmp/store\\n", encoding="utf-8")
    for pkg in ("next", "react", "react-dom", "zod", "typescript", "eslint", "@playwright/test"):
        p = nm / pkg
        p.mkdir(parents=True, exist_ok=True)
        (p / "package.json").write_text('{{"name": "' + pkg + '", "version": "1.0.0"}}', encoding="utf-8")
""",
            encoding="utf-8",
        )
        os.chmod(pnpm_script, 0o755)

    def test_cold_setup_and_warm_idempotency_with_clean_git_status(self) -> None:
        self.assertTrue(SETUP_SCRIPT.is_file(), f"missing {SETUP_SCRIPT}")
        main, linked, bindir = self._create_fixture_worktree()
        counts = self._tempdir("counts")
        self._install_fake_toolchains(bindir, counts)

        env = dict(os.environ)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PATH"] = f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}"
        env["ORCA_ROOT_PATH"] = str(main)
        env["ORCA_WORKTREE_PATH"] = str(linked)
        env["OCI_LA_ORCA_BASE_PYTHON"] = sys.executable

        # Cold run
        cold = subprocess.run(
            [sys.executable, str(SETUP_SCRIPT)],
            cwd=str(linked),
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(cold.returncode, 0, cold.stdout + cold.stderr)
        self.assertTrue((linked / ".venv" / ".orca-setup-stamp.json").is_file())
        self.assertTrue((linked / "webapp" / "node_modules" / ".orca-setup-stamp.json").is_file())
        self.assertFalse((linked / ".venv").is_symlink())
        self.assertFalse((linked / "webapp" / "node_modules").is_symlink())

        # Clean git status
        st = subprocess.run(["git", "status", "--porcelain"], cwd=linked, capture_output=True, text=True, check=True)
        self.assertEqual(st.stdout.strip(), "", f"dirty git status: {st.stdout}")

        uv_calls_after_cold = (counts / "uv_calls.txt").read_text(encoding="utf-8").splitlines()
        pnpm_calls_after_cold = (counts / "pnpm_calls.txt").read_text(encoding="utf-8").splitlines()
        self.assertGreaterEqual(len(uv_calls_after_cold), 2)
        self.assertEqual(len(pnpm_calls_after_cold), 1)

        # Warm repeat run must be idempotent and skip reinstalls
        warm = subprocess.run(
            [sys.executable, str(SETUP_SCRIPT)],
            cwd=str(linked),
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(warm.returncode, 0, warm.stdout + warm.stderr)
        self.assertEqual(
            len((counts / "uv_calls.txt").read_text(encoding="utf-8").splitlines()),
            len(uv_calls_after_cold),
            "warm run unexpectedly re-invoked uv",
        )
        self.assertEqual(
            len((counts / "pnpm_calls.txt").read_text(encoding="utf-8").splitlines()),
            len(pnpm_calls_after_cold),
            "warm run unexpectedly re-invoked pnpm",
        )

    def test_refuses_symlinked_venv_and_node_modules(self) -> None:
        self.assertTrue(SETUP_SCRIPT.is_file(), f"missing {SETUP_SCRIPT}")
        main, linked, bindir = self._create_fixture_worktree()
        counts = self._tempdir("counts-sym")
        self._install_fake_toolchains(bindir, counts)
        outside_dir = self._tempdir("outside-deps")

        env = dict(os.environ)
        env["PATH"] = f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}"
        env["ORCA_ROOT_PATH"] = str(main)
        env["ORCA_WORKTREE_PATH"] = str(linked)
        env["OCI_LA_ORCA_BASE_PYTHON"] = sys.executable

        (linked / ".venv").symlink_to(outside_dir)
        res_venv = subprocess.run(
            [sys.executable, str(SETUP_SCRIPT)],
            cwd=str(linked),
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertNotEqual(res_venv.returncode, 0)
        self.assertIn("symlink", (res_venv.stdout + res_venv.stderr).lower())

        (linked / ".venv").unlink()
        (linked / "webapp" / "node_modules").symlink_to(outside_dir)
        res_nm = subprocess.run(
            [sys.executable, str(SETUP_SCRIPT)],
            cwd=str(linked),
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertNotEqual(res_nm.returncode, 0)
        self.assertIn("symlink", (res_nm.stdout + res_nm.stderr).lower())

    def test_fails_loudly_when_required_toolchain_missing(self) -> None:
        self.assertTrue(SETUP_SCRIPT.is_file(), f"missing {SETUP_SCRIPT}")
        main, linked, bindir = self._create_fixture_worktree()
        counts = self._tempdir("counts-missing")
        self._install_fake_toolchains(bindir, counts)

        # Missing Python interpreter override
        env_bad_py = dict(os.environ)
        env_bad_py["ORCA_ROOT_PATH"] = str(main)
        env_bad_py["ORCA_WORKTREE_PATH"] = str(linked)
        env_bad_py["OCI_LA_ORCA_BASE_PYTHON"] = "/nonexistent/python3.99"
        res_py = subprocess.run(
            [sys.executable, str(SETUP_SCRIPT)],
            cwd=str(linked),
            env=env_bad_py,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertNotEqual(res_py.returncode, 0)
        self.assertTrue((res_py.stdout + res_py.stderr).strip())

        # Missing pnpm with webapp/pnpm-lock.yaml present (restrict PATH so pnpm is absent)
        (bindir / "pnpm").unlink()
        minimal_bin = self._tempdir("minbin")
        for tool in ("git",):
            found = shutil.which(tool)
            if found:
                (minimal_bin / tool).symlink_to(found)
        env_no_pnpm = dict(os.environ)
        env_no_pnpm["PATH"] = f"{bindir}{os.pathsep}{minimal_bin}"
        env_no_pnpm["ORCA_ROOT_PATH"] = str(main)
        env_no_pnpm["ORCA_WORKTREE_PATH"] = str(linked)
        env_no_pnpm["OCI_LA_ORCA_BASE_PYTHON"] = sys.executable
        res_pnpm = subprocess.run(
            [sys.executable, str(SETUP_SCRIPT)],
            cwd=str(linked),
            env=env_no_pnpm,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertNotEqual(res_pnpm.returncode, 0)
        self.assertIn("pnpm", (res_pnpm.stdout + res_pnpm.stderr).lower())

    def test_corrupt_stamped_venv_syntax_invalidates_stamp_and_rebuilds(self) -> None:
        main, linked, bindir = self._create_fixture_worktree()
        counts = self._tempdir("counts-corrupt-venv")
        self._install_fake_toolchains(bindir, counts)

        env = dict(os.environ)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PATH"] = f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}"
        env["ORCA_ROOT_PATH"] = str(main)
        env["ORCA_WORKTREE_PATH"] = str(linked)
        env["OCI_LA_ORCA_BASE_PYTHON"] = sys.executable

        cold = subprocess.run(
            [sys.executable, str(SETUP_SCRIPT)],
            cwd=str(linked),
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(cold.returncode, 0, cold.stdout + cold.stderr)
        cold_uv_calls = len((counts / "uv_calls.txt").read_text(encoding="utf-8").splitlines())

        # Corrupt a core runtime module inside the stamped .venv with invalid Python syntax
        site = next((linked / ".venv").glob("lib/python*/site-packages"))
        yaml_mod = site / "yaml.py"
        yaml_mod.write_text("def broken(:\n    pass\n", encoding="utf-8")
        self.assertTrue((linked / ".venv" / ".orca-setup-stamp.json").is_file())

        repaired = subprocess.run(
            [sys.executable, str(SETUP_SCRIPT)],
            cwd=str(linked),
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(repaired.returncode, 0, repaired.stdout + repaired.stderr)
        after_repair_uv_calls = len((counts / "uv_calls.txt").read_text(encoding="utf-8").splitlines())
        self.assertGreater(
            after_repair_uv_calls,
            cold_uv_calls,
            "corrupt stamped .venv must invalidate stamp and trigger rebuild",
        )
        vpy = linked / ".venv" / "bin" / "python"
        imp = subprocess.run(
            [str(vpy), "-c", "import yaml"],
            cwd=str(linked),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(imp.returncode, 0, imp.stderr)

        # Subsequent warm run is idempotent again
        warm = subprocess.run(
            [sys.executable, str(SETUP_SCRIPT)],
            cwd=str(linked),
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(warm.returncode, 0, warm.stdout + warm.stderr)
        self.assertEqual(
            len((counts / "uv_calls.txt").read_text(encoding="utf-8").splitlines()),
            after_repair_uv_calls,
        )

    def test_corrupt_stamped_node_modules_json_invalidates_stamp_and_rebuilds(self) -> None:
        main, linked, bindir = self._create_fixture_worktree()
        counts = self._tempdir("counts-corrupt-nm")
        self._install_fake_toolchains(bindir, counts)

        env = dict(os.environ)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PATH"] = f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}"
        env["ORCA_ROOT_PATH"] = str(main)
        env["ORCA_WORKTREE_PATH"] = str(linked)
        env["OCI_LA_ORCA_BASE_PYTHON"] = sys.executable

        cold = subprocess.run(
            [sys.executable, str(SETUP_SCRIPT)],
            cwd=str(linked),
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(cold.returncode, 0, cold.stdout + cold.stderr)
        self.assertEqual(len((counts / "pnpm_calls.txt").read_text(encoding="utf-8").splitlines()), 1)

        # Case 1: invalid JSON syntax in a required dependency's package.json
        zod_pkg = linked / "webapp" / "node_modules" / "zod" / "package.json"
        zod_pkg.write_text("{corrupt-json", encoding="utf-8")

        repaired1 = subprocess.run(
            [sys.executable, str(SETUP_SCRIPT)],
            cwd=str(linked),
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(repaired1.returncode, 0, repaired1.stdout + repaired1.stderr)
        self.assertEqual(
            len((counts / "pnpm_calls.txt").read_text(encoding="utf-8").splitlines()),
            2,
            "invalid JSON in stamped node_modules must trigger clean pnpm reinstall",
        )
        zod_data = json.loads(zod_pkg.read_text(encoding="utf-8"))
        self.assertIsInstance(zod_data, dict)
        self.assertEqual(zod_data.get("name"), "zod")

        # Case 2: non-object JSON in a required dependency's package.json
        next_pkg = linked / "webapp" / "node_modules" / "next" / "package.json"
        next_pkg.write_text("[]", encoding="utf-8")

        repaired2 = subprocess.run(
            [sys.executable, str(SETUP_SCRIPT)],
            cwd=str(linked),
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(repaired2.returncode, 0, repaired2.stdout + repaired2.stderr)
        self.assertEqual(len((counts / "pnpm_calls.txt").read_text(encoding="utf-8").splitlines()), 3)
        next_data = json.loads(next_pkg.read_text(encoding="utf-8"))
        self.assertIsInstance(next_data, dict)
        self.assertEqual(next_data.get("name"), "next")

        # Warm repeat is idempotent again
        warm = subprocess.run(
            [sys.executable, str(SETUP_SCRIPT)],
            cwd=str(linked),
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(warm.returncode, 0, warm.stdout + warm.stderr)
        self.assertEqual(len((counts / "pnpm_calls.txt").read_text(encoding="utf-8").splitlines()), 3)

    def test_strict_json_parsing_rejects_nonfinite_constants(self) -> None:
        setup_mod = _load_module("orca_setup", SETUP_SCRIPT)
        for bad_constant in ("NaN", "Infinity", "-Infinity"):
            with self.assertRaises(ValueError):
                setup_mod._strict_json_loads(f'{{"name": "zod", "version": {bad_constant}}}')

        tmp = self._tempdir("strict-json")
        stamp_path = tmp / ".orca-setup-stamp.json"
        for bad_constant in ("NaN", "Infinity", "-Infinity"):
            stamp_path.write_text(f'{{"fingerprint": {bad_constant}}}', encoding="utf-8")
            self.assertFalse(setup_mod._stamp_matches(stamp_path, "anything"))

    def test_nonfinite_json_constants_in_stamped_node_modules_invalidate_stamp_and_rebuild(self) -> None:
        setup_mod = _load_module("orca_setup", SETUP_SCRIPT)
        main, linked, bindir = self._create_fixture_worktree()
        counts = self._tempdir("counts-nonfinite-nm")
        self._install_fake_toolchains(bindir, counts)

        env = dict(os.environ)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PATH"] = f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}"
        env["ORCA_ROOT_PATH"] = str(main)
        env["ORCA_WORKTREE_PATH"] = str(linked)
        env["OCI_LA_ORCA_BASE_PYTHON"] = sys.executable

        cold = subprocess.run(
            [sys.executable, str(SETUP_SCRIPT)],
            cwd=str(linked),
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(cold.returncode, 0, cold.stdout + cold.stderr)
        self.assertEqual(len((counts / "pnpm_calls.txt").read_text(encoding="utf-8").splitlines()), 1)

        # Corrupt stamped dependency package.json with non-finite JSON constants that Python's
        # default json.loads accepts but Node's JSON.parse rejects.
        cases = (
            ("zod", '{"name":"zod","version":NaN}'),
            ("next", '{"name":"next","version":Infinity}'),
            ("react", '{"name":"react","version":-Infinity}'),
        )
        for idx, (pkg, payload) in enumerate(cases, start=2):
            pkg_json = linked / "webapp" / "node_modules" / pkg / "package.json"
            pkg_json.write_text(payload, encoding="utf-8")
            self.assertFalse(
                setup_mod._installed_pnpm_tree_ok(linked / "webapp" / "node_modules"),
                f"{pkg}/package.json with {payload} must fail strict JSON tree validation",
            )

            repaired = subprocess.run(
                [sys.executable, str(SETUP_SCRIPT)],
                cwd=str(linked),
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(repaired.returncode, 0, repaired.stdout + repaired.stderr)
            self.assertEqual(
                len((counts / "pnpm_calls.txt").read_text(encoding="utf-8").splitlines()),
                idx,
                f"non-finite JSON in {pkg}/package.json must invalidate stamp and trigger reinstall",
            )
            repaired_data = json.loads(pkg_json.read_text(encoding="utf-8"))
            self.assertIsInstance(repaired_data, dict)
            self.assertEqual(repaired_data.get("name"), pkg)

        # Warm repeat is idempotent again
        warm = subprocess.run(
            [sys.executable, str(SETUP_SCRIPT)],
            cwd=str(linked),
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(warm.returncode, 0, warm.stdout + warm.stderr)
        self.assertEqual(len((counts / "pnpm_calls.txt").read_text(encoding="utf-8").splitlines()), len(cases) + 1)

    def test_shared_monotonic_deadline_caps_serial_fallbacks(self) -> None:
        main, linked, bindir = self._create_fixture_worktree()
        counts = self._tempdir("counts-deadline")
        self._install_fake_toolchains(bindir, counts)

        # Override fake uv so --offline sleeps 1.1s and fails, then online fallback tries to sleep 5.0s.
        # With a 2.0s shared end-to-end budget, online fallback must be capped by remaining (~0.9s)
        # and fail loudly without summing past the deadline.
        uv_script = bindir / "uv"
        uv_script.write_text(
            f"""#!{sys.executable}
import subprocess, sys, time
from pathlib import Path

args = sys.argv[1:]
counter = Path({str(counts)!r}) / "uv_calls.txt"
with counter.open("a", encoding="utf-8") as fh:
    fh.write(" ".join(args) + "\\n")

if args[:1] == ["venv"]:
    subprocess.run([{sys.executable!r}, "-m", "venv", "--without-pip", str(Path(args[-1]))], check=True)
elif args[:2] == ["pip", "install"]:
    if "--offline" in args:
        time.sleep(1.1)
        sys.exit(1)
    time.sleep(5.0)
    sys.exit(0)
else:
    sys.exit(2)
""",
            encoding="utf-8",
        )
        os.chmod(uv_script, 0o755)

        env = dict(os.environ)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PATH"] = f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}"
        env["ORCA_ROOT_PATH"] = str(main)
        env["ORCA_WORKTREE_PATH"] = str(linked)
        env["OCI_LA_ORCA_BASE_PYTHON"] = sys.executable
        env["OCI_LA_ORCA_SETUP_TIMEOUT_S"] = "2.0"

        t0 = time.monotonic()
        res_env = subprocess.run(
            [sys.executable, str(SETUP_SCRIPT)],
            cwd=str(linked),
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        elapsed_env = time.monotonic() - t0
        self.assertNotEqual(res_env.returncode, 0, "exhausted E2E deadline must fail loudly")
        self.assertLess(elapsed_env, 4.0, f"serial fallback exceeded shared budget: {elapsed_env:.2f}s")
        combined_env = (res_env.stdout + res_env.stderr).lower()
        self.assertTrue(
            "timeout" in combined_env or "deadline" in combined_env,
            f"expected explicit timeout diagnostic, got: {res_env.stdout + res_env.stderr}",
        )
        self.assertFalse((counts / "pnpm_calls.txt").exists(), "must not run pnpm after deadline exhausted")

        # Also verify CLI --timeout when first attempt itself exhausts deadline (must not start fallback)
        (counts / "uv_calls.txt").unlink()
        shutil.rmtree(linked / ".venv", ignore_errors=True)
        uv_script.write_text(
            f"""#!{sys.executable}
import subprocess, sys, time
from pathlib import Path

args = sys.argv[1:]
counter = Path({str(counts)!r}) / "uv_calls.txt"
with counter.open("a", encoding="utf-8") as fh:
    fh.write(" ".join(args) + "\\n")

if args[:1] == ["venv"]:
    subprocess.run([{sys.executable!r}, "-m", "venv", "--without-pip", str(Path(args[-1]))], check=True)
elif args[:2] == ["pip", "install"]:
    time.sleep(3.5)
    sys.exit(1)
else:
    sys.exit(2)
""",
            encoding="utf-8",
        )
        os.chmod(uv_script, 0o755)
        env_cli = dict(env)
        env_cli.pop("OCI_LA_ORCA_SETUP_TIMEOUT_S", None)

        t1 = time.monotonic()
        res_cli = subprocess.run(
            [sys.executable, str(SETUP_SCRIPT), "--timeout", "1.5"],
            cwd=str(linked),
            env=env_cli,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        elapsed_cli = time.monotonic() - t1
        self.assertNotEqual(res_cli.returncode, 0)
        self.assertLess(elapsed_cli, 3.0, f"--timeout 1.5 took too long: {elapsed_cli:.2f}s")
        uv_calls_cli = (counts / "uv_calls.txt").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(uv_calls_cli), 2, f"expected venv + offline only, got: {uv_calls_cli}")


if __name__ == "__main__":
    unittest.main()
