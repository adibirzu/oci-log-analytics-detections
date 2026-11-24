#!/usr/bin/env python3
"""Contract and behavior tests for scripts/orca_setup_env.py and --hydrate-only."""

from __future__ import annotations

import importlib.util
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
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


if __name__ == "__main__":
    unittest.main()
