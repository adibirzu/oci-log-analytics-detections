#!/usr/bin/env python3
"""Cache-first, idempotent Orca worktree setup for oci-log-analytics-detections.

Provisions isolated per-worktree dependencies (never shared across worktrees):
1. Python ``.venv`` (Python >= 3.11) from root ``requirements*.txt`` using
   ``uv`` cache-first (``--offline`` then online fallback), or ``venv`` + ``pip``.
2. Forge webapp ``webapp/node_modules`` from ``webapp/pnpm-lock.yaml`` using
   ``pnpm install --frozen-lockfile --offline`` (with ``--prefer-offline`` fallback).
3. Safe, descriptor-pinned, non-destructive hydration of gitignored local env
   files from ``$ORCA_ROOT_PATH`` (never touching ``~/.oci`` or ``~/.kube``).
4. Optional toolchain summary (``terraform``, ``gitleaks``, ``shellcheck``).
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import stat
import subprocess
import sys

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from orca_setup_env import (  # noqa: E402
    UnsafePathError,
    hydrate_env,
    log_info,
    log_warn,
    open_verified_dir,
)

MIN_PYTHON = (3, 11)
VENV_DIR = ".venv"
STAMP_NAME = ".orca-setup-stamp.json"
REQ_FILES = (
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-mcp.txt",
    "requirements-hunting-test.txt",
)
REQUIRED_MODULES = (
    "oci",
    "yaml",
    "dotenv",
    "jsonschema",
    "pytest",
    "hypothesis",
    "mcp",
)
REQUIRED_WEB_PACKAGES = (
    "next",
    "react",
    "react-dom",
    "zod",
    "typescript",
    "eslint",
    "@playwright/test",
)
_SKIP_VALUES = {"1", "true", "yes", "on"}
_SUBPROC_TIMEOUT = 110


def _write_json_atomic(path: Path, payload: dict[str, object]) -> None:
    tmp = path.with_name(f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(4)}")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, indent=2) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _stamp_matches(stamp_path: Path, fingerprint: str) -> bool:
    try:
        data = json.loads(stamp_path.read_text(encoding="utf-8"))
        return isinstance(data, dict) and data.get("fingerprint") == fingerprint
    except (OSError, json.JSONDecodeError):
        return False


def _venv_python(venv: Path) -> Path:
    return venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def _probe_python(
    python_bin: Path,
    *,
    expected_venv: Path | None = None,
    check_modules: bool = False,
) -> tuple[bool, str, tuple[int, int] | None]:
    if os.path.islink(python_bin) and expected_venv is None and not python_bin.exists():
        return False, f"broken symlink at {python_bin}", None
    if not python_bin.exists() or not os.access(python_bin, os.X_OK):
        return False, f"interpreter missing or not executable at {python_bin}", None
    script = (
        "import importlib.util, json, os, sys; "
        "mods = json.loads(sys.argv[1]); "
        "missing = [m for m in mods if importlib.util.find_spec(m) is None]; "
        "print(json.dumps({'version': list(sys.version_info[:2]), "
        "'prefix': os.path.realpath(sys.prefix), "
        "'base_prefix': os.path.realpath(sys.base_prefix), "
        "'missing': missing}))"
    )
    arg = json.dumps(list(REQUIRED_MODULES) if check_modules else [])
    try:
        proc = subprocess.run(
            [str(python_bin), "-c", script, arg],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"probe failed: {exc}", None
    if proc.returncode != 0:
        return False, f"probe exited {proc.returncode}", None
    try:
        info = json.loads(proc.stdout.strip())
    except json.JSONDecodeError:
        return False, "invalid probe output", None
    ver = tuple(info.get("version") or ())
    if len(ver) < 2 or ver < MIN_PYTHON:
        return False, f"Python {ver} < 3.11", None
    if expected_venv is not None:
        expected_real = os.path.realpath(str(expected_venv))
        if info.get("prefix") == info.get("base_prefix") or info.get("prefix") != expected_real:
            return False, f"prefix {info.get('prefix')!r} != {expected_real!r}", None
    missing = info.get("missing") or []
    if check_modules and missing:
        return False, f"missing modules: {', '.join(missing)}", None
    return True, "ok", (ver[0], ver[1])


def _select_base_python(venv: Path) -> tuple[Path, tuple[int, int]]:
    venv_real = os.path.realpath(str(venv))
    explicit = os.environ.get("OCI_LA_ORCA_BASE_PYTHON", "").strip()
    if explicit:
        p = Path(explicit) if "/" in explicit else Path(shutil.which(explicit) or "")
        ok, reason, ver = _probe_python(p)
        if not ok or ver is None:
            raise RuntimeError(f"OCI_LA_ORCA_BASE_PYTHON={explicit!r} invalid: {reason}")
        return p, ver

    seen: set[str] = set()
    for candidate in ("python3.11", "python3.12", "python3.13", "python3.14", sys.executable, "python3"):
        found = candidate if "/" in candidate else shutil.which(candidate)
        if not found:
            continue
        p = Path(found)
        real = os.path.realpath(str(p))
        if real in seen or real.startswith(venv_real + os.sep):
            continue
        seen.add(real)
        ok, _, ver = _probe_python(p)
        if ok and ver is not None:
            return p, ver
    raise RuntimeError("no Python >= 3.11 interpreter found on PATH")


def _python_fingerprint(worktree: Path, py_ver: tuple[int, int]) -> str:
    h = hashlib.sha256()
    for name in REQ_FILES:
        p = worktree / name
        h.update(name.encode("utf-8") + b"\x00")
        h.update(p.read_bytes() if p.is_file() else b"")
        h.update(b"\x00")
    h.update(f"{py_ver[0]}.{py_ver[1]}\0{sys.platform}\0{platform.machine()}\0{worktree}".encode("utf-8"))
    return h.hexdigest()


def _install_python_reqs(
    worktree: Path,
    vpy: Path,
    req_args: list[str],
    uv: str | None,
) -> bool:
    if uv:
        for extra in (["--offline"], []):
            res = subprocess.run(
                [uv, "pip", "install", *extra, "--python", str(vpy), *req_args],
                cwd=str(worktree),
                timeout=_SUBPROC_TIMEOUT,
                check=False,
            )
            if res.returncode == 0:
                return True
        return False

    for extra in (["--no-index"], []):
        res = subprocess.run(
            [str(vpy), "-m", "pip", "install", "--disable-pip-version-check", "--no-input", *extra, *req_args],
            cwd=str(worktree),
            timeout=_SUBPROC_TIMEOUT,
            check=False,
        )
        if res.returncode == 0:
            return True
    return False


def ensure_python_venv(worktree: Path) -> int:
    existing_reqs = [name for name in REQ_FILES if (worktree / name).is_file()]
    if not existing_reqs:
        log_info("python: no root requirements*.txt; skipping venv setup")
        return 0

    venv = worktree / VENV_DIR
    if os.path.islink(venv):
        log_warn(".venv is a symlink; refusing to share or write through it")
        return 1
    if venv.exists() and not venv.is_dir():
        log_warn(".venv exists and is not a directory; refusing")
        return 1

    vpy = _venv_python(venv)
    stamp_path = venv / STAMP_NAME
    ok_fast, _, ver = _probe_python(vpy, expected_venv=venv, check_modules=True)
    if ok_fast and ver is not None and _stamp_matches(stamp_path, _python_fingerprint(worktree, ver)):
        log_info("python: verified .venv is up to date; skipping install")
        return 0

    try:
        base_python, _ = _select_base_python(venv)
    except RuntimeError as exc:
        log_warn(f"python: {exc}")
        return 1

    if venv.exists() and not ok_fast:
        log_info("python: removing stale or corrupt .venv")
        shutil.rmtree(venv)

    uv = shutil.which("uv")
    if not venv.exists():
        created = False
        if uv:
            res = subprocess.run(
                [uv, "venv", "--seed", "--python", str(base_python), str(venv)],
                cwd=str(worktree),
                timeout=_SUBPROC_TIMEOUT,
                check=False,
            )
            created = res.returncode == 0
            if not created and venv.exists():
                shutil.rmtree(venv)
        if not created:
            res = subprocess.run(
                [str(base_python), "-m", "venv", str(venv)],
                cwd=str(worktree),
                timeout=_SUBPROC_TIMEOUT,
                check=False,
            )
            if res.returncode != 0:
                log_warn("python: failed to create isolated .venv")
                return 1

    if os.path.islink(venv):
        log_warn(".venv became a symlink during setup; refusing")
        return 1

    # Install baseline requirements.txt + requirements-dev.txt, plus requirements-hunting-test.txt
    # (which includes requirements-mcp.txt) when present.
    req_args: list[str] = []
    for name in ("requirements.txt", "requirements-dev.txt", "requirements-hunting-test.txt"):
        if name in existing_reqs:
            req_args.extend(["-r", name])

    if not _install_python_reqs(worktree, vpy, req_args, uv):
        log_warn("python: dependency installation failed")
        return 1

    if os.path.islink(venv):
        log_warn(".venv became a symlink after install; refusing")
        return 1

    ok_post, reason_post, post_ver = _probe_python(vpy, expected_venv=venv, check_modules=True)
    if not ok_post or post_ver is None:
        log_warn(f"python: post-install verification failed ({reason_post})")
        return 1

    _write_json_atomic(
        stamp_path,
        {
            "fingerprint": _python_fingerprint(worktree, post_ver),
            "python": f"{post_ver[0]}.{post_ver[1]}",
            "platform": sys.platform,
            "arch": platform.machine(),
        },
    )
    log_info(f"python: isolated .venv ready (Python {post_ver[0]}.{post_ver[1]})")
    return 0


def _tool_version(cmd: list[str]) -> str:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)
        return res.stdout.strip() if res.returncode == 0 and res.stdout.strip() else "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def _webapp_fingerprint(webapp_dir: Path, node_ver: str, pnpm_ver: str) -> str:
    h = hashlib.sha256()
    for name in ("pnpm-lock.yaml", "package.json"):
        p = webapp_dir / name
        h.update(p.read_bytes() if p.is_file() else b"")
        h.update(b"\x00")
    h.update(f"{node_ver}\0{pnpm_ver}\0{sys.platform}\0{platform.machine()}\0{webapp_dir}".encode("utf-8"))
    return h.hexdigest()


def _installed_pnpm_tree_ok(node_modules: Path) -> bool:
    if os.path.islink(node_modules) or not node_modules.is_dir():
        return False
    if not (node_modules / ".modules.yaml").is_file():
        return False
    for pkg in REQUIRED_WEB_PACKAGES:
        pkg_dir = node_modules.joinpath(*pkg.split("/"))
        if not (pkg_dir / "package.json").is_file():
            return False
    return True


def ensure_webapp_node(worktree: Path) -> int:
    webapp_dir = worktree / "webapp"
    if os.path.islink(webapp_dir):
        log_warn("webapp is a symlink; refusing")
        return 1
    pkg_path = webapp_dir / "package.json"
    lock_path = webapp_dir / "pnpm-lock.yaml"
    if not pkg_path.is_file() or not lock_path.is_file():
        log_info("webapp: no webapp/pnpm-lock.yaml; skipping pnpm install")
        return 0

    node_modules = webapp_dir / "node_modules"
    if os.path.islink(node_modules):
        log_warn("webapp/node_modules is a symlink; refusing to share or write through it")
        return 1
    if node_modules.exists() and not node_modules.is_dir():
        log_warn("webapp/node_modules exists and is not a directory; refusing")
        return 1

    node_bin = shutil.which("node")
    pnpm_bin = shutil.which("pnpm")
    if not node_bin or not pnpm_bin:
        missing = " ".join(
            name for name, path in (("node", node_bin), ("pnpm", pnpm_bin)) if not path
        )
        log_warn(f"webapp: required toolchain missing ({missing}) with webapp/pnpm-lock.yaml present")
        return 1

    node_ver = _tool_version([node_bin, "--version"])
    pnpm_ver = _tool_version([pnpm_bin, "--version"])
    fp = _webapp_fingerprint(webapp_dir, node_ver, pnpm_ver)
    stamp_path = node_modules / STAMP_NAME

    if _stamp_matches(stamp_path, fp) and _installed_pnpm_tree_ok(node_modules):
        log_info(f"webapp: verified webapp/node_modules is up to date ({node_ver}, pnpm {pnpm_ver}); skipping install")
        return 0

    installed = False
    for flag in ("--offline", "--prefer-offline"):
        res = subprocess.run(
            [pnpm_bin, "install", "--frozen-lockfile", flag],
            cwd=str(webapp_dir),
            timeout=_SUBPROC_TIMEOUT,
            check=False,
        )
        if res.returncode == 0:
            installed = True
            break

    if not installed:
        log_warn("webapp: pnpm install --frozen-lockfile failed (offline and prefer-offline)")
        return 1

    if os.path.islink(node_modules) or not _installed_pnpm_tree_ok(node_modules):
        log_warn("webapp: post-install verification of webapp/node_modules failed")
        return 1

    _write_json_atomic(
        stamp_path,
        {
            "fingerprint": fp,
            "node": node_ver,
            "pnpm": pnpm_ver,
            "platform": sys.platform,
            "arch": platform.machine(),
        },
    )
    log_info(f"webapp: isolated webapp/node_modules ready ({node_ver}, pnpm {pnpm_ver})")
    return 0


def _report_optional_tools() -> None:
    parts = []
    for tool in ("git", "python3", "uv", "node", "pnpm", "terraform", "gitleaks", "shellcheck"):
        parts.append(f"{tool}={'ok' if shutil.which(tool) else 'missing'}")
    log_info("tools: " + " ".join(parts))


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args == ["--hydrate-only"]:
        return hydrate_env()
    if args not in ([], ["setup"]):
        print(f"orca-setup: unknown arguments: {args!r}", file=sys.stderr)
        return 1

    wt_raw = os.environ.get("ORCA_WORKTREE_PATH") or os.getcwd()
    try:
        opened = open_verified_dir(wt_raw, "ORCA_WORKTREE_PATH")
    except UnsafePathError as exc:
        log_warn(str(exc))
        return 1
    assert opened is not None
    wt_fd, worktree = opened
    os.close(wt_fd)

    if os.environ.get("OCI_LA_ORCA_SKIP_INSTALL", "").strip().lower() not in _SKIP_VALUES:
        rc = ensure_python_venv(worktree)
        if rc != 0:
            return rc
        rc = ensure_webapp_node(worktree)
        if rc != 0:
            return rc

    rc = hydrate_env()
    if rc != 0:
        return rc

    _report_optional_tools()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
