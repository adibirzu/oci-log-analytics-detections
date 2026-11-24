#!/usr/bin/env python3
"""Safe descriptor-pinned local env hydration for Orca worktrees.

Copies only gitignored, untracked local env files from ``$ORCA_ROOT_PATH``
into ``$ORCA_WORKTREE_PATH`` (default: cwd) without following symlinks,
without overwriting existing destinations, without printing values, and
without touching ``~/.oci`` or ``~/.kube``.
"""

from __future__ import annotations

import errno
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
import time
from typing import Callable

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)

_GIT_ENV_OVERRIDES = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_COMMON_DIR",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CONFIG",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_NOSYSTEM",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "GIT_PREFIX",
)

_ROOT_ENV_SUBDIRS: tuple[tuple[str, ...], ...] = (
    (),
    ("webapp",),
)


class UnsafePathError(RuntimeError):
    """Raised when an untrusted path or filesystem entry fails safety checks."""


class SetupDeadlineError(RuntimeError):
    """Raised when the shared end-to-end setup wall-clock budget is exhausted."""


def remaining_deadline(deadline: float | None, *, step: str, default: float = 15.0) -> float:
    """Return remaining seconds before ``deadline``, failing closed if exhausted."""
    if deadline is None:
        return default
    remaining = deadline - time.monotonic()
    if remaining <= 0.0:
        raise SetupDeadlineError(f"end-to-end setup deadline exhausted before {step}")
    return remaining


def log_info(message: str) -> None:
    print(f"orca-setup: {message}", flush=True)


def log_warn(message: str) -> None:
    print(f"orca-setup: warning: {message}", file=sys.stderr, flush=True)


def _split_raw_abs_path(raw: str, label: str) -> list[str]:
    if not raw or "\x00" in raw:
        raise UnsafePathError(f"refusing {label}: empty or invalid path")
    if not os.path.isabs(raw):
        raise UnsafePathError(f"refusing {label}: path must be absolute")
    segments = raw.split("/")
    for seg in segments:
        if seg in ("..", "."):
            raise UnsafePathError(f"refusing {label}: traversal segment in {raw!r}")
    return [seg for seg in segments if seg]


def _rewrite_macos_alias(parts: list[str]) -> list[str]:
    """Allow only verified root-owned macOS /tmp and /var system aliases."""
    if sys.platform != "darwin" or not parts or parts[0] not in ("tmp", "var"):
        return parts
    alias = parts[0]
    alias_path = f"/{alias}"
    target_dir = f"/private/{alias}"
    try:
        st_alias = os.lstat(alias_path)
        if not stat.S_ISLNK(st_alias.st_mode) or st_alias.st_uid != 0:
            return parts
        if os.readlink(alias_path) not in (f"private/{alias}", f"/private/{alias}"):
            return parts
        st_priv = os.lstat("/private")
        st_target = os.lstat(target_dir)
        if (
            stat.S_ISLNK(st_priv.st_mode)
            or not stat.S_ISDIR(st_priv.st_mode)
            or st_priv.st_uid != 0
            or stat.S_ISLNK(st_target.st_mode)
            or not stat.S_ISDIR(st_target.st_mode)
            or st_target.st_uid != 0
        ):
            return parts
    except OSError:
        return parts
    return ["private", alias, *parts[1:]]


def open_verified_dir(
    raw: str,
    label: str,
    *,
    allow_missing: bool = False,
) -> tuple[int, Path] | None:
    """Open ``raw`` component-by-component with ``O_DIRECTORY | O_NOFOLLOW``."""
    parts = _rewrite_macos_alias(_split_raw_abs_path(raw, label))
    cur_fd = os.open("/", os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC)
    try:
        if not stat.S_ISDIR(os.fstat(cur_fd).st_mode):
            raise UnsafePathError(f"refusing {label}: root is not a directory")
        for part in parts:
            try:
                next_fd = os.open(
                    part,
                    os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC,
                    dir_fd=cur_fd,
                )
            except OSError as exc:
                if allow_missing and exc.errno == errno.ENOENT:
                    return None
                raise UnsafePathError(
                    f"refusing {label}: unsafe or missing component {part!r} ({exc.strerror or exc})"
                ) from exc
            try:
                if not stat.S_ISDIR(os.fstat(next_fd).st_mode):
                    raise UnsafePathError(
                        f"refusing {label}: component {part!r} is not a directory"
                    )
            except Exception:
                os.close(next_fd)
                raise
            os.close(cur_fd)
            cur_fd = next_fd
        canonical = Path("/" + "/".join(parts)) if parts else Path("/")
        out_fd = cur_fd
        cur_fd = -1
        return out_fd, canonical
    finally:
        if cur_fd >= 0:
            os.close(cur_fd)


def _open_subpath_dir_fd(base_fd: int, parts: tuple[str, ...], label: str) -> int | None:
    """Open a relative subdir chain under ``base_fd`` with ``O_DIRECTORY | O_NOFOLLOW``."""
    if not parts:
        return os.dup(base_fd)
    cur_fd = os.dup(base_fd)
    try:
        for part in parts:
            try:
                next_fd = os.open(
                    part,
                    os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC,
                    dir_fd=cur_fd,
                )
            except OSError as exc:
                if exc.errno == errno.ENOENT:
                    return None
                raise UnsafePathError(
                    f"refusing {label}/{part}: unsafe directory ({exc.strerror or exc})"
                ) from exc
            os.close(cur_fd)
            cur_fd = next_fd
        out_fd = cur_fd
        cur_fd = -1
        return out_fd
    finally:
        if cur_fd >= 0:
            os.close(cur_fd)


def is_env_candidate_name(name: str) -> bool:
    """Allow only ``.env``, ``.env.local``, or ``.env.local.<PROFILE>`` (never templates)."""
    if "/" in name or "\x00" in name or name in (".", ".."):
        return False
    if name not in (".env", ".env.local") and not name.startswith(".env.local."):
        return False
    if name == ".env.local.example" or name.endswith((".example", ".sample", ".template")):
        return False
    return True


def _clean_git_env() -> dict[str, str]:
    env = dict(os.environ)
    for var in _GIT_ENV_OVERRIDES:
        env.pop(var, None)
    return env


def _confirm_git_ignored(
    repo_dir: Path,
    repo_fd: int,
    rel_path: str,
    *,
    deadline: float | None = None,
) -> bool:
    """Confirm ``repo_dir`` is the git toplevel and ``rel_path`` is untracked + ignored."""
    git_env = _clean_git_env()
    try:
        top = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=str(repo_dir),
            env=git_env,
            capture_output=True,
            text=True,
            timeout=remaining_deadline(deadline, step="git rev-parse"),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        if deadline is not None:
            raise SetupDeadlineError("end-to-end setup deadline exhausted during git rev-parse") from exc
        return False
    except (OSError, subprocess.SubprocessError):
        return False
    if top.returncode != 0 or not top.stdout.strip():
        return False
    try:
        opened_top = open_verified_dir(top.stdout.strip(), "git toplevel")
    except UnsafePathError:
        return False
    if opened_top is None:
        return False
    top_fd, _ = opened_top
    try:
        st_repo = os.fstat(repo_fd)
        st_top = os.fstat(top_fd)
        if (st_repo.st_dev, st_repo.st_ino) != (st_top.st_dev, st_top.st_ino):
            return False
    finally:
        os.close(top_fd)

    try:
        tracked = subprocess.run(
            ["git", "ls-files", "--error-unmatch", "--", rel_path],
            cwd=str(repo_dir),
            env=git_env,
            capture_output=True,
            text=True,
            timeout=remaining_deadline(deadline, step=f"git ls-files {rel_path}"),
            check=False,
        )
        if tracked.returncode != 1:
            return False
        ignored = subprocess.run(
            ["git", "check-ignore", "-q", "--", rel_path],
            cwd=str(repo_dir),
            env=git_env,
            capture_output=True,
            text=True,
            timeout=remaining_deadline(deadline, step=f"git check-ignore {rel_path}"),
            check=False,
        )
        return ignored.returncode == 0
    except subprocess.TimeoutExpired as exc:
        if deadline is not None:
            raise SetupDeadlineError(f"end-to-end setup deadline exhausted during git ignore check for {rel_path}") from exc
        return False
    except (OSError, subprocess.SubprocessError):
        return False


def _read_all(fd: int) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = os.read(fd, 1 << 20)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError(errno.EIO, "short write made no progress")
        view = view[written:]


def _verify_reg_single_link(
    st: os.stat_result,
    label: str,
    *,
    expected_id: tuple[int, int] | None = None,
) -> tuple[int, int]:
    """Enforce regular file, single hardlink (st_nlink == 1), and stable dev/ino identity."""
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise UnsafePathError(f"refusing non-regular {label}")
    if st.st_nlink != 1:
        raise UnsafePathError(f"refusing hardlinked {label} (st_nlink={st.st_nlink})")
    identity = (st.st_dev, st.st_ino)
    if expected_id is not None and identity != expected_id:
        raise UnsafePathError(f"refusing {label}: file identity changed across fstat")
    return identity


def _copy_env_file_fd(
    src_dir_fd: int,
    dst_dir_fd: int,
    name: str,
    *,
    _write_bytes_fn: Callable[[int, bytes], None] | None = None,
) -> str:
    try:
        st_dst = os.lstat(name, dir_fd=dst_dir_fd)
    except FileNotFoundError:
        st_dst = None

    if st_dst is not None:
        dst_id = _verify_reg_single_link(st_dst, f"destination {name}")
        try:
            dst_fd = os.open(
                name,
                os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_CLOEXEC,
                dir_fd=dst_dir_fd,
            )
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise UnsafePathError(f"refusing symlink destination {name}") from exc
            if exc.errno == errno.EACCES:
                return "already exists"
            raise
        try:
            _verify_reg_single_link(os.fstat(dst_fd), f"destination {name} after open", expected_id=dst_id)
        finally:
            os.close(dst_fd)
        return "already exists"

    st_src = os.lstat(name, dir_fd=src_dir_fd)
    src_id = _verify_reg_single_link(st_src, f"source {name}")

    in_fd = os.open(
        name,
        os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_CLOEXEC,
        dir_fd=src_dir_fd,
    )
    try:
        _verify_reg_single_link(os.fstat(in_fd), f"source {name} after open", expected_id=src_id)
        data = _read_all(in_fd)
        _verify_reg_single_link(os.fstat(in_fd), f"source {name} after read", expected_id=src_id)
    finally:
        os.close(in_fd)

    tmp_name = f".orca-tmp-{os.getpid()}-{secrets.token_hex(8)}-{name}"
    tmp_fd = os.open(
        tmp_name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC,
        0o600,
        dir_fd=dst_dir_fd,
    )
    linked = False
    try:
        try:
            tmp_id = _verify_reg_single_link(os.fstat(tmp_fd), f"staging {name}")
            os.fchmod(tmp_fd, 0o600)
            (_write_bytes_fn or _write_all)(tmp_fd, data)
            os.fsync(tmp_fd)
            _verify_reg_single_link(os.fstat(tmp_fd), f"staging {name} after write", expected_id=tmp_id)
        finally:
            os.close(tmp_fd)

        link_kwargs = {"follow_symlinks": False} if os.link in os.supports_follow_symlinks else {}
        try:
            os.link(tmp_name, name, src_dir_fd=dst_dir_fd, dst_dir_fd=dst_dir_fd, **link_kwargs)
            linked = True
        except FileExistsError:
            st_race = os.lstat(name, dir_fd=dst_dir_fd)
            _verify_reg_single_link(st_race, f"destination {name}")
            return "already exists"
    finally:
        try:
            os.unlink(tmp_name, dir_fd=dst_dir_fd)
        except FileNotFoundError:
            pass

    if linked:
        st_final = os.lstat(name, dir_fd=dst_dir_fd)
        _verify_reg_single_link(st_final, f"destination {name} after link", expected_id=tmp_id)
        chk_fd = os.open(
            name,
            os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_CLOEXEC,
            dir_fd=dst_dir_fd,
        )
        try:
            _verify_reg_single_link(os.fstat(chk_fd), f"destination {name} after verify", expected_id=tmp_id)
        finally:
            os.close(chk_fd)
        return "copied"
    return "already exists"


def _hydrate_subdir(
    src_root_path: Path,
    src_root_fd: int,
    dst_root_path: Path,
    dst_root_fd: int,
    subdir: tuple[str, ...],
    *,
    deadline: float | None = None,
) -> tuple[int, int]:
    copied = 0
    skipped = 0
    prefix = "/".join(subdir)
    try:
        src_sub_fd = _open_subpath_dir_fd(src_root_fd, subdir, "ORCA_ROOT_PATH")
    except UnsafePathError as exc:
        log_warn(f"hydrate-env: {exc}; skipping {prefix or 'root'}")
        return 0, 1
    if src_sub_fd is None:
        return 0, 0
    try:
        names = sorted(n for n in os.listdir(src_sub_fd) if is_env_candidate_name(n))
        if not names:
            return 0, 0
        try:
            dst_sub_fd = _open_subpath_dir_fd(dst_root_fd, subdir, "ORCA_WORKTREE_PATH")
        except UnsafePathError as exc:
            log_warn(f"hydrate-env: {exc}; skipping {prefix or 'root'}")
            return 0, len(names)
        if dst_sub_fd is None:
            return 0, len(names)
        try:
            for name in names:
                rel = f"{prefix}/{name}" if prefix else name
                if not _confirm_git_ignored(src_root_path, src_root_fd, rel, deadline=deadline):
                    log_warn(f"hydrate-env: refusing unignored or tracked source {rel}")
                    skipped += 1
                    continue
                if not _confirm_git_ignored(dst_root_path, dst_root_fd, rel, deadline=deadline):
                    log_warn(f"hydrate-env: refusing unignored or tracked destination {rel}")
                    skipped += 1
                    continue
                try:
                    outcome = _copy_env_file_fd(src_sub_fd, dst_sub_fd, name)
                except (UnsafePathError, OSError) as exc:
                    log_warn(f"hydrate-env: refused {rel} ({exc})")
                    skipped += 1
                    continue
                if outcome == "copied":
                    copied += 1
                    log_info(f"hydrate-env: {rel} hydrated (mode 0600)")
                else:
                    skipped += 1
                    log_info(f"hydrate-env: {rel} {outcome}; leaving untouched")
        finally:
            os.close(dst_sub_fd)
    finally:
        os.close(src_sub_fd)
    return copied, skipped


def hydrate_env(*, deadline: float | None = None) -> int:
    """Hydrate gitignored local env files from ``$ORCA_ROOT_PATH`` safely."""
    root_raw = os.environ.get("ORCA_ROOT_PATH", "").strip()
    if not root_raw:
        log_info("hydrate-env: ORCA_ROOT_PATH not set; nothing to do")
        return 0
    wt_raw = os.environ.get("ORCA_WORKTREE_PATH") or os.getcwd()

    src_fd = -1
    dst_fd = -1
    try:
        opened_src = open_verified_dir(root_raw, "ORCA_ROOT_PATH", allow_missing=True)
        if opened_src is None:
            log_info("hydrate-env: ORCA_ROOT_PATH does not exist; nothing to do")
            return 0
        src_fd, src_path = opened_src

        opened_dst = open_verified_dir(wt_raw, "ORCA_WORKTREE_PATH")
        assert opened_dst is not None
        dst_fd, dst_path = opened_dst

        st_src = os.fstat(src_fd)
        st_dst = os.fstat(dst_fd)
        if (st_src.st_dev, st_src.st_ino) == (st_dst.st_dev, st_dst.st_ino):
            log_info("hydrate-env: worktree is the Orca root; nothing to do")
            return 0

        total_copied = 0
        total_skipped = 0
        for subdir in _ROOT_ENV_SUBDIRS:
            c, s = _hydrate_subdir(src_path, src_fd, dst_path, dst_fd, subdir, deadline=deadline)
            total_copied += c
            total_skipped += s
        log_info(f"hydrate-env: copied {total_copied} file(s), skipped {total_skipped}")
        return 0
    except SetupDeadlineError as exc:
        log_warn(f"hydrate-env: timeout: {exc}")
        return 1
    except (UnsafePathError, OSError) as exc:
        log_warn(f"hydrate-env: {exc}; no files copied")
        return 0
    finally:
        if src_fd >= 0:
            os.close(src_fd)
        if dst_fd >= 0:
            os.close(dst_fd)
