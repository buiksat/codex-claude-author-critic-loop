"""Hermetic, refresh-compatible Codex file-auth status probing.

The pinned Codex binary unconditionally creates ``CODEX_HOME/tmp/arg0`` even
for ``codex login status``.  SQLite redirection does not affect that helper
directory.  A status probe therefore mounts the complete transactional home
so an atomic ``auth.json`` refresh can persist, while shadowing only ``tmp``
with private disposable storage.  The persistent mountpoint is removed again
before the caller regains control.
"""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
from pathlib import Path

from .codex_client import build_codex_parent_environment
from .errors import AgentLoopError
from .filesystem import ConfinedFilesystem
from .manifests import SubjectManifest
from .runtime_adapters import SandboxExecutor
from .sandbox import SandboxMount, SandboxRole

_CACHE_DIRECTORY_NAMES = (b".tmp", b"plugins", b"skills", b"tmp")
_PERSISTENT_DIRECTORY_NAMES = {b"sessions"}
_PERSISTENT_FILE_LIMITS = {
    b"auth.json": 1024 * 1024,
    b"config.toml": 1024 * 1024,
    b"goals_1.sqlite": 64 * 1024 * 1024,
    b"goals_1.sqlite-shm": 64 * 1024 * 1024,
    b"goals_1.sqlite-wal": 64 * 1024 * 1024,
    b"installation_id": 4096,
    b"logs_2.sqlite": 64 * 1024 * 1024,
    b"logs_2.sqlite-shm": 64 * 1024 * 1024,
    b"logs_2.sqlite-wal": 64 * 1024 * 1024,
    b"memories_1.sqlite": 64 * 1024 * 1024,
    b"memories_1.sqlite-shm": 64 * 1024 * 1024,
    b"memories_1.sqlite-wal": 64 * 1024 * 1024,
    b"models_cache.json": 16 * 1024 * 1024,
    b"state_5.sqlite": 64 * 1024 * 1024,
    b"state_5.sqlite-shm": 64 * 1024 * 1024,
    b"state_5.sqlite-wal": 64 * 1024 * 1024,
}
_PERSISTENT_CODEX_HOME_NAMES = _PERSISTENT_DIRECTORY_NAMES | set(_PERSISTENT_FILE_LIMITS)
_STATUS_OUTPUT_MAX_BYTES = 64 * 1024


def _safe_root_file(directory_fd: int, name: bytes, *, max_bytes: int) -> bool:
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory_fd,
        )
    except OSError:
        return False
    try:
        info = os.fstat(descriptor)
        expected_modes = {0o600, 0o644} if name == b"installation_id" else {0o600}
        return bool(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.geteuid()
            and info.st_gid == os.getegid()
            and stat.S_IMODE(info.st_mode) in expected_modes
            and info.st_nlink == 1
            and 0 <= info.st_size <= max_bytes
            and not os.listxattr(descriptor)
        )
    except OSError:
        return False
    finally:
        os.close(descriptor)


def _safe_root_directory(directory_fd: int, name: bytes) -> bool:
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
            dir_fd=directory_fd,
        )
    except OSError:
        return False
    try:
        info = os.fstat(descriptor)
        return bool(
            stat.S_ISDIR(info.st_mode)
            and info.st_uid == os.geteuid()
            and info.st_gid == os.getegid()
            and stat.S_IMODE(info.st_mode) == 0o700
            and not os.listxattr(descriptor)
        )
    except OSError:
        return False
    finally:
        os.close(descriptor)


def _prepare_runtime_mountpoints(codex_home: Path) -> bool:
    """Discard exact derived caches and create four empty mountpoints."""

    if not shutil.rmtree.avoids_symlink_attacks:
        return False
    try:
        with ConfinedFilesystem.open(codex_home) as filesystem:
            directory_fd = filesystem.open_directory()
            try:
                root = os.fstat(directory_fd)
                if (
                    not stat.S_ISDIR(root.st_mode)
                    or root.st_uid != os.geteuid()
                    or stat.S_IMODE(root.st_mode) != 0o700
                ):
                    return False
                names = {os.fsencode(name) for name in os.listdir(directory_fd)}
                allowed = _PERSISTENT_CODEX_HOME_NAMES | set(_CACHE_DIRECTORY_NAMES)
                if names - allowed:
                    return False
                for name in names & _PERSISTENT_DIRECTORY_NAMES:
                    if not _safe_root_directory(directory_fd, name):
                        return False
                for name in names & set(_PERSISTENT_FILE_LIMITS):
                    if not _safe_root_file(
                        directory_fd,
                        name,
                        max_bytes=_PERSISTENT_FILE_LIMITS[name],
                    ):
                        return False
                # Validate every disposable root before deleting any of them.
                for name in names & set(_CACHE_DIRECTORY_NAMES):
                    if not _safe_root_directory(directory_fd, name):
                        return False
                for name in _CACHE_DIRECTORY_NAMES:
                    if name in names:
                        shutil.rmtree(name, dir_fd=directory_fd)
                for name in _CACHE_DIRECTORY_NAMES:
                    os.mkdir(name, mode=0o700, dir_fd=directory_fd)
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except OSError:
        return False
    return True


def _remove_empty_runtime_mountpoints(codex_home: Path) -> bool:
    """Remove only empty mountpoints; never erase post-probe surprises."""

    try:
        with ConfinedFilesystem.open(codex_home) as filesystem:
            directory_fd = filesystem.open_directory()
            try:
                # Inspect all four first so a shadowing failure never causes
                # partial cleanup that could hide a second unsafe mountpoint.
                for name in _CACHE_DIRECTORY_NAMES:
                    runtime_fd = filesystem.open_directory(name)
                    try:
                        if os.listdir(runtime_fd):
                            return False
                    finally:
                        os.close(runtime_fd)
                for name in _CACHE_DIRECTORY_NAMES:
                    os.rmdir(name, dir_fd=directory_fd)
                os.fsync(directory_fd)
                remaining = {os.fsencode(name) for name in os.listdir(directory_fd)}
                return not (remaining - _PERSISTENT_CODEX_HOME_NAMES)
            finally:
                os.close(directory_fd)
    except OSError:
        return False


def probe_codex_file_auth_status(
    executor: SandboxExecutor,
    *,
    install_mount: SandboxMount,
    executable: str,
    codex_home: Path,
    scratch_parent: Path | None = None,
    timeout_seconds: float = 15,
) -> bool:
    """Run ``codex login status`` without retaining Codex helper scratch.

    The whole private home remains one writable mount so a CLI token refresh
    can atomically replace ``auth.json``.  A nested disposable mount receives
    ``tmp/arg0``.  The trusted status process runs through the ordinary
    Bubblewrap/sandbox-init/transient-service path; no model request is made.
    """

    if not callable(getattr(executor, "execute", None)):
        raise TypeError("executor must provide the SandboxExecutor execute contract")
    if not isinstance(install_mount, SandboxMount) or not install_mount.read_only:
        raise TypeError("install_mount must be a read-only SandboxMount")
    selected_home = Path(codex_home)
    selected_parent = None if scratch_parent is None else Path(scratch_parent)
    if not _prepare_runtime_mountpoints(selected_home):
        return False

    process_ok = False
    cleanup_ok = False
    try:
        with tempfile.TemporaryDirectory(
            prefix="agent-loop-codex-auth-status-",
            dir=selected_parent,
        ) as scratch_name:
            scratch = Path(scratch_name)
            scratch.chmod(0o700)
            scratch_directories: dict[bytes, Path] = {}
            for name in _CACHE_DIRECTORY_NAMES:
                directory = scratch / os.fsdecode(name)
                directory.mkdir(mode=0o700)
                scratch_directories[name] = directory
            execution = executor.execute(
                role=SandboxRole.CRITIC,
                manifest=SubjectManifest.empty(),
                argv=(
                    executable,
                    "-c",
                    'cli_auth_credentials_store="file"',
                    "login",
                    "status",
                ),
                environment=build_codex_parent_environment(),
                cwd="/runtime/critic-cwd",
                timeout_seconds=timeout_seconds,
                mounts=(
                    install_mount,
                    SandboxMount(
                        os.fspath(selected_home),
                        "/control/codex-home",
                        read_only=False,
                    ),
                    *(
                        SandboxMount(
                            os.fspath(scratch_directories[name]),
                            f"/control/codex-home/{os.fsdecode(name)}",
                            read_only=False,
                        )
                        for name in _CACHE_DIRECTORY_NAMES
                    ),
                ),
                output_max_bytes=_STATUS_OUTPUT_MAX_BYTES,
            )
            process = execution.result.process
            process_ok = bool(
                process.returncode == 0 and not process.timed_out and not process.output_limited
            )
            cleanup_ok = bool(
                execution.result.cleanup.namespace_empty and execution.service.cgroup_empty
            )
    except AgentLoopError, OSError, TypeError, ValueError:
        return False
    finally:
        mountpoints_removed = _remove_empty_runtime_mountpoints(selected_home)
    return process_ok and cleanup_ok and mountpoints_removed


__all__ = ["probe_codex_file_auth_status"]
