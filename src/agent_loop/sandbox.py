"""The sole Bubblewrap backend and its role-specific mount/network policy."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath

from .constants import (
    DEFAULT_WORKSPACE_BYTES,
    SUPPORTED_BWRAP_PACKAGE,
    SUPPORTED_BWRAP_SHA256,
    SUPPORTED_BWRAP_UPSTREAM,
)
from .errors import StopReason, fail
from .provenance import reject_extended_metadata_fd
from .service import BoundedProcessResult, run_bounded_process

BWRAP_PATH = "/usr/bin/bwrap"


class SandboxRole(StrEnum):
    AUTHOR = "author"
    VALIDATION = "validation"
    CRITIC = "critic"
    GIT = "git"


@dataclass(frozen=True, slots=True)
class SandboxMount:
    source: str
    target: str
    read_only: bool = True
    closure_sha256: str | None = None

    def __post_init__(self) -> None:
        source = PurePosixPath(self.source)
        target = PurePosixPath(self.target)
        if not source.is_absolute() or ".." in source.parts:
            raise ValueError("sandbox mount source must be a normalized absolute path")
        if not target.is_absolute() or ".." in target.parts or str(target) == "/":
            raise ValueError("sandbox mount target must be a normalized non-root absolute path")
        if self.closure_sha256 is not None:
            if not self.read_only:
                raise ValueError("only read-only mounts may carry a closure witness")
            if re.fullmatch(r"[0-9a-f]{64}", self.closure_sha256) is None:
                raise ValueError("sandbox mount closure witness must be lowercase SHA-256")


@dataclass(frozen=True, slots=True)
class SandboxPolicy:
    role: SandboxRole
    workspace_bytes: int = DEFAULT_WORKSPACE_BYTES
    mounts: tuple[SandboxMount, ...] = ()
    control_egress: bool = False
    cwd: str = "/runtime"

    def __post_init__(self) -> None:
        if not isinstance(self.role, SandboxRole):
            raise TypeError("role must be a SandboxRole")
        if not isinstance(self.workspace_bytes, int) or self.workspace_bytes <= 0:
            raise ValueError("workspace_bytes must be positive")
        if self.control_egress != (self.role in {SandboxRole.AUTHOR, SandboxRole.CRITIC}):
            raise ValueError("only author and critic trusted control roles may retain host egress")
        cwd = PurePosixPath(self.cwd)
        if not cwd.is_absolute() or ".." in cwd.parts:
            raise ValueError("sandbox cwd must be normalized and absolute")
        targets: set[str] = set()
        for mount in self.mounts:
            if mount.target in targets:
                raise ValueError("sandbox mount targets must be unique")
            targets.add(mount.target)
            if not mount.read_only and not mount.target.startswith("/control/"):
                raise ValueError("host-backed writable mounts are confined to /control")
            if not mount.read_only and self.role not in {SandboxRole.AUTHOR, SandboxRole.CRITIC}:
                raise ValueError("untrusted no-network roles cannot receive writable host mounts")

    @classmethod
    def author(cls, *, mounts: tuple[SandboxMount, ...] = ()) -> SandboxPolicy:
        return cls(
            SandboxRole.AUTHOR,
            mounts=mounts,
            control_egress=True,
            cwd="/runtime/author-cwd",
        )

    @classmethod
    def validation(cls, *, mounts: tuple[SandboxMount, ...] = ()) -> SandboxPolicy:
        return cls(SandboxRole.VALIDATION, mounts=mounts, cwd="/workspace")

    @classmethod
    def critic(cls, *, mounts: tuple[SandboxMount, ...] = ()) -> SandboxPolicy:
        return cls(
            SandboxRole.CRITIC,
            mounts=mounts,
            control_egress=True,
            cwd="/runtime/critic-cwd",
        )

    @classmethod
    def git(cls, *, mounts: tuple[SandboxMount, ...] = ()) -> SandboxPolicy:
        return cls(SandboxRole.GIT, mounts=mounts, cwd="/runtime/git-cwd")


@dataclass(frozen=True, slots=True)
class BubblewrapProvenance:
    package_version: str
    upstream_version: str
    executable: str
    owner_uid: int
    owner_gid: int
    mode: int
    sha256: str


def _probe_env() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": "/nonexistent",
    }


def _small_command(argv: tuple[str, ...]) -> BoundedProcessResult:
    try:
        result = run_bounded_process(
            argv,
            input_bytes=b"",
            timeout_seconds=10,
            output_max_bytes=256 * 1024,
            env=_probe_env(),
        )
    except OSError as exc:
        raise fail(
            StopReason.BWRAP_PACKAGE_OR_MODE_UNSAFE,
            "platform probe could not start",
        ) from exc
    if result.output_limited:
        raise fail(StopReason.BWRAP_PACKAGE_OR_MODE_UNSAFE, "platform probe output exceeded cap")
    if result.timed_out:
        raise fail(StopReason.BWRAP_PACKAGE_OR_MODE_UNSAFE, "platform probe timed out")
    return result


def probe_bubblewrap_package() -> BubblewrapProvenance:
    """Accept only the reviewed Ubuntu package and exact non-setuid executable."""

    try:
        info = os.lstat(BWRAP_PATH)
    except OSError as exc:
        raise fail(
            StopReason.BWRAP_PACKAGE_OR_MODE_UNSAFE,
            "Bubblewrap executable missing",
        ) from exc
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0:
        raise fail(
            StopReason.BWRAP_PACKAGE_OR_MODE_UNSAFE,
            "Bubblewrap must be a root-owned regular file",
        )
    permission_bits = stat.S_IMODE(info.st_mode)
    if permission_bits != 0o755 or info.st_mode & (stat.S_ISUID | stat.S_ISGID):
        raise fail(
            StopReason.BWRAP_PACKAGE_OR_MODE_UNSAFE,
            "Bubblewrap mode must be exactly non-setuid 0755",
        )
    fd = os.open(BWRAP_PATH, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise fail(StopReason.BWRAP_PACKAGE_OR_MODE_UNSAFE, "Bubblewrap changed during probe")
        try:
            reject_extended_metadata_fd(fd)
        except ValueError as exc:
            raise fail(
                StopReason.BWRAP_PACKAGE_OR_MODE_UNSAFE,
                "Bubblewrap extended metadata is unsafe or unverifiable",
            ) from exc
        with os.fdopen(os.dup(fd), "rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
    finally:
        os.close(fd)
    if digest not in SUPPORTED_BWRAP_SHA256:
        raise fail(StopReason.BWRAP_PACKAGE_OR_MODE_UNSAFE, "unexpected Bubblewrap binary hash")

    package = _small_command(
        ("/usr/bin/dpkg-query", "-W", "-f=${Version}", "bubblewrap")
    )
    if package.returncode != 0:
        raise fail(StopReason.BWRAP_PACKAGE_OR_MODE_UNSAFE, "Bubblewrap package query failed")
    package_version = package.stdout.decode("ascii", "strict")
    if package_version != SUPPORTED_BWRAP_PACKAGE:
        raise fail(
            StopReason.BWRAP_PACKAGE_OR_MODE_UNSAFE,
            f"unsupported Bubblewrap package revision: {package_version!r}",
        )
    verified = _small_command(("/usr/bin/dpkg", "--verify", "bubblewrap"))
    if verified.returncode != 0 or verified.stdout or verified.stderr:
        raise fail(
            StopReason.BWRAP_PACKAGE_OR_MODE_UNSAFE,
            "dpkg reports modified Bubblewrap files",
        )
    version = _small_command((BWRAP_PATH, "--version"))
    match = re.fullmatch(rb"bubblewrap ([0-9.]+)\n?", version.stdout)
    if version.returncode != 0 or match is None:
        raise fail(StopReason.BWRAP_PACKAGE_OR_MODE_UNSAFE, "could not parse bwrap --version")
    upstream = match.group(1).decode("ascii")
    if upstream != SUPPORTED_BWRAP_UPSTREAM:
        raise fail(
            StopReason.BWRAP_PACKAGE_OR_MODE_UNSAFE,
            "unsupported upstream Bubblewrap version",
        )
    return BubblewrapProvenance(
        package_version,
        upstream,
        BWRAP_PATH,
        info.st_uid,
        info.st_gid,
        permission_bits,
        digest,
    )


def _ensure_target_parents(argv: list[str], target: str, created: set[str]) -> None:
    parts = PurePosixPath(target).parents
    for parent in reversed(parts):
        rendered = str(parent)
        if rendered == "/" or rendered in created:
            continue
        argv.extend(("--dir", rendered))
        created.add(rendered)


def build_bwrap_argv(policy: SandboxPolicy, command: tuple[str, ...]) -> tuple[str, ...]:
    """Build the only reviewed namespace topology; there is no fallback path."""

    if not command or not os.path.isabs(command[0]) or any("\x00" in item for item in command):
        raise ValueError("sandbox command must be a non-empty absolute NUL-free argv")
    argv = [
        BWRAP_PATH,
        "--die-with-parent",
        "--new-session",
        "--unshare-user",
        "--unshare-pid",
        "--as-pid-1",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup",
    ]
    if not policy.control_egress:
        argv.append("--unshare-net")
    argv.extend(
        (
            "--cap-drop",
            "ALL",
            "--clearenv",
            "--setenv",
            "PATH",
            "/usr/bin:/bin",
            "--setenv",
            "HOME",
            "/runtime/home",
            "--setenv",
            "TMPDIR",
            "/runtime/tmp",
            "--setenv",
            "LANG",
            "C.UTF-8",
            "--tmpfs",
            "/",
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "usr/bin",
            "/bin",
            "--symlink",
            "usr/sbin",
            "/sbin",
            "--symlink",
            "usr/lib",
            "/lib",
            "--symlink",
            "usr/lib64",
            "/lib64",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/run",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/runtime",
            "--dir",
            "/runtime/home",
            "--dir",
            "/runtime/tmp",
            "--dir",
            "/runtime/author-cwd",
            "--dir",
            "/runtime/critic-cwd",
            "--dir",
            "/runtime/critic-tmp",
            "--dir",
            "/runtime/git-cwd",
            "--dir",
            "/control",
            "--size",
            str(policy.workspace_bytes),
            "--tmpfs",
            "/workspace",
        )
    )
    created = {
        "/runtime",
        "/runtime/home",
        "/runtime/tmp",
        "/runtime/author-cwd",
        "/runtime/critic-cwd",
        "/runtime/critic-tmp",
        "/runtime/git-cwd",
        "/control",
        "/workspace",
    }
    # These are the minimum reviewed host files for NSS and trusted TLS egress.
    etc_mounts = [
        path
        for path in (
            "/etc/passwd",
            "/etc/group",
            "/etc/nsswitch.conf",
            "/etc/hosts",
            "/etc/resolv.conf",
            "/etc/ssl/certs",
        )
        if os.path.exists(path)
    ]
    for path in etc_mounts:
        _ensure_target_parents(argv, path, created)
        argv.extend(("--ro-bind", path, path))
    for mount in policy.mounts:
        _ensure_target_parents(argv, mount.target, created)
        argv.extend(("--ro-bind" if mount.read_only else "--bind", mount.source, mount.target))
    argv.extend(("--chdir", policy.cwd, "--"))
    argv.extend(command)
    return tuple(argv)


def probe_bwrap_namespaces() -> None:
    provenance = probe_bubblewrap_package()
    if provenance.executable != BWRAP_PATH:
        raise fail(StopReason.BWRAP_PACKAGE_OR_MODE_UNSAFE, "Bubblewrap executable mismatch")
    policy = SandboxPolicy.validation()
    result = _small_command(build_bwrap_argv(policy, ("/usr/bin/true",)))
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "backslashreplace")[-1024:]
        raise fail(StopReason.SANDBOX_SETUP_FAILURE, f"Bubblewrap namespace probe failed: {detail}")
