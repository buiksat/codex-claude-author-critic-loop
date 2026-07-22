"""Pinned host/tool verification before any credential or model spending."""

from __future__ import annotations

import hashlib
import os
import platform
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

from .author_service import AuthorServiceProvenance, inspect_fixed_author_service
from .constants import (
    SUPPORTED_BASH_VERSION_PREFIX,
    SUPPORTED_CLAUDE_VERSION,
    SUPPORTED_CODEX_VERSION,
    SUPPORTED_GIT_VERSION,
    SUPPORTED_MACHINE,
    SUPPORTED_OS_ID,
    SUPPORTED_OS_VERSION,
    SUPPORTED_PYTHON,
    SUPPORTED_SYSTEMD_VERSION,
)
from .errors import AgentLoopError, StopReason, fail
from .filesystem import require_openat2
from .provenance import (
    reject_extended_metadata_fd,
    safe_owned_mode,
    verify_safe_ancestors,
)
from .sandbox import BubblewrapProvenance, probe_bubblewrap_package, probe_bwrap_namespaces
from .service import (
    BoundedProcessResult,
    ServiceLimits,
    TransientServiceRunner,
    run_bounded_process,
)

_SERVICE_VERSION_GATE_MARKER = b"\x00"
_SERVICE_VERSION_GATE_CODE = (
    "import os,sys\n"
    "if os.read(0,1) != b'\\x00': raise SystemExit(125)\n"
    "os.execv(sys.argv[1],sys.argv[1:])\n"
)


@dataclass(frozen=True, slots=True)
class TrustedExecutable:
    requested_path: str
    resolved_path: str
    owner_uid: int
    mode: int
    sha256: str
    version: str


@dataclass(frozen=True, slots=True)
class EnvironmentReport:
    os_id: str
    os_version: str
    machine: str
    kernel: str
    python: str
    git: str
    systemd: str
    bash: str
    bubblewrap: BubblewrapProvenance
    python_executable: TrustedExecutable
    codex: TrustedExecutable
    claude: TrustedExecutable
    author_service: AuthorServiceProvenance
    openat2: bool
    namespace_probe: bool
    transient_service_probe: bool

    def to_json_obj(self) -> dict[str, object]:
        return {
            "os_id": self.os_id,
            "os_version": self.os_version,
            "machine": self.machine,
            "kernel": self.kernel,
            "python": self.python,
            "git": self.git,
            "systemd": self.systemd,
            "bash": self.bash,
            "bubblewrap": {
                "package_version": self.bubblewrap.package_version,
                "upstream_version": self.bubblewrap.upstream_version,
                "executable": self.bubblewrap.executable,
                "owner_uid": self.bubblewrap.owner_uid,
                "owner_gid": self.bubblewrap.owner_gid,
                "mode": f"{self.bubblewrap.mode:04o}",
                "sha256": self.bubblewrap.sha256,
            },
            "python_executable": _executable_json(self.python_executable),
            "codex": _executable_json(self.codex),
            "claude": _executable_json(self.claude),
            "author_service": {
                "protocol": self.author_service.protocol,
                "build_id": self.author_service.build_id,
                "authorized_uid": self.author_service.authorized_uid,
                "socket_path": self.author_service.socket_path,
                "socket_owner_uid": self.author_service.socket_owner_uid,
                "socket_mode": f"{self.author_service.socket_mode:04o}",
                "socket_unit_sha256": self.author_service.socket_unit_sha256,
                "broker_unit_sha256": self.author_service.broker_unit_sha256,
                "socket_dropin_sha256": self.author_service.socket_dropin_sha256,
                "config_sha256": self.author_service.config_sha256,
                "install_record_sha256": self.author_service.install_record_sha256,
                "runtime_closure_sha256": self.author_service.runtime_closure_sha256,
                "wheel_sha256": self.author_service.wheel_sha256,
                "codex_closure_sha256": self.author_service.codex_closure_sha256,
                "effective_units_sha256": self.author_service.effective_units_sha256,
                "package_version": self.author_service.package_version,
                "broker_probe": self.author_service.broker_probe,
            },
            "openat2": self.openat2,
            "namespace_probe": self.namespace_probe,
            "transient_service_probe": self.transient_service_probe,
        }


def _executable_json(value: TrustedExecutable) -> dict[str, object]:
    return {
        "requested_path": value.requested_path,
        "resolved_path": value.resolved_path,
        "owner_uid": value.owner_uid,
        "mode": f"{value.mode:04o}",
        "sha256": value.sha256,
        "version": value.version,
    }


def _os_release() -> dict[str, str]:
    result: dict[str, str] = {}
    data = Path("/etc/os-release").read_text(encoding="utf-8")
    if len(data.encode("utf-8")) > 64 * 1024:
        raise fail(StopReason.SANDBOX_SETUP_FAILURE, "os-release is unexpectedly large")
    for line in data.splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Z_]+", name):
            continue
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
        result[name] = value
    return result


def _tool_environment(home: str = "/nonexistent") -> dict[str, str]:
    return {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": home,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
    }


def _run_small(argv: tuple[str, ...], *, env: dict[str, str] | None = None) -> bytes:
    try:
        result = run_bounded_process(
            argv,
            input_bytes=b"",
            timeout_seconds=15,
            output_max_bytes=1024 * 1024,
            env=env or _tool_environment(),
        )
    except OSError as exc:
        raise fail(StopReason.SANDBOX_SETUP_FAILURE, f"tool probe failed: {argv[0]}") from exc
    return _probe_stdout(argv, result)


def _probe_stdout(argv: tuple[str, ...], result: BoundedProcessResult) -> bytes:
    if result.output_limited:
        raise fail(StopReason.SANDBOX_SETUP_FAILURE, f"tool probe output exceeded cap: {argv[0]}")
    if result.timed_out:
        raise fail(StopReason.SANDBOX_SETUP_FAILURE, f"tool probe timed out: {argv[0]}")
    if result.returncode != 0:
        raise fail(
            StopReason.SANDBOX_SETUP_FAILURE,
            f"tool probe exited unsuccessfully: {argv[0]} ({result.returncode})",
        )
    return result.stdout


def _run_small_in_service(
    argv: tuple[str, ...],
    runner: TransientServiceRunner,
    *,
    env: dict[str, str] | None = None,
) -> bytes:
    selected_environment = env or _tool_environment()
    probed_command = (
        "/usr/bin/env",
        "-i",
        *(f"{name}={value}" for name, value in sorted(selected_environment.items())),
        *argv,
    )
    # Keep even an instantaneously exiting version command alive until the
    # parent has inspected the transient unit's exact lifecycle properties.
    # TransientServiceRunner invokes its inspection callback before it writes
    # this one-byte marker, after which the gate execs the reviewed command.
    command = (
        "/usr/bin/python3",
        "-I",
        "-B",
        "-S",
        "-c",
        _SERVICE_VERSION_GATE_CODE,
        *probed_command,
    )
    limits = ServiceLimits(
        memory_max_bytes=256 * 1024 * 1024,
        tasks_max=64,
        runtime_max_seconds=15,
        timeout_stop_seconds=3,
        limit_fsize_bytes=1024 * 1024,
        limit_nofile=128,
        output_max_bytes=1024 * 1024,
    )
    try:
        service = runner.run(
            command,
            role="trusted-executable-version",
            input_bytes=_SERVICE_VERSION_GATE_MARKER,
            timeout_seconds=15,
            limits=limits,
        )
    except (OSError, ValueError) as exc:
        raise fail(
            StopReason.SANDBOX_SETUP_FAILURE,
            f"contained tool probe failed: {argv[0]}",
        ) from exc
    if not service.cgroup_empty:
        raise fail(
            StopReason.SERVICE_LIFECYCLE_MISMATCH,
            "contained tool version probe did not prove cgroup emptiness",
        )
    return _probe_stdout(argv, service.process)


def inspect_trusted_executable(
    path: str,
    *,
    version_argv: tuple[str, ...],
    service_runner: TransientServiceRunner | None = None,
) -> TrustedExecutable:
    if not version_argv or version_argv[0] != path:
        raise ValueError("version argv must begin with the selected executable path")
    requested = Path(path)
    if not requested.is_absolute():
        raise ValueError("trusted executable path must be absolute")
    resolved = Path(os.path.realpath(requested))
    try:
        verify_safe_ancestors(resolved)
    except (OSError, ValueError) as exc:
        raise fail(
            StopReason.SANDBOX_SETUP_FAILURE,
            "trusted executable ancestry is unsafe or unverifiable",
        ) from exc
    info = os.stat(resolved, follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid not in {0, os.geteuid()}:
        raise fail(StopReason.SANDBOX_SETUP_FAILURE, "trusted executable ownership/type is unsafe")
    mode = stat.S_IMODE(info.st_mode)
    if not safe_owned_mode(info) or not mode & 0o100:
        raise fail(StopReason.SANDBOX_SETUP_FAILURE, "trusted executable mode is unsafe")
    fd = os.open(resolved, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_uid",
            "st_gid",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(getattr(info, name) != getattr(opened, name) for name in stable_fields):
            raise fail(StopReason.SANDBOX_SETUP_FAILURE, "trusted executable changed during probe")
        try:
            reject_extended_metadata_fd(fd)
        except ValueError as exc:
            raise fail(
                StopReason.SANDBOX_SETUP_FAILURE,
                "trusted executable extended metadata is unsafe or unverifiable",
            ) from exc
        with os.fdopen(os.dup(fd), "rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        descriptor_path = f"/proc/{os.getpid()}/fd/{fd}"
        actual_argv = (
            "/usr/bin/env",
            "-a",
            str(resolved),
            descriptor_path,
            *version_argv[1:],
        )
        version_bytes = (
            _run_small(actual_argv)
            if service_runner is None
            else _run_small_in_service(actual_argv, service_runner)
        )
        retained_after = os.fstat(fd)
        try:
            after = os.stat(resolved, follow_symlinks=False)
        except OSError:
            raise fail(
                StopReason.SANDBOX_SETUP_FAILURE,
                "trusted executable disappeared during its version probe",
            ) from None
        if any(
            getattr(opened, name) != getattr(observed, name)
            for observed in (retained_after, after)
            for name in stable_fields
        ):
            raise fail(
                StopReason.SANDBOX_SETUP_FAILURE,
                "trusted executable changed during its version probe",
            )
        try:
            reject_extended_metadata_fd(fd)
        except ValueError as exc:
            raise fail(
                StopReason.SANDBOX_SETUP_FAILURE,
                "trusted executable extended metadata changed during its version probe",
            ) from exc
    finally:
        os.close(fd)
    version = version_bytes.decode("utf-8", "strict").strip()
    return TrustedExecutable(path, str(resolved), info.st_uid, mode, digest, version)


def run_preflight(
    *,
    codex_path: str,
    claude_path: str,
    probe_containment: bool = True,
) -> EnvironmentReport:
    release = _os_release()
    os_id = release.get("ID", "")
    os_version = release.get("VERSION_ID", "")
    if os_id != SUPPORTED_OS_ID or os_version != SUPPORTED_OS_VERSION:
        raise fail(StopReason.SANDBOX_SETUP_FAILURE, "host is outside the frozen Ubuntu matrix")
    if platform.machine() != SUPPORTED_MACHINE or sys.version_info[:3] != SUPPORTED_PYTHON:
        raise fail(StopReason.SANDBOX_SETUP_FAILURE, "machine or Python is outside the matrix")
    python_executable = inspect_trusted_executable(
        "/usr/bin/python3",
        version_argv=("/usr/bin/python3", "--version"),
    )
    expected_python = "Python " + ".".join(str(part) for part in SUPPORTED_PYTHON)
    if python_executable.version != expected_python:
        raise fail(StopReason.SANDBOX_SETUP_FAILURE, "unsupported sandbox Python version")
    git = _run_small(("/usr/bin/git", "--version")).decode("ascii", "strict").strip()
    if git != f"git version {SUPPORTED_GIT_VERSION}":
        raise fail(StopReason.GIT_POLICY_OR_OUTPUT_FAILURE, "unsupported Git version")
    systemd_line = _run_small(("/usr/bin/systemctl", "--version")).splitlines()[0].decode("ascii")
    if systemd_line != f"systemd {SUPPORTED_SYSTEMD_VERSION} (259.5-0ubuntu3)":
        raise fail(StopReason.SERVICE_LIFECYCLE_MISMATCH, "unsupported systemd version")
    bash_line = _run_small(("/bin/bash", "--version")).splitlines()[0].decode("utf-8")
    bash_match = re.search(r"version ([0-9.]+)", bash_line)
    if bash_match is None or not bash_match.group(1).startswith(SUPPORTED_BASH_VERSION_PREFIX):
        raise fail(StopReason.SANDBOX_SETUP_FAILURE, "unsupported Bash version")
    bubblewrap = probe_bubblewrap_package()
    version_service = TransientServiceRunner()
    codex = inspect_trusted_executable(
        codex_path,
        version_argv=(codex_path, "--version"),
        service_runner=version_service,
    )
    claude = inspect_trusted_executable(
        claude_path,
        version_argv=(claude_path, "--version"),
        service_runner=version_service,
    )
    if codex.version != f"codex-cli {SUPPORTED_CODEX_VERSION}":
        raise fail(StopReason.GITLESS_INVOCATION_PROBE_FAILED, "unsupported Codex CLI version")
    if claude.version != f"{SUPPORTED_CLAUDE_VERSION} (Claude Code)":
        raise fail(StopReason.SANDBOX_SETUP_FAILURE, "unsupported Claude Code version")
    require_openat2()
    try:
        author_service = inspect_fixed_author_service(probe=probe_containment)
    except AgentLoopError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise fail(
            StopReason.SANDBOX_SETUP_FAILURE,
            "fixed author-service installation provenance is missing or unsafe",
        ) from exc
    namespace_ok = False
    service_ok = False
    if probe_containment:
        probe_bwrap_namespaces()
        namespace_ok = True
        TransientServiceRunner().probe(
            limits=ServiceLimits(
                memory_max_bytes=128 * 1024 * 1024,
                tasks_max=32,
                runtime_max_seconds=30,
                limit_fsize_bytes=1024 * 1024,
                limit_nofile=128,
                output_max_bytes=1024 * 1024,
            )
        )
        service_ok = True
    return EnvironmentReport(
        os_id,
        os_version,
        platform.machine(),
        platform.release(),
        platform.python_version(),
        git,
        systemd_line,
        bash_line,
        bubblewrap,
        python_executable,
        codex,
        claude,
        author_service,
        True,
        namespace_ok,
        service_ok,
    )
