"""Production adapters joining the sandbox boundary to the serial runner.

This module is intentionally small in authority: it can materialize only a
canonical manifest, launch one reviewed argv through ``sandbox-init`` under the
sole Bubblewrap/systemd backend, and translate the already-validated result to
the runner's immutable adapter records.  Agent output never selects a host
command, mount, environment key, or working directory.
"""

from __future__ import annotations

import json
import math
import os
import stat
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import Protocol

from . import claude_managed_policy
from .artifacts import ContentAddressedBlobStore
from .claude_client import ClaudeClient, ClaudeInvocation
from .codex_client import CodexClient, CodexInvocation, build_codex_parent_environment
from .constants import (
    CLAUDE_API_TIMEOUT_MS,
    DEFAULT_AUTHOR_TIMEOUT_SECONDS,
    DEFAULT_CRITIC_TIMEOUT_SECONDS,
    DEFAULT_MAX_AGENT_OUTPUT_BYTES,
    DEFAULT_MAX_FIELD_BYTES,
    DEFAULT_MAX_RAW_LOG_BYTES,
    DEFAULT_MAX_RUNTIME_SECONDS,
    DEFAULT_STOP_TIMEOUT_SECONDS,
    DEFAULT_VALIDATION_TIMEOUT_SECONDS,
    Limits,
)
from .credentials import CodexCredentialTransaction, build_claude_parent_environment
from .declassify import KnownSecret, raw_log_contains_known_secret
from .errors import StopReason, fail
from .manifests import SubjectManifest, verify_manifest_blobs
from .models import EntryKind, sha256_hex
from .provenance import (
    closure_sha256,
    open_verified_closure,
    python_source_closure_sha256,
    snapshot_reviewed_closure,
)
from .runner import (
    AuthorRequest,
    AuthorTurn,
    CriticRequest,
    CriticTurn,
    ValidationRequest,
    ValidationTurn,
)
from .sandbox import SandboxMount, SandboxPolicy, SandboxRole, build_bwrap_argv
from .sandbox_init import (
    MAX_PROTOCOL_EXPORT_BYTES,
    SandboxRequest,
    SandboxResult,
    SupervisorLimits,
    encode_request,
    parse_request,
    parse_result,
)
from .service import (
    BoundedProcessResult,
    ServiceLimits,
    ServiceResult,
    TransientServiceRunner,
)
from .validation import CheckExecution, ValidationSummary
from .validation_batch import (
    MAX_VALIDATION_BATCH_RESULT_BYTES,
    MAX_VALIDATION_CHECKS,
    VALIDATION_BATCH_SENTINEL,
    ValidationBatchCheck,
    ValidationBatchRecord,
    ValidationBatchRequest,
    encode_validation_batch_request,
    parse_validation_batch_result,
)

Clock = Callable[[], float]

_RUNTIME_PACKAGE_TARGET = "/opt/agent-loop-runtime"
_SANDBOX_INIT_BOOTSTRAP = (
    "import importlib.machinery as m,runpy,sys;"
    f"root={_RUNTIME_PACKAGE_TARGET!r};package=root+'/agent_loop';"
    "source_loader=(m.SourceFileLoader,m.SOURCE_SUFFIXES);"
    "sys.path_importer_cache[root]=m.FileFinder(root,source_loader);"
    "sys.path_importer_cache[package]=m.FileFinder(package,source_loader);"
    "sys.path.insert(0,root);"
    "runpy.run_module('agent_loop.sandbox_init',run_name='__main__')"
)
_SANDBOX_INIT_COMMAND = (
    "/usr/bin/python3",
    "-I",
    "-B",
    "-c",
    _SANDBOX_INIT_BOOTSTRAP,
)
_MOUNT_FD_LAUNCHER = (
    "import json,os,sys\n"
    "payload=json.loads(sys.argv[1]);argv=payload['argv'];retained=[]\n"
    "for binding in payload['bindings']:\n"
    " flags=os.O_RDONLY|os.O_NOFOLLOW\n"
    " if binding['directory']:flags|=os.O_DIRECTORY\n"
    " fd=os.open(binding['source'],flags);info=os.fstat(fd)\n"
    " if [info.st_dev,info.st_ino] != binding['identity']:raise SystemExit(124)\n"
    " os.set_inheritable(fd,True);retained.append(fd)\n"
    " option='--ro-bind' if binding['read_only'] else '--bind';matched=False\n"
    " for index in range(len(argv)-2):\n"
    "  if argv[index:index+3] == [option,binding['source'],binding['target']]:\n"
    "   argv[index+1]=f'/proc/self/fd/{fd}';matched=True;break\n"
    " if not matched:raise SystemExit(123)\n"
    "os.execv(argv[0],argv)\n"
)
_VALIDATION_ENVIRONMENT = {
    "PATH": "/usr/bin:/bin",
    "HOME": "/runtime/home",
    "TMPDIR": "/runtime/tmp",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TZ": "UTC",
}


def _open_mount_authority(
    mount: SandboxMount,
    *,
    python_sources_only: bool,
) -> int:
    if mount.closure_sha256 is not None:
        return open_verified_closure(
            Path(mount.source),
            mount.closure_sha256,
            python_sources_only=python_sources_only,
        )
    metadata = os.stat(mount.source, follow_symlinks=False)
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    if stat.S_ISDIR(metadata.st_mode):
        flags |= os.O_DIRECTORY
    elif not stat.S_ISREG(metadata.st_mode):
        raise ValueError("sandbox mount source has an unsafe type")
    descriptor = os.open(mount.source, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise ValueError("sandbox mount source identity changed")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _bind_mount_sources_to_descriptors(
    command: tuple[str, ...],
    mounts: Sequence[SandboxMount],
    *,
    verified_descriptors: Sequence[int] | None = None,
) -> tuple[tuple[str, ...], tuple[int, ...]]:
    if verified_descriptors is not None and len(verified_descriptors) != len(mounts):
        raise ValueError("verified mount descriptors do not match the mount list")
    bindings: list[dict[str, object]] = []
    retained: list[int] = []
    try:
        for index, mount in enumerate(mounts):
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
            metadata = os.stat(mount.source, follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                flags |= os.O_DIRECTORY
            elif not stat.S_ISREG(metadata.st_mode):
                raise ValueError("sandbox mount source is not a regular file or directory")
            descriptor = (
                os.open(mount.source, flags)
                if verified_descriptors is None
                else os.dup(verified_descriptors[index])
            )
            retained.append(descriptor)
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise ValueError("sandbox mount source identity changed before launch")
            bindings.append(
                {
                    "source": mount.source,
                    "target": mount.target,
                    "read_only": mount.read_only,
                    "directory": stat.S_ISDIR(opened.st_mode),
                    "identity": [opened.st_dev, opened.st_ino],
                }
            )
        payload = json.dumps(
            {"argv": list(command), "bindings": bindings},
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        launcher = ("/usr/bin/python3", "-I", "-B", "-c", _MOUNT_FD_LAUNCHER, payload)
        return launcher, tuple(retained)
    except BaseException:
        for descriptor in retained:
            os.close(descriptor)
        raise


class ServiceRunner(Protocol):
    """The narrow side-effect surface used by :class:`SandboxExecutor`."""

    def run(
        self,
        command: tuple[str, ...],
        *,
        role: str,
        input_bytes: bytes = b"",
        timeout_seconds: float,
        limits: ServiceLimits | None = None,
    ) -> ServiceResult: ...


class CredentialTransaction(Protocol):
    """Structural view used to make credential ordering independently testable."""

    @property
    def codex_home(self) -> Path: ...

    def reconcile_after_turn(self) -> bool: ...


@dataclass(frozen=True, slots=True)
class SandboxExecution:
    """One response bound to its exact request and outer-service cleanup proof."""

    request: SandboxRequest
    result: SandboxResult
    service: ServiceResult
    completed_at: float

    def bounded_process(self) -> BoundedProcessResult:
        """Translate the primary result without confusing it with systemd-run."""

        duration_seconds = self.result.process.duration_ms / 1000
        return BoundedProcessResult(
            returncode=self.result.process.returncode,
            stdout=self.result.process.stdout,
            stderr=self.result.process.stderr,
            started_at=max(0.0, self.completed_at - duration_seconds),
            completed_at=self.completed_at,
            timed_out=self.result.process.timed_out,
            output_limited=self.result.process.output_limited,
        )


AttemptSink = Callable[[SandboxRole, int, SandboxExecution], None]
ServiceAttemptSink = Callable[
    [SandboxRole, int, SandboxRequest, ServiceResult, float],
    None,
]


def _normalized_host_path(value: str | os.PathLike[str], *, name: str) -> str:
    raw = os.fspath(value)
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise ValueError(f"{name} must be a non-empty text path")
    path = Path(raw)
    normalized = os.path.normpath(raw)
    if (
        not path.is_absolute()
        or raw == "/"
        or raw.startswith("//")
        or raw != normalized
        or ".." in path.parts
    ):
        raise ValueError(f"{name} must be a normalized absolute non-root path")
    return raw


def _normalized_sandbox_path(value: str, *, name: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{name} must be a non-empty NUL-free path")
    parsed = PurePosixPath(value)
    if not parsed.is_absolute() or str(parsed) != value or value == "/" or ".." in parsed.parts:
        raise ValueError(f"{name} must be a normalized absolute non-root path")
    return value


def _reject_supervisor_shadow(target: str) -> None:
    """Prevent later mounts from replacing trusted PID-1 code or interpreter."""

    for protected in ("/usr/bin/python3", _RUNTIME_PACKAGE_TARGET):
        if (
            target == protected
            or protected.startswith(target.rstrip("/") + "/")
            or target.startswith(protected.rstrip("/") + "/")
        ):
            raise ValueError("sandbox mount target overlaps the trusted supervisor runtime")


def _targets_overlap(first: str, second: str) -> bool:
    return (
        first == second
        or first.startswith(second.rstrip("/") + "/")
        or second.startswith(first.rstrip("/") + "/")
    )


def _frozen_toolchain_mounts(
    mounts: Sequence[SandboxMount],
) -> tuple[SandboxMount, ...]:
    frozen = tuple(mounts)
    targets: list[str] = []
    for mount in frozen:
        if not isinstance(mount, SandboxMount) or not mount.read_only:
            raise ValueError("author toolchain mounts must be reviewed and read-only")
        source = _normalized_host_path(mount.source, name="toolchain mount source")
        target = _normalized_sandbox_path(mount.target, name="toolchain mount target")
        if not os.path.exists(source):
            raise ValueError("reviewed toolchain mount source does not exist")
        reserved_targets = (
            "/control",
            "/dev",
            "/proc",
            "/run",
            "/runtime",
            "/tmp",
            "/workspace",
        )
        if any(
            target == reserved or target.startswith(reserved + "/")
            for reserved in reserved_targets
        ):
            raise ValueError("toolchain mount targets cannot enter private sandbox state")
        _reject_supervisor_shadow(target)
        if any(_targets_overlap(target, previous) for previous in targets):
            raise ValueError("toolchain mount targets cannot overlap")
        targets.append(target)
    return frozen


def _policy_for(
    role: SandboxRole,
    *,
    workspace_bytes: int,
    mounts: tuple[SandboxMount, ...],
) -> SandboxPolicy:
    if role is SandboxRole.AUTHOR:
        return SandboxPolicy(
            role,
            workspace_bytes=workspace_bytes,
            mounts=mounts,
            control_egress=True,
            cwd="/runtime/author-cwd",
        )
    if role is SandboxRole.CRITIC:
        return SandboxPolicy(
            role,
            workspace_bytes=workspace_bytes,
            mounts=mounts,
            control_egress=True,
            cwd="/runtime/critic-cwd",
        )
    if role is SandboxRole.VALIDATION:
        return SandboxPolicy(
            role,
            workspace_bytes=workspace_bytes,
            mounts=mounts,
            cwd="/workspace",
        )
    return SandboxPolicy(
        role,
        workspace_bytes=workspace_bytes,
        mounts=mounts,
        cwd="/runtime/git-cwd",
    )


class SandboxExecutor:
    """Run the installed trusted supervisor under Bubblewrap and systemd.

    ``sandbox-init`` is the initial command in Bubblewrap's PID namespace, and
    Bubblewrap is the main command of the transient service.  There is no host
    subprocess fallback.  Tests may inject a service runner which executes the
    same encoded supervisor request without requiring the pinned target host.
    """

    def __init__(
        self,
        blobs: ContentAddressedBlobStore,
        *,
        service: ServiceRunner | None = None,
        package_root: str | os.PathLike[str] | None = None,
        limits: Limits | None = None,
        terminate_grace_ms: int = 1_000,
        max_export_bytes: int = MAX_PROTOCOL_EXPORT_BYTES,
        service_attempt_sink: ServiceAttemptSink | None = None,
        clock: Clock = time.monotonic,
    ) -> None:
        if not isinstance(blobs, ContentAddressedBlobStore):
            raise TypeError("blobs must be a ContentAddressedBlobStore")
        if limits is not None and not isinstance(limits, Limits):
            raise TypeError("limits must be a Limits instance")
        if not callable(clock):
            raise TypeError("clock must be callable")
        if service_attempt_sink is not None and not callable(service_attempt_sink):
            raise TypeError("service_attempt_sink must be callable")
        if (
            not isinstance(terminate_grace_ms, int)
            or isinstance(terminate_grace_ms, bool)
            or not 1 <= terminate_grace_ms <= 5_000
        ):
            raise ValueError("terminate_grace_ms must be in [1, 5000]")
        if (
            not isinstance(max_export_bytes, int)
            or isinstance(max_export_bytes, bool)
            or not DEFAULT_MAX_FIELD_BYTES + 1_024
            <= max_export_bytes
            <= MAX_PROTOCOL_EXPORT_BYTES
        ):
            raise ValueError("max_export_bytes is outside the sandbox protocol bound")
        selected_root = (
            Path(__file__).parent.parent if package_root is None else Path(package_root)
        )
        normalized_root = Path(
            _normalized_host_path(selected_root, name="installed package root")
        )
        package_directory = normalized_root / "agent_loop"
        if not (package_directory / "sandbox_init.py").is_file():
            raise ValueError("installed package root does not contain agent_loop/sandbox_init.py")
        package_closure_sha256 = python_source_closure_sha256(package_directory)
        snapshot_directory = tempfile.TemporaryDirectory(prefix="agent-loop-mounts-")
        package_snapshot_parent = Path(snapshot_directory.name) / "runtime"
        package_snapshot_parent.mkdir(mode=0o700)
        try:
            package_snapshot, package_snapshot_sha256 = snapshot_reviewed_closure(
                package_directory,
                package_snapshot_parent,
                package_closure_sha256,
                python_sources_only=True,
            )
        except BaseException:
            snapshot_directory.cleanup()
            raise
        self._blobs = blobs
        self._service: ServiceRunner | None = service
        self._package_mount = SandboxMount(
            os.fspath(package_snapshot),
            f"{_RUNTIME_PACKAGE_TARGET}/agent_loop",
            read_only=True,
            closure_sha256=package_snapshot_sha256,
        )
        self._package_source_directory = package_directory
        self._package_source_closure_sha256 = package_closure_sha256
        self._package_directory = package_snapshot
        self._package_closure_sha256 = package_snapshot_sha256
        self._snapshot_directory = snapshot_directory
        self._mount_snapshots: dict[tuple[str, str], tuple[str, str]] = {}
        self._limits = limits or Limits()
        self._terminate_grace_ms = terminate_grace_ms
        self._max_export_bytes = max_export_bytes
        self._service_attempt_sink = service_attempt_sink
        self._service_attempt_number = 0
        self._clock = clock

    @property
    def blobs(self) -> ContentAddressedBlobStore:
        return self._blobs

    @property
    def limits(self) -> Limits:
        return self._limits

    def _request_blobs(self, manifest: SubjectManifest) -> tuple[tuple[str, bytes], ...]:
        verify_manifest_blobs(manifest, self._blobs)
        digests = sorted(
            {
                entry.blob_sha256
                for entry in manifest.entries
                if entry.kind is EntryKind.REGULAR and entry.blob_sha256 is not None
            }
        )
        result: list[tuple[str, bytes]] = []
        for digest in digests:
            result.append((digest, self._blobs.read_blob(digest)))
        return tuple(result)

    def _snapshot_mount(self, mount: SandboxMount) -> SandboxMount:
        digest = mount.closure_sha256
        if digest is None:
            return mount
        key = (mount.source, digest)
        selected = self._mount_snapshots.get(key)
        if selected is None:
            parent = Path(self._snapshot_directory.name) / f"mount-{len(self._mount_snapshots):04d}"
            parent.mkdir(mode=0o700)
            snapshot, snapshot_digest = snapshot_reviewed_closure(
                Path(mount.source),
                parent,
                digest,
            )
            selected = (os.fspath(snapshot), snapshot_digest)
            self._mount_snapshots[key] = selected
        return SandboxMount(
            selected[0],
            mount.target,
            read_only=True,
            closure_sha256=selected[1],
        )

    def execute(
        self,
        *,
        role: SandboxRole,
        manifest: SubjectManifest,
        argv: Sequence[str],
        environment: Mapping[str, str],
        cwd: str,
        timeout_seconds: float,
        stdin_bytes: bytes = b"",
        mounts: Sequence[SandboxMount] = (),
        output_max_bytes: int = DEFAULT_MAX_AGENT_OUTPUT_BYTES,
    ) -> SandboxExecution:
        if not isinstance(role, SandboxRole):
            raise TypeError("role must be a SandboxRole")
        if not isinstance(manifest, SubjectManifest):
            raise TypeError("manifest must be a SubjectManifest")
        if (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or not math.isfinite(float(timeout_seconds))
            or timeout_seconds <= 0
            or timeout_seconds > DEFAULT_MAX_RUNTIME_SECONDS
        ):
            raise ValueError("sandbox timeout is outside the supported runtime bound")
        selected_argv = tuple(argv)
        selected_mounts = tuple(mounts)
        is_validation_batch = bool(
            role is SandboxRole.VALIDATION
            and selected_argv == (VALIDATION_BATCH_SENTINEL,)
            and cwd == "/workspace"
            and dict(environment) == _VALIDATION_ENVIRONMENT
            and all(
                isinstance(mount, SandboxMount)
                and mount.read_only
                and not mount.target.startswith("/control")
                for mount in selected_mounts
            )
        )
        if VALIDATION_BATCH_SENTINEL in selected_argv and not is_validation_batch:
            raise ValueError("the validation-batch sentinel is reserved to its exact role")
        maximum_output = (
            MAX_VALIDATION_BATCH_RESULT_BYTES
            if is_validation_batch
            else DEFAULT_MAX_AGENT_OUTPUT_BYTES
        )
        if (
            not isinstance(output_max_bytes, int)
            or isinstance(output_max_bytes, bool)
            or not 1 <= output_max_bytes <= maximum_output
        ):
            raise ValueError("output_max_bytes is outside the sandbox protocol bound")
        if not isinstance(stdin_bytes, bytes):
            raise TypeError("sandbox stdin must be bytes")
        try:
            current_source_sha256 = python_source_closure_sha256(
                self._package_source_directory
            )
            current_runtime_sha256 = python_source_closure_sha256(self._package_directory)
        except (OSError, TypeError, ValueError):
            raise fail(
                StopReason.SANDBOX_SETUP_FAILURE,
                "trusted sandbox-init package closure is no longer verifiable",
            ) from None
        if (
            current_source_sha256 != self._package_source_closure_sha256
            or current_runtime_sha256 != self._package_closure_sha256
        ):
            raise fail(
                StopReason.SANDBOX_SETUP_FAILURE,
                "trusted sandbox-init package closure changed before launch",
            )
        effective_mounts: list[SandboxMount] = []
        for mount in selected_mounts:
            if not isinstance(mount, SandboxMount):
                raise TypeError("mounts must contain only SandboxMount values")
            source = _normalized_host_path(mount.source, name="sandbox mount source")
            target = _normalized_sandbox_path(mount.target, name="sandbox mount target")
            if not os.path.exists(source):
                raise ValueError("sandbox mount source does not exist")
            _reject_supervisor_shadow(target)
            if mount.closure_sha256 is not None:
                try:
                    current_mount_sha256 = closure_sha256(Path(source))
                except (OSError, TypeError, ValueError):
                    raise fail(
                        StopReason.SANDBOX_SETUP_FAILURE,
                        "a reviewed mount closure is no longer verifiable",
                    ) from None
                if current_mount_sha256 != mount.closure_sha256:
                    raise fail(
                        StopReason.SANDBOX_SETUP_FAILURE,
                        "a reviewed mount closure changed before launch",
                    )
            try:
                effective_mount = self._snapshot_mount(mount)
            except (OSError, TypeError, ValueError):
                raise fail(
                    StopReason.SANDBOX_SETUP_FAILURE,
                    "a reviewed mount could not be snapshotted safely",
                ) from None
            if effective_mount.closure_sha256 is not None:
                try:
                    snapshot_sha256 = closure_sha256(Path(effective_mount.source))
                except (OSError, TypeError, ValueError):
                    raise fail(
                        StopReason.SANDBOX_SETUP_FAILURE,
                        "a private mount snapshot is no longer verifiable",
                    ) from None
                if snapshot_sha256 != effective_mount.closure_sha256:
                    raise fail(
                        StopReason.SANDBOX_SETUP_FAILURE,
                        "a private mount snapshot changed before launch",
                    )
            effective_mounts.append(effective_mount)
        request = SandboxRequest(
            manifest=manifest,
            blobs=self._request_blobs(manifest),
            argv=selected_argv,
            env=tuple(sorted(dict(environment).items())),
            cwd=cwd,
            stdin_bytes=stdin_bytes,
            limits=SupervisorLimits(
                timeout_ms=max(1, math.ceil(float(timeout_seconds) * 1_000)),
                terminate_grace_ms=self._terminate_grace_ms,
                max_output_bytes=output_max_bytes,
                max_export_bytes=self._max_export_bytes,
                subject=self._limits,
            ),
        )
        encoded = encode_request(request)
        # Validate locally with the exact decoder used inside the namespace.
        # This makes an invalid fixed environment/argv a pre-spawn failure.
        parse_request(encoded)

        policy_mounts = (self._package_mount, *effective_mounts)
        policy = _policy_for(
            role,
            workspace_bytes=self._limits.workspace_bytes,
            mounts=policy_mounts,
        )
        inner_command = build_bwrap_argv(policy, _SANDBOX_INIT_COMMAND)
        mount_authorities: list[int] = []
        try:
            for index, mount in enumerate(policy_mounts):
                mount_authorities.append(
                    _open_mount_authority(
                        mount,
                        python_sources_only=index == 0,
                    )
                )
            command, mount_descriptors = _bind_mount_sources_to_descriptors(
                inner_command,
                policy_mounts,
                verified_descriptors=mount_authorities,
            )
        except (OSError, TypeError, ValueError):
            raise fail(
                StopReason.SANDBOX_SETUP_FAILURE,
                "sandbox mount identities could not be retained before launch",
            ) from None
        finally:
            for descriptor in mount_authorities:
                os.close(descriptor)
        cleanup_allowance = self._terminate_grace_ms / 1_000 + 4
        service_timeout = float(timeout_seconds) + cleanup_allowance
        service_limits = ServiceLimits(
            memory_max_bytes=self._limits.memory_max_bytes,
            tasks_max=self._limits.tasks_max,
            runtime_max_seconds=max(1, math.ceil(service_timeout)),
            timeout_stop_seconds=DEFAULT_STOP_TIMEOUT_SECONDS,
            limit_fsize_bytes=self._limits.limit_fsize_bytes,
            limit_nofile=self._limits.limit_nofile,
            output_max_bytes=self._max_export_bytes,
        )
        self._service_attempt_number += 1
        service_attempt_number = self._service_attempt_number
        retained_by_service = self._service is None and self._service_attempt_sink is not None

        def retain_service_result(result: ServiceResult) -> None:
            if self._service_attempt_sink is not None:
                self._service_attempt_sink(
                    role,
                    service_attempt_number,
                    request,
                    result,
                    float(self._clock()),
                )

        service_runner: ServiceRunner = (
            TransientServiceRunner(
                result_sink=retain_service_result if retained_by_service else None
            )
            if self._service is None
            else self._service
        )
        try:
            service_result = service_runner.run(
                command,
                role=role.value,
                input_bytes=encoded,
                timeout_seconds=service_timeout,
                limits=service_limits,
            )
        finally:
            for descriptor in mount_descriptors:
                os.close(descriptor)
        completed_at = float(self._clock())
        if self._service_attempt_sink is not None and not retained_by_service:
            self._service_attempt_sink(
                role,
                service_attempt_number,
                request,
                service_result,
                completed_at,
            )
        if not service_result.cgroup_empty:
            raise fail(
                StopReason.SERVICE_LIFECYCLE_MISMATCH,
                "transient sandbox service did not prove cgroup emptiness",
            )
        if service_result.process.output_limited:
            raise fail(StopReason.AGENT_OUTPUT_LIMIT, "sandbox protocol output exceeded its cap")
        if service_result.process.timed_out:
            raise fail(
                StopReason.SERVICE_LIFECYCLE_MISMATCH,
                "transient sandbox service exceeded the supervisor cleanup allowance",
            )

        # Parse before checking the wrapper status: sandbox-init deliberately
        # exits nonzero after emitting a typed, strict error response.
        result = parse_result(service_result.process.stdout, request=request)
        if service_result.process.returncode != 0:
            raise fail(
                StopReason.SERVICE_LIFECYCLE_MISMATCH,
                "sandbox-init emitted a result but its transient service failed",
            )
        if not result.cleanup.namespace_empty:
            # The response parser already rejects this, retained as an explicit
            # acceptance condition at the adapter boundary.
            raise fail(
                StopReason.AUTHOR_SERVICE_NOT_EMPTY,
                "sandbox candidate cannot be accepted before PID namespace cleanup",
            )
        return SandboxExecution(request, result, service_result, completed_at)

    def persist_new_blobs(self, execution: SandboxExecution) -> None:
        """Persist verified exports only after the calling adapter's final gate."""

        if not isinstance(execution, SandboxExecution):
            raise TypeError("execution must be a SandboxExecution")
        for digest, data in execution.result.new_blobs:
            if sha256_hex(data) != digest or self._blobs.put_blob(data) != digest:
                raise fail(
                    StopReason.OUT_OF_BAND_CHANGE,
                    "sandbox export changed content-addressed blob identity",
                )


@dataclass(frozen=True, slots=True)
class FixedValidationCheck:
    """One operator-selected command frozen before any author turn."""

    check_id: str
    command: str
    timeout_seconds: float = DEFAULT_VALIDATION_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        if (
            not isinstance(self.check_id, str)
            or not self.check_id
            or "\x00" in self.check_id
            or len(self.check_id.encode("utf-8")) > 256
        ):
            raise ValueError("validation check ID is empty, unsafe, or oversized")
        if (
            not isinstance(self.command, str)
            or not self.command
            or "\x00" in self.command
            or len(self.command.encode("utf-8")) > DEFAULT_MAX_FIELD_BYTES
        ):
            raise ValueError("validation command is empty, unsafe, or oversized")
        if (
            not isinstance(self.timeout_seconds, (int, float))
            or isinstance(self.timeout_seconds, bool)
            or not math.isfinite(float(self.timeout_seconds))
            or not 0 < self.timeout_seconds <= DEFAULT_MAX_RUNTIME_SECONDS
        ):
            raise ValueError("validation timeout is outside the supported bound")


# Concise public spelling for callers which do not need to emphasize freezing.
ValidationCheck = FixedValidationCheck


def _bounded_timeout(value: float, *, name: str) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(float(value))
        or not 0 < value <= DEFAULT_MAX_RUNTIME_SECONDS
    ):
        raise ValueError(f"{name} is outside the supported runtime bound")
    return float(value)


def _remaining_timeout(
    *,
    deadline: float,
    maximum: float,
    clock: Clock,
    reason: StopReason,
) -> float:
    remaining = float(deadline) - float(clock())
    selected = min(float(maximum), remaining)
    if not math.isfinite(selected) or selected <= 0:
        raise fail(reason, "no eligible time remains before the monotonic deadline")
    return selected


class SandboxedValidationAdapter:
    """Run every fixed check sequentially in one materialized no-network tmpfs."""

    def __init__(
        self,
        executor: SandboxExecutor,
        checks: Sequence[FixedValidationCheck],
        *,
        mounts: Sequence[SandboxMount] = (),
        max_raw_log_bytes: int = DEFAULT_MAX_RAW_LOG_BYTES,
        output_max_bytes: int = DEFAULT_MAX_AGENT_OUTPUT_BYTES,
        attempt_sink: AttemptSink | None = None,
        clock: Clock = time.monotonic,
    ) -> None:
        frozen_checks = tuple(checks)
        if not frozen_checks or any(
            not isinstance(check, FixedValidationCheck) for check in frozen_checks
        ):
            raise ValueError("validation requires at least one FixedValidationCheck")
        identifiers = [check.check_id for check in frozen_checks]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("validation check IDs must be unique")
        if len(frozen_checks) > MAX_VALIDATION_CHECKS:
            raise ValueError("validation check count exceeds the reviewed batch bound")
        if (
            not isinstance(max_raw_log_bytes, int)
            or isinstance(max_raw_log_bytes, bool)
            or not 1 <= max_raw_log_bytes <= DEFAULT_MAX_RAW_LOG_BYTES
        ):
            raise ValueError("max_raw_log_bytes is outside the reviewed bound")
        if (
            not isinstance(output_max_bytes, int)
            or isinstance(output_max_bytes, bool)
            or not 1 <= output_max_bytes <= DEFAULT_MAX_AGENT_OUTPUT_BYTES
        ):
            raise ValueError("output_max_bytes is outside the sandbox protocol bound")
        if not callable(clock):
            raise TypeError("clock must be callable")
        if attempt_sink is not None and not callable(attempt_sink):
            raise TypeError("attempt_sink must be callable")
        self._executor = executor
        self._checks = frozen_checks
        self._mounts = tuple(mounts)
        self._max_raw_log_bytes = max_raw_log_bytes
        self._output_max_bytes = output_max_bytes
        self._attempt_sink = attempt_sink
        self._attempt_number = 0
        self._clock = clock

    def validate(self, request: ValidationRequest) -> ValidationTurn:
        timeout = _remaining_timeout(
            deadline=request.deadline,
            maximum=DEFAULT_MAX_RUNTIME_SECONDS,
            clock=self._clock,
            reason=StopReason.VALIDATION_TIMEOUT,
        )
        overhead = sum(
            len(_validation_log_header(check.check_id, stream)) + 1
            for check in self._checks
            for stream in ("stdout", "stderr")
        )
        batch_request = ValidationBatchRequest(
            checks=tuple(
                ValidationBatchCheck(
                    check.check_id,
                    check.command,
                    max(1, math.ceil(check.timeout_seconds * 1_000)),
                    self._output_max_bytes,
                )
                for check in self._checks
            ),
            max_raw_output_bytes=max(1, self._max_raw_log_bytes - overhead),
        )
        self._attempt_number += 1
        attempt_number = self._attempt_number
        execution = self._executor.execute(
            role=SandboxRole.VALIDATION,
            manifest=request.subject,
            argv=(VALIDATION_BATCH_SENTINEL,),
            environment=_VALIDATION_ENVIRONMENT,
            cwd="/workspace",
            timeout_seconds=timeout,
            stdin_bytes=encode_validation_batch_request(batch_request),
            mounts=self._mounts,
            output_max_bytes=MAX_VALIDATION_BATCH_RESULT_BYTES,
        )
        if self._attempt_sink is not None:
            # Persist the strict supervisor result before checking its status,
            # decoding the batch protocol, or translating bounded raw output.
            self._attempt_sink(SandboxRole.VALIDATION, attempt_number, execution)
        process = execution.bounded_process()
        if process.returncode != 0 or process.timed_out or process.output_limited:
            raise fail(
                StopReason.VALIDATION_PROCESS_FAILURE,
                "trusted validation-batch supervisor did not return one complete result",
            )
        try:
            records = parse_validation_batch_result(
                process.stdout,
                expected_checks=len(self._checks),
                max_raw_output_bytes=batch_request.max_raw_output_bytes,
            )
        except ValueError:
            raise fail(
                StopReason.SANDBOX_SETUP_FAILURE,
                "trusted validation-batch result failed strict validation",
            ) from None
        executions, raw_log = self._translate_batch_records(
            records,
            completed_at=execution.completed_at,
        )
        summary = ValidationSummary(
            schema_version=1,
            subject_fingerprint=request.subject.fingerprint,
            checks=executions,
        )
        return ValidationTurn(summary, execution.result.candidate, raw_log)

    def _translate_batch_records(
        self,
        records: Sequence[ValidationBatchRecord],
        *,
        completed_at: float,
    ) -> tuple[tuple[CheckExecution, ...], bytes]:
        duration = sum(record.duration_ms for record in records) / 1_000
        cursor = max(0.0, completed_at - duration)
        executions: list[CheckExecution] = []
        raw_log = bytearray()
        for check, record in zip(self._checks, records, strict=False):
            started_at = cursor
            cursor += record.duration_ms / 1_000
            command_unexecutable = (
                record.returncode in {126, 127} and not record.output_limited
            )
            executions.append(
                CheckExecution(
                    check.check_id,
                    check.command,
                    started_at,
                    cursor,
                    None
                    if record.timed_out or record.output_limited or record.returncode < 0
                    else record.returncode,
                    None
                    if record.timed_out or record.output_limited or record.returncode >= 0
                    else -record.returncode,
                    record.timed_out,
                    command_unexecutable,
                    record.process_started and not command_unexecutable,
                    record.output_limited,
                )
            )
            for stream, data in (("stdout", record.stdout), ("stderr", record.stderr)):
                raw_log.extend(_validation_log_header(check.check_id, stream))
                raw_log.extend(data)
                if not data.endswith(b"\n"):
                    raw_log.extend(b"\n")
                if len(raw_log) > self._max_raw_log_bytes:
                    raise fail(
                        StopReason.AGENT_OUTPUT_LIMIT,
                        "validation raw-log cap was exceeded",
                    )
        return tuple(executions), bytes(raw_log)


def _validation_log_header(check_id: str, stream: str) -> bytes:
    return json.dumps(
        {"check_id": check_id, "stream": stream},
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii") + b"\n"


def _reviewed_install(
    install_mount: SandboxMount,
    executable: str,
    *,
    name: str,
) -> tuple[SandboxMount, str]:
    if not isinstance(install_mount, SandboxMount) or not install_mount.read_only:
        raise ValueError(f"{name} install must be one reviewed read-only mount")
    source = _normalized_host_path(install_mount.source, name=f"{name} install source")
    if not os.path.exists(source):
        raise ValueError(f"{name} reviewed install source does not exist")
    _normalized_sandbox_path(install_mount.target, name=f"{name} install target")
    _reject_supervisor_shadow(install_mount.target)
    selected_executable = _normalized_sandbox_path(executable, name=f"{name} executable")
    target = install_mount.target.rstrip("/")
    if selected_executable != target and not selected_executable.startswith(target + "/"):
        raise ValueError(f"{name} executable must be contained by its reviewed install mount")
    return install_mount, selected_executable


def _reviewed_managed_claude_boundary(
    boundary: claude_managed_policy.ManagedClaudeBoundary,
    *,
    install_mount: SandboxMount,
    config_mount: SandboxMount,
) -> tuple[SandboxMount, SandboxMount]:
    """Validate the two fixed administrator-managed critic mounts."""

    if not isinstance(boundary, claude_managed_policy.ManagedClaudeBoundary):
        raise TypeError("managed_boundary must be a ManagedClaudeBoundary")
    if (
        boundary.protocol
        != claude_managed_policy.MANAGED_CLAUDE_BOUNDARY_PROTOCOL
        or boundary.probe_id != claude_managed_policy.MANAGED_CLAUDE_BOUNDARY_ID
    ):
        raise ValueError("managed Claude boundary identity is unsupported")

    expected = (
        (
            boundary.policy_mount,
            claude_managed_policy.MANAGED_CLAUDE_POLICY_SOURCE,
            claude_managed_policy.MANAGED_CLAUDE_POLICY_TARGET,
            "policy",
        ),
        (
            boundary.helper_mount,
            claude_managed_policy.MANAGED_CLAUDE_HELPER_SOURCE,
            claude_managed_policy.MANAGED_CLAUDE_HELPER_TARGET,
            "helper",
        ),
    )
    reviewed: list[SandboxMount] = []
    for mount, source, target, name in expected:
        if not isinstance(mount, SandboxMount):
            raise TypeError(f"managed Claude {name} mount must be a SandboxMount")
        if mount.source != source or mount.target != target:
            raise ValueError(f"managed Claude {name} mount path is not the fixed path")
        if not mount.read_only or mount.closure_sha256 is None:
            raise ValueError(
                f"managed Claude {name} mount must be read-only and closure-witnessed"
            )
        _normalized_host_path(mount.source, name=f"managed Claude {name} source")
        _normalized_sandbox_path(mount.target, name=f"managed Claude {name} target")
        _reject_supervisor_shadow(mount.target)
        reviewed.append(mount)

    policy_mount, helper_mount = reviewed
    if _targets_overlap(policy_mount.target, helper_mount.target):
        raise ValueError("managed Claude mount targets cannot overlap")

    private_targets = (
        "/control",
        "/dev",
        "/proc",
        "/run",
        "/runtime",
        "/tmp",
        "/workspace",
    )
    existing_targets = (install_mount.target, config_mount.target)
    for mount in reviewed:
        if any(_targets_overlap(mount.target, target) for target in private_targets):
            raise ValueError("managed Claude mounts cannot enter private sandbox state")
        if any(_targets_overlap(mount.target, target) for target in existing_targets):
            raise ValueError("managed Claude mounts cannot overlap install or config mounts")

    existing_sources = (install_mount.source, config_mount.source)
    for mount in reviewed:
        if any(_targets_overlap(mount.source, source) for source in existing_sources):
            raise ValueError("managed Claude sources cannot overlap install or config sources")
    if _targets_overlap(policy_mount.source, helper_mount.source):
        raise ValueError("managed Claude mount sources cannot overlap")

    return policy_mount, helper_mount


class SandboxedCodexAuthorAdapter:
    """Exact first/resume Codex turns over a transactional control mount."""

    def __init__(
        self,
        executor: SandboxExecutor,
        transaction: CodexCredentialTransaction | CredentialTransaction,
        *,
        install_mount: SandboxMount,
        executable: str,
        toolchain_mounts: Sequence[SandboxMount] = (),
        timeout_seconds: float = DEFAULT_AUTHOR_TIMEOUT_SECONDS,
        output_max_bytes: int = DEFAULT_MAX_AGENT_OUTPUT_BYTES,
        attempt_sink: AttemptSink | None = None,
        secret_refresh: Callable[[], object] | None = None,
        clock: Clock = time.monotonic,
    ) -> None:
        reviewed_mount, reviewed_executable = _reviewed_install(
            install_mount, executable, name="Codex"
        )
        self._executor = executor
        self._transaction = transaction
        self._install_mount = reviewed_mount
        self._toolchain_mounts = _frozen_toolchain_mounts(toolchain_mounts)
        if any(
            _targets_overlap(self._install_mount.target, mount.target)
            for mount in self._toolchain_mounts
        ):
            raise ValueError("Codex install and author toolchain mounts cannot overlap")
        self._executable = reviewed_executable
        self._timeout_seconds = _bounded_timeout(timeout_seconds, name="author timeout")
        if (
            not isinstance(output_max_bytes, int)
            or isinstance(output_max_bytes, bool)
            or not 1 <= output_max_bytes <= DEFAULT_MAX_AGENT_OUTPUT_BYTES
        ):
            raise ValueError("output_max_bytes is outside the sandbox protocol bound")
        self._output_max_bytes = output_max_bytes
        if not callable(clock):
            raise TypeError("clock must be callable")
        if attempt_sink is not None and not callable(attempt_sink):
            raise TypeError("attempt_sink must be callable")
        self._attempt_sink = attempt_sink
        if secret_refresh is not None and not callable(secret_refresh):
            raise TypeError("secret_refresh must be callable")
        self._secret_refresh = secret_refresh
        self._clock = clock

    def turn(self, request: AuthorRequest) -> AuthorTurn:
        # Capture the complete pre-turn credential generation before the CLI
        # can replace it.  Output sinks then refresh the same append-only
        # history after transport, closing the B-to-C declassification gap.
        if self._secret_refresh is not None:
            self._secret_refresh()
        timeout = _remaining_timeout(
            deadline=request.deadline,
            maximum=self._timeout_seconds,
            clock=self._clock,
            reason=StopReason.AUTHOR_TIMEOUT,
        )
        control_mount = SandboxMount(
            _normalized_host_path(self._transaction.codex_home, name="transactional CODEX_HOME"),
            "/control/codex-home",
            read_only=False,
        )
        captured: SandboxExecution | None = None
        transport_entered = False

        def transport(
            invocation: CodexInvocation,
            selected_timeout: float,
            output_max_bytes: int,
        ) -> BoundedProcessResult:
            nonlocal captured, transport_entered
            transport_entered = True
            captured = self._executor.execute(
                role=SandboxRole.AUTHOR,
                manifest=request.subject,
                argv=invocation.argv,
                environment=invocation.launch_environment(),
                cwd=invocation.cwd,
                timeout_seconds=selected_timeout,
                mounts=(self._install_mount, *self._toolchain_mounts, control_mount),
                output_max_bytes=output_max_bytes,
            )
            return captured.bounded_process()

        client = CodexClient(transport)
        result = None
        client_error: BaseException | None = None
        try:
            if request.thread_id is None:
                result = client.first_turn(
                    request.prompt,
                    timeout_seconds=timeout,
                    executable=self._executable,
                    parent_environment=build_codex_parent_environment(),
                    output_max_bytes=self._output_max_bytes,
                )
            else:
                result = client.resume_turn(
                    request.thread_id,
                    request.prompt,
                    timeout_seconds=timeout,
                    executable=self._executable,
                    parent_environment=build_codex_parent_environment(),
                    output_max_bytes=self._output_max_bytes,
                )
        except BaseException as error:
            client_error = error

        reconcile_error: BaseException | None = None
        refresh_error: BaseException | None = None
        if transport_entered:
            # Learn every generation created by both the model command and the
            # reconciliation status probe before retaining the inner attempt.
            try:
                self._transaction.reconcile_after_turn()
            except BaseException as error:
                reconcile_error = error
            try:
                if self._secret_refresh is not None:
                    self._secret_refresh()
            except BaseException as error:
                refresh_error = error

        sink_error: BaseException | None = None
        if captured is not None and refresh_error is None and self._attempt_sink is not None:
            try:
                self._attempt_sink(SandboxRole.AUTHOR, request.round_number, captured)
            except BaseException as error:
                sink_error = error

        if refresh_error is not None:
            raise refresh_error
        if reconcile_error is not None:
            raise reconcile_error
        if sink_error is not None:
            raise sink_error
        if client_error is not None:
            raise client_error

        if captured is None or result is None:
            raise fail(
                StopReason.RUNNER_INTERNAL_ERROR,
                "Codex transport returned no sandbox result",
            )
        events: list[dict[str, object]] = []
        for encoded_event in result.event_json:
            value = json.loads(encoded_event)
            if not isinstance(value, dict):
                raise fail(StopReason.AUTHOR_PROCESS_FAILURE, "Codex event was not an object")
            events.append(value)
        usage = {
            "input_tokens": result.usage.input_tokens,
            "cached_input_tokens": result.usage.cached_input_tokens,
            "output_tokens": result.usage.output_tokens,
            "reasoning_output_tokens": result.usage.reasoning_output_tokens,
        }
        self._executor.persist_new_blobs(captured)
        return AuthorTurn(
            candidate=captured.result.candidate,
            thread_id=result.thread_id,
            final_message=result.final_message,
            events=tuple(events),
            usage=usage,
            observed_model=result.observed_model,
            observed_effort=result.observed_effort,
        )


class SandboxedClaudeCriticAdapter:
    """Fresh, tool-disabled Claude review over only the complete bundle stdin."""

    def __init__(
        self,
        executor: SandboxExecutor,
        token: str,
        *,
        install_mount: SandboxMount,
        executable: str,
        config_dir: str | os.PathLike[str],
        managed_boundary: claude_managed_policy.ManagedClaudeBoundary,
        timeout_seconds: float = DEFAULT_CRITIC_TIMEOUT_SECONDS,
        model: str | None = None,
        effort: str | None = None,
        attempt_sink: AttemptSink | None = None,
        clock: Clock = time.monotonic,
    ) -> None:
        reviewed_mount, reviewed_executable = _reviewed_install(
            install_mount, executable, name="Claude"
        )
        selected_timeout = _bounded_timeout(timeout_seconds, name="critic timeout")
        if selected_timeout * 1_000 <= CLAUDE_API_TIMEOUT_MS:
            raise ValueError("outer critic timeout must exceed API_TIMEOUT_MS")
        config_source = _normalized_host_path(config_dir, name="generated Claude config")
        if not Path(config_source).is_dir():
            raise ValueError("generated Claude config mount must be a directory")
        # Validate the dedicated token without copying or consulting ambient
        # authentication state.  The environment is rebuilt per fresh round.
        build_claude_parent_environment(
            token,
            config_dir="/control/claude-home",
            tmp_dir="/runtime/critic-tmp",
        )
        self._executor = executor
        self._token = token
        self._token_secret = (KnownSecret("claude-setup-token", token.encode("utf-8")),)
        self._install_mount = reviewed_mount
        self._executable = reviewed_executable
        self._config_mount = SandboxMount(
            config_source,
            "/control/claude-home",
            read_only=True,
        )
        (
            self._managed_policy_mount,
            self._managed_helper_mount,
        ) = _reviewed_managed_claude_boundary(
            managed_boundary,
            install_mount=reviewed_mount,
            config_mount=self._config_mount,
        )
        self._timeout_seconds = selected_timeout
        self._model = model
        self._effort = effort
        if not callable(clock):
            raise TypeError("clock must be callable")
        if attempt_sink is not None and not callable(attempt_sink):
            raise TypeError("attempt_sink must be callable")
        self._attempt_sink = attempt_sink
        self._clock = clock

    def review(self, request: CriticRequest) -> CriticTurn:
        timeout = _remaining_timeout(
            deadline=request.deadline,
            maximum=self._timeout_seconds,
            clock=self._clock,
            reason=StopReason.CRITIC_TIMEOUT,
        )
        if timeout * 1_000 <= CLAUDE_API_TIMEOUT_MS:
            raise fail(
                StopReason.CRITIC_TIMEOUT,
                "remaining critic deadline does not exceed the pinned API timeout",
            )
        if raw_log_contains_known_secret(request.bundle.encoded, self._token_secret):
            raise fail(
                StopReason.REVIEW_CONTENT_WITHHELD,
                "critic bundle contains dedicated credential material",
            )
        parent_environment = build_claude_parent_environment(
            self._token,
            config_dir="/control/claude-home",
            tmp_dir="/runtime/critic-tmp",
        )
        captured: SandboxExecution | None = None

        def transport(
            invocation: ClaudeInvocation,
            selected_timeout: float,
            output_max_bytes: int,
        ) -> BoundedProcessResult:
            nonlocal captured
            captured = self._executor.execute(
                role=SandboxRole.CRITIC,
                manifest=SubjectManifest.empty(),
                argv=invocation.argv,
                environment=invocation.launch_environment(),
                cwd=invocation.cwd,
                stdin_bytes=invocation.stdin,
                timeout_seconds=selected_timeout,
                mounts=(
                    self._install_mount,
                    self._config_mount,
                    self._managed_policy_mount,
                    self._managed_helper_mount,
                ),
                output_max_bytes=output_max_bytes,
            )
            if captured.result.candidate != SubjectManifest.empty():
                raise fail(
                    StopReason.OUT_OF_BAND_CHANGE,
                    "tool-disabled critic changed its empty sandbox subject",
                )
            if raw_log_contains_known_secret(
                captured.result.process.stdout
                + captured.result.process.stderr
                + captured.service.process.stdout
                + captured.service.process.stderr,
                self._token_secret,
            ):
                raise fail(
                    StopReason.CREDENTIAL_REFRESH_FAILURE,
                    "Claude control output contained dedicated credential bytes",
                )
            if self._attempt_sink is not None:
                sanitized_request = replace(
                    captured.request,
                    env=tuple(
                        item
                        for item in captured.request.env
                        if item[0] != "CLAUDE_CODE_OAUTH_TOKEN"
                    ),
                )
                self._attempt_sink(
                    SandboxRole.CRITIC,
                    request.round_number,
                    replace(captured, request=sanitized_request),
                )
            return captured.bounded_process()

        result = ClaudeClient(transport).review(
            request.bundle,
            parent_environment,
            approval=request.approval,
            timeout_seconds=timeout,
            executable=self._executable,
            model=self._model,
            effort=self._effort,
        )
        if captured is None:
            raise fail(
                StopReason.RUNNER_INTERNAL_ERROR,
                "Claude transport returned no sandbox result",
            )
        observed_model = result.observed_model
        raw_model = result.envelope.get("model")
        if raw_model is not None:
            if (
                not isinstance(raw_model, str)
                or not raw_model
                or len(raw_model.encode("utf-8")) > 256
            ):
                raise fail(
                    StopReason.SANDBOX_SETUP_FAILURE,
                    "Claude result reported invalid model-selection metadata",
                )
            if observed_model is not None and raw_model != observed_model:
                raise fail(
                    StopReason.SANDBOX_SETUP_FAILURE,
                    "Claude result and API request reported different models",
                )
            observed_model = raw_model
        if result.usage.model_usage:
            if len(result.usage.model_usage) != 1:
                raise fail(
                    StopReason.SANDBOX_SETUP_FAILURE,
                    "Claude usage reported ambiguous model-selection metadata",
                )
            sole_model = next(iter(result.usage.model_usage))
            if not sole_model or len(sole_model.encode("utf-8")) > 256:
                raise fail(
                    StopReason.SANDBOX_SETUP_FAILURE,
                    "Claude usage reported invalid model-selection metadata",
                )
            if observed_model is not None and sole_model != observed_model:
                raise fail(
                    StopReason.SANDBOX_SETUP_FAILURE,
                    "Claude usage and API request reported different models",
                )
            observed_model = sole_model
        return CriticTurn(
            review=result.review,
            completed_at=result.completed_at,
            envelope=result.envelope,
            total_cost_usd=result.usage.total_cost_usd,
            observed_model=observed_model,
            observed_effort=result.observed_effort,
        )


__all__ = [
    "AttemptSink",
    "FixedValidationCheck",
    "SandboxExecution",
    "SandboxExecutor",
    "SandboxedClaudeCriticAdapter",
    "SandboxedCodexAuthorAdapter",
    "SandboxedValidationAdapter",
    "ServiceAttemptSink",
    "ValidationCheck",
]
