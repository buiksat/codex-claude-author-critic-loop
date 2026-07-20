from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

import agent_loop.runtime_adapters as runtime_adapters
from agent_loop.artifacts import ArtifactStore, ContentAddressedBlobStore
from agent_loop.constants import Limits
from agent_loop.credentials import CodexCredentialTransaction, codex_credential_root
from agent_loop.declassify import declassify_validation
from agent_loop.errors import AgentLoopError, StopReason, fail
from agent_loop.manifests import SubjectManifest
from agent_loop.models import ManifestEntry, PathPolicy, sha256_hex
from agent_loop.prompts import ReviewBundle
from agent_loop.provenance import closure_sha256, open_verified_closure
from agent_loop.runner import AuthorRequest, CriticRequest, LoopRunner, ValidationRequest
from agent_loop.runtime_adapters import (
    FixedValidationCheck,
    SandboxExecution,
    SandboxExecutor,
    SandboxedClaudeCriticAdapter,
    SandboxedCodexAuthorAdapter,
    SandboxedValidationAdapter,
)
from agent_loop.sandbox import SandboxMount, SandboxRole
from agent_loop.sandbox_init import (
    CleanupResult,
    PrimaryResult,
    SandboxRequest,
    SandboxResult,
    SupervisorLimits,
    encode_result,
    parse_request,
)
from agent_loop.schemas import ApprovalContext, Verdict
from agent_loop.service import (
    BoundedProcessResult,
    ServiceLimits,
    ServiceResult,
    run_bounded_process,
)
from agent_loop.validation import (
    CheckOutcome,
    ValidationSummary,
    classify_validations,
    verify_validation_mutation,
)
from agent_loop.workflow import parse_codex_file_auth


_DIRECT_SUPERVISOR = r"""
import sys
from agent_loop.sandbox_init import (
    _error_bytes,
    encode_result,
    execute_request,
    parse_request,
)

request = None
try:
    request = parse_request(sys.stdin.buffer.read())
    result = execute_request(request, workspace=sys.argv[1])
    sys.stdout.buffer.write(encode_result(result, max_bytes=request.limits.max_export_bytes))
except BaseException as error:
    sys.stdout.buffer.write(_error_bytes(error))
    raise SystemExit(2)
"""


class DirectSupervisorService:
    """Portable test double which still crosses the real supervisor protocol."""

    def __init__(self, root: Path, *, cgroup_empty: bool = True) -> None:
        self.root = root
        self.cgroup_empty = cgroup_empty
        self.commands: list[tuple[str, ...]] = []
        self.requests: list[SandboxRequest] = []
        self.roles: list[str] = []

    def run(
        self,
        command: tuple[str, ...],
        *,
        role: str,
        input_bytes: bytes = b"",
        timeout_seconds: float,
        limits: ServiceLimits | None = None,
    ) -> ServiceResult:
        assert limits is not None
        self.commands.append(command)
        self.requests.append(parse_request(input_bytes))
        self.roles.append(role)
        workspace = self.root / f"workspace-{len(self.commands)}"
        workspace.mkdir()
        environment = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONPATH": os.path.abspath("src"),
            "LANG": "C.UTF-8",
        }
        completed = subprocess.run(
            (sys.executable, "-c", _DIRECT_SUPERVISOR, os.fspath(workspace)),
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            close_fds=True,
            check=False,
            timeout=timeout_seconds + 3,
        )
        now = float(len(self.commands))
        process = BoundedProcessResult(
            completed.returncode,
            completed.stdout,
            completed.stderr,
            now - 0.5,
            now,
            False,
            False,
        )
        return ServiceResult(
            f"agent-loop-test-{len(self.commands)}.service",
            process,
            {"Type": "exec", "KillMode": "control-group"},
            "/test",
            self.cgroup_empty,
        )


class MalformedService:
    def run(
        self,
        command: tuple[str, ...],
        *,
        role: str,
        input_bytes: bytes = b"",
        timeout_seconds: float,
        limits: ServiceLimits | None = None,
    ) -> ServiceResult:
        del command, role, input_bytes, timeout_seconds, limits
        process = BoundedProcessResult(0, b"{}\n", b"", 0.0, 1.0, False, False)
        return ServiceResult("agent-loop-test.service", process, {}, "/test", True)


class OutputLimitedService:
    def run(
        self,
        command: tuple[str, ...],
        *,
        role: str,
        input_bytes: bytes = b"",
        timeout_seconds: float,
        limits: ServiceLimits | None = None,
    ) -> ServiceResult:
        del command, role, input_bytes, timeout_seconds, limits
        process = BoundedProcessResult(
            1,
            b"bounded outer prefix",
            b"",
            0.0,
            1.0,
            False,
            True,
        )
        return ServiceResult("agent-loop-limited.service", process, {}, "/test", True)


def _blobs(tmp_path: Path) -> tuple[ArtifactStore, ContentAddressedBlobStore]:
    artifacts = ArtifactStore.create(tmp_path / "artifacts")
    return artifacts, ContentAddressedBlobStore(artifacts)


def _manifest(
    blobs: ContentAddressedBlobStore,
    files: Mapping[bytes, bytes],
) -> SubjectManifest:
    entries = []
    for path, data in sorted(files.items()):
        digest = blobs.put_blob(data)
        entries.append(ManifestEntry.regular(path, size=len(data), blob_sha256=digest))
    return SubjectManifest.build(entries)


def test_001_ignored_runtime_configuration_changes_validation_behavior(
    tmp_path: Path,
) -> None:
    artifacts, blobs = _blobs(tmp_path)
    try:
        service_root = tmp_path / "services"
        service_root.mkdir()
        adapter = SandboxedValidationAdapter(
            SandboxExecutor(blobs, service=DirectSupervisorService(service_root)),
            (
                FixedValidationCheck(
                    "runtime-config",
                    'test "$(cat runtime.conf 2>/dev/null)" = enabled',
                    2,
                ),
            ),
        )
        ignored_without_config = _manifest(
            blobs,
            {b".gitignore": b"runtime.conf\n"},
        )
        ignored_with_config = _manifest(
            blobs,
            {
                b".gitignore": b"runtime.conf\n",
                b"runtime.conf": b"enabled\n",
            },
        )

        absent = adapter.validate(
            ValidationRequest(ignored_without_config, None, time_deadline())
        )
        present = adapter.validate(
            ValidationRequest(ignored_with_config, None, time_deadline())
        )

        assert absent.summary.checks[0].exit_code == 1
        assert present.summary.checks[0].exit_code == 0
        assert b"runtime.conf" in {entry.path for entry in ignored_with_config.entries}
    finally:
        artifacts.close()


def test_009_executor_uses_bwrap_pid1_supervisor_and_delays_blob_persistence(
    tmp_path: Path,
) -> None:
    artifacts, blobs = _blobs(tmp_path)
    try:
        service = DirectSupervisorService(tmp_path / "services")
        service.root.mkdir()
        executor = SandboxExecutor(blobs, service=service, clock=lambda: 7.0)

        execution = executor.execute(
            role=SandboxRole.VALIDATION,
            manifest=SubjectManifest.empty(),
            argv=(
                "/usr/bin/python3",
                "-c",
                "from pathlib import Path; Path('result').write_bytes(b'candidate'); print('ok')",
            ),
            environment={
                "PATH": "/usr/bin:/bin",
                "HOME": "/runtime/home",
                "TMPDIR": "/runtime/tmp",
                "LANG": "C.UTF-8",
            },
            cwd="/workspace",
            timeout_seconds=2,
        )

        assert execution.result.process.stdout == b"ok\n"
        assert execution.result.cleanup.namespace_empty is True
        assert service.roles == ["validation"]
        command = service.commands[0]
        assert command[:4] == ("/usr/bin/python3", "-I", "-B", "-c")
        launched = tuple(json.loads(command[-1])["argv"])
        assert launched[0] == "/usr/bin/bwrap"
        assert "--as-pid-1" in launched
        assert "--unshare-net" in launched
        assert "/opt/agent-loop-runtime" in launched
        assert launched[-5:-1] == ("/usr/bin/python3", "-I", "-B", "-c")
        assert "agent_loop.sandbox_init" in launched[-1]
        assert service.requests[0].manifest == SubjectManifest.empty()

        digest, payload = execution.result.new_blobs[0]
        assert payload == b"candidate"
        with pytest.raises(AgentLoopError):
            blobs.read_blob(digest)
        executor.persist_new_blobs(execution)
        assert blobs.read_blob(digest) == payload
    finally:
        artifacts.close()


def test_executor_rejects_missing_cgroup_proof_and_malformed_response(tmp_path: Path) -> None:
    artifacts, blobs = _blobs(tmp_path)
    try:
        service_root = tmp_path / "services"
        service_root.mkdir()
        no_cgroup = SandboxExecutor(
            blobs,
            service=DirectSupervisorService(service_root, cgroup_empty=False),
        )
        with pytest.raises(AgentLoopError) as missing:
            no_cgroup.execute(
                role=SandboxRole.VALIDATION,
                manifest=SubjectManifest.empty(),
                argv=("/usr/bin/true",),
                environment={"PATH": "/usr/bin:/bin"},
                cwd="/workspace",
                timeout_seconds=1,
            )
        assert missing.value.reason is StopReason.SERVICE_LIFECYCLE_MISMATCH

        attempts: list[tuple[SandboxRole, int, SandboxRequest, ServiceResult, float]] = []
        malformed = SandboxExecutor(
            blobs,
            service=MalformedService(),
            service_attempt_sink=lambda role, number, request, service, completed: (
                attempts.append((role, number, request, service, completed))
            ),
        )
        with pytest.raises(AgentLoopError) as invalid:
            malformed.execute(
                role=SandboxRole.VALIDATION,
                manifest=SubjectManifest.empty(),
                argv=("/usr/bin/true",),
                environment={"PATH": "/usr/bin:/bin"},
                cwd="/workspace",
                timeout_seconds=1,
            )
        assert invalid.value.reason is StopReason.SANDBOX_SETUP_FAILURE
        assert len(attempts) == 1
        assert attempts[0][0:2] == (SandboxRole.VALIDATION, 1)
        assert attempts[0][2].manifest == SubjectManifest.empty()
        assert attempts[0][3].process.stdout == b"{}\n"

        limited_attempts: list[
            tuple[SandboxRole, int, SandboxRequest, ServiceResult, float]
        ] = []
        limited = SandboxExecutor(
            blobs,
            service=OutputLimitedService(),
            service_attempt_sink=lambda role, number, request, service, completed: (
                limited_attempts.append((role, number, request, service, completed))
            ),
        )
        with pytest.raises(AgentLoopError) as capped:
            limited.execute(
                role=SandboxRole.VALIDATION,
                manifest=SubjectManifest.empty(),
                argv=("/usr/bin/true",),
                environment={"PATH": "/usr/bin:/bin"},
                cwd="/workspace",
                timeout_seconds=1,
            )
        assert capped.value.reason is StopReason.AGENT_OUTPUT_LIMIT
        assert limited_attempts[0][3].process.stdout == b"bounded outer prefix"
        assert limited_attempts[0][3].process.output_limited is True
    finally:
        artifacts.close()


def test_executor_rechecks_trusted_sandbox_init_closure_before_each_launch(
    tmp_path: Path,
) -> None:
    artifacts, blobs = _blobs(tmp_path)
    package_root = tmp_path / "runtime-package"
    package = package_root / "agent_loop"
    package.mkdir(parents=True)
    supervisor = package / "sandbox_init.py"
    supervisor.write_text("raise SystemExit(0)\n", encoding="utf-8")
    try:
        executor = SandboxExecutor(
            blobs,
            service=MalformedService(),
            package_root=package_root,
        )
        supervisor.write_text("raise SystemExit(1)\n", encoding="utf-8")

        with pytest.raises(AgentLoopError) as changed:
            executor.execute(
                role=SandboxRole.VALIDATION,
                manifest=SubjectManifest.empty(),
                argv=("/usr/bin/true",),
                environment={"PATH": "/usr/bin:/bin"},
                cwd="/workspace",
                timeout_seconds=1,
            )

        assert changed.value.reason is StopReason.SANDBOX_SETUP_FAILURE
        assert "package closure changed" in changed.value.detail
    finally:
        artifacts.close()


def test_mount_launcher_rejects_a_source_root_swap_after_descriptor_binding(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    replacement = tmp_path / "replacement"
    parked = tmp_path / "parked"
    source.mkdir()
    replacement.mkdir()
    mount = SandboxMount(os.fspath(source), "/opt/reviewed")
    inner = (
        "/usr/bin/bwrap",
        "--ro-bind",
        os.fspath(source),
        mount.target,
    )
    launcher, descriptors = runtime_adapters._bind_mount_sources_to_descriptors(
        inner,
        (mount,),
    )
    source.rename(parked)
    replacement.rename(source)
    try:
        result = subprocess.run(launcher, check=False, close_fds=True)
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
        source.rename(replacement)
        parked.rename(source)

    assert result.returncode == 124


def test_mount_binding_rejects_root_swap_after_closure_verification(tmp_path: Path) -> None:
    source = tmp_path / "source"
    replacement = tmp_path / "replacement"
    parked = tmp_path / "parked"
    source.mkdir()
    replacement.mkdir()
    (source / "tool").write_text("reviewed\n", encoding="utf-8")
    (replacement / "tool").write_text("replacement\n", encoding="utf-8")
    mount = SandboxMount(
        os.fspath(source),
        "/opt/reviewed",
        closure_sha256=closure_sha256(source),
    )
    authority = open_verified_closure(source, mount.closure_sha256 or "")
    source.rename(parked)
    replacement.rename(source)
    try:
        with pytest.raises(ValueError, match="identity changed"):
            runtime_adapters._bind_mount_sources_to_descriptors(
                (
                    "/usr/bin/bwrap",
                    "--ro-bind",
                    os.fspath(source),
                    mount.target,
                ),
                (mount,),
                verified_descriptors=(authority,),
            )
    finally:
        os.close(authority)
        source.rename(replacement)
        parked.rename(source)


def test_executor_rechecks_every_witnessed_mount_before_launch(tmp_path: Path) -> None:
    artifacts, blobs = _blobs(tmp_path)
    reviewed = tmp_path / "reviewed-tool"
    reviewed.write_text("one\n", encoding="utf-8")
    mount = SandboxMount(
        str(reviewed),
        "/opt/reviewed-tool",
        closure_sha256=closure_sha256(reviewed),
    )
    reviewed.write_text("two\n", encoding="utf-8")
    try:
        executor = SandboxExecutor(blobs, service=MalformedService())
        with pytest.raises(AgentLoopError) as changed:
            executor.execute(
                role=SandboxRole.VALIDATION,
                manifest=SubjectManifest.empty(),
                argv=("/usr/bin/true",),
                environment={"PATH": "/usr/bin:/bin"},
                cwd="/workspace",
                timeout_seconds=1,
                mounts=(mount,),
            )
        assert changed.value.reason is StopReason.SANDBOX_SETUP_FAILURE
        assert "mount closure changed" in changed.value.detail
    finally:
        artifacts.close()


def test_executor_rechecks_cached_private_mount_snapshot_before_launch(
    tmp_path: Path,
) -> None:
    artifacts, blobs = _blobs(tmp_path)
    reviewed = tmp_path / "reviewed-tool"
    reviewed.write_text("stable\n", encoding="utf-8")
    mount = SandboxMount(
        os.fspath(reviewed),
        "/opt/reviewed-tool",
        closure_sha256=closure_sha256(reviewed),
    )
    try:
        executor = SandboxExecutor(blobs, service=MalformedService())
        cached = executor._snapshot_mount(mount)
        cached_path = Path(cached.source)
        cached_path.chmod(0o600)
        cached_path.write_text("changed\n", encoding="utf-8")

        with pytest.raises(AgentLoopError) as changed:
            executor.execute(
                role=SandboxRole.VALIDATION,
                manifest=SubjectManifest.empty(),
                argv=("/usr/bin/true",),
                environment={"PATH": "/usr/bin:/bin"},
                cwd="/workspace",
                timeout_seconds=1,
                mounts=(mount,),
            )
        assert changed.value.reason is StopReason.SANDBOX_SETUP_FAILURE
        assert "private mount snapshot changed" in changed.value.detail
    finally:
        artifacts.close()


def test_validation_runs_fixed_checks_sequentially_in_one_fresh_tmpfs(
    tmp_path: Path,
) -> None:
    artifacts, blobs = _blobs(tmp_path)
    try:
        subject = _manifest(blobs, {b"source.txt": b"base"})
        service_root = tmp_path / "services"
        service_root.mkdir()
        service = DirectSupervisorService(service_root)
        executor = SandboxExecutor(blobs, service=service, clock=lambda: 5.0)
        checks = (
            FixedValidationCheck(
                "one",
                "test ! -e cache; mkdir cache; printf one > cache/one; printf first",
                2,
            ),
            FixedValidationCheck(
                "two",
                "test \"$(cat cache/one)\" = one; printf two > cache/two; printf second >&2",
                2,
            ),
        )
        adapter = SandboxedValidationAdapter(
            executor,
            checks,
            clock=lambda: 0.0,
        )

        turn = adapter.validate(ValidationRequest(subject, None, 10.0))

        assert turn.summary.subject_fingerprint == subject.fingerprint
        assert turn.summary.all_pass is True
        assert [check.check_id for check in turn.summary.checks] == ["one", "two"]
        assert len(service.requests) == 1
        assert service.requests[0].manifest == subject
        assert service.requests[0].argv == (
            "/opt/agent-loop-runtime/agent_loop/.validation-batch-v1",
        )
        assert all(
            all(check.command not in argument for argument in outer_command)
            for check in checks
            for outer_command in service.commands
        )
        assert b"first" in turn.raw_log and b"second" in turn.raw_log
        paths = {entry.path for entry in turn.result_manifest.entries}
        assert paths == {b"source.txt", b"cache/one", b"cache/two"}
        policy = PathPolicy.from_strings(discard_only_patterns=("cache/**",))
        assert verify_validation_mutation(subject, turn.result_manifest, policy) == (
            b"cache/one",
            b"cache/two",
        )
        assert service.requests[0].environment == {
            "HOME": "/runtime/home",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/bin:/bin",
            "TMPDIR": "/runtime/tmp",
            "TZ": "UTC",
        }
    finally:
        artifacts.close()


def test_validation_authoritative_mutation_is_visible_to_upstream_policy(tmp_path: Path) -> None:
    artifacts, blobs = _blobs(tmp_path)
    try:
        subject = _manifest(blobs, {b"source.txt": b"base"})
        service_root = tmp_path / "services"
        service_root.mkdir()
        executor = SandboxExecutor(blobs, service=DirectSupervisorService(service_root))
        turn = SandboxedValidationAdapter(
            executor,
            (FixedValidationCheck("hostile", "printf changed > source.txt", 2),),
        ).validate(ValidationRequest(subject, None, time_deadline()))
        with pytest.raises(AgentLoopError) as caught:
            verify_validation_mutation(subject, turn.result_manifest, PathPolicy())
        assert caught.value.reason is StopReason.VALIDATION_MUTATED_SUBJECT
    finally:
        artifacts.close()


def test_validation_ordinary_failure_does_not_hide_later_shared_workspace_check(
    tmp_path: Path,
) -> None:
    artifacts, blobs = _blobs(tmp_path)
    service_root = tmp_path / "services"
    service_root.mkdir()
    try:
        adapter = SandboxedValidationAdapter(
            SandboxExecutor(blobs, service=DirectSupervisorService(service_root)),
            (
                FixedValidationCheck("build", "printf built > build-output; false", 2),
                FixedValidationCheck("test", "test \"$(cat build-output)\" = built", 2),
            ),
        )
        turn = adapter.validate(
            ValidationRequest(SubjectManifest.empty(), None, time_deadline())
        )
        assert [check.exit_code for check in turn.summary.checks] == [1, 0]
        assert b"build-output" in {entry.path for entry in turn.result_manifest.entries}
    finally:
        artifacts.close()


def test_validation_cleans_detached_descendants_before_the_next_check(tmp_path: Path) -> None:
    artifacts, blobs = _blobs(tmp_path)
    service_root = tmp_path / "services"
    service_root.mkdir()
    daemon = (
        "/usr/bin/python3 -c $'import os,time,pathlib\\n"
        "pid=os.fork()\\n"
        "if pid:\\n"
        " while not pathlib.Path(\"daemon.pid\").exists(): time.sleep(.005)\\n"
        " os._exit(0)\\n"
        "os.setsid()\\n"
        "pathlib.Path(\"daemon.pid\").write_text(str(os.getpid()))\\n"
        "time.sleep(30)'"
    )
    try:
        adapter = SandboxedValidationAdapter(
            SandboxExecutor(blobs, service=DirectSupervisorService(service_root)),
            (
                FixedValidationCheck("spawn", daemon, 2),
                FixedValidationCheck(
                    "prove-clean",
                    "test ! -e /proc/\"$(cat daemon.pid)\"; printf clean > cleanup-ok",
                    2,
                ),
            ),
        )
        turn = adapter.validate(
            ValidationRequest(SubjectManifest.empty(), None, time_deadline())
        )
        assert turn.summary.all_pass is True
        assert b"cleanup-ok" in {entry.path for entry in turn.result_manifest.entries}
    finally:
        artifacts.close()


def test_validation_final_manifest_is_the_last_shared_workspace_state(tmp_path: Path) -> None:
    artifacts, blobs = _blobs(tmp_path)
    service_root = tmp_path / "services"
    service_root.mkdir()
    try:
        adapter = SandboxedValidationAdapter(
            SandboxExecutor(blobs, service=DirectSupervisorService(service_root)),
            (
                FixedValidationCheck("create", "printf old > result; printf gone > removed", 2),
                FixedValidationCheck("replace", "printf new > result; rm removed", 2),
            ),
        )
        turn = adapter.validate(
            ValidationRequest(SubjectManifest.empty(), None, time_deadline())
        )
        assert len(turn.result_manifest.entries) == 1
        entry = turn.result_manifest.entries[0]
        assert entry.path == b"result"
        assert entry.blob_sha256 == sha256_hex(b"new")
    finally:
        artifacts.close()


def test_validation_aggregate_output_limit_stops_the_remaining_batch(tmp_path: Path) -> None:
    artifacts, blobs = _blobs(tmp_path)
    service_root = tmp_path / "services"
    service_root.mkdir()
    try:
        adapter = SandboxedValidationAdapter(
            SandboxExecutor(blobs, service=DirectSupervisorService(service_root)),
            (
                FixedValidationCheck("one", "printf '%0200d' 0", 2),
                FixedValidationCheck("two", "printf '%0100d' 0", 2),
                FixedValidationCheck("must-not-run", "touch forbidden", 2),
            ),
            max_raw_log_bytes=512,
            output_max_bytes=400,
        )
        turn = adapter.validate(
            ValidationRequest(SubjectManifest.empty(), None, time_deadline())
        )
        assert turn.summary.checks[-1].output_limited is True
        assert turn.summary.checks[-1].outcome is CheckOutcome.OUTPUT_LIMITED
        assert b'"check_id":"two"' in turn.raw_log
        assert not (service_root / "workspace-1" / "forbidden").exists()
    finally:
        artifacts.close()


@pytest.mark.parametrize(
    ("check", "expected_timed_out", "expected_signal", "marker", "logged"),
    (
        (
            FixedValidationCheck(
                "timeout",
                "printf timeout-log; printf partial > timeout-marker; sleep 5",
                0.05,
            ),
            True,
            None,
            b"timeout-marker",
            b"timeout-log",
        ),
        (
            FixedValidationCheck(
                "signal",
                "printf signal-log; printf partial > signal-marker; kill -TERM $$",
                2,
            ),
            False,
            15,
            b"signal-marker",
            b"signal-log",
        ),
    ),
)
def test_validation_terminal_process_record_preserves_partial_evidence_and_stops_checks(
    tmp_path: Path,
    check: FixedValidationCheck,
    expected_timed_out: bool,
    expected_signal: int | None,
    marker: bytes,
    logged: bytes,
) -> None:
    artifacts, blobs = _blobs(tmp_path)
    try:
        service_root = tmp_path / "services"
        service_root.mkdir()
        service = DirectSupervisorService(service_root)
        executor = SandboxExecutor(blobs, service=service)
        adapter = SandboxedValidationAdapter(
            executor,
            (check, FixedValidationCheck("must-not-run", "printf ran > forbidden", 2)),
        )

        turn = adapter.validate(
            ValidationRequest(SubjectManifest.empty(), None, time_deadline())
        )

        assert len(service.requests) == 1
        assert len(turn.summary.checks) == 1
        terminal = turn.summary.checks[0]
        assert terminal.timed_out is expected_timed_out
        assert terminal.signal == expected_signal
        assert terminal.exit_code is None
        assert logged in turn.raw_log
        assert marker in {entry.path for entry in turn.result_manifest.entries}
        assert b"forbidden" not in {entry.path for entry in turn.result_manifest.entries}
        classified = classify_validations(None, turn.summary)
        evidence = declassify_validation(
            turn.summary.subject_fingerprint,
            classified,
            raw_log=turn.raw_log,
        )
        with pytest.raises(AgentLoopError) as stopped:
            LoopRunner._ensure_validation_can_continue(
                turn.summary,
                evidence,
                baseline=False,
            )
        expected_reason = (
            StopReason.VALIDATION_TIMEOUT
            if expected_timed_out
            else StopReason.VALIDATION_PROCESS_FAILURE
        )
        assert stopped.value.reason is expected_reason
    finally:
        artifacts.close()


@pytest.mark.parametrize(
    ("baseline", "command", "files", "expected_reason", "expected_status"),
    (
        (
            None,
            "agent-loop-command-that-does-not-exist",
            {},
            StopReason.BASELINE_INFRASTRUCTURE_FAILURE,
            127,
        ),
        (
            "present",
            "./not-executable",
            {b"not-executable": b"#!/bin/sh\nexit 0\n"},
            StopReason.VALIDATION_PROCESS_FAILURE,
            126,
        ),
    ),
)
def test_validation_unexecutable_shell_status_is_retained_as_infrastructure_evidence(
    tmp_path: Path,
    baseline: str | None,
    command: str,
    files: Mapping[bytes, bytes],
    expected_reason: StopReason,
    expected_status: int,
) -> None:
    artifacts, blobs = _blobs(tmp_path)
    try:
        subject = _manifest(blobs, files) if files else SubjectManifest.empty()
        service_root = tmp_path / "services"
        service_root.mkdir()
        executor = SandboxExecutor(blobs, service=DirectSupervisorService(service_root))
        adapter = SandboxedValidationAdapter(
            executor,
            (
                FixedValidationCheck(
                    "missing-tool",
                    command,
                    2,
                ),
            ),
        )
        prior = (
            None
            if baseline is None
            else ValidationSummary(1, subject.fingerprint, ())
        )

        turn = adapter.validate(ValidationRequest(subject, prior, time_deadline()))
        assert len(turn.summary.checks) == 1
        terminal = turn.summary.checks[0]
        assert terminal.exit_code == expected_status
        assert terminal.infrastructure_failure is True
        assert terminal.process_started is False
        with pytest.raises(AgentLoopError) as caught:
            classified = classify_validations(None, turn.summary)
            evidence = declassify_validation(
                subject.fingerprint,
                classified,
                raw_log=turn.raw_log,
            )
            LoopRunner._ensure_validation_can_continue(
                turn.summary,
                evidence,
                baseline=prior is None,
            )
        assert caught.value.reason is expected_reason
    finally:
        artifacts.close()


def time_deadline() -> float:
    # The production adapter uses a monotonic absolute deadline.
    return time.monotonic() + 10


class ScriptedExecutor:
    """Agent-side fake: returns strict supervisor-shaped results, never calls a model."""

    def __init__(
        self,
        *,
        stdout: bytes,
        candidate: SubjectManifest,
        new_blobs: tuple[tuple[str, bytes], ...] = (),
        returncode: int = 0,
        events: list[str] | None = None,
    ) -> None:
        self.stdout = stdout
        self.candidate = candidate
        self.new_blobs = new_blobs
        self.returncode = returncode
        self.calls: list[dict[str, object]] = []
        self.events = [] if events is None else events

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
        output_max_bytes: int,
    ) -> SandboxExecution:
        self.events.append("execute")
        self.calls.append(
            {
                "role": role,
                "manifest": manifest,
                "argv": tuple(argv),
                "environment": dict(environment),
                "cwd": cwd,
                "timeout_seconds": timeout_seconds,
                "stdin_bytes": stdin_bytes,
                "mounts": tuple(mounts),
                "output_max_bytes": output_max_bytes,
            }
        )
        request = SandboxRequest(
            manifest,
            (),
            tuple(argv),
            tuple(sorted(environment.items())),
            cwd,
            stdin_bytes,
            SupervisorLimits(1_000, 100, output_max_bytes, 2 * 1024 * 1024, Limits()),
        )
        result = SandboxResult(
            manifest.fingerprint,
            self.candidate,
            self.new_blobs,
            PrimaryResult(self.returncode, self.stdout, b"", False, False, 1),
            CleanupResult(0, True),
        )
        process = BoundedProcessResult(
            0,
            encode_result(result, max_bytes=2 * 1024 * 1024),
            b"",
            1,
            2,
            False,
            False,
        )
        service = ServiceResult("agent-loop-scripted.service", process, {}, "/test", True)
        return SandboxExecution(request, result, service, 2.0)

    def persist_new_blobs(self, execution: SandboxExecution) -> None:
        assert execution.result.candidate == self.candidate
        self.events.append("persist")


def test_validation_supervisor_attempt_is_retained_before_batch_parse_failure() -> None:
    attempts: list[tuple[SandboxRole, int, SandboxExecution]] = []
    executor = ScriptedExecutor(
        stdout=b"malformed validation batch output\n",
        candidate=SubjectManifest.empty(),
    )
    adapter = SandboxedValidationAdapter(
        executor,  # type: ignore[arg-type]
        (FixedValidationCheck("check", "true", 2),),
        attempt_sink=lambda role, attempt, execution: attempts.append(
            (role, attempt, execution)
        ),
        clock=lambda: 0.0,
    )

    with pytest.raises(AgentLoopError) as caught:
        adapter.validate(
            ValidationRequest(SubjectManifest.empty(), None, 1_000.0)
        )

    assert caught.value.reason is StopReason.SANDBOX_SETUP_FAILURE
    assert len(attempts) == 1
    assert attempts[0][0:2] == (SandboxRole.VALIDATION, 1)
    assert attempts[0][2].result.process.stdout == b"malformed validation batch output\n"


class RecordingTransaction:
    def __init__(
        self,
        codex_home: Path,
        events: list[str],
        *,
        fail_reconcile: bool = False,
    ) -> None:
        self._codex_home = codex_home
        self.events = events
        self.fail_reconcile = fail_reconcile

    @property
    def codex_home(self) -> Path:
        return self._codex_home

    def reconcile_after_turn(self) -> bool:
        self.events.append("reconcile")
        if self.fail_reconcile:
            raise fail(StopReason.CREDENTIAL_REFRESH_FAILURE, "fake refresh failed")
        return False


def _strict_codex_auth(generation: str) -> bytes:
    values = {
        "auth_mode": "chatgpt",
        "OPENAI_API_KEY": None,
        "tokens": {
            "id_token": f"fake-{generation}-id-token",
            "access_token": f"fake-{generation}-access-token",
            "refresh_token": f"fake-{generation}-refresh-token",
            "account_id": f"fake-{generation}-account",
        },
        "last_refresh": "2099-01-01T00:00:00Z",
    }
    return json.dumps(values, sort_keys=True, separators=(",", ":")).encode()


class ExecutableCodexExecutor:
    """Translate the reviewed control mount while launching the external fake CLI."""

    def __init__(self, codex_home: Path) -> None:
        self.codex_home = codex_home
        self.persisted = 0

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
        output_max_bytes: int,
    ) -> SandboxExecution:
        assert role is SandboxRole.AUTHOR
        assert any(mount.target == "/control/codex-home" for mount in mounts)
        launch_environment = dict(environment)
        launch_environment["CODEX_HOME"] = os.fspath(self.codex_home)
        process = run_bounded_process(
            tuple(argv),
            input_bytes=stdin_bytes,
            timeout_seconds=timeout_seconds,
            output_max_bytes=output_max_bytes,
            env=launch_environment,
        )
        request = SandboxRequest(
            manifest,
            (),
            tuple(argv),
            tuple(sorted(environment.items())),
            cwd,
            stdin_bytes,
            SupervisorLimits(1_000, 100, output_max_bytes, 2 * 1024 * 1024, Limits()),
        )
        result = SandboxResult(
            manifest.fingerprint,
            manifest,
            (),
            PrimaryResult(
                process.returncode,
                process.stdout,
                process.stderr,
                process.timed_out,
                process.output_limited,
                max(0, int((process.completed_at - process.started_at) * 1_000)),
            ),
            CleanupResult(0, True),
        )
        outer = BoundedProcessResult(
            0,
            encode_result(result, max_bytes=2 * 1024 * 1024),
            b"",
            process.started_at,
            process.completed_at,
            False,
            False,
        )
        service = ServiceResult("agent-loop-fake.service", outer, {}, "/test", True)
        return SandboxExecution(request, result, service, process.completed_at)

    def persist_new_blobs(self, execution: SandboxExecution) -> None:
        assert execution.result.new_blobs == ()
        self.persisted += 1


def _codex_jsonl(thread_id: str) -> bytes:
    values = (
        {"type": "thread.started", "thread_id": thread_id, "model": "gpt-fake"},
        {"type": "item.completed", "item": {"type": "agent_message", "text": "done"}},
        {
            "type": "turn.completed",
            "usage": {"input_tokens": 3, "output_tokens": 2},
            "model": "gpt-fake",
        },
    )
    return b"\n".join(json.dumps(value, separators=(",", ":")).encode() for value in values) + b"\n"


@pytest.mark.parametrize(
    ("scenario", "expected_reason"),
    (
        ("credential-refresh", None),
        ("credential-refresh-crash", StopReason.AUTHOR_PROCESS_FAILURE),
        (
            "credential-refresh-truncated-crash",
            StopReason.CREDENTIAL_REFRESH_FAILURE,
        ),
    ),
)
def test_067_external_fake_refresh_is_reconciled_before_adapter_returns(
    tmp_path: Path,
    scenario: str,
    expected_reason: StopReason | None,
) -> None:
    fake_source = Path(__file__).parents[1] / "fakes" / "fake_codex.py"
    install = tmp_path / "codex-install"
    install.mkdir()
    fake_codex = install / "codex"
    shutil.copyfile(fake_source, fake_codex)
    fake_codex.chmod(0o755)

    state_home = tmp_path / "state"
    account = codex_credential_root("fake-refresh", state_home=state_home)
    account.mkdir(mode=0o700, parents=True)
    old_auth = _strict_codex_auth("old")
    (account / "auth.json").write_bytes(old_auth)
    (account / "auth.json").chmod(0o600)

    def probe(codex_home: Path) -> bool:
        return parse_codex_file_auth((codex_home / "auth.json").read_bytes())

    transaction = CodexCredentialTransaction.acquire(
        "fake-refresh",
        f"run-{scenario}",
        auth_parser=parse_codex_file_auth,
        auth_probe=probe,
        state_home=state_home,
    )
    executor = ExecutableCodexExecutor(transaction.codex_home)
    adapter = SandboxedCodexAuthorAdapter(
        executor,  # type: ignore[arg-type]
        transaction,
        install_mount=SandboxMount(os.fspath(install), os.fspath(install)),
        executable=os.fspath(fake_codex),
        clock=lambda: 0.0,
    )
    try:
        if expected_reason is not None:
            with pytest.raises(AgentLoopError) as caught:
                adapter.turn(
                    AuthorRequest(
                        1,
                        SubjectManifest.empty(),
                        f"scenario:{scenario}",
                        None,
                        1_000,
                    )
                )
            assert caught.value.reason is expected_reason
            assert executor.persisted == 0
        else:
            turn = adapter.turn(
                AuthorRequest(
                    1,
                    SubjectManifest.empty(),
                    f"scenario:{scenario}",
                    None,
                    1_000,
                )
            )
            assert turn.thread_id == "thread-001"
            assert executor.persisted == 1

        if scenario == "credential-refresh-truncated-crash":
            assert not parse_codex_file_auth(transaction.candidate_auth_path.read_bytes())
            assert (account / "auth.json").read_bytes() == old_auth
        else:
            refreshed = _strict_codex_auth("refreshed")
            assert transaction.candidate_auth_path.read_bytes() == refreshed
            assert (account / "auth.json").read_bytes() == refreshed
            transaction.complete()
    finally:
        transaction.close()


def test_065_codex_adapter_routes_first_resume_and_reconciles_before_acceptance(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    payload = b"candidate"
    digest = sha256_hex(payload)
    candidate = SubjectManifest.build(
        [ManifestEntry.regular(b"new.txt", size=len(payload), blob_sha256=digest)]
    )
    executor = ScriptedExecutor(
        stdout=_codex_jsonl("thread-001"),
        candidate=candidate,
        new_blobs=((digest, payload),),
        events=events,
    )
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir()
    install = tmp_path / "codex-install"
    toolchain = tmp_path / "author-toolchain"
    install.mkdir()
    toolchain.mkdir()
    adapter = SandboxedCodexAuthorAdapter(
        executor,  # type: ignore[arg-type]
        RecordingTransaction(codex_home, events),
        install_mount=SandboxMount(str(install), "/opt/reviewed-codex"),
        executable="/opt/reviewed-codex/codex",
        toolchain_mounts=(SandboxMount(str(toolchain), "/opt/reviewed-toolchain"),),
        clock=lambda: 0.0,
    )

    first = adapter.turn(AuthorRequest(1, SubjectManifest.empty(), "first", None, 1_000))
    resumed = adapter.turn(
        AuthorRequest(2, SubjectManifest.empty(), "revise", first.thread_id, 1_000)
    )

    assert first.candidate == candidate
    assert first.thread_id == "thread-001"
    assert resumed.candidate == candidate
    assert resumed.thread_id == first.thread_id
    assert first.usage == {
        "input_tokens": 3,
        "cached_input_tokens": 0,
        "output_tokens": 2,
        "reasoning_output_tokens": 0,
    }
    assert events == ["execute", "reconcile", "persist", "execute", "reconcile", "persist"]
    first_argv = executor.calls[0]["argv"]
    resume_argv = executor.calls[1]["argv"]
    assert isinstance(first_argv, tuple) and "resume" not in first_argv
    assert isinstance(resume_argv, tuple)
    assert resume_argv[resume_argv.index("resume") + 4] == "thread-001"
    for call in executor.calls:
        assert call["role"] is SandboxRole.AUTHOR
        assert call["cwd"] == "/runtime/author-cwd"
        mounts = call["mounts"]
        assert isinstance(mounts, tuple)
        control = next(item for item in mounts if item.target == "/control/codex-home")
        assert control.read_only is False
        reviewed_toolchain = next(
            item for item in mounts if item.target == "/opt/reviewed-toolchain"
        )
        assert reviewed_toolchain.read_only is True
        assert call["environment"] == {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": "/runtime/home",
            "TMPDIR": "/runtime/tmp",
            "LANG": "C.UTF-8",
            "CODEX_HOME": "/control/codex-home",
        }


def test_codex_refresh_failure_blocks_candidate_persistence(tmp_path: Path) -> None:
    events: list[str] = []
    executor = ScriptedExecutor(
        stdout=_codex_jsonl("thread-001"),
        candidate=SubjectManifest.empty(),
        events=events,
    )
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir()
    install = tmp_path / "codex-install"
    install.mkdir()
    adapter = SandboxedCodexAuthorAdapter(
        executor,  # type: ignore[arg-type]
        RecordingTransaction(codex_home, events, fail_reconcile=True),
        install_mount=SandboxMount(str(install), "/opt/reviewed-codex"),
        executable="/opt/reviewed-codex/codex",
        clock=lambda: 0.0,
    )
    with pytest.raises(AgentLoopError) as caught:
        adapter.turn(AuthorRequest(1, SubjectManifest.empty(), "first", None, 1_000))
    assert caught.value.reason is StopReason.CREDENTIAL_REFRESH_FAILURE
    assert events == ["execute", "reconcile"]


def test_codex_secret_history_refreshes_before_every_cli_launch(tmp_path: Path) -> None:
    events: list[str] = []
    executor = ScriptedExecutor(
        stdout=_codex_jsonl("thread-001"),
        candidate=SubjectManifest.empty(),
        events=events,
    )
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir()
    install = tmp_path / "codex-install"
    install.mkdir()
    adapter = SandboxedCodexAuthorAdapter(
        executor,  # type: ignore[arg-type]
        RecordingTransaction(codex_home, events),
        install_mount=SandboxMount(str(install), "/opt/reviewed-codex"),
        executable="/opt/reviewed-codex/codex",
        secret_refresh=lambda: events.append("secret-refresh"),
        clock=lambda: 0.0,
    )

    first = adapter.turn(AuthorRequest(1, SubjectManifest.empty(), "first", None, 1_000))
    adapter.turn(
        AuthorRequest(2, SubjectManifest.empty(), "revise", first.thread_id, 1_000)
    )

    assert events == [
        "secret-refresh",
        "execute",
        "reconcile",
        "secret-refresh",
        "persist",
        "secret-refresh",
        "execute",
        "reconcile",
        "secret-refresh",
        "persist",
    ]


def test_codex_malformed_turn_is_still_reconciled_without_persistence(tmp_path: Path) -> None:
    events: list[str] = []
    attempts: list[tuple[SandboxRole, int, SandboxExecution]] = []
    executor = ScriptedExecutor(
        stdout=b"{not-json\n",
        candidate=SubjectManifest.empty(),
        events=events,
    )
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir()
    install = tmp_path / "codex-install"
    install.mkdir()
    adapter = SandboxedCodexAuthorAdapter(
        executor,  # type: ignore[arg-type]
        RecordingTransaction(codex_home, events),
        install_mount=SandboxMount(str(install), "/opt/reviewed-codex"),
        executable="/opt/reviewed-codex/codex",
        attempt_sink=lambda role, round_number, execution: attempts.append(
            (role, round_number, execution)
        ),
        clock=lambda: 0.0,
    )
    with pytest.raises(AgentLoopError) as caught:
        adapter.turn(AuthorRequest(1, SubjectManifest.empty(), "first", None, 1_000))
    assert caught.value.reason is StopReason.AUTHOR_PROCESS_FAILURE
    assert events == ["execute", "reconcile"]
    assert len(attempts) == 1
    assert attempts[0][0:2] == (SandboxRole.AUTHOR, 1)
    assert attempts[0][2].result.process.stdout == b"{not-json\n"


def test_author_toolchain_mounts_must_be_frozen_reviewed_and_read_only(
    tmp_path: Path,
) -> None:
    executor = ScriptedExecutor(
        stdout=_codex_jsonl("thread-001"),
        candidate=SubjectManifest.empty(),
    )
    codex_home = tmp_path / "codex-home"
    install = tmp_path / "codex-install"
    toolchain = tmp_path / "toolchain"
    codex_home.mkdir()
    install.mkdir()
    toolchain.mkdir()
    transaction = RecordingTransaction(codex_home, [])
    install_mount = SandboxMount(str(install), "/opt/reviewed-codex")

    with pytest.raises(ValueError, match="read-only"):
        SandboxedCodexAuthorAdapter(
            executor,  # type: ignore[arg-type]
            transaction,
            install_mount=install_mount,
            executable="/opt/reviewed-codex/codex",
            toolchain_mounts=(
                SandboxMount(str(toolchain), "/opt/reviewed-toolchain", read_only=False),
            ),
        )
    with pytest.raises(ValueError, match="private sandbox state"):
        SandboxedCodexAuthorAdapter(
            executor,  # type: ignore[arg-type]
            transaction,
            install_mount=install_mount,
            executable="/opt/reviewed-codex/codex",
            toolchain_mounts=(SandboxMount(str(toolchain), "/runtime/toolchain"),),
        )


def _claude_envelope() -> bytes:
    return json.dumps(
        {
            "type": "result",
            "model": "claude-fake",
            "effort": "high",
            "total_cost_usd": 0.0,
            "modelUsage": {"claude-fake": {}},
            "structured_output": {
                "schema_version": 1,
                "verdict": "LGTM",
                "summary": "complete",
                "blocked_reason": None,
                "blocking_findings": [],
                "non_blocking_findings": [],
            },
        },
        separators=(",", ":"),
    ).encode()


def test_048_claude_adapter_uses_empty_subject_bundle_stdin_and_dedicated_mounts(
    tmp_path: Path,
) -> None:
    executor = ScriptedExecutor(
        stdout=_claude_envelope(),
        candidate=SubjectManifest.empty(),
    )
    install = tmp_path / "claude-install"
    config = tmp_path / "claude-config"
    install.mkdir()
    config.mkdir()
    adapter = SandboxedClaudeCriticAdapter(
        executor,  # type: ignore[arg-type]
        "fake-dedicated-token",
        install_mount=SandboxMount(str(install), "/opt/reviewed-claude"),
        executable="/opt/reviewed-claude/claude",
        config_dir=config,
        model="claude-requested",
        effort="high",
        clock=lambda: 0.0,
    )
    bundle = ReviewBundle({}, b"complete-bundle", 4, "a" * 64)

    turn = adapter.review(
        CriticRequest(1, bundle, ApprovalContext(True, True, True), 1_000)
    )

    assert turn.review.verdict is Verdict.LGTM
    assert turn.observed_model == "claude-fake"
    assert turn.observed_effort == "high"
    assert turn.total_cost_usd == 0.0
    call = executor.calls[0]
    assert call["role"] is SandboxRole.CRITIC
    assert call["manifest"] == SubjectManifest.empty()
    assert call["stdin_bytes"] == bundle.encoded
    assert call["cwd"] == "/runtime/critic-cwd"
    argv = call["argv"]
    assert isinstance(argv, tuple)
    assert "--safe-mode" in argv and "--no-session-persistence" in argv
    assert argv[argv.index("--model") + 1] == "claude-requested"
    assert argv[argv.index("--effort") + 1] == "high"
    assert argv[argv.index("--tools") + 1] == ""
    environment = call["environment"]
    assert isinstance(environment, dict)
    assert environment["CLAUDE_CODE_OAUTH_TOKEN"] == "fake-dedicated-token"
    assert environment["TMPDIR"] == "/runtime/tmp"
    assert environment["CLAUDE_CODE_TMPDIR"] == "/runtime/critic-tmp"
    mounts = call["mounts"]
    assert isinstance(mounts, tuple)
    config_mount = next(item for item in mounts if item.target == "/control/claude-home")
    assert config_mount.read_only is True


def test_critic_nonzero_attempt_reaches_sink_once_before_client_failure(tmp_path: Path) -> None:
    attempts: list[tuple[SandboxRole, int, SandboxExecution]] = []
    executor = ScriptedExecutor(
        stdout=_claude_envelope(),
        candidate=SubjectManifest.empty(),
        returncode=9,
    )
    install = tmp_path / "claude-install"
    config = tmp_path / "claude-config"
    install.mkdir()
    config.mkdir()
    adapter = SandboxedClaudeCriticAdapter(
        executor,  # type: ignore[arg-type]
        "fake-dedicated-token",
        install_mount=SandboxMount(str(install), "/opt/reviewed-claude"),
        executable="/opt/reviewed-claude/claude",
        config_dir=config,
        attempt_sink=lambda role, round_number, execution: attempts.append(
            (role, round_number, execution)
        ),
        clock=lambda: 0.0,
    )

    with pytest.raises(AgentLoopError) as caught:
        adapter.review(
            CriticRequest(
                4,
                ReviewBundle({}, b"bundle", 2, "a" * 64),
                ApprovalContext(True, True, True),
                1_000,
            )
        )

    assert caught.value.reason is StopReason.CRITIC_PROCESS_FAILURE
    assert len(attempts) == 1
    assert attempts[0][0:2] == (SandboxRole.CRITIC, 4)
    assert attempts[0][2].result.process.returncode == 9
    assert "CLAUDE_CODE_OAUTH_TOKEN" not in attempts[0][2].request.environment


def test_claude_adapter_rejects_any_empty_subject_mutation(tmp_path: Path) -> None:
    payload = b"unexpected"
    digest = sha256_hex(payload)
    candidate = SubjectManifest.build(
        [ManifestEntry.regular(b"written", size=len(payload), blob_sha256=digest)]
    )
    executor = ScriptedExecutor(
        stdout=_claude_envelope(),
        candidate=candidate,
        new_blobs=((digest, payload),),
    )
    install = tmp_path / "claude-install"
    config = tmp_path / "claude-config"
    install.mkdir()
    config.mkdir()
    adapter = SandboxedClaudeCriticAdapter(
        executor,  # type: ignore[arg-type]
        "fake-dedicated-token",
        install_mount=SandboxMount(str(install), "/opt/reviewed-claude"),
        executable="/opt/reviewed-claude/claude",
        config_dir=config,
        clock=lambda: 0.0,
    )
    with pytest.raises(AgentLoopError) as caught:
        adapter.review(
            CriticRequest(
                1,
                ReviewBundle({}, b"bundle", 2, "a" * 64),
                ApprovalContext(True, True, True),
                1_000,
            )
        )
    assert caught.value.reason is StopReason.OUT_OF_BAND_CHANGE


def test_072_claude_token_encoding_cannot_enter_retained_envelope(tmp_path: Path) -> None:
    token = "fake-dedicated-token"
    attempts: list[tuple[SandboxRole, int, SandboxExecution]] = []
    executor = ScriptedExecutor(
        stdout=token.encode().hex().encode(),
        candidate=SubjectManifest.empty(),
    )
    install = tmp_path / "claude-install"
    config = tmp_path / "claude-config"
    install.mkdir()
    config.mkdir()
    adapter = SandboxedClaudeCriticAdapter(
        executor,  # type: ignore[arg-type]
        token,
        install_mount=SandboxMount(str(install), "/opt/reviewed-claude"),
        executable="/opt/reviewed-claude/claude",
        config_dir=config,
        attempt_sink=lambda role, round_number, execution: attempts.append(
            (role, round_number, execution)
        ),
        clock=lambda: 0.0,
    )
    with pytest.raises(AgentLoopError) as caught:
        adapter.review(
            CriticRequest(
                1,
                ReviewBundle({}, b"bundle", 2, "a" * 64),
                ApprovalContext(True, True, True),
                1_000,
            )
        )
    assert caught.value.reason is StopReason.CREDENTIAL_REFRESH_FAILURE
    assert attempts == []
