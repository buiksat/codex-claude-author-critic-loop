from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
import types
from dataclasses import replace
from pathlib import Path

import pytest

import agent_loop.sandbox_init as sandbox_init_module

from agent_loop.claude_client import build_claude_argv
from agent_loop.constants import REGULAR_MODE, Limits
from agent_loop.declassify import KnownSecret
from agent_loop.errors import AgentLoopError, StopReason
from agent_loop.manifests import SubjectManifest, reconcile_candidate
from agent_loop.models import EntryKind, ManifestEntry, PathPolicy, sha256_hex
from agent_loop.runner import LoopRunner, LoopSettings, _manifest_contains_known_secret
from agent_loop.sandbox_init import (
    CleanupResult,
    MIN_PROTOCOL_EXPORT_BYTES,
    PrimaryResult,
    SandboxRequest,
    SandboxResult,
    SupervisorLimits,
    encode_request,
    encode_result,
    parse_request,
    parse_response,
    parse_result,
)
from agent_loop.validation_batch import (
    MAX_VALIDATION_BATCH_RESULT_BYTES,
    VALIDATION_BATCH_SENTINEL,
    ValidationBatchCheck,
    ValidationBatchRequest,
    encode_validation_batch_request,
    parse_validation_batch_result,
)
from tests.fakes.runner_harness import (
    FakeAuthor,
    FakeClock,
    FakeCritic,
    FakeJournal,
    FakeValidator,
    MemoryBlobStore,
    lgtm_review,
    manifest_from_files,
    revise_review,
)


def _request(
    code: str,
    *,
    files: dict[bytes, bytes] | None = None,
    timeout_ms: int = 2_000,
    max_output_bytes: int = 64 * 1024,
    max_files: int = 128,
    stdin: bytes = b"",
) -> SandboxRequest:
    blobs: dict[str, bytes] = {}
    entries: list[ManifestEntry] = []
    for path, data in sorted((files or {}).items()):
        digest = sha256_hex(data)
        blobs[digest] = data
        entries.append(
            ManifestEntry(
                path=path,
                kind=EntryKind.REGULAR,
                mode=REGULAR_MODE,
                size=len(data),
                blob_sha256=digest,
            )
        )
    return SandboxRequest(
        manifest=SubjectManifest.build(entries),
        blobs=tuple(sorted(blobs.items())),
        argv=("/usr/bin/python3", "-c", code),
        env=(
            ("HOME", "/runtime/home"),
            ("LANG", "C.UTF-8"),
            ("PATH", "/usr/bin:/bin"),
            ("TMPDIR", "/runtime/tmp"),
        ),
        cwd="/workspace",
        stdin_bytes=stdin,
        limits=SupervisorLimits(
            timeout_ms=timeout_ms,
            terminate_grace_ms=200,
            max_output_bytes=max_output_bytes,
            max_export_bytes=2 * 1024 * 1024,
            subject=Limits(
                max_files=max_files,
                max_file_bytes=1024 * 1024,
                max_total_subject_bytes=4 * 1024 * 1024,
                max_path_bytes=1024,
                max_path_depth=32,
            ),
        ),
    )


def _run_direct(workspace: Path, request: SandboxRequest) -> dict[str, object]:
    script = """
import sys
from agent_loop.sandbox_init import encode_result, execute_request, parse_request
request = parse_request(sys.stdin.buffer.read())
result = execute_request(request, workspace=sys.argv[1])
sys.stdout.buffer.write(encode_result(result, max_bytes=request.limits.max_export_bytes))
"""
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONPATH": os.path.abspath("src"),
        "LANG": "C.UTF-8",
    }
    completed = subprocess.run(
        (sys.executable, "-c", script, os.fspath(workspace)),
        input=encode_request(request),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        close_fds=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "backslashreplace")
    return json.loads(completed.stdout)


def _run_direct_outcome(workspace: Path, request: SandboxRequest) -> dict[str, object]:
    """Run the real supervisor while serializing an expected typed export failure."""

    script = """
import json, sys
from agent_loop.errors import AgentLoopError
from agent_loop.sandbox_init import encode_result, execute_request, parse_request
request = parse_request(sys.stdin.buffer.read())
try:
    result = execute_request(request, workspace=sys.argv[1])
except AgentLoopError as error:
    sys.stdout.write(json.dumps({"kind": "error", "reason": error.reason.value}))
else:
    sys.stdout.buffer.write(encode_result(result, max_bytes=request.limits.max_export_bytes))
"""
    completed = subprocess.run(
        (sys.executable, "-c", script, os.fspath(workspace)),
        input=encode_request(request),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONPATH": os.path.abspath("src"),
            "LANG": "C.UTF-8",
        },
        close_fds=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "backslashreplace")
    return json.loads(completed.stdout)


@pytest.fixture
def fake_workspace_agent(tmp_path: Path) -> Path:
    source = Path(__file__).parents[1] / "fakes" / "fake_workspace_agent.py"
    executable = tmp_path / "fake-workspace-agent"
    shutil.copyfile(source, executable)
    executable.chmod(0o755)
    return executable


def _fake_workspace_request(
    executable: Path,
    scenario: str,
    *,
    files: dict[bytes, bytes] | None = None,
    timeout_ms: int = 2_000,
    max_output_bytes: int = 64 * 1024,
    max_files: int = 128,
    max_file_bytes: int = 1024 * 1024,
) -> SandboxRequest:
    request = _request(
        "pass",
        files=files,
        timeout_ms=timeout_ms,
        max_output_bytes=max_output_bytes,
        max_files=max_files,
    )
    return replace(
        request,
        argv=(os.fspath(executable), scenario),
        limits=replace(
            request.limits,
            subject=replace(
                request.limits.subject,
                max_file_bytes=max_file_bytes,
            ),
        ),
    )


def _candidate_and_blobs(
    result: dict[str, object],
) -> tuple[SubjectManifest, MemoryBlobStore]:
    candidate_value = result["candidate_manifest"]
    assert isinstance(candidate_value, dict)
    candidate = SubjectManifest.from_json_obj(candidate_value)
    blobs = MemoryBlobStore()
    for digest, data in _decoded_new_blobs(result).items():
        assert blobs.put_blob(data) == digest
    return candidate, blobs


def _decoded_new_blobs(result: dict[str, object]) -> dict[str, bytes]:
    raw = result["new_blobs"]
    assert isinstance(raw, list)
    return {
        item["sha256"]: base64.b64decode(item["data_b64"], validate=True)
        for item in raw
    }


def test_protocol_rejects_duplicate_and_unknown_properties() -> None:
    request = _request("pass")
    valid = encode_request(request)
    with pytest.raises(AgentLoopError) as duplicate:
        parse_request(valid.replace(b'{"argv"', b'{"kind":"request","argv"', 1))
    assert duplicate.value.reason is StopReason.SANDBOX_SETUP_FAILURE

    value = json.loads(valid)
    value["unknown"] = True
    with pytest.raises(AgentLoopError) as unknown:
        parse_request(json.dumps(value).encode())
    assert unknown.value.reason is StopReason.SANDBOX_SETUP_FAILURE


def test_protocol_rejects_missing_blob_and_noncanonical_base64() -> None:
    request = _request("pass", files={b"input": b"bytes"})
    value = json.loads(encode_request(request))
    value["blobs"] = []
    with pytest.raises(AgentLoopError):
        parse_request(json.dumps(value).encode())

    value = json.loads(encode_request(request))
    value["stdin_b64"] = "YQ"
    with pytest.raises(AgentLoopError):
        parse_request(json.dumps(value).encode())


def test_protocol_rejects_non_allowlisted_environment() -> None:
    request = _request("pass")
    value = json.loads(encode_request(request))
    value["env"]["AWS_SECRET_ACCESS_KEY"] = "must-not-enter"
    with pytest.raises(AgentLoopError) as captured:
        parse_request(json.dumps(value).encode())
    assert captured.value.reason is StopReason.SANDBOX_SETUP_FAILURE


def test_protocol_round_trips_claude_empty_tool_argument_but_rejects_empty_executable(
) -> None:
    environment = dict(_request("pass").env)
    environment.update(
        {
            "CLAUDE_CODE_DEBUG_LOG_LEVEL": "verbose",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        }
    )
    request = replace(
        _request("pass"),
        argv=build_claude_argv(model="claude-pinned", effort="high"),
        env=tuple(sorted(environment.items())),
        cwd="/runtime/critic-cwd",
    )

    parsed = parse_request(encode_request(request))

    assert parsed == request
    assert parsed.argv[parsed.argv.index("--tools") + 1] == ""
    assert dict(parsed.env)["CLAUDE_CODE_DEBUG_LOG_LEVEL"] == "verbose"
    assert dict(parsed.env)["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] == "1"

    for key in (
        "CLAUDE_CODE_DEBUG_LOG_LEVEL",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
    ):
        broadened = json.loads(encode_request(request))
        broadened["env"][key] = "0"
        with pytest.raises(AgentLoopError, match="fixed sandbox value"):
            parse_request(json.dumps(broadened).encode())

    invalid = replace(request, argv=("", "--version"))
    with pytest.raises(AgentLoopError, match=r"argv\[0\].*non-empty"):
        parse_request(encode_request(invalid))


def test_protocol_reserves_large_output_only_for_exact_validation_batch() -> None:
    broadened = replace(
        _request("pass"),
        limits=replace(
            _request("pass").limits,
            max_output_bytes=MAX_VALIDATION_BATCH_RESULT_BYTES,
        ),
    )
    with pytest.raises(AgentLoopError, match="ordinary primary output"):
        parse_request(encode_request(broadened))

    batch = replace(
        broadened,
        argv=(VALIDATION_BATCH_SENTINEL,),
        env=tuple(
            sorted(
                {
                    "PATH": "/usr/bin:/bin",
                    "HOME": "/runtime/home",
                    "TMPDIR": "/runtime/tmp",
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "TZ": "UTC",
                }.items()
            )
        ),
        stdin_bytes=encode_validation_batch_request(
            ValidationBatchRequest(
                (ValidationBatchCheck("one", "true", 1_000, 1_024),),
                1_024,
            )
        ),
    )
    assert parse_request(encode_request(batch)) == batch


def test_validation_batch_deadline_before_launch_records_unstarted_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = replace(
        _request("pass", timeout_ms=1),
        argv=(VALIDATION_BATCH_SENTINEL,),
        stdin_bytes=encode_validation_batch_request(
            ValidationBatchRequest(
                (ValidationBatchCheck("one", "true", 1_000, 1_024),),
                1_024,
            )
        ),
        limits=replace(
            _request("pass").limits,
            timeout_ms=1,
            max_output_bytes=MAX_VALIDATION_BATCH_RESULT_BYTES,
        ),
    )
    readings = iter((0.0, 0.01, 0.01))
    monkeypatch.setattr(
        sandbox_init_module,
        "time",
        types.SimpleNamespace(monotonic=lambda: next(readings)),
    )
    process, cleanup = sandbox_init_module._run_validation_batch(request, tmp_path)
    records = parse_validation_batch_result(
        process.stdout,
        expected_checks=1,
        max_raw_output_bytes=1_024,
    )
    assert cleanup.namespace_empty is True
    assert records[0].timed_out is True
    assert records[0].process_started is False


@pytest.mark.parametrize(
    "injected",
    (
        OSError("injected post-spawn pipe setup failure"),
        KeyboardInterrupt(),
    ),
)
def test_primary_post_spawn_setup_failure_terminates_and_closes_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    injected: BaseException,
) -> None:
    class FakePipe:
        def __init__(self, descriptor: int) -> None:
            self._descriptor = descriptor
            self.closed = False

        def fileno(self) -> int:
            return self._descriptor

        def close(self) -> None:
            self.closed = True

    class FakeProcess:
        def __init__(self) -> None:
            self.pid = 4242
            self.stdin = None
            self.stdout = FakePipe(10)
            self.stderr = FakePipe(11)
            self.returncode: int | None = None

    process = FakeProcess()
    terminated: list[FakeProcess] = []

    monkeypatch.setattr(sandbox_init_module, "_prepare_supervisor", lambda: None)
    monkeypatch.setattr(
        sandbox_init_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: process,
    )
    monkeypatch.setattr(
        sandbox_init_module,
        "_harden_primary_after_exec",
        lambda _process: None,
    )

    def terminate(
        selected: FakeProcess,
        *,
        grace_ms: int,
    ) -> CleanupResult:
        assert grace_ms > 0
        selected.returncode = -9
        terminated.append(selected)
        return CleanupResult(1, True)

    monkeypatch.setattr(sandbox_init_module, "_terminate_descendants", terminate)

    def fail_setup(_descriptor: int, _blocking: bool) -> None:
        raise injected

    monkeypatch.setattr(sandbox_init_module.os, "set_blocking", fail_setup)

    with pytest.raises(type(injected)):
        sandbox_init_module._run_primary(_request("pass"), tmp_path)

    assert terminated == [process]
    assert process.returncode == -9
    assert process.stdout.closed is True
    assert process.stderr.closed is True


def test_primary_cleanup_failures_do_not_replace_active_interruption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    interruption = KeyboardInterrupt()

    class FakePipe:
        def __init__(self, descriptor: int, close_error: BaseException | None = None) -> None:
            self._descriptor = descriptor
            self._close_error = close_error
            self.closed = False
            self.close_attempted = False

        def fileno(self) -> int:
            return self._descriptor

        def close(self) -> None:
            self.close_attempted = True
            if self._close_error is not None:
                raise self._close_error
            self.closed = True

    class FakeSelector:
        def register(self, *_args: object) -> None:
            raise interruption

        def close(self) -> None:
            raise RuntimeError("injected selector close failure")

    class FakeProcess:
        def __init__(self) -> None:
            self.pid = 4242
            self.stdin = None
            self.stdout = FakePipe(10, OSError("injected stdout close failure"))
            self.stderr = FakePipe(11)
            self.returncode: int | None = None

    process = FakeProcess()
    terminated: list[FakeProcess] = []
    monkeypatch.setattr(sandbox_init_module, "_prepare_supervisor", lambda: None)
    monkeypatch.setattr(
        sandbox_init_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: process,
    )
    monkeypatch.setattr(
        sandbox_init_module,
        "_harden_primary_after_exec",
        lambda _process: None,
    )
    monkeypatch.setattr(sandbox_init_module.os, "set_blocking", lambda *_args: None)
    monkeypatch.setattr(
        sandbox_init_module.selectors,
        "DefaultSelector",
        FakeSelector,
    )

    def terminate(
        selected: FakeProcess,
        *,
        grace_ms: int,
    ) -> CleanupResult:
        assert grace_ms > 0
        selected.returncode = -9
        terminated.append(selected)
        return CleanupResult(1, True)

    monkeypatch.setattr(sandbox_init_module, "_terminate_descendants", terminate)

    with pytest.raises(KeyboardInterrupt) as captured:
        sandbox_init_module._run_primary(_request("pass"), tmp_path)

    assert captured.value is interruption
    assert terminated == [process]
    assert getattr(captured.value, "__notes__", []) == [
        "post-spawn selector close also failed: RuntimeError",
        "post-spawn stdout pipe close also failed: OSError",
    ]
    assert process.stdout.close_attempted is True
    assert process.stderr.closed is True


def test_primary_cleanup_failure_is_fatal_after_successful_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selector_failure = RuntimeError("injected selector close failure")

    class FakePipe:
        def __init__(self, descriptor: int, close_error: BaseException | None = None) -> None:
            self._descriptor = descriptor
            self._close_error = close_error
            self.closed = False
            self.close_attempted = False

        def fileno(self) -> int:
            return self._descriptor

        def close(self) -> None:
            self.close_attempted = True
            if self._close_error is not None:
                raise self._close_error
            self.closed = True

    class FakeSelector:
        def register(self, *_args: object) -> None:
            return None

        def close(self) -> None:
            raise selector_failure

    class FakeProcess:
        def __init__(self) -> None:
            self.pid = 4242
            self.stdin = None
            self.stdout = FakePipe(10, OSError("injected stdout close failure"))
            self.stderr = FakePipe(11)
            self.returncode = 0

        def poll(self) -> int:
            return self.returncode

    process = FakeProcess()
    monkeypatch.setattr(sandbox_init_module, "_prepare_supervisor", lambda: None)
    monkeypatch.setattr(
        sandbox_init_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: process,
    )
    monkeypatch.setattr(
        sandbox_init_module,
        "_harden_primary_after_exec",
        lambda _process: None,
    )
    monkeypatch.setattr(sandbox_init_module.os, "set_blocking", lambda *_args: None)
    monkeypatch.setattr(
        sandbox_init_module.selectors,
        "DefaultSelector",
        FakeSelector,
    )
    monkeypatch.setattr(
        sandbox_init_module,
        "_terminate_descendants",
        lambda *_args, **_kwargs: CleanupResult(0, True),
    )
    monkeypatch.setattr(
        sandbox_init_module,
        "_drain_after_cleanup",
        lambda *_args, **_kwargs: False,
    )

    with pytest.raises(RuntimeError) as captured:
        sandbox_init_module._run_primary(_request("pass"), tmp_path)

    assert captured.value is selector_failure
    assert getattr(captured.value, "__notes__", []) == [
        "post-spawn stdout pipe close also failed: OSError",
        "post-spawn cleanup failed while closing selector",
    ]
    assert process.stdout.close_attempted is True
    assert process.stderr.closed is True


def test_protocol_error_response_remains_within_minimum_export_cap() -> None:
    key = json.dumps("\N{COLLISION SYMBOL}" * 8_192)
    malformed = f"{{{key}:0,{key}:1}}".encode()
    completed = subprocess.run(
        (sys.executable, "-m", "agent_loop.sandbox_init"),
        input=malformed,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONPATH": os.path.abspath("src"),
            "LANG": "C.UTF-8",
        },
        close_fds=True,
        check=False,
        timeout=5,
    )
    assert completed.returncode == 2
    assert completed.stderr == b""
    assert len(completed.stdout) <= MIN_PROTOCOL_EXPORT_BYTES
    assert json.loads(completed.stdout)["kind"] == "error"


def test_009_materialize_run_cleanup_then_complete_export(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    code = (
        "from pathlib import Path; "
        "data=Path('input.txt').read_bytes(); "
        "Path('output.txt').write_bytes(data+b'-changed'); "
        "Path('ignored.cache').write_bytes(b'authoritative'); "
        "Path('input.txt').unlink(); print('done')"
    )
    result = _run_direct(workspace, _request(code, files={b"input.txt": b"base"}))
    assert result["kind"] == "result"
    assert result["process"]["returncode"] == 0
    assert base64.b64decode(result["process"]["stdout_b64"]) == b"done\n"
    assert result["cleanup"] == {
        "export_started_after_cleanup": True,
        "namespace_empty": True,
        "terminated_pids": 0,
    }
    paths = {
        base64.b64decode(entry["path_b64"])
        for entry in result["candidate_manifest"]["entries"]
    }
    assert paths == {b"ignored.cache", b"output.txt"}
    assert set(_decoded_new_blobs(result).values()) == {b"authoritative", b"base-changed"}


def test_phase3_configurable_executable_mutation_matrix_crosses_real_export_and_policy(
    tmp_path: Path,
    fake_workspace_agent: Path,
) -> None:
    def execute(scenario: str) -> tuple[SubjectManifest, MemoryBlobStore]:
        workspace = tmp_path / scenario
        workspace.mkdir()
        result = _run_direct(
            workspace,
            _fake_workspace_request(fake_workspace_agent, scenario),
        )
        process = result["process"]
        assert isinstance(process, dict) and process["returncode"] == 0
        return _candidate_and_blobs(result)

    allowed, _allowed_blobs = execute("allowed")
    allowed_result = reconcile_candidate(SubjectManifest.empty(), allowed, PathPolicy())
    assert [change.new_path for change in allowed_result.semantic_changes] == [
        b"src/allowed.txt"
    ]

    protected, _protected_blobs = execute("protected")
    with pytest.raises(AgentLoopError) as protected_error:
        reconcile_candidate(SubjectManifest.empty(), protected, PathPolicy())
    assert protected_error.value.reason is StopReason.PROTECTED_SUBJECT_PATH_CHANGED

    ignored, _ignored_blobs = execute("ignored")
    ignored_result = reconcile_candidate(SubjectManifest.empty(), ignored, PathPolicy())
    assert {entry.path for entry in ignored_result.authoritative_manifest.entries} == {
        b".gitignore",
        b"ignored/generated.txt",
    }

    secret_candidate, secret_blobs = execute("secret-like")
    secret = KnownSecret("phase3-fake", b"fake-matrix-secret")
    assert _manifest_contains_known_secret(secret_candidate, secret_blobs, (secret,))

    binary, binary_blobs = execute("binary")
    binary_entry = next(entry for entry in binary.entries if entry.path == b"binary.dat")
    assert binary_entry.blob_sha256 is not None
    assert binary_blobs.read_blob(binary_entry.blob_sha256) == b"\x00\xffbinary\x00payload"

    symlink, _symlink_blobs = execute("symlink")
    link = next(entry for entry in symlink.entries if entry.path == b"link")
    assert link.kind is EntryKind.SYMLINK
    assert link.symlink_target == b"../literal-target"


@pytest.mark.parametrize(
    ("scenario", "max_files", "max_file_bytes"),
    (
        ("oversized", 128, 128),
        ("hard-link", 128, 1024 * 1024),
        ("special", 128, 1024 * 1024),
        ("many-files", 4, 1024 * 1024),
    ),
)
def test_phase3_configurable_executable_unsafe_mutations_fail_closed_after_cleanup(
    tmp_path: Path,
    fake_workspace_agent: Path,
    scenario: str,
    max_files: int,
    max_file_bytes: int,
) -> None:
    workspace = tmp_path / scenario
    workspace.mkdir()
    result = _run_direct_outcome(
        workspace,
        _fake_workspace_request(
            fake_workspace_agent,
            scenario,
            max_files=max_files,
            max_file_bytes=max_file_bytes,
        ),
    )

    assert result == {
        "kind": "error",
        "reason": StopReason.UNSAFE_FILE_TYPE_OR_HARD_LINK.value,
    }


@pytest.mark.parametrize("scenario", ("fork", "daemon"))
def test_phase3_configurable_executable_descendants_are_reaped(
    tmp_path: Path,
    fake_workspace_agent: Path,
    scenario: str,
) -> None:
    workspace = tmp_path / scenario
    workspace.mkdir()
    result = _run_direct(
        workspace,
        _fake_workspace_request(fake_workspace_agent, scenario),
    )

    process = result["process"]
    cleanup = result["cleanup"]
    assert isinstance(process, dict) and process["returncode"] == 0
    assert isinstance(cleanup, dict) and cleanup["namespace_empty"] is True
    assert cleanup["terminated_pids"] >= 1


@pytest.mark.parametrize(
    ("scenario", "timeout_ms", "output_cap", "expected_field"),
    (
        ("hang", 100, 64 * 1024, "timed_out"),
        ("output-limit", 2_000, 1024, "output_limited"),
    ),
)
def test_phase3_configurable_executable_hang_and_output_limits_are_bounded(
    tmp_path: Path,
    fake_workspace_agent: Path,
    scenario: str,
    timeout_ms: int,
    output_cap: int,
    expected_field: str,
) -> None:
    workspace = tmp_path / scenario
    workspace.mkdir()
    result = _run_direct(
        workspace,
        _fake_workspace_request(
            fake_workspace_agent,
            scenario,
            timeout_ms=timeout_ms,
            max_output_bytes=output_cap,
        ),
    )

    process = result["process"]
    cleanup = result["cleanup"]
    assert isinstance(process, dict) and process[expected_field] is True
    assert process["returncode"] < 0
    assert isinstance(cleanup, dict) and cleanup["namespace_empty"] is True


def test_phase3_configurable_executable_nonzero_is_retained_with_exact_prefix(
    tmp_path: Path,
    fake_workspace_agent: Path,
) -> None:
    workspace = tmp_path / "nonzero"
    workspace.mkdir()
    result = _run_direct(
        workspace,
        _fake_workspace_request(fake_workspace_agent, "nonzero"),
    )

    process = result["process"]
    assert isinstance(process, dict) and process["returncode"] == 7
    assert base64.b64decode(process["stderr_b64"]) == b"deterministic fake failure\n"


def _executable_revision_candidate(
    tmp_path: Path,
    executable: Path,
    scenario: str,
    before: bytes,
) -> tuple[SubjectManifest, MemoryBlobStore]:
    workspace = tmp_path / scenario
    workspace.mkdir()
    result = _run_direct(
        workspace,
        _fake_workspace_request(
            executable,
            scenario,
            files={b"app.py": before},
        ),
    )
    return _candidate_and_blobs(result)


def test_phase3_executable_revision_sequence_converges_on_final_round(
    tmp_path: Path,
    fake_workspace_agent: Path,
) -> None:
    first, first_blobs = _executable_revision_candidate(
        tmp_path,
        fake_workspace_agent,
        "revision-one",
        b"value = 0\n",
    )
    second, second_blobs = _executable_revision_candidate(
        tmp_path,
        fake_workspace_agent,
        "revision-two",
        b"value = 1\n",
    )
    blobs = MemoryBlobStore()
    base = manifest_from_files(blobs, {b"app.py": b"value = 0\n"})
    blobs.values.update(first_blobs.values)
    blobs.values.update(second_blobs.values)
    author = FakeAuthor((first, second))
    journal = FakeJournal()

    result = LoopRunner(
        author=author,
        validator=FakeValidator((True, False, True)),
        critic=FakeCritic((revise_review(), lgtm_review())),
        blobs=blobs,
        policy=PathPolicy(),
        journal=journal,
        clock=FakeClock(),
    ).run("implement the revision", base, LoopSettings(max_rounds=2))

    assert result.stop_reason is StopReason.CONVERGED
    assert result.rounds_completed == 2
    assert result.subject == second
    assert author.requests[1].thread_id == "thread-exact-001"


def test_phase3_executable_exact_repeat_reaches_stall_detection(
    tmp_path: Path,
    fake_workspace_agent: Path,
) -> None:
    first, first_blobs = _executable_revision_candidate(
        tmp_path,
        fake_workspace_agent,
        "revision-one",
        b"value = 0\n",
    )
    repeated, repeated_blobs = _executable_revision_candidate(
        tmp_path,
        fake_workspace_agent,
        "revision-one-repeat",
        b"value = 0\n",
    )
    blobs = MemoryBlobStore()
    base = manifest_from_files(blobs, {b"app.py": b"value = 0\n"})
    blobs.values.update(first_blobs.values)
    blobs.values.update(repeated_blobs.values)
    review = revise_review(finding_id="same", required_fix="same exact fix")

    result = LoopRunner(
        author=FakeAuthor((first, repeated)),
        validator=FakeValidator((True, False, False)),
        critic=FakeCritic((review, review)),
        blobs=blobs,
        policy=PathPolicy(),
        journal=FakeJournal(),
        clock=FakeClock(),
    ).run("implement the revision", base, LoopSettings(max_rounds=3))

    assert first == repeated
    assert result.stop_reason is StopReason.STALLED
    assert result.rounds_completed == 2


def test_primary_stdin_and_nonzero_exit_are_captured_before_export(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    code = (
        "import pathlib,sys; "
        "pathlib.Path('stdin.bin').write_bytes(sys.stdin.buffer.read()); "
        "print('failure-detail', file=sys.stderr); raise SystemExit(7)"
    )
    result = _run_direct(workspace, _request(code, stdin=b"input-data"))
    assert result["process"]["returncode"] == 7
    assert base64.b64decode(result["process"]["stderr_b64"]) == b"failure-detail\n"
    assert result["cleanup"]["namespace_empty"] is True
    assert b"input-data" in _decoded_new_blobs(result).values()


@pytest.mark.parametrize(
    "argv",
    [
        pytest.param(
            ("/usr/bin/git", "add", "--", "tracked.txt"),
            id="staging",
        ),
        pytest.param(
            ("/usr/bin/git", "log", "-1", "--oneline"),
            id="history",
        ),
    ],
)
def test_006_git_staging_and_history_fail_in_gitless_materialization(
    tmp_path: Path,
    argv: tuple[str, ...],
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    request = replace(
        _request("pass", files={b"tracked.txt": b"authoritative\n"}),
        argv=argv,
    )

    result = _run_direct(workspace, request)

    process = result["process"]
    assert isinstance(process, dict)
    assert process["returncode"] != 0
    assert b"not a git repository" in base64.b64decode(process["stderr_b64"])
    assert result["base_fingerprint"] == request.manifest.fingerprint
    assert SubjectManifest.from_json_obj(result["candidate_manifest"]) == request.manifest
    assert not (workspace / ".git").exists()


@pytest.mark.parametrize(
    "argv",
    [
        ("/usr/bin/true",),
        ("/bin/bash", "--noprofile", "--norc", "-c", "exit 0"),
    ],
)
def test_primary_post_exec_hardening_supports_native_and_shell_images(
    tmp_path: Path,
    argv: tuple[str, ...],
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    request = replace(_request("pass"), argv=argv)
    result = _run_direct(workspace, request)
    assert result["kind"] == "result"
    assert result["process"]["returncode"] == 0
    assert result["cleanup"]["namespace_empty"] is True


def test_029_setsid_descendant_is_killed_and_reaped_before_export(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    code = """
import os, pathlib, time
pid = os.fork()
if pid == 0:
    os.setsid()
    pathlib.Path('daemon.pid').write_text(str(os.getpid()))
    while True:
        time.sleep(1)
while not pathlib.Path('daemon.pid').exists():
    time.sleep(0.001)
"""
    result = _run_direct(workspace, _request(code))
    assert result["process"]["returncode"] == 0
    assert result["cleanup"]["namespace_empty"] is True
    assert result["cleanup"]["terminated_pids"] >= 1
    daemon_pid = int((workspace / "daemon.pid").read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(daemon_pid, 0)


def test_timeout_kills_primary_and_all_descendants_before_export(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    code = """
import os, pathlib, time
if os.fork() == 0:
    os.setsid()
    while True: time.sleep(1)
pathlib.Path('started').write_text('yes')
while True: time.sleep(1)
"""
    result = _run_direct(workspace, _request(code, timeout_ms=100))
    assert result["process"]["timed_out"] is True
    assert result["process"]["returncode"] < 0
    assert result["cleanup"]["namespace_empty"] is True
    assert result["cleanup"]["terminated_pids"] >= 1


def test_output_limit_is_bounded_and_cleanup_precedes_export(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    result = _run_direct(
        workspace,
        _request("import os; os.write(1,b'x'*1000000)", max_output_bytes=1024),
    )
    process = result["process"]
    assert process["output_limited"] is True
    assert len(base64.b64decode(process["stdout_b64"])) == 1024
    assert result["cleanup"]["namespace_empty"] is True


def test_sandbox_protocol_json_schema_accepts_request_and_result(tmp_path: Path) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(Path("schemas/sandbox-protocol-v1.schema.json").read_text())
    validator = jsonschema.Draft202012Validator(schema)
    request = _request("pass")
    validator.validate(json.loads(encode_request(request)))
    batch = replace(
        request,
        argv=(VALIDATION_BATCH_SENTINEL,),
        env=tuple(
            sorted(
                {
                    "PATH": "/usr/bin:/bin",
                    "HOME": "/runtime/home",
                    "TMPDIR": "/runtime/tmp",
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "TZ": "UTC",
                }.items()
            )
        ),
        stdin_bytes=encode_validation_batch_request(
            ValidationBatchRequest(
                (ValidationBatchCheck("one", "true", 1_000, 1_024),),
                1_024,
            )
        ),
        limits=replace(
            request.limits,
            max_output_bytes=MAX_VALIDATION_BATCH_RESULT_BYTES,
        ),
    )
    validator.validate(json.loads(encode_request(batch)))
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    validator.validate(_run_direct(workspace, request))


def test_strict_response_parser_binds_fingerprint_cleanup_and_new_blobs() -> None:
    request = _request("pass")
    payload = b"candidate"
    digest = sha256_hex(payload)
    candidate = SubjectManifest.build(
        [ManifestEntry.regular(b"file", size=len(payload), blob_sha256=digest)]
    )
    result = SandboxResult(
        base_fingerprint=request.manifest.fingerprint,
        candidate=candidate,
        new_blobs=((digest, payload),),
        process=PrimaryResult(0, b"out", b"", False, False, 1),
        cleanup=CleanupResult(0, True),
    )
    encoded = encode_result(result, max_bytes=request.limits.max_export_bytes)
    assert parse_result(encoded, request=request) == result

    tampered = json.loads(encoded)
    tampered["base_fingerprint"] = "0" * 64
    with pytest.raises(AgentLoopError):
        parse_response(json.dumps(tampered).encode(), request=request)

    tampered = json.loads(encoded)
    tampered["cleanup"]["export_started_after_cleanup"] = False
    with pytest.raises(AgentLoopError):
        parse_response(json.dumps(tampered).encode(), request=request)

    tampered = json.loads(encoded)
    tampered["new_blobs"] = []
    with pytest.raises(AgentLoopError):
        parse_response(json.dumps(tampered).encode(), request=request)

    duplicate = encoded.replace(b'{"base_fingerprint"', b'{"kind":"result","base_fingerprint"', 1)
    with pytest.raises(AgentLoopError):
        parse_response(duplicate, request=request)

    tampered = json.loads(encoded)
    tampered["unknown"] = True
    with pytest.raises(AgentLoopError):
        parse_response(json.dumps(tampered).encode(), request=request)


def test_parse_result_raises_typed_remote_error() -> None:
    request = _request("pass")
    response = json.dumps(
        {
            "protocol_version": 1,
            "kind": "error",
            "error": {
                "reason": StopReason.AUTHOR_SERVICE_NOT_EMPTY.value,
                "detail": "cleanup proof failed",
            },
        }
    ).encode()
    parsed = parse_response(response, request=request)
    assert parsed.reason is StopReason.AUTHOR_SERVICE_NOT_EMPTY
    with pytest.raises(AgentLoopError) as captured:
        parse_result(response, request=request)
    assert captured.value.reason is StopReason.AUTHOR_SERVICE_NOT_EMPTY
