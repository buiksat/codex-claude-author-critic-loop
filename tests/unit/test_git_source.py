from __future__ import annotations

import os
import selectors
import subprocess
from pathlib import Path

import pytest

import agent_loop.git_source as git_source
from agent_loop.constants import Limits
from agent_loop.errors import AgentLoopError, StopReason, fail
from agent_loop.git_source import (
    GitCommandRunner,
    GitSandboxMode,
    _assert_read_only_git_command,
    _parse_cat_file_batch,
    _parse_ls_tree,
    sanitized_git_environment,
)
from agent_loop.service import BoundedProcessResult, ServiceLimits, ServiceResult


def _fake_executable(path: Path, body: str) -> Path:
    path.write_text(f"#!/usr/bin/python3\n{body}", encoding="utf-8")
    path.chmod(0o755)
    return path


def test_037_git_environment_is_an_allowlist_not_an_ambient_copy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    hostile_names = (
        "GIT_EXTERNAL_DIFF",
        "GIT_CONFIG_COUNT",
        "GIT_SSH_COMMAND",
        "SSH_COMMAND",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "EDITOR",
        "VISUAL",
    )
    for name in hostile_names:
        monkeypatch.setenv(name, "hostile-value")
    environment = sanitized_git_environment()
    assert not set(hostile_names).intersection(environment)
    assert environment["GIT_OPTIONAL_LOCKS"] == "0"
    assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
    assert environment["GIT_CONFIG_GLOBAL"] == "/dev/null"
    assert environment["GIT_NO_REPLACE_OBJECTS"] == "1"
    assert environment["GIT_NO_LAZY_FETCH"] == "1"

    fake = _fake_executable(
        tmp_path / "fake-git",
        "import os, sys\n"
        f"names = {hostile_names!r}\n"
        "bad = any(name in os.environ for name in names)\n"
        "sys.stdout.buffer.write(b'bad' if bad else b'clean')\n",
    )
    runner = GitCommandRunner(
        git_executable=os.fspath(fake),
        sandbox_mode=GitSandboxMode.DISABLED,
    )
    result = runner.run(
        tmp_path,
        ("rev-parse", "HEAD^{commit}", "HEAD^{tree}"),
        max_stdout_bytes=16,
    )
    assert result.stdout == b"clean"


def test_038_only_fixed_read_only_git_commands_are_admitted() -> None:
    forbidden_commands = (
        "checkout",
        "clean",
        "commit",
        "diff",
        "fetch",
        "reset",
        "status",
        "worktree",
    )
    for forbidden in forbidden_commands:
        with pytest.raises(ValueError, match="read-only allowlist"):
            _assert_read_only_git_command((forbidden,))
    with pytest.raises(ValueError, match="not a read operation"):
        _assert_read_only_git_command(("config", "--local", "--no-includes", "user.name", "x"))
    with pytest.raises(ValueError, match="mutation"):
        _assert_read_only_git_command(
            ("config", "--local", "--no-includes", "--get", "--unset", "core.bare")
        )
    with pytest.raises(ValueError, match="raw cat-file"):
        _assert_read_only_git_command(("cat-file", "--textconv", "HEAD:payload.txt"))


def test_039_ls_tree_parser_is_nul_safe_and_rejects_submodules() -> None:
    first_oid = b"1" * 40
    second_oid = b"2" * 40
    data = (
        b"100644 blob " + first_oid + b"\tline\nname\twith-tab\x00"
        b"120000 blob " + second_oid + b"\tlink\x00"
    )
    entries = _parse_ls_tree(data, limits=Limits())
    assert [entry.path for entry in entries] == [b"line\nname\twith-tab", b"link"]
    assert entries[1].mode == 0o120000

    with pytest.raises(AgentLoopError) as caught:
        _parse_ls_tree(
            b"160000 commit " + first_oid + b"\tvendor\x00",
            limits=Limits(),
        )
    assert caught.value.reason is StopReason.REPOSITORY_SHAPE_UNSUPPORTED


def test_039_cat_file_batch_parser_preserves_binary_and_delimiters() -> None:
    first = "a" * 40
    second = "b" * 40
    binary = b"\x00\n\xffpayload\n"
    link = b"../../literal-target"
    data = (
        f"{first} blob {len(binary)}\n".encode()
        + binary
        + b"\n"
        + f"{second} blob {len(link)}\n".encode()
        + link
        + b"\n"
    )
    parsed = _parse_cat_file_batch(data, (first, second), max_file_bytes=1_024)
    assert parsed == {first: binary, second: link}

    with pytest.raises(AgentLoopError) as caught:
        _parse_cat_file_batch(
            f"{first} missing\n".encode(),
            (first,),
            max_file_bytes=1_024,
        )
    assert caught.value.reason is StopReason.REPOSITORY_SHAPE_UNSUPPORTED


def test_038_bounded_git_output_fails_closed(tmp_path: Path) -> None:
    fake = _fake_executable(
        tmp_path / "loud-git",
        "import sys\nsys.stdout.buffer.write(b'x' * 4096)\n",
    )
    runner = GitCommandRunner(
        git_executable=os.fspath(fake),
        sandbox_mode=GitSandboxMode.DISABLED,
    )
    with pytest.raises(AgentLoopError) as caught:
        runner.run(
            tmp_path,
            ("rev-parse", "HEAD^{commit}", "HEAD^{tree}"),
            max_stdout_bytes=8,
        )
    assert caught.value.reason is StopReason.GIT_POLICY_OR_OUTPUT_FAILURE
    assert "byte limit" in caught.value.detail


class _PostSpawnPipe:
    def __init__(self, descriptor: int) -> None:
        self.descriptor = descriptor
        self.closed = False

    def fileno(self) -> int:
        return self.descriptor

    def close(self) -> None:
        self.closed = True


class _PostSpawnProcess:
    pid = 424_242

    def __init__(self) -> None:
        self.stdin = _PostSpawnPipe(10)
        self.stdout = _PostSpawnPipe(11)
        self.stderr = _PostSpawnPipe(12)
        self.returncode: int | None = None
        self.wait_timeouts: list[float | None] = []
        self.kill_calls = 0

    def wait(self, timeout: float | None = None) -> int:
        self.wait_timeouts.append(timeout)
        self.returncode = -9
        return self.returncode

    def kill(self) -> None:
        self.kill_calls += 1


class _PostSpawnSelector:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


def _inject_post_spawn_setup_error(
    monkeypatch: pytest.MonkeyPatch,
    error: BaseException,
) -> tuple[_PostSpawnProcess, _PostSpawnSelector, list[object]]:
    process = _PostSpawnProcess()
    selector = _PostSpawnSelector()
    terminated: list[object] = []

    def spawn(*_args: object, **_kwargs: object) -> _PostSpawnProcess:
        return process

    def create_selector() -> _PostSpawnSelector:
        return selector

    def fail_setup(_descriptor: int, _blocking: bool) -> None:
        raise error

    def record_termination(spawned: object) -> None:
        terminated.append(spawned)

    monkeypatch.setattr(subprocess, "Popen", spawn)
    monkeypatch.setattr(selectors, "DefaultSelector", create_selector)
    monkeypatch.setattr(os, "set_blocking", fail_setup)
    monkeypatch.setattr(git_source, "_kill_process_group", record_termination)
    return process, selector, terminated


def _run_injected_post_spawn_setup() -> None:
    git_source._bounded_process(
        ("/usr/bin/git", "rev-parse", "HEAD"),
        cwd=None,
        environment={"PATH": "/usr/bin:/bin"},
        stdin_data=b"",
        max_stdout_bytes=1_024,
        max_stderr_bytes=1_024,
        timeout_seconds=1,
    )


def _assert_post_spawn_cleanup(
    process: _PostSpawnProcess,
    selector: _PostSpawnSelector,
    terminated: list[object],
) -> None:
    assert terminated == [process]
    assert process.wait_timeouts == [1]
    assert process.kill_calls == 0
    assert selector.closed
    assert process.stdin.closed
    assert process.stdout.closed
    assert process.stderr.closed


def test_bounded_git_post_spawn_setup_failure_kills_reaps_and_closes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process, selector, terminated = _inject_post_spawn_setup_error(
        monkeypatch,
        OSError("injected post-spawn setup failure"),
    )

    with pytest.raises(OSError, match="injected post-spawn setup failure"):
        _run_injected_post_spawn_setup()

    _assert_post_spawn_cleanup(process, selector, terminated)


def test_bounded_git_post_spawn_setup_interrupt_kills_reaps_and_closes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process, selector, terminated = _inject_post_spawn_setup_error(
        monkeypatch,
        KeyboardInterrupt(),
    )

    with pytest.raises(KeyboardInterrupt):
        _run_injected_post_spawn_setup()

    _assert_post_spawn_cleanup(process, selector, terminated)


def test_039_required_bwrap_is_fail_closed_when_unavailable(tmp_path: Path) -> None:
    runner = GitCommandRunner(
        bwrap_executable=os.fspath(tmp_path / "absent-bwrap"),
        sandbox_mode=GitSandboxMode.REQUIRED,
    )
    with pytest.raises(AgentLoopError) as caught:
        runner.run(tmp_path, ("rev-parse", "HEAD^{commit}", "HEAD^{tree}"))
    assert caught.value.reason is StopReason.SANDBOX_SETUP_FAILURE


class _RecordingGitService:
    def __init__(self, process: BoundedProcessResult) -> None:
        self.process = process
        self.calls: list[dict[str, object]] = []

    def run(
        self,
        command: tuple[str, ...],
        *,
        role: str,
        input_bytes: bytes = b"",
        timeout_seconds: float,
        limits: ServiceLimits | None = None,
    ) -> ServiceResult:
        self.calls.append(
            {
                "command": command,
                "role": role,
                "input_bytes": input_bytes,
                "timeout_seconds": timeout_seconds,
                "limits": limits,
            }
        )
        return ServiceResult(
            "agent-loop-git-fake.service",
            self.process,
            {"ControlGroup": "/user.slice/agent-loop-git-fake.service"},
            "/user.slice/agent-loop-git-fake.service",
            True,
        )


def _service_process(
    *,
    stdout: bytes = b"ok",
    stderr: bytes = b"",
    returncode: int = 0,
) -> BoundedProcessResult:
    return BoundedProcessResult(
        returncode,
        stdout,
        stderr,
        1.0,
        2.0,
        False,
        False,
    )


def test_required_git_bwrap_uses_transient_service_and_hardened_namespaces(
    tmp_path: Path,
) -> None:
    bwrap = _fake_executable(tmp_path / "bwrap", "raise SystemExit(99)\n")
    service = _RecordingGitService(_service_process())
    runner = GitCommandRunner(
        bwrap_executable=os.fspath(bwrap),
        sandbox_mode=GitSandboxMode.REQUIRED,
        timeout_seconds=3.5,
        max_stderr_bytes=17,
        service_runner=service,
    )

    result = runner.run(
        tmp_path,
        ("rev-parse", "HEAD^{commit}", "HEAD^{tree}"),
        stdin_data=b"fixed input",
        max_stdout_bytes=23,
    )

    assert result.stdout == b"ok"
    assert len(service.calls) == 1
    call = service.calls[0]
    command = call["command"]
    assert isinstance(command, tuple)
    for option in (
        "--unshare-net",
        "--unshare-pid",
        "--as-pid-1",
        "--unshare-cgroup",
        "--cap-drop",
        "ALL",
    ):
        assert option in command
    assert call["role"] == "git"
    assert call["input_bytes"] == b"\x00fixed input"
    assert call["timeout_seconds"] == 3.5
    limits = call["limits"]
    assert isinstance(limits, ServiceLimits)
    assert limits.runtime_max_seconds == 4
    assert limits.output_max_bytes == 40


@pytest.mark.parametrize(
    ("stdout", "stderr", "detail"),
    [(b"x" * 9, b"", "stdout"), (b"", b"x" * 9, "stderr")],
)
def test_required_git_service_preserves_separate_stream_caps(
    tmp_path: Path,
    stdout: bytes,
    stderr: bytes,
    detail: str,
) -> None:
    bwrap = _fake_executable(tmp_path / "bwrap", "raise SystemExit(99)\n")
    service = _RecordingGitService(_service_process(stdout=stdout, stderr=stderr))
    runner = GitCommandRunner(
        bwrap_executable=os.fspath(bwrap),
        sandbox_mode=GitSandboxMode.REQUIRED,
        max_stderr_bytes=8,
        service_runner=service,
    )

    with pytest.raises(AgentLoopError) as caught:
        runner.run(
            tmp_path,
            ("rev-parse", "HEAD^{commit}", "HEAD^{tree}"),
            max_stdout_bytes=8,
        )
    assert caught.value.reason is StopReason.GIT_POLICY_OR_OUTPUT_FAILURE
    assert detail in caught.value.detail
    assert len(service.calls) == 1


def test_required_git_service_failure_never_falls_back_to_host_execution(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    bwrap = _fake_executable(tmp_path / "bwrap", "raise SystemExit(99)\n")

    class FailingService:
        def run(self, *_args: object, **_kwargs: object) -> ServiceResult:
            raise fail(
                StopReason.SERVICE_LIFECYCLE_MISMATCH,
                "synthetic service lifecycle failure",
            )

    def forbidden_host_process(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("REQUIRED mode must not execute Git directly on the host")

    monkeypatch.setattr("agent_loop.git_source._bounded_process", forbidden_host_process)
    runner = GitCommandRunner(
        bwrap_executable=os.fspath(bwrap),
        sandbox_mode=GitSandboxMode.REQUIRED,
        service_runner=FailingService(),
    )

    with pytest.raises(AgentLoopError) as caught:
        runner.run(tmp_path, ("rev-parse", "HEAD^{commit}", "HEAD^{tree}"))
    assert caught.value.reason is StopReason.SANDBOX_SETUP_FAILURE
