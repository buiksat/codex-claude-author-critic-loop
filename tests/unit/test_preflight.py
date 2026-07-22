from __future__ import annotations

import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent_loop.errors import AgentLoopError, StopReason
from agent_loop.preflight import _run_small_in_service, inspect_trusted_executable
from agent_loop.service import (
    BoundedProcessResult,
    ServiceLimits,
    ServiceResult,
    TransientServiceRunner,
)


def _executable(path: Path) -> None:
    path.write_text("#!/bin/sh\nprintf 'safe-version\\n'\n", encoding="ascii")
    path.chmod(0o700)


def test_fast_service_version_probe_uses_inspection_gate() -> None:
    class RecordingRunner:
        def __init__(self) -> None:
            self.command: tuple[str, ...] = ()
            self.input_bytes = b""

        def run(
            self,
            command: tuple[str, ...],
            *,
            role: str,
            input_bytes: bytes,
            timeout_seconds: float,
            limits: ServiceLimits,
        ) -> ServiceResult:
            assert role == "trusted-executable-version"
            assert timeout_seconds == 15
            assert limits.runtime_max_seconds == 15
            self.command = command
            self.input_bytes = input_bytes
            process = BoundedProcessResult(0, b"fast-version\n", b"", 1, 2, False, False)
            return ServiceResult("agent-loop-test.service", process, {}, "/test", True)

    runner = RecordingRunner()
    output = _run_small_in_service(
        ("/opt/reviewed/tool", "--version"),
        runner,  # type: ignore[arg-type]
    )

    assert output == b"fast-version\n"
    assert runner.input_bytes == b"\x00"
    assert runner.command[:5] == ("/usr/bin/python3", "-I", "-B", "-S", "-c")
    assert runner.command[6:8] == ("/usr/bin/env", "-i")
    assert runner.command[-2:] == ("/opt/reviewed/tool", "--version")


def test_trusted_executable_rejects_setid_mode(tmp_path: Path) -> None:
    executable = tmp_path / "tool"
    _executable(executable)
    executable.chmod(0o700 | stat.S_ISUID)

    with pytest.raises(AgentLoopError) as caught:
        inspect_trusted_executable(
            os.fspath(executable),
            version_argv=(os.fspath(executable), "--version"),
        )
    assert caught.value.reason is StopReason.SANDBOX_SETUP_FAILURE


def test_trusted_executable_rejects_extended_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "tool"
    _executable(executable)

    monkeypatch.setattr(
        "agent_loop.preflight.reject_extended_metadata_fd",
        lambda _descriptor: (_ for _ in ()).throw(ValueError("extended metadata")),
    )
    with pytest.raises(AgentLoopError) as caught:
        inspect_trusted_executable(
            os.fspath(executable),
            version_argv=(os.fspath(executable), "--version"),
        )
    assert caught.value.reason is StopReason.SANDBOX_SETUP_FAILURE


def test_trusted_executable_rejects_hard_links(tmp_path: Path) -> None:
    executable = tmp_path / "tool"
    _executable(executable)
    os.link(executable, tmp_path / "second-name")

    with pytest.raises(AgentLoopError) as caught:
        inspect_trusted_executable(
            os.fspath(executable),
            version_argv=(os.fspath(executable), "--version"),
        )
    assert caught.value.reason is StopReason.SANDBOX_SETUP_FAILURE


def test_trusted_executable_rejects_group_write_for_foreign_supplemental_member(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "tool"
    _executable(executable)
    executable.chmod(0o720)
    current = SimpleNamespace(
        pw_name="effective-user",
        pw_uid=os.geteuid(),
        pw_gid=os.getegid(),
    )
    foreign = SimpleNamespace(
        pw_name="foreign-user",
        pw_uid=os.geteuid() + 1,
        pw_gid=os.getegid() + 1,
    )
    monkeypatch.setattr(
        "agent_loop.provenance.grp.getgrgid",
        lambda _group_id: SimpleNamespace(gr_mem=(foreign.pw_name,)),
    )
    monkeypatch.setattr(
        "agent_loop.provenance.pwd.getpwall",
        lambda: [current, foreign],
    )

    with pytest.raises(AgentLoopError) as caught:
        inspect_trusted_executable(
            os.fspath(executable),
            version_argv=(os.fspath(executable), "--version"),
        )
    assert caught.value.reason is StopReason.SANDBOX_SETUP_FAILURE


def test_trusted_executable_allows_group_write_for_genuinely_private_group(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "tool"
    _executable(executable)
    executable.chmod(0o720)
    current = SimpleNamespace(
        pw_name="effective-user",
        pw_uid=os.geteuid(),
        pw_gid=os.getegid(),
    )
    monkeypatch.setattr(
        "agent_loop.provenance.grp.getgrgid",
        lambda _group_id: SimpleNamespace(gr_mem=(current.pw_name,)),
    )
    monkeypatch.setattr(
        "agent_loop.provenance.pwd.getpwall",
        lambda: [current],
    )

    inspected = inspect_trusted_executable(
        os.fspath(executable),
        version_argv=(os.fspath(executable), "--version"),
    )

    assert inspected.mode == 0o720
    assert inspected.version == "safe-version"


def test_trusted_executable_rejects_change_during_version_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "tool"
    _executable(executable)

    def mutate(_argv: tuple[str, ...], *, env: dict[str, str] | None = None) -> bytes:
        del env
        executable.write_text("#!/bin/sh\nprintf 'changed-version\\n'\n", encoding="ascii")
        executable.chmod(0o700)
        return b"safe-version\n"

    monkeypatch.setattr("agent_loop.preflight._run_small", mutate)
    with pytest.raises(AgentLoopError) as caught:
        inspect_trusted_executable(
            os.fspath(executable),
            version_argv=(os.fspath(executable), "--version"),
        )
    assert caught.value.reason is StopReason.SANDBOX_SETUP_FAILURE


def test_user_tool_version_probe_routes_through_supplied_service_runner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "tool"
    _executable(executable)
    runner = TransientServiceRunner()
    observed: list[tuple[tuple[str, ...], TransientServiceRunner]] = []

    def contained(
        argv: tuple[str, ...],
        selected_runner: TransientServiceRunner,
        *,
        env: dict[str, str] | None = None,
    ) -> bytes:
        assert env is None
        observed.append((argv, selected_runner))
        return b"safe-version\n"

    monkeypatch.setattr("agent_loop.preflight._run_small_in_service", contained)
    inspected = inspect_trusted_executable(
        os.fspath(executable),
        version_argv=(os.fspath(executable), "--version"),
        service_runner=runner,
    )

    assert inspected.version == "safe-version"
    assert len(observed) == 1
    argv, selected = observed[0]
    assert selected is runner
    assert argv[:3] == ("/usr/bin/env", "-a", os.fspath(executable))
    assert argv[3].startswith(f"/proc/{os.getpid()}/fd/")
    assert argv[4:] == ("--version",)
