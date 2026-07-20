import signal

import pytest

from agent_loop.errors import AgentLoopError, StopReason, fail
from agent_loop.service import (
    BoundedProcessInterrupted,
    BoundedProcessStartFailure,
    BoundedProcessResult,
    ServiceLimits,
    TransientServiceRunner,
    _systemd_timespan_usec,
    _verify_properties,
    build_systemd_run_argv,
    run_bounded_process,
)


def test_systemd_argv_contains_exact_lifecycle_contract() -> None:
    argv = build_systemd_run_argv(
        "agent-loop-test-123.service",
        ("/usr/bin/true",),
        ServiceLimits(),
    )
    rendered = "\n".join(argv)
    for value in (
        "--service-type=exec",
        "KillMode=control-group",
        "SendSIGKILL=yes",
        "TimeoutStopSec=5s",
        "OOMPolicy=kill",
        "CollectMode=inactive-or-failed",
        "LimitCORE=0",
    ):
        assert value in rendered
    assert "--expand-environment=no" in argv


def test_service_argv_rejects_shell_and_untrusted_unit_shapes() -> None:
    with pytest.raises(ValueError):
        build_systemd_run_argv("../../bad.service", ("/usr/bin/true",), ServiceLimits())
    with pytest.raises(ValueError):
        build_systemd_run_argv("agent-loop-ok.service", ("true",), ServiceLimits())


def test_observed_service_properties_must_match_selected_resource_limits() -> None:
    limits = ServiceLimits(
        memory_max_bytes=64,
        tasks_max=2,
        runtime_max_seconds=90,
        timeout_stop_seconds=2,
        limit_fsize_bytes=128,
        limit_nofile=16,
        cpu_quota_percent=150,
    )
    properties = {
        "Type": "exec",
        "KillMode": "control-group",
        "SendSIGKILL": "yes",
        "OOMPolicy": "kill",
        "CollectMode": "inactive-or-failed",
        "LimitCORE": "0",
        "MemoryMax": "64",
        "TasksMax": "2",
        "RuntimeMaxUSec": "1min 30s",
        "TimeoutStopUSec": "2s",
        "LimitFSIZE": "128",
        "LimitNOFILE": "16",
        "CPUQuotaPerSecUSec": "1.5s",
    }
    _verify_properties(properties, limits)
    properties["MemoryMax"] = "65"
    with pytest.raises(AgentLoopError, match="property mismatch"):
        _verify_properties(properties, limits)


@pytest.mark.parametrize(
    ("rendered", "expected"),
    [("2s", 2_000_000), ("1.5s", 1_500_000), ("1min 30s", 90_000_000)],
)
def test_systemd_timespan_parser(rendered: str, expected: int) -> None:
    assert _systemd_timespan_usec(rendered) == expected
    assert _systemd_timespan_usec(rendered + " garbage") is None


def _bounded_result(*, output_limited: bool = False) -> BoundedProcessResult:
    return BoundedProcessResult(
        returncode=0,
        stdout=b"partial",
        stderr=b"",
        started_at=1.0,
        completed_at=2.0,
        timed_out=False,
        output_limited=output_limited,
    )


def _install_fake_live_unit(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    killed: list[str] = []
    monkeypatch.setattr(
        "agent_loop.service._wait_for_properties",
        lambda _unit: {"ControlGroup": "/user.slice/fake.service"},
    )
    monkeypatch.setattr("agent_loop.service._verify_properties", lambda *_args: None)
    monkeypatch.setattr(
        "agent_loop.service._kill_unit", lambda unit: killed.append(unit)
    )
    monkeypatch.setattr(
        "agent_loop.service._wait_for_cgroup_empty", lambda *_args, **_kwargs: True
    )
    return killed


def test_output_limit_returns_bounded_prefix_after_forced_unit_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    killed = _install_fake_live_unit(monkeypatch)

    def fake_process(*_args: object, on_started: object, **_kwargs: object) -> object:
        assert callable(on_started)
        on_started(object())
        return _bounded_result(output_limited=True)

    monkeypatch.setattr("agent_loop.service.run_bounded_process", fake_process)
    result = TransientServiceRunner().run(
        ("/usr/bin/true",), role="output", timeout_seconds=1
    )
    assert result.process.output_limited is True
    assert result.process.stdout == b"partial"
    assert len(killed) == 1


def test_property_probe_failure_still_cleans_the_started_unit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    killed = _install_fake_live_unit(monkeypatch)
    original = fail(StopReason.SERVICE_LIFECYCLE_MISMATCH, "property mismatch")
    monkeypatch.setattr(
        "agent_loop.service._verify_properties",
        lambda *_args: (_ for _ in ()).throw(original),
    )

    def fake_process(*_args: object, on_started: object, **_kwargs: object) -> object:
        assert callable(on_started)
        try:
            on_started(object())
        except BaseException as error:
            raise BoundedProcessStartFailure(error, _bounded_result()) from error
        raise AssertionError("property failure should abort the launcher")

    monkeypatch.setattr("agent_loop.service.run_bounded_process", fake_process)
    retained: list[object] = []
    with pytest.raises(AgentLoopError) as captured:
        TransientServiceRunner(result_sink=retained.append).run(
            ("/usr/bin/true",), role="properties", timeout_seconds=1
        )
    assert captured.value is original
    assert len(killed) == 1
    assert len(retained) == 1


def test_interrupt_still_cleans_the_started_unit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    killed = _install_fake_live_unit(monkeypatch)

    retained: list[object] = []

    def fake_process(*_args: object, on_started: object, **_kwargs: object) -> object:
        assert callable(on_started)
        on_started(object())
        raise BoundedProcessInterrupted(_bounded_result())

    monkeypatch.setattr("agent_loop.service.run_bounded_process", fake_process)
    with pytest.raises(KeyboardInterrupt):
        TransientServiceRunner(result_sink=retained.append).run(
            ("/usr/bin/true",), role="interrupt", timeout_seconds=1
        )
    assert len(killed) == 1
    assert len(retained) == 1


def test_cleanup_failure_remains_fatal_when_bounded_output_was_retained(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_live_unit(monkeypatch)
    monkeypatch.setattr(
        "agent_loop.service._wait_for_cgroup_empty", lambda *_args, **_kwargs: False
    )

    def fake_process(*_args: object, on_started: object, **_kwargs: object) -> object:
        assert callable(on_started)
        on_started(object())
        return _bounded_result(output_limited=True)

    monkeypatch.setattr("agent_loop.service.run_bounded_process", fake_process)
    retained: list[object] = []
    with pytest.raises(AgentLoopError) as captured:
        TransientServiceRunner(result_sink=retained.append).run(
            ("/usr/bin/true",), role="secondary", timeout_seconds=1
        )
    assert captured.value.reason is StopReason.SERVICE_LIFECYCLE_MISMATCH
    assert len(retained) == 1


@pytest.mark.parametrize(
    ("sleep_seconds", "timeout_seconds", "expected_timeout", "expected_returncode"),
    (
        (1.1, 2.0, False, 0),
        (5.0, 0.1, True, -15),
    ),
)
def test_bounded_process_waits_for_stdio_closed_child_or_reports_real_timeout(
    sleep_seconds: float,
    timeout_seconds: float,
    expected_timeout: bool,
    expected_returncode: int,
) -> None:
    program = (
        "import os,time;"
        "os.close(0);os.close(1);os.close(2);"
        f"time.sleep({sleep_seconds!r})"
    )
    result = run_bounded_process(
        ("/usr/bin/python3", "-c", program),
        timeout_seconds=timeout_seconds,
        output_max_bytes=1024,
        env={"PATH": "/usr/bin:/bin"},
    )

    assert result.timed_out is expected_timeout
    assert result.returncode == expected_returncode


def test_post_spawn_stdio_setup_failure_reaps_child_and_carries_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_setup(_fd: int, _blocking: bool) -> None:
        raise OSError("injected post-spawn setup failure")

    monkeypatch.setattr("agent_loop.service.os.set_blocking", fail_setup)
    with pytest.raises(BoundedProcessStartFailure) as caught:
        run_bounded_process(
            ("/usr/bin/sleep", "10"),
            timeout_seconds=1,
            output_max_bytes=1024,
            env={"PATH": "/usr/bin:/bin"},
        )

    assert isinstance(caught.value.error, OSError)
    assert caught.value.result.returncode < 0
    assert caught.value.result.stdout == b""
    assert caught.value.result.stderr == b""


def test_post_spawn_setup_interrupt_reaps_child_and_carries_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def interrupt_setup(_fd: int, _blocking: bool) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr("agent_loop.service.os.set_blocking", interrupt_setup)
    with pytest.raises(BoundedProcessInterrupted) as caught:
        run_bounded_process(
            ("/usr/bin/sleep", "10"),
            timeout_seconds=1,
            output_max_bytes=1024,
            env={"PATH": "/usr/bin:/bin"},
        )

    assert caught.value.result.returncode < 0
    assert caught.value.result.stdout == b""
    assert caught.value.result.stderr == b""


def test_property_probe_interrupt_kills_unit_and_reaps_launcher(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakePipe:
        closed = False

        def close(self) -> None:
            self.closed = True

    class FakeProcess:
        def __init__(self) -> None:
            self.pid = 4242
            self.stdout = FakePipe()
            self.stderr = FakePipe()
            self.returncode: int | None = None
            self.waited = False

        def poll(self) -> int | None:
            return self.returncode

        def wait(self, *, timeout: float) -> int:
            assert timeout == 2
            self.waited = True
            self.returncode = -9
            return self.returncode

    process = FakeProcess()
    killed_units: list[str] = []
    killed_groups: list[tuple[int, object]] = []
    monkeypatch.setattr(
        "agent_loop.service.subprocess.Popen",
        lambda *_args, **_kwargs: process,
    )
    monkeypatch.setattr(
        "agent_loop.service._wait_for_properties",
        lambda _unit: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    monkeypatch.setattr(
        "agent_loop.service._kill_unit",
        lambda unit: killed_units.append(unit),
    )
    monkeypatch.setattr(
        "agent_loop.service.os.killpg",
        lambda pid, selected_signal: killed_groups.append((pid, selected_signal)),
    )

    with pytest.raises(KeyboardInterrupt):
        TransientServiceRunner().probe()

    assert len(killed_units) == 1
    assert killed_groups == [(process.pid, signal.SIGKILL)]
    assert process.waited is True
    assert process.stdout.closed is True
    assert process.stderr.closed is True
