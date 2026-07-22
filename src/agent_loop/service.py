"""Bounded transient-systemd service lifecycle and cgroup verification."""

from __future__ import annotations

import os
import re
import selectors
import signal
import subprocess
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import IO, cast

from .constants import (
    DEFAULT_LIMIT_FSIZE_BYTES,
    DEFAULT_LIMIT_NOFILE,
    DEFAULT_MAX_AGENT_OUTPUT_BYTES,
    DEFAULT_MEMORY_MAX_BYTES,
    DEFAULT_STOP_TIMEOUT_SECONDS,
    DEFAULT_TASKS_MAX,
)
from .errors import AgentLoopError, StopReason, fail

_UNIT_NAME = re.compile(r"^agent-loop-[a-z0-9-]{1,96}\.service$")
_LIFECYCLE_PROPERTIES = {
    "Type": "exec",
    "KillMode": "control-group",
    "SendSIGKILL": "yes",
    "OOMPolicy": "kill",
    "CollectMode": "inactive-or-failed",
    "LimitCORE": "0",
}


@dataclass(frozen=True, slots=True)
class ServiceLimits:
    memory_max_bytes: int = DEFAULT_MEMORY_MAX_BYTES
    tasks_max: int = DEFAULT_TASKS_MAX
    runtime_max_seconds: int = 15 * 60
    timeout_stop_seconds: int = DEFAULT_STOP_TIMEOUT_SECONDS
    limit_fsize_bytes: int = DEFAULT_LIMIT_FSIZE_BYTES
    limit_nofile: int = DEFAULT_LIMIT_NOFILE
    cpu_quota_percent: int = 200
    output_max_bytes: int = DEFAULT_MAX_AGENT_OUTPUT_BYTES

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")

    def properties(self) -> tuple[str, ...]:
        return (
            "KillMode=control-group",
            "SendSIGKILL=yes",
            f"TimeoutStopSec={self.timeout_stop_seconds}s",
            "OOMPolicy=kill",
            "CollectMode=inactive-or-failed",
            f"MemoryMax={self.memory_max_bytes}",
            f"TasksMax={self.tasks_max}",
            f"RuntimeMaxSec={self.runtime_max_seconds}s",
            f"LimitFSIZE={self.limit_fsize_bytes}",
            f"LimitNOFILE={self.limit_nofile}",
            "LimitCORE=0",
            f"CPUQuota={self.cpu_quota_percent}%",
        )


@dataclass(frozen=True, slots=True)
class BoundedProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    started_at: float
    completed_at: float
    timed_out: bool
    output_limited: bool


class BoundedProcessInterrupted(KeyboardInterrupt):
    """Operator interruption carrying the already-bounded process prefix."""

    def __init__(self, result: BoundedProcessResult) -> None:
        super().__init__()
        self.result = result


class BoundedProcessStartFailure(Exception):
    """A post-spawn operation failed, with bounded launch metadata attached."""

    def __init__(self, error: BaseException, result: BoundedProcessResult) -> None:
        super().__init__(type(error).__name__)
        self.error = error
        self.result = result


@dataclass(frozen=True, slots=True)
class ServiceResult:
    unit_name: str
    process: BoundedProcessResult
    observed_properties: dict[str, str]
    control_group: str | None
    cgroup_empty: bool


ServiceResultSink = Callable[[ServiceResult], None]


def service_environment() -> dict[str, str]:
    """Small environment sufficient to contact the current user manager."""

    return {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "SYSTEMD_COLORS": "0",
        "TERM": "dumb",
        "XDG_RUNTIME_DIR": f"/run/user/{os.getuid()}",
    }


def new_unit_name(role: str) -> str:
    normalized = re.sub(r"[^a-z0-9-]", "-", role.lower()).strip("-")[:32]
    if not normalized:
        raise ValueError("service role has no safe unit-name characters")
    return f"agent-loop-{normalized}-{uuid.uuid4().hex}.service"


def build_systemd_run_argv(
    unit_name: str,
    command: tuple[str, ...],
    limits: ServiceLimits,
) -> tuple[str, ...]:
    if _UNIT_NAME.fullmatch(unit_name) is None:
        raise ValueError("invalid runner-owned transient unit name")
    if not command or not all(
        isinstance(item, str) and item and "\x00" not in item for item in command
    ):
        raise ValueError("service command must be a non-empty NUL-free argv")
    if not os.path.isabs(command[0]):
        raise ValueError("service executable must be an absolute reviewed path")
    argv = [
        "/usr/bin/systemd-run",
        "--user",
        "--wait",
        "--collect",
        "--pipe",
        "--quiet",
        "--expand-environment=no",
        "--service-type=exec",
        f"--unit={unit_name}",
    ]
    argv.extend(f"--property={value}" for value in limits.properties())
    argv.append("--")
    argv.extend(command)
    return tuple(argv)


def run_bounded_process(
    argv: tuple[str, ...],
    *,
    input_bytes: bytes = b"",
    timeout_seconds: float,
    output_max_bytes: int,
    env: dict[str, str],
    on_abort: Callable[[], None] | None = None,
    on_started: Callable[[subprocess.Popen[bytes]], None] | None = None,
) -> BoundedProcessResult:
    """Stream stdin/stdout/stderr without `communicate`'s unbounded buffering."""

    if timeout_seconds <= 0 or output_max_bytes <= 0:
        raise ValueError("process timeout and output cap must be positive")
    started = time.monotonic()
    stdout = bytearray()
    stderr = bytearray()
    deadline = started + timeout_seconds
    timed_out = False
    output_limited = False
    aborted = False
    abort_started_at: float | None = None
    primary_error: BaseException | None = None
    cleanup_errors: list[BaseException] = []
    selector: selectors.BaseSelector | None = None
    process: subprocess.Popen[bytes] | None = None

    def abort() -> None:
        nonlocal aborted, abort_started_at
        if process is None:
            return
        if aborted:
            return
        aborted = True
        abort_started_at = time.monotonic()
        callback_error: BaseException | None = None
        if on_abort is not None:
            try:
                on_abort()
            except BaseException as error:
                callback_error = error
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        if callback_error is not None:
            raise callback_error

    try:
        # Establish the cleanup guard before launching.  A KeyboardInterrupt,
        # allocation failure, or injected setup error at any later bytecode
        # boundary must not strand a successfully spawned process group.
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            close_fds=True,
            start_new_session=True,
        )
        if on_started is not None:
            on_started(process)
        if process.stdin is None or process.stdout is None or process.stderr is None:
            raise RuntimeError("spawned process has no configured standard streams")
        for stream in (process.stdin, process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        input_view = memoryview(input_bytes)
        input_offset = 0
        if input_view:
            selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
        else:
            process.stdin.close()
        while selector.get_map() or process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                abort()
                remaining = 0.1
            events = selector.select(min(max(remaining, 0.0), 0.1)) if selector.get_map() else ()
            if not events and not selector.get_map() and process.poll() is None:
                time.sleep(min(max(remaining, 0.0), 0.05))
            for key, mask in events:
                stream = cast(IO[bytes], key.fileobj)
                if key.data == "stdin" and mask & selectors.EVENT_WRITE:
                    try:
                        written = os.write(
                            stream.fileno(), input_view[input_offset : input_offset + 65536]
                        )
                    except BrokenPipeError:
                        written = 0
                        input_offset = len(input_view)
                    input_offset += written
                    if input_offset >= len(input_view):
                        selector.unregister(stream)
                        stream.close()
                elif mask & selectors.EVENT_READ:
                    try:
                        chunk = os.read(stream.fileno(), 65536)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(stream)
                        stream.close()
                        continue
                    target = stdout if key.data == "stdout" else stderr
                    remaining_output = output_max_bytes - len(stdout) - len(stderr)
                    if len(chunk) > remaining_output:
                        if remaining_output > 0:
                            target.extend(chunk[:remaining_output])
                        output_limited = True
                        abort()
                    else:
                        target.extend(chunk)
            if (
                aborted
                and abort_started_at is not None
                and process.poll() is None
                and time.monotonic() > abort_started_at + 1.0
            ):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if process.poll() is not None and all(
                key.data == "stdin" for key in selector.get_map().values()
            ):
                for key in list(selector.get_map().values()):
                    registered_stream = cast(IO[bytes], key.fileobj)
                    selector.unregister(registered_stream)
                    registered_stream.close()
    except BaseException as error:
        if process is None:
            raise
        primary_error = error
        try:
            abort()
        except BaseException as cleanup_error:
            cleanup_errors.append(cleanup_error)
    finally:
        if selector is not None:
            try:
                selector.close()
            except BaseException as cleanup_error:
                cleanup_errors.append(cleanup_error)
        if process is not None:
            for process_stream in (process.stdin, process.stdout, process.stderr):
                if process_stream is not None and not process_stream.closed:
                    try:
                        process_stream.close()
                    except BaseException as cleanup_error:
                        cleanup_errors.append(cleanup_error)

    assert process is not None
    try:
        returncode = process.wait(timeout=1)
    except BaseException as wait_error:
        if not isinstance(wait_error, subprocess.TimeoutExpired) and primary_error is None:
            primary_error = wait_error
        try:
            abort()
        except BaseException as cleanup_error:
            cleanup_errors.append(cleanup_error)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            returncode = process.wait(timeout=2)
        except BaseException as reap_error:
            if primary_error is None:
                primary_error = reap_error
            else:
                cleanup_errors.append(reap_error)
            returncode = (
                process.returncode if isinstance(process.returncode, int) else -int(signal.SIGKILL)
            )
    result = BoundedProcessResult(
        returncode=returncode,
        stdout=bytes(stdout),
        stderr=bytes(stderr),
        started_at=started,
        completed_at=time.monotonic(),
        timed_out=timed_out,
        output_limited=output_limited,
    )
    if primary_error is None and cleanup_errors:
        primary_error = cleanup_errors.pop(0)
    for cleanup_failure in cleanup_errors:
        if primary_error is not None:
            primary_error.add_note(
                f"post-spawn cleanup also failed: {type(cleanup_failure).__name__}"
            )
    if isinstance(primary_error, KeyboardInterrupt):
        raise BoundedProcessInterrupted(result)
    if primary_error is not None:
        raise BoundedProcessStartFailure(primary_error, result) from primary_error
    return result


def _systemctl(*args: str, timeout: float = 3.0) -> BoundedProcessResult:
    return run_bounded_process(
        ("/usr/bin/systemctl", "--user", *args),
        input_bytes=b"",
        timeout_seconds=timeout,
        output_max_bytes=128 * 1024,
        env=service_environment(),
    )


def _read_properties(unit_name: str) -> dict[str, str]:
    names = (
        "Type",
        "KillMode",
        "SendSIGKILL",
        "TimeoutStopUSec",
        "OOMPolicy",
        "CollectMode",
        "MemoryMax",
        "TasksMax",
        "RuntimeMaxUSec",
        "LimitFSIZE",
        "LimitNOFILE",
        "LimitCORE",
        "CPUQuotaPerSecUSec",
        "ControlGroup",
        "LoadState",
        "MainPID",
        "ActiveState",
        "SubState",
    )
    result = _systemctl("show", unit_name, *(f"--property={name}" for name in names))
    if (
        result.returncode != 0
        or result.timed_out
        or result.output_limited
        or len(result.stdout) > 64 * 1024
    ):
        return {}
    properties: dict[str, str] = {}
    for line in result.stdout.decode("utf-8", "strict").splitlines():
        if "=" in line:
            name, value = line.split("=", 1)
            properties[name] = value
    return properties


def _wait_for_properties(unit_name: str, timeout_seconds: float = 3.0) -> dict[str, str]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        properties = _read_properties(unit_name)
        if (
            properties.get("LoadState") == "loaded"
            and properties.get("ControlGroup", "").startswith("/")
            and properties.get("ActiveState") in {"activating", "active", "deactivating"}
        ):
            return properties
        time.sleep(0.02)
    return {}


_SYSTEMD_TIMESPAN = re.compile(r"([0-9]+(?:\.[0-9]+)?)(us|ms|s|min|h|d)")
_TIMESPAN_MULTIPLIER = {
    "us": Decimal(1),
    "ms": Decimal(1_000),
    "s": Decimal(1_000_000),
    "min": Decimal(60_000_000),
    "h": Decimal(3_600_000_000),
    "d": Decimal(86_400_000_000),
}


def _systemd_timespan_usec(value: str) -> int | None:
    """Parse the bounded normalized timespans returned by `systemctl show`."""

    position = 0
    total = Decimal(0)
    try:
        for match in _SYSTEMD_TIMESPAN.finditer(value):
            if value[position : match.start()].strip():
                return None
            total += Decimal(match.group(1)) * _TIMESPAN_MULTIPLIER[match.group(2)]
            position = match.end()
    except InvalidOperation, OverflowError:
        return None
    if position == 0 or value[position:].strip() or total != total.to_integral_value():
        return None
    result = int(total)
    return result if result >= 0 else None


def _verify_properties(properties: dict[str, str], limits: ServiceLimits) -> None:
    if not properties:
        raise fail(StopReason.SERVICE_LIFECYCLE_MISMATCH, "could not inspect transient unit")
    expected_exact = {
        **_LIFECYCLE_PROPERTIES,
        "MemoryMax": str(limits.memory_max_bytes),
        "TasksMax": str(limits.tasks_max),
        "LimitFSIZE": str(limits.limit_fsize_bytes),
        "LimitNOFILE": str(limits.limit_nofile),
    }
    mismatches: dict[str, tuple[object, object]] = {
        key: (expected, properties.get(key))
        for key, expected in expected_exact.items()
        if properties.get(key) != expected
    }
    expected_times = {
        "TimeoutStopUSec": limits.timeout_stop_seconds * 1_000_000,
        "RuntimeMaxUSec": limits.runtime_max_seconds * 1_000_000,
        "CPUQuotaPerSecUSec": limits.cpu_quota_percent * 10_000,
    }
    for key, expected in expected_times.items():
        observed = properties.get(key)
        parsed = None if observed is None else _systemd_timespan_usec(observed)
        if parsed != expected:
            mismatches[key] = (expected, observed)
    if mismatches:
        raise fail(
            StopReason.SERVICE_LIFECYCLE_MISMATCH,
            f"transient unit property mismatch: {mismatches!r}",
        )


def _kill_unit(unit_name: str) -> None:
    _systemctl("kill", "--kill-whom=all", "--signal=TERM", unit_name)
    time.sleep(0.05)
    _systemctl("kill", "--kill-whom=all", "--signal=KILL", unit_name)


def _cgroup_is_empty(control_group: str | None) -> bool:
    if not control_group or not control_group.startswith("/") or ".." in control_group.split("/"):
        return False
    path = Path("/sys/fs/cgroup") / control_group.lstrip("/")
    try:
        procs = (path / "cgroup.procs").read_bytes()
        events = (path / "cgroup.events").read_text(encoding="ascii")
    except FileNotFoundError:
        return True  # a collected cgroup cannot retain processes
    except OSError:
        return False
    populated = dict(
        line.split(maxsplit=1) for line in events.splitlines() if len(line.split(maxsplit=1)) == 2
    ).get("populated")
    return not procs.strip() and populated == "0"


def _wait_for_cgroup_empty(control_group: str | None, *, timeout_seconds: float) -> bool:
    """Wait for the observed service cgroup to empty or be collected."""

    if not control_group or timeout_seconds <= 0:
        return False
    deadline = time.monotonic() + timeout_seconds
    while True:
        if _cgroup_is_empty(control_group):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.02)


class TransientServiceRunner:
    """Launch one reviewed absolute argv under the exact transient-unit contract."""

    def __init__(self, *, result_sink: ServiceResultSink | None = None) -> None:
        if result_sink is not None and not callable(result_sink):
            raise TypeError("result_sink must be callable")
        self._result_sink = result_sink

    def run(
        self,
        command: tuple[str, ...],
        *,
        role: str,
        input_bytes: bytes = b"",
        timeout_seconds: float,
        limits: ServiceLimits | None = None,
    ) -> ServiceResult:
        selected = limits or ServiceLimits(runtime_max_seconds=max(1, int(timeout_seconds)))
        unit_name = new_unit_name(role)
        argv = build_systemd_run_argv(unit_name, command, selected)
        observed: dict[str, str] = {}
        control_group: str | None = None
        launcher_started = False
        process: BoundedProcessResult | None = None
        primary_error: BaseException | None = None
        cleanup_error: AgentLoopError | None = None
        abort_cleanup_error: Exception | None = None
        cgroup_empty = False

        # The service waits for stdin in sandbox uses; for short probes the
        # property query may race, so the host test supplies a bounded sleep.
        def capture_or_kill() -> None:
            nonlocal abort_cleanup_error
            try:
                _kill_unit(unit_name)
            except Exception as exc:
                # The lifecycle-finally path below retries cleanup and makes
                # the observed cgroup, rather than this command, authoritative.
                abort_cleanup_error = exc

        def inspect_live(_process: subprocess.Popen[bytes]) -> None:
            nonlocal observed, control_group, launcher_started
            launcher_started = True
            observed = _wait_for_properties(unit_name)
            control_group = observed.get("ControlGroup") or None
            _verify_properties(observed, selected)

        try:
            process = run_bounded_process(
                argv,
                input_bytes=input_bytes,
                timeout_seconds=timeout_seconds + selected.timeout_stop_seconds + 3,
                output_max_bytes=selected.output_max_bytes,
                env=service_environment(),
                on_abort=capture_or_kill,
                on_started=inspect_live,
            )
        except BoundedProcessInterrupted as exc:
            process = exc.result
            primary_error = exc
        except BoundedProcessStartFailure as exc:
            process = exc.result
            primary_error = exc.error
        except BaseException as exc:
            primary_error = exc
        finally:
            if launcher_started:
                try:
                    _kill_unit(unit_name)
                except Exception as exc:
                    cleanup_error = fail(
                        StopReason.SERVICE_LIFECYCLE_MISMATCH,
                        f"transient service unit cleanup command failed: {type(exc).__name__}",
                    )

                if control_group is None:
                    try:
                        final_properties = _read_properties(unit_name)
                    except OSError, subprocess.SubprocessError, UnicodeDecodeError:
                        final_properties = {}
                    control_group = final_properties.get("ControlGroup") or None

                cgroup_empty = _wait_for_cgroup_empty(
                    control_group,
                    timeout_seconds=selected.timeout_stop_seconds + 2,
                )
                if not cgroup_empty:
                    command_detail = (
                        " after an earlier cleanup command failure"
                        if abort_cleanup_error is not None
                        else ""
                    )
                    cleanup_error = fail(
                        StopReason.SERVICE_LIFECYCLE_MISMATCH,
                        "transient service cgroup emptiness could not be proven after cleanup"
                        + command_detail,
                    )
            else:
                cgroup_empty = False

        result = (
            None
            if process is None
            else ServiceResult(
                unit_name=unit_name,
                process=process,
                observed_properties=observed,
                control_group=control_group,
                cgroup_empty=cgroup_empty,
            )
        )
        sink_error: BaseException | None = None
        if result is not None and self._result_sink is not None:
            try:
                self._result_sink(result)
            except BaseException as exc:
                sink_error = exc
        if primary_error is None and sink_error is not None:
            primary_error = sink_error
        elif primary_error is not None and sink_error is not None:
            primary_error.add_note(
                f"service result retention also failed: {type(sink_error).__name__}"
            )
        if primary_error is not None:
            if cleanup_error is not None:
                primary_error.add_note(str(cleanup_error))
            raise primary_error
        if cleanup_error is not None:
            raise cleanup_error
        if result is None:
            raise fail(
                StopReason.SERVICE_LIFECYCLE_MISMATCH,
                "transient service launcher returned no process result",
            )
        return result

    def probe(self, *, limits: ServiceLimits | None = None) -> dict[str, str]:
        """Instantiate a live service, inspect exact properties, then clean it."""

        selected = limits or ServiceLimits(runtime_max_seconds=30)
        unit_name = new_unit_name("property-probe")
        command = ("/usr/bin/sleep", "2")
        argv = build_systemd_run_argv(unit_name, command, selected)
        process: subprocess.Popen[bytes] | None = None
        try:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=service_environment(),
                close_fds=True,
                start_new_session=True,
            )
            properties = _wait_for_properties(unit_name)
            _verify_properties(properties, selected)
            control_group = properties.get("ControlGroup")
            _kill_unit(unit_name)
            try:
                process.wait(timeout=selected.timeout_stop_seconds + 3)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=2)
            deadline = time.monotonic() + selected.timeout_stop_seconds + 2
            while time.monotonic() < deadline and not _cgroup_is_empty(control_group):
                time.sleep(0.02)
            if not _cgroup_is_empty(control_group):
                raise fail(
                    StopReason.SERVICE_LIFECYCLE_MISMATCH,
                    "transient service cgroup was not empty after forced cleanup",
                )
            return properties
        finally:
            try:
                # The runner-owned unit name is available even if interruption
                # lands immediately as Popen returns but before its object is
                # assigned locally.
                _kill_unit(unit_name)
            finally:
                if process is not None:
                    try:
                        if process.poll() is None:
                            try:
                                os.killpg(process.pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                        process.wait(timeout=2)
                    finally:
                        if process.stdout is not None:
                            process.stdout.close()
                        if process.stderr is not None:
                            process.stderr.close()
