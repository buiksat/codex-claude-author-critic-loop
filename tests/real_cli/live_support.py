"""Shared opt-in live-CLI gates which never consult ambient credentials."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol

import pytest

from agent_loop.capabilities import (
    CAPABILITY_RECEIPT_RELATIVE_PATH,
    REQUIRED_ACCEPTANCE_GATES,
    LiveCapabilityBinding,
    write_successful_live_capability_receipt,
)
from agent_loop.constants import SUPPORTED_CODEX_VERSION
from agent_loop.preflight import run_preflight
from agent_loop.provenance import (
    closure_sha256,
    installed_runtime_closure_sha256,
    verify_safe_ancestors,
)
from agent_loop.sandbox import SandboxMount
from agent_loop.sandbox_init import SandboxRequest, SandboxResult, parse_request, parse_response
from agent_loop.service import ServiceLimits, ServiceResult, TransientServiceRunner

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_REQUIRED_GATE_NODEIDS = frozenset(
    {
        "tests/host/test_network_boundary.py::test_008_network_split_for_no_network_role",
        "tests/host/test_platform.py::test_011_patched_bubblewrap",
        "tests/host/test_sandbox.py::test_009_full_tmpfs_is_exported_only_after_cleanup",
        (
            "tests/host/test_sandbox.py::"
            "test_009_sandbox_init_is_pid_one_and_workspace_has_no_host_backing"
        ),
        "tests/host/test_service.py::test_071_transient_service_lifecycle",
        (
            "tests/host/test_service_cleanup.py::"
            "test_029_sets_id_orphan_is_reaped_before_export_and_cgroup_collection"
        ),
        (
            "tests/host/test_service_cleanup.py::"
            "test_029_timeout_kills_new_session_and_service_cgroup_is_empty"
        ),
        (
            "tests/real_cli/test_live_codex_acceptance.py::"
            "test_033_065_066_live_profile_gitless_exact_resume_and_marker_isolation"
        ),
        (
            "tests/real_cli/test_live_claude_managed_boundary.py::"
            "test_049_live_managed_claude_child_is_scrubbed_confined_and_attested"
        ),
        *(
            "tests/host/test_limits.py::" + name
            for name in (
                "test_010_primary_output_limit_stops_process_and_still_proves_cleanup",
                "test_010_max_files_fails_closed_without_candidate_export",
                "test_010_tmpfs_byte_ceiling_is_a_real_enospc_boundary",
                "test_010_limit_nofile_is_inherited_and_fails_closed",
                "test_010_limit_fsize_stops_an_oversized_write",
                "test_010_tasks_max_rejects_forks_and_cleanup_still_completes",
                "test_010_runtime_max_terminates_the_whole_service",
                "test_010_memory_max_cgroup_file_caps_stressed_workload",
            )
        ),
        *(
            "tests/host/test_process_isolation.py::" + name
            for name in (
                "test_030_proc_parent_environment_descriptors_and_memory_are_denied",
                "test_030_ptrace_process_vm_and_pidfd_getfd_are_denied",
                "test_030_no_inherited_descriptors_core_or_ambient_credentials",
                "test_030_untrusted_child_cannot_introspect_trusted_primary_parent",
            )
        ),
    }
)
_REPORT_PHASES = frozenset({"setup", "call", "teardown"})
_RECEIPT_VALUE_NAMES = (
    "AGENT_LOOP_STATE_HOME",
    "AGENT_LOOP_CODEX_CREDENTIAL_ID",
    "AGENT_LOOP_CLAUDE_CREDENTIAL_ID",
    "AGENT_LOOP_CODEX_MODEL",
    "AGENT_LOOP_CODEX_EFFORT",
    "AGENT_LOOP_CLAUDE_MODEL",
    "AGENT_LOOP_CLAUDE_EFFORT",
    "AGENT_LOOP_CODEX_INSTALL_ROOT",
    "AGENT_LOOP_CODEX_INSTALL_RELATIVE",
    "AGENT_LOOP_CLAUDE_INSTALL_ROOT",
    "AGENT_LOOP_CLAUDE_INSTALL_RELATIVE",
)

_OBSERVED_VALUES: dict[str, str] = {}


class LiveGateConfigurationError(ValueError):
    """An explicit live-gate selector is absent, unsafe, or changed mid-session."""


class ReportLike(Protocol):
    nodeid: str
    when: str
    outcome: str


def _checked_value(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise LiveGateConfigurationError(
            f"{name} is required when its live acceptance probe is enabled"
        )
    previous = _OBSERVED_VALUES.setdefault(name, value)
    if previous != value:
        raise LiveGateConfigurationError(f"{name} changed during the live acceptance session")
    return value


def _checked_identifier(name: str) -> str:
    value = _checked_value(name)
    if _IDENTIFIER.fullmatch(value) is None:
        raise LiveGateConfigurationError(f"{name} must be a safe explicit identifier")
    return value


def _checked_directory(name: str) -> Path:
    raw = _checked_value(name)
    path = Path(raw)
    if (
        not path.is_absolute()
        or raw == "/"
        or raw.startswith("//")
        or os.path.normpath(raw) != raw
        or ".." in path.parts
        or not path.is_dir()
    ):
        raise LiveGateConfigurationError(
            f"{name} must name an existing normalized absolute non-root directory"
        )
    return path


def _pytest_checked[T](operation: Callable[[], T]) -> T:
    try:
        return operation()
    except LiveGateConfigurationError as exc:
        pytest.fail(str(exc))


def require_live() -> None:
    if os.environ.get("AGENT_LOOP_ALLOW_LIVE") != "1":
        pytest.skip("set AGENT_LOOP_ALLOW_LIVE=1 to enable pinned real-CLI probes")


def required_value(name: str) -> str:
    return _pytest_checked(lambda: _checked_value(name))


def required_identifier(name: str) -> str:
    return _pytest_checked(lambda: _checked_identifier(name))


def required_directory(name: str) -> Path:
    return _pytest_checked(lambda: _checked_directory(name))


def require_paid_confirmation(tool: str) -> None:
    variable = f"AGENT_LOOP_CONFIRM_PAID_{tool.upper()}"
    if os.environ.get(variable) != "1":
        pytest.fail(f"{variable}=1 is required to authorize this paid live probe")


@dataclass(frozen=True, slots=True)
class LiveInstall:
    host_executable: Path
    mount: SandboxMount
    sandbox_executable: str
    closure_sha256: str


_OBSERVED_INSTALLS: dict[str, LiveInstall] = {}


def reset_live_gate_session_state() -> None:
    """Discard all selector/install observations before each pytest session."""

    _OBSERVED_VALUES.clear()
    _OBSERVED_INSTALLS.clear()


def launched_bwrap_argv(command: tuple[str, ...]) -> tuple[str, ...]:
    """Extract the descriptor-binding launcher's reviewed Bubblewrap argv."""

    if command[:4] != ("/usr/bin/python3", "-I", "-B", "-c") or len(command) != 6:
        raise ValueError("sandbox service did not use the reviewed mount launcher")
    payload = json.loads(command[5])
    if not isinstance(payload, dict) or set(payload) != {"argv", "bindings"}:
        raise ValueError("sandbox mount-launch payload is malformed")
    argv = payload["argv"]
    if not isinstance(argv, list) or any(not isinstance(item, str) for item in argv):
        raise ValueError("sandbox mount-launch argv is malformed")
    return tuple(argv)


def inspect_live_install(tool: str) -> LiveInstall:
    if tool not in {"codex", "claude"}:
        raise LiveGateConfigurationError("the live install name must be codex or claude")
    upper = tool.upper()
    root = _checked_directory(f"AGENT_LOOP_{upper}_INSTALL_ROOT")
    relative_raw = _checked_value(f"AGENT_LOOP_{upper}_INSTALL_RELATIVE")
    relative = PurePosixPath(relative_raw)
    if (
        relative.is_absolute()
        or str(relative) != relative_raw
        or relative_raw in {"", "."}
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise LiveGateConfigurationError(
            f"AGENT_LOOP_{upper}_INSTALL_RELATIVE must be a normalized relative path"
        )
    executable = root.joinpath(*relative.parts)
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise LiveGateConfigurationError(
            f"the configured {tool} executable is missing or not executable"
        )
    if Path(os.path.realpath(root)) != root or Path(os.path.realpath(executable)) != executable:
        raise LiveGateConfigurationError(
            f"the configured {tool} install must use canonical paths without symlinks"
        )
    try:
        verify_safe_ancestors(executable)
        with executable.open("rb") as stream:
            magic = stream.read(4)
        if tool == "codex":
            if magic == b"\x7fELF" or executable.name != "codex.js":
                raise LiveGateConfigurationError(
                    "the reviewed Codex live install must be its npm bin/codex.js"
                )
            if executable.parent.name != "bin" or executable.parent.parent != root:
                raise LiveGateConfigurationError(
                    "AGENT_LOOP_CODEX_INSTALL_ROOT must be the exact reviewed npm package root"
                )
            package_path = root / "package.json"
            package = json.loads(package_path.read_text(encoding="utf-8"))
            if not isinstance(package, dict) or (
                package.get("name"),
                package.get("version"),
            ) != ("@openai/codex", SUPPORTED_CODEX_VERSION):
                raise LiveGateConfigurationError(
                    "the reviewed Codex npm package identity is not the frozen CLI version"
                )
            source = root
            target = "/opt/agent-loop-tools/codex-package"
            sandbox_executable = target + "/bin/codex.js"
        else:
            if magic != b"\x7fELF":
                raise LiveGateConfigurationError(
                    "the reviewed Claude live install must be the exact ELF executable"
                )
            source = executable
            target = "/opt/agent-loop-tools/claude"
            sandbox_executable = target
        closure_digest = closure_sha256(source)
    except LiveGateConfigurationError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise LiveGateConfigurationError(
            f"the configured {tool} install closure is unsafe or unsupported"
        ) from exc
    selected = LiveInstall(
        host_executable=executable,
        mount=SandboxMount(
            os.fspath(source),
            target,
            read_only=True,
            closure_sha256=closure_digest,
        ),
        sandbox_executable=sandbox_executable,
        closure_sha256=closure_digest,
    )
    previous = _OBSERVED_INSTALLS.setdefault(tool, selected)
    if previous != selected:
        raise LiveGateConfigurationError(
            f"the reviewed {tool} install changed during the live acceptance session"
        )
    return selected


def required_install(tool: str) -> LiveInstall:
    return _pytest_checked(lambda: inspect_live_install(tool))


@dataclass(slots=True)
class LiveGateReportLedger:
    """Track exact pass phases and reject sessions containing skip/xfail outcomes."""

    phases: dict[str, set[str]]
    disqualified: bool = False

    @classmethod
    def create(cls) -> LiveGateReportLedger:
        return cls({nodeid: set() for nodeid in _REQUIRED_GATE_NODEIDS})

    def record_collection_outcome(self, outcome: str) -> None:
        if outcome != "passed":
            self.disqualified = True

    def record(self, report: ReportLike) -> None:
        outcome = report.outcome
        was_xfail = vars(report).get("wasxfail") is not None
        if outcome != "passed" or was_xfail:
            self.disqualified = True
        nodeid = report.nodeid
        phase = report.when
        if nodeid not in self.phases or phase not in _REPORT_PHASES:
            return
        if outcome != "passed" or was_xfail:
            self.disqualified = True
            return
        self.phases[nodeid].add(phase)

    def eligible(self, exitstatus: int) -> bool:
        return (
            exitstatus == int(pytest.ExitCode.OK)
            and not self.disqualified
            and all(phases == _REPORT_PHASES for phases in self.phases.values())
        )


def write_live_gate_receipt_from_observed_environment() -> Path:
    """Re-probe, re-hash, and bind only selectors consumed by the passing gates."""

    missing = sorted(set(_RECEIPT_VALUE_NAMES) - _OBSERVED_VALUES.keys())
    if missing:
        raise LiveGateConfigurationError(
            "the passing live gates did not consume every receipt-bound explicit selector"
        )
    for name in _RECEIPT_VALUE_NAMES:
        _checked_value(name)
    before = {
        "codex": inspect_live_install("codex"),
        "claude": inspect_live_install("claude"),
    }
    report = run_preflight(
        codex_path=os.fspath(before["codex"].host_executable),
        claude_path=os.fspath(before["claude"].host_executable),
    )
    after = {
        "codex": inspect_live_install("codex"),
        "claude": inspect_live_install("claude"),
    }
    if before != after:
        raise LiveGateConfigurationError(
            "a reviewed live install changed while constructing its capability receipt"
        )
    if (
        report.codex.resolved_path != os.fspath(after["codex"].host_executable)
        or report.claude.resolved_path != os.fspath(after["claude"].host_executable)
    ):
        raise LiveGateConfigurationError(
            "preflight resolved a different executable than the reviewed live mounts"
        )
    binding = LiveCapabilityBinding.from_environment_report(
        report,
        codex_credential_id=_checked_identifier("AGENT_LOOP_CODEX_CREDENTIAL_ID"),
        claude_credential_id=_checked_identifier("AGENT_LOOP_CLAUDE_CREDENTIAL_ID"),
        author_model=_checked_value("AGENT_LOOP_CODEX_MODEL"),
        author_effort=_checked_value("AGENT_LOOP_CODEX_EFFORT"),
        critic_model=_checked_value("AGENT_LOOP_CLAUDE_MODEL"),
        critic_effort=_checked_value("AGENT_LOOP_CLAUDE_EFFORT"),
        codex_install_closure_sha256=after["codex"].closure_sha256,
        claude_install_closure_sha256=after["claude"].closure_sha256,
        runtime_closure_sha256=installed_runtime_closure_sha256(),
    )
    receipt_path = _checked_directory("AGENT_LOOP_STATE_HOME") / (
        CAPABILITY_RECEIPT_RELATIVE_PATH
    )
    write_successful_live_capability_receipt(
        receipt_path,
        binding,
        successful_gates=REQUIRED_ACCEPTANCE_GATES,
    )
    return receipt_path


class RecordingService:
    """Record strict supervisor requests/results while delegating to production systemd."""

    def __init__(self) -> None:
        self._delegate = TransientServiceRunner()
        self.commands: list[tuple[str, ...]] = []
        self.roles: list[str] = []
        self.requests: list[SandboxRequest] = []
        self.results: list[SandboxResult] = []

    def run(
        self,
        command: tuple[str, ...],
        *,
        role: str,
        input_bytes: bytes = b"",
        timeout_seconds: float,
        limits: ServiceLimits | None = None,
    ) -> ServiceResult:
        request = parse_request(input_bytes)
        self.commands.append(command)
        self.roles.append(role)
        self.requests.append(request)
        result = self._delegate.run(
            command,
            role=role,
            input_bytes=input_bytes,
            timeout_seconds=timeout_seconds,
            limits=limits,
        )
        if result.process.stdout:
            response = parse_response(result.process.stdout, request=request)
            if isinstance(response, SandboxResult):
                self.results.append(response)
        return result
