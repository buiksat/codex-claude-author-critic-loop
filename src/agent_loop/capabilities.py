"""Private, durable receipts for the opt-in pinned live capability gates.

The receipt is deliberately not a general cache.  It is a short-lived,
canonical record that all required paid/live acceptance probes succeeded for
one exact host, CLI installation, credential identity, and model selection.
Production code must reconstruct the expected binding from its current
preflight and run configuration and call :func:`verify_live_capability_receipt`.

Only successful opt-in acceptance tests should call
:func:`write_successful_live_capability_receipt`.  Receipt files contain no
credential bytes, but their account identifiers and environment facts are
sensitive operational metadata, so both the containing directory and file are
required to be private.
"""

from __future__ import annotations

import errno
import json
import os
import re
import stat
import time
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Never, Self

from .constants import PRIVATE_DIR_MODE, PRIVATE_FILE_MODE, SPEC_VERSION
from .errors import AgentLoopError
from .filesystem import ConfinedFilesystem

if TYPE_CHECKING:
    from .preflight import EnvironmentReport, TrustedExecutable


CAPABILITY_RECEIPT_SCHEMA_VERSION = 2
CAPABILITY_RECEIPT_TYPE = "agent-loop.live-capabilities"
CAPABILITY_RECEIPT_RELATIVE_PATH = Path("agent-loop/capabilities/live-v2.json")
MAX_CAPABILITY_RECEIPT_BYTES = 64 * 1024
MAX_CAPABILITY_RECEIPT_VALIDITY_SECONDS = 7 * 24 * 60 * 60

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_MODEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_EFFORT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


class AcceptanceGate(StrEnum):
    """Target-host and paid gates required by the production capability receipt."""

    NETWORK_SPLIT = "08-network-split"
    FULL_TMPFS_EXPORT = "09-full-tmpfs-export"
    RESOURCE_LIMITS = "10-resource-limits"
    BUBBLEWRAP_PROVENANCE = "11-bubblewrap-provenance"
    DESCENDANT_CLEANUP = "29-descendant-cleanup"
    PROCESS_INTROSPECTION = "30-process-introspection"
    CUSTOM_PROFILE = "33-custom-profile"
    MANAGED_CLAUDE_BOUNDARY = "49-managed-claude-boundary"
    GITLESS_FIRST_AND_RESUME = "65-gitless-first-turn-and-resume"
    PROJECT_INSTRUCTION_ISOLATION = "66-project-instruction-isolation"
    SERVICE_LIFECYCLE = "71-transient-service-lifecycle"


REQUIRED_ACCEPTANCE_GATES = tuple(AcceptanceGate)


class CapabilityReceiptError(ValueError):
    """A live receipt is unsafe, malformed, stale, or does not match preflight."""


def _invalid(detail: str) -> Never:
    raise CapabilityReceiptError(detail)


def _safe_text(value: object, *, field: str, max_bytes: int = 1024) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        _invalid(f"{field} must be a non-empty NUL-free string")
    if len(value.encode("utf-8")) > max_bytes:
        _invalid(f"{field} exceeds its byte limit")
    return value


def _matching_text(value: object, pattern: re.Pattern[str], *, field: str) -> str:
    text = _safe_text(value, field=field, max_bytes=256)
    if pattern.fullmatch(text) is None:
        _invalid(f"{field} is not a safe exact identifier")
    return text


def _sha256(value: object, *, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        _invalid(f"{field} must be a lowercase SHA-256 digest")
    return value


def _absolute_path(value: object, *, field: str) -> str:
    text = _safe_text(value, field=field, max_bytes=4096)
    if (
        not text.startswith("/")
        or text == "/"
        or text.startswith("//")
        or text.endswith("/")
        or os.path.normpath(text) != text
    ):
        _invalid(f"{field} must be a normalized absolute non-root path")
    return text


def _true(value: object, *, field: str) -> bool:
    if value is not True:
        _invalid(f"{field} must be true")
    return True


def _timestamp(value: object, *, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 2**63:
        _invalid(f"{field} must be a non-negative signed 64-bit integer")
    return value


def _positive_bounded_seconds(value: object, *, field: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value <= 0
        or value > MAX_CAPABILITY_RECEIPT_VALIDITY_SECONDS
    ):
        raise ValueError(
            f"{field} must be between 1 and "
            f"{MAX_CAPABILITY_RECEIPT_VALIDITY_SECONDS} seconds"
        )
    return value


def _closed_object(value: object, keys: set[str], *, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        _invalid(f"{field} must be an object")
    actual = set(value)
    missing = keys - actual
    unknown = actual - keys
    if missing:
        _invalid(f"{field} is missing required properties")
    if unknown:
        _invalid(f"{field} contains unknown properties")
    return value


@dataclass(frozen=True, slots=True)
class HostCapabilityBinding:
    """Exact host and frozen-matrix facts on which live probes depended."""

    os_id: str
    os_version: str
    machine: str
    kernel: str
    python: str
    git: str
    systemd: str
    bash: str
    bubblewrap_package_version: str
    bubblewrap_upstream_version: str
    bubblewrap_executable_sha256: str
    python_executable_sha256: str
    runtime_closure_sha256: str
    openat2: bool
    namespace_probe: bool
    transient_service_probe: bool

    def __post_init__(self) -> None:
        for name in (
            "os_id",
            "os_version",
            "machine",
            "kernel",
            "python",
            "git",
            "systemd",
            "bash",
            "bubblewrap_package_version",
            "bubblewrap_upstream_version",
        ):
            _safe_text(getattr(self, name), field=f"host.{name}")
        _sha256(
            self.bubblewrap_executable_sha256,
            field="host.bubblewrap_executable_sha256",
        )
        _sha256(
            self.python_executable_sha256,
            field="host.python_executable_sha256",
        )
        _sha256(
            self.runtime_closure_sha256,
            field="host.runtime_closure_sha256",
        )
        for name in ("openat2", "namespace_probe", "transient_service_probe"):
            _true(getattr(self, name), field=f"host.{name}")

    @classmethod
    def from_environment_report(
        cls,
        report: EnvironmentReport,
        *,
        runtime_closure_sha256: str,
    ) -> Self:
        """Bind the exact successful production preflight report."""

        return cls(
            os_id=report.os_id,
            os_version=report.os_version,
            machine=report.machine,
            kernel=report.kernel,
            python=report.python,
            git=report.git,
            systemd=report.systemd,
            bash=report.bash,
            bubblewrap_package_version=report.bubblewrap.package_version,
            bubblewrap_upstream_version=report.bubblewrap.upstream_version,
            bubblewrap_executable_sha256=report.bubblewrap.sha256,
            python_executable_sha256=report.python_executable.sha256,
            runtime_closure_sha256=runtime_closure_sha256,
            openat2=report.openat2,
            namespace_probe=report.namespace_probe,
            transient_service_probe=report.transient_service_probe,
        )

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
            "bubblewrap_package_version": self.bubblewrap_package_version,
            "bubblewrap_upstream_version": self.bubblewrap_upstream_version,
            "bubblewrap_executable_sha256": self.bubblewrap_executable_sha256,
            "python_executable_sha256": self.python_executable_sha256,
            "runtime_closure_sha256": self.runtime_closure_sha256,
            "openat2": self.openat2,
            "namespace_probe": self.namespace_probe,
            "transient_service_probe": self.transient_service_probe,
        }


@dataclass(frozen=True, slots=True)
class ToolCapabilityBinding:
    """One exact CLI executable, account identity, and requested model tuple."""

    version: str
    executable_sha256: str
    credential_id: str
    requested_model: str
    requested_effort: str
    install_closure_sha256: str | None = None

    def __post_init__(self) -> None:
        _safe_text(self.version, field="tool.version", max_bytes=256)
        _sha256(self.executable_sha256, field="tool.executable_sha256")
        _matching_text(self.credential_id, _IDENTIFIER, field="tool.credential_id")
        _matching_text(self.requested_model, _MODEL, field="tool.requested_model")
        _matching_text(self.requested_effort, _EFFORT, field="tool.requested_effort")
        if self.install_closure_sha256 is not None:
            _sha256(
                self.install_closure_sha256,
                field="tool.install_closure_sha256",
            )

    @classmethod
    def from_trusted_executable(
        cls,
        executable: TrustedExecutable,
        *,
        credential_id: str,
        requested_model: str,
        requested_effort: str,
        install_closure_sha256: str | None = None,
    ) -> Self:
        """Bind a production preflight executable without trusting its path spelling."""

        return cls(
            version=executable.version,
            executable_sha256=executable.sha256,
            install_closure_sha256=install_closure_sha256,
            credential_id=credential_id,
            requested_model=requested_model,
            requested_effort=requested_effort,
        )

    def to_json_obj(self) -> dict[str, object]:
        result: dict[str, object] = {
            "version": self.version,
            "executable_sha256": self.executable_sha256,
            "credential_id": self.credential_id,
            "requested_model": self.requested_model,
            "requested_effort": self.requested_effort,
        }
        if self.install_closure_sha256 is not None:
            result["install_closure_sha256"] = self.install_closure_sha256
        return result


@dataclass(frozen=True, slots=True)
class ManagedClaudeBoundaryCapabilityBinding:
    """Exact managed-policy and helper closure proven by the Claude live gate."""

    policy_path: str
    helper_path: str
    policy_sha256: str
    helper_sha256: str
    probe_protocol: str
    probe_id: str

    def __post_init__(self) -> None:
        _absolute_path(self.policy_path, field="managed_claude_boundary.policy_path")
        _absolute_path(self.helper_path, field="managed_claude_boundary.helper_path")
        _sha256(
            self.policy_sha256,
            field="managed_claude_boundary.policy_sha256",
        )
        _sha256(
            self.helper_sha256,
            field="managed_claude_boundary.helper_sha256",
        )
        _matching_text(
            self.probe_protocol,
            _IDENTIFIER,
            field="managed_claude_boundary.probe_protocol",
        )
        _matching_text(
            self.probe_id,
            _IDENTIFIER,
            field="managed_claude_boundary.probe_id",
        )

    def to_json_obj(self) -> dict[str, object]:
        return {
            "policy_path": self.policy_path,
            "helper_path": self.helper_path,
            "policy_sha256": self.policy_sha256,
            "helper_sha256": self.helper_sha256,
            "probe_protocol": self.probe_protocol,
            "probe_id": self.probe_id,
        }


@dataclass(frozen=True, slots=True)
class LiveCapabilityBinding:
    """Everything that must match before a live receipt can authorize a run."""

    host: HostCapabilityBinding
    codex: ToolCapabilityBinding
    claude: ToolCapabilityBinding
    managed_claude_boundary: ManagedClaudeBoundaryCapabilityBinding

    def __post_init__(self) -> None:
        if not isinstance(self.host, HostCapabilityBinding):
            raise TypeError("host must be a HostCapabilityBinding")
        if not isinstance(self.codex, ToolCapabilityBinding):
            raise TypeError("codex must be a ToolCapabilityBinding")
        if not isinstance(self.claude, ToolCapabilityBinding):
            raise TypeError("claude must be a ToolCapabilityBinding")
        if not isinstance(
            self.managed_claude_boundary,
            ManagedClaudeBoundaryCapabilityBinding,
        ):
            raise TypeError(
                "managed_claude_boundary must be a "
                "ManagedClaudeBoundaryCapabilityBinding"
            )

    @classmethod
    def from_environment_report(
        cls,
        report: EnvironmentReport,
        *,
        codex_credential_id: str,
        claude_credential_id: str,
        author_model: str,
        author_effort: str,
        critic_model: str,
        critic_effort: str,
        managed_claude_boundary: ManagedClaudeBoundaryCapabilityBinding,
        codex_install_closure_sha256: str | None = None,
        claude_install_closure_sha256: str | None = None,
        runtime_closure_sha256: str,
    ) -> Self:
        """Construct the exact binding shared by live tests and production."""

        return cls(
            host=HostCapabilityBinding.from_environment_report(
                report,
                runtime_closure_sha256=runtime_closure_sha256,
            ),
            codex=ToolCapabilityBinding.from_trusted_executable(
                report.codex,
                credential_id=codex_credential_id,
                requested_model=author_model,
                requested_effort=author_effort,
                install_closure_sha256=codex_install_closure_sha256,
            ),
            claude=ToolCapabilityBinding.from_trusted_executable(
                report.claude,
                credential_id=claude_credential_id,
                requested_model=critic_model,
                requested_effort=critic_effort,
                install_closure_sha256=claude_install_closure_sha256,
            ),
            managed_claude_boundary=managed_claude_boundary,
        )

    def to_json_obj(self) -> dict[str, object]:
        return {
            "host": self.host.to_json_obj(),
            "tools": {
                "codex": self.codex.to_json_obj(),
                "claude": self.claude.to_json_obj(),
            },
            "managed_claude_boundary": self.managed_claude_boundary.to_json_obj(),
        }


@dataclass(frozen=True, slots=True)
class LiveCapabilityReceipt:
    """A parsed receipt which has not necessarily been freshness-verified."""

    binding: LiveCapabilityBinding
    issued_at_unix: int
    expires_at_unix: int
    acceptance_gates: tuple[AcceptanceGate, ...] = REQUIRED_ACCEPTANCE_GATES
    schema_version: int = CAPABILITY_RECEIPT_SCHEMA_VERSION
    spec_version: str = SPEC_VERSION
    receipt_type: str = CAPABILITY_RECEIPT_TYPE

    def __post_init__(self) -> None:
        if not isinstance(self.binding, LiveCapabilityBinding):
            raise TypeError("binding must be a LiveCapabilityBinding")
        issued = _timestamp(self.issued_at_unix, field="issued_at_unix")
        expires = _timestamp(self.expires_at_unix, field="expires_at_unix")
        if expires <= issued:
            _invalid("expires_at_unix must be later than issued_at_unix")
        if expires - issued > MAX_CAPABILITY_RECEIPT_VALIDITY_SECONDS:
            _invalid("receipt validity exceeds the maximum lifetime")
        if self.acceptance_gates != REQUIRED_ACCEPTANCE_GATES:
            _invalid("receipt must contain the complete ordered acceptance gate set")
        if self.schema_version != CAPABILITY_RECEIPT_SCHEMA_VERSION:
            _invalid("unsupported capability receipt schema_version")
        if self.spec_version != SPEC_VERSION:
            _invalid("capability receipt specification version does not match")
        if self.receipt_type != CAPABILITY_RECEIPT_TYPE:
            _invalid("unsupported capability receipt type")

    def to_json_obj(self) -> dict[str, object]:
        result = self.binding.to_json_obj()
        result.update(
            {
                "receipt_type": self.receipt_type,
                "schema_version": self.schema_version,
                "spec_version": self.spec_version,
                "issued_at_unix": self.issued_at_unix,
                "expires_at_unix": self.expires_at_unix,
                "acceptance_gates": [gate.value for gate in self.acceptance_gates],
            }
        )
        return result

    def to_bytes(self) -> bytes:
        return json.dumps(
            self.to_json_obj(),
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii") + b"\n"


_HOST_KEYS = {
    "os_id",
    "os_version",
    "machine",
    "kernel",
    "python",
    "git",
    "systemd",
    "bash",
    "bubblewrap_package_version",
    "bubblewrap_upstream_version",
    "bubblewrap_executable_sha256",
    "python_executable_sha256",
    "runtime_closure_sha256",
    "openat2",
    "namespace_probe",
    "transient_service_probe",
}
_TOOL_REQUIRED_KEYS = {
    "version",
    "executable_sha256",
    "credential_id",
    "requested_model",
    "requested_effort",
}
_MANAGED_CLAUDE_BOUNDARY_KEYS = {
    "policy_path",
    "helper_path",
    "policy_sha256",
    "helper_sha256",
    "probe_protocol",
    "probe_id",
}
_TOP_LEVEL_KEYS = {
    "receipt_type",
    "schema_version",
    "spec_version",
    "issued_at_unix",
    "expires_at_unix",
    "acceptance_gates",
    "host",
    "tools",
    "managed_claude_boundary",
}


def _duplicate_rejecting_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _invalid("capability receipt contains a duplicate JSON property")
        result[key] = value
    return result


def _parse_tool(value: object, *, field: str) -> ToolCapabilityBinding:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        _invalid(f"{field} must be an object")
    actual = set(value)
    missing = _TOOL_REQUIRED_KEYS - actual
    unknown = actual - (_TOOL_REQUIRED_KEYS | {"install_closure_sha256"})
    if missing:
        _invalid(f"{field} is missing required properties")
    if unknown:
        _invalid(f"{field} contains unknown properties")
    closure = value.get("install_closure_sha256")
    return ToolCapabilityBinding(
        version=_safe_text(value["version"], field=f"{field}.version", max_bytes=256),
        executable_sha256=_sha256(
            value["executable_sha256"],
            field=f"{field}.executable_sha256",
        ),
        install_closure_sha256=(
            None
            if "install_closure_sha256" not in value
            else _sha256(closure, field=f"{field}.install_closure_sha256")
        ),
        credential_id=_matching_text(
            value["credential_id"],
            _IDENTIFIER,
            field=f"{field}.credential_id",
        ),
        requested_model=_matching_text(
            value["requested_model"],
            _MODEL,
            field=f"{field}.requested_model",
        ),
        requested_effort=_matching_text(
            value["requested_effort"],
            _EFFORT,
            field=f"{field}.requested_effort",
        ),
    )


def _parse_managed_claude_boundary(
    value: object,
) -> ManagedClaudeBoundaryCapabilityBinding:
    field = "managed_claude_boundary"
    boundary = _closed_object(value, _MANAGED_CLAUDE_BOUNDARY_KEYS, field=field)
    return ManagedClaudeBoundaryCapabilityBinding(
        policy_path=_absolute_path(
            boundary["policy_path"],
            field=f"{field}.policy_path",
        ),
        helper_path=_absolute_path(
            boundary["helper_path"],
            field=f"{field}.helper_path",
        ),
        policy_sha256=_sha256(
            boundary["policy_sha256"],
            field=f"{field}.policy_sha256",
        ),
        helper_sha256=_sha256(
            boundary["helper_sha256"],
            field=f"{field}.helper_sha256",
        ),
        probe_protocol=_matching_text(
            boundary["probe_protocol"],
            _IDENTIFIER,
            field=f"{field}.probe_protocol",
        ),
        probe_id=_matching_text(
            boundary["probe_id"],
            _IDENTIFIER,
            field=f"{field}.probe_id",
        ),
    )


def _parse_receipt(data: bytes) -> LiveCapabilityReceipt:
    if not isinstance(data, bytes):
        raise TypeError("capability receipt data must be bytes")
    if len(data) > MAX_CAPABILITY_RECEIPT_BYTES:
        _invalid("capability receipt exceeds its byte limit")
    try:
        decoded = data.decode("utf-8", "strict")
        value: object = json.loads(
            decoded,
            object_pairs_hook=_duplicate_rejecting_object,
            parse_constant=lambda token: _invalid(
                f"capability receipt contains non-finite number {token}"
            ),
        )
    except CapabilityReceiptError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError):
        _invalid("capability receipt is not valid UTF-8 JSON")

    top = _closed_object(value, _TOP_LEVEL_KEYS, field="receipt")
    if top["receipt_type"] != CAPABILITY_RECEIPT_TYPE:
        _invalid("unsupported capability receipt type")
    if top["schema_version"] != CAPABILITY_RECEIPT_SCHEMA_VERSION:
        _invalid("unsupported capability receipt schema_version")
    if top["spec_version"] != SPEC_VERSION:
        _invalid("capability receipt specification version does not match")

    host = _closed_object(top["host"], _HOST_KEYS, field="host")
    tools = _closed_object(top["tools"], {"codex", "claude"}, field="tools")
    raw_gates = top["acceptance_gates"]
    expected_gate_values = [gate.value for gate in REQUIRED_ACCEPTANCE_GATES]
    if not isinstance(raw_gates, list) or raw_gates != expected_gate_values:
        _invalid("receipt must contain the complete ordered acceptance gate set")

    receipt = LiveCapabilityReceipt(
        binding=LiveCapabilityBinding(
            host=HostCapabilityBinding(
                os_id=_safe_text(host["os_id"], field="host.os_id"),
                os_version=_safe_text(host["os_version"], field="host.os_version"),
                machine=_safe_text(host["machine"], field="host.machine"),
                kernel=_safe_text(host["kernel"], field="host.kernel"),
                python=_safe_text(host["python"], field="host.python"),
                git=_safe_text(host["git"], field="host.git"),
                systemd=_safe_text(host["systemd"], field="host.systemd"),
                bash=_safe_text(host["bash"], field="host.bash"),
                bubblewrap_package_version=_safe_text(
                    host["bubblewrap_package_version"],
                    field="host.bubblewrap_package_version",
                ),
                bubblewrap_upstream_version=_safe_text(
                    host["bubblewrap_upstream_version"],
                    field="host.bubblewrap_upstream_version",
                ),
                bubblewrap_executable_sha256=_sha256(
                    host["bubblewrap_executable_sha256"],
                    field="host.bubblewrap_executable_sha256",
                ),
                python_executable_sha256=_sha256(
                    host["python_executable_sha256"],
                    field="host.python_executable_sha256",
                ),
                runtime_closure_sha256=_sha256(
                    host["runtime_closure_sha256"],
                    field="host.runtime_closure_sha256",
                ),
                openat2=_true(host["openat2"], field="host.openat2"),
                namespace_probe=_true(
                    host["namespace_probe"],
                    field="host.namespace_probe",
                ),
                transient_service_probe=_true(
                    host["transient_service_probe"],
                    field="host.transient_service_probe",
                ),
            ),
            codex=_parse_tool(tools["codex"], field="tools.codex"),
            claude=_parse_tool(tools["claude"], field="tools.claude"),
            managed_claude_boundary=_parse_managed_claude_boundary(
                top["managed_claude_boundary"]
            ),
        ),
        issued_at_unix=_timestamp(top["issued_at_unix"], field="issued_at_unix"),
        expires_at_unix=_timestamp(top["expires_at_unix"], field="expires_at_unix"),
    )
    if receipt.to_bytes() != data:
        _invalid("capability receipt is not in canonical writer format")
    return receipt


def _normalized_receipt_path(path: str | os.PathLike[str]) -> Path:
    raw = os.fspath(path)
    if not isinstance(raw, str):
        raise TypeError("capability receipt path must be a text filesystem path")
    if (
        not raw.startswith("/")
        or raw == "/"
        or raw.startswith("//")
        or raw.endswith("/")
        or os.path.normpath(raw) != raw
        or "\x00" in raw
    ):
        raise ValueError("capability receipt path must be normalized and absolute")
    if len(os.fsencode(raw)) > 4096:
        raise ValueError("capability receipt path exceeds its byte limit")
    selected = Path(raw)
    if selected.parent == Path("/"):
        raise ValueError("capability receipt must be inside a private directory")
    return selected


def _require_private_directory(filesystem: ConfinedFilesystem) -> None:
    info = os.fstat(filesystem.fileno())
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_gid != os.getegid()
        or stat.S_IMODE(info.st_mode) != PRIVATE_DIR_MODE
    ):
        _invalid("capability receipt directory is not private")
    try:
        attributes = os.listxattr(filesystem.fileno())
    except OSError:
        _invalid("capability receipt directory metadata cannot be verified")
    if attributes:
        _invalid("capability receipt directory has unsupported metadata")


def _private_file_info(filesystem: ConfinedFilesystem, name: bytes) -> os.stat_result:
    try:
        info = filesystem.lstat(name)
    except AgentLoopError:
        _invalid("capability receipt file cannot be safely inspected")
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != os.geteuid()
        or info.st_gid != os.getegid()
        or stat.S_IMODE(info.st_mode) != PRIVATE_FILE_MODE
    ):
        _invalid("capability receipt is not a private single-link regular file")
    return info


def _read_private_receipt(path: Path) -> bytes:
    try:
        filesystem = ConfinedFilesystem.open(path.parent)
    except (AgentLoopError, OSError, TypeError, ValueError):
        _invalid("capability receipt directory cannot be opened without symlinks")
    with filesystem:
        _require_private_directory(filesystem)
        name = os.fsencode(path.name)
        _private_file_info(filesystem, name)
        try:
            return filesystem.read_bytes(name, max_bytes=MAX_CAPABILITY_RECEIPT_BYTES)
        except (AgentLoopError, OSError, TypeError, ValueError):
            _invalid("capability receipt cannot be read as a stable private file")


def write_successful_live_capability_receipt(
    path: str | os.PathLike[str],
    binding: LiveCapabilityBinding,
    *,
    successful_gates: Collection[AcceptanceGate],
    issued_at_unix: int | None = None,
    valid_for_seconds: int = MAX_CAPABILITY_RECEIPT_VALIDITY_SECONDS,
) -> LiveCapabilityReceipt:
    """Atomically persist a receipt after *all* opt-in live gates succeeded.

    The explicit ordered gate argument prevents a partial or skipped live test
    from accidentally emitting a production-acceptable receipt.  The function
    contains no live calls and performs no probing itself.
    """

    if not isinstance(binding, LiveCapabilityBinding):
        raise TypeError("binding must be a LiveCapabilityBinding")
    if tuple(successful_gates) != REQUIRED_ACCEPTANCE_GATES:
        raise ValueError("successful_gates must be the complete ordered live gate set")
    lifetime = _positive_bounded_seconds(valid_for_seconds, field="valid_for_seconds")
    issued = (
        time.time_ns() // 1_000_000_000
        if issued_at_unix is None
        else _timestamp(issued_at_unix, field="issued_at_unix")
    )
    if issued > 2**63 - 1 - lifetime:
        raise ValueError("capability receipt expiry exceeds the timestamp range")
    receipt = LiveCapabilityReceipt(
        binding=binding,
        issued_at_unix=issued,
        expires_at_unix=issued + lifetime,
    )
    encoded = receipt.to_bytes()
    if len(encoded) > MAX_CAPABILITY_RECEIPT_BYTES:
        raise ValueError("capability receipt exceeds its byte limit")

    selected = _normalized_receipt_path(path)
    try:
        filesystem = ConfinedFilesystem.create_private(selected.parent)
    except (AgentLoopError, OSError, TypeError, ValueError):
        _invalid("capability receipt directory cannot be created without symlinks")
    with filesystem:
        _require_private_directory(filesystem)
        name = os.fsencode(selected.name)
        try:
            existing = filesystem.lstat(name)
        except AgentLoopError as exc:
            cause = exc.__cause__
            if not isinstance(cause, OSError) or cause.errno != errno.ENOENT:
                _invalid("existing capability receipt cannot be safely inspected")
        else:
            if (
                not stat.S_ISREG(existing.st_mode)
                or existing.st_nlink != 1
                or existing.st_uid != os.geteuid()
                or existing.st_gid != os.getegid()
                or stat.S_IMODE(existing.st_mode) != PRIVATE_FILE_MODE
            ):
                _invalid("existing capability receipt is not a private regular file")
            try:
                filesystem.read_bytes(name, max_bytes=MAX_CAPABILITY_RECEIPT_BYTES)
            except (AgentLoopError, OSError, TypeError, ValueError):
                _invalid("existing capability receipt metadata is unsafe")
        try:
            filesystem.atomic_write(
                name,
                encoded,
                mode=PRIVATE_FILE_MODE,
                create_parents=False,
            )
            _private_file_info(filesystem, name)
            persisted = filesystem.read_bytes(name, max_bytes=MAX_CAPABILITY_RECEIPT_BYTES)
        except (AgentLoopError, OSError, TypeError, ValueError):
            _invalid("capability receipt could not be atomically persisted")
        if persisted != encoded:
            _invalid("persisted capability receipt failed byte verification")
    return receipt


def verify_live_capability_receipt(
    path: str | os.PathLike[str],
    expected: LiveCapabilityBinding,
    *,
    now_unix: int | None = None,
    max_age_seconds: int = MAX_CAPABILITY_RECEIPT_VALIDITY_SECONDS,
) -> LiveCapabilityReceipt:
    """Verify privacy, schema, freshness, gates, and the exact current binding."""

    if not isinstance(expected, LiveCapabilityBinding):
        raise TypeError("expected must be a LiveCapabilityBinding")
    allowed_age = _positive_bounded_seconds(max_age_seconds, field="max_age_seconds")
    now = (
        time.time_ns() // 1_000_000_000
        if now_unix is None
        else _timestamp(now_unix, field="now_unix")
    )
    selected = _normalized_receipt_path(path)
    receipt = _parse_receipt(_read_private_receipt(selected))
    if receipt.binding != expected:
        _invalid("capability receipt does not match the current exact binding")
    if receipt.issued_at_unix > now:
        _invalid("capability receipt was issued in the future")
    if now >= receipt.expires_at_unix or now - receipt.issued_at_unix > allowed_age:
        _invalid("capability receipt is stale")
    return receipt
