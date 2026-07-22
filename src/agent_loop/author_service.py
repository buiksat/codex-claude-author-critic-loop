"""Fixed root-broker boundary for the Codex author service.

The ordinary runner connects to one root-owned, socket-activated broker.  The
broker accepts no command or systemd property from the caller: it receives one
strict sandbox request plus already-open mount descriptors, then generates the
only reviewed root-manager transient unit.  The unit runs as the connecting
UID, has a manager-created mount/PID namespace, and starts the fixed
``sandbox-init`` entry point as PID 1.  Codex may therefore retain its own
unprivileged Bubblewrap permission-profile sandbox without nesting inside an
outer user namespace.
"""

from __future__ import annotations

import array
import hashlib
import json
import os
import re
import select
import shutil
import socket
import stat
import struct
import subprocess
import threading
import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .codex_client import (
    AUTHOR_CWD,
    AUTHOR_PERMISSION_PROFILE,
    AUTHOR_WORKSPACE,
    build_codex_parent_environment,
)
from .constants import (
    DEFAULT_LIMIT_FSIZE_BYTES,
    DEFAULT_LIMIT_NOFILE,
    DEFAULT_MAX_RUNTIME_SECONDS,
    DEFAULT_MEMORY_MAX_BYTES,
    DEFAULT_STOP_TIMEOUT_SECONDS,
    DEFAULT_TASKS_MAX,
    DEFAULT_WORKSPACE_BYTES,
)
from .errors import AgentLoopError, StopReason, fail
from .provenance import (
    MAX_REVIEWED_CLOSURE_BYTES,
    MAX_REVIEWED_CLOSURE_FILES,
    descriptor_closure_witness,
    python_source_closure_sha256,
    reject_extended_metadata_fd,
    snapshot_descriptor_closure,
)
from .sandbox import SandboxMount
from .sandbox_init import (
    MAX_PROTOCOL_EXPORT_BYTES,
    MAX_PROTOCOL_INPUT_BYTES,
    SandboxRequest,
    parse_request,
)
from .service import (
    BoundedProcessResult,
    BoundedProcessStartFailure,
    ServiceLimits,
    ServiceResult,
    run_bounded_process,
)

AUTHOR_SERVICE_PROTOCOL = 1
AUTHOR_SERVICE_BUILD_ID = "fixed-system-author-v1"
AUTHOR_SERVICE_PACKAGE_VERSION = "1.1.0"
AUTHOR_SERVICE_SOCKET = "/run/agent-loop/author.sock"
AUTHOR_SERVICE_SOCKET_UNIT = "/etc/systemd/system/agent-loop-author.socket"
AUTHOR_SERVICE_BROKER_UNIT = "/etc/systemd/system/agent-loop-author@.service"
AUTHOR_SERVICE_SOCKET_DROPIN = "/etc/systemd/system/agent-loop-author.socket.d/operator.conf"
AUTHOR_SERVICE_CONFIG = "/etc/agent-loop/author-service.conf"
AUTHOR_SERVICE_INSTALL_RECORD = "/etc/agent-loop/author-service-install.txt"
AUTHOR_SERVICE_INSTALL_ROOT = "/opt/agent-loop-author-service"
AUTHOR_SERVICE_RUNTIME_PACKAGE = (
    AUTHOR_SERVICE_INSTALL_ROOT + "/runtime/lib/python3.14/site-packages/agent_loop"
)
AUTHOR_SERVICE_INSTALLED_ASSET_ROOT = (
    AUTHOR_SERVICE_INSTALL_ROOT + "/runtime/share/agent-loop/support/author-service"
)
AUTHOR_SERVICE_REVIEWED_WHEEL = AUTHOR_SERVICE_INSTALL_ROOT + "/agent_loop-1.1.0-py3-none-any.whl"
AUTHOR_BROKER_UNIT_ENV = "AGENT_LOOP_AUTHOR_BROKER_UNIT"
AUTHOR_ALLOWED_UID_ENV = "AGENT_LOOP_AUTHOR_ALLOWED_UID"
AUTHOR_CODEX_CLOSURE_ENV = "AGENT_LOOP_AUTHOR_CODEX_CLOSURE_SHA256"
AUTHOR_SERVICE_MAX_MOUNTS = 32
AUTHOR_SERVICE_MAX_HEADER_BYTES = 64 * 1024
AUTHOR_SERVICE_ROOT_TMPFS_BYTES = 64 * 1024 * 1024
AUTHOR_SERVICE_RUNTIME_TMPFS_BYTES = 64 * 1024 * 1024
AUTHOR_SERVICE_MAX_CLOSURE_ENTRIES = 4_096
AUTHOR_SERVICE_MAX_CLOSURE_BYTES = 512 * 1024 * 1024
AUTHOR_SERVICE_PUBLICATION_ROOT = "/run/agent-loop/author-closures"

_MAGIC_REQUEST = b"ALAUTH1Q"
_MAGIC_FRAME = b"ALAUTH1R"
_PREFIX = struct.Struct("!8sIQ")
_CREDENTIALS = struct.Struct("3i")
_AUTHOR_UNIT = re.compile(r"^agent-loop-author-[0-9]+-[0-9a-f]{32}\.service$")
_BROKER_UNIT = re.compile(r"^agent-loop-author@[-A-Za-z0-9_:.\\x]+\.service$")
_SYSTEMD_UNSAFE_PATH = re.compile(r"[\x00-\x20:%\\]")
_SAFE_THREAD_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,255}$")
_TOOLCHAIN_TARGET = re.compile(r"^/opt/agent-loop-toolchains/[0-9a-f]{64}$")
_CLOSURE_ROOT_NAME = re.compile(r"^[A-Za-z0-9._-]{1,255}$")
_BROKER_DIAGNOSTIC_CODES = frozenset(
    {
        "broker_bootstrap",
        "request_frame",
        "request_policy",
        "request_acceptance",
        "request_payload",
        "request_shape",
        "closure_snapshot",
        "closure_cleanup",
        "limit_contract",
        "author_launch",
        "result_delivery",
    }
)
_FIXED_ETC_BINDS = (
    "/etc/passwd",
    "/etc/group",
    "/etc/nsswitch.conf",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/ssl/certs",
)
_SANDBOX_INIT_BOOTSTRAP = (
    "import importlib.machinery as m,runpy,sys;"
    "root='/opt/agent-loop-runtime';package=root+'/agent_loop';"
    "source_loader=(m.SourceFileLoader,m.SOURCE_SUFFIXES);"
    "sys.path_importer_cache[root]=m.FileFinder(root,source_loader);"
    "sys.path_importer_cache[package]=m.FileFinder(package,source_loader);"
    "sys.path.insert(0,root);"
    "runpy.run_module('agent_loop.sandbox_init',run_name='__main__')"
)
_FIXED_EXEC_START = ("/usr/bin/python3", "-I", "-B", "-S", "-c", _SANDBOX_INIT_BOOTSTRAP)

_ROOT_ASSET_MAX_BYTES = 4 * 1024 * 1024
_ROOT_CLOSURE_MAX_ENTRIES = 2_048


@dataclass(frozen=True, slots=True)
class AuthorServiceProvenance:
    """Exact installed fixed-manager boundary admitted by preflight."""

    protocol: int
    build_id: str
    authorized_uid: int
    socket_path: str
    socket_owner_uid: int
    socket_mode: int
    socket_unit_sha256: str
    broker_unit_sha256: str
    socket_dropin_sha256: str
    config_sha256: str
    install_record_sha256: str
    runtime_closure_sha256: str
    wheel_sha256: str
    codex_closure_sha256: str
    effective_units_sha256: str
    package_version: str
    broker_probe: bool


def _root_component_fd(path: Path, *, final_directory: bool) -> int:
    """Open an exact root-owned path without following any path component."""

    if not path.is_absolute() or path == Path("/") or os.path.normpath(path) != os.fspath(path):
        raise ValueError("fixed author-service path must be normalized and absolute")
    current = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for index, component in enumerate(path.parts[1:]):
            final = index == len(path.parts[1:]) - 1
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
            if not final or final_directory:
                flags |= os.O_DIRECTORY
            next_fd = os.open(component, flags, dir_fd=current)
            try:
                info = os.fstat(next_fd)
                if info.st_uid != 0 or info.st_gid != 0:
                    raise ValueError("fixed author-service path is not root-owned")
                mode = stat.S_IMODE(info.st_mode)
                if mode & 0o022 or info.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
                    raise ValueError("fixed author-service path is writable or specially moded")
                reject_extended_metadata_fd(next_fd)
            except BaseException:
                os.close(next_fd)
                raise
            os.close(current)
            current = next_fd
        return current
    except BaseException:
        os.close(current)
        raise


def _read_root_regular(path: str, *, mode: int, max_bytes: int = _ROOT_ASSET_MAX_BYTES) -> bytes:
    descriptor = _root_component_fd(Path(path), final_directory=False)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != mode
            or not 0 <= before.st_size <= max_bytes
        ):
            raise ValueError("fixed author-service file metadata is unsafe")
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, max_bytes + 1 - observed))
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            if observed > max_bytes:
                raise ValueError("fixed author-service file exceeds its byte limit")
        after = os.fstat(descriptor)
        stable = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_uid,
            before.st_gid,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) == (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_uid,
            after.st_gid,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if observed != before.st_size or not stable:
            raise ValueError("fixed author-service file changed during inspection")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _root_owned_closure(path: Path) -> None:
    """Reject any non-root-owned or mutable entry in the installed broker package."""

    root_fd = _root_component_fd(path, final_directory=True)
    stack = [root_fd]
    retained: list[int] = []
    entries = 0
    try:
        while stack:
            directory = stack.pop()
            retained.append(directory)
            for name in os.listdir(directory):
                entries += 1
                if entries > _ROOT_CLOSURE_MAX_ENTRIES:
                    raise ValueError("fixed author-service runtime closure is unexpectedly large")
                metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if metadata.st_uid != 0 or metadata.st_gid != 0:
                    raise ValueError("fixed author-service runtime entry is not root-owned")
                if stat.S_IMODE(metadata.st_mode) & 0o022 or metadata.st_mode & (
                    stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX
                ):
                    raise ValueError("fixed author-service runtime entry is mutable or special")
                flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
                if stat.S_ISDIR(metadata.st_mode):
                    flags |= os.O_DIRECTORY
                elif not stat.S_ISREG(metadata.st_mode):
                    raise ValueError("fixed author-service runtime contains a special file")
                child = os.open(name, flags, dir_fd=directory)
                try:
                    opened = os.fstat(child)
                    if (opened.st_dev, opened.st_ino, opened.st_mode) != (
                        metadata.st_dev,
                        metadata.st_ino,
                        metadata.st_mode,
                    ) or (stat.S_ISREG(opened.st_mode) and opened.st_nlink != 1):
                        raise ValueError("fixed author-service runtime entry changed")
                    reject_extended_metadata_fd(child)
                except BaseException:
                    os.close(child)
                    raise
                if stat.S_ISDIR(opened.st_mode):
                    stack.append(child)
                else:
                    os.close(child)
    finally:
        for descriptor in (*stack, *retained):
            os.close(descriptor)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _effective_systemd_units() -> bytes:
    properties = (
        "LoadState",
        "FragmentPath",
        "DropInPaths",
        "ActiveState",
        "SubState",
        "UnitFileState",
        "NeedDaemonReload",
    )
    documents: list[bytes] = []
    for unit in ("agent-loop-author.socket", "agent-loop-author@attest.service"):
        argv = (
            "/usr/bin/systemctl",
            "show",
            "--no-pager",
            *(f"--property={name}" for name in properties),
            unit,
        )
        result = run_bounded_process(
            argv,
            timeout_seconds=10,
            output_max_bytes=64 * 1024,
            env={
                "PATH": "/usr/bin:/bin",
                "HOME": "/nonexistent",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
            },
        )
        if result.returncode != 0 or result.timed_out or result.output_limited or result.stderr:
            raise ValueError("fixed author-service effective unit cannot be inspected")
        try:
            text = result.stdout.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise ValueError("fixed author-service effective unit output is invalid") from exc
        observed: dict[str, str] = {}
        for line in text.splitlines():
            if "=" not in line:
                raise ValueError("fixed author-service effective unit output is malformed")
            name, value = line.split("=", 1)
            if name not in properties or name in observed:
                raise ValueError("fixed author-service effective unit fields changed")
            observed[name] = value
        if set(observed) != set(properties):
            raise ValueError("fixed author-service effective unit fields are incomplete")
        expected_fragment = (
            AUTHOR_SERVICE_SOCKET_UNIT if unit.endswith(".socket") else AUTHOR_SERVICE_BROKER_UNIT
        )
        expected_dropins = AUTHOR_SERVICE_SOCKET_DROPIN if unit.endswith(".socket") else ""
        if (
            observed["LoadState"] != "loaded"
            or observed["FragmentPath"] != expected_fragment
            or observed["DropInPaths"] != expected_dropins
            or observed["NeedDaemonReload"] != "no"
        ):
            raise ValueError("fixed author-service effective unit or drop-ins changed")
        if unit.endswith(".socket") and (
            observed["ActiveState"] != "active"
            or observed["SubState"] != "listening"
            or observed["UnitFileState"] != "enabled"
        ):
            raise ValueError("fixed author-service socket is not enabled and listening")
        documents.append((unit + "\n" + text).encode("utf-8"))
    return b"\0".join(documents)


def _parse_assignment_file(data: bytes, expected_names: tuple[str, ...]) -> dict[str, str]:
    try:
        text = data.decode("ascii", "strict")
    except UnicodeDecodeError as exc:
        raise ValueError("fixed author-service metadata is not ASCII") from exc
    if not text.endswith("\n") or "\r" in text:
        raise ValueError("fixed author-service metadata has invalid line framing")
    result: dict[str, str] = {}
    for line in text[:-1].split("\n"):
        if "=" not in line:
            raise ValueError("fixed author-service metadata is malformed")
        name, value = line.split("=", 1)
        if name in result or not value:
            raise ValueError("fixed author-service metadata is malformed")
        result[name] = value
    if tuple(result) != expected_names:
        raise ValueError("fixed author-service metadata fields changed")
    return result


def inspect_fixed_author_service(*, probe: bool = True) -> AuthorServiceProvenance:
    """Inspect and optionally live-probe the one-time-installed root boundary."""

    if os.geteuid() <= 0:
        raise ValueError("fixed author-service operator must be unprivileged")
    socket_unit = _read_root_regular(AUTHOR_SERVICE_SOCKET_UNIT, mode=0o644)
    broker_unit = _read_root_regular(AUTHOR_SERVICE_BROKER_UNIT, mode=0o644)
    dropin = _read_root_regular(AUTHOR_SERVICE_SOCKET_DROPIN, mode=0o644)
    config = _read_root_regular(AUTHOR_SERVICE_CONFIG, mode=0o644)
    install_record = _read_root_regular(AUTHOR_SERVICE_INSTALL_RECORD, mode=0o644)
    installed_socket_asset = _read_root_regular(
        AUTHOR_SERVICE_INSTALLED_ASSET_ROOT + "/agent-loop-author.socket",
        mode=0o644,
    )
    installed_broker_asset = _read_root_regular(
        AUTHOR_SERVICE_INSTALLED_ASSET_ROOT + "/agent-loop-author@.service",
        mode=0o644,
    )
    if socket_unit != installed_socket_asset or broker_unit != installed_broker_asset:
        raise ValueError("installed author-service units differ from the reviewed wheel assets")

    config_fields = _parse_assignment_file(
        config,
        (AUTHOR_ALLOWED_UID_ENV, AUTHOR_CODEX_CLOSURE_ENV),
    )
    try:
        authorized_uid = int(config_fields[AUTHOR_ALLOWED_UID_ENV], 10)
    except ValueError as exc:
        raise ValueError("fixed author-service authorized UID is malformed") from exc
    if authorized_uid != os.geteuid():
        raise ValueError("fixed author-service is bound to a different operator UID")
    codex_closure_sha256 = config_fields[AUTHOR_CODEX_CLOSURE_ENV]
    if re.fullmatch(r"[0-9a-f]{64}", codex_closure_sha256) is None:
        raise ValueError("fixed author-service Codex closure witness is malformed")
    expected_dropin = (
        f"[Socket]\nSocketUser={authorized_uid}\nSocketGroup=root\nSocketMode=0600\n"
    ).encode("ascii")
    if dropin != expected_dropin:
        raise ValueError("fixed author-service socket drop-in changed")

    record = _parse_assignment_file(
        install_record,
        ("wheel_sha256", "package_version", "operator_uid", "codex_closure_sha256"),
    )
    if (
        re.fullmatch(r"[0-9a-f]{64}", record["wheel_sha256"]) is None
        or record["package_version"] != AUTHOR_SERVICE_PACKAGE_VERSION
        or record["operator_uid"] != str(authorized_uid)
        or record["codex_closure_sha256"] != codex_closure_sha256
    ):
        raise ValueError("fixed author-service install record is malformed")
    reviewed_wheel = _read_root_regular(
        AUTHOR_SERVICE_REVIEWED_WHEEL,
        mode=0o444,
        max_bytes=512 * 1024 * 1024,
    )
    if _sha256_bytes(reviewed_wheel) != record["wheel_sha256"]:
        raise ValueError("fixed author-service reviewed wheel changed")

    runtime_package = Path(AUTHOR_SERVICE_RUNTIME_PACKAGE)
    _root_owned_closure(runtime_package)
    runtime_digest = python_source_closure_sha256(runtime_package)
    effective_units = _effective_systemd_units()

    socket_info = os.lstat(AUTHOR_SERVICE_SOCKET)
    parent_fd = _root_component_fd(Path(AUTHOR_SERVICE_SOCKET).parent, final_directory=True)
    os.close(parent_fd)
    if (
        not stat.S_ISSOCK(socket_info.st_mode)
        or socket_info.st_uid != authorized_uid
        or socket_info.st_gid != 0
        or stat.S_IMODE(socket_info.st_mode) != 0o600
    ):
        raise ValueError("fixed author-service runtime socket is unsafe")

    if probe:
        FixedAuthorServiceClient().probe()
    return AuthorServiceProvenance(
        protocol=AUTHOR_SERVICE_PROTOCOL,
        build_id=AUTHOR_SERVICE_BUILD_ID,
        authorized_uid=authorized_uid,
        socket_path=AUTHOR_SERVICE_SOCKET,
        socket_owner_uid=socket_info.st_uid,
        socket_mode=stat.S_IMODE(socket_info.st_mode),
        socket_unit_sha256=_sha256_bytes(socket_unit),
        broker_unit_sha256=_sha256_bytes(broker_unit),
        socket_dropin_sha256=_sha256_bytes(dropin),
        config_sha256=_sha256_bytes(config),
        install_record_sha256=_sha256_bytes(install_record),
        runtime_closure_sha256=runtime_digest,
        wheel_sha256=record["wheel_sha256"],
        codex_closure_sha256=codex_closure_sha256,
        effective_units_sha256=_sha256_bytes(effective_units),
        package_version=record["package_version"],
        broker_probe=probe,
    )


@dataclass(frozen=True, slots=True)
class AuthorMountDescriptor:
    """One already-verified mount authority sent to the fixed broker."""

    mount: SandboxMount
    descriptor: int


type BrokerMount = tuple[int, str, bool, str, str | None, str]
type SystemAuthorMount = tuple[int | str, str, bool]


def _strict_json(data: bytes) -> dict[str, object]:
    def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in values:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    value = json.loads(
        data.decode("utf-8", "strict"),
        object_pairs_hook=pairs,
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-finite number")),
    )
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValueError("frame body must be a JSON object")
    return value


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _remaining(deadline: float) -> float:
    result = deadline - time.monotonic()
    if result <= 0:
        raise TimeoutError("author-service IPC deadline expired")
    return result


def _sendall(connection: socket.socket, data: bytes, deadline: float) -> None:
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        connection.settimeout(_remaining(deadline))
        sent = connection.send(view[offset:])
        if sent <= 0:
            raise ConnectionError("author-service socket closed while sending")
        offset += sent


def _recvall(connection: socket.socket, size: int, deadline: float) -> bytes:
    if size < 0:
        raise ValueError("negative author-service frame size")
    result = bytearray()
    while len(result) < size:
        connection.settimeout(_remaining(deadline))
        chunk = connection.recv(min(65536, size - len(result)))
        if not chunk:
            raise ConnectionError("author-service socket closed before a complete frame")
        result.extend(chunk)
    return bytes(result)


def _send_frame(
    connection: socket.socket,
    header: dict[str, object],
    payload: bytes,
    deadline: float,
) -> None:
    encoded = _json_bytes(header)
    if len(encoded) > AUTHOR_SERVICE_MAX_HEADER_BYTES:
        raise ValueError("author-service response header exceeded its bound")
    _sendall(connection, _PREFIX.pack(_MAGIC_FRAME, len(encoded), len(payload)), deadline)
    _sendall(connection, encoded, deadline)
    _sendall(connection, payload, deadline)


def _receive_frame(
    connection: socket.socket,
    deadline: float,
    *,
    max_payload: int,
) -> tuple[dict[str, object], bytes]:
    magic, header_size, payload_size = _PREFIX.unpack(_recvall(connection, _PREFIX.size, deadline))
    if magic != _MAGIC_FRAME or not 1 <= header_size <= AUTHOR_SERVICE_MAX_HEADER_BYTES:
        raise ValueError("author-service returned an invalid frame prefix")
    if payload_size > max_payload:
        raise ValueError("author-service returned an oversized payload")
    header = _strict_json(_recvall(connection, header_size, deadline))
    return header, _recvall(connection, payload_size, deadline)


def _broker_error_header(
    error: BaseException,
    diagnostic_code: str,
) -> dict[str, object]:
    """Return a bounded error frame without reflecting untrusted exception text."""

    if diagnostic_code not in _BROKER_DIAGNOSTIC_CODES:
        diagnostic_code = "broker_bootstrap"
    if isinstance(error, AgentLoopError):
        reason = error.reason
        detail = error.detail[:4096]
    else:
        reason = StopReason.SANDBOX_SETUP_FAILURE
        detail = "fixed author broker rejected the request"
    return {
        "protocol": AUTHOR_SERVICE_PROTOCOL,
        "kind": "error",
        "reason": reason.value,
        "detail": detail,
        "diagnostic_code": diagnostic_code,
    }


def _raise_broker_error(response: dict[str, object]) -> None:
    """Validate and raise a broker error with its non-secret diagnostic code."""

    if (
        set(response)
        != {
            "protocol",
            "kind",
            "reason",
            "detail",
            "diagnostic_code",
        }
        or response.get("protocol") != AUTHOR_SERVICE_PROTOCOL
        or response.get("kind") != "error"
    ):
        raise fail(StopReason.SANDBOX_SETUP_FAILURE, "author broker error was malformed")
    try:
        reason = StopReason(str(response["reason"]))
    except ValueError:
        raise fail(StopReason.SANDBOX_SETUP_FAILURE, "author broker error was malformed") from None
    detail = response["detail"]
    diagnostic_code = response["diagnostic_code"]
    if (
        not isinstance(detail, str)
        or not detail
        or len(detail) > 4096
        or not isinstance(diagnostic_code, str)
        or diagnostic_code not in _BROKER_DIAGNOSTIC_CODES
    ):
        raise fail(StopReason.SANDBOX_SETUP_FAILURE, "author broker error was malformed")
    raise fail(reason, f"{detail} [broker diagnostic: {diagnostic_code}]")


def _safe_target(value: str) -> str:
    if not isinstance(value, str) or _SYSTEMD_UNSAFE_PATH.search(value):
        raise ValueError("mount target is unsafe for the fixed systemd interface")
    path = PurePosixPath(value)
    if not path.is_absolute() or str(path) in {"/", "."} or str(path) != value:
        raise ValueError("mount target must be a normalized non-root absolute path")
    if ".." in path.parts:
        raise ValueError("mount target contains parent traversal")
    return value


def _mount_header(authorities: Sequence[AuthorMountDescriptor]) -> list[dict[str, object]]:
    if not 1 <= len(authorities) <= AUTHOR_SERVICE_MAX_MOUNTS:
        raise ValueError("author service requires a bounded non-empty mount list")
    result: list[dict[str, object]] = []
    targets: set[str] = set()
    writable = 0
    for authority in authorities:
        if not isinstance(authority, AuthorMountDescriptor):
            raise TypeError("author mount authorities have an invalid type")
        target = _safe_target(authority.mount.target)
        if target in targets:
            raise ValueError("author mount targets must be unique")
        targets.add(target)
        opened = os.fstat(authority.descriptor)
        if not (stat.S_ISDIR(opened.st_mode) or stat.S_ISREG(opened.st_mode)):
            raise ValueError("author mount descriptor has an unsafe type")
        if not authority.mount.read_only:
            writable += 1
            if target != "/control/codex-home" or not stat.S_ISDIR(opened.st_mode):
                raise ValueError("the sole writable author mount must be CODEX_HOME")
        if target == "/control/codex-home":
            closure_kind = "control"
        elif target == "/opt/agent-loop-runtime/agent_loop":
            closure_kind = "python-source"
        elif target in {"/opt/agent-loop-tools/codex", "/opt/agent-loop-tools/codex-package"}:
            closure_kind = "reviewed-install"
        elif _TOOLCHAIN_TARGET.fullmatch(target) is not None:
            closure_kind = "toolchain"
        else:
            raise ValueError("author mount target has no closed descriptor role")
        closure_sha256 = authority.mount.closure_sha256
        root_name = Path(authority.mount.source).name
        if _CLOSURE_ROOT_NAME.fullmatch(root_name) is None:
            raise ValueError("author mount closure root name is unsafe")
        if closure_kind == "control":
            if authority.mount.read_only or closure_sha256 is not None:
                raise ValueError("author control mount cannot carry a closure witness")
        elif (
            not authority.mount.read_only
            or not isinstance(closure_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", closure_sha256) is None
        ):
            raise ValueError("read-only author mounts require an exact closure witness")
        if closure_kind == "toolchain" and target.rsplit("/", 1)[-1] != closure_sha256:
            raise ValueError("toolchain mount target must name its exact closure witness")
        result.append(
            {
                "target": target,
                "read_only": authority.mount.read_only,
                "directory": stat.S_ISDIR(opened.st_mode),
                "device": opened.st_dev,
                "inode": opened.st_ino,
                "mode": stat.S_IFMT(opened.st_mode) | stat.S_IMODE(opened.st_mode),
                "closure_kind": closure_kind,
                "closure_sha256": closure_sha256,
                "root_name": root_name,
            }
        )
    if writable != 1:
        raise ValueError("author service requires exactly one writable CODEX_HOME mount")
    if "/opt/agent-loop-runtime/agent_loop" not in targets:
        raise ValueError("author service requires the reviewed sandbox-init mount")
    return result


def _codex_install_executable(targets: set[str]) -> str:
    file_target = "/opt/agent-loop-tools/codex"
    package_target = "/opt/agent-loop-tools/codex-package"
    selected = targets & {file_target, package_target}
    if len(selected) != 1:
        raise ValueError("author service requires exactly one fixed Codex install target")
    target = selected.pop()
    return target if target == file_target else target + "/bin/codex.js"


def _validate_author_request_shape(parsed: SandboxRequest, targets: set[str]) -> None:
    if (
        parsed.cwd != AUTHOR_CWD
        or parsed.stdin_bytes
        or dict(parsed.env) != build_codex_parent_environment()
    ):
        raise ValueError("fixed author service accepts only the exact Codex environment")
    argv = parsed.argv
    executable = _codex_install_executable(targets)
    if not argv or argv[0] != executable:
        raise ValueError("author request executable is outside the fixed Codex mount")
    status = (
        executable,
        "-c",
        'cli_auth_credentials_store="file"',
        "login",
        "status",
    )
    if argv == status:
        if parsed.manifest.entries:
            raise ValueError("Codex login status may not receive a workspace subject")
        return
    prefix = (
        executable,
        "-a",
        "never",
        "-C",
        AUTHOR_CWD,
        "--add-dir",
        AUTHOR_WORKSPACE,
        "-c",
        f'default_permissions="{AUTHOR_PERMISSION_PROFILE}"',
        "exec",
    )
    if argv[: len(prefix)] != prefix:
        raise ValueError("author request is outside the exact Codex exec grammar")
    suffix = argv[len(prefix) :]
    first = len(suffix) == 4 and suffix[:3] == (
        "--json",
        "--strict-config",
        "--skip-git-repo-check",
    )
    resume = (
        len(suffix) == 6
        and suffix[:4] == ("resume", "--json", "--strict-config", "--skip-git-repo-check")
        and _SAFE_THREAD_ID.fullmatch(suffix[4]) is not None
    )
    prompt = suffix[-1] if suffix else ""
    if not (first or resume) or not prompt or "\x00" in prompt:
        raise ValueError("author request is outside the exact first/resume grammar")


def _limits_json(limits: ServiceLimits) -> dict[str, int]:
    if (
        limits.memory_max_bytes != DEFAULT_MEMORY_MAX_BYTES
        or limits.tasks_max != DEFAULT_TASKS_MAX
        or limits.timeout_stop_seconds != DEFAULT_STOP_TIMEOUT_SECONDS
        or limits.limit_fsize_bytes != DEFAULT_LIMIT_FSIZE_BYTES
        or limits.limit_nofile != DEFAULT_LIMIT_NOFILE
        or limits.cpu_quota_percent != 200
        or limits.runtime_max_seconds > DEFAULT_MAX_RUNTIME_SECONDS
    ):
        raise ValueError("author limits are outside the installed fixed-service contract")
    return {
        "memory_max_bytes": limits.memory_max_bytes,
        "tasks_max": limits.tasks_max,
        "runtime_max_seconds": limits.runtime_max_seconds,
        "timeout_stop_seconds": limits.timeout_stop_seconds,
        "limit_fsize_bytes": limits.limit_fsize_bytes,
        "limit_nofile": limits.limit_nofile,
        "cpu_quota_percent": limits.cpu_quota_percent,
        "output_max_bytes": limits.output_max_bytes,
    }


def _published_mount_source(value: str, *, unit_name: str) -> str:
    """Accept only this request's root-private, host-visible closure path."""

    if not isinstance(value, str) or _SYSTEMD_UNSAFE_PATH.search(value):
        raise ValueError("published author mount source is unsafe")
    source = PurePosixPath(value)
    publication_root = PurePosixPath(AUTHOR_SERVICE_PUBLICATION_ROOT)
    if not source.is_absolute() or str(source) != value or ".." in source.parts:
        raise ValueError("published author mount source is not normalized")
    try:
        relative = source.relative_to(publication_root)
    except ValueError:
        raise ValueError("published author mount escaped its fixed root") from None
    expected_request = unit_name.removesuffix(".service")
    if (
        len(relative.parts) != 3
        or relative.parts[0] != expected_request
        or re.fullmatch(r"mount-[0-9]{2}", relative.parts[1]) is None
        or _CLOSURE_ROOT_NAME.fullmatch(relative.parts[2]) is None
    ):
        raise ValueError("published author mount source has an invalid request identity")
    return value


def build_system_author_argv(
    *,
    unit_name: str,
    broker_unit: str,
    peer_uid: int,
    peer_gid: int,
    workspace_bytes: int,
    mounts: Sequence[SystemAuthorMount],
    limits: ServiceLimits,
    broker_pid: int,
) -> tuple[str, ...]:
    """Generate the complete root-manager unit; callers provide no property text."""

    if _AUTHOR_UNIT.fullmatch(unit_name) is None or _BROKER_UNIT.fullmatch(broker_unit) is None:
        raise ValueError("author or broker unit name is outside the fixed namespace")
    if peer_uid <= 0 or peer_gid <= 0 or broker_pid <= 1:
        raise ValueError("author service requires an unprivileged peer and live broker")
    if not 1 <= workspace_bytes <= DEFAULT_WORKSPACE_BYTES:
        raise ValueError("author workspace exceeds the installed tmpfs ceiling")
    _limits_json(limits)
    properties = [
        "KillMode=control-group",
        "SendSIGKILL=yes",
        f"TimeoutStopSec={limits.timeout_stop_seconds}s",
        "OOMPolicy=kill",
        "CollectMode=inactive-or-failed",
        f"MemoryMax={limits.memory_max_bytes}",
        f"TasksMax={limits.tasks_max}",
        f"RuntimeMaxSec={limits.runtime_max_seconds}s",
        f"LimitFSIZE={limits.limit_fsize_bytes}",
        f"LimitNOFILE={limits.limit_nofile}",
        "LimitCORE=0",
        f"CPUQuota={limits.cpu_quota_percent}%",
        f"BindsTo={broker_unit}",
        f"After={broker_unit}",
        "PrivatePIDs=yes",
        "PrivateIPC=yes",
        "PrivateDevices=yes",
        "ProtectHostname=yes",
        "ProtectProc=invisible",
        "ProcSubset=all",
        "NoNewPrivileges=yes",
        "CapabilityBoundingSet=",
        "AmbientCapabilities=",
        "ProtectKernelTunables=yes",
        "ProtectKernelModules=yes",
        "ProtectControlGroups=yes",
        # systemd 259 implements RestrictSUIDSGID with a seccomp rule that
        # returns ENOSYS for openat2.  sandbox-init requires openat2 for every
        # descriptor-confined workspace operation.  NoNewPrivileges, an empty
        # child capability set, nosuid writable mounts, and a read-only root
        # retain the relevant privilege-escalation boundary without that rule.
        "LockPersonality=yes",
        "RestrictRealtime=yes",
        "UMask=0077",
        "SupplementaryGroups=",
        f"TemporaryFileSystem=/:ro,nodev,nosuid,size={AUTHOR_SERVICE_ROOT_TMPFS_BYTES}",
        # The minimal root is intentionally empty.  Give systemd one small,
        # root-owned staging filesystem on which it can create the destination
        # directories for the reviewed /opt bind mounts below.  The peer UID
        # cannot write this mount, and the actual closures are mounted read-only.
        "TemporaryFileSystem=/opt:nodev,nosuid,size=4194304,mode=0755",
        (
            "TemporaryFileSystem=/runtime:nodev,nosuid,"
            f"size={AUTHOR_SERVICE_RUNTIME_TMPFS_BYTES},mode=0700,uid={peer_uid},gid={peer_gid}"
        ),
        (
            "TemporaryFileSystem=/runtime/author-cwd:nodev,nosuid,"
            f"size=1048576,mode=0700,uid={peer_uid},gid={peer_gid}"
        ),
        (
            "TemporaryFileSystem=/runtime/home:nodev,nosuid,"
            f"size=16777216,mode=0700,uid={peer_uid},gid={peer_gid}"
        ),
        (
            "TemporaryFileSystem=/runtime/tmp:nodev,nosuid,"
            f"size=33554432,mode=0700,uid={peer_uid},gid={peer_gid}"
        ),
        (
            "TemporaryFileSystem=/workspace:nodev,nosuid,"
            f"size={workspace_bytes},mode=0700,uid={peer_uid},gid={peer_gid}"
        ),
        "TemporaryFileSystem=/control:nodev,nosuid,noexec,size=1048576,mode=0755",
        # Codex 0.144.6 materializes bundled skills and the plugin marketplace
        # beneath its control home even when every corresponding feature is
        # disabled.  They are derived cache, not continuity state.  Keep them
        # private and writable for the trusted CLI, but discard them with the
        # author unit.  Auth, rollout/session evidence, and the pinned CLI's
        # small bounded continuity databases remain available for resume.
        (
            "TemporaryFileSystem=/control/codex-home/.tmp:nodev,nosuid,noexec,"
            f"size=268435456,mode=0700,uid={peer_uid},gid={peer_gid}"
        ),
        (
            "TemporaryFileSystem=/control/codex-home/tmp:nodev,nosuid,noexec,"
            f"size=16777216,mode=0700,uid={peer_uid},gid={peer_gid}"
        ),
        (
            "TemporaryFileSystem=/control/codex-home/skills:nodev,nosuid,noexec,"
            f"size=16777216,mode=0700,uid={peer_uid},gid={peer_gid}"
        ),
        (
            "TemporaryFileSystem=/control/codex-home/plugins:nodev,nosuid,noexec,"
            f"size=67108864,mode=0700,uid={peer_uid},gid={peer_gid}"
        ),
        "TemporaryFileSystem=/tmp:nodev,nosuid,size=16777216,mode=1777",
        "TemporaryFileSystem=/run:nodev,nosuid,noexec,size=4194304,mode=0700",
    ]
    for source in ("/usr", "/bin", "/lib", "/lib64", *_FIXED_ETC_BINDS):
        properties.append(f"BindReadOnlyPaths={source}:{source}")
    seen: set[str] = set()
    sources: set[str] = set()
    for authority, raw_target, read_only in mounts:
        target = _safe_target(raw_target)
        if target in seen or not isinstance(read_only, bool):
            raise ValueError("author mount source/target is invalid or duplicated")
        seen.add(target)
        if isinstance(authority, bool):
            raise ValueError("author mount authority has an invalid type")
        if isinstance(authority, int):
            if authority < 3 or read_only or target != "/control/codex-home":
                raise ValueError("only CODEX_HOME may retain a writable descriptor authority")
            source = f"/proc/{broker_pid}/fd/{authority}"
        elif isinstance(authority, str):
            if not read_only:
                raise ValueError("published author closures are read-only")
            source = _published_mount_source(authority, unit_name=unit_name)
        else:
            raise ValueError("author mount authority has an invalid type")
        if source in sources:
            raise ValueError("author mount source is duplicated")
        sources.add(source)
        property_name = "BindReadOnlyPaths" if read_only else "BindPaths"
        properties.append(f"{property_name}={source}:{target}")
    argv = [
        "/usr/bin/systemd-run",
        "--wait",
        "--collect",
        "--pipe",
        "--quiet",
        "--expand-environment=no",
        "--service-type=exec",
        f"--unit={unit_name}",
        f"--uid={peer_uid}",
        f"--gid={peer_gid}",
        "--working-directory=/runtime/author-cwd",
    ]
    argv.extend(f"--property={value}" for value in properties)
    argv.extend(("--", *_FIXED_EXEC_START))
    return tuple(argv)


def _system_environment() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "SYSTEMD_COLORS": "0",
        "TERM": "dumb",
    }


def _systemctl(*args: str, timeout: float = 3.0) -> BoundedProcessResult:
    return run_bounded_process(
        ("/usr/bin/systemctl", *args),
        timeout_seconds=timeout,
        output_max_bytes=128 * 1024,
        env=_system_environment(),
    )


def _kill_system_unit(unit_name: str) -> None:
    if _AUTHOR_UNIT.fullmatch(unit_name) is None:
        raise ValueError("refusing to kill a non-author unit")
    _systemctl("kill", "--kill-whom=all", "--signal=TERM", unit_name)
    time.sleep(0.05)
    _systemctl("kill", "--kill-whom=all", "--signal=KILL", unit_name)


def _control_group_for(unit_name: str) -> str:
    result = _systemctl("show", unit_name, "--property=ControlGroup", "--value")
    if result.returncode != 0 or result.timed_out or result.output_limited:
        return ""
    value = result.stdout.decode("utf-8", "strict").strip()
    return value if value.startswith("/") and ".." not in value.split("/") else ""


def _cgroup_empty(control_group: str) -> bool:
    if not control_group:
        return False
    path = Path("/sys/fs/cgroup") / control_group.lstrip("/")
    try:
        procs = (path / "cgroup.procs").read_bytes()
        events = (path / "cgroup.events").read_text(encoding="ascii")
    except FileNotFoundError:
        return True
    except OSError:
        return False
    populated = dict(line.split(maxsplit=1) for line in events.splitlines()).get("populated")
    return not procs.strip() and populated == "0"


def _author_unit_absent(unit_name: str) -> bool:
    result = _systemctl("show", unit_name, "--property=LoadState", "--value")
    return bool(
        result.returncode == 0
        and not result.timed_out
        and not result.output_limited
        and not result.stderr
        and result.stdout.decode("utf-8", "strict").strip() == "not-found"
    )


def _run_system_author(
    *,
    request: bytes,
    unit_name: str,
    broker_unit: str,
    peer_uid: int,
    peer_gid: int,
    workspace_bytes: int,
    mounts: Sequence[SystemAuthorMount],
    timeout_seconds: float,
    limits: ServiceLimits,
    cancelled: threading.Event,
) -> ServiceResult:
    argv = build_system_author_argv(
        unit_name=unit_name,
        broker_unit=broker_unit,
        peer_uid=peer_uid,
        peer_gid=peer_gid,
        workspace_bytes=workspace_bytes,
        mounts=mounts,
        limits=limits,
        broker_pid=os.getpid(),
    )
    control_group = ""

    def started(_process: subprocess.Popen[bytes]) -> None:
        nonlocal control_group
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and not control_group:
            control_group = _control_group_for(unit_name)
            if not control_group:
                time.sleep(0.02)
        if not control_group:
            raise fail(StopReason.SERVICE_LIFECYCLE_MISMATCH, "author unit cgroup was absent")
        if cancelled.is_set():
            _kill_system_unit(unit_name)
            raise fail(StopReason.USER_INTERRUPT, "author-service peer disconnected")

    process: BoundedProcessResult | None = None
    primary_error: BaseException | None = None
    try:
        process = run_bounded_process(
            argv,
            input_bytes=request,
            timeout_seconds=timeout_seconds + limits.timeout_stop_seconds + 3,
            output_max_bytes=limits.output_max_bytes,
            env=_system_environment(),
            on_abort=lambda: _kill_system_unit(unit_name),
            on_started=started,
        )
    except BoundedProcessStartFailure as exc:
        primary_error = exc.error
    except BaseException as exc:
        primary_error = exc
    finally:
        try:
            _kill_system_unit(unit_name)
        except Exception:
            pass
    deadline = time.monotonic() + limits.timeout_stop_seconds + 2

    def empty_or_absent() -> bool:
        return _cgroup_empty(control_group) if control_group else _author_unit_absent(unit_name)

    while time.monotonic() < deadline and not empty_or_absent():
        time.sleep(0.02)
    empty = empty_or_absent()
    if not empty:
        raise fail(
            StopReason.SERVICE_LIFECYCLE_MISMATCH,
            "fixed author unit cgroup emptiness could not be proven",
        ) from primary_error
    if primary_error is not None:
        raise primary_error
    assert process is not None
    return ServiceResult(
        unit_name, process, {"backend": "fixed-system-author-v1"}, control_group, True
    )


class FixedAuthorServiceClient:
    """Unprivileged client for the one-time-installed fixed author broker."""

    def __init__(
        self,
        *,
        socket_path: str = AUTHOR_SERVICE_SOCKET,
        result_sink: Callable[[ServiceResult], None] | None = None,
        require_root_socket: bool = True,
    ) -> None:
        if not isinstance(socket_path, str) or not socket_path.startswith("/"):
            raise ValueError("author-service socket path must be absolute")
        self.socket_path = socket_path
        self._result_sink = result_sink
        self._require_root_socket = require_root_socket

    def _connect(self, deadline: float) -> socket.socket:
        if self._require_root_socket:
            socket_info = os.lstat(self.socket_path)
            parent_info = os.lstat(os.path.dirname(self.socket_path))
            if (
                not stat.S_ISSOCK(socket_info.st_mode)
                or socket_info.st_uid != os.geteuid()
                or stat.S_IMODE(socket_info.st_mode) != 0o600
                or not stat.S_ISDIR(parent_info.st_mode)
                or parent_info.st_uid != 0
                or stat.S_IMODE(parent_info.st_mode) & 0o022
            ):
                raise ValueError("author-service socket ownership or mode is unsafe")
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
        connection.settimeout(_remaining(deadline))
        connection.connect(self.socket_path)
        peer_pid, peer_uid, _peer_gid = _CREDENTIALS.unpack(
            connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _CREDENTIALS.size)
        )
        if peer_uid != 0 or peer_pid <= 0:
            connection.close()
            raise ValueError("fixed author broker is not a root-owned peer")
        return connection

    def probe(self, *, timeout_seconds: float = 10) -> None:
        """Verify the installed broker without credentials or model traffic."""

        deadline = time.monotonic() + timeout_seconds
        connection: socket.socket | None = None
        try:
            connection = self._connect(deadline)
            header = _json_bytes(
                {
                    "protocol": AUTHOR_SERVICE_PROTOCOL,
                    "kind": "probe",
                    "build_id": AUTHOR_SERVICE_BUILD_ID,
                }
            )
            _sendall(connection, _PREFIX.pack(_MAGIC_REQUEST, len(header), 0), deadline)
            _sendall(connection, header, deadline)
            response, payload = _receive_frame(connection, deadline, max_payload=0)
            if payload or response != {
                "protocol": AUTHOR_SERVICE_PROTOCOL,
                "kind": "probe",
                "build_id": AUTHOR_SERVICE_BUILD_ID,
            }:
                raise ValueError("fixed author broker probe response changed")
        except (OSError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
            raise fail(
                StopReason.SANDBOX_SETUP_FAILURE,
                "fixed author broker is absent, stale, or unsafe; run the one-time "
                "administrator bootstrap",
            ) from exc
        finally:
            if connection is not None:
                connection.close()

    def run_author(
        self,
        *,
        input_bytes: bytes,
        mounts: Sequence[AuthorMountDescriptor],
        workspace_bytes: int,
        timeout_seconds: float,
        limits: ServiceLimits,
    ) -> ServiceResult:
        if (
            not isinstance(input_bytes, bytes)
            or not 1 <= len(input_bytes) <= MAX_PROTOCOL_INPUT_BYTES
        ):
            raise ValueError("author sandbox request is empty or oversized")
        request = parse_request(input_bytes)
        authorities = tuple(mounts)
        mount_header = _mount_header(authorities)
        targets = {str(item["target"]) for item in mount_header}
        _validate_author_request_shape(request, targets)
        header = {
            "protocol": AUTHOR_SERVICE_PROTOCOL,
            "kind": "run",
            "request_bytes": len(input_bytes),
            "request_sha256": hashlib.sha256(input_bytes).hexdigest(),
            "workspace_bytes": workspace_bytes,
            "limits": _limits_json(limits),
            "mounts": mount_header,
        }
        encoded_header = _json_bytes(header)
        if len(encoded_header) > AUTHOR_SERVICE_MAX_HEADER_BYTES:
            raise ValueError("author-service request header exceeded its bound")
        deadline = time.monotonic() + timeout_seconds + limits.timeout_stop_seconds + 10
        descriptors = array.array("i", (authority.descriptor for authority in authorities))
        connection: socket.socket | None = None
        try:
            connection = self._connect(deadline)
            prefix = _PREFIX.pack(_MAGIC_REQUEST, len(encoded_header), len(input_bytes))
            connection.settimeout(_remaining(deadline))
            sent = connection.sendmsg(
                (prefix + encoded_header,),
                [(socket.SOL_SOCKET, socket.SCM_RIGHTS, descriptors)],
            )
            if sent <= 0:
                raise ConnectionError("author-service broker rejected the request header")
            if sent < len(prefix) + len(encoded_header):
                _sendall(connection, (prefix + encoded_header)[sent:], deadline)
            accepted, accepted_payload = _receive_frame(connection, deadline, max_payload=0)
            if accepted.get("kind") == "error":
                _raise_broker_error(accepted)
            if accepted_payload or accepted != {
                "kind": "accepted",
                "protocol": AUTHOR_SERVICE_PROTOCOL,
            }:
                raise ValueError("author-service broker returned an invalid acceptance frame")
            _sendall(connection, input_bytes, deadline)
            response, payload = _receive_frame(
                connection,
                deadline,
                max_payload=MAX_PROTOCOL_EXPORT_BYTES,
            )
        except AgentLoopError:
            raise
        except (OSError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
            raise fail(
                StopReason.SANDBOX_SETUP_FAILURE,
                "fixed author broker is absent, stale, or failed its strict protocol; "
                "run the one-time administrator bootstrap",
            ) from exc
        finally:
            if connection is not None:
                connection.close()
        if response.get("protocol") != AUTHOR_SERVICE_PROTOCOL:
            raise fail(StopReason.SANDBOX_SETUP_FAILURE, "author broker protocol changed")
        if response.get("kind") == "error":
            _raise_broker_error(response)
        expected = {
            "protocol",
            "kind",
            "unit",
            "control_group",
            "returncode",
            "timed_out",
            "output_limited",
            "started_at",
            "completed_at",
            "stdout_bytes",
            "stderr_bytes",
        }
        if set(response) != expected or response.get("kind") != "result":
            raise fail(StopReason.SANDBOX_SETUP_FAILURE, "author broker result was malformed")
        unit = response["unit"]
        group = response["control_group"]
        returncode = response["returncode"]
        timed_out = response["timed_out"]
        output_limited = response["output_limited"]
        started_at = response["started_at"]
        completed_at = response["completed_at"]
        stdout_bytes = response["stdout_bytes"]
        stderr_bytes = response["stderr_bytes"]
        if (
            not isinstance(unit, str)
            or _AUTHOR_UNIT.fullmatch(unit) is None
            or not isinstance(group, str)
            or not group.startswith("/")
            or not isinstance(returncode, int)
            or isinstance(returncode, bool)
            or not isinstance(timed_out, bool)
            or not isinstance(output_limited, bool)
            or not isinstance(started_at, (int, float))
            or isinstance(started_at, bool)
            or not isinstance(completed_at, (int, float))
            or isinstance(completed_at, bool)
            or not isinstance(stdout_bytes, int)
            or isinstance(stdout_bytes, bool)
            or not isinstance(stderr_bytes, int)
            or isinstance(stderr_bytes, bool)
            or min(stdout_bytes, stderr_bytes) < 0
            or stdout_bytes + stderr_bytes != len(payload)
            or not 0 <= float(started_at) <= float(completed_at)
        ):
            raise fail(StopReason.SANDBOX_SETUP_FAILURE, "author broker metadata was malformed")
        process = BoundedProcessResult(
            returncode,
            payload[:stdout_bytes],
            payload[stdout_bytes:],
            float(started_at),
            float(completed_at),
            timed_out,
            output_limited,
        )
        result = ServiceResult(
            unit,
            process,
            {"backend": "fixed-system-author-v1"},
            group,
            True,
        )
        if self._result_sink is not None:
            self._result_sink(result)
        return result


def _receive_request(
    connection: socket.socket,
    deadline: float,
) -> tuple[dict[str, object], list[int], int]:
    connection.settimeout(_remaining(deadline))
    data, ancillary, flags, _address = connection.recvmsg(
        AUTHOR_SERVICE_MAX_HEADER_BYTES + _PREFIX.size,
        socket.CMSG_SPACE(AUTHOR_SERVICE_MAX_MOUNTS * array.array("i").itemsize),
    )
    if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(data) < _PREFIX.size:
        raise ValueError("author-service request header or descriptors were truncated")
    magic, header_size, request_size = _PREFIX.unpack(data[: _PREFIX.size])
    if (
        magic != _MAGIC_REQUEST
        or not 1 <= header_size <= AUTHOR_SERVICE_MAX_HEADER_BYTES
        or request_size > MAX_PROTOCOL_INPUT_BYTES
    ):
        raise ValueError("author-service request prefix is invalid")
    body = bytearray(data[_PREFIX.size :])
    if len(body) < header_size:
        body.extend(_recvall(connection, header_size - len(body), deadline))
    if len(body) != header_size:
        raise ValueError("author-service sent request bytes before broker acceptance")
    descriptors: list[int] = []
    for level, kind, value in ancillary:
        if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
            raise ValueError("author broker rejected unknown ancillary data")
        received = array.array("i")
        received.frombytes(value[: len(value) - (len(value) % received.itemsize)])
        descriptors.extend(received)
    return _strict_json(bytes(body)), descriptors, request_size


def _validate_broker_request(
    header: dict[str, object],
    descriptors: Sequence[int],
    request_size: int,
    *,
    peer_uid: int,
    allowed_codex_closure: str,
    installed_runtime_closure: str,
) -> tuple[int, ServiceLimits, tuple[BrokerMount, ...], str]:
    expected = {
        "protocol",
        "kind",
        "request_bytes",
        "request_sha256",
        "workspace_bytes",
        "limits",
        "mounts",
    }
    if (
        re.fullmatch(r"[0-9a-f]{64}", allowed_codex_closure) is None
        or re.fullmatch(r"[0-9a-f]{64}", installed_runtime_closure) is None
    ):
        raise ValueError("author broker installed closure policy is malformed")
    protocol = header.get("protocol")
    if (
        set(header) != expected
        or not isinstance(protocol, int)
        or isinstance(protocol, bool)
        or protocol != AUTHOR_SERVICE_PROTOCOL
    ):
        raise ValueError("author broker request schema is unsupported")
    request_bytes = header.get("request_bytes")
    if (
        header.get("kind") != "run"
        or not isinstance(request_bytes, int)
        or isinstance(request_bytes, bool)
        or request_bytes != request_size
    ):
        raise ValueError("author broker request length is contradictory")
    digest = header.get("request_sha256")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise ValueError("author broker request digest is invalid")
    workspace = header.get("workspace_bytes")
    if not isinstance(workspace, int) or isinstance(workspace, bool):
        raise ValueError("author broker workspace limit is invalid")
    raw_limits = header.get("limits")
    if not isinstance(raw_limits, dict) or any(not isinstance(key, str) for key in raw_limits):
        raise ValueError("author broker service limits are invalid")
    try:
        limits = ServiceLimits(**raw_limits)
    except TypeError, ValueError:
        raise ValueError("author broker service limits are invalid") from None
    _limits_json(limits)
    raw_mounts = header.get("mounts")
    if not isinstance(raw_mounts, list) or len(raw_mounts) != len(descriptors):
        raise ValueError("author broker mount descriptors do not match metadata")
    mounts: list[BrokerMount] = []
    writable = 0
    targets: set[str] = set()
    identities: set[tuple[int, int]] = set()
    for raw, descriptor in zip(raw_mounts, descriptors, strict=True):
        if not isinstance(raw, dict) or set(raw) != {
            "target",
            "read_only",
            "directory",
            "device",
            "inode",
            "mode",
            "closure_kind",
            "closure_sha256",
            "root_name",
        }:
            raise ValueError("author broker mount metadata is malformed")
        target = _safe_target(raw["target"] if isinstance(raw["target"], str) else "")
        read_only = raw["read_only"]
        directory = raw["directory"]
        numeric_metadata = (raw["device"], raw["inode"], raw["mode"])
        closure_kind = raw["closure_kind"]
        closure_sha256 = raw["closure_sha256"]
        root_name = raw["root_name"]
        if (
            not isinstance(read_only, bool)
            or not isinstance(directory, bool)
            or any(
                not isinstance(value, int) or isinstance(value, bool) for value in numeric_metadata
            )
            or not isinstance(closure_kind, str)
            or not isinstance(root_name, str)
            or _CLOSURE_ROOT_NAME.fullmatch(root_name) is None
            or target in targets
        ):
            raise ValueError("author broker mount flags or target are invalid")
        targets.add(target)
        opened = os.fstat(descriptor)
        expected_identity = (raw["device"], raw["inode"], raw["mode"])
        observed_identity = (
            opened.st_dev,
            opened.st_ino,
            stat.S_IFMT(opened.st_mode) | stat.S_IMODE(opened.st_mode),
        )
        if expected_identity != observed_identity or directory != stat.S_ISDIR(opened.st_mode):
            raise ValueError("author broker mount descriptor identity changed")
        if not (stat.S_ISDIR(opened.st_mode) or stat.S_ISREG(opened.st_mode)):
            raise ValueError("author broker rejected a special mount descriptor")
        if opened.st_uid not in {0, peer_uid}:
            raise ValueError("author broker rejected a foreign-owned mount descriptor")
        if (
            stat.S_IMODE(opened.st_mode) & 0o022
            or opened.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)
            or (stat.S_ISREG(opened.st_mode) and opened.st_nlink != 1)
        ):
            raise ValueError("author broker rejected mutable or specially-moded mount authority")
        try:
            reject_extended_metadata_fd(descriptor)
        except ValueError as exc:
            raise ValueError("author broker rejected mount authority metadata") from exc
        identity = (opened.st_dev, opened.st_ino)
        if identity in identities:
            raise ValueError("author broker rejected duplicate mount authority")
        identities.add(identity)
        os.set_inheritable(descriptor, False)
        if not read_only:
            writable += 1
            if (
                target != "/control/codex-home"
                or not directory
                or opened.st_uid != peer_uid
                or stat.S_IMODE(opened.st_mode) & 0o077
            ):
                raise ValueError("author broker writable control mount is unsafe")
        if target == "/control/codex-home":
            expected_kind = "control"
        elif target == "/opt/agent-loop-runtime/agent_loop":
            expected_kind = "python-source"
        elif target in {"/opt/agent-loop-tools/codex", "/opt/agent-loop-tools/codex-package"}:
            expected_kind = "reviewed-install"
        elif _TOOLCHAIN_TARGET.fullmatch(target) is not None:
            expected_kind = "toolchain"
        else:
            raise ValueError("author broker rejected an unconfigured mount-target class")
        if closure_kind != expected_kind:
            raise ValueError("author broker descriptor role is contradictory")
        if expected_kind == "control":
            if read_only or closure_sha256 is not None:
                raise ValueError("author broker control authority cannot be read-only")
        elif (
            not read_only
            or not isinstance(closure_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", closure_sha256) is None
        ):
            raise ValueError("author broker read-only authority lacks a closure witness")
        if expected_kind == "toolchain" and target.rsplit("/", 1)[-1] != closure_sha256:
            raise ValueError("author broker toolchain target does not match its closure")
        if expected_kind == "python-source" and closure_sha256 != installed_runtime_closure:
            raise ValueError("author broker runtime closure is not the installed closure")
        if expected_kind == "reviewed-install" and closure_sha256 != allowed_codex_closure:
            raise ValueError("author broker Codex closure is not the reviewed install")
        mounts.append((descriptor, target, read_only, closure_kind, closure_sha256, root_name))
    if writable != 1 or "/opt/agent-loop-runtime/agent_loop" not in targets:
        raise ValueError("author broker mount set is incomplete")
    install_executable = _codex_install_executable(targets)
    allowed_targets = {
        "/opt/agent-loop-runtime/agent_loop",
        "/control/codex-home",
        install_executable.removesuffix("/bin/codex.js"),
    }
    if any(
        target not in allowed_targets and _TOOLCHAIN_TARGET.fullmatch(target) is None
        for target in targets
    ):
        raise ValueError("author broker rejected an unconfigured mount-target class")
    return workspace, limits, tuple(mounts), digest


def _safe_publication_directory(
    unit_name: str,
    *,
    publication_root: Path = Path(AUTHOR_SERVICE_PUBLICATION_ROOT),
    owner_uid: int = 0,
    owner_gid: int = 0,
) -> Path:
    """Create one root-private host-visible publication for a broker request."""

    if _AUTHOR_UNIT.fullmatch(unit_name) is None:
        raise ValueError("author publication unit identity is invalid")
    if not publication_root.is_absolute() or publication_root == Path("/"):
        raise ValueError("author publication root is invalid")
    parent = publication_root.parent
    parent_info = os.lstat(parent)
    if (
        not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != owner_uid
        or parent_info.st_gid != owner_gid
        or stat.S_IMODE(parent_info.st_mode) & 0o022
        or os.path.realpath(parent) != os.fspath(parent)
    ):
        raise ValueError("author publication parent is unsafe")
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        reject_extended_metadata_fd(parent_fd)
        try:
            os.mkdir(publication_root.name, 0o700, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except FileExistsError:
            pass
        root_fd = os.open(
            publication_root.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
    finally:
        os.close(parent_fd)
    try:
        root_info = os.fstat(root_fd)
        if (
            root_info.st_uid != owner_uid
            or root_info.st_gid != owner_gid
            or stat.S_IMODE(root_info.st_mode) != 0o700
        ):
            raise ValueError("author publication root is unsafe")
        reject_extended_metadata_fd(root_fd)
        request_name = unit_name.removesuffix(".service")
        os.mkdir(request_name, 0o700, dir_fd=root_fd)
        os.fsync(root_fd)
        request_fd = os.open(
            request_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=root_fd,
        )
        try:
            request_info = os.fstat(request_fd)
            if (
                request_info.st_uid != owner_uid
                or request_info.st_gid != owner_gid
                or stat.S_IMODE(request_info.st_mode) != 0o700
            ):
                raise ValueError("author publication request directory is unsafe")
            reject_extended_metadata_fd(request_fd)
        finally:
            os.close(request_fd)
    finally:
        os.close(root_fd)
    return publication_root / request_name


def _make_publication_removable(descriptor: int, *, owner_uid: int, owner_gid: int) -> None:
    pending = [os.dup(descriptor)]
    try:
        while pending:
            directory_fd = pending.pop()
            try:
                info = os.fstat(directory_fd)
                if (
                    not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != owner_uid
                    or info.st_gid != owner_gid
                    or info.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)
                ):
                    raise ValueError("author publication cleanup encountered unsafe metadata")
                reject_extended_metadata_fd(directory_fd)
                os.fchmod(directory_fd, 0o700)
                for name in os.listdir(directory_fd):
                    raw_name = os.fsencode(name)
                    child = os.stat(raw_name, dir_fd=directory_fd, follow_symlinks=False)
                    if stat.S_ISDIR(child.st_mode):
                        child_fd = os.open(
                            raw_name,
                            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                            dir_fd=directory_fd,
                        )
                        opened = os.fstat(child_fd)
                        if (opened.st_dev, opened.st_ino) != (child.st_dev, child.st_ino):
                            os.close(child_fd)
                            raise ValueError("author publication changed during cleanup")
                        pending.append(child_fd)
                    elif (
                        not stat.S_ISREG(child.st_mode)
                        or child.st_uid != owner_uid
                        or child.st_gid != owner_gid
                        or child.st_nlink != 1
                        or child.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)
                    ):
                        raise ValueError("author publication cleanup rejected an unsafe entry")
                    else:
                        file_fd = os.open(
                            raw_name,
                            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                            dir_fd=directory_fd,
                        )
                        try:
                            reject_extended_metadata_fd(file_fd)
                        finally:
                            os.close(file_fd)
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except BaseException:
        for directory_fd in pending:
            os.close(directory_fd)
        raise


def _remove_closure_publication(
    publication: Path,
    *,
    publication_root: Path = Path(AUTHOR_SERVICE_PUBLICATION_ROOT),
    owner_uid: int = 0,
    owner_gid: int = 0,
) -> None:
    """Descriptor-safely remove one request publication after cgroup emptiness."""

    if not shutil.rmtree.avoids_symlink_attacks or publication.parent != publication_root:
        raise ValueError("safe author publication cleanup is unavailable")
    if _AUTHOR_UNIT.fullmatch(publication.name + ".service") is None:
        raise ValueError("author publication cleanup identity is invalid")
    root_fd = os.open(
        publication_root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        root_info = os.fstat(root_fd)
        if (
            root_info.st_uid != owner_uid
            or root_info.st_gid != owner_gid
            or stat.S_IMODE(root_info.st_mode) != 0o700
        ):
            raise ValueError("author publication root changed before cleanup")
        reject_extended_metadata_fd(root_fd)
        request_fd = os.open(
            publication.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=root_fd,
        )
        try:
            _make_publication_removable(request_fd, owner_uid=owner_uid, owner_gid=owner_gid)
        finally:
            os.close(request_fd)
        shutil.rmtree(os.fsencode(publication.name), dir_fd=root_fd)
        os.fsync(root_fd)
    finally:
        os.close(root_fd)


def _snapshot_broker_mounts(
    mounts: Sequence[BrokerMount],
    *,
    peer_uid: int,
    publication: Path,
) -> tuple[SystemAuthorMount, ...]:
    """Publish read-only closures; retain the live writable CODEX_HOME fd."""

    publication_info = os.lstat(publication)
    if (
        not stat.S_ISDIR(publication_info.st_mode)
        or publication_info.st_uid != 0
        or publication_info.st_gid != 0
        or stat.S_IMODE(publication_info.st_mode) != 0o700
        or os.path.realpath(publication) != os.fspath(publication)
    ):
        raise ValueError("author closure publication is unsafe")
    publication_fd = os.open(
        publication,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        reject_extended_metadata_fd(publication_fd)
    finally:
        os.close(publication_fd)

    selected: list[SystemAuthorMount] = []
    total_entries = 0
    total_bytes = 0
    for index, (descriptor, target, read_only, kind, digest, root_name) in enumerate(mounts):
        remaining_entries = AUTHOR_SERVICE_MAX_CLOSURE_ENTRIES - total_entries
        remaining_bytes = AUTHOR_SERVICE_MAX_CLOSURE_BYTES - total_bytes
        if remaining_entries <= 0 or remaining_bytes <= 0:
            raise ValueError("author broker closure aggregate exceeds its installed limits")
        closure_files = min(remaining_entries, MAX_REVIEWED_CLOSURE_FILES)
        closure_bytes = min(remaining_bytes, MAX_REVIEWED_CLOSURE_BYTES)
        if kind == "control":
            _control_digest, entries, byte_count = descriptor_closure_witness(
                descriptor,
                root_name=root_name.encode("ascii"),
                allowed_owner_uid=peer_uid,
                max_files=closure_files,
                max_bytes=closure_bytes,
            )
            total_entries += entries
            total_bytes += byte_count
            selected.append((descriptor, target, read_only))
            continue
        assert digest is not None
        parent = publication / f"mount-{index:02d}"
        os.mkdir(parent, 0o700)
        snapshot, mounted_digest, entries, byte_count = snapshot_descriptor_closure(
            descriptor,
            parent,
            digest,
            root_name=root_name.encode("ascii"),
            allowed_owner_uid=peer_uid,
            python_sources_only=kind == "python-source",
            max_files=closure_files,
            max_bytes=closure_bytes,
        )
        if mounted_digest != digest:
            raise ValueError("author broker normalized closure digest changed")
        total_entries += entries
        total_bytes += byte_count
        selected.append((os.fspath(snapshot), target, True))
    if (
        total_entries > AUTHOR_SERVICE_MAX_CLOSURE_ENTRIES
        or total_bytes > AUTHOR_SERVICE_MAX_CLOSURE_BYTES
    ):
        raise ValueError("author broker closure aggregate exceeds its installed limits")
    return tuple(selected)


def _validate_probe_request(header: dict[str, object]) -> bool:
    if set(header) != {"protocol", "kind", "build_id"} or header.get("kind") != "probe":
        return False
    protocol = header.get("protocol")
    if (
        not isinstance(protocol, int)
        or isinstance(protocol, bool)
        or protocol != AUTHOR_SERVICE_PROTOCOL
        or header.get("build_id") != AUTHOR_SERVICE_BUILD_ID
    ):
        raise ValueError("author broker probe contract changed")
    return True


def broker_main() -> int:
    """Serve one systemd ``Accept=yes`` connection, then exit."""

    connection = socket.socket(fileno=os.dup(0))
    descriptors: list[int] = []
    publication: Path | None = None
    publication_cleanup_safe = True
    diagnostic_code = "broker_bootstrap"
    try:
        peer_pid, peer_uid, peer_gid = _CREDENTIALS.unpack(
            connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _CREDENTIALS.size)
        )
        allowed_uid_raw = os.environ.get(AUTHOR_ALLOWED_UID_ENV, "")
        try:
            allowed_uid = int(allowed_uid_raw, 10)
        except ValueError:
            raise ValueError("author broker allowed UID is absent or malformed") from None
        if peer_uid != allowed_uid or peer_uid <= 0 or peer_gid <= 0 or peer_pid <= 1:
            raise ValueError("author broker accepts only unprivileged local peers")
        allowed_codex_closure = os.environ.get(AUTHOR_CODEX_CLOSURE_ENV, "")
        if re.fullmatch(r"[0-9a-f]{64}", allowed_codex_closure) is None:
            raise ValueError("author broker reviewed Codex closure is absent or malformed")
        installed_runtime_closure = python_source_closure_sha256(
            Path(AUTHOR_SERVICE_RUNTIME_PACKAGE)
        )
        broker_unit = os.environ.get(AUTHOR_BROKER_UNIT_ENV, "")
        if _BROKER_UNIT.fullmatch(broker_unit) is None:
            raise ValueError("author broker unit identity is absent or malformed")
        deadline = time.monotonic() + 30
        diagnostic_code = "request_frame"
        header, descriptors, request_size = _receive_request(connection, deadline)
        if _validate_probe_request(header):
            if descriptors or request_size:
                raise ValueError("author broker probe carried unexpected authority")
            _send_frame(
                connection,
                {
                    "protocol": AUTHOR_SERVICE_PROTOCOL,
                    "kind": "probe",
                    "build_id": AUTHOR_SERVICE_BUILD_ID,
                },
                b"",
                deadline,
            )
            return 0
        diagnostic_code = "request_policy"
        workspace, limits, mounts, expected_digest = _validate_broker_request(
            header,
            descriptors,
            request_size,
            peer_uid=peer_uid,
            allowed_codex_closure=allowed_codex_closure,
            installed_runtime_closure=installed_runtime_closure,
        )
        unit_name = f"agent-loop-author-{peer_uid}-{uuid.uuid4().hex}.service"
        diagnostic_code = "request_acceptance"
        _send_frame(
            connection,
            {"kind": "accepted", "protocol": AUTHOR_SERVICE_PROTOCOL},
            b"",
            deadline,
        )
        diagnostic_code = "request_payload"
        request = _recvall(connection, request_size, deadline)
        if hashlib.sha256(request).hexdigest() != expected_digest:
            raise ValueError("author broker request changed after acceptance")
        diagnostic_code = "request_shape"
        parsed = parse_request(request)
        deadline = (
            time.monotonic()
            + parsed.limits.timeout_ms / 1_000
            + parsed.limits.terminate_grace_ms / 1_000
            + 15
        )
        targets = {target for _descriptor, target, _read_only, *_metadata in mounts}
        _validate_author_request_shape(parsed, targets)
        diagnostic_code = "closure_snapshot"
        publication = _safe_publication_directory(unit_name)
        snapshot_mounts = _snapshot_broker_mounts(
            mounts,
            peer_uid=peer_uid,
            publication=publication,
        )
        cleanup_allowance_ms = parsed.limits.terminate_grace_ms + 4_000
        expected_runtime = max(1, (parsed.limits.timeout_ms + cleanup_allowance_ms + 999) // 1000)
        diagnostic_code = "limit_contract"
        if (
            limits.runtime_max_seconds != expected_runtime
            or limits.output_max_bytes != parsed.limits.max_export_bytes
        ):
            raise ValueError("author broker request and service limits are incoherent")
        cancelled = threading.Event()

        def monitor() -> None:
            poller = select.poll()
            mask = select.POLLIN | select.POLLHUP | select.POLLERR
            if hasattr(select, "POLLRDHUP"):
                mask |= select.POLLRDHUP
            poller.register(connection, mask)
            if poller.poll():
                cancelled.set()
                try:
                    _kill_system_unit(unit_name)
                except Exception:
                    pass

        watcher = threading.Thread(target=monitor, name="author-peer-watch", daemon=True)
        watcher.start()
        diagnostic_code = "author_launch"
        try:
            service = _run_system_author(
                request=request,
                unit_name=unit_name,
                broker_unit=broker_unit,
                peer_uid=peer_uid,
                peer_gid=peer_gid,
                workspace_bytes=workspace,
                mounts=snapshot_mounts,
                timeout_seconds=parsed.limits.timeout_ms / 1000,
                limits=limits,
                cancelled=cancelled,
            )
        except AgentLoopError as error:
            if error.reason is StopReason.SERVICE_LIFECYCLE_MISMATCH:
                # Never remove a source tree while an author cgroup may still
                # hold it.  The root-private, credential-free publication is
                # intentionally retained for administrator recovery instead.
                publication_cleanup_safe = False
            raise
        diagnostic_code = "closure_cleanup"
        _remove_closure_publication(publication)
        publication = None
        if cancelled.is_set():
            return 2
        diagnostic_code = "result_delivery"
        _send_frame(
            connection,
            {
                "protocol": AUTHOR_SERVICE_PROTOCOL,
                "kind": "result",
                "unit": service.unit_name,
                "control_group": service.control_group,
                "returncode": service.process.returncode,
                "timed_out": service.process.timed_out,
                "output_limited": service.process.output_limited,
                "started_at": service.process.started_at,
                "completed_at": service.process.completed_at,
                "stdout_bytes": len(service.process.stdout),
                "stderr_bytes": len(service.process.stderr),
            },
            service.process.stdout + service.process.stderr,
            deadline,
        )
        return 0
    except AgentLoopError as caught_error:
        response_error: BaseException = caught_error
        if publication is not None and publication_cleanup_safe:
            failure_diagnostic = diagnostic_code
            try:
                _remove_closure_publication(publication)
                publication = None
            except Exception as cleanup_error:
                diagnostic_code = "closure_cleanup"
                response_error = fail(
                    StopReason.SANDBOX_SETUP_FAILURE,
                    "fixed author closure publication cleanup failed",
                )
                response_error.__cause__ = cleanup_error
            else:
                diagnostic_code = failure_diagnostic
        try:
            _send_frame(
                connection,
                _broker_error_header(response_error, diagnostic_code),
                b"",
                time.monotonic() + 2,
            )
        except Exception:
            pass
        return 2
    except Exception as caught_error:
        response_error = caught_error
        if publication is not None and publication_cleanup_safe:
            failure_diagnostic = diagnostic_code
            try:
                _remove_closure_publication(publication)
                publication = None
            except Exception as cleanup_error:
                diagnostic_code = "closure_cleanup"
                response_error = cleanup_error
            else:
                diagnostic_code = failure_diagnostic
        try:
            _send_frame(
                connection,
                _broker_error_header(response_error, diagnostic_code),
                b"",
                time.monotonic() + 2,
            )
        except Exception:
            pass
        return 2
    finally:
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass
        connection.close()


if __name__ == "__main__":
    raise SystemExit(broker_main())
