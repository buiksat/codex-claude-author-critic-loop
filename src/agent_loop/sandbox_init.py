"""Trusted in-namespace supervisor and strict sandbox protocol version 1.

The production entry point is the initial process in Bubblewrap's PID
namespace.  It materializes a canonical subject, launches exactly one reviewed
argv, tears down and reaps every descendant, proves the namespace empty, and
only then scans and exports the candidate state.
"""

from __future__ import annotations

import base64
import binascii
import ctypes
import errno
import json
import os
import resource
import selectors
import signal
import subprocess
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import Any, Final, Never

from .constants import (
    DEFAULT_MAX_AGENT_OUTPUT_BYTES,
    DEFAULT_MAX_FIELD_BYTES,
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_PATH_BYTES,
    DEFAULT_MAX_PATH_DEPTH,
    DEFAULT_MAX_RUNTIME_SECONDS,
    DEFAULT_MAX_TOTAL_SUBJECT_BYTES,
    DEFAULT_TASKS_MAX,
    SANDBOX_PROTOCOL_VERSION,
    Limits,
)
from .errors import AgentLoopError, StopReason, fail
from .filesystem import ConfinedFilesystem
from .manifests import SubjectManifest, build_manifest_from_scan
from .models import BlobReader, BlobWriter, EntryKind, sha256_hex
from .validation_batch import (
    MAX_VALIDATION_BATCH_RESULT_BYTES,
    MAX_VALIDATION_CHECKS,
    VALIDATION_BATCH_SENTINEL,
    ValidationBatchRecord,
    encode_validation_batch_result,
    parse_validation_batch_request,
)

_LIBC = ctypes.CDLL(None, use_errno=True)
_LIBC.prctl.restype = ctypes.c_int
_LIBC.ptrace.restype = ctypes.c_long

PR_SET_DUMPABLE: Final = 4
PR_SET_CHILD_SUBREAPER: Final = 36
PR_GET_CHILD_SUBREAPER: Final = 37

PTRACE_TRACEME: Final = 0
PTRACE_PEEKTEXT: Final = 1
PTRACE_GETREGS: Final = 12
PTRACE_SETREGS: Final = 13
PTRACE_DETACH: Final = 17
PTRACE_SYSCALL: Final = 24
SYS_PRCTL_X86_64: Final = 157
_SYSCALL_INSTRUCTION: Final = b"\x0f\x05"

MAX_ARGV_ITEMS: Final = 256
MAX_ENV_ITEMS: Final = 64
MAX_ARGV_BYTES: Final = 256 * 1024
MAX_ENV_BYTES: Final = 256 * 1024
MAX_TERMINATE_GRACE_MS: Final = 5_000
MAX_STDIN_BYTES: Final = DEFAULT_MAX_AGENT_OUTPUT_BYTES
_BASE64_SUBJECT_CEILING: Final = ((DEFAULT_MAX_TOTAL_SUBJECT_BYTES + 2) // 3) * 4
MAX_PROTOCOL_INPUT_BYTES: Final = _BASE64_SUBJECT_CEILING + 16 * 1024 * 1024
MAX_PROTOCOL_EXPORT_BYTES: Final = MAX_PROTOCOL_INPUT_BYTES
MIN_PROTOCOL_EXPORT_BYTES: Final = DEFAULT_MAX_FIELD_BYTES + 1024

_ALLOWED_CWDS = frozenset(
    {
        "/workspace",
        "/runtime/author-cwd",
        "/runtime/critic-cwd",
        "/runtime/git-cwd",
    }
)
_ALLOWED_ENV = frozenset(
    {
        "PATH",
        "HOME",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "TZ",
        "TERM",
        "CODEX_HOME",
        "CLAUDE_CODE_OAUTH_TOKEN",
        "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB",
        "CLAUDE_CODE_MAX_RETRIES",
        "API_TIMEOUT_MS",
        "MAX_STRUCTURED_OUTPUT_RETRIES",
        "CLAUDE_CONFIG_DIR",
        "CLAUDE_CODE_TMPDIR",
    }
)
_FIXED_ENV_VALUES = {
    "PATH": frozenset({"/usr/bin:/bin", "/usr/local/bin:/usr/bin:/bin"}),
    "HOME": frozenset({"/runtime/home"}),
    "TMPDIR": frozenset({"/runtime/tmp"}),
    "LANG": frozenset({"C.UTF-8"}),
    "LC_ALL": frozenset({"C.UTF-8"}),
    "TZ": frozenset({"UTC"}),
    "CODEX_HOME": frozenset({"/control/codex-home"}),
    "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": frozenset({"1"}),
    "CLAUDE_CODE_MAX_RETRIES": frozenset({"2"}),
    "API_TIMEOUT_MS": frozenset({"300000"}),
    "MAX_STRUCTURED_OUTPUT_RETRIES": frozenset({"1"}),
    "CLAUDE_CONFIG_DIR": frozenset({"/control/claude-home"}),
    "CLAUDE_CODE_TMPDIR": frozenset({"/runtime/critic-tmp"}),
}
_VALIDATION_BATCH_ENVIRONMENT = {
    "PATH": "/usr/bin:/bin",
    "HOME": "/runtime/home",
    "TMPDIR": "/runtime/tmp",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TZ": "UTC",
}


class _X86Registers(ctypes.Structure):
    _fields_ = [  # noqa: RUF012 - ctypes requires this mutable class descriptor
        (name, ctypes.c_ulonglong)
        for name in (
            "r15",
            "r14",
            "r13",
            "r12",
            "rbp",
            "rbx",
            "r11",
            "r10",
            "r9",
            "r8",
            "rax",
            "rcx",
            "rdx",
            "rsi",
            "rdi",
            "orig_rax",
            "rip",
            "cs",
            "eflags",
            "rsp",
            "ss",
            "fs_base",
            "gs_base",
            "ds",
            "es",
            "fs",
            "gs",
        )
    ]


def _protocol_error(detail: str) -> Never:
    raise fail(StopReason.SANDBOX_SETUP_FAILURE, f"sandbox protocol: {detail}")


def _strict_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _protocol_error(f"duplicate property {key!r}")
        result[key] = value
    return result


def _parse_json(data: bytes, *, max_bytes: int = MAX_PROTOCOL_INPUT_BYTES) -> dict[str, Any]:
    if not isinstance(data, bytes):
        raise TypeError("protocol input must be bytes")
    if len(data) > max_bytes:
        _protocol_error("input exceeded the absolute byte ceiling")
    try:
        text = data.decode("utf-8", "strict")
        value = json.loads(
            text,
            object_pairs_hook=_strict_object_pairs,
            parse_constant=lambda token: _protocol_error(f"non-finite number {token!r}"),
        )
    except AgentLoopError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        _protocol_error(f"input is not one strict UTF-8 JSON object: {exc}")
    if not isinstance(value, dict):
        _protocol_error("top-level input must be an object")
    return value


def _closed_object(value: object, expected: set[str], where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        _protocol_error(f"{where} must be an object with string keys")
    keys = set(value)
    missing = expected - keys
    unknown = keys - expected
    if missing or unknown:
        _protocol_error(
            f"{where} has missing keys {sorted(missing)!r} and unknown keys {sorted(unknown)!r}"
        )
    return value


def _bounded_int(value: object, *, where: str, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        _protocol_error(f"{where} must be an integer in [{minimum}, {maximum}]")
    return value


def _canonical_b64(value: object, *, where: str, max_decoded_bytes: int) -> bytes:
    if not isinstance(value, str):
        _protocol_error(f"{where} must be a base64 string")
    try:
        encoded = value.encode("ascii")
        decoded = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        _protocol_error(f"{where} is invalid base64: {exc}")
    if base64.b64encode(decoded) != encoded:
        _protocol_error(f"{where} is not canonical base64")
    if len(decoded) > max_decoded_bytes:
        _protocol_error(f"{where} exceeds its decoded byte limit")
    return decoded


@dataclass(frozen=True, slots=True)
class SupervisorLimits:
    timeout_ms: int
    terminate_grace_ms: int
    max_output_bytes: int
    max_export_bytes: int
    subject: Limits


@dataclass(frozen=True, slots=True)
class SandboxRequest:
    manifest: SubjectManifest
    blobs: tuple[tuple[str, bytes], ...]
    argv: tuple[str, ...]
    env: tuple[tuple[str, str], ...]
    cwd: str
    stdin_bytes: bytes
    limits: SupervisorLimits

    @property
    def environment(self) -> dict[str, str]:
        return dict(self.env)


@dataclass(frozen=True, slots=True)
class PrimaryResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    output_limited: bool
    duration_ms: int


@dataclass(frozen=True, slots=True)
class CleanupResult:
    terminated_pids: int
    namespace_empty: bool


@dataclass(frozen=True, slots=True)
class SandboxResult:
    base_fingerprint: str
    candidate: SubjectManifest
    new_blobs: tuple[tuple[str, bytes], ...]
    process: PrimaryResult
    cleanup: CleanupResult

    def to_json_obj(self) -> dict[str, object]:
        return {
            "protocol_version": SANDBOX_PROTOCOL_VERSION,
            "kind": "result",
            "base_fingerprint": self.base_fingerprint,
            "process": {
                "returncode": self.process.returncode,
                "timed_out": self.process.timed_out,
                "output_limited": self.process.output_limited,
                "duration_ms": self.process.duration_ms,
                "stdout_b64": base64.b64encode(self.process.stdout).decode("ascii"),
                "stderr_b64": base64.b64encode(self.process.stderr).decode("ascii"),
            },
            "cleanup": {
                "terminated_pids": self.cleanup.terminated_pids,
                "namespace_empty": self.cleanup.namespace_empty,
                "export_started_after_cleanup": True,
            },
            "candidate_manifest": self.candidate.to_json_obj(),
            "new_blobs": [
                {
                    "sha256": digest,
                    "data_b64": base64.b64encode(data).decode("ascii"),
                }
                for digest, data in self.new_blobs
            ],
        }


@dataclass(frozen=True, slots=True)
class SandboxErrorResponse:
    reason: StopReason
    detail: str


class _MemoryBlobs(BlobReader, BlobWriter):
    def __init__(self, values: Mapping[str, bytes]) -> None:
        self.values = dict(values)

    def read_blob(self, sha256: str) -> bytes:
        try:
            return self.values[sha256]
        except KeyError as exc:
            raise fail(StopReason.OUT_OF_BAND_CHANGE, "manifest references a missing blob") from exc

    def put_blob(self, data: bytes) -> str:
        digest = sha256_hex(data)
        existing = self.values.get(digest)
        if existing is not None and existing != data:
            raise fail(StopReason.OUT_OF_BAND_CHANGE, "SHA-256 blob identity collision")
        self.values[digest] = data
        return digest


def _parse_limits(value: object) -> SupervisorLimits:
    raw = _closed_object(
        value,
        {
            "timeout_ms",
            "terminate_grace_ms",
            "max_output_bytes",
            "max_export_bytes",
            "max_files",
            "max_file_bytes",
            "max_total_subject_bytes",
            "max_path_bytes",
            "max_path_depth",
        },
        "limits",
    )
    timeout_ms = _bounded_int(
        raw["timeout_ms"],
        where="limits.timeout_ms",
        minimum=1,
        maximum=DEFAULT_MAX_RUNTIME_SECONDS * 1000,
    )
    terminate_grace_ms = _bounded_int(
        raw["terminate_grace_ms"],
        where="limits.terminate_grace_ms",
        minimum=1,
        maximum=MAX_TERMINATE_GRACE_MS,
    )
    max_output_bytes = _bounded_int(
        raw["max_output_bytes"],
        where="limits.max_output_bytes",
        minimum=1,
        maximum=MAX_VALIDATION_BATCH_RESULT_BYTES,
    )
    max_export_bytes = _bounded_int(
        raw["max_export_bytes"],
        where="limits.max_export_bytes",
        minimum=MIN_PROTOCOL_EXPORT_BYTES,
        maximum=MAX_PROTOCOL_EXPORT_BYTES,
    )
    max_files = _bounded_int(
        raw["max_files"],
        where="limits.max_files",
        minimum=1,
        maximum=DEFAULT_MAX_FILES,
    )
    max_file_bytes = _bounded_int(
        raw["max_file_bytes"],
        where="limits.max_file_bytes",
        minimum=1,
        maximum=DEFAULT_MAX_FILE_BYTES,
    )
    max_total_subject_bytes = _bounded_int(
        raw["max_total_subject_bytes"],
        where="limits.max_total_subject_bytes",
        minimum=1,
        maximum=DEFAULT_MAX_TOTAL_SUBJECT_BYTES,
    )
    max_path_bytes = _bounded_int(
        raw["max_path_bytes"],
        where="limits.max_path_bytes",
        minimum=1,
        maximum=DEFAULT_MAX_PATH_BYTES,
    )
    max_path_depth = _bounded_int(
        raw["max_path_depth"],
        where="limits.max_path_depth",
        minimum=1,
        maximum=DEFAULT_MAX_PATH_DEPTH,
    )
    return SupervisorLimits(
        timeout_ms=timeout_ms,
        terminate_grace_ms=terminate_grace_ms,
        max_output_bytes=max_output_bytes,
        max_export_bytes=max_export_bytes,
        subject=Limits(
            max_files=max_files,
            max_file_bytes=max_file_bytes,
            max_total_subject_bytes=max_total_subject_bytes,
            max_path_bytes=max_path_bytes,
            max_path_depth=max_path_depth,
        ),
    )


def parse_request(data: bytes) -> SandboxRequest:
    """Parse and locally validate one complete protocol request."""

    value = _parse_json(data)
    raw = _closed_object(
        value,
        {
            "protocol_version",
            "kind",
            "manifest",
            "blobs",
            "argv",
            "env",
            "cwd",
            "stdin_b64",
            "limits",
        },
        "request",
    )
    protocol_version = raw["protocol_version"]
    if (
        not isinstance(protocol_version, int)
        or isinstance(protocol_version, bool)
        or protocol_version != SANDBOX_PROTOCOL_VERSION
    ):
        _protocol_error("unsupported protocol_version")
    if not isinstance(raw["kind"], str) or raw["kind"] != "request":
        _protocol_error("request.kind must be 'request'")
    limits = _parse_limits(raw["limits"])
    try:
        manifest = SubjectManifest.from_json_obj(raw["manifest"], limits=limits.subject)
    except (TypeError, ValueError) as exc:
        _protocol_error(f"manifest is invalid: {exc}")

    raw_blobs = raw["blobs"]
    if not isinstance(raw_blobs, list) or len(raw_blobs) > limits.subject.max_files:
        _protocol_error("blobs must be an array within max_files")
    blobs: dict[str, bytes] = {}
    total_blob_bytes = 0
    for index, raw_blob in enumerate(raw_blobs):
        item = _closed_object(raw_blob, {"sha256", "data_b64"}, f"blobs[{index}]")
        digest = item["sha256"]
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            _protocol_error(f"blobs[{index}].sha256 is not a lowercase SHA-256 digest")
        if digest in blobs:
            _protocol_error(f"blobs[{index}] duplicates a blob identity")
        decoded = _canonical_b64(
            item["data_b64"],
            where=f"blobs[{index}].data_b64",
            max_decoded_bytes=limits.subject.max_file_bytes,
        )
        if sha256_hex(decoded) != digest:
            _protocol_error(f"blobs[{index}] bytes do not match sha256")
        total_blob_bytes += len(decoded)
        if total_blob_bytes > limits.subject.max_total_subject_bytes:
            _protocol_error("blob bytes exceed max_total_subject_bytes")
        blobs[digest] = decoded

    required_blobs = {
        entry.blob_sha256
        for entry in manifest.entries
        if entry.kind is EntryKind.REGULAR
    }
    if set(blobs) != required_blobs:
        _protocol_error("blobs must exactly match the regular files referenced by manifest")

    raw_argv = raw["argv"]
    if not isinstance(raw_argv, list) or not raw_argv or len(raw_argv) > MAX_ARGV_ITEMS:
        _protocol_error("argv must be a non-empty bounded array")
    argv: list[str] = []
    argv_bytes = 0
    for index, item in enumerate(raw_argv):
        if not isinstance(item, str) or not item or "\x00" in item:
            _protocol_error(f"argv[{index}] must be a non-empty NUL-free string")
        try:
            encoded = item.encode("utf-8")
        except UnicodeEncodeError as exc:
            _protocol_error(f"argv[{index}] contains an invalid Unicode scalar: {exc}")
        if len(encoded) > DEFAULT_MAX_FIELD_BYTES:
            _protocol_error(f"argv[{index}] exceeds its field limit")
        argv_bytes += len(encoded)
        if argv_bytes > MAX_ARGV_BYTES:
            _protocol_error("argv exceeds its aggregate byte limit")
        argv.append(item)
    executable = PurePosixPath(argv[0])
    if (
        not executable.is_absolute()
        or argv[0].startswith("//")
        or str(executable) != argv[0]
        or ".." in executable.parts
    ):
        _protocol_error("argv[0] must be an absolute normalized executable path")

    raw_env = raw["env"]
    if not isinstance(raw_env, Mapping) or any(not isinstance(key, str) for key in raw_env):
        _protocol_error("env must be an object with string keys")
    if len(raw_env) > MAX_ENV_ITEMS:
        _protocol_error("env has too many properties")
    env: list[tuple[str, str]] = []
    env_bytes = 0
    for key in sorted(raw_env):
        item = raw_env[key]
        if key not in _ALLOWED_ENV:
            _protocol_error(f"env property {key!r} is not allowlisted")
        if not isinstance(item, str) or "\x00" in item:
            _protocol_error(f"env.{key} must be a NUL-free string")
        try:
            encoded_value = item.encode("utf-8")
        except UnicodeEncodeError as exc:
            _protocol_error(f"env.{key} contains an invalid Unicode scalar: {exc}")
        if len(encoded_value) > DEFAULT_MAX_FIELD_BYTES:
            _protocol_error(f"env.{key} exceeds its field limit")
        accepted_values = _FIXED_ENV_VALUES.get(key)
        if accepted_values is not None and item not in accepted_values:
            _protocol_error(f"env.{key} is outside its fixed sandbox value set")
        if key == "CLAUDE_CODE_OAUTH_TOKEN" and not item:
            _protocol_error("env.CLAUDE_CODE_OAUTH_TOKEN cannot be empty")
        env_bytes += len(key) + len(encoded_value)
        if env_bytes > MAX_ENV_BYTES:
            _protocol_error("env exceeds its aggregate byte limit")
        env.append((key, item))

    cwd = raw["cwd"]
    if not isinstance(cwd, str) or cwd not in _ALLOWED_CWDS:
        _protocol_error("cwd is not one of the fixed sandbox working directories")
    stdin_bytes = _canonical_b64(
        raw["stdin_b64"],
        where="stdin_b64",
        max_decoded_bytes=MAX_STDIN_BYTES,
    )
    selected_argv = tuple(argv)
    is_validation_batch = selected_argv == (VALIDATION_BATCH_SENTINEL,)
    if VALIDATION_BATCH_SENTINEL in selected_argv and not is_validation_batch:
        _protocol_error("the validation-batch sentinel requires its exact reserved argv")
    if is_validation_batch:
        if (
            cwd != "/workspace"
            or dict(env) != _VALIDATION_BATCH_ENVIRONMENT
            or limits.max_output_bytes != MAX_VALIDATION_BATCH_RESULT_BYTES
        ):
            _protocol_error("the validation-batch request has a broadened execution shape")
        try:
            parse_validation_batch_request(stdin_bytes)
        except ValueError as exc:
            _protocol_error(f"validation-batch request is invalid: {exc}")
    elif limits.max_output_bytes > DEFAULT_MAX_AGENT_OUTPUT_BYTES:
        _protocol_error("ordinary primary output exceeds the agent-output ceiling")
    return SandboxRequest(
        manifest=manifest,
        blobs=tuple(sorted(blobs.items())),
        argv=selected_argv,
        env=tuple(env),
        cwd=cwd,
        stdin_bytes=stdin_bytes,
        limits=limits,
    )


def encode_request(request: SandboxRequest) -> bytes:
    """Encode a parsed request deterministically for tests and outer runners."""

    value = {
        "protocol_version": SANDBOX_PROTOCOL_VERSION,
        "kind": "request",
        "manifest": request.manifest.to_json_obj(),
        "blobs": [
            {"sha256": digest, "data_b64": base64.b64encode(data).decode("ascii")}
            for digest, data in request.blobs
        ],
        "argv": list(request.argv),
        "env": dict(request.env),
        "cwd": request.cwd,
        "stdin_b64": base64.b64encode(request.stdin_bytes).decode("ascii"),
        "limits": {
            "timeout_ms": request.limits.timeout_ms,
            "terminate_grace_ms": request.limits.terminate_grace_ms,
            "max_output_bytes": request.limits.max_output_bytes,
            "max_export_bytes": request.limits.max_export_bytes,
            "max_files": request.limits.subject.max_files,
            "max_file_bytes": request.limits.subject.max_file_bytes,
            "max_total_subject_bytes": request.limits.subject.max_total_subject_bytes,
            "max_path_bytes": request.limits.subject.max_path_bytes,
            "max_path_depth": request.limits.subject.max_path_depth,
        },
    }
    return _json_bytes(value)


def parse_response(
    data: bytes,
    *,
    request: SandboxRequest,
) -> SandboxResult | SandboxErrorResponse:
    """Strictly parse supervisor stdout and bind it to the originating request."""

    value = _parse_json(data, max_bytes=request.limits.max_export_bytes)
    protocol_version = value.get("protocol_version")
    if (
        not isinstance(protocol_version, int)
        or isinstance(protocol_version, bool)
        or protocol_version != SANDBOX_PROTOCOL_VERSION
    ):
        _protocol_error("response has an unsupported protocol_version")
    kind = value.get("kind")
    if kind == "error":
        raw = _closed_object(value, {"protocol_version", "kind", "error"}, "error response")
        error = _closed_object(raw["error"], {"reason", "detail"}, "error response.error")
        reason_value = error["reason"]
        detail = error["detail"]
        if not isinstance(reason_value, str):
            _protocol_error("error response reason must be a string")
        try:
            reason = StopReason(reason_value)
        except ValueError as exc:
            _protocol_error("error response reason is not a known stop reason")
        if not isinstance(detail, str):
            _protocol_error("error response detail must be a string")
        try:
            detail_size = len(detail.encode("utf-8"))
        except UnicodeEncodeError as exc:
            _protocol_error(f"error response detail has invalid Unicode: {exc}")
        if detail_size > DEFAULT_MAX_FIELD_BYTES:
            _protocol_error("error response detail exceeds its byte limit")
        return SandboxErrorResponse(reason, detail)
    if kind != "result":
        _protocol_error("response.kind must be 'result' or 'error'")
    validation_batch = request.argv == (VALIDATION_BATCH_SENTINEL,)

    raw = _closed_object(
        value,
        {
            "protocol_version",
            "kind",
            "base_fingerprint",
            "process",
            "cleanup",
            "candidate_manifest",
            "new_blobs",
        },
        "result response",
    )
    if raw["base_fingerprint"] != request.manifest.fingerprint:
        _protocol_error("result base_fingerprint does not match its request")
    process_raw = _closed_object(
        raw["process"],
        {
            "returncode",
            "timed_out",
            "output_limited",
            "duration_ms",
            "stdout_b64",
            "stderr_b64",
        },
        "result response.process",
    )
    returncode = process_raw["returncode"]
    if not isinstance(returncode, int) or isinstance(returncode, bool):
        _protocol_error("process.returncode must be an integer")
    timed_out = process_raw["timed_out"]
    output_limited = process_raw["output_limited"]
    if not isinstance(timed_out, bool) or not isinstance(output_limited, bool):
        _protocol_error("process timeout/output flags must be booleans")
    duration_ms = _bounded_int(
        process_raw["duration_ms"],
        where="process.duration_ms",
        minimum=0,
        # Cleanup has independent bounded waits for SIGKILL/reap and pipe EOF.
        maximum=request.limits.timeout_ms + request.limits.terminate_grace_ms + 4_000,
    )
    stdout = _canonical_b64(
        process_raw["stdout_b64"],
        where="process.stdout_b64",
        max_decoded_bytes=request.limits.max_output_bytes,
    )
    stderr = _canonical_b64(
        process_raw["stderr_b64"],
        where="process.stderr_b64",
        max_decoded_bytes=request.limits.max_output_bytes,
    )
    if len(stdout) + len(stderr) > request.limits.max_output_bytes:
        _protocol_error("combined process output exceeds max_output_bytes")

    cleanup_raw = _closed_object(
        raw["cleanup"],
        {"terminated_pids", "namespace_empty", "export_started_after_cleanup"},
        "result response.cleanup",
    )
    terminated_pids = _bounded_int(
        cleanup_raw["terminated_pids"],
        where="cleanup.terminated_pids",
        minimum=0,
        maximum=DEFAULT_TASKS_MAX * (MAX_VALIDATION_CHECKS if validation_batch else 1),
    )
    if cleanup_raw["namespace_empty"] is not True:
        _protocol_error("result cannot export without namespace emptiness")
    if cleanup_raw["export_started_after_cleanup"] is not True:
        _protocol_error("result claims export before cleanup")

    try:
        candidate = SubjectManifest.from_json_obj(
            raw["candidate_manifest"],
            limits=request.limits.subject,
        )
    except (TypeError, ValueError) as exc:
        _protocol_error(f"candidate_manifest is invalid: {exc}")
    raw_new_blobs = raw["new_blobs"]
    if not isinstance(raw_new_blobs, list) or len(raw_new_blobs) > request.limits.subject.max_files:
        _protocol_error("new_blobs must be an array within max_files")
    new_blobs: dict[str, bytes] = {}
    total_new_bytes = 0
    previous_digest: str | None = None
    for index, raw_blob in enumerate(raw_new_blobs):
        item = _closed_object(raw_blob, {"sha256", "data_b64"}, f"new_blobs[{index}]")
        digest = item["sha256"]
        if not isinstance(digest, str) or len(digest) != 64:
            _protocol_error(f"new_blobs[{index}].sha256 is invalid")
        if any(character not in "0123456789abcdef" for character in digest):
            _protocol_error(f"new_blobs[{index}].sha256 is invalid")
        if previous_digest is not None and digest <= previous_digest:
            _protocol_error("new_blobs must be uniquely sorted by digest")
        previous_digest = digest
        blob = _canonical_b64(
            item["data_b64"],
            where=f"new_blobs[{index}].data_b64",
            max_decoded_bytes=request.limits.subject.max_file_bytes,
        )
        if sha256_hex(blob) != digest:
            _protocol_error(f"new_blobs[{index}] bytes do not match sha256")
        total_new_bytes += len(blob)
        if total_new_bytes > request.limits.subject.max_total_subject_bytes:
            _protocol_error("new_blobs exceed max_total_subject_bytes")
        new_blobs[digest] = blob

    input_blobs = dict(request.blobs)
    candidate_digests = {
        entry.blob_sha256
        for entry in candidate.entries
        if entry.kind is EntryKind.REGULAR
    }
    expected_new = candidate_digests - set(input_blobs)
    if validation_batch:
        if new_blobs:
            _protocol_error("validation-batch results cannot export disposable blob bytes")
    elif set(new_blobs) != expected_new:
        _protocol_error("new_blobs do not exactly cover new candidate content")
    for entry in candidate.entries:
        if entry.kind is EntryKind.SYMLINK:
            continue
        assert entry.blob_sha256 is not None and entry.size is not None
        blob = input_blobs.get(entry.blob_sha256, new_blobs.get(entry.blob_sha256))
        if blob is None and validation_batch:
            continue
        if blob is None or len(blob) != entry.size or sha256_hex(blob) != entry.blob_sha256:
            _protocol_error("candidate regular entry is not backed by verified blob bytes")

    return SandboxResult(
        base_fingerprint=request.manifest.fingerprint,
        candidate=candidate,
        new_blobs=tuple(sorted(new_blobs.items())),
        process=PrimaryResult(
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            timed_out=timed_out,
            output_limited=output_limited,
            duration_ms=duration_ms,
        ),
        cleanup=CleanupResult(terminated_pids, True),
    )


def parse_result(data: bytes, *, request: SandboxRequest) -> SandboxResult:
    """Parse one response and raise its typed remote error when not a result."""

    response = parse_response(data, request=request)
    if isinstance(response, SandboxErrorResponse):
        raise fail(response.reason, response.detail)
    return response


def _prctl(option: int, argument: int) -> None:
    ctypes.set_errno(0)
    result = _LIBC.prctl(
        ctypes.c_int(option),
        ctypes.c_ulong(argument),
        ctypes.c_ulong(0),
        ctypes.c_ulong(0),
        ctypes.c_ulong(0),
    )
    if result != 0:
        error_number = ctypes.get_errno()
        raise fail(
            StopReason.SANDBOX_SETUP_FAILURE,
            f"required prctl({option}) failed with errno {error_number}",
        )


def _trace_me_before_exec() -> None:
    """Stop at successful exec so the supervisor can harden the new image."""

    ctypes.set_errno(0)
    result = _LIBC.ptrace(
        ctypes.c_uint(PTRACE_TRACEME),
        ctypes.c_int(0),
        ctypes.c_void_p(),
        ctypes.c_void_p(),
    )
    if result != 0:
        raise OSError(ctypes.get_errno(), "PTRACE_TRACEME failed")


def _ptrace(
    request: int,
    pid: int,
    *,
    address: int = 0,
    data: object = 0,
) -> int:
    ctypes.set_errno(0)
    data_argument: object
    if isinstance(data, int):
        data_argument = ctypes.c_void_p(data)
    else:
        data_argument = data
    result = int(
        _LIBC.ptrace(
            ctypes.c_uint(request),
            ctypes.c_int(pid),
            ctypes.c_void_p(address),
            data_argument,
        )
    )
    error_number = ctypes.get_errno()
    if result == -1 and error_number != 0:
        raise fail(
            StopReason.SANDBOX_SETUP_FAILURE,
            f"required ptrace request {request} failed with errno {error_number}",
        )
    return result


def _kill_failed_exec_hardening(process: subprocess.Popen[bytes]) -> None:
    try:
        os.kill(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        os.waitpid(process.pid, 0)
    except ChildProcessError:
        pass
    process.returncode = -signal.SIGKILL


def _vdso_syscall_address(pid: int) -> int:
    try:
        mappings = Path(f"/proc/{pid}/maps").read_text(encoding="ascii")
    except OSError as exc:
        raise fail(
            StopReason.SANDBOX_SETUP_FAILURE,
            "could not inspect the primary vDSO mapping",
        ) from exc
    for line in mappings.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) != 6 or fields[5] != "[vdso]" or "x" not in fields[1]:
            continue
        try:
            start_text, end_text = fields[0].split("-", 1)
            start = int(start_text, 16)
            end = int(end_text, 16)
        except ValueError as exc:
            raise fail(
                StopReason.SANDBOX_SETUP_FAILURE,
                "primary vDSO mapping has an invalid address range",
            ) from exc
        if end <= start or end - start > 1024 * 1024:
            raise fail(
                StopReason.SANDBOX_SETUP_FAILURE,
                "primary vDSO mapping is outside its reviewed size bound",
            )
        image = bytearray()
        word_size = ctypes.sizeof(ctypes.c_long)
        for address in range(start, end, word_size):
            word = _ptrace(PTRACE_PEEKTEXT, pid, address=address)
            image.extend((word & ((1 << (word_size * 8)) - 1)).to_bytes(word_size, "little"))
        offset = bytes(image[: end - start]).find(_SYSCALL_INSTRUCTION)
        if offset >= 0:
            return start + offset
    raise fail(
        StopReason.SANDBOX_SETUP_FAILURE,
        "primary vDSO lacks the reviewed syscall instruction",
    )


def _harden_primary_after_exec(process: subprocess.Popen[bytes]) -> None:
    """Inject ``prctl(PR_SET_DUMPABLE, 0)`` before primary user code runs.

    Linux resets dumpability while replacing a process image, so merely setting
    it in a fork pre-exec hook does not protect the trusted control process from
    a same-UID generated child.  On the frozen x86-64 platform the supervisor
    traces the exec stop, executes one reviewed syscall through the kernel vDSO,
    then restores the untouched registers before detaching.  No primary memory
    is modified.
    """

    if os.uname().machine != "x86_64":
        _kill_failed_exec_hardening(process)
        raise fail(
            StopReason.SANDBOX_SETUP_FAILURE,
            "post-exec dumpability hardening is pinned to x86_64",
        )
    detached = False
    saved = _X86Registers()
    try:
        waited_pid, status = os.waitpid(process.pid, os.WUNTRACED)
        if (
            waited_pid != process.pid
            or not os.WIFSTOPPED(status)
            or os.WSTOPSIG(status) != signal.SIGTRAP
        ):
            raise fail(
                StopReason.SANDBOX_SETUP_FAILURE,
                "primary did not produce the required post-exec trace stop",
            )
        _ptrace(PTRACE_GETREGS, process.pid, data=ctypes.pointer(saved))
        syscall_address = _vdso_syscall_address(process.pid)
        syscall_registers = _X86Registers()
        ctypes.memmove(ctypes.byref(syscall_registers), ctypes.byref(saved), ctypes.sizeof(saved))
        syscall_registers.rax = SYS_PRCTL_X86_64
        syscall_registers.orig_rax = (1 << 64) - 1
        syscall_registers.rip = syscall_address
        syscall_registers.rdi = PR_SET_DUMPABLE
        syscall_registers.rsi = 0
        syscall_registers.rdx = 0
        syscall_registers.r10 = 0
        syscall_registers.r8 = 0
        _ptrace(
            PTRACE_SETREGS,
            process.pid,
            data=ctypes.pointer(syscall_registers),
        )
        _ptrace(PTRACE_SYSCALL, process.pid)
        waited_pid, status = os.waitpid(process.pid, os.WUNTRACED)
        if (
            waited_pid != process.pid
            or not os.WIFSTOPPED(status)
            or os.WSTOPSIG(status) != signal.SIGTRAP
        ):
            raise fail(
                StopReason.SANDBOX_SETUP_FAILURE,
                "primary did not stop at the dumpability syscall entry",
            )
        _ptrace(PTRACE_SYSCALL, process.pid)
        waited_pid, status = os.waitpid(process.pid, os.WUNTRACED)
        if (
            waited_pid != process.pid
            or not os.WIFSTOPPED(status)
            or os.WSTOPSIG(status) != signal.SIGTRAP
        ):
            raise fail(
                StopReason.SANDBOX_SETUP_FAILURE,
                "primary did not stop at the dumpability syscall exit",
            )
        observed = _X86Registers()
        _ptrace(PTRACE_GETREGS, process.pid, data=ctypes.pointer(observed))
        syscall_result = ctypes.c_longlong(observed.rax).value
        _ptrace(PTRACE_SETREGS, process.pid, data=ctypes.pointer(saved))
        _ptrace(PTRACE_DETACH, process.pid)
        detached = True
        if syscall_result != 0:
            raise fail(
                StopReason.SANDBOX_SETUP_FAILURE,
                f"primary dumpability hardening returned {syscall_result}",
            )
    except BaseException:
        if not detached:
            try:
                _ptrace(PTRACE_SETREGS, process.pid, data=ctypes.pointer(saved))
            except BaseException:
                pass
            try:
                _ptrace(PTRACE_DETACH, process.pid)
            except BaseException:
                pass
        _kill_failed_exec_hardening(process)
        raise


def _prepare_supervisor() -> None:
    _prctl(PR_SET_CHILD_SUBREAPER, 1)
    observed = ctypes.c_int(0)
    ctypes.set_errno(0)
    if _LIBC.prctl(PR_GET_CHILD_SUBREAPER, ctypes.byref(observed), 0, 0, 0) != 0:
        _protocol_error("could not verify child-subreaper state")
    if observed.value != 1:
        _protocol_error("child-subreaper state was not enabled")
    _prctl(PR_SET_DUMPABLE, 0)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)


def _visible_pids() -> set[int]:
    try:
        names = os.listdir("/proc")
    except OSError as exc:
        raise fail(StopReason.AUTHOR_SERVICE_NOT_EMPTY, "cannot enumerate namespace /proc") from exc
    return {int(name) for name in names if name.isascii() and name.isdigit()}


def _process_parent(pid: int) -> int | None:
    try:
        data = Path(f"/proc/{pid}/status").read_text(encoding="ascii")
    except (FileNotFoundError, ProcessLookupError):
        return None
    except OSError as exc:
        raise fail(
            StopReason.AUTHOR_SERVICE_NOT_EMPTY,
            f"cannot inspect descendant pid {pid}",
        ) from exc
    for line in data.splitlines():
        if line.startswith("PPid:"):
            try:
                return int(line.split(":", 1)[1].strip())
            except ValueError as exc:
                raise fail(
                    StopReason.AUTHOR_SERVICE_NOT_EMPTY,
                    f"invalid PPid for descendant {pid}",
                ) from exc
    raise fail(StopReason.AUTHOR_SERVICE_NOT_EMPTY, f"missing PPid for descendant {pid}")


def _descendant_pids() -> set[int]:
    supervisor_pid = os.getpid()
    visible = _visible_pids() - {supervisor_pid}
    if supervisor_pid == 1:
        return visible
    parents = {pid: _process_parent(pid) for pid in visible}
    descendants: set[int] = set()
    changed = True
    while changed:
        changed = False
        for pid, parent in parents.items():
            if pid not in descendants and (parent == supervisor_pid or parent in descendants):
                descendants.add(pid)
                changed = True
    return descendants


def _signal_processes(pids: set[int], selected_signal: signal.Signals) -> None:
    for pid in sorted(pids, reverse=True):
        try:
            os.kill(pid, selected_signal)
        except ProcessLookupError:
            pass
        except PermissionError as exc:
            raise fail(
                StopReason.AUTHOR_SERVICE_NOT_EMPTY,
                f"permission denied killing descendant pid {pid}",
            ) from exc


def _reap_adopted_children() -> None:
    while True:
        try:
            pid, _status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid <= 0:
            return


def _terminate_descendants(
    primary: subprocess.Popen[bytes],
    *,
    grace_ms: int,
) -> CleanupResult:
    terminated: set[int] = set()
    try:
        os.killpg(primary.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + grace_ms / 1000
    while time.monotonic() < deadline:
        descendants = _descendant_pids()
        terminated.update(descendants)
        _signal_processes(descendants, signal.SIGTERM)
        primary_status = primary.poll()
        if primary_status is not None:
            _reap_adopted_children()
        if not _descendant_pids():
            break
        time.sleep(0.01)

    remaining = _descendant_pids()
    terminated.update(remaining)
    try:
        os.killpg(primary.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    _signal_processes(remaining, signal.SIGKILL)
    try:
        primary.wait(timeout=1.0)
    except subprocess.TimeoutExpired as exc:
        raise fail(
            StopReason.AUTHOR_SERVICE_NOT_EMPTY,
            "primary did not exit after SIGKILL",
        ) from exc

    proof_deadline = time.monotonic() + 1.0
    while time.monotonic() < proof_deadline:
        _reap_adopted_children()
        remaining = _descendant_pids()
        if not remaining:
            return CleanupResult(len(terminated), True)
        terminated.update(remaining)
        _signal_processes(remaining, signal.SIGKILL)
        time.sleep(0.01)
    raise fail(
        StopReason.AUTHOR_SERVICE_NOT_EMPTY,
        f"could not prove descendant emptiness; remaining={sorted(_descendant_pids())!r}",
    )


def _append_bounded(
    target: bytearray,
    chunk: bytes,
    *,
    stdout: bytearray,
    stderr: bytearray,
    maximum: int,
) -> bool:
    available = maximum - len(stdout) - len(stderr)
    if available <= 0:
        return bool(chunk)
    target.extend(chunk[:available])
    return len(chunk) > available


def _drain_after_cleanup(
    selector: selectors.BaseSelector,
    stdout: bytearray,
    stderr: bytearray,
    maximum: int,
) -> bool:
    limited = False
    deadline = time.monotonic() + 1.0
    while selector.get_map() and time.monotonic() < deadline:
        events = selector.select(0.05)
        for key, _mask in events:
            if key.data == "stdin":
                selector.unregister(key.fileobj)
                key.fileobj.close()
                continue
            try:
                chunk = os.read(key.fileobj.fileno(), 65536)
            except BlockingIOError:
                continue
            if not chunk:
                selector.unregister(key.fileobj)
                key.fileobj.close()
                continue
            target = stdout if key.data == "stdout" else stderr
            limited |= _append_bounded(
                target,
                chunk,
                stdout=stdout,
                stderr=stderr,
                maximum=maximum,
            )
    if selector.get_map():
        raise fail(
            StopReason.AUTHOR_SERVICE_NOT_EMPTY,
            "primary pipes did not close after descendant cleanup",
        )
    return limited


def _close_primary_resources(
    selector: selectors.BaseSelector | None,
    process: subprocess.Popen[bytes] | None,
    primary_error: BaseException | None,
) -> None:
    """Close every post-spawn resource without replacing an active failure."""

    cleanup_failures: list[tuple[str, BaseException]] = []
    if selector is not None:
        try:
            selector.close()
        except BaseException as cleanup_error:
            cleanup_failures.append(("selector", cleanup_error))
    if process is not None:
        for name, stream in (
            ("stdin", process.stdin),
            ("stdout", process.stdout),
            ("stderr", process.stderr),
        ):
            try:
                if stream is not None and not stream.closed:
                    stream.close()
            except BaseException as cleanup_error:
                cleanup_failures.append((f"{name} pipe", cleanup_error))

    if not cleanup_failures:
        return
    if primary_error is not None:
        for resource_name, cleanup_error in cleanup_failures:
            primary_error.add_note(
                f"post-spawn {resource_name} close also failed: "
                f"{type(cleanup_error).__name__}"
            )
        return

    resource_name, cleanup_error = cleanup_failures[0]
    for secondary_name, secondary_error in cleanup_failures[1:]:
        cleanup_error.add_note(
            f"post-spawn {secondary_name} close also failed: "
            f"{type(secondary_error).__name__}"
        )
    cleanup_error.add_note(f"post-spawn cleanup failed while closing {resource_name}")
    raise cleanup_error


def _run_primary(request: SandboxRequest, workspace: Path) -> tuple[PrimaryResult, CleanupResult]:
    _prepare_supervisor()
    cwd = os.fspath(workspace) if request.cwd == "/workspace" else request.cwd
    started = time.monotonic()
    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    stdout = bytearray()
    stderr = bytearray()
    timed_out = False
    output_limited = False
    cleanup: CleanupResult | None = None
    primary_error: BaseException | None = None
    deadline = started + request.limits.timeout_ms / 1000
    try:
        try:
            process = subprocess.Popen(
                request.argv,
                stdin=subprocess.PIPE if request.stdin_bytes else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd,
                env=request.environment,
                close_fds=True,
                start_new_session=True,
                bufsize=0,
                # The supervisor is single-threaded; this hook only requests the
                # kernel's deterministic exec stop and performs no Python I/O.
                preexec_fn=_trace_me_before_exec,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise fail(
                StopReason.SANDBOX_SETUP_FAILURE,
                f"could not launch the traced primary: {type(exc).__name__}",
            ) from exc
        # Every operation after Popen is inside this cleanup guard.  In
        # particular, ptrace hardening, pipe setup, selector construction, and
        # asynchronous operator interruption cannot strand the primary.
        _harden_primary_after_exec(process)
        assert process.stdout is not None and process.stderr is not None
        os.set_blocking(process.stdout.fileno(), False)
        os.set_blocking(process.stderr.fileno(), False)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        input_view = memoryview(request.stdin_bytes)
        input_offset = 0
        if process.stdin is not None:
            os.set_blocking(process.stdin.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
        while process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            for key, mask in selector.select(min(remaining, 0.05)):
                stream = key.fileobj
                if key.data == "stdin" and mask & selectors.EVENT_WRITE:
                    try:
                        written = os.write(
                            stream.fileno(),
                            input_view[input_offset : input_offset + 65536],
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
                    output_limited |= _append_bounded(
                        target,
                        chunk,
                        stdout=stdout,
                        stderr=stderr,
                        maximum=request.limits.max_output_bytes,
                    )
                    if output_limited:
                        break
            if output_limited:
                break

        cleanup = _terminate_descendants(
            process,
            grace_ms=request.limits.terminate_grace_ms,
        )
        output_limited |= _drain_after_cleanup(
            selector,
            stdout,
            stderr,
            request.limits.max_output_bytes,
        )
    except BaseException as error:
        primary_error = error
        if process is not None and cleanup is None:
            try:
                _terminate_descendants(process, grace_ms=request.limits.terminate_grace_ms)
            except BaseException as cleanup_error:
                error.add_note(
                    "post-spawn descendant cleanup also failed: "
                    f"{type(cleanup_error).__name__}"
                )
        raise
    finally:
        _close_primary_resources(selector, process, primary_error)

    assert process is not None
    assert cleanup is not None
    return (
        PrimaryResult(
            returncode=process.returncode,
            stdout=bytes(stdout),
            stderr=bytes(stderr),
            timed_out=timed_out,
            output_limited=output_limited,
            duration_ms=max(0, int((time.monotonic() - started) * 1000)),
        ),
        cleanup,
    )


def _trim_validation_output(
    stdout: bytes,
    stderr: bytes,
    maximum: int,
) -> tuple[bytes, bytes, bool]:
    if len(stdout) + len(stderr) <= maximum:
        return stdout, stderr, False
    retained_stdout = stdout[:maximum]
    remaining = maximum - len(retained_stdout)
    return retained_stdout, stderr[:remaining], True


def _run_validation_batch(
    request: SandboxRequest,
    workspace: Path,
) -> tuple[PrimaryResult, CleanupResult]:
    try:
        batch = parse_validation_batch_request(request.stdin_bytes)
    except ValueError as exc:
        raise fail(
            StopReason.SANDBOX_SETUP_FAILURE,
            "validation-batch request failed strict validation",
        ) from exc
    started = time.monotonic()
    deadline = started + request.limits.timeout_ms / 1_000
    remaining_raw = batch.max_raw_output_bytes
    records: list[ValidationBatchRecord] = []
    terminated_pids = 0
    for index, check in enumerate(batch.checks):
        remaining_ms = max(0, int((deadline - time.monotonic()) * 1_000))
        if remaining_ms == 0:
            records.append(
                ValidationBatchRecord(index, 0, True, False, False, 0, b"", b"")
            )
            break
        child_output_max = min(check.output_max_bytes, max(1, remaining_raw + 1))
        child_limits = replace(
            request.limits,
            timeout_ms=min(check.timeout_ms, remaining_ms),
            max_output_bytes=child_output_max,
        )
        child_request = replace(
            request,
            argv=(
                "/usr/bin/bash",
                "--noprofile",
                "--norc",
                "-c",
                check.command,
            ),
            cwd="/workspace",
            stdin_bytes=b"",
            limits=child_limits,
        )
        process, cleanup = _run_primary(child_request, workspace)
        terminated_pids += cleanup.terminated_pids
        stdout, stderr, raw_limited = _trim_validation_output(
            process.stdout,
            process.stderr,
            remaining_raw,
        )
        remaining_raw -= len(stdout) + len(stderr)
        output_limited = process.output_limited or raw_limited
        records.append(
            ValidationBatchRecord(
                index,
                process.returncode,
                process.timed_out,
                output_limited,
                True,
                process.duration_ms,
                stdout,
                stderr,
            )
        )
        if (
            process.timed_out
            or output_limited
            or process.returncode < 0
            or process.returncode in {126, 127}
        ):
            break
    try:
        encoded = encode_validation_batch_result(tuple(records))
    except ValueError as exc:
        raise fail(
            StopReason.AGENT_OUTPUT_LIMIT,
            "validation-batch result exceeded its trusted protocol bound",
        ) from exc
    return (
        PrimaryResult(
            returncode=0,
            stdout=encoded,
            stderr=b"",
            timed_out=False,
            output_limited=False,
            duration_ms=max(0, int((time.monotonic() - started) * 1_000)),
        ),
        CleanupResult(terminated_pids, True),
    )


def execute_request(
    request: SandboxRequest,
    *,
    workspace: str | bytes | os.PathLike[str] | os.PathLike[bytes] = "/workspace",
) -> SandboxResult:
    """Execute one request; candidate export is unreachable before cleanup proof."""

    workspace_path = Path(os.fsdecode(os.fspath(workspace)))
    input_blobs = _MemoryBlobs(dict(request.blobs))
    with ConfinedFilesystem.open(workspace_path) as filesystem:
        filesystem.materialize_manifest(
            request.manifest,
            input_blobs,
            limits=request.limits.subject,
        )
        verified_blobs = _MemoryBlobs({})
        verified_base = build_manifest_from_scan(
            filesystem.scan_records(limits=request.limits.subject),
            verified_blobs,
            limits=request.limits.subject,
        )
        if verified_base.fingerprint != request.manifest.fingerprint:
            raise fail(
                StopReason.OUT_OF_BAND_CHANGE,
                "materialized base fingerprint differs before primary launch",
            )

        if request.argv == (VALIDATION_BATCH_SENTINEL,):
            process, cleanup = _run_validation_batch(request, workspace_path)
        else:
            process, cleanup = _run_primary(request, workspace_path)
        if not cleanup.namespace_empty:
            raise fail(
                StopReason.AUTHOR_SERVICE_NOT_EMPTY,
                "candidate export was blocked because cleanup was not proven",
            )

        exported_blobs = _MemoryBlobs({})
        candidate = build_manifest_from_scan(
            filesystem.scan_records(limits=request.limits.subject),
            exported_blobs,
            limits=request.limits.subject,
        )

    original_digests = set(dict(request.blobs))
    new_blobs = (
        ()
        if request.argv == (VALIDATION_BATCH_SENTINEL,)
        else tuple(
            (digest, data)
            for digest, data in sorted(exported_blobs.values.items())
            if digest not in original_digests
        )
    )
    result = SandboxResult(
        base_fingerprint=request.manifest.fingerprint,
        candidate=candidate,
        new_blobs=new_blobs,
        process=process,
        cleanup=cleanup,
    )
    encoded = _json_bytes(result.to_json_obj())
    if len(encoded) > request.limits.max_export_bytes:
        raise fail(
            StopReason.AGENT_OUTPUT_LIMIT,
            "sandbox export exceeded max_export_bytes",
        )
    return result


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii") + b"\n"


def encode_result(result: SandboxResult, *, max_bytes: int) -> bytes:
    data = _json_bytes(result.to_json_obj())
    if len(data) > max_bytes:
        raise fail(StopReason.AGENT_OUTPUT_LIMIT, "sandbox result exceeds export byte limit")
    return data


def _error_bytes(error: BaseException) -> bytes:
    if isinstance(error, AgentLoopError):
        reason = error.reason.value
        detail = error.detail
    else:
        reason = StopReason.RUNNER_INTERNAL_ERROR.value
        detail = f"{type(error).__name__}: supervisor operation failed"
    detail_bytes = detail.encode("utf-8", "backslashreplace")[:DEFAULT_MAX_FIELD_BYTES]
    safe_detail = detail_bytes.decode("utf-8", "ignore")

    def render(selected_detail: str) -> bytes:
        return _json_bytes(
            {
                "protocol_version": SANDBOX_PROTOCOL_VERSION,
                "kind": "error",
                "error": {"reason": reason, "detail": selected_detail},
            }
        )

    encoded = render(safe_detail)
    if len(encoded) <= MIN_PROTOCOL_EXPORT_BYTES:
        return encoded
    lower = 0
    upper = len(safe_detail)
    while lower < upper:
        middle = (lower + upper + 1) // 2
        if len(render(safe_detail[:middle])) <= MIN_PROTOCOL_EXPORT_BYTES:
            lower = middle
        else:
            upper = middle - 1
    return render(safe_detail[:lower])


def _read_stdin_bounded() -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(0, min(1024 * 1024, MAX_PROTOCOL_INPUT_BYTES - total + 1))
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_PROTOCOL_INPUT_BYTES:
            _protocol_error("stdin exceeded the absolute protocol byte ceiling")
        chunks.append(chunk)
    return b"".join(chunks)


def _write_stdout(data: bytes) -> None:
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        written = os.write(1, view[offset:])
        if written <= 0:
            raise OSError(errno.EIO, "short protocol write")
        offset += written


def main(argv: list[str] | None = None) -> int:
    """Console callable for ``python -m agent_loop.sandbox_init``."""

    if argv is None:
        argv = sys.argv[1:]
    if argv:
        _write_stdout(_error_bytes(ValueError("sandbox-init takes no arguments")))
        return 2
    request: SandboxRequest | None = None
    try:
        raw = _read_stdin_bounded()
        try:
            os.close(0)
        except OSError:
            pass
        request = parse_request(raw)
        result = execute_request(request)
        _write_stdout(encode_result(result, max_bytes=request.limits.max_export_bytes))
        return 0
    except BaseException as exc:
        try:
            _write_stdout(_error_bytes(exc))
        except OSError:
            return 3
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
