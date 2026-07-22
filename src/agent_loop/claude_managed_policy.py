"""Reviewed administrator-managed Claude boundary assets.

The pinned Claude CLI intentionally keeps administrator policy enabled in
``--safe-mode``.  Production therefore admits exactly one small managed
``SessionStart`` hook and binds both its policy and executable helper into the
live capability receipt.  The assets are mounted by descriptor-backed closure
witnesses; ordinary ambient Claude configuration is never consulted.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .provenance import closure_sha256
from .sandbox import SandboxMount

MANAGED_CLAUDE_BOUNDARY_PROTOCOL = "attested-v1"
MANAGED_CLAUDE_BOUNDARY_ID = "reviewed-managed-boundary-v1"
MANAGED_CLAUDE_BOUNDARY_MARKER = (
    f"AGENT_LOOP_MANAGED_CLAUDE_BOUNDARY_OK:{MANAGED_CLAUDE_BOUNDARY_ID}:credential_absent:scrub=1"
)
MANAGED_CLAUDE_BOUNDARY_REDACTED_MARKER = (
    f"AGENT_LOOP_MANAGED_CLAUDE_BOUNDARY_OK:{MANAGED_CLAUDE_BOUNDARY_ID}:"
    "credential_absent:[REDACTED]"
)

MANAGED_CLAUDE_POLICY_SOURCE = "/etc/claude-code"
MANAGED_CLAUDE_POLICY_TARGET = "/etc/claude-code"
MANAGED_CLAUDE_POLICY_FILE = "managed-settings.json"
MANAGED_CLAUDE_HELPER_SOURCE = "/usr/local/libexec/agent-loop-claude-boundary-attest"
MANAGED_CLAUDE_HELPER_TARGET = MANAGED_CLAUDE_HELPER_SOURCE

MAX_MANAGED_POLICY_BYTES = 64 * 1024
MAX_MANAGED_POLICY_FILES = 8
MAX_MANAGED_HELPER_BYTES = 1024 * 1024

_ADMIN_UID = 0
_ADMIN_GID = 0
_DIRECTORY_MODES = frozenset({0o555, 0o755})
_POLICY_FILE_MODES = frozenset({0o444, 0o644})
_HELPER_FILE_MODES = frozenset({0o555, 0o755})


def managed_claude_boundary_attested(output: bytes) -> bool:
    """Recognize only the helper marker or pinned Claude's exact redaction.

    Claude 2.1.215 retains the successful exit-2 SessionStart hook message in
    verbose stderr but rewrites the assignment-shaped ``scrub=1`` suffix to
    ``[REDACTED]``.  The root-owned helper closure proves the condition behind
    that marker; this parser deliberately admits neither prefixes nor other
    redaction spellings.
    """

    if not isinstance(output, bytes):
        raise TypeError("managed Claude boundary output must be bytes")
    return any(
        marker.encode("ascii") in output
        for marker in (
            MANAGED_CLAUDE_BOUNDARY_MARKER,
            MANAGED_CLAUDE_BOUNDARY_REDACTED_MARKER,
        )
    )


def managed_claude_policy_document() -> dict[str, object]:
    """Return the only locally managed Claude policy accepted by version 1."""

    return {
        "allowManagedHooksOnly": True,
        "disableAllHooks": False,
        "hooks": {
            "SessionStart": [
                {
                    "matcher": "startup",
                    "hooks": [
                        {
                            "type": "command",
                            "command": MANAGED_CLAUDE_HELPER_TARGET,
                            "args": [],
                            "timeout": 5,
                        }
                    ],
                }
            ]
        },
    }


@dataclass(frozen=True, slots=True)
class ManagedClaudeBoundary:
    """Exact immutable policy/helper mounts admitted to the critic sandbox."""

    policy_mount: SandboxMount
    helper_mount: SandboxMount
    protocol: str = MANAGED_CLAUDE_BOUNDARY_PROTOCOL
    probe_id: str = MANAGED_CLAUDE_BOUNDARY_ID

    def __post_init__(self) -> None:
        expected = (
            (
                self.policy_mount,
                MANAGED_CLAUDE_POLICY_SOURCE,
                MANAGED_CLAUDE_POLICY_TARGET,
                "policy",
            ),
            (
                self.helper_mount,
                MANAGED_CLAUDE_HELPER_SOURCE,
                MANAGED_CLAUDE_HELPER_TARGET,
                "helper",
            ),
        )
        for mount, source, target, name in expected:
            if not isinstance(mount, SandboxMount):
                raise TypeError(f"managed Claude {name} mount must be a SandboxMount")
            if mount.source != source or mount.target != target:
                raise ValueError(f"managed Claude {name} mount path is not the fixed path")
            if not mount.read_only or mount.closure_sha256 is None:
                raise ValueError(
                    f"managed Claude {name} mount must be read-only and closure-witnessed"
                )
        if self.protocol != MANAGED_CLAUDE_BOUNDARY_PROTOCOL:
            raise ValueError("managed Claude boundary protocol is unsupported")
        if self.probe_id != MANAGED_CLAUDE_BOUNDARY_ID:
            raise ValueError("managed Claude boundary probe identifier is unsupported")

    @property
    def policy_sha256(self) -> str:
        witness = self.policy_mount.closure_sha256
        assert witness is not None
        return witness

    @property
    def helper_sha256(self) -> str:
        witness = self.helper_mount.closure_sha256
        assert witness is not None
        return witness


def _metadata_tuple(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _reject_xattrs(path: Path) -> None:
    try:
        attributes = os.listxattr(path, follow_symlinks=False)
    except OSError as exc:
        raise ValueError("managed Claude asset metadata cannot be verified") from exc
    if attributes:
        raise ValueError("managed Claude assets cannot carry extended metadata")


def _verify_root_owned_path(
    path: Path,
    *,
    final_directory: bool,
    final_modes: frozenset[int],
) -> os.stat_result:
    if not path.is_absolute() or path == Path("/") or os.path.realpath(path) != os.fspath(path):
        raise ValueError("managed Claude asset path must be canonical and non-root")

    current = Path("/")
    for index, component in enumerate(path.parts[1:]):
        current /= component
        try:
            info = os.lstat(current)
        except OSError as exc:
            raise ValueError("managed Claude asset is missing") from exc
        final = index == len(path.parts[1:]) - 1
        expected_directory = final_directory if final else True
        if expected_directory:
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError("managed Claude asset directory shape is invalid")
            allowed_modes = final_modes if final else _DIRECTORY_MODES
        else:
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("managed Claude asset file shape is invalid")
            allowed_modes = final_modes
        if info.st_uid != _ADMIN_UID or info.st_gid != _ADMIN_GID:
            raise ValueError("managed Claude assets must be administrator-owned")
        if stat.S_IMODE(info.st_mode) not in allowed_modes:
            raise ValueError("managed Claude asset mode is unsafe")
        if info.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
            raise ValueError("managed Claude asset special mode is unsafe")
        _reject_xattrs(current)
    return os.lstat(path)


def _read_stable_policy(path: Path) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as exc:
        raise ValueError("managed Claude policy cannot be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != _ADMIN_UID
            or before.st_gid != _ADMIN_GID
            or stat.S_IMODE(before.st_mode) not in _POLICY_FILE_MODES
            or before.st_size > MAX_MANAGED_POLICY_BYTES
        ):
            raise ValueError("managed Claude policy file metadata is unsafe")
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, MAX_MANAGED_POLICY_BYTES + 1 - observed))
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            if observed > MAX_MANAGED_POLICY_BYTES:
                raise ValueError("managed Claude policy exceeds its byte limit")
        after = os.fstat(descriptor)
        if observed != before.st_size or _metadata_tuple(before) != _metadata_tuple(after):
            raise ValueError("managed Claude policy changed while being inspected")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _duplicate_rejecting_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("managed Claude policy contains a duplicate property")
        result[key] = value
    return result


def _verify_policy_document(data: bytes) -> None:
    try:
        decoded = data.decode("utf-8", "strict")
        value: object = json.loads(
            decoded,
            object_pairs_hook=_duplicate_rejecting_object,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"unsupported JSON constant {token}")
            ),
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ValueError("managed Claude policy is not strict UTF-8 JSON") from exc
    try:
        observed = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        expected = json.dumps(
            managed_claude_policy_document(),
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("managed Claude policy has unsupported JSON values") from exc
    if observed != expected:
        raise ValueError("managed Claude policy is outside the reviewed closed contract")


def inspect_managed_claude_boundary() -> ManagedClaudeBoundary:
    """Inspect, semantically validate, and hash the fixed admin boundary."""

    policy_root = Path(MANAGED_CLAUDE_POLICY_SOURCE)
    helper = Path(MANAGED_CLAUDE_HELPER_SOURCE)
    _verify_root_owned_path(
        policy_root,
        final_directory=True,
        final_modes=_DIRECTORY_MODES,
    )
    try:
        entries = os.listdir(policy_root)
    except OSError as exc:
        raise ValueError("managed Claude policy directory cannot be listed") from exc
    if entries != [MANAGED_CLAUDE_POLICY_FILE] and set(entries) != {MANAGED_CLAUDE_POLICY_FILE}:
        raise ValueError("managed Claude policy directory contains unexpected entries")
    policy_file = policy_root / MANAGED_CLAUDE_POLICY_FILE
    _verify_root_owned_path(
        policy_file,
        final_directory=False,
        final_modes=_POLICY_FILE_MODES,
    )
    _verify_policy_document(_read_stable_policy(policy_file))

    _verify_root_owned_path(
        helper,
        final_directory=False,
        final_modes=_HELPER_FILE_MODES,
    )
    helper_info = os.lstat(helper)
    if not 1 <= helper_info.st_size <= MAX_MANAGED_HELPER_BYTES:
        raise ValueError("managed Claude helper size is outside its bound")

    policy_digest = closure_sha256(
        policy_root,
        max_files=MAX_MANAGED_POLICY_FILES,
        max_bytes=MAX_MANAGED_POLICY_BYTES,
    )
    helper_digest = closure_sha256(
        helper,
        max_files=1,
        max_bytes=MAX_MANAGED_HELPER_BYTES,
    )
    return ManagedClaudeBoundary(
        policy_mount=SandboxMount(
            MANAGED_CLAUDE_POLICY_SOURCE,
            MANAGED_CLAUDE_POLICY_TARGET,
            read_only=True,
            closure_sha256=policy_digest,
        ),
        helper_mount=SandboxMount(
            MANAGED_CLAUDE_HELPER_SOURCE,
            MANAGED_CLAUDE_HELPER_TARGET,
            read_only=True,
            closure_sha256=helper_digest,
        ),
    )


__all__ = [
    "MANAGED_CLAUDE_BOUNDARY_ID",
    "MANAGED_CLAUDE_BOUNDARY_MARKER",
    "MANAGED_CLAUDE_BOUNDARY_PROTOCOL",
    "MANAGED_CLAUDE_BOUNDARY_REDACTED_MARKER",
    "MANAGED_CLAUDE_HELPER_SOURCE",
    "MANAGED_CLAUDE_HELPER_TARGET",
    "MANAGED_CLAUDE_POLICY_FILE",
    "MANAGED_CLAUDE_POLICY_SOURCE",
    "MANAGED_CLAUDE_POLICY_TARGET",
    "ManagedClaudeBoundary",
    "inspect_managed_claude_boundary",
    "managed_claude_boundary_attested",
    "managed_claude_policy_document",
]
