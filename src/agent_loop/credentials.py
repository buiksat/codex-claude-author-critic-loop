"""Account-scoped credential transactions and Claude token isolation.

Credential bytes are deliberately absent from every exception detail and from
all transaction metadata.  Callers must treat returned tokens and the Codex
transaction home as control-plane secrets and must never mount them into an
untrusted execution path.
"""

from __future__ import annotations

import fcntl
import grp
import hashlib
import json
import os
import pwd
import re
import shutil
import stat
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Self

from .constants import PRIVATE_DIR_MODE, PRIVATE_FILE_MODE
from .errors import AgentLoopError, StopReason, fail
from .filesystem import ConfinedFilesystem, open_beneath, validate_relative_path

AuthParser = Callable[[bytes], bool]
AuthProbe = Callable[[Path], bool]
EvidenceBarrier = Callable[[str, tuple[bytes, ...]], None]
GenerationParser = Callable[[bytes], tuple[int, ...] | None]

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TRANSACTION_SCHEMA_VERSION = 1
_MAX_AUTH_BYTES = 4 * 1024 * 1024
_MAX_AUTH_GENERATION_HISTORY = 256
_MAX_AUTH_GENERATION_HISTORY_BYTES = 16 * _MAX_AUTH_BYTES
_MAX_TOKEN_BYTES = 64 * 1024
_MAX_CLAUDE_CREDENTIAL_BYTES = 4 * 1024 * 1024
_MAX_METADATA_BYTES = 16 * 1024
_LOCK_POLL_SECONDS = 0.01
_STATUS_LOCK_TIMEOUT_SECONDS = 0.05
_DEFAULT_PROFILE_METADATA = b"default-profile.json"
_DEFAULT_PROFILE_TRANSITION = b"default-profile-transition.json"
_DEFAULT_PROFILE_SCHEMA_VERSION = 1
_DEFAULT_PROFILE_TRANSITION_SCHEMA_VERSION = 1
_CODEX_REFRESH_TIMESTAMP = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$"
)
DEFAULT_CODEX_CREDENTIAL_ID = "default"
DEFAULT_CLAUDE_CREDENTIAL_ID = "default"


@dataclass(frozen=True, slots=True)
class CredentialEnrollment:
    """Content-free result from one idempotent credential enrollment."""

    credential_id: str
    installed: bool


@dataclass(frozen=True, slots=True)
class DefaultCredentialEnrollment:
    """Result of optional default-profile discovery before a normal run."""

    codex: CredentialEnrollment | None
    claude: CredentialEnrollment | None


@dataclass(slots=True)
class _LockedCredentialAccount:
    """One private account filesystem with its exclusive lock held."""

    filesystem: ConfinedFilesystem
    lock_fd: int

    def close(self) -> None:
        try:
            fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(self.lock_fd)
            self.filesystem.close()


@dataclass(frozen=True, slots=True)
class _DefaultPairTransition:
    """Non-secret journal binding one old and new default credential pair."""

    codex_run_id: str
    claude_run_id: str
    old_codex_sha256: str
    old_claude_sha256: str
    new_codex_sha256: str
    new_claude_sha256: str


def _safe_identifier(value: str, *, name: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{name} is not a safe identifier")
    if value in {".", ".."}:
        raise ValueError(f"{name} is not a safe identifier")
    return value


def _normalized_absolute(path: str | os.PathLike[str], *, name: str) -> Path:
    raw = os.fspath(path)
    if not isinstance(raw, str):
        raise TypeError(f"{name} must use a text filesystem path")
    candidate = Path(raw)
    if not candidate.is_absolute() or raw == "/":
        raise ValueError(f"{name} must be a normalized absolute path")
    if raw.startswith("//") or raw.endswith("/"):
        raise ValueError(f"{name} must be a normalized absolute path")
    components = raw[1:].split("/")
    if any(component in {"", ".", ".."} for component in components):
        raise ValueError(f"{name} must be a normalized absolute path")
    return candidate


def xdg_state_home(
    *,
    state_home: str | os.PathLike[str] | None = None,
    environ: Mapping[str, str] | None = None,
) -> Path:
    """Resolve the private state base without expanding or resolving symlinks."""

    if state_home is not None:
        return _normalized_absolute(state_home, name="state_home")
    selected = os.environ if environ is None else environ
    configured = selected.get("XDG_STATE_HOME")
    if configured:
        return _normalized_absolute(configured, name="XDG_STATE_HOME")
    home = selected.get("HOME")
    if not home:
        raise ValueError("HOME or XDG_STATE_HOME is required")
    return _normalized_absolute(home, name="HOME") / ".local" / "state"


def codex_credential_root(
    credential_id: str,
    *,
    state_home: str | os.PathLike[str] | None = None,
    environ: Mapping[str, str] | None = None,
) -> Path:
    safe_id = _safe_identifier(credential_id, name="Codex credential ID")
    root = xdg_state_home(state_home=state_home, environ=environ)
    return root / "agent-loop" / "credentials" / "codex" / safe_id


def claude_credential_root(
    credential_id: str,
    *,
    state_home: str | os.PathLike[str] | None = None,
    environ: Mapping[str, str] | None = None,
) -> Path:
    safe_id = _safe_identifier(credential_id, name="Claude credential ID")
    root = xdg_state_home(state_home=state_home, environ=environ)
    return root / "agent-loop" / "credentials" / "claude" / safe_id


def _authorized_passwd_home() -> Path:
    try:
        record = pwd.getpwuid(os.geteuid())
    except KeyError:
        raise fail(
            StopReason.CREDENTIAL_REFRESH_FAILURE,
            "authorized UID has no passwd-home for default credential discovery",
        ) from None
    return _normalized_absolute(record.pw_dir, name="authorized passwd-home")


def active_codex_auth_path() -> Path:
    """Resolve the active standard Codex file-login path without reading it."""

    return _authorized_passwd_home() / ".codex" / "auth.json"


def active_claude_credentials_path() -> Path:
    """Resolve the active standard Linux Claude Code login path without reading it."""

    return _authorized_passwd_home() / ".claude" / ".credentials.json"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _private_regular_info(filesystem: ConfinedFilesystem, path: bytes) -> os.stat_result:
    info = filesystem.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("credential path is not a single-link regular file")
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != PRIVATE_FILE_MODE:
        raise ValueError("credential file ownership or mode is not private")
    return info


def _read_private_file(
    filesystem: ConfinedFilesystem,
    path: bytes,
    *,
    max_bytes: int,
    reason: StopReason,
    detail: str,
) -> bytes:
    try:
        _private_regular_info(filesystem, path)
        return filesystem.read_bytes(path, max_bytes=max_bytes)
    except AgentLoopError, OSError, TypeError, ValueError:
        raise fail(reason, detail) from None


def _read_private_source_file(
    path: str | os.PathLike[str],
    *,
    max_bytes: int,
    detail: str,
) -> bytes:
    """Read a user-selected credential without following any path component."""

    selected = _normalized_absolute(path, name="credential source")
    parent: ConfinedFilesystem | None = None
    try:
        parent = ConfinedFilesystem.open(selected.parent)
        info = os.fstat(parent.fileno())
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o002
            or not _source_parent_group_is_private(info)
        ):
            raise fail(
                StopReason.CREDENTIAL_REFRESH_FAILURE,
                f"{detail}; credential source parent is not owned and write-safe",
            )
        return _read_private_file(
            parent,
            os.fsencode(selected.name),
            max_bytes=max_bytes,
            reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
            detail=detail,
        )
    finally:
        if parent is not None:
            parent.close()


def _source_parent_group_is_private(info: os.stat_result) -> bool:
    """Accept group-write only for an actual user-private primary group."""

    if not stat.S_IMODE(info.st_mode) & 0o020:
        return True
    try:
        owner = pwd.getpwuid(os.geteuid())
        group = grp.getgrgid(info.st_gid)
        other_primary_users = tuple(
            record
            for record in pwd.getpwall()
            if record.pw_gid == info.st_gid and record.pw_uid != os.geteuid()
        )
    except KeyError:
        return False
    return (
        info.st_gid == owner.pw_gid
        and not other_primary_users
        and set(group.gr_mem) <= {owner.pw_name}
    )


def _read_optional_private_file(
    filesystem: ConfinedFilesystem,
    path: bytes,
    *,
    max_bytes: int,
) -> bytes | None:
    try:
        _private_regular_info(filesystem, path)
    except AgentLoopError as exc:
        cause = exc.__cause__
        if isinstance(cause, OSError) and cause.errno == 2:
            return None
        raise
    return filesystem.read_bytes(path, max_bytes=max_bytes)


def _verify_private_directory(filesystem: ConfinedFilesystem, *, detail: str) -> None:
    info = os.fstat(filesystem.fileno())
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_gid != os.getegid()
        or stat.S_IMODE(info.st_mode) != PRIVATE_DIR_MODE
    ):
        raise fail(StopReason.CREDENTIAL_REFRESH_FAILURE, detail)
    try:
        attributes = os.listxattr(filesystem.fileno())
    except OSError:
        raise fail(StopReason.CREDENTIAL_REFRESH_FAILURE, detail) from None
    if attributes:
        raise fail(StopReason.CREDENTIAL_REFRESH_FAILURE, detail)


def _validate_auth_bytes(
    data: bytes,
    parser: AuthParser,
    *,
    reason: StopReason,
    detail: str,
) -> None:
    try:
        valid = parser(data)
    except Exception:
        # Parser exceptions can contain the parsed credential.  Never attach
        # them as an exception cause or interpolate their text.
        raise fail(reason, detail) from None
    if valid is not True:
        raise fail(reason, detail)


def _run_auth_probe(
    codex_home: Path,
    probe: AuthProbe,
    *,
    reason: StopReason,
    detail: str,
) -> None:
    try:
        valid = probe(codex_home)
    except Exception:
        raise fail(reason, detail) from None
    if valid is not True:
        raise fail(reason, detail)


class _AuthGenerationHistory:
    """Bounded, deduplicated, memory-only history of validated auth documents."""

    def __init__(self) -> None:
        self._values: list[bytes] = []
        self._seen: set[bytes] = set()
        self._total_bytes = 0

    def append(self, value: bytes) -> bool:
        if not isinstance(value, bytes):
            raise TypeError("credential generation must be bytes")
        if value in self._seen:
            return False
        if (
            len(self._values) >= _MAX_AUTH_GENERATION_HISTORY
            or self._total_bytes + len(value) > _MAX_AUTH_GENERATION_HISTORY_BYTES
        ):
            raise fail(
                StopReason.CREDENTIAL_REFRESH_FAILURE,
                "credential generation history exceeded its private in-memory bound",
            )
        self._values.append(value)
        self._seen.add(value)
        self._total_bytes += len(value)
        return True

    def snapshot(self) -> tuple[bytes, ...]:
        return tuple(self._values)

    def clear(self) -> None:
        self._values.clear()
        self._seen.clear()
        self._total_bytes = 0


def _strict_metadata(data: bytes) -> tuple[str, str]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate metadata key")
            result[key] = value
        return result

    try:
        value = json.loads(data.decode("ascii"), object_pairs_hook=reject_duplicates)
    except UnicodeDecodeError, ValueError:
        raise ValueError("transaction metadata is malformed") from None
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "run_id",
        "baseline_sha256",
        "state",
    }:
        raise ValueError("transaction metadata shape is invalid")
    if value["schema_version"] != _TRANSACTION_SCHEMA_VERSION or value["state"] != "active":
        raise ValueError("transaction metadata version or state is invalid")
    run_id = value["run_id"]
    baseline = value["baseline_sha256"]
    if not isinstance(run_id, str) or not isinstance(baseline, str):
        raise ValueError("transaction metadata field type is invalid")
    _safe_identifier(run_id, name="transaction run ID")
    if _SHA256.fullmatch(baseline) is None:
        raise ValueError("transaction baseline hash is invalid")
    return run_id, baseline


def _metadata_bytes(run_id: str, baseline_sha256: str) -> bytes:
    value = {
        "schema_version": _TRANSACTION_SCHEMA_VERSION,
        "run_id": run_id,
        "baseline_sha256": baseline_sha256,
        "state": "active",
    }
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )


def _pair_transition_bytes(transition: _DefaultPairTransition) -> bytes:
    for run_id in (transition.codex_run_id, transition.claude_run_id):
        _safe_identifier(run_id, name="pair transition run ID")
    for digest in (
        transition.old_codex_sha256,
        transition.old_claude_sha256,
        transition.new_codex_sha256,
        transition.new_claude_sha256,
    ):
        if _SHA256.fullmatch(digest) is None:
            raise ValueError("pair transition hash is invalid")
    return (
        json.dumps(
            {
                "schema_version": _DEFAULT_PROFILE_TRANSITION_SCHEMA_VERSION,
                "state": "prepared",
                "profile": "default",
                "codex_run_id": transition.codex_run_id,
                "claude_run_id": transition.claude_run_id,
                "old_codex_sha256": transition.old_codex_sha256,
                "old_claude_sha256": transition.old_claude_sha256,
                "new_codex_sha256": transition.new_codex_sha256,
                "new_claude_sha256": transition.new_claude_sha256,
            },
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )


def _strict_pair_transition(data: bytes) -> _DefaultPairTransition:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate transition key")
            result[key] = value
        return result

    expected = {
        "schema_version",
        "state",
        "profile",
        "codex_run_id",
        "claude_run_id",
        "old_codex_sha256",
        "old_claude_sha256",
        "new_codex_sha256",
        "new_claude_sha256",
    }
    try:
        value = json.loads(data.decode("ascii"), object_pairs_hook=reject_duplicates)
    except UnicodeDecodeError, ValueError:
        raise ValueError("pair transition journal is malformed") from None
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or value["schema_version"] != _DEFAULT_PROFILE_TRANSITION_SCHEMA_VERSION
        or value["state"] != "prepared"
        or value["profile"] != "default"
    ):
        raise ValueError("pair transition journal shape is invalid")
    fields = (
        "codex_run_id",
        "claude_run_id",
        "old_codex_sha256",
        "old_claude_sha256",
        "new_codex_sha256",
        "new_claude_sha256",
    )
    if any(not isinstance(value[name], str) for name in fields):
        raise ValueError("pair transition journal field type is invalid")
    transition = _DefaultPairTransition(
        codex_run_id=value["codex_run_id"],
        claude_run_id=value["claude_run_id"],
        old_codex_sha256=value["old_codex_sha256"],
        old_claude_sha256=value["old_claude_sha256"],
        new_codex_sha256=value["new_codex_sha256"],
        new_claude_sha256=value["new_claude_sha256"],
    )
    # The canonical re-encoding check rejects alternate encodings and keeps
    # the recovery witness byte-for-byte deterministic.
    if data != _pair_transition_bytes(transition):
        raise ValueError("pair transition journal is not canonical")
    return transition


def _pair_transition_checkpoint(phase: str) -> None:
    """No-op production checkpoint replaced only by deterministic crash tests."""

    del phase


def _acquire_flock(fd: int, *, timeout_seconds: float) -> None:
    if (
        not isinstance(timeout_seconds, (int, float))
        or isinstance(timeout_seconds, bool)
        or timeout_seconds <= 0
    ):
        raise ValueError("lock_timeout_seconds must be positive")
    deadline = time.monotonic() + float(timeout_seconds)
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            if time.monotonic() >= deadline:
                raise fail(
                    StopReason.CREDENTIAL_STATE_CONFLICT,
                    "timed out waiting for the account-scoped credential lock",
                ) from None
            time.sleep(_LOCK_POLL_SECONDS)


def _open_account_lock(filesystem: ConfinedFilesystem, *, timeout_seconds: float) -> int:
    fd: int | None = None
    try:
        fd = open_beneath(
            filesystem.fileno(),
            b"lock",
            os.O_RDWR | os.O_CREAT,
            mode=PRIVATE_FILE_MODE,
        )
        os.fchmod(fd, PRIVATE_FILE_MODE)
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != PRIVATE_FILE_MODE
        ):
            raise ValueError("unsafe account lock file")
        os.fsync(fd)
        os.fsync(filesystem.fileno())
        _acquire_flock(fd, timeout_seconds=timeout_seconds)
        return fd
    except BaseException:
        if fd is not None:
            os.close(fd)
        raise


def _lock_credential_account(
    root: Path,
    *,
    timeout_seconds: float,
) -> _LockedCredentialAccount:
    filesystem: ConfinedFilesystem | None = None
    lock_fd: int | None = None
    try:
        filesystem = ConfinedFilesystem.create_private(root)
        _verify_private_directory(
            filesystem,
            detail="credential account directory is not private",
        )
        lock_fd = _open_account_lock(filesystem, timeout_seconds=timeout_seconds)
        return _LockedCredentialAccount(filesystem, lock_fd)
    except BaseException:
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
        if filesystem is not None:
            filesystem.close()
        raise


def _transaction_names(filesystem: ConfinedFilesystem) -> tuple[str, ...]:
    directory_fd = filesystem.open_directory(b"transactions")
    try:
        raw_names = sorted(os.fsencode(name) for name in os.listdir(directory_fd))
        names: list[str] = []
        for raw_name in raw_names:
            try:
                name = raw_name.decode("ascii")
                _safe_identifier(name, name="pending transaction ID")
                info = os.stat(raw_name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError, UnicodeDecodeError, ValueError:
                raise fail(
                    StopReason.CREDENTIAL_STATE_CONFLICT,
                    "credential transaction directory contains ambiguous state",
                ) from None
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != PRIVATE_DIR_MODE
            ):
                raise fail(
                    StopReason.CREDENTIAL_STATE_CONFLICT,
                    "credential transaction directory contains unsafe state",
                )
            names.append(name)
        return tuple(names)
    finally:
        os.close(directory_fd)


def _transaction_names_if_present(filesystem: ConfinedFilesystem) -> tuple[str, ...]:
    try:
        return _transaction_names(filesystem)
    except AgentLoopError as exc:
        cause = exc.__cause__
        if isinstance(cause, OSError) and cause.errno == 2:
            return ()
        raise


def _remove_transaction(filesystem: ConfinedFilesystem, run_id: str) -> None:
    if not shutil.rmtree.avoids_symlink_attacks:
        raise fail(
            StopReason.CREDENTIAL_REFRESH_FAILURE,
            "descriptor-safe credential transaction cleanup is unavailable",
        )
    directory_fd = filesystem.open_directory(b"transactions")
    try:
        try:
            shutil.rmtree(run_id.encode("ascii"), dir_fd=directory_fd)
            os.fsync(directory_fd)
        except FileNotFoundError, OSError:
            raise fail(
                StopReason.CREDENTIAL_REFRESH_FAILURE,
                "credential transaction cleanup failed",
            ) from None
    finally:
        os.close(directory_fd)


class CodexCredentialTransaction:
    """A locked, refresh-persistent Codex file-auth transaction for one run."""

    def __init__(
        self,
        *,
        account_root: Path,
        credential_id: str,
        run_id: str,
        filesystem: ConfinedFilesystem,
        lock_fd: int,
        parser: AuthParser,
        probe: AuthProbe,
        evidence_barrier: EvidenceBarrier | None,
        baseline_sha256: str,
        auth_history: _AuthGenerationHistory,
    ) -> None:
        self.account_root = account_root
        self.credential_id = credential_id
        self.run_id = run_id
        self._filesystem = filesystem
        self._lock_fd = lock_fd
        self._parser = parser
        self._probe = probe
        self._evidence_barrier = evidence_barrier
        self._baseline_sha256 = baseline_sha256
        self._auth_history = auth_history
        self._closed = False
        self._completed = False

    @classmethod
    def acquire(
        cls,
        credential_id: str,
        run_id: str,
        *,
        auth_parser: AuthParser,
        auth_probe: AuthProbe,
        state_home: str | os.PathLike[str] | None = None,
        environ: Mapping[str, str] | None = None,
        lock_timeout_seconds: float = 30.0,
        evidence_barrier: EvidenceBarrier | None = None,
    ) -> Self:
        """Acquire a standalone transaction for a non-default credential.

        The default credential belongs to an atomically committed Codex/Claude
        pair.  It may therefore be opened only through
        :class:`CombinedCredentialTransaction`, which holds the profile and
        both account locks while updating the pair witness.
        """

        return cls._acquire(
            credential_id,
            run_id,
            auth_parser=auth_parser,
            auth_probe=auth_probe,
            state_home=state_home,
            environ=environ,
            lock_timeout_seconds=lock_timeout_seconds,
            evidence_barrier=evidence_barrier,
            allow_default=False,
        )

    @classmethod
    def _acquire_for_combined(
        cls,
        credential_id: str,
        run_id: str,
        *,
        auth_parser: AuthParser,
        auth_probe: AuthProbe,
        state_home: str | os.PathLike[str] | None = None,
        environ: Mapping[str, str] | None = None,
        lock_timeout_seconds: float = 30.0,
        evidence_barrier: EvidenceBarrier | None = None,
    ) -> Self:
        return cls._acquire(
            credential_id,
            run_id,
            auth_parser=auth_parser,
            auth_probe=auth_probe,
            state_home=state_home,
            environ=environ,
            lock_timeout_seconds=lock_timeout_seconds,
            evidence_barrier=evidence_barrier,
            allow_default=True,
        )

    @classmethod
    def _acquire(
        cls,
        credential_id: str,
        run_id: str,
        *,
        auth_parser: AuthParser,
        auth_probe: AuthProbe,
        state_home: str | os.PathLike[str] | None,
        environ: Mapping[str, str] | None,
        lock_timeout_seconds: float,
        evidence_barrier: EvidenceBarrier | None,
        allow_default: bool,
    ) -> Self:
        safe_credential_id = _safe_identifier(credential_id, name="Codex credential ID")
        safe_run_id = _safe_identifier(run_id, name="run ID")
        if safe_credential_id == DEFAULT_CODEX_CREDENTIAL_ID and not allow_default:
            raise ValueError(
                "the default Codex credential must be acquired through the combined default profile"
            )
        if not callable(auth_parser) or not callable(auth_probe):
            raise TypeError("auth_parser and auth_probe must be callable")
        if evidence_barrier is not None and not callable(evidence_barrier):
            raise TypeError("evidence_barrier must be callable")
        account_root = codex_credential_root(
            safe_credential_id,
            state_home=state_home,
            environ=environ,
        )
        filesystem: ConfinedFilesystem | None = None
        lock_fd: int | None = None
        auth_history = _AuthGenerationHistory()
        try:
            filesystem = ConfinedFilesystem.create_private(account_root)
            _verify_private_directory(
                filesystem,
                detail="Codex credential account directory is not private",
            )
            lock_fd = _open_account_lock(filesystem, timeout_seconds=lock_timeout_seconds)
            transactions_fd = filesystem.mkdirs(b"transactions")
            os.close(transactions_fd)

            durable = _read_private_file(
                filesystem,
                b"auth.json",
                max_bytes=_MAX_AUTH_BYTES,
                reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
                detail="durable Codex credential is missing or unsafe",
            )
            _validate_auth_bytes(
                durable,
                auth_parser,
                reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
                detail="durable Codex credential validation failed",
            )
            auth_history.append(durable)

            cls._recover_pending(
                filesystem=filesystem,
                account_root=account_root,
                parser=auth_parser,
                probe=auth_probe,
                durable=durable,
                auth_history=auth_history,
                evidence_barrier=evidence_barrier,
            )

            # Recovery may have promoted a refreshed candidate.
            durable = _read_private_file(
                filesystem,
                b"auth.json",
                max_bytes=_MAX_AUTH_BYTES,
                reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
                detail="durable Codex credential became unavailable",
            )
            _validate_auth_bytes(
                durable,
                auth_parser,
                reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
                detail="durable Codex credential validation failed",
            )
            auth_history.append(durable)
            baseline = _sha256(durable)
            cls._seed_transaction(filesystem, safe_run_id, durable, baseline)
            return cls(
                account_root=account_root,
                credential_id=safe_credential_id,
                run_id=safe_run_id,
                filesystem=filesystem,
                lock_fd=lock_fd,
                parser=auth_parser,
                probe=auth_probe,
                evidence_barrier=evidence_barrier,
                baseline_sha256=baseline,
                auth_history=auth_history,
            )
        except BaseException:
            auth_history.clear()
            if lock_fd is not None:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                finally:
                    os.close(lock_fd)
            if filesystem is not None:
                filesystem.close()
            raise

    @staticmethod
    def _seed_transaction(
        filesystem: ConfinedFilesystem,
        run_id: str,
        durable: bytes,
        baseline_sha256: str,
    ) -> None:
        transaction = f"transactions/{run_id}".encode("ascii")
        transaction_fd = filesystem.mkdirs(transaction)
        os.close(transaction_fd)
        codex_home = transaction + b"/codex-home"
        codex_home_fd = filesystem.mkdirs(codex_home)
        os.close(codex_home_fd)
        sessions_fd = filesystem.mkdirs(codex_home + b"/sessions")
        os.close(sessions_fd)
        filesystem.atomic_write(
            codex_home + b"/auth.json",
            durable,
            mode=PRIVATE_FILE_MODE,
        )
        filesystem.atomic_write(
            transaction + b"/transaction.json",
            _metadata_bytes(run_id, baseline_sha256),
            mode=PRIVATE_FILE_MODE,
        )

    @classmethod
    def _recover_pending(
        cls,
        *,
        filesystem: ConfinedFilesystem,
        account_root: Path,
        parser: AuthParser,
        probe: AuthProbe,
        durable: bytes,
        auth_history: _AuthGenerationHistory,
        evidence_barrier: EvidenceBarrier | None,
    ) -> None:
        pending = _transaction_names(filesystem)
        if not pending:
            return
        if len(pending) != 1:
            raise fail(
                StopReason.CREDENTIAL_STATE_CONFLICT,
                "multiple pending credential transactions require explicit recovery",
            )
        run_id = pending[0]
        prefix = f"transactions/{run_id}".encode("ascii")
        metadata = _read_private_file(
            filesystem,
            prefix + b"/transaction.json",
            max_bytes=_MAX_METADATA_BYTES,
            reason=StopReason.CREDENTIAL_STATE_CONFLICT,
            detail="pending credential transaction metadata is unsafe",
        )
        try:
            recorded_run_id, baseline = _strict_metadata(metadata)
        except ValueError:
            raise fail(
                StopReason.CREDENTIAL_STATE_CONFLICT,
                "pending credential transaction metadata is invalid",
            ) from None
        if recorded_run_id != run_id:
            raise fail(
                StopReason.CREDENTIAL_STATE_CONFLICT,
                "pending transaction metadata no longer matches its directory",
            )
        if evidence_barrier is not None:
            # An empty generation snapshot is a content-free recovery signal:
            # replay any durable whole-run withholding marker before touching
            # a candidate that may be malformed or reporting a manual state
            # conflict and therefore cannot reach the ordinary secret scan.
            evidence_barrier(run_id, ())
        if _sha256(durable) != baseline:
            raise fail(
                StopReason.CREDENTIAL_STATE_CONFLICT,
                "durable credential no longer matches the pending transaction baseline",
            )
        candidate = _read_private_file(
            filesystem,
            prefix + b"/codex-home/auth.json",
            max_bytes=_MAX_AUTH_BYTES,
            reason=StopReason.CREDENTIAL_STATE_CONFLICT,
            detail="pending credential candidate is missing or unsafe",
        )
        _validate_auth_bytes(
            candidate,
            parser,
            reason=StopReason.CREDENTIAL_STATE_CONFLICT,
            detail="pending credential candidate validation failed",
        )
        auth_history.append(candidate)
        codex_home = account_root / "transactions" / run_id / "codex-home"
        try:
            _run_auth_probe(
                codex_home,
                probe,
                reason=StopReason.CREDENTIAL_STATE_CONFLICT,
                detail="pending credential candidate probe failed",
            )
        finally:
            # A probe may refresh auth and then fail or be interrupted.  Read,
            # validate, and remember that post-probe generation before Python
            # re-raises the original BaseException.  A failed capture safely
            # supersedes the probe outcome because the generation is unknown.
            candidate = _read_private_file(
                filesystem,
                prefix + b"/codex-home/auth.json",
                max_bytes=_MAX_AUTH_BYTES,
                reason=StopReason.CREDENTIAL_STATE_CONFLICT,
                detail="pending credential candidate changed unsafely during validation",
            )
            _validate_auth_bytes(
                candidate,
                parser,
                reason=StopReason.CREDENTIAL_STATE_CONFLICT,
                detail="pending credential candidate validation failed",
            )
            auth_history.append(candidate)
            if evidence_barrier is not None:
                evidence_barrier(run_id, auth_history.snapshot())
        current = _read_private_file(
            filesystem,
            b"auth.json",
            max_bytes=_MAX_AUTH_BYTES,
            reason=StopReason.CREDENTIAL_STATE_CONFLICT,
            detail="durable credential changed during crash recovery",
        )
        if _sha256(current) != baseline:
            raise fail(
                StopReason.CREDENTIAL_STATE_CONFLICT,
                "durable credential changed during crash recovery",
            )
        if candidate != current:
            filesystem.atomic_write(
                b"auth.json",
                candidate,
                mode=PRIVATE_FILE_MODE,
                create_parents=False,
            )
        try:
            _remove_transaction(filesystem, run_id)
        except AgentLoopError:
            raise fail(
                StopReason.CREDENTIAL_STATE_CONFLICT,
                "recovered credential but transaction cleanup requires explicit review",
            ) from None

    @property
    def baseline_sha256(self) -> str:
        return self._baseline_sha256

    @property
    def auth_generations(self) -> tuple[bytes, ...]:
        """Return every validated auth generation seen by this open transaction."""

        self._require_open()
        return self._auth_history.snapshot()

    @property
    def transaction_root(self) -> Path:
        return self.account_root / "transactions" / self.run_id

    @property
    def codex_home(self) -> Path:
        return self.transaction_root / "codex-home"

    @property
    def candidate_auth_path(self) -> Path:
        return self.codex_home / "auth.json"

    @property
    def metadata_path(self) -> Path:
        return self.transaction_root / "transaction.json"

    def _require_open(self) -> None:
        if self._closed:
            raise RuntimeError("credential transaction is closed")

    def capture_candidate_generation(self) -> bool:
        """Capture the current validated candidate after an external auth mutation."""

        self._require_open()
        if self._completed:
            raise RuntimeError("credential transaction is already complete")
        candidate = _read_private_file(
            self._filesystem,
            f"transactions/{self.run_id}/codex-home/auth.json".encode("ascii"),
            max_bytes=_MAX_AUTH_BYTES,
            reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
            detail="Codex credential refresh candidate is missing or unsafe",
        )
        _validate_auth_bytes(
            candidate,
            self._parser,
            reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
            detail="Codex credential refresh candidate failed validation",
        )
        return self._auth_history.append(candidate)

    def _stage_candidate_generation(self, candidate: bytes) -> None:
        """Stage one parser-valid default-source generation under this lock."""

        self._require_open()
        _validate_auth_bytes(
            candidate,
            self._parser,
            reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
            detail="newer standard Codex login failed validation while staging",
        )
        self._filesystem.atomic_write(
            f"transactions/{self.run_id}/codex-home/auth.json".encode("ascii"),
            candidate,
            mode=PRIVATE_FILE_MODE,
            create_parents=False,
        )
        self._auth_history.append(candidate)

    def _restore_durable_candidate(self) -> None:
        """Restore the locked durable generation after a source-probe failure."""

        self._require_open()
        durable = _read_private_file(
            self._filesystem,
            b"auth.json",
            max_bytes=_MAX_AUTH_BYTES,
            reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
            detail="durable Codex login became unsafe while restoring a failed source",
        )
        self._stage_candidate_generation(durable)

    def remove_candidate_config(self) -> None:
        """Remove a generated config after a pre-runtime preparation failure."""

        self._require_open()
        home = self._filesystem.open_directory(
            f"transactions/{self.run_id}/codex-home".encode("ascii")
        )
        try:
            try:
                os.unlink(b"config.toml", dir_fd=home)
            except FileNotFoundError:
                return
            except OSError:
                raise fail(
                    StopReason.CREDENTIAL_REFRESH_FAILURE,
                    "transactional Codex configuration cleanup failed",
                ) from None
            os.fsync(home)
        finally:
            os.close(home)

    def reconcile_after_turn(self) -> bool:
        """Validate and atomically persist a changed transaction credential."""

        self._require_open()
        if self._completed:
            raise RuntimeError("credential transaction is already complete")
        prefix = f"transactions/{self.run_id}/codex-home/auth.json".encode("ascii")
        current = _read_private_file(
            self._filesystem,
            b"auth.json",
            max_bytes=_MAX_AUTH_BYTES,
            reason=StopReason.CREDENTIAL_STATE_CONFLICT,
            detail="durable credential changed or became unsafe during the run",
        )
        if _sha256(current) != self._baseline_sha256:
            raise fail(
                StopReason.CREDENTIAL_STATE_CONFLICT,
                "durable credential changed outside the locked transaction",
            )
        candidate = _read_private_file(
            self._filesystem,
            prefix,
            max_bytes=_MAX_AUTH_BYTES,
            reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
            detail="Codex credential refresh candidate is missing or unsafe",
        )
        if candidate == current:
            self._auth_history.append(candidate)
            return False

        _validate_auth_bytes(
            candidate,
            self._parser,
            reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
            detail="Codex credential refresh candidate failed validation",
        )
        self._auth_history.append(candidate)
        try:
            _run_auth_probe(
                self.codex_home,
                self._probe,
                reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
                detail="Codex credential refresh candidate failed the auth-status probe",
            )
        finally:
            # Preserve a valid generation written immediately before any
            # ordinary probe failure or asynchronous operator interruption.
            candidate = _read_private_file(
                self._filesystem,
                prefix,
                max_bytes=_MAX_AUTH_BYTES,
                reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
                detail="Codex credential refresh candidate changed unsafely during validation",
            )
            _validate_auth_bytes(
                candidate,
                self._parser,
                reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
                detail="Codex credential refresh candidate failed validation",
            )
            self._auth_history.append(candidate)
            if self._evidence_barrier is not None:
                self._evidence_barrier(self.run_id, self._auth_history.snapshot())
        current = _read_private_file(
            self._filesystem,
            b"auth.json",
            max_bytes=_MAX_AUTH_BYTES,
            reason=StopReason.CREDENTIAL_STATE_CONFLICT,
            detail="durable credential changed during refresh validation",
        )
        if _sha256(current) != self._baseline_sha256:
            raise fail(
                StopReason.CREDENTIAL_STATE_CONFLICT,
                "durable credential changed during refresh validation",
            )
        self._filesystem.atomic_write(
            b"auth.json",
            candidate,
            mode=PRIVATE_FILE_MODE,
            create_parents=False,
        )
        self._baseline_sha256 = _sha256(candidate)
        metadata = f"transactions/{self.run_id}/transaction.json".encode("ascii")
        self._filesystem.atomic_write(
            metadata,
            _metadata_bytes(self.run_id, self._baseline_sha256),
            mode=PRIVATE_FILE_MODE,
            create_parents=False,
        )
        return True

    def complete(self) -> None:
        """Reconcile one final time, then delete active credential state."""

        self._require_open()
        if self._completed:
            return
        self.reconcile_after_turn()
        _remove_transaction(self._filesystem, self.run_id)
        self._completed = True

    def finalize_reconciled(self) -> None:
        """Delete a transaction only after an external reconcile/scan barrier.

        This operation performs no auth probe and therefore cannot create an
        unclassified credential generation.  It re-reads both witnesses and
        requires the already-reconciled candidate to equal durable state.
        """

        self._require_open()
        if self._completed:
            return
        durable = _read_private_file(
            self._filesystem,
            b"auth.json",
            max_bytes=_MAX_AUTH_BYTES,
            reason=StopReason.CREDENTIAL_STATE_CONFLICT,
            detail="durable Codex credential became unsafe before finalization",
        )
        candidate = _read_private_file(
            self._filesystem,
            f"transactions/{self.run_id}/codex-home/auth.json".encode("ascii"),
            max_bytes=_MAX_AUTH_BYTES,
            reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
            detail="Codex credential candidate became unsafe before finalization",
        )
        _validate_auth_bytes(
            candidate,
            self._parser,
            reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
            detail="Codex credential candidate failed final validation",
        )
        self._auth_history.append(candidate)
        if _sha256(durable) != self._baseline_sha256 or candidate != durable:
            raise fail(
                StopReason.CREDENTIAL_STATE_CONFLICT,
                "Codex credential changed after the final reconcile barrier",
            )
        _remove_transaction(self._filesystem, self.run_id)
        self._completed = True

    def close(self) -> None:
        """Release the account lock, preserving an incomplete transaction."""

        if self._closed:
            return
        try:
            fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(self._lock_fd)
            self._filesystem.close()
            self._auth_history.clear()
            self._closed = True

    def __enter__(self) -> Self:
        self._require_open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        try:
            if exc_type is None:
                self.complete()
        finally:
            self.close()


def _strict_json_object(data: bytes) -> dict[str, object] | None:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(data.decode("utf-8", "strict"), object_pairs_hook=reject_duplicates)
    except UnicodeDecodeError, ValueError, RecursionError, MemoryError:
        return None
    return value if isinstance(value, dict) else None


def parse_claude_cli_credentials(data: bytes) -> bool:
    """Validate the pinned Linux Claude Code subscription-login file shape."""

    if not isinstance(data, bytes) or len(data) > _MAX_CLAUDE_CREDENTIAL_BYTES:
        return False
    value = _strict_json_object(data)
    if value is None or not {"claudeAiOauth"} <= set(value):
        return False
    if set(value) - {"claudeAiOauth", "organizationUuid"}:
        return False
    oauth = value.get("claudeAiOauth")
    if not isinstance(oauth, dict):
        return False
    required = {
        "accessToken",
        "refreshToken",
        "expiresAt",
        "refreshTokenExpiresAt",
        "scopes",
        "subscriptionType",
        "rateLimitTier",
    }
    if set(oauth) != required:
        return False
    for name in ("accessToken", "refreshToken", "subscriptionType", "rateLimitTier"):
        item = oauth.get(name)
        if (
            not isinstance(item, str)
            or not item
            or "\x00" in item
            or len(item.encode("utf-8")) > _MAX_TOKEN_BYTES
        ):
            return False
    for name in ("expiresAt", "refreshTokenExpiresAt"):
        item = oauth.get(name)
        if not isinstance(item, int) or isinstance(item, bool) or item <= 0:
            return False
    scopes = oauth.get("scopes")
    if (
        not isinstance(scopes, list)
        or not 1 <= len(scopes) <= 64
        or not all(
            isinstance(item, str)
            and item
            and "\x00" not in item
            and len(item.encode("utf-8")) <= 1024
            for item in scopes
        )
    ):
        return False
    organization = value.get("organizationUuid")
    return organization is None or (
        isinstance(organization, str)
        and bool(organization)
        and "\x00" not in organization
        and len(organization.encode("utf-8")) <= 1024
    )


def claude_cli_credential_secret_values(data: bytes) -> tuple[bytes, ...]:
    """Extract only credential-bearing fields after strict shape validation."""

    if not parse_claude_cli_credentials(data):
        raise ValueError("Claude CLI credential document is invalid")
    value = _strict_json_object(data)
    assert value is not None
    oauth = value["claudeAiOauth"]
    assert isinstance(oauth, dict)
    return tuple(str(oauth[name]).encode("utf-8") for name in ("accessToken", "refreshToken"))


class ClaudeCredentialTransaction:
    """Locked refresh-persistent copy of an existing Claude Code login."""

    def __init__(
        self,
        *,
        account_root: Path,
        credential_id: str,
        run_id: str,
        filesystem: ConfinedFilesystem,
        lock_fd: int,
        baseline_sha256: str,
        auth_history: _AuthGenerationHistory,
        evidence_barrier: EvidenceBarrier | None,
    ) -> None:
        self.account_root = account_root
        self.credential_id = credential_id
        self.run_id = run_id
        self._filesystem = filesystem
        self._lock_fd = lock_fd
        self._baseline_sha256 = baseline_sha256
        self._auth_history = auth_history
        self._evidence_barrier = evidence_barrier
        self._closed = False
        self._completed = False

    @classmethod
    def acquire(
        cls,
        credential_id: str,
        run_id: str,
        *,
        state_home: str | os.PathLike[str] | None = None,
        environ: Mapping[str, str] | None = None,
        lock_timeout_seconds: float = 30.0,
        evidence_barrier: EvidenceBarrier | None = None,
    ) -> Self:
        """Acquire a standalone transaction for a non-default credential."""

        return cls._acquire(
            credential_id,
            run_id,
            state_home=state_home,
            environ=environ,
            lock_timeout_seconds=lock_timeout_seconds,
            evidence_barrier=evidence_barrier,
            allow_default=False,
        )

    @classmethod
    def _acquire_for_combined(
        cls,
        credential_id: str,
        run_id: str,
        *,
        state_home: str | os.PathLike[str] | None = None,
        environ: Mapping[str, str] | None = None,
        lock_timeout_seconds: float = 30.0,
        evidence_barrier: EvidenceBarrier | None = None,
    ) -> Self:
        return cls._acquire(
            credential_id,
            run_id,
            state_home=state_home,
            environ=environ,
            lock_timeout_seconds=lock_timeout_seconds,
            evidence_barrier=evidence_barrier,
            allow_default=True,
        )

    @classmethod
    def _acquire(
        cls,
        credential_id: str,
        run_id: str,
        *,
        state_home: str | os.PathLike[str] | None,
        environ: Mapping[str, str] | None,
        lock_timeout_seconds: float,
        evidence_barrier: EvidenceBarrier | None,
        allow_default: bool,
    ) -> Self:
        safe_id = _safe_identifier(credential_id, name="Claude credential ID")
        safe_run = _safe_identifier(run_id, name="run ID")
        if safe_id == DEFAULT_CLAUDE_CREDENTIAL_ID and not allow_default:
            raise ValueError(
                "the default Claude credential must be acquired through the combined "
                "default profile"
            )
        root = claude_credential_root(safe_id, state_home=state_home, environ=environ)
        filesystem: ConfinedFilesystem | None = None
        lock_fd: int | None = None
        history = _AuthGenerationHistory()
        try:
            filesystem = ConfinedFilesystem.create_private(root)
            _verify_private_directory(
                filesystem,
                detail="Claude credential account directory is not private",
            )
            lock_fd = _open_account_lock(filesystem, timeout_seconds=lock_timeout_seconds)
            transactions_fd = filesystem.mkdirs(b"transactions")
            os.close(transactions_fd)
            durable = _read_private_file(
                filesystem,
                b"credentials.json",
                max_bytes=_MAX_CLAUDE_CREDENTIAL_BYTES,
                reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
                detail="durable Claude credential is missing or unsafe",
            )
            _validate_auth_bytes(
                durable,
                parse_claude_cli_credentials,
                reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
                detail="durable Claude credential validation failed",
            )
            history.append(durable)
            cls._recover_pending(
                filesystem=filesystem,
                account_root=root,
                durable=durable,
                history=history,
                evidence_barrier=evidence_barrier,
            )
            durable = _read_private_file(
                filesystem,
                b"credentials.json",
                max_bytes=_MAX_CLAUDE_CREDENTIAL_BYTES,
                reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
                detail="durable Claude credential became unavailable",
            )
            _validate_auth_bytes(
                durable,
                parse_claude_cli_credentials,
                reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
                detail="durable Claude credential validation failed",
            )
            history.append(durable)
            baseline = _sha256(durable)
            transaction = f"transactions/{safe_run}".encode("ascii")
            transaction_fd = filesystem.mkdirs(transaction)
            os.close(transaction_fd)
            home = transaction + b"/claude-home"
            home_fd = filesystem.mkdirs(home)
            os.close(home_fd)
            filesystem.atomic_write(
                home + b"/.credentials.json",
                durable,
                mode=PRIVATE_FILE_MODE,
            )
            filesystem.atomic_write(
                transaction + b"/transaction.json",
                _metadata_bytes(safe_run, baseline),
                mode=PRIVATE_FILE_MODE,
            )
            return cls(
                account_root=root,
                credential_id=safe_id,
                run_id=safe_run,
                filesystem=filesystem,
                lock_fd=lock_fd,
                baseline_sha256=baseline,
                auth_history=history,
                evidence_barrier=evidence_barrier,
            )
        except BaseException:
            history.clear()
            if lock_fd is not None:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                finally:
                    os.close(lock_fd)
            if filesystem is not None:
                filesystem.close()
            raise

    @classmethod
    def _recover_pending(
        cls,
        *,
        filesystem: ConfinedFilesystem,
        account_root: Path,
        durable: bytes,
        history: _AuthGenerationHistory,
        evidence_barrier: EvidenceBarrier | None,
    ) -> None:
        pending = _transaction_names(filesystem)
        if not pending:
            return
        if len(pending) != 1:
            raise fail(
                StopReason.CREDENTIAL_STATE_CONFLICT,
                "multiple pending Claude credential transactions require explicit recovery",
            )
        run_id = pending[0]
        prefix = f"transactions/{run_id}".encode("ascii")
        metadata = _read_private_file(
            filesystem,
            prefix + b"/transaction.json",
            max_bytes=_MAX_METADATA_BYTES,
            reason=StopReason.CREDENTIAL_STATE_CONFLICT,
            detail="pending Claude credential metadata is unsafe",
        )
        try:
            recorded_run, baseline = _strict_metadata(metadata)
        except ValueError:
            raise fail(
                StopReason.CREDENTIAL_STATE_CONFLICT,
                "pending Claude credential metadata is invalid",
            ) from None
        if recorded_run != run_id or _sha256(durable) != baseline:
            raise fail(
                StopReason.CREDENTIAL_STATE_CONFLICT,
                "pending Claude credential baseline is inconsistent",
            )
        if evidence_barrier is not None:
            evidence_barrier(run_id, ())
        candidate = _read_private_file(
            filesystem,
            prefix + b"/claude-home/.credentials.json",
            max_bytes=_MAX_CLAUDE_CREDENTIAL_BYTES,
            reason=StopReason.CREDENTIAL_STATE_CONFLICT,
            detail="pending Claude credential candidate is missing or unsafe",
        )
        _validate_auth_bytes(
            candidate,
            parse_claude_cli_credentials,
            reason=StopReason.CREDENTIAL_STATE_CONFLICT,
            detail="pending Claude credential candidate failed validation",
        )
        history.append(candidate)
        if evidence_barrier is not None:
            evidence_barrier(run_id, history.snapshot())
        if candidate != durable:
            filesystem.atomic_write(
                b"credentials.json",
                candidate,
                mode=PRIVATE_FILE_MODE,
                create_parents=False,
            )
        _remove_transaction(filesystem, run_id)

    @property
    def claude_home(self) -> Path:
        return self.account_root / "transactions" / self.run_id / "claude-home"

    @property
    def auth_generations(self) -> tuple[bytes, ...]:
        self._require_open()
        return self._auth_history.snapshot()

    def _require_open(self) -> None:
        if self._closed:
            raise RuntimeError("Claude credential transaction is closed")

    def capture_candidate_generation(self) -> bool:
        self._require_open()
        candidate = _read_private_file(
            self._filesystem,
            f"transactions/{self.run_id}/claude-home/.credentials.json".encode("ascii"),
            max_bytes=_MAX_CLAUDE_CREDENTIAL_BYTES,
            reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
            detail="Claude credential refresh candidate is missing or unsafe",
        )
        _validate_auth_bytes(
            candidate,
            parse_claude_cli_credentials,
            reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
            detail="Claude credential refresh candidate failed validation",
        )
        return self._auth_history.append(candidate)

    def _stage_candidate_generation(self, candidate: bytes) -> None:
        """Stage one parser-valid default-source generation under this lock."""

        self._require_open()
        _validate_auth_bytes(
            candidate,
            parse_claude_cli_credentials,
            reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
            detail="newer standard Claude login failed validation while staging",
        )
        self._filesystem.atomic_write(
            f"transactions/{self.run_id}/claude-home/.credentials.json".encode("ascii"),
            candidate,
            mode=PRIVATE_FILE_MODE,
            create_parents=False,
        )
        self._auth_history.append(candidate)

    def _restore_durable_candidate(self) -> None:
        """Restore the locked durable generation after a source-probe failure."""

        self._require_open()
        durable = _read_private_file(
            self._filesystem,
            b"credentials.json",
            max_bytes=_MAX_CLAUDE_CREDENTIAL_BYTES,
            reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
            detail="durable Claude login became unsafe while restoring a failed source",
        )
        self._stage_candidate_generation(durable)

    def reconcile_after_turn(self) -> bool:
        self._require_open()
        if self._completed:
            raise RuntimeError("Claude credential transaction is already complete")
        durable = _read_private_file(
            self._filesystem,
            b"credentials.json",
            max_bytes=_MAX_CLAUDE_CREDENTIAL_BYTES,
            reason=StopReason.CREDENTIAL_STATE_CONFLICT,
            detail="durable Claude credential changed or became unsafe",
        )
        if _sha256(durable) != self._baseline_sha256:
            raise fail(
                StopReason.CREDENTIAL_STATE_CONFLICT,
                "durable Claude credential changed outside the locked transaction",
            )
        candidate = _read_private_file(
            self._filesystem,
            f"transactions/{self.run_id}/claude-home/.credentials.json".encode("ascii"),
            max_bytes=_MAX_CLAUDE_CREDENTIAL_BYTES,
            reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
            detail="Claude credential refresh candidate is missing or unsafe",
        )
        _validate_auth_bytes(
            candidate,
            parse_claude_cli_credentials,
            reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
            detail="Claude credential refresh candidate failed validation",
        )
        self._auth_history.append(candidate)
        if candidate == durable:
            return False
        if self._evidence_barrier is not None:
            self._evidence_barrier(self.run_id, self._auth_history.snapshot())
        self._filesystem.atomic_write(
            b"credentials.json",
            candidate,
            mode=PRIVATE_FILE_MODE,
            create_parents=False,
        )
        self._baseline_sha256 = _sha256(candidate)
        self._filesystem.atomic_write(
            f"transactions/{self.run_id}/transaction.json".encode("ascii"),
            _metadata_bytes(self.run_id, self._baseline_sha256),
            mode=PRIVATE_FILE_MODE,
            create_parents=False,
        )
        return True

    def finalize_reconciled(self) -> None:
        self._require_open()
        if self._completed:
            return
        durable = _read_private_file(
            self._filesystem,
            b"credentials.json",
            max_bytes=_MAX_CLAUDE_CREDENTIAL_BYTES,
            reason=StopReason.CREDENTIAL_STATE_CONFLICT,
            detail="durable Claude credential became unsafe before finalization",
        )
        candidate = _read_private_file(
            self._filesystem,
            f"transactions/{self.run_id}/claude-home/.credentials.json".encode("ascii"),
            max_bytes=_MAX_CLAUDE_CREDENTIAL_BYTES,
            reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
            detail="Claude credential candidate became unsafe before finalization",
        )
        if _sha256(durable) != self._baseline_sha256 or candidate != durable:
            raise fail(
                StopReason.CREDENTIAL_STATE_CONFLICT,
                "Claude credential changed after the final reconcile barrier",
            )
        _remove_transaction(self._filesystem, self.run_id)
        self._completed = True

    def close(self) -> None:
        if self._closed:
            return
        try:
            fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(self._lock_fd)
            self._filesystem.close()
            self._auth_history.clear()
            self._closed = True


@dataclass(frozen=True, slots=True)
class _PreparedCredentialRecovery:
    run_id: str | None
    durable: bytes
    candidate: bytes


def _probe_standard_generation(
    filesystem: ConfinedFilesystem,
    *,
    account_root: Path,
    run_id: str,
    label: str,
    candidate: bytes,
    max_bytes: int,
    parser: AuthParser,
    probe: AuthProbe,
    evidence_barrier: EvidenceBarrier | None,
    prior_generations: tuple[bytes, ...],
) -> bytes | None:
    """Probe a standard login in disposable transaction state before staging it."""

    _validate_auth_bytes(
        candidate,
        parser,
        reason=StopReason.CREDENTIAL_STATE_CONFLICT,
        detail=f"newer standard {label} login is invalid during recovery",
    )
    prefix = f"transactions/{run_id}".encode("ascii")
    probe_name = b"source-probe-codex" if label == "Codex" else b"source-probe-claude"
    probe_home_path = prefix + b"/" + probe_name
    probe_credential_name = b"auth.json" if label == "Codex" else b".credentials.json"
    _remove_relative_tree(filesystem, probe_home_path)
    probe_home_fd = filesystem.mkdirs(probe_home_path)
    os.close(probe_home_fd)
    filesystem.atomic_write(
        probe_home_path + b"/" + probe_credential_name,
        candidate,
        mode=PRIVATE_FILE_MODE,
        create_parents=False,
    )
    control_home = account_root / "transactions" / run_id / os.fsdecode(probe_name)
    probed = candidate
    failed = False
    try:
        try:
            _run_auth_probe(
                control_home,
                probe,
                reason=StopReason.CREDENTIAL_STATE_CONFLICT,
                detail=f"newer standard {label} login could not be confirmed",
            )
        except AgentLoopError:
            failed = True
    finally:
        probed = _read_private_file(
            filesystem,
            probe_home_path + b"/" + probe_credential_name,
            max_bytes=max_bytes,
            reason=StopReason.CREDENTIAL_STATE_CONFLICT,
            detail=f"newer standard {label} login changed unsafely during validation",
        )
        _validate_auth_bytes(
            probed,
            parser,
            reason=StopReason.CREDENTIAL_STATE_CONFLICT,
            detail=f"newer standard {label} login became invalid during validation",
        )
        if evidence_barrier is not None:
            evidence_barrier(
                run_id,
                tuple(dict.fromkeys((*prior_generations, candidate, probed))),
            )
        _remove_relative_tree(filesystem, probe_home_path)
    return None if failed else probed


def _prepare_pending_recovery(
    account: _LockedCredentialAccount,
    *,
    account_root: Path,
    candidate_suffix: bytes,
    max_bytes: int,
    parser: AuthParser,
    generation_parser: GenerationParser,
    probe: AuthProbe | None,
    replacement: bytes | None,
    evidence_barrier: EvidenceBarrier | None,
    label: str,
) -> _PreparedCredentialRecovery:
    durable_name = b"auth.json" if label == "Codex" else b"credentials.json"
    durable = _read_private_file(
        account.filesystem,
        durable_name,
        max_bytes=max_bytes,
        reason=StopReason.CREDENTIAL_STATE_CONFLICT,
        detail=f"durable {label} credential is unsafe during pair recovery",
    )
    _validate_auth_bytes(
        durable,
        parser,
        reason=StopReason.CREDENTIAL_STATE_CONFLICT,
        detail=f"durable {label} credential is invalid during pair recovery",
    )
    pending = _transaction_names_if_present(account.filesystem)
    if not pending:
        return _PreparedCredentialRecovery(None, durable, durable)
    if len(pending) != 1:
        raise fail(
            StopReason.CREDENTIAL_STATE_CONFLICT,
            f"multiple pending {label} transactions require explicit review",
        )
    run_id = pending[0]
    prefix = f"transactions/{run_id}".encode("ascii")
    metadata = _read_private_file(
        account.filesystem,
        prefix + b"/transaction.json",
        max_bytes=_MAX_METADATA_BYTES,
        reason=StopReason.CREDENTIAL_STATE_CONFLICT,
        detail=f"pending {label} transaction metadata is unsafe",
    )
    try:
        recorded_run, baseline = _strict_metadata(metadata)
    except ValueError:
        raise fail(
            StopReason.CREDENTIAL_STATE_CONFLICT,
            f"pending {label} transaction metadata is invalid",
        ) from None
    if recorded_run != run_id:
        raise fail(
            StopReason.CREDENTIAL_STATE_CONFLICT,
            f"pending {label} transaction identity is inconsistent",
        )
    if evidence_barrier is not None:
        evidence_barrier(run_id, ())
    candidate = _read_private_file(
        account.filesystem,
        prefix + candidate_suffix,
        max_bytes=max_bytes,
        reason=StopReason.CREDENTIAL_STATE_CONFLICT,
        detail=f"pending {label} candidate is missing or unsafe",
    )
    _validate_auth_bytes(
        candidate,
        parser,
        reason=StopReason.CREDENTIAL_STATE_CONFLICT,
        detail=f"pending {label} candidate is invalid",
    )
    if baseline != _sha256(durable):
        # A previously committed pair may have crashed while deleting its
        # transaction directory.  It is cleanup-only exactly when candidate
        # and durable are already identical under the matching pair marker.
        if candidate != durable:
            raise fail(
                StopReason.CREDENTIAL_STATE_CONFLICT,
                f"pending {label} baseline does not match the committed pair",
            )
        if evidence_barrier is not None:
            evidence_barrier(run_id, (durable,))
        return _PreparedCredentialRecovery(run_id, durable, durable)
    original_candidate = candidate
    replacement_probed = False
    candidate_generation = generation_parser(candidate)
    replacement_generation = generation_parser(replacement) if replacement is not None else None
    replacement_supersedes_candidate = replacement is not None and (
        candidate == durable
        or (
            replacement_generation is not None
            and candidate_generation is not None
            and replacement_generation > candidate_generation
        )
    )
    if replacement_supersedes_candidate and probe is not None:
        assert replacement is not None
        probed_replacement = _probe_standard_generation(
            account.filesystem,
            account_root=account_root,
            run_id=run_id,
            label=label,
            candidate=replacement,
            max_bytes=max_bytes,
            parser=parser,
            probe=probe,
            evidence_barrier=evidence_barrier,
            prior_generations=(durable, original_candidate),
        )
        if probed_replacement is not None:
            replacement_probed = True
            candidate = probed_replacement
            account.filesystem.atomic_write(
                prefix + candidate_suffix,
                candidate,
                mode=PRIVATE_FILE_MODE,
                create_parents=False,
            )
    if probe is not None and not replacement_probed:
        control_home = account_root / "transactions" / run_id
        control_home /= "codex-home" if label == "Codex" else "claude-home"
        try:
            _run_auth_probe(
                control_home,
                probe,
                reason=StopReason.CREDENTIAL_STATE_CONFLICT,
                detail=f"pending {label} authentication status probe failed",
            )
        finally:
            candidate = _read_private_file(
                account.filesystem,
                prefix + candidate_suffix,
                max_bytes=max_bytes,
                reason=StopReason.CREDENTIAL_STATE_CONFLICT,
                detail=f"pending {label} candidate changed unsafely during validation",
            )
            _validate_auth_bytes(
                candidate,
                parser,
                reason=StopReason.CREDENTIAL_STATE_CONFLICT,
                detail=f"pending {label} candidate is invalid",
            )
    if evidence_barrier is not None:
        evidence_barrier(
            run_id,
            tuple(dict.fromkeys((durable, original_candidate, candidate))),
        )
    return _PreparedCredentialRecovery(run_id, durable, candidate)


def _transition_marker(transition: _DefaultPairTransition, *, new: bool) -> bytes:
    codex_hash = transition.new_codex_sha256 if new else transition.old_codex_sha256
    claude_hash = transition.new_claude_sha256 if new else transition.old_claude_sha256
    return _default_profile_metadata_from_hashes(codex_hash, claude_hash)


def _write_pair_transition(
    profile_filesystem: ConfinedFilesystem,
    transition: _DefaultPairTransition,
) -> None:
    existing = _read_optional_private_file(
        profile_filesystem,
        _DEFAULT_PROFILE_TRANSITION,
        max_bytes=_MAX_METADATA_BYTES,
    )
    encoded = _pair_transition_bytes(transition)
    if existing is not None and existing != encoded:
        raise fail(
            StopReason.CREDENTIAL_STATE_CONFLICT,
            "a different default credential pair transition is already pending",
        )
    if existing is None:
        profile_filesystem.atomic_write(
            _DEFAULT_PROFILE_TRANSITION,
            encoded,
            mode=PRIVATE_FILE_MODE,
            create_parents=False,
        )
    _pair_transition_checkpoint("after_journal")


def _journal_candidate(
    account: _LockedCredentialAccount,
    *,
    run_id: str,
    candidate_suffix: bytes,
    old_sha256: str,
    new_sha256: str,
    max_bytes: int,
    parser: AuthParser,
    evidence_barrier: EvidenceBarrier | None,
    label: str,
) -> bytes | None:
    pending = _transaction_names_if_present(account.filesystem)
    if not pending:
        return None
    if pending != (run_id,):
        raise fail(
            StopReason.CREDENTIAL_STATE_CONFLICT,
            f"pending {label} transactions do not match the pair journal",
        )
    prefix = f"transactions/{run_id}".encode("ascii")
    metadata = _read_private_file(
        account.filesystem,
        prefix + b"/transaction.json",
        max_bytes=_MAX_METADATA_BYTES,
        reason=StopReason.CREDENTIAL_STATE_CONFLICT,
        detail=f"pending {label} transaction metadata is unsafe",
    )
    try:
        recorded_run, baseline = _strict_metadata(metadata)
    except ValueError:
        raise fail(
            StopReason.CREDENTIAL_STATE_CONFLICT,
            f"pending {label} transaction metadata is invalid",
        ) from None
    if recorded_run != run_id or baseline not in {old_sha256, new_sha256}:
        raise fail(
            StopReason.CREDENTIAL_STATE_CONFLICT,
            f"pending {label} transaction is not bound to the pair journal",
        )
    if evidence_barrier is not None:
        evidence_barrier(run_id, ())
    candidate = _read_private_file(
        account.filesystem,
        prefix + candidate_suffix,
        max_bytes=max_bytes,
        reason=StopReason.CREDENTIAL_STATE_CONFLICT,
        detail=f"pending {label} candidate is missing or unsafe",
    )
    _validate_auth_bytes(
        candidate,
        parser,
        reason=StopReason.CREDENTIAL_STATE_CONFLICT,
        detail=f"pending {label} candidate is invalid",
    )
    if _sha256(candidate) != new_sha256:
        raise fail(
            StopReason.CREDENTIAL_STATE_CONFLICT,
            f"pending {label} candidate does not match the pair journal",
        )
    if evidence_barrier is not None:
        evidence_barrier(run_id, (candidate,))
    return candidate


def _roll_forward_pair_transition(
    profile_filesystem: ConfinedFilesystem,
    *,
    transition: _DefaultPairTransition,
    claude_account: _LockedCredentialAccount,
    codex_account: _LockedCredentialAccount,
    claude_candidate: bytes | None,
    codex_candidate: bytes | None,
    codex_auth_parser: AuthParser,
    cleanup_transactions: bool,
) -> None:
    metadata = _read_private_file(
        profile_filesystem,
        _DEFAULT_PROFILE_METADATA,
        max_bytes=_MAX_METADATA_BYTES,
        reason=StopReason.CREDENTIAL_STATE_CONFLICT,
        detail="default credential pair metadata is missing during recovery",
    )
    old_marker = _transition_marker(transition, new=False)
    new_marker = _transition_marker(transition, new=True)
    if metadata not in {old_marker, new_marker}:
        raise fail(
            StopReason.CREDENTIAL_STATE_CONFLICT,
            "default credential pair metadata is not bound to the pending transition",
        )

    current_claude = _read_private_file(
        claude_account.filesystem,
        b"credentials.json",
        max_bytes=_MAX_CLAUDE_CREDENTIAL_BYTES,
        reason=StopReason.CREDENTIAL_STATE_CONFLICT,
        detail="durable Claude credential is unsafe during pair recovery",
    )
    current_codex = _read_private_file(
        codex_account.filesystem,
        b"auth.json",
        max_bytes=_MAX_AUTH_BYTES,
        reason=StopReason.CREDENTIAL_STATE_CONFLICT,
        detail="durable Codex credential is unsafe during pair recovery",
    )
    _validate_auth_bytes(
        current_claude,
        parse_claude_cli_credentials,
        reason=StopReason.CREDENTIAL_STATE_CONFLICT,
        detail="durable Claude credential is invalid during pair recovery",
    )
    _validate_auth_bytes(
        current_codex,
        codex_auth_parser,
        reason=StopReason.CREDENTIAL_STATE_CONFLICT,
        detail="durable Codex credential is invalid during pair recovery",
    )
    claude_hash = _sha256(current_claude)
    codex_hash = _sha256(current_codex)
    if claude_hash not in {
        transition.old_claude_sha256,
        transition.new_claude_sha256,
    } or codex_hash not in {
        transition.old_codex_sha256,
        transition.new_codex_sha256,
    }:
        raise fail(
            StopReason.CREDENTIAL_STATE_CONFLICT,
            "durable credentials are not an old, mixed, or new journaled pair",
        )
    if claude_candidate is None or codex_candidate is None:
        if (
            metadata != new_marker
            or claude_hash != transition.new_claude_sha256
            or codex_hash != transition.new_codex_sha256
        ):
            raise fail(
                StopReason.CREDENTIAL_STATE_CONFLICT,
                "a journaled candidate witness disappeared before pair commit",
            )
    if claude_hash != transition.new_claude_sha256:
        if claude_candidate is None or _sha256(claude_candidate) != transition.new_claude_sha256:
            raise fail(
                StopReason.CREDENTIAL_STATE_CONFLICT,
                "the journaled Claude candidate is unavailable for roll-forward",
            )
        claude_account.filesystem.atomic_write(
            b"credentials.json",
            claude_candidate,
            mode=PRIVATE_FILE_MODE,
            create_parents=False,
        )
    _pair_transition_checkpoint("after_first_provider")
    if codex_hash != transition.new_codex_sha256:
        if codex_candidate is None or _sha256(codex_candidate) != transition.new_codex_sha256:
            raise fail(
                StopReason.CREDENTIAL_STATE_CONFLICT,
                "the journaled Codex candidate is unavailable for roll-forward",
            )
        codex_account.filesystem.atomic_write(
            b"auth.json",
            codex_candidate,
            mode=PRIVATE_FILE_MODE,
            create_parents=False,
        )
    _pair_transition_checkpoint("after_second_provider")
    if metadata != new_marker:
        profile_filesystem.atomic_write(
            _DEFAULT_PROFILE_METADATA,
            new_marker,
            mode=PRIVATE_FILE_MODE,
            create_parents=False,
        )
    _pair_transition_checkpoint("after_metadata")

    if cleanup_transactions:
        if _transaction_names_if_present(claude_account.filesystem):
            _remove_transaction(claude_account.filesystem, transition.claude_run_id)
        if _transaction_names_if_present(codex_account.filesystem):
            _remove_transaction(codex_account.filesystem, transition.codex_run_id)
    else:
        claude_account.filesystem.atomic_write(
            f"transactions/{transition.claude_run_id}/transaction.json".encode("ascii"),
            _metadata_bytes(transition.claude_run_id, transition.new_claude_sha256),
            mode=PRIVATE_FILE_MODE,
            create_parents=False,
        )
        codex_account.filesystem.atomic_write(
            f"transactions/{transition.codex_run_id}/transaction.json".encode("ascii"),
            _metadata_bytes(transition.codex_run_id, transition.new_codex_sha256),
            mode=PRIVATE_FILE_MODE,
            create_parents=False,
        )
    _pair_transition_checkpoint("after_cleanup")
    _remove_relative_file(profile_filesystem, _DEFAULT_PROFILE_TRANSITION)


def _coordinated_recover_default_pair(
    profile_filesystem: ConfinedFilesystem,
    *,
    selected_state: Path,
    codex_auth_parser: AuthParser,
    codex_auth_probe: AuthProbe,
    claude_auth_probe: AuthProbe,
    codex_evidence_barrier: EvidenceBarrier | None,
    claude_evidence_barrier: EvidenceBarrier | None,
    lock_timeout_seconds: float,
) -> tuple[bytes | None, bytes | None]:
    """Recover the pair and return strictly newer standard generations."""

    claude_root = claude_credential_root(
        DEFAULT_CLAUDE_CREDENTIAL_ID,
        state_home=selected_state,
    )
    codex_root = codex_credential_root(
        DEFAULT_CODEX_CREDENTIAL_ID,
        state_home=selected_state,
    )
    claude_account: _LockedCredentialAccount | None = None
    codex_account: _LockedCredentialAccount | None = None
    try:
        claude_account = _lock_credential_account(
            claude_root,
            timeout_seconds=lock_timeout_seconds,
        )
        codex_account = _lock_credential_account(
            codex_root,
            timeout_seconds=lock_timeout_seconds,
        )
        transition_data = _read_optional_private_file(
            profile_filesystem,
            _DEFAULT_PROFILE_TRANSITION,
            max_bytes=_MAX_METADATA_BYTES,
        )
        if transition_data is not None:
            try:
                transition = _strict_pair_transition(transition_data)
            except ValueError:
                raise fail(
                    StopReason.CREDENTIAL_STATE_CONFLICT,
                    "default credential pair transition journal is invalid",
                ) from None
            # Journal recovery validates the candidate with the real parser;
            # pass it into the generic helper without invoking another status
            # probe that could create an unjournaled generation.
            codex_candidate = _journal_candidate(
                codex_account,
                run_id=transition.codex_run_id,
                candidate_suffix=b"/codex-home/auth.json",
                old_sha256=transition.old_codex_sha256,
                new_sha256=transition.new_codex_sha256,
                max_bytes=_MAX_AUTH_BYTES,
                parser=codex_auth_parser,
                evidence_barrier=codex_evidence_barrier,
                label="Codex",
            )
            claude_candidate = _journal_candidate(
                claude_account,
                run_id=transition.claude_run_id,
                candidate_suffix=b"/claude-home/.credentials.json",
                old_sha256=transition.old_claude_sha256,
                new_sha256=transition.new_claude_sha256,
                max_bytes=_MAX_CLAUDE_CREDENTIAL_BYTES,
                parser=parse_claude_cli_credentials,
                evidence_barrier=claude_evidence_barrier,
                label="Claude",
            )
            _roll_forward_pair_transition(
                profile_filesystem,
                transition=transition,
                claude_account=claude_account,
                codex_account=codex_account,
                claude_candidate=claude_candidate,
                codex_candidate=codex_candidate,
                codex_auth_parser=codex_auth_parser,
                cleanup_transactions=True,
            )

        current_codex = _read_private_file(
            codex_account.filesystem,
            b"auth.json",
            max_bytes=_MAX_AUTH_BYTES,
            reason=StopReason.CREDENTIAL_STATE_CONFLICT,
            detail="durable Codex credential is unsafe during pair recovery",
        )
        current_claude = _read_private_file(
            claude_account.filesystem,
            b"credentials.json",
            max_bytes=_MAX_CLAUDE_CREDENTIAL_BYTES,
            reason=StopReason.CREDENTIAL_STATE_CONFLICT,
            detail="durable Claude credential is unsafe during pair recovery",
        )
        metadata = _read_optional_private_file(
            profile_filesystem,
            _DEFAULT_PROFILE_METADATA,
            max_bytes=_MAX_METADATA_BYTES,
        )
        if metadata is None or not _valid_default_profile_metadata(
            metadata,
            codex_data=current_codex,
            claude_data=current_claude,
        ):
            raise fail(
                StopReason.CREDENTIAL_STATE_CONFLICT,
                "default credential pair has no committed matching generation; run "
                "`agent-loop auth init --repair` after review",
            )
        replacement_codex, replacement_claude = _newer_standard_credential_pair(
            current_codex,
            current_claude,
            codex_auth_parser=codex_auth_parser,
        )
        claude_recovery = _prepare_pending_recovery(
            claude_account,
            account_root=claude_root,
            candidate_suffix=b"/claude-home/.credentials.json",
            max_bytes=_MAX_CLAUDE_CREDENTIAL_BYTES,
            parser=parse_claude_cli_credentials,
            generation_parser=_claude_refresh_generation,
            probe=None,
            replacement=None,
            evidence_barrier=claude_evidence_barrier,
            label="Claude",
        )
        codex_recovery = _prepare_pending_recovery(
            codex_account,
            account_root=codex_root,
            candidate_suffix=b"/codex-home/auth.json",
            max_bytes=_MAX_AUTH_BYTES,
            parser=codex_auth_parser,
            generation_parser=_codex_refresh_generation,
            probe=None,
            replacement=None,
            evidence_barrier=codex_evidence_barrier,
            label="Codex",
        )
        changed = (
            claude_recovery.candidate != claude_recovery.durable
            or codex_recovery.candidate != codex_recovery.durable
        )
        if not changed:
            if claude_recovery.run_id is not None:
                _remove_transaction(claude_account.filesystem, claude_recovery.run_id)
            if codex_recovery.run_id is not None:
                _remove_transaction(codex_account.filesystem, codex_recovery.run_id)
            return replacement_codex, replacement_claude
        if (
            claude_recovery.run_id is None
            or codex_recovery.run_id is None
            or claude_recovery.run_id != codex_recovery.run_id
        ):
            raise fail(
                StopReason.CREDENTIAL_STATE_CONFLICT,
                "a changed default credential candidate lacks its paired transaction witness",
            )
        # Only a structurally paired changed transaction may be status-probed
        # or superseded.  This second phase prevents a newer standard source
        # from turning cleanup-only, one-sided crash residue into an
        # unjournaled changed candidate.
        claude_recovery = _prepare_pending_recovery(
            claude_account,
            account_root=claude_root,
            candidate_suffix=b"/claude-home/.credentials.json",
            max_bytes=_MAX_CLAUDE_CREDENTIAL_BYTES,
            parser=parse_claude_cli_credentials,
            generation_parser=_claude_refresh_generation,
            probe=claude_auth_probe,
            replacement=replacement_claude,
            evidence_barrier=claude_evidence_barrier,
            label="Claude",
        )
        codex_recovery = _prepare_pending_recovery(
            codex_account,
            account_root=codex_root,
            candidate_suffix=b"/codex-home/auth.json",
            max_bytes=_MAX_AUTH_BYTES,
            parser=codex_auth_parser,
            generation_parser=_codex_refresh_generation,
            probe=codex_auth_probe,
            replacement=replacement_codex,
            evidence_barrier=codex_evidence_barrier,
            label="Codex",
        )
        changed = (
            claude_recovery.candidate != claude_recovery.durable
            or codex_recovery.candidate != codex_recovery.durable
        )
        if not changed:
            assert claude_recovery.run_id is not None
            assert codex_recovery.run_id is not None
            _remove_transaction(claude_account.filesystem, claude_recovery.run_id)
            _remove_transaction(codex_account.filesystem, codex_recovery.run_id)
            return None, None
        assert claude_recovery.run_id is not None
        assert codex_recovery.run_id is not None
        assert claude_recovery.run_id == codex_recovery.run_id
        transition = _DefaultPairTransition(
            codex_run_id=codex_recovery.run_id,
            claude_run_id=claude_recovery.run_id,
            old_codex_sha256=_sha256(codex_recovery.durable),
            old_claude_sha256=_sha256(claude_recovery.durable),
            new_codex_sha256=_sha256(codex_recovery.candidate),
            new_claude_sha256=_sha256(claude_recovery.candidate),
        )
        _write_pair_transition(profile_filesystem, transition)
        _roll_forward_pair_transition(
            profile_filesystem,
            transition=transition,
            claude_account=claude_account,
            codex_account=codex_account,
            claude_candidate=claude_recovery.candidate,
            codex_candidate=codex_recovery.candidate,
            codex_auth_parser=codex_auth_parser,
            cleanup_transactions=True,
        )
        return None, None
    finally:
        if codex_account is not None:
            codex_account.close()
        if claude_account is not None:
            claude_account.close()


class CombinedCredentialTransaction:
    """One profile-locked lifecycle over the Claude -> Codex lock order."""

    def __init__(
        self,
        codex: CodexCredentialTransaction,
        claude: ClaudeCredentialTransaction,
        *,
        codex_auth_parser: AuthParser,
        claude_auth_probe: AuthProbe,
        profile_filesystem: ConfinedFilesystem | None = None,
        profile_lock_fd: int | None = None,
    ) -> None:
        if not isinstance(codex, CodexCredentialTransaction) or not isinstance(
            claude, ClaudeCredentialTransaction
        ):
            raise TypeError("combined credential transaction requires both vendor transactions")
        if not callable(codex_auth_parser) or not callable(claude_auth_probe):
            raise TypeError("combined credential validators must be callable")
        self.codex = codex
        self.claude = claude
        self._codex_auth_parser = codex_auth_parser
        self._claude_auth_probe = claude_auth_probe
        if (profile_filesystem is None) != (profile_lock_fd is None):
            raise TypeError("combined profile lock authority must be supplied as a pair")
        self._profile_filesystem = profile_filesystem
        self._profile_lock_fd = profile_lock_fd
        self._closed = False

    @classmethod
    def acquire(
        cls,
        codex_credential_id: str,
        claude_credential_id: str,
        run_id: str,
        *,
        codex_auth_parser: AuthParser,
        codex_auth_probe: AuthProbe,
        claude_auth_probe: AuthProbe,
        state_home: str | os.PathLike[str] | None = None,
        codex_evidence_barrier: EvidenceBarrier | None = None,
        claude_evidence_barrier: EvidenceBarrier | None = None,
        lock_timeout_seconds: float = 30.0,
    ) -> Self:
        """Acquire profile, Claude, then Codex and prove one committed pair."""

        safe_codex_id = _safe_identifier(
            codex_credential_id,
            name="Codex credential ID",
        )
        safe_claude_id = _safe_identifier(
            claude_credential_id,
            name="Claude credential ID",
        )
        codex_is_default = safe_codex_id == DEFAULT_CODEX_CREDENTIAL_ID
        claude_is_default = safe_claude_id == DEFAULT_CLAUDE_CREDENTIAL_ID
        if codex_is_default != claude_is_default:
            raise ValueError("the default Codex and Claude credentials must be selected as a pair")
        selected_state = xdg_state_home(state_home=state_home)
        profiles_root = selected_state / "agent-loop" / "credentials"
        profile_filesystem: ConfinedFilesystem | None = None
        profile_lock_fd: int | None = None
        claude: ClaudeCredentialTransaction | None = None
        codex: CodexCredentialTransaction | None = None
        replacement_codex: bytes | None = None
        replacement_claude: bytes | None = None
        success = False
        try:
            profile_filesystem = ConfinedFilesystem.open(profiles_root)
            _verify_private_directory(
                profile_filesystem,
                detail="credential profile directory is not private",
            )
            profile_lock_fd = _open_account_lock(
                profile_filesystem,
                timeout_seconds=lock_timeout_seconds,
            )
            for vendor, identifier in (
                ("claude", safe_claude_id),
                ("codex", safe_codex_id),
            ):
                if not _relative_entry_exists(
                    profile_filesystem,
                    f"{vendor}/{identifier}".encode("ascii"),
                ):
                    login = "claude auth login" if vendor == "claude" else "codex login"
                    guidance = (
                        f"run `{login}` once, then rerun; the default profile syncs automatically"
                        if codex_is_default
                        else "the selected custom credential ID must be enrolled explicitly"
                    )
                    raise fail(
                        StopReason.CREDENTIAL_REFRESH_FAILURE,
                        f"{vendor} login is missing; {guidance}",
                    )
            if codex_is_default and claude_is_default:
                replacement_codex, replacement_claude = _coordinated_recover_default_pair(
                    profile_filesystem,
                    selected_state=selected_state,
                    codex_auth_parser=codex_auth_parser,
                    codex_auth_probe=codex_auth_probe,
                    claude_auth_probe=claude_auth_probe,
                    codex_evidence_barrier=codex_evidence_barrier,
                    claude_evidence_barrier=claude_evidence_barrier,
                    lock_timeout_seconds=lock_timeout_seconds,
                )
            claude = ClaudeCredentialTransaction._acquire_for_combined(
                safe_claude_id,
                run_id,
                state_home=selected_state,
                lock_timeout_seconds=lock_timeout_seconds,
                evidence_barrier=claude_evidence_barrier,
            )
            codex = CodexCredentialTransaction._acquire_for_combined(
                safe_codex_id,
                run_id,
                auth_parser=codex_auth_parser,
                auth_probe=codex_auth_probe,
                state_home=selected_state,
                lock_timeout_seconds=lock_timeout_seconds,
                evidence_barrier=codex_evidence_barrier,
            )
            if replacement_claude is not None:
                claude._auth_history.append(replacement_claude)
                replacement_claude = _probe_standard_generation(
                    claude._filesystem,
                    account_root=claude.account_root,
                    run_id=claude.run_id,
                    label="Claude",
                    candidate=replacement_claude,
                    max_bytes=_MAX_CLAUDE_CREDENTIAL_BYTES,
                    parser=parse_claude_cli_credentials,
                    probe=claude_auth_probe,
                    evidence_barrier=claude_evidence_barrier,
                    prior_generations=claude._auth_history.snapshot(),
                )
                if replacement_claude is not None:
                    claude._auth_history.append(replacement_claude)
                    claude._stage_candidate_generation(replacement_claude)
            if replacement_codex is not None:
                codex._auth_history.append(replacement_codex)
                replacement_codex = _probe_standard_generation(
                    codex._filesystem,
                    account_root=codex.account_root,
                    run_id=codex.run_id,
                    label="Codex",
                    candidate=replacement_codex,
                    max_bytes=_MAX_AUTH_BYTES,
                    parser=codex_auth_parser,
                    probe=codex_auth_probe,
                    evidence_barrier=codex_evidence_barrier,
                    prior_generations=codex._auth_history.snapshot(),
                )
                if replacement_codex is not None:
                    codex._auth_history.append(replacement_codex)
                    codex._stage_candidate_generation(replacement_codex)
            combined = cls(
                codex,
                claude,
                codex_auth_parser=codex_auth_parser,
                claude_auth_probe=claude_auth_probe,
                profile_filesystem=profile_filesystem,
                profile_lock_fd=profile_lock_fd,
            )
            combined._verify_committed_default_pair()
            try:
                try:
                    _run_auth_probe(
                        claude.claude_home,
                        claude_auth_probe,
                        reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
                        detail=(
                            "Claude authentication status could not be confirmed. Run "
                            "`claude auth status`; only if it reports signed out, run "
                            "`claude auth login` once, then rerun. No `agent-loop auth` "
                            "command is required."
                        ),
                    )
                except AgentLoopError:
                    if replacement_claude is None:
                        raise
                    claude._restore_durable_candidate()
                    _run_auth_probe(
                        claude.claude_home,
                        claude_auth_probe,
                        reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
                        detail=(
                            "Claude authentication status could not be confirmed. Run "
                            "`claude auth status`; only if it reports signed out, run "
                            "`claude auth login` once, then rerun. No `agent-loop auth` "
                            "command is required."
                        ),
                    )
            finally:
                claude.capture_candidate_generation()
            try:
                try:
                    _run_auth_probe(
                        codex.codex_home,
                        codex_auth_probe,
                        reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
                        detail=(
                            "Codex authentication status could not be confirmed. Run "
                            "`codex login status`; only if it reports signed out, run "
                            "`codex login` once, then rerun. No `agent-loop auth` command "
                            "is required."
                        ),
                    )
                except AgentLoopError:
                    if replacement_codex is None:
                        raise
                    codex._restore_durable_candidate()
                    _run_auth_probe(
                        codex.codex_home,
                        codex_auth_probe,
                        reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
                        detail=(
                            "Codex authentication status could not be confirmed. Run "
                            "`codex login status`; only if it reports signed out, run "
                            "`codex login` once, then rerun. No `agent-loop auth` command "
                            "is required."
                        ),
                    )
            finally:
                codex.capture_candidate_generation()
            if codex_is_default:
                combined._reconcile_default_pair(probe_candidates=False)
            else:
                codex.reconcile_after_turn()
                claude.reconcile_after_turn()
            success = True
            return combined
        finally:
            if not success:
                if codex is not None:
                    codex.close()
                if claude is not None:
                    claude.close()
                if profile_lock_fd is not None:
                    try:
                        fcntl.flock(profile_lock_fd, fcntl.LOCK_UN)
                    finally:
                        os.close(profile_lock_fd)
                if profile_filesystem is not None:
                    profile_filesystem.close()

    def _durable_pair(self) -> tuple[bytes, bytes]:
        codex_data = _read_private_file(
            self.codex._filesystem,
            b"auth.json",
            max_bytes=_MAX_AUTH_BYTES,
            reason=StopReason.CREDENTIAL_STATE_CONFLICT,
            detail="committed Codex credential became unsafe",
        )
        claude_data = _read_private_file(
            self.claude._filesystem,
            b"credentials.json",
            max_bytes=_MAX_CLAUDE_CREDENTIAL_BYTES,
            reason=StopReason.CREDENTIAL_STATE_CONFLICT,
            detail="committed Claude credential became unsafe",
        )
        return codex_data, claude_data

    def _verify_committed_default_pair(self) -> None:
        if (
            self.codex.credential_id != DEFAULT_CODEX_CREDENTIAL_ID
            or self.claude.credential_id != DEFAULT_CLAUDE_CREDENTIAL_ID
        ):
            return
        if self._profile_filesystem is None:
            raise RuntimeError("default pair verification requires the profile lock")
        metadata = _read_optional_private_file(
            self._profile_filesystem,
            _DEFAULT_PROFILE_METADATA,
            max_bytes=_MAX_METADATA_BYTES,
        )
        codex_data, claude_data = self._durable_pair()
        if metadata is None or not _valid_default_profile_metadata(
            metadata,
            codex_data=codex_data,
            claude_data=claude_data,
        ):
            raise fail(
                StopReason.CREDENTIAL_STATE_CONFLICT,
                "default credential pair has no committed matching generation; run "
                "`agent-loop auth init --repair` after review",
            )

    def _reconcile_default_pair(self, *, probe_candidates: bool) -> bool:
        if self._profile_filesystem is None:
            raise RuntimeError("default pair reconciliation requires the profile lock")
        codex_durable, claude_durable = self._durable_pair()
        _validate_auth_bytes(
            codex_durable,
            self._codex_auth_parser,
            reason=StopReason.CREDENTIAL_STATE_CONFLICT,
            detail="durable Codex credential is invalid before pair reconciliation",
        )
        _validate_auth_bytes(
            claude_durable,
            parse_claude_cli_credentials,
            reason=StopReason.CREDENTIAL_STATE_CONFLICT,
            detail="durable Claude credential is invalid before pair reconciliation",
        )
        if (
            _sha256(codex_durable) != self.codex._baseline_sha256
            or _sha256(claude_durable) != self.claude._baseline_sha256
        ):
            raise fail(
                StopReason.CREDENTIAL_STATE_CONFLICT,
                "the durable credential pair changed outside the locked transaction",
            )

        codex_path = f"transactions/{self.codex.run_id}/codex-home/auth.json".encode("ascii")
        claude_path = f"transactions/{self.claude.run_id}/claude-home/.credentials.json".encode(
            "ascii"
        )
        codex_candidate = _read_private_file(
            self.codex._filesystem,
            codex_path,
            max_bytes=_MAX_AUTH_BYTES,
            reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
            detail="Codex credential refresh candidate is missing or unsafe",
        )
        claude_candidate = _read_private_file(
            self.claude._filesystem,
            claude_path,
            max_bytes=_MAX_CLAUDE_CREDENTIAL_BYTES,
            reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
            detail="Claude credential refresh candidate is missing or unsafe",
        )
        _validate_auth_bytes(
            codex_candidate,
            self._codex_auth_parser,
            reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
            detail="Codex credential refresh candidate failed validation",
        )
        _validate_auth_bytes(
            claude_candidate,
            parse_claude_cli_credentials,
            reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
            detail="Claude credential refresh candidate failed validation",
        )
        self.codex._auth_history.append(codex_candidate)
        self.claude._auth_history.append(claude_candidate)
        codex_changed = codex_candidate != codex_durable
        claude_changed = claude_candidate != claude_durable
        if not codex_changed and not claude_changed:
            return False

        if probe_candidates and claude_changed:
            try:
                _run_auth_probe(
                    self.claude.claude_home,
                    self._claude_auth_probe,
                    reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
                    detail="Claude credential refresh candidate failed the auth-status probe",
                )
            finally:
                claude_candidate = _read_private_file(
                    self.claude._filesystem,
                    claude_path,
                    max_bytes=_MAX_CLAUDE_CREDENTIAL_BYTES,
                    reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
                    detail=(
                        "Claude credential refresh candidate changed unsafely during validation"
                    ),
                )
                _validate_auth_bytes(
                    claude_candidate,
                    parse_claude_cli_credentials,
                    reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
                    detail="Claude credential refresh candidate failed validation",
                )
                self.claude._auth_history.append(claude_candidate)
        if self.claude._evidence_barrier is not None and claude_changed:
            self.claude._evidence_barrier(
                self.claude.run_id,
                self.claude._auth_history.snapshot(),
            )

        if probe_candidates and codex_changed:
            try:
                _run_auth_probe(
                    self.codex.codex_home,
                    self.codex._probe,
                    reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
                    detail="Codex credential refresh candidate failed the auth-status probe",
                )
            finally:
                codex_candidate = _read_private_file(
                    self.codex._filesystem,
                    codex_path,
                    max_bytes=_MAX_AUTH_BYTES,
                    reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
                    detail="Codex credential refresh candidate changed unsafely during validation",
                )
                _validate_auth_bytes(
                    codex_candidate,
                    self._codex_auth_parser,
                    reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
                    detail="Codex credential refresh candidate failed validation",
                )
                self.codex._auth_history.append(codex_candidate)
        if self.codex._evidence_barrier is not None and codex_changed:
            self.codex._evidence_barrier(
                self.codex.run_id,
                self.codex._auth_history.snapshot(),
            )

        current_codex, current_claude = self._durable_pair()
        if current_codex != codex_durable or current_claude != claude_durable:
            raise fail(
                StopReason.CREDENTIAL_STATE_CONFLICT,
                "the durable credential pair changed during candidate validation",
            )
        transition = _DefaultPairTransition(
            codex_run_id=self.codex.run_id,
            claude_run_id=self.claude.run_id,
            old_codex_sha256=self.codex._baseline_sha256,
            old_claude_sha256=self.claude._baseline_sha256,
            new_codex_sha256=_sha256(codex_candidate),
            new_claude_sha256=_sha256(claude_candidate),
        )
        _write_pair_transition(self._profile_filesystem, transition)
        _roll_forward_pair_transition(
            self._profile_filesystem,
            transition=transition,
            claude_account=_LockedCredentialAccount(
                self.claude._filesystem,
                self.claude._lock_fd,
            ),
            codex_account=_LockedCredentialAccount(
                self.codex._filesystem,
                self.codex._lock_fd,
            ),
            claude_candidate=claude_candidate,
            codex_candidate=codex_candidate,
            codex_auth_parser=self._codex_auth_parser,
            cleanup_transactions=False,
        )
        self.codex._baseline_sha256 = transition.new_codex_sha256
        self.claude._baseline_sha256 = transition.new_claude_sha256
        return True

    @property
    def codex_home(self) -> Path:
        return self.codex.codex_home

    @property
    def claude_home(self) -> Path:
        return self.claude.claude_home

    @property
    def auth_generations(self) -> tuple[bytes, ...]:
        return self.codex.auth_generations

    @property
    def claude_auth_generations(self) -> tuple[bytes, ...]:
        return self.claude.auth_generations

    def capture_candidate_generation(self) -> bool:
        codex_changed = self.codex.capture_candidate_generation()
        claude_changed = self.claude.capture_candidate_generation()
        return codex_changed or claude_changed

    def remove_candidate_config(self) -> None:
        self.codex.remove_candidate_config()

    def reconcile_after_turn(self) -> bool:
        if (
            self.codex.credential_id == DEFAULT_CODEX_CREDENTIAL_ID
            and self.claude.credential_id == DEFAULT_CLAUDE_CREDENTIAL_ID
        ):
            return self._reconcile_default_pair(probe_candidates=True)
        codex_changed = self.codex.reconcile_after_turn()
        claude_changed = self.claude.reconcile_after_turn()
        return codex_changed or claude_changed

    def complete(self) -> None:
        self.reconcile_after_turn()
        self.finalize_reconciled()

    def finalize_reconciled(self) -> None:
        self.codex.finalize_reconciled()
        self.claude.finalize_reconciled()

    def close(self) -> None:
        if self._closed:
            return
        first_error: BaseException | None = None
        try:
            self.codex.close()
        except BaseException as exc:
            first_error = exc
        try:
            self.claude.close()
        except BaseException:
            if first_error is None:
                raise
        finally:
            if self._profile_lock_fd is not None:
                try:
                    fcntl.flock(self._profile_lock_fd, fcntl.LOCK_UN)
                finally:
                    os.close(self._profile_lock_fd)
                    self._profile_lock_fd = None
            if self._profile_filesystem is not None:
                self._profile_filesystem.close()
                self._profile_filesystem = None
            self._closed = True
        if first_error is not None:
            raise first_error


def _enroll_private_file(
    *,
    root: Path,
    relative_path: bytes,
    data: bytes,
    validate: Callable[[bytes], bool],
    credential_id: str,
    replace: bool,
    lock_timeout_seconds: float,
) -> CredentialEnrollment:
    """Install one credential under the account lock without exposing its bytes."""

    if not isinstance(data, bytes):
        raise TypeError("credential enrollment data must be bytes")
    if not callable(validate):
        raise TypeError("credential validator must be callable")
    try:
        valid = validate(data)
    except Exception:
        raise fail(
            StopReason.CREDENTIAL_REFRESH_FAILURE,
            "credential enrollment input failed validation",
        ) from None
    if valid is not True:
        raise fail(
            StopReason.CREDENTIAL_REFRESH_FAILURE,
            "credential enrollment input failed validation",
        )

    filesystem: ConfinedFilesystem | None = None
    lock_fd: int | None = None
    try:
        filesystem = ConfinedFilesystem.create_private(root)
        _verify_private_directory(
            filesystem,
            detail="credential enrollment directory is not private",
        )
        lock_fd = _open_account_lock(filesystem, timeout_seconds=lock_timeout_seconds)
        if _transaction_names_if_present(filesystem):
            raise fail(
                StopReason.CREDENTIAL_STATE_CONFLICT,
                "credential enrollment cannot replace an account with an active transaction",
            )
        try:
            current = _read_optional_private_file(
                filesystem,
                relative_path,
                max_bytes=max(_MAX_AUTH_BYTES, _MAX_TOKEN_BYTES),
            )
        except AgentLoopError, OSError, TypeError, ValueError:
            raise fail(
                StopReason.CREDENTIAL_REFRESH_FAILURE,
                "existing enrolled credential is unsafe",
            ) from None
        if current is not None:
            try:
                current_valid = validate(current)
            except Exception:
                current_valid = False
            if current_valid is not True:
                raise fail(
                    StopReason.CREDENTIAL_REFRESH_FAILURE,
                    "existing enrolled credential failed validation",
                )
            if current == data:
                return CredentialEnrollment(credential_id, installed=False)
            if not replace:
                raise fail(
                    StopReason.CREDENTIAL_STATE_CONFLICT,
                    "a different credential is already enrolled; use explicit replacement",
                )
        filesystem.atomic_write(
            relative_path,
            data,
            mode=PRIVATE_FILE_MODE,
            create_parents=False,
        )
        return CredentialEnrollment(credential_id, installed=True)
    finally:
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
        if filesystem is not None:
            filesystem.close()


def enroll_codex_file_auth(
    credential_id: str = DEFAULT_CODEX_CREDENTIAL_ID,
    *,
    source_auth_path: str | os.PathLike[str],
    auth_parser: AuthParser,
    state_home: str | os.PathLike[str] | None = None,
    environ: Mapping[str, str] | None = None,
    replace: bool = False,
    lock_timeout_seconds: float = 30.0,
) -> CredentialEnrollment:
    """One-time import of an existing private Codex CLI file login.

    The source is copied rather than moved.  Subsequent agent-loop runs use the
    account-scoped copy and persist Codex refreshes there under the same lock.
    """

    safe_id = _safe_identifier(credential_id, name="Codex credential ID")
    data = _read_private_source_file(
        source_auth_path,
        max_bytes=_MAX_AUTH_BYTES,
        detail="Codex credential import source is missing or unsafe",
    )
    return _enroll_private_file(
        root=codex_credential_root(safe_id, state_home=state_home, environ=environ),
        relative_path=b"auth.json",
        data=data,
        validate=auth_parser,
        credential_id=safe_id,
        replace=replace,
        lock_timeout_seconds=lock_timeout_seconds,
    )


def codex_file_auth_enrolled(
    credential_id: str = DEFAULT_CODEX_CREDENTIAL_ID,
    *,
    auth_parser: AuthParser,
    state_home: str | os.PathLike[str] | None = None,
    environ: Mapping[str, str] | None = None,
) -> bool:
    """Return whether one valid private account-scoped Codex login exists."""

    safe_id = _safe_identifier(credential_id, name="Codex credential ID")
    return _private_credential_enrolled(
        codex_credential_root(safe_id, state_home=state_home, environ=environ),
        b"auth.json",
        max_bytes=_MAX_AUTH_BYTES,
        validate=auth_parser,
    )


def _normalized_claude_token_bytes(raw: bytes) -> bytes:
    if not isinstance(raw, bytes):
        raise TypeError("Claude setup token must be bytes")
    if len(raw) > _MAX_TOKEN_BYTES:
        raise ValueError("Claude setup token exceeds its byte limit")
    if raw.endswith(b"\r\n"):
        raw = raw[:-2]
    elif raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        token = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise ValueError("Claude setup token encoding is invalid") from None
    if not token or any(character.isspace() or ord(character) < 0x20 for character in token):
        raise ValueError("Claude setup token format is invalid")
    return token.encode("utf-8")


def enroll_claude_setup_token(
    token: str | bytes,
    credential_id: str = DEFAULT_CLAUDE_CREDENTIAL_ID,
    *,
    state_home: str | os.PathLike[str] | None = None,
    environ: Mapping[str, str] | None = None,
    replace: bool = False,
    lock_timeout_seconds: float = 30.0,
) -> CredentialEnrollment:
    """One-time private enrollment of an inference-only Claude setup token."""

    safe_id = _safe_identifier(credential_id, name="Claude credential ID")
    raw = token.encode("utf-8") if isinstance(token, str) else token
    try:
        normalized = _normalized_claude_token_bytes(raw)
    except TypeError, ValueError:
        raise fail(
            StopReason.CREDENTIAL_REFRESH_FAILURE,
            "Claude setup token enrollment input is invalid",
        ) from None
    return _enroll_private_file(
        root=claude_credential_root(safe_id, state_home=state_home, environ=environ),
        relative_path=b"oauth-token",
        data=normalized + b"\n",
        validate=lambda value: _valid_claude_token_file(value),
        credential_id=safe_id,
        replace=replace,
        lock_timeout_seconds=lock_timeout_seconds,
    )


def enroll_claude_cli_credentials(
    credential_id: str = DEFAULT_CLAUDE_CREDENTIAL_ID,
    *,
    source_credentials_path: str | os.PathLike[str],
    state_home: str | os.PathLike[str] | None = None,
    environ: Mapping[str, str] | None = None,
    replace: bool = False,
    lock_timeout_seconds: float = 30.0,
) -> CredentialEnrollment:
    """Import an existing Linux Claude Code ``/login`` credential file once."""

    safe_id = _safe_identifier(credential_id, name="Claude credential ID")
    data = _read_private_source_file(
        source_credentials_path,
        max_bytes=_MAX_CLAUDE_CREDENTIAL_BYTES,
        detail="Claude credential import source is missing or unsafe",
    )
    return _enroll_private_file(
        root=claude_credential_root(safe_id, state_home=state_home, environ=environ),
        relative_path=b"credentials.json",
        data=data,
        validate=parse_claude_cli_credentials,
        credential_id=safe_id,
        replace=replace,
        lock_timeout_seconds=lock_timeout_seconds,
    )


def claude_cli_credentials_enrolled(
    credential_id: str = DEFAULT_CLAUDE_CREDENTIAL_ID,
    *,
    state_home: str | os.PathLike[str] | None = None,
    environ: Mapping[str, str] | None = None,
) -> bool:
    """Return whether a valid private refresh-persistent Claude login exists."""

    safe_id = _safe_identifier(credential_id, name="Claude credential ID")
    return _private_credential_enrolled(
        claude_credential_root(safe_id, state_home=state_home, environ=environ),
        b"credentials.json",
        max_bytes=_MAX_CLAUDE_CREDENTIAL_BYTES,
        validate=parse_claude_cli_credentials,
    )


def _default_profile_metadata_from_hashes(
    codex_sha256: str,
    claude_sha256: str,
) -> bytes:
    if _SHA256.fullmatch(codex_sha256) is None or _SHA256.fullmatch(claude_sha256) is None:
        raise ValueError("default credential metadata hash is invalid")
    return (
        json.dumps(
            {
                "schema_version": _DEFAULT_PROFILE_SCHEMA_VERSION,
                "profile": "default",
                "codex_credential_id": DEFAULT_CODEX_CREDENTIAL_ID,
                "codex_adapter": "file-account",
                "claude_credential_id": DEFAULT_CLAUDE_CREDENTIAL_ID,
                "claude_adapter": "file-account",
                "codex_sha256": codex_sha256,
                "claude_sha256": claude_sha256,
            },
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )


def _default_profile_metadata_bytes(codex_data: bytes, claude_data: bytes) -> bytes:
    if not isinstance(codex_data, bytes) or not isinstance(claude_data, bytes):
        raise TypeError("default credential metadata inputs must be bytes")
    return _default_profile_metadata_from_hashes(_sha256(codex_data), _sha256(claude_data))


def _valid_default_profile_metadata(
    data: bytes,
    *,
    codex_data: bytes,
    claude_data: bytes,
) -> bool:
    return data == _default_profile_metadata_bytes(codex_data, claude_data)


def _relative_entry_exists(filesystem: ConfinedFilesystem, path: bytes) -> bool:
    try:
        filesystem.lstat(path)
    except AgentLoopError as exc:
        cause = exc.__cause__
        if isinstance(cause, OSError) and cause.errno == 2:
            return False
        raise
    return True


def _remove_relative_tree(filesystem: ConfinedFilesystem, path: bytes) -> None:
    components = validate_relative_path(path)
    if len(components) < 2 or not shutil.rmtree.avoids_symlink_attacks:
        raise fail(
            StopReason.CREDENTIAL_REFRESH_FAILURE,
            "default credential bootstrap rollback is unavailable",
        )
    parent = b"/".join(components[:-1])
    try:
        parent_fd = filesystem.open_directory(parent)
    except AgentLoopError as exc:
        cause = exc.__cause__
        if isinstance(cause, OSError) and cause.errno == 2:
            return
        raise
    try:
        shutil.rmtree(components[-1], dir_fd=parent_fd)
        os.fsync(parent_fd)
    except FileNotFoundError:
        return
    except OSError:
        raise fail(
            StopReason.CREDENTIAL_REFRESH_FAILURE,
            "default credential bootstrap rollback failed",
        ) from None
    finally:
        os.close(parent_fd)


def _remove_relative_file(filesystem: ConfinedFilesystem, path: bytes) -> None:
    components = validate_relative_path(path)
    parent = b"/".join(components[:-1])
    parent_fd = filesystem.open_directory(parent) if parent else filesystem.open_directory()
    try:
        os.unlink(components[-1], dir_fd=parent_fd)
        os.fsync(parent_fd)
    except FileNotFoundError:
        return
    except OSError:
        raise fail(
            StopReason.CREDENTIAL_REFRESH_FAILURE,
            "credential rollback could not remove a private file",
        ) from None
    finally:
        os.close(parent_fd)


def auto_enroll_default_cli_credentials(
    *,
    codex_credential_id: str,
    claude_credential_id: str,
    codex_auth_parser: AuthParser,
    state_home: str | os.PathLike[str] | None = None,
    codex_source_path: str | os.PathLike[str] | None = None,
    claude_source_path: str | os.PathLike[str] | None = None,
) -> DefaultCredentialEnrollment:
    """Atomically import a wholly absent default pair from passwd-home.

    Custom profile names never consult ambient state.  Existing valid defaults
    are reused as a pair; partial, invalid, or metadata-less state fails closed.
    Both standard source files are read and validated before either target is
    created.  Ordinary failures roll back every target created by this call.
    """

    if (
        codex_credential_id != DEFAULT_CODEX_CREDENTIAL_ID
        or claude_credential_id != DEFAULT_CLAUDE_CREDENTIAL_ID
    ):
        return DefaultCredentialEnrollment(None, None)
    selected_state = xdg_state_home(state_home=state_home)
    profiles_root = selected_state / "agent-loop" / "credentials"
    filesystem: ConfinedFilesystem | None = None
    lock_fd: int | None = None
    claude_account: _LockedCredentialAccount | None = None
    codex_account: _LockedCredentialAccount | None = None
    rollback_new_pair = False
    try:
        filesystem = ConfinedFilesystem.create_private(profiles_root)
        _verify_private_directory(
            filesystem,
            detail="credential profile directory is not private",
        )
        lock_fd = _open_account_lock(filesystem, timeout_seconds=30.0)
        codex_present = _relative_entry_exists(filesystem, b"codex/default")
        claude_present = _relative_entry_exists(filesystem, b"claude/default")
        metadata = _read_optional_private_file(
            filesystem,
            _DEFAULT_PROFILE_METADATA,
            max_bytes=_MAX_METADATA_BYTES,
        )
        transition_data = _read_optional_private_file(
            filesystem,
            _DEFAULT_PROFILE_TRANSITION,
            max_bytes=_MAX_METADATA_BYTES,
        )
        if codex_present or claude_present or metadata is not None or transition_data is not None:
            if not (codex_present and claude_present and metadata is not None):
                raise fail(
                    StopReason.CREDENTIAL_STATE_CONFLICT,
                    "default credential profile is partial and requires explicit repair",
                )
            # Total lock order is profile -> Claude -> Codex.  Verify the
            # durable pair only after both account locks are held, so repair
            # cannot interleave a mixed generation with ordinary preflight.
            claude_account = _lock_credential_account(
                claude_credential_root(
                    DEFAULT_CLAUDE_CREDENTIAL_ID,
                    state_home=selected_state,
                ),
                timeout_seconds=30.0,
            )
            codex_account = _lock_credential_account(
                codex_credential_root(
                    DEFAULT_CODEX_CREDENTIAL_ID,
                    state_home=selected_state,
                ),
                timeout_seconds=30.0,
            )
            codex_durable = _read_private_file(
                codex_account.filesystem,
                b"auth.json",
                max_bytes=_MAX_AUTH_BYTES,
                reason=StopReason.CREDENTIAL_STATE_CONFLICT,
                detail=(
                    "managed Codex credential copy is missing or unsafe; inspect "
                    "`agent-loop auth status`, then use reviewed `agent-loop auth init --repair`"
                ),
            )
            _validate_auth_bytes(
                codex_durable,
                codex_auth_parser,
                reason=StopReason.CREDENTIAL_STATE_CONFLICT,
                detail=(
                    "managed Codex credential copy is invalid; inspect `agent-loop auth status`, "
                    "then use reviewed `agent-loop auth init --repair`"
                ),
            )
            claude_durable = _read_private_file(
                claude_account.filesystem,
                b"credentials.json",
                max_bytes=_MAX_CLAUDE_CREDENTIAL_BYTES,
                reason=StopReason.CREDENTIAL_STATE_CONFLICT,
                detail=(
                    "managed Claude credential copy is missing or unsafe; inspect "
                    "`agent-loop auth status`, then use reviewed `agent-loop auth init --repair`"
                ),
            )
            _validate_auth_bytes(
                claude_durable,
                parse_claude_cli_credentials,
                reason=StopReason.CREDENTIAL_STATE_CONFLICT,
                detail=(
                    "managed Claude credential copy is invalid; inspect `agent-loop auth status`, "
                    "then use reviewed `agent-loop auth init --repair`"
                ),
            )
            if transition_data is not None:
                try:
                    transition = _strict_pair_transition(transition_data)
                except ValueError:
                    raise fail(
                        StopReason.CREDENTIAL_STATE_CONFLICT,
                        "default credential pair transition journal is invalid",
                    ) from None
                if (
                    metadata
                    not in {
                        _transition_marker(transition, new=False),
                        _transition_marker(transition, new=True),
                    }
                    or _sha256(codex_durable)
                    not in {
                        transition.old_codex_sha256,
                        transition.new_codex_sha256,
                    }
                    or _sha256(claude_durable)
                    not in {
                        transition.old_claude_sha256,
                        transition.new_claude_sha256,
                    }
                ):
                    raise fail(
                        StopReason.CREDENTIAL_STATE_CONFLICT,
                        "default credential pair transition witnesses are inconsistent",
                    )
                # Combined acquisition owns recovery because it also has the
                # pinned status probes and evidence barriers.  Lazy bootstrap
                # must not misclassify a recoverable transition as repair.
                return DefaultCredentialEnrollment(None, None)
            if not _valid_default_profile_metadata(
                metadata,
                codex_data=codex_durable,
                claude_data=claude_durable,
            ):
                raise fail(
                    StopReason.CREDENTIAL_STATE_CONFLICT,
                    "default credential pair has no committed matching generation; run "
                    "`agent-loop auth init --repair` after review",
                )
            return DefaultCredentialEnrollment(None, None)

        rollback_new_pair = True

        codex_data = _read_private_source_file(
            active_codex_auth_path() if codex_source_path is None else codex_source_path,
            max_bytes=_MAX_AUTH_BYTES,
            detail=(
                "standard Codex login is missing or unsafe; run `codex login` if needed, then retry"
            ),
        )
        _validate_auth_bytes(
            codex_data,
            codex_auth_parser,
            reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
            detail=(
                "standard Codex login failed validation; run `codex login` if needed, then retry"
            ),
        )
        claude_data = _read_private_source_file(
            (
                active_claude_credentials_path()
                if claude_source_path is None
                else claude_source_path
            ),
            max_bytes=_MAX_CLAUDE_CREDENTIAL_BYTES,
            detail=(
                "standard Claude login is missing or unsafe; run `claude auth login` if needed, "
                "then retry"
            ),
        )
        _validate_auth_bytes(
            claude_data,
            parse_claude_cli_credentials,
            reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
            detail=(
                "standard Claude login failed validation; run `claude auth login` if needed, "
                "then retry"
            ),
        )

        claude_account = _lock_credential_account(
            claude_credential_root(DEFAULT_CLAUDE_CREDENTIAL_ID, state_home=selected_state),
            timeout_seconds=30.0,
        )
        codex_account = _lock_credential_account(
            codex_credential_root(DEFAULT_CODEX_CREDENTIAL_ID, state_home=selected_state),
            timeout_seconds=30.0,
        )
        if _transaction_names_if_present(
            claude_account.filesystem
        ) or _transaction_names_if_present(codex_account.filesystem):
            raise fail(
                StopReason.CREDENTIAL_STATE_CONFLICT,
                "new default credential roots unexpectedly contain transaction state",
            )
        if (
            _read_optional_private_file(
                codex_account.filesystem,
                b"auth.json",
                max_bytes=_MAX_AUTH_BYTES,
            )
            is not None
            or _read_optional_private_file(
                claude_account.filesystem,
                b"credentials.json",
                max_bytes=_MAX_CLAUDE_CREDENTIAL_BYTES,
            )
            is not None
        ):
            raise fail(
                StopReason.CREDENTIAL_STATE_CONFLICT,
                "default credential roots changed during exclusive bootstrap",
            )
        codex_account.filesystem.atomic_write(
            b"auth.json",
            codex_data,
            mode=PRIVATE_FILE_MODE,
            create_parents=False,
        )
        claude_account.filesystem.atomic_write(
            b"credentials.json",
            claude_data,
            mode=PRIVATE_FILE_MODE,
            create_parents=False,
        )
        filesystem.atomic_write(
            _DEFAULT_PROFILE_METADATA,
            _default_profile_metadata_bytes(codex_data, claude_data),
            mode=PRIVATE_FILE_MODE,
            create_parents=False,
        )
        rollback_new_pair = False
        return DefaultCredentialEnrollment(
            CredentialEnrollment(DEFAULT_CODEX_CREDENTIAL_ID, installed=True),
            CredentialEnrollment(DEFAULT_CLAUDE_CREDENTIAL_ID, installed=True),
        )
    except BaseException as original_error:
        if rollback_new_pair and filesystem is not None:
            rollback_error: BaseException | None = None
            try:
                _remove_relative_file(filesystem, _DEFAULT_PROFILE_METADATA)
            except BaseException as exc:
                rollback_error = exc
            for path in (b"codex/default", b"claude/default"):
                try:
                    _remove_relative_tree(filesystem, path)
                except BaseException as exc:
                    rollback_error = rollback_error or exc
            if rollback_error is not None:
                raise rollback_error from original_error
        raise
    finally:
        if codex_account is not None:
            codex_account.close()
        if claude_account is not None:
            claude_account.close()
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
        if filesystem is not None:
            filesystem.close()


def default_cli_credential_pair_state(
    *,
    codex_auth_parser: AuthParser,
    state_home: str | os.PathLike[str] | None = None,
) -> str:
    """Return a secret-free readiness, busy, or recovery state."""

    selected_state = xdg_state_home(state_home=state_home)
    profiles_root = selected_state / "agent-loop" / "credentials"
    filesystem: ConfinedFilesystem | None = None
    lock_fd: int | None = None
    claude_account: _LockedCredentialAccount | None = None
    codex_account: _LockedCredentialAccount | None = None
    try:
        try:
            filesystem = ConfinedFilesystem.open(profiles_root)
        except AgentLoopError as exc:
            cause = exc.__cause__
            if isinstance(cause, OSError) and cause.errno == 2:
                return "absent"
            return "repair_required"
        _verify_private_directory(
            filesystem,
            detail="credential profile directory is not private",
        )
        try:
            lock_fd = _open_account_lock(
                filesystem,
                timeout_seconds=_STATUS_LOCK_TIMEOUT_SECONDS,
            )
        except AgentLoopError as exc:
            if exc.reason is StopReason.CREDENTIAL_STATE_CONFLICT:
                return "busy"
            raise
        codex_present = _relative_entry_exists(filesystem, b"codex/default")
        claude_present = _relative_entry_exists(filesystem, b"claude/default")
        metadata = _read_optional_private_file(
            filesystem,
            _DEFAULT_PROFILE_METADATA,
            max_bytes=_MAX_METADATA_BYTES,
        )
        transition_data = _read_optional_private_file(
            filesystem,
            _DEFAULT_PROFILE_TRANSITION,
            max_bytes=_MAX_METADATA_BYTES,
        )
        if (
            not codex_present
            and not claude_present
            and metadata is None
            and transition_data is None
        ):
            return "absent"
        if not (codex_present and claude_present and metadata is not None):
            return "repair_required"
        try:
            claude_account = _lock_credential_account(
                claude_credential_root(DEFAULT_CLAUDE_CREDENTIAL_ID, state_home=selected_state),
                timeout_seconds=_STATUS_LOCK_TIMEOUT_SECONDS,
            )
            codex_account = _lock_credential_account(
                codex_credential_root(DEFAULT_CODEX_CREDENTIAL_ID, state_home=selected_state),
                timeout_seconds=_STATUS_LOCK_TIMEOUT_SECONDS,
            )
        except AgentLoopError as exc:
            if exc.reason is StopReason.CREDENTIAL_STATE_CONFLICT:
                return "busy"
            raise
        codex_data = _read_private_file(
            codex_account.filesystem,
            b"auth.json",
            max_bytes=_MAX_AUTH_BYTES,
            reason=StopReason.CREDENTIAL_STATE_CONFLICT,
            detail="default Codex credential is unsafe",
        )
        claude_data = _read_private_file(
            claude_account.filesystem,
            b"credentials.json",
            max_bytes=_MAX_CLAUDE_CREDENTIAL_BYTES,
            reason=StopReason.CREDENTIAL_STATE_CONFLICT,
            detail="default Claude credential is unsafe",
        )
        _validate_auth_bytes(
            codex_data,
            codex_auth_parser,
            reason=StopReason.CREDENTIAL_STATE_CONFLICT,
            detail="default Codex credential is invalid",
        )
        _validate_auth_bytes(
            claude_data,
            parse_claude_cli_credentials,
            reason=StopReason.CREDENTIAL_STATE_CONFLICT,
            detail="default Claude credential is invalid",
        )
        if transition_data is not None:
            try:
                transition = _strict_pair_transition(transition_data)
            except ValueError:
                return "repair_required"
            marker_is_old = metadata == _transition_marker(transition, new=False)
            marker_is_new = metadata == _transition_marker(transition, new=True)
            codex_is_bound = _sha256(codex_data) in {
                transition.old_codex_sha256,
                transition.new_codex_sha256,
            }
            claude_is_bound = _sha256(claude_data) in {
                transition.old_claude_sha256,
                transition.new_claude_sha256,
            }
            codex_pending = _transaction_names_if_present(codex_account.filesystem)
            claude_pending = _transaction_names_if_present(claude_account.filesystem)
            if (
                not (marker_is_old or marker_is_new)
                or not codex_is_bound
                or not claude_is_bound
                or codex_pending not in {(), (transition.codex_run_id,)}
                or claude_pending not in {(), (transition.claude_run_id,)}
            ):
                return "repair_required"
            codex_candidate = _journal_candidate(
                codex_account,
                run_id=transition.codex_run_id,
                candidate_suffix=b"/codex-home/auth.json",
                old_sha256=transition.old_codex_sha256,
                new_sha256=transition.new_codex_sha256,
                max_bytes=_MAX_AUTH_BYTES,
                parser=codex_auth_parser,
                evidence_barrier=None,
                label="Codex",
            )
            claude_candidate = _journal_candidate(
                claude_account,
                run_id=transition.claude_run_id,
                candidate_suffix=b"/claude-home/.credentials.json",
                old_sha256=transition.old_claude_sha256,
                new_sha256=transition.new_claude_sha256,
                max_bytes=_MAX_CLAUDE_CREDENTIAL_BYTES,
                parser=parse_claude_cli_credentials,
                evidence_barrier=None,
                label="Claude",
            )
            if not codex_pending or not claude_pending:
                if not marker_is_new:
                    return "repair_required"
                if (
                    _sha256(codex_data) != transition.new_codex_sha256
                    or _sha256(claude_data) != transition.new_claude_sha256
                ):
                    return "repair_required"
            if bool(codex_pending) != (codex_candidate is not None) or bool(claude_pending) != (
                claude_candidate is not None
            ):
                return "repair_required"
            return "recovery_pending"
        if not _valid_default_profile_metadata(
            metadata,
            codex_data=codex_data,
            claude_data=claude_data,
        ):
            return "repair_required"
        if _transaction_names_if_present(
            claude_account.filesystem
        ) or _transaction_names_if_present(codex_account.filesystem):
            return "recovery_pending"
        return "ready"
    except AgentLoopError, OSError, TypeError, ValueError:
        return "repair_required"
    finally:
        if codex_account is not None:
            codex_account.close()
        if claude_account is not None:
            claude_account.close()
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
        if filesystem is not None:
            filesystem.close()


def _read_existing_account_credential(
    root: Path,
    path: bytes,
    *,
    max_bytes: int,
    validate: Callable[[bytes], bool],
) -> bytes | None:
    try:
        filesystem = ConfinedFilesystem.open(root)
    except AgentLoopError as exc:
        cause = exc.__cause__
        if isinstance(cause, OSError) and cause.errno == 2:
            return None
        raise
    try:
        _verify_private_directory(
            filesystem,
            detail="credential repair found a non-private account directory",
        )
        if _transaction_names_if_present(filesystem):
            raise fail(
                StopReason.CREDENTIAL_STATE_CONFLICT,
                "credential repair cannot run while an account transaction is active",
            )
        data = _read_optional_private_file(filesystem, path, max_bytes=max_bytes)
        if data is None:
            raise fail(
                StopReason.CREDENTIAL_STATE_CONFLICT,
                (
                    "credential repair found an incomplete account directory; "
                    "manual review is required"
                ),
            )
        _validate_auth_bytes(
            data,
            validate,
            reason=StopReason.CREDENTIAL_STATE_CONFLICT,
            detail=(
                "credential repair found invalid existing account data; manual review is required"
            ),
        )
        return data
    finally:
        filesystem.close()


def _account_transaction_names_if_present(root: Path) -> tuple[str, ...]:
    try:
        filesystem = ConfinedFilesystem.open(root)
    except AgentLoopError as exc:
        cause = exc.__cause__
        if isinstance(cause, OSError) and cause.errno == 2:
            return ()
        raise
    try:
        _verify_private_directory(
            filesystem,
            detail="credential account directory is not private",
        )
        return _transaction_names_if_present(filesystem)
    finally:
        filesystem.close()


def repair_default_cli_credentials(
    *,
    codex_auth_parser: AuthParser,
    state_home: str | os.PathLike[str] | None = None,
    codex_source_path: str | os.PathLike[str] | None = None,
    claude_source_path: str | os.PathLike[str] | None = None,
) -> DefaultCredentialEnrollment:
    """Explicitly rotate or complete the default pair with ordinary rollback."""

    selected_state = xdg_state_home(state_home=state_home)
    profiles_root = selected_state / "agent-loop" / "credentials"
    filesystem: ConfinedFilesystem | None = None
    lock_fd: int | None = None
    claude_account: _LockedCredentialAccount | None = None
    codex_account: _LockedCredentialAccount | None = None
    codex_root_present = True
    claude_root_present = True
    try:
        filesystem = ConfinedFilesystem.create_private(profiles_root)
        _verify_private_directory(
            filesystem,
            detail="credential profile directory is not private",
        )
        lock_fd = _open_account_lock(filesystem, timeout_seconds=30.0)
        if (
            _read_optional_private_file(
                filesystem,
                _DEFAULT_PROFILE_TRANSITION,
                max_bytes=_MAX_METADATA_BYTES,
            )
            is not None
        ):
            raise fail(
                StopReason.CREDENTIAL_STATE_CONFLICT,
                "credential repair cannot replace a recoverable pair transition",
            )
        codex_root = codex_credential_root(
            DEFAULT_CODEX_CREDENTIAL_ID,
            state_home=selected_state,
        )
        claude_root = claude_credential_root(
            DEFAULT_CLAUDE_CREDENTIAL_ID,
            state_home=selected_state,
        )
        codex_root_present = _relative_entry_exists(filesystem, b"codex/default")
        claude_root_present = _relative_entry_exists(filesystem, b"claude/default")
        if _account_transaction_names_if_present(
            claude_root
        ) or _account_transaction_names_if_present(codex_root):
            raise fail(
                StopReason.CREDENTIAL_STATE_CONFLICT,
                "credential repair cannot run while an account transaction is active",
            )
        codex_data = _read_private_source_file(
            active_codex_auth_path() if codex_source_path is None else codex_source_path,
            max_bytes=_MAX_AUTH_BYTES,
            detail=(
                "Codex repair source is missing or unsafe; run `codex login`, then retry "
                "`agent-loop auth init --repair`"
            ),
        )
        _validate_auth_bytes(
            codex_data,
            codex_auth_parser,
            reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
            detail=(
                "Codex repair source failed validation; run `codex login`, then retry "
                "`agent-loop auth init --repair`"
            ),
        )
        claude_data = _read_private_source_file(
            (
                active_claude_credentials_path()
                if claude_source_path is None
                else claude_source_path
            ),
            max_bytes=_MAX_CLAUDE_CREDENTIAL_BYTES,
            detail=(
                "Claude repair source is missing or unsafe; run `claude auth login`, then retry "
                "`agent-loop auth init --repair`"
            ),
        )
        _validate_auth_bytes(
            claude_data,
            parse_claude_cli_credentials,
            reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
            detail=(
                "Claude repair source failed validation; run `claude auth login`, then retry "
                "`agent-loop auth init --repair`"
            ),
        )
        # The profile lock and both account locks stay held through snapshot,
        # pair write, commit-marker write, and any rollback.
        claude_account = _lock_credential_account(
            claude_root,
            timeout_seconds=30.0,
        )
        codex_account = _lock_credential_account(
            codex_root,
            timeout_seconds=30.0,
        )
        if _transaction_names_if_present(
            claude_account.filesystem
        ) or _transaction_names_if_present(codex_account.filesystem):
            raise fail(
                StopReason.CREDENTIAL_STATE_CONFLICT,
                "credential repair cannot run while an account transaction is active",
            )
        old_codex = _read_optional_private_file(
            codex_account.filesystem,
            b"auth.json",
            max_bytes=_MAX_AUTH_BYTES,
        )
        if old_codex is not None:
            _validate_auth_bytes(
                old_codex,
                codex_auth_parser,
                reason=StopReason.CREDENTIAL_STATE_CONFLICT,
                detail=(
                    "credential repair found invalid Codex account data; manual review is required"
                ),
            )
        old_claude = _read_optional_private_file(
            claude_account.filesystem,
            b"credentials.json",
            max_bytes=_MAX_CLAUDE_CREDENTIAL_BYTES,
        )
        if old_claude is not None:
            _validate_auth_bytes(
                old_claude,
                parse_claude_cli_credentials,
                reason=StopReason.CREDENTIAL_STATE_CONFLICT,
                detail=(
                    "credential repair found invalid Claude account data; manual review is required"
                ),
            )
        old_metadata = _read_optional_private_file(
            filesystem,
            _DEFAULT_PROFILE_METADATA,
            max_bytes=_MAX_METADATA_BYTES,
        )
        try:
            codex_account.filesystem.atomic_write(
                b"auth.json",
                codex_data,
                mode=PRIVATE_FILE_MODE,
                create_parents=False,
            )
            claude_account.filesystem.atomic_write(
                b"credentials.json",
                claude_data,
                mode=PRIVATE_FILE_MODE,
                create_parents=False,
            )
            filesystem.atomic_write(
                _DEFAULT_PROFILE_METADATA,
                _default_profile_metadata_bytes(codex_data, claude_data),
                mode=PRIVATE_FILE_MODE,
                create_parents=False,
            )
        except BaseException as original_error:
            rollback_error: BaseException | None = None
            for old, account, path in (
                (old_codex, codex_account, b"auth.json"),
                (old_claude, claude_account, b"credentials.json"),
            ):
                try:
                    if old is None:
                        _remove_relative_file(account.filesystem, path)
                    else:
                        account.filesystem.atomic_write(
                            path,
                            old,
                            mode=PRIVATE_FILE_MODE,
                            create_parents=False,
                        )
                except BaseException as exc:
                    rollback_error = rollback_error or exc
            try:
                if old_metadata is not None:
                    filesystem.atomic_write(
                        _DEFAULT_PROFILE_METADATA,
                        old_metadata,
                        mode=PRIVATE_FILE_MODE,
                        create_parents=False,
                    )
                else:
                    _remove_relative_file(filesystem, _DEFAULT_PROFILE_METADATA)
            except BaseException as exc:
                rollback_error = rollback_error or exc
            for existed, path in (
                (codex_root_present, b"codex/default"),
                (claude_root_present, b"claude/default"),
            ):
                if existed:
                    continue
                try:
                    _remove_relative_tree(filesystem, path)
                except BaseException as exc:
                    rollback_error = rollback_error or exc
            if rollback_error is not None:
                raise rollback_error from original_error
            raise
        return DefaultCredentialEnrollment(
            CredentialEnrollment(DEFAULT_CODEX_CREDENTIAL_ID, old_codex != codex_data),
            CredentialEnrollment(DEFAULT_CLAUDE_CREDENTIAL_ID, old_claude != claude_data),
        )
    except BaseException as original_error:
        cleanup_error: BaseException | None = None
        if filesystem is not None:
            for existed, path in (
                (codex_root_present, b"codex/default"),
                (claude_root_present, b"claude/default"),
            ):
                if existed:
                    continue
                try:
                    _remove_relative_tree(filesystem, path)
                except BaseException as exc:
                    cleanup_error = cleanup_error or exc
        if cleanup_error is not None:
            raise cleanup_error from original_error
        raise
    finally:
        if codex_account is not None:
            codex_account.close()
        if claude_account is not None:
            claude_account.close()
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
        if filesystem is not None:
            filesystem.close()


def _codex_refresh_generation(data: bytes) -> tuple[int, ...] | None:
    value = _strict_json_object(data)
    refreshed = None if value is None else value.get("last_refresh")
    match = _CODEX_REFRESH_TIMESTAMP.fullmatch(refreshed) if isinstance(refreshed, str) else None
    if match is None:
        return None
    components = tuple(int(item) for item in match.groups(default="0")[:6])
    fraction = int(match.group(7).ljust(9, "0")) if match.group(7) else 0
    year, month, day, hour, minute, second = components
    if (
        not 1970 <= year <= 9999
        or not 1 <= month <= 12
        or not 1 <= day <= 31
        or not 0 <= hour <= 23
        or not 0 <= minute <= 59
        or not 0 <= second <= 60
    ):
        return None
    return (*components, fraction)


def _claude_refresh_generation(data: bytes) -> tuple[int, int] | None:
    value = _strict_json_object(data)
    oauth = None if value is None else value.get("claudeAiOauth")
    if not isinstance(oauth, dict):
        return None
    refresh_expiry = oauth.get("refreshTokenExpiresAt")
    access_expiry = oauth.get("expiresAt")
    if (
        not isinstance(refresh_expiry, int)
        or isinstance(refresh_expiry, bool)
        or not isinstance(access_expiry, int)
        or isinstance(access_expiry, bool)
    ):
        return None
    return refresh_expiry, access_expiry


def _optional_standard_credential(
    path: Path,
    *,
    max_bytes: int,
    validate: AuthParser,
) -> bytes | None:
    if not os.path.lexists(path):
        return None
    try:
        value = _read_private_source_file(
            path,
            max_bytes=max_bytes,
            detail="standard vendor login is present but unsafe",
        )
    except AgentLoopError:
        # A valid private default remains usable while an incomplete or
        # unsupported ambient vendor login is repaired by its own CLI.
        return None
    return value if validate(value) else None


def _newer_standard_credential_pair(
    codex_durable: bytes,
    claude_durable: bytes,
    *,
    codex_auth_parser: AuthParser,
) -> tuple[bytes | None, bytes | None]:
    """Select only monotonic, parser-valid vendor-login generations."""

    standard_codex_path = active_codex_auth_path()
    standard_claude_path = active_claude_credentials_path()
    standard_codex = _optional_standard_credential(
        standard_codex_path,
        max_bytes=_MAX_AUTH_BYTES,
        validate=codex_auth_parser,
    )
    standard_claude = _optional_standard_credential(
        standard_claude_path,
        max_bytes=_MAX_CLAUDE_CREDENTIAL_BYTES,
        validate=parse_claude_cli_credentials,
    )
    codex_source_generation = (
        _codex_refresh_generation(standard_codex) if standard_codex is not None else None
    )
    codex_durable_generation = _codex_refresh_generation(codex_durable)
    claude_source_generation = (
        _claude_refresh_generation(standard_claude) if standard_claude is not None else None
    )
    claude_durable_generation = _claude_refresh_generation(claude_durable)
    return (
        standard_codex
        if codex_source_generation is not None
        and codex_durable_generation is not None
        and codex_source_generation > codex_durable_generation
        else None,
        standard_claude
        if claude_source_generation is not None
        and claude_durable_generation is not None
        and claude_source_generation > claude_durable_generation
        else None,
    )


def claude_setup_token_enrolled(
    credential_id: str = DEFAULT_CLAUDE_CREDENTIAL_ID,
    *,
    state_home: str | os.PathLike[str] | None = None,
    environ: Mapping[str, str] | None = None,
) -> bool:
    """Return whether one valid private inference-only Claude token exists."""

    safe_id = _safe_identifier(credential_id, name="Claude credential ID")
    return _private_credential_enrolled(
        claude_credential_root(safe_id, state_home=state_home, environ=environ),
        b"oauth-token",
        max_bytes=_MAX_TOKEN_BYTES,
        validate=_valid_claude_token_file,
    )


def _valid_claude_token_file(raw: bytes) -> bool:
    try:
        _normalized_claude_token_bytes(raw)
    except TypeError, ValueError:
        return False
    return True


def _private_credential_enrolled(
    root: Path,
    relative_path: bytes,
    *,
    max_bytes: int,
    validate: Callable[[bytes], bool],
) -> bool:
    filesystem: ConfinedFilesystem | None = None
    try:
        try:
            filesystem = ConfinedFilesystem.open(root)
        except AgentLoopError as exc:
            cause = exc.__cause__
            if isinstance(cause, OSError) and cause.errno == 2:
                return False
            raise
        _verify_private_directory(
            filesystem,
            detail="credential enrollment directory is not private",
        )
        try:
            data = _read_optional_private_file(
                filesystem,
                relative_path,
                max_bytes=max_bytes,
            )
        except AgentLoopError, OSError, TypeError, ValueError:
            raise fail(
                StopReason.CREDENTIAL_REFRESH_FAILURE,
                "enrolled credential is unsafe",
            ) from None
        if data is None:
            return False
        try:
            valid = validate(data)
        except Exception:
            valid = False
        if valid is not True:
            raise fail(
                StopReason.CREDENTIAL_REFRESH_FAILURE,
                "enrolled credential failed validation",
            )
        return True
    finally:
        if filesystem is not None:
            filesystem.close()


def load_claude_setup_token(
    credential_id: str,
    *,
    state_home: str | os.PathLike[str] | None = None,
    environ: Mapping[str, str] | None = None,
) -> str:
    """Load only the dedicated mode-0600 setup token, never ambient auth."""

    root = claude_credential_root(
        credential_id,
        state_home=state_home,
        environ=environ,
    )
    filesystem: ConfinedFilesystem | None = None
    try:
        filesystem = ConfinedFilesystem.open(root)
        _verify_private_directory(
            filesystem,
            detail="Claude credential account directory is not private",
        )
        raw = _read_private_file(
            filesystem,
            b"oauth-token",
            max_bytes=_MAX_TOKEN_BYTES,
            reason=StopReason.CREDENTIAL_REFRESH_FAILURE,
            detail="dedicated Claude setup token is missing or unsafe",
        )
    finally:
        if filesystem is not None:
            filesystem.close()
    try:
        token = _normalized_claude_token_bytes(raw).decode("utf-8")
    except TypeError, ValueError:
        raise fail(
            StopReason.CREDENTIAL_REFRESH_FAILURE,
            "dedicated Claude setup token format is invalid",
        ) from None
    return token


def _safe_control_directory(path: str | os.PathLike[str], *, name: str) -> str:
    return str(_normalized_absolute(path, name=name))


def build_claude_parent_environment(
    token: str | None,
    *,
    config_dir: str | os.PathLike[str],
    tmp_dir: str | os.PathLike[str],
    ambient: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Build a complete allowlisted parent env; ambient values are never copied."""

    del ambient  # Accepted only so callers can prove hostile ambient state is ignored.
    if token is not None and (
        not isinstance(token, str)
        or not token
        or any(character.isspace() or ord(character) < 0x20 for character in token)
    ):
        raise ValueError("Claude setup token format is invalid")
    config = _safe_control_directory(config_dir, name="CLAUDE_CONFIG_DIR")
    temporary = _safe_control_directory(tmp_dir, name="CLAUDE_CODE_TMPDIR")
    result = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": "/runtime/home",
        "TMPDIR": "/runtime/tmp",
        "LANG": "C.UTF-8",
        "CLAUDE_CONFIG_DIR": config,
        "CLAUDE_CODE_TMPDIR": temporary,
        "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
    }
    if token is not None:
        result["CLAUDE_CODE_OAUTH_TOKEN"] = token
    return result


def scrub_claude_child_environment(parent: Mapping[str, str]) -> dict[str, str]:
    """Model the allowlisted managed-child view used by confinement probes."""

    allowed = (
        "PATH",
        "HOME",
        "TMPDIR",
        "LANG",
        "CLAUDE_CONFIG_DIR",
        "CLAUDE_CODE_TMPDIR",
        "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB",
    )
    return {name: parent[name] for name in allowed if name in parent}


__all__ = [
    "DEFAULT_CLAUDE_CREDENTIAL_ID",
    "DEFAULT_CODEX_CREDENTIAL_ID",
    "AuthParser",
    "AuthProbe",
    "ClaudeCredentialTransaction",
    "CodexCredentialTransaction",
    "CombinedCredentialTransaction",
    "CredentialEnrollment",
    "DefaultCredentialEnrollment",
    "active_claude_credentials_path",
    "active_codex_auth_path",
    "auto_enroll_default_cli_credentials",
    "build_claude_parent_environment",
    "claude_cli_credential_secret_values",
    "claude_cli_credentials_enrolled",
    "claude_credential_root",
    "claude_setup_token_enrolled",
    "codex_credential_root",
    "codex_file_auth_enrolled",
    "default_cli_credential_pair_state",
    "enroll_claude_cli_credentials",
    "enroll_claude_setup_token",
    "enroll_codex_file_auth",
    "load_claude_setup_token",
    "parse_claude_cli_credentials",
    "repair_default_cli_credentials",
    "scrub_claude_child_environment",
    "xdg_state_home",
]
