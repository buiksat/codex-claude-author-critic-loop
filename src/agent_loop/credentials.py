"""Account-scoped credential transactions and Claude token isolation.

Credential bytes are deliberately absent from every exception detail and from
all transaction metadata.  Callers must treat returned tokens and the Codex
transaction home as control-plane secrets and must never mount them into an
untrusted execution path.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from types import TracebackType
from typing import Self

from .constants import PRIVATE_DIR_MODE, PRIVATE_FILE_MODE
from .errors import AgentLoopError, StopReason, fail
from .filesystem import ConfinedFilesystem, open_beneath

AuthParser = Callable[[bytes], bool]
AuthProbe = Callable[[Path], bool]
EvidenceBarrier = Callable[[str, tuple[bytes, ...]], None]

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TRANSACTION_SCHEMA_VERSION = 1
_MAX_AUTH_BYTES = 4 * 1024 * 1024
_MAX_AUTH_GENERATION_HISTORY = 256
_MAX_AUTH_GENERATION_HISTORY_BYTES = 16 * _MAX_AUTH_BYTES
_MAX_TOKEN_BYTES = 64 * 1024
_MAX_METADATA_BYTES = 16 * 1024
_LOCK_POLL_SECONDS = 0.01


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
    except (AgentLoopError, OSError, TypeError, ValueError):
        raise fail(reason, detail) from None


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
    except (UnicodeDecodeError, ValueError):
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
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii") + b"\n"


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
            except (OSError, UnicodeDecodeError, ValueError):
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
        except (FileNotFoundError, OSError):
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
        safe_credential_id = _safe_identifier(
            credential_id, name="Codex credential ID"
        )
        safe_run_id = _safe_identifier(run_id, name="run ID")
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
    if raw.endswith(b"\r\n"):
        raw = raw[:-2]
    elif raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        token = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise fail(
            StopReason.CREDENTIAL_REFRESH_FAILURE,
            "dedicated Claude setup token encoding is invalid",
        ) from None
    if not token or any(character.isspace() or ord(character) < 0x20 for character in token):
        raise fail(
            StopReason.CREDENTIAL_REFRESH_FAILURE,
            "dedicated Claude setup token format is invalid",
        )
    return token


def _safe_control_directory(path: str | os.PathLike[str], *, name: str) -> str:
    return str(_normalized_absolute(path, name=name))


def build_claude_parent_environment(
    token: str,
    *,
    config_dir: str | os.PathLike[str],
    tmp_dir: str | os.PathLike[str],
    ambient: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Build a complete allowlisted parent env; ambient values are never copied."""

    del ambient  # Accepted only so callers can prove hostile ambient state is ignored.
    if (
        not isinstance(token, str)
        or not token
        or any(character.isspace() or ord(character) < 0x20 for character in token)
    ):
        raise ValueError("Claude setup token format is invalid")
    config = _safe_control_directory(config_dir, name="CLAUDE_CONFIG_DIR")
    temporary = _safe_control_directory(tmp_dir, name="CLAUDE_CODE_TMPDIR")
    return {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": "/runtime/home",
        "TMPDIR": "/runtime/tmp",
        "LANG": "C.UTF-8",
        "CLAUDE_CONFIG_DIR": config,
        "CLAUDE_CODE_TMPDIR": temporary,
        "CLAUDE_CODE_OAUTH_TOKEN": token,
        "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
    }


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
    "AuthParser",
    "AuthProbe",
    "CodexCredentialTransaction",
    "build_claude_parent_environment",
    "claude_credential_root",
    "codex_credential_root",
    "load_claude_setup_token",
    "scrub_claude_child_environment",
    "xdg_state_home",
]
