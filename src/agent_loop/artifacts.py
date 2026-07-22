"""Private, crash-consistent retained artifact storage."""

from __future__ import annotations

import base64
import binascii
import errno
import fcntl
import hashlib
import json
import os
import stat
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import TracebackType
from typing import Self

from .constants import PRIVATE_FILE_MODE, Limits
from .declassify import KnownSecret, raw_log_contains_known_secret
from .errors import AgentLoopError, StopReason, fail
from .filesystem import ConfinedFilesystem
from .models import sha256_hex

_WITHHOLDING_CONTROL_DIRECTORY = ".agent-loop-artifact-control"
_WITHHOLDING_MARKER_PREFIX = b"withheld-v1-"
_WITHHOLDING_LOCK_PREFIX = b"lock-v1-"


def _artifact_path(path: str | bytes) -> bytes:
    if isinstance(path, bytes):
        return path
    if not isinstance(path, str):
        raise TypeError("artifact paths must be str or bytes")
    try:
        return path.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("runner-owned artifact names must be ASCII") from exc


def _withholding_location(
    root: str | bytes | os.PathLike[str] | os.PathLike[bytes],
) -> tuple[str | bytes, bytes]:
    """Return a private sibling control root and opaque per-run latch name.

    The latch deliberately lives outside the retained run tree.  Credential
    values are arbitrary non-empty UTF-8 strings, so no fixed retained
    filename can be proven disjoint from every possible value.
    """

    raw = os.fspath(root)
    if not isinstance(raw, (str, bytes)):
        raise TypeError("artifact root must be a filesystem path")
    if isinstance(raw, bytes):
        parent_bytes = os.path.dirname(raw)
        if not os.path.basename(raw):
            raise ValueError("artifact root must have a final component")
        if os.path.basename(parent_bytes) == b"runs":
            control_root_bytes = os.path.join(
                os.path.dirname(parent_bytes), b"control", b"artifact-withholding"
            )
        else:
            control_root_bytes = os.path.join(
                parent_bytes, _WITHHOLDING_CONTROL_DIRECTORY.encode("ascii")
            )
        root_absolute_bytes = os.path.abspath(raw)
        control_absolute_bytes = os.path.abspath(control_root_bytes)
        if os.path.commonpath((root_absolute_bytes, control_absolute_bytes)) == root_absolute_bytes:
            raise ValueError(
                "artifact root must be structurally disjoint from its withholding control root"
            )
        marker = _WITHHOLDING_MARKER_PREFIX + hashlib.sha256(raw).hexdigest().encode("ascii")
        return control_root_bytes, marker

    parent_text = os.path.dirname(raw)
    if not os.path.basename(raw):
        raise ValueError("artifact root must have a final component")
    if os.path.basename(parent_text) == "runs":
        control_root_text = os.path.join(
            os.path.dirname(parent_text), "control", "artifact-withholding"
        )
    else:
        control_root_text = os.path.join(parent_text, _WITHHOLDING_CONTROL_DIRECTORY)
    root_absolute_text = os.path.abspath(raw)
    control_absolute_text = os.path.abspath(control_root_text)
    if os.path.commonpath((root_absolute_text, control_absolute_text)) == root_absolute_text:
        raise ValueError(
            "artifact root must be structurally disjoint from its withholding control root"
        )
    marker = _WITHHOLDING_MARKER_PREFIX + hashlib.sha256(raw.encode()).hexdigest().encode("ascii")
    return control_root_text, marker


def _retained_bytes_contain_known_secret(
    data: bytes,
    secrets: tuple[KnownSecret, ...],
) -> bool:
    """Scan raw, decoded JSON, and canonical base64 artifact representations."""

    def decode_base64(value: bytes) -> bytes | None:
        if not value or len(value) % 4:
            return None
        try:
            decoded = base64.b64decode(value, validate=True)
        except binascii.Error:
            return None
        return decoded if base64.b64encode(decoded) == value else None

    pending: list[tuple[bytes, int]] = [(data, 0)]
    decoded_bytes = 0
    visited_values = 0
    while pending:
        current, depth = pending.pop()
        if raw_log_contains_known_secret(current, secrets):
            return True
        if depth >= 4:
            continue
        direct = decode_base64(current.strip())
        if direct is not None:
            decoded_bytes += len(direct)
            if decoded_bytes > 512 * 1024 * 1024:
                return True
            pending.append((direct, depth + 1))

        documents: list[object] = []
        try:
            documents.append(json.loads(current))
        except UnicodeDecodeError, ValueError, RecursionError:
            for line in current.splitlines():
                if not line:
                    continue
                try:
                    documents.append(json.loads(line))
                except UnicodeDecodeError, ValueError, RecursionError:
                    continue

        stack = documents
        while stack:
            visited_values += 1
            if visited_values > 1_000_000:
                return True
            value = stack.pop()
            if isinstance(value, str):
                try:
                    encoded = value.encode("utf-8", "strict")
                except UnicodeEncodeError:
                    return True
                if raw_log_contains_known_secret(encoded, secrets):
                    return True
                try:
                    ascii_value = value.encode("ascii")
                except UnicodeEncodeError:
                    continue
                decoded = decode_base64(ascii_value)
                if decoded is not None:
                    decoded_bytes += len(decoded)
                    if decoded_bytes > 512 * 1024 * 1024:
                        return True
                    pending.append((decoded, depth + 1))
            elif isinstance(value, dict):
                stack.extend(value.keys())
                stack.extend(value.values())
            elif isinstance(value, (tuple, list)):
                stack.extend(value)
    return False


class ArtifactStore:
    """A private run-root store that never follows artifact-path symlinks."""

    def __init__(
        self,
        filesystem: ConfinedFilesystem,
        *,
        withholding_control_root: object,
        withholding_marker: object,
    ) -> None:
        root_info = os.fstat(filesystem.fileno())
        if (
            root_info.st_uid != os.geteuid()
            or root_info.st_gid != os.getegid()
            or stat.S_IMODE(root_info.st_mode) != 0o700
        ):
            filesystem.close()
            raise fail(
                StopReason.OUT_OF_BAND_CHANGE,
                "artifact root ownership or mode is not private",
            )
        self._filesystem = filesystem
        if not isinstance(withholding_control_root, (str, bytes)) or not isinstance(
            withholding_marker, bytes
        ):
            filesystem.close()
            raise TypeError("artifact withholding control identity is invalid")
        marker_digest = withholding_marker.removeprefix(_WITHHOLDING_MARKER_PREFIX)
        if (
            not withholding_marker.startswith(_WITHHOLDING_MARKER_PREFIX)
            or len(marker_digest) != 64
            or any(value not in b"0123456789abcdef" for value in marker_digest)
        ):
            filesystem.close()
            raise ValueError("artifact withholding marker identity is invalid")
        self._withholding_control_root = withholding_control_root
        self._withholding_marker = withholding_marker
        self._withholding_lock_name = _WITHHOLDING_LOCK_PREFIX + marker_digest
        self._withholding_lock_fd: int | None = None
        self._withholding_thread_lock = threading.RLock()
        self._withholding_lock_depth = 0
        self._content_withheld_due_to_secret = False
        self._secret_scrub_failed = False
        try:
            self._withholding_lock_fd = self._open_withholding_lock()
            self._acquire_withholding_lock()
            try:
                self._content_withheld_due_to_secret = self._durable_withholding_latched()
            finally:
                self._release_withholding_lock()
        except BaseException:
            if self._withholding_lock_fd is not None:
                os.close(self._withholding_lock_fd)
            filesystem.close()
            raise

    @classmethod
    def create(cls, root: str | bytes | os.PathLike[str] | os.PathLike[bytes]) -> Self:
        """Create/open a mode-0700 run root through confined path traversal."""

        control_root, marker = _withholding_location(root)
        return cls(
            ConfinedFilesystem.create_private(root),
            withholding_control_root=control_root,
            withholding_marker=marker,
        )

    @classmethod
    def open(cls, root: str | bytes | os.PathLike[str] | os.PathLike[bytes]) -> Self:
        control_root, marker = _withholding_location(root)
        return cls(
            ConfinedFilesystem.open(root),
            withholding_control_root=control_root,
            withholding_marker=marker,
        )

    @classmethod
    def from_filesystem(cls, filesystem: ConfinedFilesystem) -> Self:
        del filesystem
        raise ValueError("path-bound artifact withholding identity is required; use create or open")

    @property
    def content_withheld_due_to_secret(self) -> bool:
        self._acquire_withholding_lock()
        try:
            return self._withholding_latched_unlocked()
        finally:
            self._release_withholding_lock()

    def _withholding_latched_unlocked(self) -> bool:
        if not self._content_withheld_due_to_secret:
            self._content_withheld_due_to_secret = self._durable_withholding_latched()
        return self._content_withheld_due_to_secret

    @staticmethod
    def _private_control_root(filesystem: ConfinedFilesystem) -> None:
        info = os.fstat(filesystem.fileno())
        if (
            info.st_uid != os.geteuid()
            or info.st_gid != os.getegid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise fail(
                StopReason.CREDENTIAL_REFRESH_FAILURE,
                "artifact withholding control directory is unsafe",
            )

    def _open_withholding_lock(self) -> int:
        control = self._open_withholding_control(create=True)
        assert control is not None
        descriptor: int | None = None
        created = False
        try:
            flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
            try:
                descriptor = os.open(
                    self._withholding_lock_name,
                    flags | os.O_CREAT | os.O_EXCL,
                    mode=PRIVATE_FILE_MODE,
                    dir_fd=control.fileno(),
                )
                created = True
            except FileExistsError:
                descriptor = os.open(
                    self._withholding_lock_name,
                    flags,
                    dir_fd=control.fileno(),
                )
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.geteuid()
                or info.st_gid != os.getegid()
                or stat.S_IMODE(info.st_mode) != PRIVATE_FILE_MODE
                or info.st_size != 0
            ):
                raise fail(
                    StopReason.CREDENTIAL_REFRESH_FAILURE,
                    "artifact withholding lock is unsafe",
                )
            if created:
                os.fchmod(descriptor, PRIVATE_FILE_MODE)
                os.fsync(descriptor)
                os.fsync(control.fileno())
            return descriptor
        except BaseException as exc:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            if isinstance(exc, (AgentLoopError, OSError)):
                raise fail(
                    StopReason.CREDENTIAL_REFRESH_FAILURE,
                    "artifact withholding lock could not be opened safely",
                ) from None
            raise
        finally:
            control.close()

    def _acquire_withholding_lock(self) -> None:
        self._withholding_thread_lock.acquire()
        try:
            descriptor = self._withholding_lock_fd
            if descriptor is None:
                raise ValueError("artifact store is closed")
            if self._withholding_lock_depth == 0:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
            self._withholding_lock_depth += 1
        except BaseException:
            self._withholding_thread_lock.release()
            raise

    def _release_withholding_lock(self) -> None:
        try:
            descriptor = self._withholding_lock_fd
            if descriptor is None or self._withholding_lock_depth <= 0:
                raise ValueError("artifact store withholding lock is not held")
            self._withholding_lock_depth -= 1
            if self._withholding_lock_depth == 0:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            self._withholding_thread_lock.release()

    @contextmanager
    def retained_filesystem(self) -> Iterator[ConfinedFilesystem]:
        """Yield run-root authority while atomically enforcing the durable latch."""

        self._acquire_withholding_lock()
        filesystem: ConfinedFilesystem | None = None
        primary: BaseException | None = None
        cleanup_errors: list[BaseException] = []
        try:
            if self._withholding_latched_unlocked():
                raise fail(
                    StopReason.CREDENTIAL_REFRESH_FAILURE,
                    "retained artifact content is permanently withheld",
                )
            filesystem = ConfinedFilesystem.from_fd(self._filesystem.fileno())
            yield filesystem
        except BaseException as exc:
            primary = exc
            raise
        finally:
            if filesystem is not None:
                try:
                    filesystem.close()
                except BaseException as exc:
                    cleanup_errors.append(exc)
            try:
                self._release_withholding_lock()
            except BaseException as exc:
                cleanup_errors.append(exc)
            if primary is not None:
                for cleanup_error in cleanup_errors:
                    primary.add_note(
                        f"retained filesystem cleanup also failed: {type(cleanup_error).__name__}"
                    )
            elif cleanup_errors:
                raise cleanup_errors[0]

    def _open_withholding_control(self, *, create: bool) -> ConfinedFilesystem | None:
        root = self._withholding_control_root
        try:
            control = (
                ConfinedFilesystem.create_private(root) if create else ConfinedFilesystem.open(root)
            )
        except (AgentLoopError, OSError) as exc:
            cause = exc.__cause__ if isinstance(exc, AgentLoopError) else exc
            if not create and isinstance(cause, OSError) and cause.errno == errno.ENOENT:
                return None
            raise fail(
                StopReason.CREDENTIAL_REFRESH_FAILURE,
                "artifact withholding control directory could not be opened safely",
            ) from None
        try:
            self._private_control_root(control)
        except BaseException:
            control.close()
            raise
        return control

    def _durable_withholding_latched(self) -> bool:
        marker_name = self._withholding_marker
        control = self._open_withholding_control(create=False)
        if control is None:
            return False
        try:
            try:
                marker = control.lstat(marker_name)
            except AgentLoopError as exc:
                cause = exc.__cause__
                if isinstance(cause, OSError) and cause.errno == errno.ENOENT:
                    return False
                raise fail(
                    StopReason.CREDENTIAL_REFRESH_FAILURE,
                    "artifact withholding latch could not be inspected safely",
                ) from None
            if (
                not stat.S_ISREG(marker.st_mode)
                or marker.st_nlink != 1
                or marker.st_uid != os.geteuid()
                or marker.st_gid != os.getegid()
                or stat.S_IMODE(marker.st_mode) != PRIVATE_FILE_MODE
                or marker.st_size != 0
            ):
                raise fail(
                    StopReason.CREDENTIAL_REFRESH_FAILURE,
                    "artifact withholding latch is unsafe",
                )
            return True
        finally:
            control.close()

    def _persist_credential_withheld_marker(self) -> None:
        self._content_withheld_due_to_secret = True
        marker_name = self._withholding_marker
        control = self._open_withholding_control(create=True)
        assert control is not None
        try:
            control.atomic_write(
                marker_name,
                b"",
                mode=PRIVATE_FILE_MODE,
                create_parents=False,
            )
        finally:
            control.close()

    @staticmethod
    def _erase_directory(directory_fd: int) -> None:
        """Remove every child without following a subject-controlled link."""

        with os.scandir(directory_fd) as iterator:
            entries = list(iterator)
        mutated = False
        for entry in entries:
            name = os.fsencode(entry.name)
            info = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                child = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=directory_fd,
                )
                try:
                    ArtifactStore._erase_directory(child)
                finally:
                    os.close(child)
                os.rmdir(name, dir_fd=directory_fd)
                mutated = True
            else:
                os.unlink(name, dir_fd=directory_fd)
                mutated = True
        if mutated:
            os.fsync(directory_fd)

    def scrub_known_secrets(self, secrets: tuple[KnownSecret, ...]) -> bool:
        """Irreversibly withhold retained bytes tainted by a new generation.

        Credential refresh can create a value that coincides with evidence
        retained earlier in the run.  Re-scan the entire private run tree at
        each new generation.  Detection is read-only; when a collision exists,
        durably latch whole-run withholding before deleting any evidence.
        """

        self._acquire_withholding_lock()
        try:
            return self._scrub_known_secrets_unlocked(secrets)
        finally:
            self._release_withholding_lock()

    def _scrub_known_secrets_unlocked(
        self,
        secrets: tuple[KnownSecret, ...],
    ) -> bool:
        if not isinstance(secrets, tuple) or not all(
            isinstance(secret, KnownSecret) for secret in secrets
        ):
            raise TypeError("artifact secret scrub requires KnownSecret values")
        if self._secret_scrub_failed:
            self._withhold_all_content_unlocked()
            raise fail(
                StopReason.CREDENTIAL_REFRESH_FAILURE,
                "a prior credential evidence scrub did not complete",
            )
        collision = False

        def visit(directory_fd: int, prefix: bytes) -> None:
            nonlocal collision
            with os.scandir(directory_fd) as iterator:
                entries = list(iterator)
            for entry in entries:
                name = os.fsencode(entry.name)
                relative = name if not prefix else prefix + b"/" + name
                info = entry.stat(follow_symlinks=False)
                path_sensitive = raw_log_contains_known_secret(relative, secrets)
                if stat.S_ISDIR(info.st_mode):
                    if path_sensitive:
                        collision = True
                        continue
                    child = os.open(
                        name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                        dir_fd=directory_fd,
                    )
                    try:
                        visit(child, relative)
                    finally:
                        os.close(child)
                    continue
                if stat.S_ISLNK(info.st_mode):
                    target = os.readlink(name, dir_fd=directory_fd)
                    if path_sensitive or raw_log_contains_known_secret(target, secrets):
                        collision = True
                    continue
                if not stat.S_ISREG(info.st_mode):
                    raise fail(
                        StopReason.CREDENTIAL_REFRESH_FAILURE,
                        "private artifact tree contained an unsafe file type during scrub",
                    )
                if path_sensitive:
                    collision = True
                    continue
                data = self._filesystem.read_bytes(relative, max_bytes=info.st_size)
                if _retained_bytes_contain_known_secret(data, secrets):
                    collision = True

        try:
            root = os.dup(self._filesystem.fileno())
            try:
                visit(root, b"")
            finally:
                os.close(root)
        except AgentLoopError, OSError:
            self._secret_scrub_failed = True
            try:
                self._withhold_all_content_unlocked()
            except AgentLoopError, OSError:
                pass
            raise fail(
                StopReason.CREDENTIAL_REFRESH_FAILURE,
                "private artifact evidence could not be scrubbed after credential refresh",
            ) from None
        if collision:
            self._withhold_all_content_unlocked()
        return collision

    def withhold_all_content(self) -> None:
        """Remove all run content when a new credential cannot be parsed safely."""

        self._acquire_withholding_lock()
        try:
            self._withhold_all_content_unlocked()
        finally:
            self._release_withholding_lock()

    def _withhold_all_content_unlocked(self) -> None:
        # The marker is a durable pending/completed-withholding latch.  Persist
        # it before the first destructive step so interruption cannot leave an
        # apparently ordinary, partially erased run.  A reopened store can
        # then retry this operation idempotently.
        marker_error: BaseException | None = None
        try:
            self._persist_credential_withheld_marker()
        except BaseException as exc:
            self._secret_scrub_failed = True
            self._content_withheld_due_to_secret = True
            marker_error = (
                fail(
                    StopReason.CREDENTIAL_REFRESH_FAILURE,
                    "private artifact withholding could not be durably marked",
                )
                if isinstance(exc, (AgentLoopError, OSError))
                else exc
            )

        erase_error: BaseException | None = None
        try:
            root = os.dup(self._filesystem.fileno())
            try:
                self._erase_directory(root)
                os.fsync(root)
            finally:
                os.close(root)
        except BaseException as exc:
            self._secret_scrub_failed = True
            erase_error = (
                fail(
                    StopReason.CREDENTIAL_REFRESH_FAILURE,
                    "private artifact evidence could not be fully withheld",
                )
                if isinstance(exc, OSError)
                else exc
            )

        # A transient failure before marker durability must not leave retained
        # bytes readable after reopen.  Erasure is attempted regardless, then
        # the durable poison marker is retried so recovery can finish a partial
        # wipe.  The original failure remains primary.
        if marker_error is not None:
            try:
                self._persist_credential_withheld_marker()
            except BaseException as retry_error:
                marker_error.add_note(
                    f"artifact withholding marker retry also failed: {type(retry_error).__name__}"
                )
        if marker_error is not None:
            if erase_error is not None:
                marker_error.add_note(
                    f"artifact evidence erasure also failed: {type(erase_error).__name__}"
                )
            raise marker_error
        if erase_error is not None:
            raise erase_error

    def close(self) -> None:
        self._withholding_thread_lock.acquire()
        try:
            if self._withholding_lock_depth != 0:
                raise ValueError("artifact store cannot close during a retained-tree operation")
            descriptor = self._withholding_lock_fd
            self._withholding_lock_fd = None
            errors: list[BaseException] = []
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except BaseException as exc:
                    errors.append(exc)
            try:
                self._filesystem.close()
            except BaseException as exc:
                errors.append(exc)
            if errors:
                primary = errors[0]
                for secondary in errors[1:]:
                    primary.add_note(
                        f"artifact store cleanup also failed: {type(secondary).__name__}"
                    )
                raise primary
        finally:
            self._withholding_thread_lock.release()

    def __enter__(self) -> Self:
        self._filesystem.fileno()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def ensure_directory(self, path: str | bytes) -> None:
        self._acquire_withholding_lock()
        try:
            if self._withholding_latched_unlocked():
                return
            directory_fd = self._filesystem.mkdirs(_artifact_path(path))
            os.close(directory_fd)
        finally:
            self._release_withholding_lock()

    def write_bytes(self, path: str | bytes, data: bytes) -> None:
        self._acquire_withholding_lock()
        try:
            if self._withholding_latched_unlocked():
                return
            self._filesystem.atomic_write(
                _artifact_path(path),
                data,
                mode=PRIVATE_FILE_MODE,
                create_parents=True,
            )
        finally:
            self._release_withholding_lock()

    def write_text(self, path: str | bytes, text: str) -> None:
        if self.content_withheld_due_to_secret:
            return
        if not isinstance(text, str):
            raise TypeError("artifact text must be a string")
        self.write_bytes(path, text.encode("utf-8"))

    def write_json(self, path: str | bytes, value: object) -> None:
        """Write stable UTF-8 JSON with an explicit final newline."""

        if self.content_withheld_due_to_secret:
            return
        encoded = (
            json.dumps(
                value,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            + b"\n"
        )
        self.write_bytes(path, encoded)

    def read_bytes(self, path: str | bytes, *, max_bytes: int) -> bytes:
        self._acquire_withholding_lock()
        try:
            if self._withholding_latched_unlocked():
                raise fail(
                    StopReason.CREDENTIAL_REFRESH_FAILURE,
                    "retained artifact content is permanently withheld",
                )
            return self._filesystem.read_bytes(_artifact_path(path), max_bytes=max_bytes)
        finally:
            self._release_withholding_lock()

    def read_text(self, path: str | bytes, *, max_bytes: int) -> str:
        return self.read_bytes(path, max_bytes=max_bytes).decode("utf-8", errors="strict")

    def read_json(self, path: str | bytes, *, max_bytes: int) -> object:
        value: object = json.loads(self.read_text(path, max_bytes=max_bytes))
        return value


class ContentAddressedBlobStore:
    """Private immutable-by-identity regular-file blob storage."""

    def __init__(
        self,
        artifacts: ArtifactStore,
        *,
        prefix: str | bytes = "subjects/blobs",
        max_blob_bytes: int | None = None,
    ) -> None:
        if not isinstance(artifacts, ArtifactStore):
            raise TypeError("artifacts must be an ArtifactStore")
        selected_max = Limits().max_file_bytes if max_blob_bytes is None else max_blob_bytes
        if not isinstance(selected_max, int) or isinstance(selected_max, bool) or selected_max <= 0:
            raise ValueError("max_blob_bytes must be a positive integer")
        self._artifacts = artifacts
        self._prefix = _artifact_path(prefix)
        self._max_blob_bytes = selected_max
        artifacts.ensure_directory(self._prefix)

    def _path(self, digest: str) -> bytes:
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ValueError("blob identity must be a lowercase SHA-256 digest")
        return self._prefix + b"/" + digest.encode("ascii")

    def put_blob(self, data: bytes) -> str:
        if not isinstance(data, bytes):
            raise TypeError("blob data must be bytes")
        if len(data) > self._max_blob_bytes:
            raise ValueError("blob exceeds max_blob_bytes")
        digest = sha256_hex(data)
        path = self._path(digest)
        try:
            existing = self._artifacts.read_bytes(path, max_bytes=self._max_blob_bytes)
        except AgentLoopError as exc:
            cause = exc.__cause__
            if not isinstance(cause, OSError) or cause.errno != errno.ENOENT:
                raise
            self._artifacts.write_bytes(path, data)
        else:
            if existing != data:
                raise fail(
                    StopReason.OUT_OF_BAND_CHANGE,
                    "content-addressed blob bytes do not match their identity",
                )
        return digest

    def read_blob(self, sha256: str) -> bytes:
        path = self._path(sha256)
        data = self._artifacts.read_bytes(path, max_bytes=self._max_blob_bytes)
        if sha256_hex(data) != sha256:
            raise fail(
                StopReason.OUT_OF_BAND_CHANGE,
                "content-addressed blob failed identity verification",
            )
        return data


def create_artifact_store(root: str | bytes | Path) -> ArtifactStore:
    """Create a store using the public convenience spelling."""

    return ArtifactStore.create(root)
