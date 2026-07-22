"""Linux-only confined filesystem primitives for the canonical subject runtime.

All untrusted subject identities remain raw relative bytes.  Path resolution is
performed by ``openat2(2)`` beneath a retained directory descriptor, with every
symlink component and procfs-style magic link rejected.  There is deliberately
no portable or best-effort fallback.
"""

from __future__ import annotations

import ctypes
import errno
import fcntl
import os
import platform
import secrets
import stat
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Final, Self

from .constants import (
    EXECUTABLE_MODE,
    PRIVATE_DIR_MODE,
    PRIVATE_FILE_MODE,
    REGULAR_MODE,
    SYMLINK_MODE,
    Limits,
)
from .errors import AgentLoopError, StopReason, fail
from .models import BlobReader, EntryKind, ScanRecord, sha256_hex

# Linux uapi values from include/uapi/linux/openat2.h.  The frozen platform is
# x86_64 Ubuntu, where openat2 is syscall 437.
RESOLVE_NO_MAGICLINKS: Final = 0x02
RESOLVE_NO_SYMLINKS: Final = 0x04
RESOLVE_BENEATH: Final = 0x08
REQUIRED_RESOLVE_FLAGS: Final = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS
SYS_OPENAT2_X86_64: Final = 437

_LIBC = ctypes.CDLL(None, use_errno=True)
_LIBC.syscall.restype = ctypes.c_long
_LIBC.flistxattr.restype = ctypes.c_ssize_t
_LIBC.llistxattr.restype = ctypes.c_ssize_t


class _OpenHow(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_uint64),
        ("mode", ctypes.c_uint64),
        ("resolve", ctypes.c_uint64),
    ]


def _path_label(path: bytes) -> str:
    """Return a bounded control-character-safe label for private diagnostics."""

    abbreviated = path if len(path) <= 256 else path[:256] + b"..."
    return repr(abbreviated)


def _unsafe(path: bytes, detail: str) -> AgentLoopError:
    return fail(
        StopReason.UNSAFE_OR_AMBIGUOUS_PATH,
        f"{detail}: {_path_label(path)}",
    )


def _unsafe_type(path: bytes, detail: str) -> AgentLoopError:
    return fail(
        StopReason.UNSAFE_FILE_TYPE_OR_HARD_LINK,
        f"{detail}: {_path_label(path)}",
    )


def validate_relative_path(path: bytes, *, limits: Limits | None = None) -> tuple[bytes, ...]:
    """Validate and split one canonical raw-byte subject path.

    Empty, absolute, NUL-bearing, repeated-separator, dot, and dot-dot forms are
    rejected instead of normalized.  Rejecting aliases is important because the
    original bytes are the manifest identity.
    """

    if not isinstance(path, bytes):
        raise TypeError("confined paths must be bytes")
    if not path:
        raise _unsafe(path, "path is empty")
    if path.startswith(b"/"):
        raise _unsafe(path, "absolute path is forbidden")
    if b"\x00" in path:
        raise _unsafe(path, "path contains NUL")
    components = tuple(path.split(b"/"))
    if any(component in {b"", b".", b".."} for component in components):
        raise _unsafe(path, "path contains an empty, dot, or dot-dot component")
    if limits is not None:
        if len(path) > limits.max_path_bytes:
            raise _unsafe(path, "path exceeds max_path_bytes")
        if len(components) > limits.max_path_depth:
            raise _unsafe(path, "path exceeds max_path_depth")
    return components


def _invoke_openat2(
    dir_fd: int,
    path: bytes,
    flags: int,
    mode: int = 0,
    resolve: int = REQUIRED_RESOLVE_FLAGS,
) -> int:
    """Invoke the target-platform syscall and return a new descriptor."""

    if sys.platform != "linux" or platform.machine() != "x86_64":
        raise OSError(errno.ENOSYS, "openat2 is unsupported on this platform")
    how = _OpenHow(flags=flags, mode=mode, resolve=resolve)
    ctypes.set_errno(0)
    result = _LIBC.syscall(
        ctypes.c_long(SYS_OPENAT2_X86_64),
        ctypes.c_int(dir_fd),
        ctypes.c_char_p(path),
        ctypes.byref(how),
        ctypes.c_size_t(ctypes.sizeof(how)),
    )
    if result < 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))
    return int(result)


def require_openat2() -> None:
    """Fail closed unless the required syscall and resolution policy work."""

    root_fd = os.open(b"/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        try:
            probe_fd = _invoke_openat2(
                root_fd,
                b".",
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
            )
        except OSError as exc:
            raise fail(
                StopReason.SANDBOX_SETUP_FAILURE,
                f"required openat2 policy unavailable (errno {exc.errno})",
            ) from exc
        else:
            os.close(probe_fd)

        # RESOLVE_BENEATH must reject an escape and NO_MAGICLINKS must reject
        # the procfs magic link.  Unexpected success means the boundary is not
        # the one version 1 requires.
        for hostile in (b"../", b"proc/self/exe"):
            try:
                escaped_fd = _invoke_openat2(
                    root_fd,
                    hostile,
                    os.O_RDONLY | os.O_CLOEXEC,
                )
            except OSError:
                continue
            else:
                os.close(escaped_fd)
                raise fail(
                    StopReason.SANDBOX_SETUP_FAILURE,
                    f"openat2 policy accepted hostile probe {_path_label(hostile)}",
                )
    finally:
        os.close(root_fd)


def _dup_cloexec(fd: int) -> int:
    return int(fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 0))


def open_beneath(
    root_fd: int,
    path: bytes,
    flags: int,
    *,
    mode: int = 0,
    limits: Limits | None = None,
) -> int:
    """Open a raw relative path without following any symlink component."""

    validate_relative_path(path, limits=limits)
    safe_flags = flags | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        opened_fd = _invoke_openat2(root_fd, path, safe_flags, mode)
    except OSError as exc:
        raise _unsafe(path, f"confined open failed with errno {exc.errno}") from exc
    # O_PATH|O_NOFOLLOW may ask openat2 for a descriptor to the final link
    # object rather than following it.  This API has a separate literal
    # readlink path, so never return such a descriptor to callers.
    if stat.S_ISLNK(os.fstat(opened_fd).st_mode):
        os.close(opened_fd)
        raise _unsafe(path, "confined open resolved to a symlink object")
    return opened_fd


def _split_absolute_path(
    path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
) -> tuple[bytes, ...]:
    raw = os.fsencode(os.fspath(path))
    if not raw.startswith(b"/") or raw.startswith(b"//"):
        raise _unsafe(raw, "private root must be an absolute normalized path")
    if raw == b"/":
        return ()
    if raw.endswith(b"/"):
        raise _unsafe(raw, "private root must not have a trailing separator")
    relative = raw[1:]
    return validate_relative_path(relative)


def _open_absolute_directory(
    path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
) -> int:
    components = _split_absolute_path(path)
    current_fd = os.open(b"/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in components:
            next_fd = open_beneath(
                current_fd,
                component,
                os.O_RDONLY | os.O_DIRECTORY,
            )
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def read_confined_absolute_file(
    path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
    *,
    max_bytes: int,
) -> bytes:
    """Read one absolute/working-directory-relative file without symlink traversal."""

    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 0:
        raise ValueError("max_bytes must be a non-negative integer")
    raw = os.fsencode(os.fspath(path))
    if not raw.startswith(b"/"):
        raw = os.fsencode(os.getcwd()) + b"/" + raw
    components = _split_absolute_path(raw)
    if not components:
        raise _unsafe(raw, "confined file path cannot be the filesystem root")
    parent = b"/" + b"/".join(components[:-1]) if len(components) > 1 else b"/"
    with ConfinedFilesystem.open(parent) as filesystem:
        return filesystem.read_bytes(components[-1], max_bytes=max_bytes)


def _create_private_absolute_directory(
    path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
) -> int:
    """Create missing absolute-path components without following symlinks."""

    components = _split_absolute_path(path)
    if not components:
        raise _unsafe(b"/", "filesystem root cannot be a private state root")
    current_fd = os.open(b"/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for index, component in enumerate(components):
            created = False
            try:
                next_fd = open_beneath(
                    current_fd,
                    component,
                    os.O_RDONLY | os.O_DIRECTORY,
                )
            except AgentLoopError as open_error:
                cause = open_error.__cause__
                if not isinstance(cause, OSError) or cause.errno != errno.ENOENT:
                    raise
                try:
                    os.mkdir(component, PRIVATE_DIR_MODE, dir_fd=current_fd)
                    created = True
                    os.fsync(current_fd)
                except FileExistsError:
                    # A concurrent creator is safe only if openat2 proves it is
                    # the expected directory rather than a link.
                    pass
                except OSError as exc:
                    raise _unsafe(
                        component,
                        f"private directory creation failed ({exc.errno})",
                    ) from exc
                next_fd = open_beneath(
                    current_fd,
                    component,
                    os.O_RDONLY | os.O_DIRECTORY,
                )
            os.close(current_fd)
            current_fd = next_fd

            info = os.fstat(current_fd)
            if not stat.S_ISDIR(info.st_mode):
                raise _unsafe(component, "private path component is not a directory")
            if created:
                os.fchmod(current_fd, PRIVATE_DIR_MODE)
                _reject_unsafe_metadata_fd(current_fd, os.fstat(current_fd), component)
                os.fsync(current_fd)
            if index == len(components) - 1:
                if info.st_uid != os.geteuid():
                    raise _unsafe(component, "private root is not owned by the runner uid")
                os.fchmod(current_fd, PRIVATE_DIR_MODE)
                _reject_unsafe_metadata_fd(current_fd, os.fstat(current_fd), component)
                os.fsync(current_fd)
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def _same_object(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        first.st_dev == second.st_dev
        and first.st_ino == second.st_ino
        and stat.S_IFMT(first.st_mode) == stat.S_IFMT(second.st_mode)
    )


def _same_stable_metadata(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        _same_object(first, second)
        and first.st_mode == second.st_mode
        and first.st_uid == second.st_uid
        and first.st_gid == second.st_gid
        and first.st_nlink == second.st_nlink
        and first.st_size == second.st_size
        and first.st_mtime_ns == second.st_mtime_ns
        and first.st_ctime_ns == second.st_ctime_ns
    )


def _reject_unsafe_metadata_fd(fd: int, info: os.stat_result, path: bytes) -> None:
    if info.st_uid != os.geteuid() or info.st_gid != os.getegid():
        raise _unsafe_type(path, "entry ownership differs from the normalized sandbox owner")
    if info.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
        raise _unsafe_type(path, "setuid, setgid, or sticky metadata is forbidden")
    ctypes.set_errno(0)
    result = _LIBC.flistxattr(ctypes.c_int(fd), None, ctypes.c_size_t(0))
    if result > 0:
        raise _unsafe_type(path, "extended attributes, ACLs, or capabilities are forbidden")
    if result < 0:
        error_number = ctypes.get_errno()
        if error_number not in {errno.ENOTSUP, errno.EOPNOTSUPP}:
            raise _unsafe_type(path, f"could not verify extended attributes ({error_number})")


def _reject_symlink_xattrs(parent_fd: int, name: bytes, path: bytes) -> None:
    # llistxattr does not accept dirfd.  /proc/self/fd names the already-open,
    # verified parent directory; llistxattr itself does not follow the final
    # symlink.  No target content or target metadata is read.
    proc_path = f"/proc/self/fd/{parent_fd}/".encode("ascii") + name
    ctypes.set_errno(0)
    result = _LIBC.llistxattr(ctypes.c_char_p(proc_path), None, ctypes.c_size_t(0))
    if result > 0:
        raise _unsafe_type(path, "symlink extended attributes are forbidden")
    if result < 0:
        error_number = ctypes.get_errno()
        if error_number not in {errno.ENOTSUP, errno.EOPNOTSUPP}:
            raise _unsafe_type(path, f"could not verify symlink attributes ({error_number})")


def classify_entry_mode(mode: int, path: bytes = b"<entry>") -> EntryKind | None:
    """Classify an lstat mode, rejecting every unsupported special type."""

    if stat.S_ISDIR(mode):
        return None
    if stat.S_ISREG(mode):
        return EntryKind.REGULAR
    if stat.S_ISLNK(mode):
        return EntryKind.SYMLINK
    if stat.S_ISFIFO(mode):
        kind = "FIFO"
    elif stat.S_ISSOCK(mode):
        kind = "socket"
    elif stat.S_ISBLK(mode):
        kind = "block device"
    elif stat.S_ISCHR(mode):
        kind = "character device"
    else:
        kind = "unknown file type"
    raise _unsafe_type(path, f"{kind} is forbidden")


@dataclass(slots=True)
class ConfinedFilesystem:
    """A retained directory descriptor used as the only filesystem authority."""

    _root_fd: int
    _closed: bool = False

    def __post_init__(self) -> None:
        info = os.fstat(self._root_fd)
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("root_fd must reference a directory")

    @classmethod
    def from_fd(cls, root_fd: int) -> Self:
        return cls(_dup_cloexec(root_fd))

    @classmethod
    def open(cls, path: str | bytes | os.PathLike[str] | os.PathLike[bytes]) -> Self:
        require_openat2()
        return cls(_open_absolute_directory(path))

    @classmethod
    def create_private(cls, path: str | bytes | os.PathLike[str] | os.PathLike[bytes]) -> Self:
        require_openat2()
        return cls(_create_private_absolute_directory(path))

    def fileno(self) -> int:
        if self._closed:
            raise ValueError("confined filesystem is closed")
        return self._root_fd

    def close(self) -> None:
        if not self._closed:
            os.close(self._root_fd)
            self._closed = True

    def __enter__(self) -> Self:
        self.fileno()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def open_directory(self, path: bytes = b"") -> int:
        if not path:
            return _dup_cloexec(self.fileno())
        return open_beneath(
            self.fileno(),
            path,
            os.O_RDONLY | os.O_DIRECTORY,
        )

    def mkdirs(self, path: bytes) -> int:
        """Create a private directory tree and return its CLOEXEC descriptor."""

        components = validate_relative_path(path)
        current_fd = _dup_cloexec(self.fileno())
        try:
            for component in components:
                try:
                    os.mkdir(component, PRIVATE_DIR_MODE, dir_fd=current_fd)
                    os.fsync(current_fd)
                except FileExistsError:
                    pass
                except OSError as exc:
                    raise _unsafe(path, f"directory creation failed ({exc.errno})") from exc
                next_fd = open_beneath(
                    current_fd,
                    component,
                    os.O_RDONLY | os.O_DIRECTORY,
                )
                info = os.fstat(next_fd)
                if info.st_uid != os.geteuid():
                    os.close(next_fd)
                    raise _unsafe(path, "directory is not owned by the runner uid")
                os.fchmod(next_fd, PRIVATE_DIR_MODE)
                _reject_unsafe_metadata_fd(next_fd, os.fstat(next_fd), path)
                os.fsync(next_fd)
                os.close(current_fd)
                current_fd = next_fd
            return current_fd
        except BaseException:
            os.close(current_fd)
            raise

    def _parent_and_name(self, path: bytes, *, create_parents: bool) -> tuple[int, bytes]:
        components = validate_relative_path(path)
        name = components[-1]
        if len(components) == 1:
            return _dup_cloexec(self.fileno()), name
        parent_path = b"/".join(components[:-1])
        parent_fd = self.mkdirs(parent_path) if create_parents else self.open_directory(parent_path)
        return parent_fd, name

    def lstat(self, path: bytes) -> os.stat_result:
        parent_fd, name = self._parent_and_name(path, create_parents=False)
        try:
            try:
                return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except OSError as exc:
                raise _unsafe(path, f"lstat failed ({exc.errno})") from exc
        finally:
            os.close(parent_fd)

    def read_bytes(self, path: bytes, *, max_bytes: int) -> bytes:
        """Read one stable, single-link regular file beneath the root."""

        if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 0:
            raise ValueError("max_bytes must be a non-negative integer")
        parent_fd, name = self._parent_and_name(path, create_parents=False)
        try:
            try:
                before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except OSError as exc:
                raise _unsafe(path, f"pre-read lstat failed ({exc.errno})") from exc
            if not stat.S_ISREG(before.st_mode):
                raise _unsafe_type(path, "safe reads require a regular file")
            if before.st_nlink != 1:
                raise _unsafe_type(path, "regular file has more than one hard link")
            if before.st_size > max_bytes:
                raise _unsafe_type(path, "regular file exceeds max_bytes")

            fd = open_beneath(parent_fd, name, os.O_RDONLY)
            try:
                opened = os.fstat(fd)
                if not _same_object(before, opened):
                    raise _unsafe(path, "file identity changed while opening")
                if opened.st_nlink != 1:
                    raise _unsafe_type(path, "regular file gained a hard link")
                _reject_unsafe_metadata_fd(fd, opened, path)
                chunks: list[bytes] = []
                remaining = max_bytes + 1
                while remaining:
                    chunk = os.read(fd, min(1024 * 1024, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                data = b"".join(chunks)
                if len(data) > max_bytes:
                    raise _unsafe_type(path, "regular file grew beyond max_bytes")
                after = os.fstat(fd)
                if not _same_object(opened, after) or after.st_nlink != 1:
                    raise _unsafe(path, "file identity changed while reading")
                if (
                    after.st_size != opened.st_size
                    or after.st_mtime_ns != opened.st_mtime_ns
                    or after.st_ctime_ns != opened.st_ctime_ns
                    or len(data) != after.st_size
                ):
                    raise _unsafe(path, "file content or metadata changed while reading")
                current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if not _same_object(after, current):
                    raise _unsafe(path, "path was replaced while reading")
                return data
            finally:
                os.close(fd)
        finally:
            os.close(parent_fd)

    def readlink(self, path: bytes) -> bytes:
        """Read only the literal bytes of a stable symlink target."""

        parent_fd, name = self._parent_and_name(path, create_parents=False)
        try:
            before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if not stat.S_ISLNK(before.st_mode):
                raise _unsafe_type(path, "literal link read requires a symlink")
            _reject_symlink_xattrs(parent_fd, name, path)
            target = os.readlink(name, dir_fd=parent_fd)
            after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if not _same_object(before, after):
                raise _unsafe(path, "symlink was replaced while reading its target")
            return target
        except AgentLoopError:
            raise
        except OSError as exc:
            raise _unsafe(path, f"literal symlink read failed ({exc.errno})") from exc
        finally:
            os.close(parent_fd)

    def atomic_write(
        self,
        path: bytes,
        data: bytes,
        *,
        mode: int = PRIVATE_FILE_MODE,
        create_parents: bool = True,
        normalize_timestamp: bool = False,
    ) -> None:
        """Durably replace a file without following the destination path."""

        if not isinstance(data, bytes):
            raise TypeError("atomic write data must be bytes")
        if mode not in {PRIVATE_FILE_MODE, PRIVATE_DIR_MODE}:
            raise ValueError("atomic file mode must be 0600 or 0700")
        parent_fd, name = self._parent_and_name(path, create_parents=create_parents)
        temporary = b".agent-loop-tmp-" + secrets.token_hex(16).encode("ascii")
        temp_fd: int | None = None
        try:
            temp_fd = open_beneath(
                parent_fd,
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                mode=mode,
            )
            os.fchmod(temp_fd, mode)
            _reject_unsafe_metadata_fd(temp_fd, os.fstat(temp_fd), path)
            view = memoryview(data)
            offset = 0
            while offset < len(view):
                written = os.write(temp_fd, view[offset:])
                if written <= 0:
                    raise OSError(errno.EIO, "short atomic write")
                offset += written
            if normalize_timestamp:
                os.utime(temp_fd, ns=(0, 0))
            os.fsync(temp_fd)
            os.close(temp_fd)
            temp_fd = None

            try:
                existing = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                existing = None
            if existing is not None and stat.S_ISDIR(existing.st_mode):
                raise _unsafe(path, "atomic destination is a directory")
            if existing is not None and not (
                stat.S_ISREG(existing.st_mode) or stat.S_ISLNK(existing.st_mode)
            ):
                raise _unsafe_type(path, "atomic destination has an unsafe file type")
            os.replace(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            os.fsync(parent_fd)
        except AgentLoopError:
            raise
        except OSError as exc:
            raise _unsafe(path, f"atomic persistence failed ({exc.errno})") from exc
        finally:
            if temp_fd is not None:
                os.close(temp_fd)
            active_exception = sys.exc_info()[0] is not None
            try:
                os.unlink(temporary, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            except OSError as cleanup_error:
                if not active_exception:
                    raise _unsafe(
                        path,
                        f"atomic temporary cleanup failed ({cleanup_error.errno})",
                    ) from cleanup_error
            finally:
                os.close(parent_fd)

    def scan_records(self, *, limits: Limits | None = None) -> tuple[ScanRecord, ...]:
        return scan_records(self, limits=limits)

    def materialize_records(
        self,
        records: Iterable[ScanRecord],
        *,
        limits: Limits | None = None,
    ) -> None:
        materialize_records(self, records, limits=limits)

    def materialize_manifest(
        self,
        manifest: object,
        blobs: BlobReader,
        *,
        limits: Limits | None = None,
    ) -> None:
        materialize_manifest(self, manifest, blobs, limits=limits)


@dataclass(slots=True)
class _ScanBudget:
    limits: Limits
    namespace_entries: int = 0
    payload_bytes: int = 0

    def add_namespace_entry(self, path: bytes) -> None:
        self.namespace_entries += 1
        if self.namespace_entries > self.limits.max_files:
            raise _unsafe_type(path, "complete scan exceeds max_files")

    def add_payload(self, path: bytes, size: int) -> None:
        self.payload_bytes += size
        if self.payload_bytes > self.limits.max_total_subject_bytes:
            raise _unsafe_type(path, "complete scan exceeds max_total_subject_bytes")


def _scan_directory(
    directory_fd: int,
    prefix: bytes,
    budget: _ScanBudget,
    records: list[ScanRecord],
) -> None:
    try:
        raw_names = [os.fsencode(name) for name in os.listdir(directory_fd)]
    except OSError as exc:
        raise _unsafe(prefix or b"<root>", f"directory enumeration failed ({exc.errno})") from exc
    raw_names.sort()
    if len(raw_names) != len(set(raw_names)):
        raise _unsafe(prefix or b"<root>", "directory names do not round-trip uniquely")

    for name in raw_names:
        path = name if not prefix else prefix + b"/" + name
        validate_relative_path(path, limits=budget.limits)
        budget.add_namespace_entry(path)
        try:
            before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            raise _unsafe(path, f"scan lstat failed ({exc.errno})") from exc
        kind = classify_entry_mode(before.st_mode, path)

        if kind is None:
            child_fd = open_beneath(
                directory_fd,
                name,
                os.O_RDONLY | os.O_DIRECTORY,
                limits=budget.limits,
            )
            try:
                opened = os.fstat(child_fd)
                if not _same_object(before, opened):
                    raise _unsafe(path, "directory identity changed while opening")
                _reject_unsafe_metadata_fd(child_fd, opened, path)
                _scan_directory(child_fd, path, budget, records)
                after = os.fstat(child_fd)
                current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if not _same_stable_metadata(opened, after) or not _same_stable_metadata(
                    after,
                    current,
                ):
                    raise _unsafe(path, "directory identity changed while scanning")
            finally:
                os.close(child_fd)
            continue

        if kind is EntryKind.REGULAR:
            if before.st_nlink != 1:
                raise _unsafe_type(path, "regular file has more than one hard link")
            if before.st_size > budget.limits.max_file_bytes:
                raise _unsafe_type(path, "regular file exceeds max_file_bytes")
            fd = open_beneath(directory_fd, name, os.O_RDONLY, limits=budget.limits)
            try:
                opened = os.fstat(fd)
                if not _same_object(before, opened):
                    raise _unsafe(path, "regular file identity changed while opening")
                if opened.st_nlink != 1:
                    raise _unsafe_type(path, "regular file gained a hard link")
                _reject_unsafe_metadata_fd(fd, opened, path)
                chunks: list[bytes] = []
                remaining = budget.limits.max_file_bytes + 1
                while remaining:
                    chunk = os.read(fd, min(1024 * 1024, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                payload = b"".join(chunks)
                if len(payload) > budget.limits.max_file_bytes:
                    raise _unsafe_type(path, "regular file grew beyond max_file_bytes")
                after = os.fstat(fd)
                current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if (
                    not _same_object(opened, after)
                    or not _same_object(after, current)
                    or after.st_nlink != 1
                    or after.st_size != opened.st_size
                    or after.st_mtime_ns != opened.st_mtime_ns
                    or after.st_ctime_ns != opened.st_ctime_ns
                    or len(payload) != after.st_size
                ):
                    raise _unsafe(path, "regular file changed during complete scan")
            finally:
                os.close(fd)
            budget.add_payload(path, len(payload))
            normalized_mode = EXECUTABLE_MODE if before.st_mode & 0o111 else REGULAR_MODE
            records.append(
                ScanRecord(
                    path=path,
                    kind=EntryKind.REGULAR,
                    mode=normalized_mode,
                    payload=payload,
                )
            )
            continue

        _reject_symlink_xattrs(directory_fd, name, path)
        if before.st_uid != os.geteuid() or before.st_gid != os.getegid():
            raise _unsafe_type(path, "symlink ownership differs from the normalized owner")
        try:
            target = os.readlink(name, dir_fd=directory_fd)
            after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            raise _unsafe(path, f"literal symlink capture failed ({exc.errno})") from exc
        if not _same_stable_metadata(before, after):
            raise _unsafe(path, "symlink changed during complete scan")
        if len(target) > budget.limits.max_file_bytes:
            raise _unsafe_type(path, "literal symlink target exceeds max_file_bytes")
        budget.add_payload(path, len(target))
        records.append(
            ScanRecord(
                path=path,
                kind=EntryKind.SYMLINK,
                mode=SYMLINK_MODE,
                payload=target,
            )
        )


def scan_records(
    filesystem: ConfinedFilesystem,
    *,
    limits: Limits | None = None,
) -> tuple[ScanRecord, ...]:
    """Capture every regular file and symlink, ignoring no namespace entry."""

    selected_limits = limits or Limits()
    records: list[ScanRecord] = []
    budget = _ScanBudget(selected_limits)
    root_fd = filesystem.open_directory()
    try:
        _reject_unsafe_metadata_fd(root_fd, os.fstat(root_fd), b"<root>")
        _scan_directory(root_fd, b"", budget, records)
    finally:
        os.close(root_fd)
    records.sort(key=lambda record: record.path)
    return tuple(records)


def _validated_materialization_records(
    records: Iterable[ScanRecord],
    limits: Limits,
) -> tuple[ScanRecord, ...]:
    materialized = tuple(records)
    paths: set[bytes] = set()
    implied_directories: set[bytes] = set()
    total_bytes = 0
    for record in materialized:
        if not isinstance(record, ScanRecord):
            raise TypeError("materialization requires ScanRecord values")
        components = validate_relative_path(record.path, limits=limits)
        if record.path in paths:
            raise _unsafe(record.path, "materialization has a duplicate path")
        paths.add(record.path)
        for index in range(1, len(components)):
            implied_directories.add(b"/".join(components[:index]))
        total_bytes += len(record.payload)
        if record.kind is EntryKind.REGULAR:
            if len(record.payload) > limits.max_file_bytes:
                raise _unsafe_type(record.path, "materialized file exceeds max_file_bytes")
            if record.mode not in {REGULAR_MODE, EXECUTABLE_MODE}:
                raise _unsafe_type(record.path, "regular materialization mode is invalid")
        else:
            if record.mode != SYMLINK_MODE or not record.payload or b"\x00" in record.payload:
                raise _unsafe_type(record.path, "literal symlink materialization is invalid")
        if total_bytes > limits.max_total_subject_bytes:
            raise _unsafe_type(record.path, "materialization exceeds max_total_subject_bytes")
    conflicts = paths & implied_directories
    if conflicts:
        conflict = min(conflicts)
        raise _unsafe(conflict, "a file or symlink is also required as a parent directory")
    if len(paths | implied_directories) > limits.max_files:
        raise _unsafe_type(b"<subject>", "materialization exceeds max_files")
    return tuple(sorted(materialized, key=lambda record: record.path))


def materialize_records(
    filesystem: ConfinedFilesystem,
    records: Iterable[ScanRecord],
    *,
    limits: Limits | None = None,
) -> None:
    """Materialize normalized records into a fresh, empty confined root."""

    selected_limits = limits or Limits()
    normalized = _validated_materialization_records(records, selected_limits)
    root_fd = filesystem.open_directory()
    try:
        if os.listdir(root_fd):
            raise _unsafe(b"<root>", "materialization root is not empty")
    finally:
        os.close(root_fd)

    directories: set[bytes] = set()
    for record in normalized:
        components = record.path.split(b"/")
        if len(components) > 1:
            parent_path = b"/".join(components[:-1])
            parent_fd = filesystem.mkdirs(parent_path)
            os.close(parent_fd)
            for index in range(1, len(components)):
                directories.add(b"/".join(components[:index]))

        if record.kind is EntryKind.REGULAR:
            actual_mode = PRIVATE_DIR_MODE if record.mode == EXECUTABLE_MODE else PRIVATE_FILE_MODE
            filesystem.atomic_write(
                record.path,
                record.payload,
                mode=actual_mode,
                create_parents=False,
                normalize_timestamp=True,
            )
            continue

        parent_fd, name = filesystem._parent_and_name(record.path, create_parents=False)
        try:
            try:
                os.symlink(record.payload, name, dir_fd=parent_fd)
                os.utime(name, ns=(0, 0), dir_fd=parent_fd, follow_symlinks=False)
                os.fsync(parent_fd)
            except OSError as exc:
                raise _unsafe(
                    record.path,
                    f"literal symlink materialization failed ({exc.errno})",
                ) from exc
        finally:
            os.close(parent_fd)

    # Child creation changes directory timestamps.  Normalize from leaves to
    # root after the complete tree exists, then durably flush each directory.
    for directory in sorted(directories, key=lambda item: item.count(b"/"), reverse=True):
        directory_fd = filesystem.open_directory(directory)
        try:
            os.fchmod(directory_fd, PRIVATE_DIR_MODE)
            os.utime(directory_fd, ns=(0, 0))
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    root_fd = filesystem.open_directory()
    try:
        os.utime(root_fd, ns=(0, 0))
        os.fsync(root_fd)
    finally:
        os.close(root_fd)


def materialize_manifest(
    filesystem: ConfinedFilesystem,
    manifest: object,
    blobs: BlobReader,
    *,
    limits: Limits | None = None,
) -> None:
    """Resolve and verify manifest blobs, then materialize their exact records.

    The import is local so the canonical manifest module can consume scanner
    protocols without creating an import cycle at module initialization.
    """

    from .manifests import SubjectManifest

    if not isinstance(manifest, SubjectManifest):
        raise TypeError("manifest must be a SubjectManifest")
    if not isinstance(blobs, BlobReader):
        raise TypeError("blobs must implement BlobReader")
    records: list[ScanRecord] = []
    for entry in manifest.entries:
        if entry.kind is EntryKind.SYMLINK:
            assert entry.symlink_target is not None
            records.append(
                ScanRecord(entry.path, EntryKind.SYMLINK, entry.mode, entry.symlink_target)
            )
            continue
        assert entry.blob_sha256 is not None
        assert entry.size is not None
        payload = blobs.read_blob(entry.blob_sha256)
        if not isinstance(payload, bytes):
            raise TypeError("blob reader returned non-bytes content")
        if len(payload) != entry.size or sha256_hex(payload) != entry.blob_sha256:
            raise fail(
                StopReason.OUT_OF_BAND_CHANGE,
                f"manifest blob does not match entry {_path_label(entry.path)}",
            )
        records.append(ScanRecord(entry.path, EntryKind.REGULAR, entry.mode, payload))
    materialize_records(filesystem, records, limits=limits)


def open_private_root(
    path: str | bytes | Path,
    *,
    create: bool = False,
) -> ConfinedFilesystem:
    """Convenience constructor used by artifact and supervisor code."""

    return ConfinedFilesystem.create_private(path) if create else ConfinedFilesystem.open(path)
