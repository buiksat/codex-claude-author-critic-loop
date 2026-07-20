"""Bounded provenance witnesses for code and tool closures mounted read-only."""

from __future__ import annotations

import grp
import hashlib
import os
import pwd
import stat
from pathlib import Path

MAX_REVIEWED_CLOSURE_FILES = 1_024
MAX_REVIEWED_CLOSURE_BYTES = 512 * 1024 * 1024


def _private_primary_group(group_id: int) -> bool:
    if group_id != os.getegid():
        return False
    try:
        group = grp.getgrgid(group_id)
    except KeyError:
        return False
    accounts = {account.pw_name: account for account in pwd.getpwall()}
    member_names = {
        account.pw_name for account in accounts.values() if account.pw_gid == group_id
    }
    member_names.update(group.gr_mem)
    return bool(member_names) and all(
        name in accounts and accounts[name].pw_uid == os.geteuid()
        for name in member_names
    )


def safe_owned_mode(info: os.stat_result) -> bool:
    """Return whether an owned/root-owned path has no unsafe write or special mode."""

    mode = stat.S_IMODE(info.st_mode)
    return bool(
        info.st_uid in {0, os.geteuid()}
        and not mode & 0o002
        and not (mode & 0o020 and not _private_primary_group(info.st_gid))
        and not mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)
    )


_STABLE_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_nlink",
    "st_uid",
    "st_gid",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
)


def _same_metadata(before: os.stat_result, after: os.stat_result) -> bool:
    return all(getattr(before, name) == getattr(after, name) for name in _STABLE_FIELDS)


def reject_extended_metadata_fd(descriptor: int) -> None:
    """Fail closed unless an opened file or directory has no extended metadata."""

    try:
        attributes = os.listxattr(descriptor)
    except OSError as exc:
        raise ValueError("reviewed closure metadata cannot be verified") from exc
    if attributes:
        raise ValueError("reviewed closure contains extended metadata")


def _open_reviewed_root(path: Path) -> int:
    if not isinstance(path, Path) or not path.is_absolute() or path == Path("/"):
        raise ValueError("reviewed path must be an absolute non-root Path")
    components = path.parts[1:]
    current_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        if not safe_owned_mode(os.fstat(current_fd)):
            raise ValueError("unsafe reviewed path ancestor")
        reject_extended_metadata_fd(current_fd)
        for index, component in enumerate(components):
            final = index == len(components) - 1
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
            if not final:
                flags |= os.O_DIRECTORY
            next_fd = os.open(component, flags, dir_fd=current_fd)
            try:
                info = os.fstat(next_fd)
                mode = stat.S_IMODE(info.st_mode)
                protected_shared_directory = bool(
                    not final
                    and stat.S_ISDIR(info.st_mode)
                    and info.st_uid == 0
                    and mode & stat.S_ISVTX
                    and not mode & (stat.S_ISUID | stat.S_ISGID)
                )
                if not (safe_owned_mode(info) or protected_shared_directory):
                    raise ValueError("unsafe reviewed path ancestor")
                reject_extended_metadata_fd(next_fd)
            except BaseException:
                os.close(next_fd)
                raise
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def verify_safe_ancestors(path: Path) -> None:
    """Reject symbolic, writable, or specially-moded ancestors including ``path``."""

    descriptor = _open_reviewed_root(path)
    os.close(descriptor)


def _hash_open_file(descriptor: int, expected: os.stat_result) -> bytes:
    digest = hashlib.sha256()
    observed = 0
    os.lseek(descriptor, 0, os.SEEK_SET)
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        observed += len(chunk)
        if observed > expected.st_size:
            raise ValueError("reviewed closure file grew while hashing")
        digest.update(chunk)
    if observed != expected.st_size:
        raise ValueError("reviewed closure file size changed while hashing")
    return digest.digest()


def _closure_sha256_fd(
    root_fd: int,
    *,
    root_name: bytes,
    max_files: int,
    max_bytes: int,
    python_sources_only: bool,
) -> str:
    retained: list[tuple[int, os.stat_result]] = []
    records: list[tuple[bytes, bytes, int, int, bytes]] = []
    total_bytes = 0
    observed_entries = 0
    root_info = os.fstat(root_fd)
    domain = (
        b"agent-loop/python-source-closure/v1"
        if python_sources_only
        else b"agent-loop/reviewed-install-closure/v1"
    )
    if stat.S_ISREG(root_info.st_mode):
        if python_sources_only:
            raise ValueError("Python source closure root must be a directory")
        if not safe_owned_mode(root_info) or root_info.st_nlink != 1:
            raise ValueError("reviewed closure root is unsafe")
        reject_extended_metadata_fd(root_fd)
        if root_info.st_size > max_bytes:
            raise ValueError("reviewed closure byte count exceeded")
        payload_digest = _hash_open_file(root_fd, root_info)
        retained.append((os.dup(root_fd), root_info))
        records.append(
            (
                b"F",
                root_name,
                stat.S_IMODE(root_info.st_mode),
                root_info.st_size,
                payload_digest,
            )
        )
    elif stat.S_ISDIR(root_info.st_mode):
        stack: list[tuple[bytes, int]] = [(b"", os.dup(root_fd))]
        try:
            while stack:
                relative, directory_fd = stack.pop()
                directory_info = os.fstat(directory_fd)
                if not safe_owned_mode(directory_info):
                    raise ValueError("unsafe reviewed closure directory")
                reject_extended_metadata_fd(directory_fd)
                retained.append((directory_fd, directory_info))
                cache_directory = bool(
                    python_sources_only
                    and relative
                    and b"__pycache__" in relative.split(b"/")
                )
                if not cache_directory:
                    records.append(
                        (
                            b"D",
                            relative,
                            stat.S_IMODE(directory_info.st_mode),
                            0,
                            b"",
                        )
                    )
                names = sorted(os.fsencode(name) for name in os.listdir(directory_fd))
                for name in names:
                    path = name if not relative else relative + b"/" + name
                    metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if stat.S_ISDIR(metadata.st_mode):
                        child_fd = os.open(
                            name,
                            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                            dir_fd=directory_fd,
                        )
                        try:
                            if not _same_metadata(metadata, os.fstat(child_fd)):
                                raise ValueError(
                                    "reviewed closure directory identity changed"
                                )
                        except BaseException:
                            os.close(child_fd)
                            raise
                        if python_sources_only and name == b"__pycache__":
                            os.close(child_fd)
                            continue
                        observed_entries += 1
                        if observed_entries > max_files:
                            os.close(child_fd)
                            raise ValueError("reviewed closure entry count exceeded")
                        stack.append((path, child_fd))
                        continue
                    observed_entries += 1
                    if observed_entries > max_files:
                        raise ValueError("reviewed closure entry count exceeded")
                    if not stat.S_ISREG(metadata.st_mode):
                        raise ValueError(
                            "reviewed closure contains an unsafe non-regular file"
                        )
                    file_fd = os.open(
                        name,
                        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                        dir_fd=directory_fd,
                    )
                    try:
                        opened = os.fstat(file_fd)
                        if not _same_metadata(metadata, opened):
                            raise ValueError("reviewed closure file identity changed")
                        if not safe_owned_mode(opened) or opened.st_nlink != 1:
                            raise ValueError(
                                "reviewed closure contains an unsafe non-regular file"
                            )
                        reject_extended_metadata_fd(file_fd)
                        total_bytes += opened.st_size
                        if total_bytes > max_bytes:
                            raise ValueError("reviewed closure byte count exceeded")
                        if python_sources_only and not path.endswith(b".py"):
                            raise ValueError(
                                "Python source closure contains an unexpected payload"
                            )
                        payload_digest = _hash_open_file(file_fd, opened)
                    except BaseException:
                        os.close(file_fd)
                        raise
                    retained.append((file_fd, opened))
                    records.append(
                        (
                            b"F",
                            path,
                            stat.S_IMODE(opened.st_mode),
                            opened.st_size,
                            payload_digest,
                        )
                    )
        except BaseException:
            for _, descriptor in stack:
                os.close(descriptor)
            for descriptor, _ in retained:
                os.close(descriptor)
            retained.clear()
            raise
    else:
        raise ValueError("reviewed closure root is not a regular file or directory")
    try:
        if python_sources_only and not any(kind == b"F" for kind, *_ in records):
            raise ValueError("Python source closure contains no source files")
        if any(not _same_metadata(before, os.fstat(fd)) for fd, before in retained):
            raise ValueError("reviewed closure changed while hashing")
        digest = hashlib.sha256(domain + b"\0")
        for kind, path, mode, size, payload_digest in sorted(records):
            digest.update(kind)
            digest.update(len(path).to_bytes(8, "big"))
            digest.update(path)
            digest.update(mode.to_bytes(4, "big"))
            digest.update(size.to_bytes(8, "big"))
            digest.update(payload_digest)
        return digest.hexdigest()
    finally:
        for descriptor, _ in retained:
            os.close(descriptor)


def closure_sha256(
    root: Path,
    *,
    max_files: int = MAX_REVIEWED_CLOSURE_FILES,
    max_bytes: int = MAX_REVIEWED_CLOSURE_BYTES,
) -> str:
    """Hash a stable, no-symlink, metadata-safe regular-file closure."""

    if not isinstance(root, Path) or not root.is_absolute():
        raise ValueError("reviewed closure root must be an absolute Path")
    if (
        not isinstance(max_files, int)
        or isinstance(max_files, bool)
        or not 1 <= max_files <= MAX_REVIEWED_CLOSURE_FILES
        or not isinstance(max_bytes, int)
        or isinstance(max_bytes, bool)
        or not 1 <= max_bytes <= MAX_REVIEWED_CLOSURE_BYTES
    ):
        raise ValueError("reviewed closure limits are invalid")
    descriptor = _open_reviewed_root(root)
    try:
        return _closure_sha256_fd(
            descriptor,
            root_name=os.fsencode(root.name),
            max_files=max_files,
            max_bytes=max_bytes,
            python_sources_only=False,
        )
    finally:
        os.close(descriptor)


def open_verified_closure(
    root: Path,
    expected_sha256: str,
    *,
    python_sources_only: bool = False,
) -> int:
    """Return a retained root descriptor for the exact verified closure."""

    if not isinstance(expected_sha256, str) or len(expected_sha256) != 64 or any(
        character not in "0123456789abcdef" for character in expected_sha256
    ):
        raise ValueError("expected reviewed closure digest is invalid")
    descriptor = _open_reviewed_root(root)
    try:
        observed = _closure_sha256_fd(
            descriptor,
            root_name=os.fsencode(root.name),
            max_files=MAX_REVIEWED_CLOSURE_FILES,
            max_bytes=MAX_REVIEWED_CLOSURE_BYTES,
            python_sources_only=python_sources_only,
        )
        if observed != expected_sha256:
            raise ValueError("reviewed closure does not match its expected digest")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def python_source_closure_sha256(root: Path) -> str:
    """Hash the exact Python sources while rejecting importable shadow payloads.

    Interpreter-generated ``__pycache__/*.pyc`` files are location-dependent and
    therefore excluded from the receipt identity.  The trusted sandbox bootstrap
    installs a source-only finder for this package, so those cache files cannot be
    selected there.  Any other non-source package payload fails closed.
    """

    if not isinstance(root, Path) or not root.is_absolute():
        raise ValueError("Python source closure root must be an absolute Path")
    descriptor = _open_reviewed_root(root)
    try:
        return _closure_sha256_fd(
            descriptor,
            root_name=os.fsencode(root.name),
            max_files=MAX_REVIEWED_CLOSURE_FILES,
            max_bytes=MAX_REVIEWED_CLOSURE_BYTES,
            python_sources_only=True,
        )
    finally:
        os.close(descriptor)


def _copy_regular_file(
    source_fd: int,
    destination_fd: int,
    name: bytes,
    metadata: os.stat_result,
) -> None:
    output_fd = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
        dir_fd=destination_fd,
    )
    try:
        observed = 0
        os.lseek(source_fd, 0, os.SEEK_SET)
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            observed += len(chunk)
            if observed > metadata.st_size:
                raise ValueError("reviewed closure file grew while snapshotting")
            pending = memoryview(chunk)
            while pending:
                written = os.write(output_fd, pending)
                if written <= 0:
                    raise OSError("short write while snapshotting reviewed closure")
                pending = pending[written:]
        if observed != metadata.st_size or not _same_metadata(metadata, os.fstat(source_fd)):
            raise ValueError("reviewed closure file changed while snapshotting")
        os.fchmod(output_fd, stat.S_IMODE(metadata.st_mode))
        os.fsync(output_fd)
    finally:
        os.close(output_fd)


def _copy_closure_from_fd(
    source_fd: int,
    destination_parent: Path,
    source_name: bytes,
    *,
    python_sources_only: bool,
) -> Path:
    root_info = os.fstat(source_fd)
    destination = destination_parent / os.fsdecode(source_name)
    parent_fd = os.open(
        destination_parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        if stat.S_ISREG(root_info.st_mode):
            _copy_regular_file(source_fd, parent_fd, source_name, root_info)
            return destination
        if not stat.S_ISDIR(root_info.st_mode):
            raise ValueError("reviewed closure snapshot root has an unsafe type")
        os.mkdir(source_name, 0o700, dir_fd=parent_fd)
        destination_root_fd = os.open(
            source_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
    finally:
        os.close(parent_fd)
    try:
        source_root_fd = os.dup(source_fd)
    except BaseException:
        os.close(destination_root_fd)
        raise
    stack: list[tuple[bytes, int, int, os.stat_result]] = [
        (b"", source_root_fd, destination_root_fd, root_info)
    ]
    try:
        while stack:
            relative, current_source_fd, current_destination_fd, directory_info = stack.pop()
            try:
                for name in sorted(os.fsencode(item) for item in os.listdir(current_source_fd)):
                    metadata = os.stat(
                        name,
                        dir_fd=current_source_fd,
                        follow_symlinks=False,
                    )
                    path = name if not relative else relative + b"/" + name
                    if stat.S_ISDIR(metadata.st_mode):
                        if python_sources_only and name == b"__pycache__":
                            continue
                        os.mkdir(name, 0o700, dir_fd=current_destination_fd)
                        next_source_fd = os.open(
                            name,
                            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                            dir_fd=current_source_fd,
                        )
                        try:
                            next_destination_fd = os.open(
                                name,
                                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                                dir_fd=current_destination_fd,
                            )
                        except BaseException:
                            os.close(next_source_fd)
                            raise
                        try:
                            if not _same_metadata(metadata, os.fstat(next_source_fd)):
                                raise ValueError(
                                    "reviewed closure changed while snapshotting"
                                )
                        except BaseException:
                            os.close(next_source_fd)
                            os.close(next_destination_fd)
                            raise
                        stack.append(
                            (path, next_source_fd, next_destination_fd, metadata)
                        )
                        continue
                    if not stat.S_ISREG(metadata.st_mode):
                        raise ValueError("reviewed closure contains an unsafe non-regular file")
                    if python_sources_only and not path.endswith(b".py"):
                        raise ValueError("Python source snapshot contains an unexpected payload")
                    input_fd = os.open(
                        name,
                        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                        dir_fd=current_source_fd,
                    )
                    try:
                        opened = os.fstat(input_fd)
                        if not _same_metadata(metadata, opened):
                            raise ValueError("reviewed closure changed while snapshotting")
                        _copy_regular_file(
                            input_fd,
                            current_destination_fd,
                            name,
                            opened,
                        )
                    finally:
                        os.close(input_fd)
                if not _same_metadata(directory_info, os.fstat(current_source_fd)):
                    raise ValueError("reviewed closure directory changed while snapshotting")
                os.fchmod(
                    current_destination_fd,
                    stat.S_IMODE(directory_info.st_mode),
                )
                os.fsync(current_destination_fd)
            finally:
                os.close(current_source_fd)
                os.close(current_destination_fd)
    except BaseException:
        for _, pending_source, pending_destination, _ in stack:
            os.close(pending_source)
            os.close(pending_destination)
        raise
    return destination


def _normalize_snapshot_modes(root: Path) -> None:
    root_info = os.stat(root, follow_symlinks=False)
    if stat.S_ISREG(root_info.st_mode):
        os.chmod(root, 0o555 if root_info.st_mode & 0o111 else 0o444)
        return
    gathered: list[Path] = []
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        names.sort()
        files.sort()
        directory_path = Path(directory)
        gathered.append(directory_path)
        for name in files:
            child = directory_path / name
            info = os.stat(child, follow_symlinks=False)
            os.chmod(child, 0o555 if info.st_mode & 0o111 else 0o444)
    for directory in reversed(gathered):
        os.chmod(directory, 0o555)


def snapshot_reviewed_closure(
    source: Path,
    destination_parent: Path,
    expected_sha256: str,
    *,
    python_sources_only: bool = False,
) -> tuple[Path, str]:
    """Copy a verified closure into a private read-only mount snapshot."""

    if len(expected_sha256) != 64 or any(
        character not in "0123456789abcdef" for character in expected_sha256
    ):
        raise ValueError("expected reviewed closure digest is invalid")
    if not destination_parent.is_absolute() or not destination_parent.is_dir():
        raise ValueError("closure snapshot parent must be an existing absolute directory")
    source_fd = _open_reviewed_root(source)
    try:
        observed = _closure_sha256_fd(
            source_fd,
            root_name=os.fsencode(source.name),
            max_files=MAX_REVIEWED_CLOSURE_FILES,
            max_bytes=MAX_REVIEWED_CLOSURE_BYTES,
            python_sources_only=python_sources_only,
        )
        if observed != expected_sha256:
            raise ValueError("reviewed closure changed before snapshot")
        snapshot = _copy_closure_from_fd(
            source_fd,
            destination_parent,
            os.fsencode(source.name),
            python_sources_only=python_sources_only,
        )
    finally:
        os.close(source_fd)
    copied = (
        python_source_closure_sha256(snapshot)
        if python_sources_only
        else closure_sha256(snapshot)
    )
    if copied != expected_sha256:
        raise ValueError("reviewed closure changed during snapshot")
    _normalize_snapshot_modes(snapshot)
    mounted = (
        python_source_closure_sha256(snapshot)
        if python_sources_only
        else closure_sha256(snapshot)
    )
    return snapshot, mounted


def installed_runtime_closure_sha256() -> str:
    """Witness the exact importable package mounted for trusted sandbox control."""

    return python_source_closure_sha256(Path(__file__).parent)
