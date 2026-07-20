"""Private per-source execution locking, independent of Git metadata."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import socket
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Self

from .credentials import xdg_state_home
from .filesystem import ConfinedFilesystem, open_beneath


@dataclass(slots=True)
class SourceRunLock:
    source: Path
    run_id: str
    _filesystem: ConfinedFilesystem
    _fd: int
    _closed: bool = False

    @classmethod
    def acquire(
        cls,
        source: Path,
        run_id: str,
        *,
        state_home: Path | None = None,
        timeout_seconds: float = 2.0,
    ) -> Self:
        if not source.is_absolute() or not run_id or "/" in run_id or "\x00" in run_id:
            raise ValueError("source and run ID must be normalized runner-owned values")
        if timeout_seconds <= 0:
            raise ValueError("lock timeout must be positive")
        source_bytes = os.fsencode(str(source))
        key = hashlib.sha256(b"agent-loop-source-lock-v1\0" + source_bytes).hexdigest()
        base = state_home or xdg_state_home()
        root = base / "agent-loop" / "locks"
        filesystem = ConfinedFilesystem.create_private(root)
        fd: int | None = None
        try:
            fd = open_beneath(
                filesystem.fileno(),
                (key + ".lock").encode("ascii"),
                os.O_RDWR | os.O_CREAT,
                mode=0o600,
            )
            os.fchmod(fd, 0o600)
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise ValueError("source lock file is not private")
            deadline = time.monotonic() + timeout_seconds
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("another agent-loop run holds the source lock") from None
                    time.sleep(0.01)
            record = json.dumps(
                {
                    "schema_version": 1,
                    "run_id": run_id,
                    "pid": os.getpid(),
                    "hostname": socket.gethostname(),
                    "canonical_source": os.fspath(source),
                    "source_sha256": key,
                    "started_wall_time": time.time(),
                },
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii") + b"\n"
            os.ftruncate(fd, 0)
            os.lseek(fd, 0, os.SEEK_SET)
            view = memoryview(record)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
            os.fsync(filesystem.fileno())
            return cls(source, run_id, filesystem, fd)
        except BaseException:
            if fd is not None:
                os.close(fd)
            filesystem.close()
            raise

    def close(self) -> None:
        if self._closed:
            return
        try:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
        finally:
            os.close(self._fd)
            self._filesystem.close()
            self._closed = True

    def __enter__(self) -> Self:
        if self._closed:
            raise ValueError("source lock is closed")
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
