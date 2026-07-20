from __future__ import annotations

import fcntl
import os
import threading
from pathlib import Path

import pytest

import agent_loop.filesystem as filesystem_module
from agent_loop.errors import AgentLoopError, StopReason
from agent_loop.filesystem import (
    ConfinedFilesystem,
    open_beneath,
    require_openat2,
    validate_relative_path,
)


def test_openat2_required_policy_probe_passes_on_target_host() -> None:
    require_openat2()


def test_openat2_probe_fails_closed_when_syscall_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable(*args: object, **kwargs: object) -> int:
        raise OSError(38, "not implemented")

    monkeypatch.setattr(filesystem_module, "_invoke_openat2", unavailable)
    with pytest.raises(AgentLoopError) as captured:
        require_openat2()
    assert captured.value.reason is StopReason.SANDBOX_SETUP_FAILURE


@pytest.mark.parametrize(
    "path",
    [b"", b"/absolute", b".", b"..", b"a/../b", b"a/./b", b"a//b", b"a/", b"nul\x00x"],
)
def test_047_raw_paths_reject_ambiguous_aliases(path: bytes) -> None:
    with pytest.raises(AgentLoopError) as captured:
        validate_relative_path(path)
    assert captured.value.reason is StopReason.UNSAFE_OR_AMBIGUOUS_PATH


def test_047_raw_paths_preserve_newline_and_non_utf8_bytes() -> None:
    path = b"directory/line\n-\xff"
    assert validate_relative_path(path) == (b"directory", b"line\n-\xff")


def test_directory_relative_open_is_cloexec_and_nofollow(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "data").write_bytes(b"ok")
    with ConfinedFilesystem.open(root) as confined:
        fd = open_beneath(confined.fileno(), b"data", os.O_RDONLY)
        try:
            assert os.read(fd, 2) == b"ok"
            assert fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
        finally:
            os.close(fd)


def test_043_intermediate_symlink_cannot_escape(tmp_path: Path) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "secret").write_bytes(b"host-secret")
    (root / "parent").symlink_to(outside, target_is_directory=True)

    with ConfinedFilesystem.open(root) as confined:
        with pytest.raises(AgentLoopError) as captured:
            confined.read_bytes(b"parent/secret", max_bytes=1024)
    assert captured.value.reason is StopReason.UNSAFE_OR_AMBIGUOUS_PATH


def test_043_parent_swap_race_never_reads_outside_bytes(tmp_path: Path) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    parent = root / "parent"
    holding = root / "holding"
    parent.mkdir()
    (parent / "value").write_bytes(b"inside")
    (outside / "value").write_bytes(b"outside-secret")
    stop = threading.Event()

    def swap_parent() -> None:
        while not stop.is_set():
            try:
                parent.rename(holding)
                parent.symlink_to(outside, target_is_directory=True)
                parent.unlink()
                holding.rename(parent)
            except FileNotFoundError:
                continue

    worker = threading.Thread(target=swap_parent, daemon=True)
    worker.start()
    observed: list[bytes] = []
    try:
        with ConfinedFilesystem.open(root) as confined:
            for _ in range(250):
                try:
                    observed.append(confined.read_bytes(b"parent/value", max_bytes=64))
                except AgentLoopError:
                    pass
    finally:
        stop.set()
        worker.join(timeout=2)
    assert set(observed) <= {b"inside"}


def test_044_proc_magic_link_is_rejected() -> None:
    with ConfinedFilesystem.open(b"/") as confined:
        with pytest.raises(AgentLoopError) as captured:
            open_beneath(confined.fileno(), b"proc/self/exe", os.O_PATH)
    assert captured.value.reason is StopReason.UNSAFE_OR_AMBIGUOUS_PATH
