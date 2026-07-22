from __future__ import annotations

import grp
import os
import pwd
from pathlib import Path
from types import SimpleNamespace

import pytest

import agent_loop.provenance as provenance
from agent_loop.provenance import (
    closure_sha256,
    python_source_closure_sha256,
    snapshot_reviewed_closure,
)


def test_reviewed_closure_hash_is_stable_and_content_sensitive(tmp_path: Path) -> None:
    root = tmp_path / "closure"
    root.mkdir()
    selected = root / "tool.py"
    selected.write_text("VALUE = 1\n", encoding="utf-8")

    first = closure_sha256(root)
    assert closure_sha256(root) == first

    selected.write_text("VALUE = 2\n", encoding="utf-8")
    assert closure_sha256(root) != first


def test_reviewed_closure_hash_includes_root_kind_empty_directories_and_modes(
    tmp_path: Path,
) -> None:
    regular_root = tmp_path / "file" / "tool"
    regular_root.parent.mkdir()
    regular_root.write_bytes(b"identical payload")
    directory_root = tmp_path / "directory" / "closure"
    directory_root.mkdir(parents=True)
    (directory_root / "tool").write_bytes(b"identical payload")

    assert closure_sha256(regular_root) != closure_sha256(directory_root)

    initial = closure_sha256(directory_root)
    empty = directory_root / "empty"
    empty.mkdir()
    with_empty = closure_sha256(directory_root)
    assert with_empty != initial
    empty.chmod(0o700)
    assert closure_sha256(directory_root) != with_empty
    empty.rmdir()
    assert closure_sha256(directory_root) == initial


def test_reviewed_closure_rejects_links_special_entries_and_extended_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "closure"
    root.mkdir()
    selected = root / "tool.py"
    selected.write_text("pass\n", encoding="utf-8")

    os.link(selected, root / "hard-link.py")
    with pytest.raises(ValueError, match="unsafe non-regular"):
        closure_sha256(root)
    (root / "hard-link.py").unlink()

    (root / "linked.py").symlink_to(selected.name)
    with pytest.raises(ValueError, match="unsafe non-regular"):
        closure_sha256(root)
    (root / "linked.py").unlink()

    original = os.listxattr

    selected_identity = (selected.stat().st_dev, selected.stat().st_ino)

    def attributes(path: int | Path, *, follow_symlinks: bool = True) -> list[str]:
        if (
            isinstance(path, int)
            and (
                os.fstat(path).st_dev,
                os.fstat(path).st_ino,
            )
            == selected_identity
        ):
            return ["user.unreviewed"]
        return original(path, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(os, "listxattr", attributes)
    with pytest.raises(ValueError, match="extended metadata"):
        closure_sha256(root)


def test_extended_metadata_inspection_fails_closed_on_list_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = tmp_path / "tool"
    selected.write_bytes(b"tool")
    descriptor = os.open(selected, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        monkeypatch.setattr(
            os,
            "listxattr",
            lambda _descriptor: (_ for _ in ()).throw(OSError("metadata unavailable")),
        )
        with pytest.raises(ValueError, match="cannot be verified"):
            provenance.reject_extended_metadata_fd(descriptor)
    finally:
        os.close(descriptor)


def test_reviewed_closure_rejects_group_writable_or_extended_metadata_ancestors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "closure"
    root.mkdir()
    (root / "tool.py").write_text("pass\n", encoding="utf-8")
    root.chmod(0o775)
    assert closure_sha256(root)

    current = pwd.getpwuid(os.geteuid())
    foreign = SimpleNamespace(
        pw_name="foreign-member",
        pw_uid=os.geteuid() + 1,
        pw_gid=os.getegid(),
    )
    with monkeypatch.context() as group_patch:
        group_patch.setattr(
            grp,
            "getgrgid",
            lambda _group_id: SimpleNamespace(
                gr_mem=(current.pw_name, foreign.pw_name),
            ),
        )
        group_patch.setattr(pwd, "getpwall", lambda: [current, foreign])
        with pytest.raises(ValueError, match="unsafe reviewed path ancestor"):
            closure_sha256(root)
    root.chmod(0o755)

    original = os.listxattr
    ancestor_identity = (tmp_path.stat().st_dev, tmp_path.stat().st_ino)

    def attributes(path: int | Path, *, follow_symlinks: bool = True) -> list[str]:
        if (
            isinstance(path, int)
            and (
                os.fstat(path).st_dev,
                os.fstat(path).st_ino,
            )
            == ancestor_identity
        ):
            return ["user.unreviewed-ancestor"]
        return original(path, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(os, "listxattr", attributes)
    with pytest.raises(ValueError, match="extended metadata"):
        closure_sha256(root)


def test_python_source_closure_is_cache_and_location_independent(tmp_path: Path) -> None:
    first = tmp_path / "first" / "agent_loop"
    second = tmp_path / "second" / "agent_loop"
    first.mkdir(parents=True)
    second.mkdir(parents=True)
    for root in (first, second):
        (root / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
    cache = first / "__pycache__"
    cache.mkdir()
    (cache / "__init__.cpython-314.pyc").write_bytes(b"location-dependent cache")

    assert python_source_closure_sha256(first) == python_source_closure_sha256(second)

    (second / "shadow.cpython-314-x86_64-linux-gnu.so").write_bytes(b"unreviewed")
    with pytest.raises(ValueError, match="unexpected payload"):
        python_source_closure_sha256(second)


def test_reviewed_closure_snapshot_is_private_read_only_and_content_exact(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    executable = source / "tool"
    executable.write_bytes(b"#!/bin/sh\nexit 0\n")
    executable.chmod(0o755)
    nested = source / "lib"
    nested.mkdir(mode=0o711)
    (nested / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    destination = tmp_path / "private"
    destination.mkdir(mode=0o700)

    expected = closure_sha256(source)
    snapshot, mounted = snapshot_reviewed_closure(source, destination, expected)

    assert (snapshot / "tool").read_bytes() == executable.read_bytes()
    copied_module = (snapshot / "lib" / "module.py").read_text(encoding="utf-8")
    assert copied_module == "VALUE = 1\n"
    assert mounted == closure_sha256(snapshot)
    assert (snapshot / "tool").stat().st_mode & 0o222 == 0
    assert snapshot.stat().st_mode & 0o222 == 0
