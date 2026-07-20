from __future__ import annotations

import os
import socket
import stat
from pathlib import Path

import pytest

from agent_loop.constants import EXECUTABLE_MODE, REGULAR_MODE, SYMLINK_MODE, Limits
from agent_loop.errors import AgentLoopError, StopReason
from agent_loop.filesystem import ConfinedFilesystem, classify_entry_mode
from agent_loop.manifests import SubjectManifest
from agent_loop.models import EntryKind, ManifestEntry, ScanRecord, sha256_hex


class _Blobs:
    def __init__(self, values: dict[str, bytes]) -> None:
        self.values = values

    def read_blob(self, sha256: str) -> bytes:
        return self.values[sha256]


def _new_filesystem(tmp_path: Path) -> tuple[Path, ConfinedFilesystem]:
    root = tmp_path / "subject"
    return root, ConfinedFilesystem.create_private(root)


def test_004_materialization_normalizes_modes_timestamps_and_directories(tmp_path: Path) -> None:
    root, confined = _new_filesystem(tmp_path)
    records = (
        ScanRecord(b"plain", EntryKind.REGULAR, REGULAR_MODE, b"plain"),
        ScanRecord(b"nested/tool", EntryKind.REGULAR, EXECUTABLE_MODE, b"#!/bin/sh\n"),
        ScanRecord(b"nested/link", EntryKind.SYMLINK, SYMLINK_MODE, b"../plain"),
    )
    try:
        confined.materialize_records(records)
    finally:
        confined.close()

    assert stat.S_IMODE(os.lstat(root).st_mode) == 0o700
    assert stat.S_IMODE(os.lstat(root / "nested").st_mode) == 0o700
    assert stat.S_IMODE(os.lstat(root / "plain").st_mode) == 0o600
    assert stat.S_IMODE(os.lstat(root / "nested" / "tool").st_mode) == 0o700
    assert os.lstat(root / "plain").st_mtime_ns == 0
    assert os.lstat(root / "nested" / "link").st_mtime_ns == 0


def test_004_export_rejects_xattr_metadata(tmp_path: Path) -> None:
    root, confined = _new_filesystem(tmp_path)
    try:
        file_path = root / "file"
        file_path.write_bytes(b"data")
        try:
            os.setxattr(file_path, b"user.agent_loop_test", b"present")
        except OSError as exc:
            pytest.skip(f"test filesystem does not support user xattrs: {exc}")
        with pytest.raises(AgentLoopError) as captured:
            confined.scan_records()
        assert captured.value.reason is StopReason.UNSAFE_FILE_TYPE_OR_HARD_LINK
    finally:
        confined.close()


@pytest.mark.parametrize("mode", [0o4700, 0o2700, 0o1700])
def test_004_export_rejects_setid_and_sticky_metadata(tmp_path: Path, mode: int) -> None:
    root, confined = _new_filesystem(tmp_path)
    try:
        file_path = root / "file"
        file_path.write_bytes(b"data")
        file_path.chmod(mode)
        with pytest.raises(AgentLoopError) as captured:
            confined.scan_records()
        assert captured.value.reason is StopReason.UNSAFE_FILE_TYPE_OR_HARD_LINK
    finally:
        confined.close()


def test_004_export_rejects_ownership_variation(tmp_path: Path) -> None:
    alternate_groups = [group for group in os.getgroups() if group != os.getegid()]
    if not alternate_groups:
        pytest.skip("runner has no supplementary group for an unprivileged chgrp probe")
    root, confined = _new_filesystem(tmp_path)
    try:
        file_path = root / "file"
        file_path.write_bytes(b"data")
        os.chown(file_path, -1, alternate_groups[0])
        with pytest.raises(AgentLoopError) as captured:
            confined.scan_records()
        assert captured.value.reason is StopReason.UNSAFE_FILE_TYPE_OR_HARD_LINK
    finally:
        confined.close()


def test_042_symlink_capture_records_only_literal_target(tmp_path: Path) -> None:
    root, confined = _new_filesystem(tmp_path)
    outside = tmp_path / "host-secret"
    outside.write_bytes(b"contents-must-not-be-read")
    target = os.fsencode(outside)
    os.symlink(target, os.fsencode(root / "link"))
    try:
        records = confined.scan_records()
    finally:
        confined.close()
    assert records == (ScanRecord(b"link", EntryKind.SYMLINK, SYMLINK_MODE, target),)
    assert b"contents-must-not-be-read" not in records[0].payload


def test_045_hard_link_is_rejected_before_content_capture(tmp_path: Path) -> None:
    root, confined = _new_filesystem(tmp_path)
    (root / "one").write_bytes(b"sensitive")
    os.link(root / "one", root / "two")
    try:
        with pytest.raises(AgentLoopError) as captured:
            confined.scan_records()
    finally:
        confined.close()
    assert captured.value.reason is StopReason.UNSAFE_FILE_TYPE_OR_HARD_LINK
    assert "hard link" in captured.value.detail


def test_046_fifo_is_rejected_without_opening_it(tmp_path: Path) -> None:
    root, confined = _new_filesystem(tmp_path)
    os.mkfifo(root / "pipe")
    try:
        with pytest.raises(AgentLoopError) as captured:
            confined.scan_records()
    finally:
        confined.close()
    assert captured.value.reason is StopReason.UNSAFE_FILE_TYPE_OR_HARD_LINK
    assert "FIFO" in captured.value.detail


def test_046_socket_is_rejected_without_reading_it(tmp_path: Path) -> None:
    root, confined = _new_filesystem(tmp_path)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(root / "socket"))
    try:
        with pytest.raises(AgentLoopError) as captured:
            confined.scan_records()
    finally:
        server.close()
        confined.close()
    assert captured.value.reason is StopReason.UNSAFE_FILE_TYPE_OR_HARD_LINK
    assert "socket" in captured.value.detail


@pytest.mark.parametrize("mode", [stat.S_IFBLK | 0o600, stat.S_IFCHR | 0o600])
def test_046_device_modes_are_rejected_without_device_access(mode: int) -> None:
    with pytest.raises(AgentLoopError) as captured:
        classify_entry_mode(mode, b"device")
    assert captured.value.reason is StopReason.UNSAFE_FILE_TYPE_OR_HARD_LINK


def test_001_complete_scan_ignores_no_gitignore_entries(tmp_path: Path) -> None:
    root, confined = _new_filesystem(tmp_path)
    (root / ".gitignore").write_bytes(b"ignored\n")
    (root / "ignored").write_bytes(b"still-authoritative")
    try:
        records = confined.scan_records()
    finally:
        confined.close()
    assert [record.path for record in records] == [b".gitignore", b"ignored"]


def test_047_materialization_round_trips_arbitrary_path_bytes(tmp_path: Path) -> None:
    root, confined = _new_filesystem(tmp_path)
    path = b"directory/newline\n-and-\xff"
    original = (ScanRecord(path, EntryKind.REGULAR, REGULAR_MODE, b"payload"),)
    try:
        confined.materialize_records(original)
        assert confined.scan_records() == original
    finally:
        confined.close()
    assert os.path.lexists(os.fsencode(root) + b"/" + path)


def test_complete_scan_counts_empty_directories_toward_namespace_limit(tmp_path: Path) -> None:
    root, confined = _new_filesystem(tmp_path)
    for name in ("one", "two", "three"):
        (root / name).mkdir()
    try:
        with pytest.raises(AgentLoopError):
            confined.scan_records(limits=Limits(max_files=2))
    finally:
        confined.close()


def test_materialization_rejects_file_parent_conflict_before_writing(tmp_path: Path) -> None:
    root, confined = _new_filesystem(tmp_path)
    records = (
        ScanRecord(b"path", EntryKind.REGULAR, REGULAR_MODE, b"first"),
        ScanRecord(b"path/child", EntryKind.REGULAR, REGULAR_MODE, b"second"),
    )
    try:
        with pytest.raises(AgentLoopError):
            confined.materialize_records(records)
    finally:
        confined.close()
    assert list(root.iterdir()) == []


def test_manifest_materialization_verifies_content_addressed_blob(tmp_path: Path) -> None:
    payload = b"canonical"
    digest = sha256_hex(payload)
    manifest = SubjectManifest.build(
        [ManifestEntry.regular(b"file", size=len(payload), blob_sha256=digest)]
    )
    root, confined = _new_filesystem(tmp_path)
    try:
        confined.materialize_manifest(manifest, _Blobs({digest: payload}))
        assert confined.scan_records() == (
            ScanRecord(b"file", EntryKind.REGULAR, REGULAR_MODE, payload),
        )
    finally:
        confined.close()
    assert (root / "file").read_bytes() == payload


def test_manifest_materialization_rejects_blob_mismatch_before_writing(tmp_path: Path) -> None:
    payload = b"canonical"
    digest = sha256_hex(payload)
    manifest = SubjectManifest.build(
        [ManifestEntry.regular(b"file", size=len(payload), blob_sha256=digest)]
    )
    root, confined = _new_filesystem(tmp_path)
    try:
        with pytest.raises(AgentLoopError) as captured:
            confined.materialize_manifest(manifest, _Blobs({digest: b"corrupted"}))
    finally:
        confined.close()
    assert captured.value.reason is StopReason.OUT_OF_BAND_CHANGE
    assert list(root.iterdir()) == []
