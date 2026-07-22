from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from agent_loop.artifacts import ArtifactStore, ContentAddressedBlobStore
from agent_loop.errors import AgentLoopError, StopReason


def test_059_private_artifact_modes_are_independent_of_umask(tmp_path: Path) -> None:
    root = tmp_path / "state" / "run"
    previous_umask = os.umask(0)
    try:
        with ArtifactStore.create(root) as store:
            store.write_bytes("artifacts/rounds/001/result.bin", b"result")
    finally:
        os.umask(previous_umask)

    assert stat.S_IMODE(os.lstat(root).st_mode) == 0o700
    assert stat.S_IMODE(os.lstat(root / "artifacts").st_mode) == 0o700
    assert stat.S_IMODE(os.lstat(root / "artifacts" / "rounds" / "001").st_mode) == 0o700
    result_mode = os.lstat(root / "artifacts" / "rounds" / "001" / "result.bin").st_mode
    assert stat.S_IMODE(result_mode) == 0o600


def test_artifact_atomic_replace_and_canonical_json(tmp_path: Path) -> None:
    root = tmp_path / "run"
    with ArtifactStore.create(root) as store:
        store.write_bytes("value", b"old")
        store.write_bytes("value", b"new")
        assert store.read_bytes("value", max_bytes=16) == b"new"
        store.write_json("run.json", {"z": 1, "a": [True, None]})
        assert store.read_bytes("run.json", max_bytes=1024) == b'{"a":[true,null],"z":1}\n'
        assert store.read_json("run.json", max_bytes=1024) == {"a": [True, None], "z": 1}


def test_059_final_symlink_cannot_redirect_artifact_write(tmp_path: Path) -> None:
    root = tmp_path / "run"
    outside = tmp_path / "outside"
    outside.write_bytes(b"untouched")
    with ArtifactStore.create(root) as store:
        (root / "result").symlink_to(outside)
        store.write_bytes("result", b"artifact")
        assert store.read_bytes("result", max_bytes=32) == b"artifact"
    assert outside.read_bytes() == b"untouched"
    assert not (root / "result").is_symlink()


def test_059_intermediate_symlink_cannot_redirect_artifact_write(tmp_path: Path) -> None:
    root = tmp_path / "run"
    outside = tmp_path / "outside"
    outside.mkdir()
    with ArtifactStore.create(root) as store:
        (root / "rounds").symlink_to(outside, target_is_directory=True)
        with pytest.raises(AgentLoopError) as captured:
            store.write_bytes("rounds/001/result", b"artifact")
    assert captured.value.reason is StopReason.UNSAFE_OR_AMBIGUOUS_PATH
    assert list(outside.iterdir()) == []


def test_atomic_write_failure_preserves_prior_file_and_removes_temp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "run"
    with ArtifactStore.create(root) as store:
        store.write_bytes("result", b"prior")

        def fail_replace(*args: object, **kwargs: object) -> None:
            raise OSError(5, "injected replacement failure")

        monkeypatch.setattr(os, "replace", fail_replace)
        with pytest.raises(AgentLoopError):
            store.write_bytes("result", b"candidate")
        assert store.read_bytes("result", max_bytes=32) == b"prior"
        assert not any(entry.name.startswith(".agent-loop-tmp-") for entry in root.iterdir())


def test_artifact_reader_rejects_symlink_and_hardlink(tmp_path: Path) -> None:
    root = tmp_path / "run"
    outside = tmp_path / "outside"
    outside.write_bytes(b"secret")
    with ArtifactStore.create(root) as store:
        (root / "link").symlink_to(outside)
        with pytest.raises(AgentLoopError) as captured:
            store.read_bytes("link", max_bytes=32)
        assert captured.value.reason is StopReason.UNSAFE_FILE_TYPE_OR_HARD_LINK

        (root / "first").write_bytes(b"value")
        os.link(root / "first", root / "second")
        with pytest.raises(AgentLoopError) as captured:
            store.read_bytes("first", max_bytes=32)
        assert captured.value.reason is StopReason.UNSAFE_FILE_TYPE_OR_HARD_LINK


def test_059_open_rejects_artifact_root_that_is_not_private(tmp_path: Path) -> None:
    root = tmp_path / "run"
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    with pytest.raises(AgentLoopError) as captured:
        ArtifactStore.open(root)
    assert captured.value.reason is StopReason.OUT_OF_BAND_CHANGE


def test_content_addressed_blob_store_verifies_every_read(tmp_path: Path) -> None:
    root = tmp_path / "run"
    with ArtifactStore.create(root) as artifacts:
        blobs = ContentAddressedBlobStore(artifacts)
        digest = blobs.put_blob(b"payload")
        assert blobs.put_blob(b"payload") == digest
        assert blobs.read_blob(digest) == b"payload"

        blob_path = root / "subjects" / "blobs" / digest
        blob_path.write_bytes(b"corrupt")
        with pytest.raises(AgentLoopError) as captured:
            blobs.read_blob(digest)
        assert captured.value.reason is StopReason.OUT_OF_BAND_CHANGE
