from __future__ import annotations

import base64
import json
import os
import threading
from pathlib import Path

import pytest

from agent_loop.artifacts import ArtifactStore
from agent_loop.declassify import KnownSecret
from agent_loop.errors import AgentLoopError, StopReason
from agent_loop.filesystem import ConfinedFilesystem


def test_refresh_scrub_recurses_through_outer_json_and_base64(tmp_path: Path) -> None:
    root = tmp_path / "run"
    secret = KnownSecret("generation-c", b"secretvalue")
    inner = b'{"value":"\\u0073ecretvalue"}'
    outer = json.dumps(
        {"process": {"stdout_b64": base64.b64encode(inner).decode("ascii")}},
        separators=(",", ":"),
    ).encode("ascii")

    with ArtifactStore.create(root) as artifacts:
        artifacts.write_bytes("artifacts/outer.stdout", outer)
        artifacts.write_bytes("artifacts/direct.log", b"prefix " + secret.value)
        artifacts.write_bytes("artifacts/safe.json", b'{"status":"safe"}\n')

        assert artifacts.scrub_known_secrets((secret,)) is True
        assert artifacts.content_withheld_due_to_secret is True
        with pytest.raises(AgentLoopError) as withheld:
            artifacts.read_bytes("artifacts/safe.json", max_bytes=1024)
        assert withheld.value.reason is StopReason.CREDENTIAL_REFRESH_FAILURE

    assert list(root.iterdir()) == []


def test_refresh_scrub_removes_secret_symlink_targets_and_names(tmp_path: Path) -> None:
    root = tmp_path / "run"
    secret = KnownSecret("generation-c", b"refresh-token-c")

    with ArtifactStore.create(root) as artifacts:
        os.mkdir(root / "subjects", mode=0o700)
        os.symlink(secret.value.decode("ascii"), root / "subjects" / "link")
        named = root / "subjects" / secret.value.decode("ascii")
        named.write_bytes(b"otherwise safe")
        os.chmod(named, 0o600)

        assert artifacts.scrub_known_secrets((secret,)) is True

    assert not (root / "subjects" / "link").is_symlink()
    assert not named.exists()


def test_scrub_fsync_failure_latches_whole_run_withholding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "run"
    secret = KnownSecret("generation-c", b"refresh-token-c")

    with ArtifactStore.create(root) as artifacts:
        os.symlink(secret.value.decode("ascii"), root / "tainted-link")
        original_fsync = os.fsync
        calls = 0

        def fail_first_fsync(descriptor: int) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("injected fsync failure")
            original_fsync(descriptor)

        monkeypatch.setattr(os, "fsync", fail_first_fsync)
        with pytest.raises(AgentLoopError) as caught:
            artifacts.scrub_known_secrets((secret,))

        assert caught.value.reason is StopReason.CREDENTIAL_REFRESH_FAILURE
        assert artifacts.content_withheld_due_to_secret is True

    with ArtifactStore.open(root) as reopened:
        assert reopened.content_withheld_due_to_secret is True
        with pytest.raises(AgentLoopError) as withheld:
            reopened.read_bytes("tainted-link", max_bytes=1024)
        assert withheld.value.reason is StopReason.CREDENTIAL_REFRESH_FAILURE

    assert list(root.iterdir()) == []


def test_persistent_marker_failure_still_erases_retained_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "run"
    artifacts = ArtifactStore.create(root)
    artifacts.write_bytes("secret.log", b"credential-collision")
    original_write = ConfinedFilesystem.atomic_write

    def fail_marker_write(
        filesystem: ConfinedFilesystem,
        path: bytes,
        data: bytes,
        *,
        mode: int,
        create_parents: bool,
        normalize_timestamp: bool = False,
    ) -> None:
        if path.startswith(b"withheld-v1-"):
            raise OSError("injected persistent marker failure")
        original_write(
            filesystem,
            path,
            data,
            mode=mode,
            create_parents=create_parents,
            normalize_timestamp=normalize_timestamp,
        )

    monkeypatch.setattr(ConfinedFilesystem, "atomic_write", fail_marker_write)
    try:
        with pytest.raises(AgentLoopError) as caught:
            artifacts.withhold_all_content()
        assert caught.value.reason is StopReason.CREDENTIAL_REFRESH_FAILURE
        assert artifacts.content_withheld_due_to_secret is True
    finally:
        artifacts.close()

    assert list(root.iterdir()) == []
    with ArtifactStore.open(root) as reopened:
        assert reopened.content_withheld_due_to_secret is False
        with pytest.raises(AgentLoopError) as missing:
            reopened.read_bytes("secret.log", max_bytes=1024)
        assert isinstance(missing.value.__cause__, OSError)
        assert missing.value.__cause__.errno == 2


def test_withhold_marker_precedes_interrupted_erasure_and_allows_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "run"
    control_root = tmp_path / ".agent-loop-artifact-control"

    with ArtifactStore.create(root) as artifacts:
        artifacts.write_bytes("first.log", b"first retained bytes")
        artifacts.write_bytes("nested/second.log", b"second retained bytes")
        def interrupting_erase(directory_fd: int) -> None:
            markers = [
                path for path in control_root.iterdir() if path.name.startswith("withheld-v1-")
            ]
            assert len(markers) == 1
            assert markers[0].is_file()
            assert markers[0].read_bytes() == b""
            os.unlink(b"first.log", dir_fd=directory_fd)
            raise KeyboardInterrupt("injected interruption during artifact erasure")

        with monkeypatch.context() as injection:
            injection.setattr(
                ArtifactStore,
                "_erase_directory",
                staticmethod(interrupting_erase),
            )
            with pytest.raises(KeyboardInterrupt):
                artifacts.withhold_all_content()

        assert artifacts.content_withheld_due_to_secret is True
        assert not (root / "first.log").exists()
        assert (root / "nested" / "second.log").is_file()
        artifacts.write_bytes("post-latch.log", b"must not be retained")
        assert not (root / "post-latch.log").exists()
        with pytest.raises(AgentLoopError):
            artifacts.read_bytes("nested/second.log", max_bytes=1024)

    with ArtifactStore.open(root) as reopened:
        assert reopened.content_withheld_due_to_secret is True
        reopened.withhold_all_content()
        reopened.withhold_all_content()

    assert list(root.iterdir()) == []
    markers = [
        path for path in control_root.iterdir() if path.name.startswith("withheld-v1-")
    ]
    assert len(markers) == 1
    assert markers[0].read_bytes() == b""
    assert markers[0].stat().st_mode & 0o777 == 0o600


def test_withholding_latch_is_outside_run_and_cannot_collide_with_token_path(
    tmp_path: Path,
) -> None:
    root = tmp_path / "run"
    old_marker_token = b".agent-loop-credential-content-withheld"

    with ArtifactStore.create(root) as artifacts:
        artifacts.write_bytes("safe.log", b"safe")
        assert artifacts.scrub_known_secrets(
            (KnownSecret("marker-collision", old_marker_token),)
        ) is False
        artifacts.withhold_all_content()

    assert list(root.iterdir()) == []
    control_root = tmp_path / ".agent-loop-artifact-control"
    markers = [
        path for path in control_root.iterdir() if path.name.startswith("withheld-v1-")
    ]
    assert len(markers) == 1


def test_unsafe_external_withholding_latch_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "run"
    with ArtifactStore.create(root):
        pass
    control_root = tmp_path / ".agent-loop-artifact-control"
    for child in control_root.iterdir():
        child.unlink()
    control_root.rmdir()
    control_root.symlink_to(tmp_path / "elsewhere", target_is_directory=True)

    with pytest.raises(AgentLoopError) as caught:
        ArtifactStore.open(root)

    assert caught.value.reason is StopReason.CREDENTIAL_REFRESH_FAILURE


def test_descriptor_only_store_cannot_bypass_path_bound_withholding(
    tmp_path: Path,
) -> None:
    root = tmp_path / "run"
    with ArtifactStore.create(root) as artifacts:
        artifacts.withhold_all_content()
        with ConfinedFilesystem.open(root) as filesystem:
            with pytest.raises(ValueError, match="path-bound"):
                ArtifactStore.from_filesystem(filesystem)


def test_artifact_root_cannot_alias_its_external_control_root(tmp_path: Path) -> None:
    root = tmp_path / ".agent-loop-artifact-control"

    with pytest.raises(ValueError, match="structurally disjoint"):
        ArtifactStore.create(root)

    assert not root.exists()


def test_latch_and_artifact_write_are_serialized_across_store_instances(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "run"
    writer = ArtifactStore.create(root)
    withholder = ArtifactStore.open(root)
    write_started = threading.Event()
    release_write = threading.Event()
    latch_finished = threading.Event()
    failures: list[BaseException] = []
    original_write = ConfinedFilesystem.atomic_write

    def paused_write(
        filesystem: ConfinedFilesystem,
        path: bytes,
        data: bytes,
        *,
        mode: int,
        create_parents: bool,
        normalize_timestamp: bool = False,
    ) -> None:
        if filesystem is not writer._filesystem:
            original_write(
                filesystem,
                path,
                data,
                mode=mode,
                create_parents=create_parents,
                normalize_timestamp=normalize_timestamp,
            )
            return
        write_started.set()
        if not release_write.wait(2):
            raise RuntimeError("test did not release artifact write")
        original_write(
            filesystem,
            path,
            data,
            mode=mode,
            create_parents=create_parents,
            normalize_timestamp=normalize_timestamp,
        )

    monkeypatch.setattr(ConfinedFilesystem, "atomic_write", paused_write)

    def write() -> None:
        try:
            writer.write_bytes("post-latch", b"secret")
        except BaseException as exc:
            failures.append(exc)

    def latch() -> None:
        try:
            withholder.withhold_all_content()
        except BaseException as exc:
            failures.append(exc)
        finally:
            latch_finished.set()

    writing = threading.Thread(target=write)
    withholding = threading.Thread(target=latch)
    try:
        writing.start()
        assert write_started.wait(2)
        withholding.start()
        assert not latch_finished.wait(0.05)
        release_write.set()
        writing.join(2)
        withholding.join(2)
        assert failures == []
        assert latch_finished.is_set()
        assert list(root.iterdir()) == []
    finally:
        release_write.set()
        writing.join(2)
        withholding.join(2)
        writer.close()
        withholder.close()


def test_production_retained_filesystem_is_serialized_with_withholding(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state" / "agent-loop" / "runs" / "run-1"
    writer = ArtifactStore.create(root)
    withholder = ArtifactStore.open(root)
    write_started = threading.Event()
    release_write = threading.Event()
    latch_finished = threading.Event()
    failures: list[BaseException] = []

    def write_subject() -> None:
        try:
            with writer.retained_filesystem() as filesystem:
                write_started.set()
                if not release_write.wait(2):
                    raise RuntimeError("test did not release retained-tree write")
                filesystem.atomic_write(
                    b"subjects/current/app.py",
                    b"post-latch",
                    mode=0o600,
                    create_parents=True,
                )
        except BaseException as exc:
            failures.append(exc)

    def latch() -> None:
        try:
            withholder.withhold_all_content()
        except BaseException as exc:
            failures.append(exc)
        finally:
            latch_finished.set()

    writing = threading.Thread(target=write_subject)
    withholding = threading.Thread(target=latch)
    try:
        writing.start()
        assert write_started.wait(2)
        withholding.start()
        assert not latch_finished.wait(0.05)
        release_write.set()
        writing.join(2)
        withholding.join(2)
        assert failures == []
        assert latch_finished.is_set()
        assert list(root.iterdir()) == []
        with pytest.raises(AgentLoopError) as caught:
            with writer.retained_filesystem():
                raise AssertionError("latched retained authority was released")
        assert caught.value.reason is StopReason.CREDENTIAL_REFRESH_FAILURE
    finally:
        release_write.set()
        writing.join(2)
        withholding.join(2)
        writer.close()
        withholder.close()
