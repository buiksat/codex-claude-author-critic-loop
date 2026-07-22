from __future__ import annotations

import hashlib
import os
import stat
import subprocess
from collections.abc import Iterable, Sequence
from pathlib import Path

import pytest

import agent_loop.git_source as git_source
from agent_loop.constants import DEFAULT_MAX_AGENT_OUTPUT_BYTES
from agent_loop.errors import AgentLoopError, StopReason
from agent_loop.git_source import (
    GitCommandRunner,
    GitProcessResult,
    GitSandboxMode,
    extract_committed_head,
)
from agent_loop.models import EntryKind


class MemoryBlobStore:
    def __init__(self) -> None:
        self.values: dict[str, bytes] = {}

    def put_blob(self, data: bytes) -> str:
        digest = hashlib.sha256(data).hexdigest()
        self.values.setdefault(digest, data)
        return digest

    def read_blob(self, digest: str) -> bytes:
        return self.values[digest]


class MutatingBlobStore(MemoryBlobStore):
    def __init__(self, source_file: Path) -> None:
        super().__init__()
        self.source_file = source_file
        self.mutated = False

    def put_blob(self, data: bytes) -> str:
        if not self.mutated:
            self.source_file.write_bytes(b"out-of-band mutation\n")
            self.mutated = True
        return super().put_blob(data)


def _setup_environment(home: Path) -> dict[str, str]:
    home.mkdir(exist_ok=True)
    return {
        "HOME": os.fspath(home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }


def _git(repository: Path, *arguments: str, input_data: bytes | None = None) -> bytes:
    result = subprocess.run(  # noqa: S603 - fixed test helper invoking pinned /usr/bin/git
        ("/usr/bin/git", *arguments),
        cwd=repository,
        env=_setup_environment(repository.parent / "setup-home"),
        input=input_data,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"test Git setup failed ({result.returncode}): "
            f"{result.stderr.decode('utf-8', 'backslashreplace')}"
        )
    return result.stdout.rstrip(b"\n")


def _init_repository(root: Path, *, commit: bool = True) -> Path:
    root.mkdir()
    _git(root, "init", "-q", "--initial-branch=main")
    _git(root, "config", "user.name", "Agent Loop Tests")
    _git(root, "config", "user.email", "agent-loop@example.invalid")
    if commit:
        (root / "tracked.txt").write_bytes(b"committed\n")
        _git(root, "add", "--", "tracked.txt")
        _git(root, "commit", "-q", "-m", "base")
    return root


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    root_bytes = os.fsencode(root)
    stack: list[tuple[bytes, bytes]] = [(b"", root_bytes)]
    while stack:
        relative, absolute = stack.pop()
        with os.scandir(absolute) as iterator:
            children = sorted(iterator, key=lambda item: os.fsencode(item.name), reverse=True)
        for child in children:
            name = os.fsencode(child.name)
            child_relative = name if not relative else relative + b"/" + name
            metadata = child.stat(follow_symlinks=False)
            digest.update(len(child_relative).to_bytes(8, "big"))
            digest.update(child_relative)
            digest.update(stat.S_IFMT(metadata.st_mode).to_bytes(4, "big"))
            digest.update(stat.S_IMODE(metadata.st_mode).to_bytes(4, "big"))
            absolute_child = os.path.join(absolute, name)
            if stat.S_ISLNK(metadata.st_mode):
                target = os.readlink(absolute_child)
                assert isinstance(target, bytes)
                digest.update(target)
            elif stat.S_ISREG(metadata.st_mode):
                with open(absolute_child, "rb") as stream:
                    for chunk in iter(lambda: stream.read(65_536), b""):
                        digest.update(chunk)
            elif stat.S_ISDIR(metadata.st_mode):
                stack.append((child_relative, absolute_child))
            else:
                digest.update(b"special")
    return digest.hexdigest()


def _disabled_runner() -> GitCommandRunner:
    return GitCommandRunner(sandbox_mode=GitSandboxMode.DISABLED)


def test_005_006_040_private_git_derived_manifest_and_source_immutability(
    tmp_path: Path,
) -> None:
    repository = _init_repository(tmp_path / "source", commit=False)
    (repository / ".gitignore").write_bytes(b"ignored.tmp\n")
    (repository / "plain.txt").write_bytes(b"committed plain\n")
    (repository / "binary.bin").write_bytes(b"\x00binary\xff\n")
    executable = repository / "run.sh"
    executable.write_bytes(b"#!/bin/sh\nexit 0\n")
    executable.chmod(0o755)
    newline_path = os.fsencode(repository) + b"/line\nname.txt"
    descriptor = os.open(newline_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, b"newline path\n")
    finally:
        os.close(descriptor)
    os.symlink(b"../../literal-host-secret", os.fsencode(repository / "link"))
    _git(repository, "add", "--all")
    _git(repository, "commit", "-q", "-m", "canonical tree")

    before = _tree_digest(repository)
    store = MemoryBlobStore()
    snapshot = extract_committed_head(repository, store, runner=_disabled_runner())
    after = _tree_digest(repository)

    assert before == after
    entries = {entry.path: entry for entry in snapshot.manifest.entries}
    assert all(b".git" not in path.split(b"/") for path in entries)
    assert entries[b"plain.txt"].kind is EntryKind.REGULAR
    assert store.read_blob(entries[b"plain.txt"].blob_sha256 or "") == b"committed plain\n"
    assert entries[b"binary.bin"].size == len(b"\x00binary\xff\n")
    assert entries[b"run.sh"].executable
    assert entries[b"line\nname.txt"].path == b"line\nname.txt"
    assert entries[b"link"].kind is EntryKind.SYMLINK
    assert entries[b"link"].symlink_target == b"../../literal-host-secret"


def test_061_dirty_staged_untracked_and_ignored_checkout_state_is_excluded(
    tmp_path: Path,
) -> None:
    repository = _init_repository(tmp_path / "source", commit=False)
    (repository / ".gitignore").write_bytes(b"ignored.tmp\n")
    (repository / "tracked.txt").write_bytes(b"HEAD bytes\n")
    _git(repository, "add", "--all")
    _git(repository, "commit", "-q", "-m", "base")

    (repository / "tracked.txt").write_bytes(b"staged local bytes\n")
    _git(repository, "add", "--", "tracked.txt")
    (repository / "tracked.txt").write_bytes(b"unstaged local bytes\n")
    (repository / "untracked.txt").write_bytes(b"untracked\n")
    (repository / "ignored.tmp").write_bytes(b"ignored\n")
    index_before = (repository / ".git" / "index").read_bytes()

    store = MemoryBlobStore()
    snapshot = extract_committed_head(repository, store, runner=_disabled_runner())
    entries = {entry.path: entry for entry in snapshot.manifest.entries}

    tracked = entries[b"tracked.txt"]
    assert store.read_blob(tracked.blob_sha256 or "") == b"HEAD bytes\n"
    assert b"untracked.txt" not in entries
    assert b"ignored.tmp" not in entries
    assert (repository / ".git" / "index").read_bytes() == index_before
    assert "staged, unstaged, untracked, and ignored" in snapshot.warnings[0]


def test_037_038_hostile_git_environment_and_config_never_execute(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository = _init_repository(tmp_path / "source", commit=False)
    (repository / ".gitattributes").write_bytes(b"payload.txt filter=evil diff=evil\n")
    (repository / "payload.txt").write_bytes(b"raw committed bytes\n")
    _git(repository, "add", "--all")
    _git(repository, "commit", "-q", "-m", "attributes")

    marker = tmp_path / "executed"
    hostile = tmp_path / "hostile-helper"
    hostile.write_text(
        f"#!/bin/sh\nprintf invoked > {os.fspath(marker)!r}\n",
        encoding="utf-8",
    )
    hostile.chmod(0o755)
    _git(repository, "config", "core.fsmonitor", os.fspath(hostile))
    _git(repository, "config", "core.hooksPath", os.fspath(tmp_path / "hooks"))
    _git(repository, "config", "diff.external", os.fspath(hostile))
    _git(repository, "config", "filter.evil.smudge", os.fspath(hostile))
    _git(repository, "config", "filter.evil.clean", os.fspath(hostile))
    _git(repository, "config", "credential.helper", f"!{hostile}")
    _git(repository, "config", "core.pager", os.fspath(hostile))
    for name in (
        "GIT_EXTERNAL_DIFF",
        "GIT_CONFIG_GLOBAL",
        "GIT_SSH_COMMAND",
        "SSH_ASKPASS",
        "HTTPS_PROXY",
        "ALL_PROXY",
    ):
        monkeypatch.setenv(name, os.fspath(hostile))

    store = MemoryBlobStore()
    snapshot = extract_committed_head(repository, store, runner=_disabled_runner())
    payload = next(entry for entry in snapshot.manifest.entries if entry.path == b"payload.txt")
    assert store.read_blob(payload.blob_sha256 or "") == b"raw committed bytes\n"
    assert not marker.exists()


def test_039_bare_and_invalid_head_repositories_fail_closed(tmp_path: Path) -> None:
    bare = tmp_path / "bare.git"
    bare.mkdir()
    _git(bare, "init", "-q", "--bare")
    empty = _init_repository(tmp_path / "empty", commit=False)
    for repository in (bare, empty):
        with pytest.raises(AgentLoopError) as caught:
            extract_committed_head(repository, MemoryBlobStore(), runner=_disabled_runner())
        assert caught.value.reason in {
            StopReason.REPOSITORY_SHAPE_UNSUPPORTED,
            StopReason.GIT_POLICY_OR_OUTPUT_FAILURE,
        }


def test_039_submodule_and_nested_repository_shapes_are_rejected(tmp_path: Path) -> None:
    submodule_repository = _init_repository(tmp_path / "submodule")
    commit_oid = _git(submodule_repository, "rev-parse", "HEAD").decode("ascii")
    _git(
        submodule_repository,
        "update-index",
        "--add",
        "--cacheinfo",
        f"160000,{commit_oid},vendor",
    )
    _git(submodule_repository, "commit", "-q", "-m", "gitlink")
    with pytest.raises(AgentLoopError) as submodule_error:
        extract_committed_head(
            submodule_repository,
            MemoryBlobStore(),
            runner=_disabled_runner(),
        )
    assert submodule_error.value.reason is StopReason.REPOSITORY_SHAPE_UNSUPPORTED

    nested_repository = _init_repository(tmp_path / "nested")
    (nested_repository / "vendor" / ".git").mkdir(parents=True)
    with pytest.raises(AgentLoopError) as nested_error:
        extract_committed_head(
            nested_repository,
            MemoryBlobStore(),
            runner=_disabled_runner(),
        )
    assert nested_error.value.reason is StopReason.REPOSITORY_SHAPE_UNSUPPORTED


def test_039_promisor_replace_alternate_and_worktree_config_are_rejected(
    tmp_path: Path,
) -> None:
    repositories = {
        name: _init_repository(tmp_path / name)
        for name in ("promisor", "replace", "alternate", "worktree-config")
    }
    _git(repositories["promisor"], "config", "extensions.partialClone", "origin")

    replace_repository = repositories["replace"]
    (replace_repository / "tracked.txt").write_bytes(b"second\n")
    _git(replace_repository, "add", "--", "tracked.txt")
    _git(replace_repository, "commit", "-q", "-m", "second")
    _git(replace_repository, "replace", "HEAD", "HEAD~1")

    alternates = repositories["alternate"] / ".git" / "objects" / "info" / "alternates"
    alternates.write_text("/unreviewed/object/store\n", encoding="utf-8")
    _git(repositories["worktree-config"], "config", "extensions.worktreeConfig", "true")

    for repository in repositories.values():
        with pytest.raises(AgentLoopError) as caught:
            extract_committed_head(repository, MemoryBlobStore(), runner=_disabled_runner())
        assert caught.value.reason is StopReason.REPOSITORY_SHAPE_UNSUPPORTED


def test_039_missing_committed_blob_is_rejected_without_lazy_fetch(tmp_path: Path) -> None:
    repository = _init_repository(tmp_path / "source")
    object_id = _git(repository, "rev-parse", "HEAD:tracked.txt").decode("ascii")
    object_path = repository / ".git" / "objects" / object_id[:2] / object_id[2:]
    assert object_path.is_file()
    object_path.rename(tmp_path / "removed-object")

    with pytest.raises(AgentLoopError) as caught:
        extract_committed_head(repository, MemoryBlobStore(), runner=_disabled_runner())
    assert caught.value.reason in {
        StopReason.REPOSITORY_SHAPE_UNSUPPORTED,
        StopReason.GIT_POLICY_OR_OUTPUT_FAILURE,
    }


def test_040_source_mutation_during_extraction_is_fatal(tmp_path: Path) -> None:
    repository = _init_repository(tmp_path / "source")
    store = MutatingBlobStore(repository / "tracked.txt")
    with pytest.raises(AgentLoopError) as caught:
        extract_committed_head(repository, store, runner=_disabled_runner())
    assert caught.value.reason is StopReason.OUT_OF_BAND_CHANGE


def test_040_repository_root_swap_cannot_redirect_bound_git_reads(tmp_path: Path) -> None:
    repository = _init_repository(tmp_path / "source", commit=False)
    (repository / "original.txt").write_text("original\n", encoding="utf-8")
    _git(repository, "add", "--all")
    _git(repository, "commit", "-q", "-m", "original")
    replacement = _init_repository(tmp_path / "replacement", commit=False)
    (replacement / "swapped.txt").write_text("swapped\n", encoding="utf-8")
    _git(replacement, "add", "--all")
    _git(replacement, "commit", "-q", "-m", "replacement")
    parked = tmp_path / "parked-original"

    class SwappingRunner(GitCommandRunner):
        def run(
            self,
            repository: Path,
            arguments: Sequence[str],
            *,
            stdin_data: bytes = b"",
            max_stdout_bytes: int = DEFAULT_MAX_AGENT_OUTPUT_BYTES,
            allowed_returncodes: Iterable[int] = (0,),
        ) -> GitProcessResult:
            repository.rename(parked)
            replacement.rename(repository)
            try:
                return super().run(
                    repository,
                    arguments,
                    stdin_data=stdin_data,
                    max_stdout_bytes=max_stdout_bytes,
                    allowed_returncodes=allowed_returncodes,
                )
            finally:
                repository.rename(replacement)
                parked.rename(repository)

    snapshot = extract_committed_head(
        repository,
        MemoryBlobStore(),
        runner=SwappingRunner(sandbox_mode=GitSandboxMode.DISABLED),
    )

    assert {entry.path for entry in snapshot.manifest.entries} == {b"original.txt"}


def test_039_alternates_check_uses_retained_repository_root(tmp_path: Path) -> None:
    repository = _init_repository(tmp_path / "source")
    alternates = repository / ".git" / "objects" / "info" / "alternates"
    alternates.write_text("/unreviewed/object/store\n", encoding="utf-8")
    replacement = _init_repository(tmp_path / "replacement")
    parked = tmp_path / "parked-original"
    descriptor = os.open(repository, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    repository.rename(parked)
    replacement.rename(repository)
    try:
        with pytest.raises(AgentLoopError) as caught:
            git_source._reject_alternates(descriptor)
        assert caught.value.reason is StopReason.REPOSITORY_SHAPE_UNSUPPORTED
    finally:
        os.close(descriptor)
        repository.rename(replacement)
        parked.rename(repository)


def test_040_persistent_repository_root_swap_is_out_of_band(tmp_path: Path) -> None:
    repository = _init_repository(tmp_path / "source")
    replacement = _init_repository(tmp_path / "replacement")
    parked = tmp_path / "parked-original"

    class SwapAfterShapeRunner(GitCommandRunner):
        swapped = False

        def restore(self, selected: Path) -> None:
            if self.swapped:
                selected.rename(replacement)
                parked.rename(selected)
                self.swapped = False

        def run(
            self,
            repository: Path,
            arguments: Sequence[str],
            *,
            stdin_data: bytes = b"",
            max_stdout_bytes: int = DEFAULT_MAX_AGENT_OUTPUT_BYTES,
            allowed_returncodes: Iterable[int] = (0,),
        ) -> GitProcessResult:
            result = super().run(
                repository,
                arguments,
                stdin_data=stdin_data,
                max_stdout_bytes=max_stdout_bytes,
                allowed_returncodes=allowed_returncodes,
            )
            if tuple(arguments) == (
                "rev-parse",
                "--is-inside-work-tree",
                "--is-bare-repository",
                "--git-dir",
                "--git-common-dir",
            ):
                repository.rename(parked)
                replacement.rename(repository)
                self.swapped = True
            return result

    runner = SwapAfterShapeRunner(sandbox_mode=GitSandboxMode.DISABLED)
    try:
        with pytest.raises(AgentLoopError) as caught:
            extract_committed_head(repository, MemoryBlobStore(), runner=runner)
        assert caught.value.reason is StopReason.OUT_OF_BAND_CHANGE
    finally:
        runner.restore(repository)


@pytest.mark.host
def test_040_required_no_network_bwrap_reads_source_read_only(tmp_path: Path) -> None:
    repository = _init_repository(tmp_path / "source")
    before = _tree_digest(repository)
    snapshot = extract_committed_head(repository, MemoryBlobStore())
    assert [entry.path for entry in snapshot.manifest.entries] == [b"tracked.txt"]
    assert _tree_digest(repository) == before
