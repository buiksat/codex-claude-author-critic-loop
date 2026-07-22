from __future__ import annotations

import pytest

from agent_loop.constants import REGULAR_MODE
from agent_loop.errors import AgentLoopError, ExitCode, StopReason
from agent_loop.manifests import SubjectManifest, build_manifest_from_scan, reconcile_candidate
from agent_loop.models import EntryKind, PathPolicy, ScanRecord, sha256_hex


class MemoryBlobs:
    def __init__(self) -> None:
        self.values: dict[str, bytes] = {}

    def put_blob(self, data: bytes) -> str:
        digest = sha256_hex(data)
        self.values[digest] = data
        return digest

    def read_blob(self, sha256: str) -> bytes:
        return self.values[sha256]


def scan(records: list[tuple[bytes, bytes]], blobs: MemoryBlobs) -> SubjectManifest:
    return build_manifest_from_scan(
        [ScanRecord(path, EntryKind.REGULAR, REGULAR_MODE, data) for path, data in records],
        blobs,
    )


def test_001_ignored_author_output_enters_authoritative_validation_subject() -> None:
    blobs = MemoryBlobs()
    base = scan([(b".gitignore", b"runtime.conf\n")], blobs)
    candidate = scan(
        [(b".gitignore", b"runtime.conf\n"), (b"runtime.conf", b"feature=enabled\n")],
        blobs,
    )

    result = reconcile_candidate(base, candidate, PathPolicy())

    assert [entry.path for entry in result.authoritative_manifest.entries] == [
        b".gitignore",
        b"runtime.conf",
    ]
    validation_input = SubjectManifest.from_json_bytes(
        result.authoritative_manifest.to_json_bytes()
    )
    runtime_entry = next(
        entry for entry in validation_input.entries if entry.path == b"runtime.conf"
    )
    assert runtime_entry.blob_sha256 is not None
    assert blobs.read_blob(runtime_entry.blob_sha256) == b"feature=enabled\n"


def test_002_ignore_rule_change_cannot_hide_existing_or_new_candidate_entry() -> None:
    blobs = MemoryBlobs()
    base = scan([(b".gitignore", b"")], blobs)
    candidate = scan(
        [
            (b".gitignore", b"*.secret\nignored/**\n"),
            (b"credential.secret", b"subject-data"),
            (b"ignored/executable", b"#!/bin/sh\n"),
        ],
        blobs,
    )

    result = reconcile_candidate(base, candidate, PathPolicy())

    assert {entry.path for entry in result.authoritative_manifest.entries} == {
        b".gitignore",
        b"credential.secret",
        b"ignored/executable",
    }


def test_003_discard_only_output_is_recorded_but_not_authoritative_or_next_round() -> None:
    blobs = MemoryBlobs()
    base = scan([(b"src/app.py", b"old")], blobs)
    candidate = scan([(b"src/app.py", b"new"), (b"build/cache.bin", b"generated")], blobs)
    policy = PathPolicy(discard_only_patterns=(b"build/**",))

    result = reconcile_candidate(base, candidate, policy)

    assert [entry.path for entry in result.authoritative_manifest.entries] == [b"src/app.py"]
    assert len(result.discarded_changes) == 1
    assert result.discarded_changes[0].new_path == b"build/cache.bin"
    next_round = SubjectManifest.from_json_bytes(result.authoritative_manifest.to_json_bytes())
    assert all(entry.path != b"build/cache.bin" for entry in next_round.entries)


@pytest.mark.parametrize(
    "path",
    [b".codex/settings.toml", b"AGENTS.md", b"nested/AGENTS.override.md"],
)
def test_007_protected_instruction_mutation_fails_before_discard(path: bytes) -> None:
    blobs = MemoryBlobs()
    base = SubjectManifest.empty()
    candidate = scan([(path, b"hostile")], blobs)
    policy = PathPolicy(discard_only_patterns=(b"**",))

    with pytest.raises(AgentLoopError) as caught:
        reconcile_candidate(base, candidate, policy)

    assert caught.value.reason is StopReason.PROTECTED_SUBJECT_PATH_CHANGED
    assert caught.value.exit_code is ExitCode.INTEGRITY_FAILURE


def test_007_explicit_pre_run_opt_in_allows_instruction_path_as_semantic() -> None:
    blobs = MemoryBlobs()
    candidate = scan([(b"AGENTS.md", b"task intentionally changes this")], blobs)
    policy = PathPolicy(protected_opt_in_patterns=(b"AGENTS.md",))

    result = reconcile_candidate(SubjectManifest.empty(), candidate, policy)

    assert result.authoritative_manifest == candidate
    assert len(result.semantic_changes) == 1


@pytest.mark.parametrize(
    "path,protected",
    [
        (b".agent-loop.toml", (b".agent-loop.toml",)),
        (b"scripts/ci/acceptance.py", (b"scripts/ci/**",)),
    ],
)
def test_025_configured_check_definition_or_external_harness_is_protected(
    path: bytes,
    protected: tuple[bytes, ...],
) -> None:
    blobs = MemoryBlobs()
    base = scan([(path, b"assert secure")], blobs)
    candidate = scan([(path, b"pass")], blobs)

    with pytest.raises(AgentLoopError) as caught:
        reconcile_candidate(
            base,
            candidate,
            PathPolicy(protected_patterns=protected),
        )

    assert caught.value.reason is StopReason.PROTECTED_SUBJECT_PATH_CHANGED


def test_012_every_consumer_can_bind_to_one_authoritative_fingerprint() -> None:
    blobs = MemoryBlobs()
    candidate = scan([(b"src/app.py", b"code"), (b"meta/timing", b"123")], blobs)
    policy = PathPolicy(opaque_nonsemantic_patterns=(b"meta/**",))

    result = reconcile_candidate(SubjectManifest.empty(), candidate, policy)
    author_input = result.authoritative_manifest
    validation_input = SubjectManifest.from_json_bytes(author_input.to_json_bytes())
    critic_subject = SubjectManifest.from_json_obj(author_input.to_json_obj())

    assert author_input.fingerprint == validation_input.fingerprint
    assert author_input.fingerprint == critic_subject.fingerprint
    assert len(result.semantic_changes) == 1
    assert len(result.opaque_changes) == 1
    assert result.opaque_changes[0].new_path == b"meta/timing"


def test_discarding_rename_destination_preserves_semantic_source_deletion() -> None:
    blobs = MemoryBlobs()
    base = scan([(b"src/important", b"same")], blobs)
    candidate = scan([(b"cache/important", b"same")], blobs)
    policy = PathPolicy(discard_only_patterns=(b"cache/**",))

    result = reconcile_candidate(base, candidate, policy)

    assert result.authoritative_manifest == SubjectManifest.empty()
    assert len(result.discarded_changes) == 1
    assert len(result.semantic_changes) == 1
    assert result.semantic_changes[0].old_path == b"src/important"
