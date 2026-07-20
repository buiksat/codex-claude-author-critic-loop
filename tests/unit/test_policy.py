from __future__ import annotations

from typing import cast

import pytest

from agent_loop.manifests import SubjectManifest, diff_manifests
from agent_loop.models import ManifestEntry, PathDisposition, PathPolicy, sha256_hex


def regular(path: bytes, data: bytes = b"x") -> ManifestEntry:
    return ManifestEntry.regular(path, size=len(data), blob_sha256=sha256_hex(data))


@pytest.mark.parametrize(
    "path",
    [
        b".git",
        b".git/config",
        b".codex/settings.toml",
        b"AGENTS.md",
        b"AGENTS.override.md",
        b"nested/AGENTS.md",
        b"deep/path/AGENTS.override.md",
    ],
)
def test_007_default_instruction_and_git_paths_are_protected(path: bytes) -> None:
    assert PathPolicy().classify(path) is PathDisposition.PROTECTED


def test_component_globs_do_not_let_single_star_cross_directories() -> None:
    policy = PathPolicy(protected_patterns=(b"generated/*.txt",))

    assert policy.classify(b"generated/a.txt") is PathDisposition.PROTECTED
    assert policy.classify(b"generated/deep/a.txt") is PathDisposition.SEMANTIC


def test_double_star_matches_zero_or_more_components() -> None:
    policy = PathPolicy(protected_patterns=(b"**/secret",))

    assert policy.classify(b"secret") is PathDisposition.PROTECTED
    assert policy.classify(b"a/b/secret") is PathDisposition.PROTECTED


def test_recursive_glob_matching_has_a_bounded_dynamic_program() -> None:
    pattern = b"/".join([b"**", b"x"] * 64)
    path = b"/".join([b"x"] * 64)

    policy = PathPolicy(protected_patterns=(pattern,))

    assert policy.classify(path) is PathDisposition.PROTECTED


def test_007_protected_precedes_discard_and_opaque() -> None:
    policy = PathPolicy(
        protected_patterns=(b"control/**",),
        discard_only_patterns=(b"control/**",),
        opaque_nonsemantic_patterns=(b"control/**",),
    )

    assert policy.classify(b"control/config") is PathDisposition.PROTECTED


def test_predeclared_protected_opt_in_exposes_later_policy_classification() -> None:
    policy = PathPolicy(
        protected_patterns=(b".codex/**",),
        discard_only_patterns=(b".codex/cache/**",),
        protected_opt_in_patterns=(b".codex/cache/**",),
    )

    assert policy.classify(b".codex/config.toml") is PathDisposition.PROTECTED
    assert policy.classify(b".codex/cache/output") is PathDisposition.DISCARD_ONLY


def test_git_control_paths_cannot_be_opted_back_into_the_subject() -> None:
    policy = PathPolicy(
        protected_opt_in_patterns=(b".git/**", b"nested/.git/**"),
    )

    assert policy.classify(b".git/config") is PathDisposition.PROTECTED
    assert policy.classify(b"nested/.git/config") is PathDisposition.PROTECTED


def test_semantic_is_default_and_opaque_is_authoritative_classification() -> None:
    policy = PathPolicy(
        protected_patterns=(),
        opaque_nonsemantic_patterns=(b"metadata/**",),
    )

    assert policy.classify(b"src/main.py") is PathDisposition.SEMANTIC
    assert policy.classify(b"metadata/timing") is PathDisposition.OPAQUE_NONSEMANTIC


def test_cross_boundary_rename_stays_semantic() -> None:
    base = SubjectManifest.build([regular(b"src/old")])
    candidate = SubjectManifest.build([regular(b"opaque/new")])
    change = diff_manifests(base, candidate)[0]
    policy = PathPolicy(protected_patterns=(), opaque_nonsemantic_patterns=(b"opaque/**",))

    assert policy.classify_change(change) is PathDisposition.SEMANTIC


@pytest.mark.parametrize("pattern", [b"", b"/absolute", b"a//b", b"a/../b", b"nul\0x"])
def test_path_policy_rejects_ambiguous_patterns(pattern: bytes) -> None:
    with pytest.raises(ValueError):
        PathPolicy(protected_patterns=(pattern,))


def test_path_policy_is_strictly_immutable() -> None:
    with pytest.raises(TypeError, match="tuples"):
        PathPolicy(protected_patterns=cast(tuple[bytes, ...], [b"x"]))
    with pytest.raises(ValueError, match="duplicates"):
        PathPolicy(protected_patterns=(b"x", b"x"))
    with pytest.raises(ValueError, match="collection exceeds"):
        PathPolicy(protected_patterns=tuple(f"path/{index}".encode() for index in range(257)))
