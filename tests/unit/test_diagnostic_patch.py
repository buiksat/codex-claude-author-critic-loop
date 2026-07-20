from __future__ import annotations

import json

import pytest

from agent_loop.diagnostic_patch import render_diagnostic_patch
from agent_loop.errors import AgentLoopError, ExitCode, StopReason
from agent_loop.manifests import SubjectManifest
from agent_loop.models import ManifestEntry, sha256_hex


class MemoryBlobs:
    def __init__(self) -> None:
        self.values: dict[str, bytes] = {}

    def add(self, data: bytes) -> str:
        digest = sha256_hex(data)
        self.values[digest] = data
        return digest

    def read_blob(self, sha256: str) -> bytes:
        return self.values[sha256]


def regular(
    blobs: MemoryBlobs,
    path: bytes,
    data: bytes,
    *,
    executable: bool = False,
) -> ManifestEntry:
    return ManifestEntry.regular(
        path,
        size=len(data),
        blob_sha256=blobs.add(data),
        executable=executable,
    )


def decode_lines(rendered: bytes) -> list[dict[str, object]]:
    return [json.loads(line) for line in rendered.splitlines()]


def test_070_projection_exactly_covers_all_manifest_change_shapes_and_hashes() -> None:
    blobs = MemoryBlobs()
    base = SubjectManifest.build(
        [
            regular(blobs, b"delete", b"deleted text\n"),
            regular(blobs, b"modify", b"old text\n"),
            regular(blobs, b"mode", b"same bytes"),
            regular(blobs, b"old-name", b"rename bytes"),
            ManifestEntry.symlink(b"link", target=b"old-target"),
        ]
    )
    candidate = SubjectManifest.build(
        [
            regular(blobs, b"binary", b"\x00\xff"),
            regular(blobs, b"modify", b"new text\n"),
            regular(blobs, b"mode", b"same bytes", executable=True),
            regular(blobs, b"new-name", b"rename bytes"),
            ManifestEntry.symlink(b"link", target=b"new-target"),
        ]
    )

    rendered = render_diagnostic_patch(base, candidate, blobs)
    lines = decode_lines(rendered)
    header = lines[0]
    records = lines[1:]

    assert header == {
        "format": "agent-loop-diagnostic-patch",
        "version": 1,
        "base_fingerprint": base.fingerprint,
        "candidate_fingerprint": candidate.fingerprint,
        "change_count": 6,
    }
    assert {record["operation"] for record in records} == {
        "create",
        "delete",
        "modify",
        "rename-equivalent",
    }
    aspects = [record["aspects"] for record in records]
    assert all(isinstance(value, list) for value in aspects)
    assert any(isinstance(value, list) and "binary" in value for value in aspects)
    assert any(isinstance(value, list) and "content" in value for value in aspects)
    assert any(isinstance(value, list) and "symlink" in value for value in aspects)
    assert any(isinstance(value, list) and "executable-mode" in value for value in aspects)
    assert any(isinstance(value, list) and "rename-equivalent" in value for value in aspects)

    expected_hashes = {
        entry.content_sha256 for entry in (*base.entries, *candidate.entries)
    }
    projected_hashes: set[str] = set()
    for record in records:
        for side_name in ("before", "after"):
            side = record[side_name]
            if not isinstance(side, dict):
                continue
            digest = side.get("blob_sha256", side.get("target_sha256"))
            assert isinstance(digest, str)
            projected_hashes.add(digest)
    assert projected_hashes == expected_hashes


def test_047_projection_uses_lossless_identity_and_safe_display_for_arbitrary_paths() -> None:
    blobs = MemoryBlobs()
    candidate = SubjectManifest.build([regular(blobs, b"line\n\xff", b"value")])

    record = decode_lines(
        render_diagnostic_patch(SubjectManifest.empty(), candidate, blobs)
    )[1]
    after = record["after"]

    assert isinstance(after, dict)
    assert after["path_b64"] == "bGluZQr/"
    assert after["path_display"] == r"line\n\xff"
    assert "\n" not in after["path_display"]


def test_projection_is_deterministic_and_newline_terminated() -> None:
    blobs = MemoryBlobs()
    base = SubjectManifest.build([regular(blobs, b"a", b"old")])
    candidate = SubjectManifest.build([regular(blobs, b"a", b"new")])

    first = render_diagnostic_patch(base, candidate, blobs)
    second = render_diagnostic_patch(base, candidate, blobs)

    assert first == second
    assert first.endswith(b"\n")


def test_projection_fails_closed_at_byte_bound() -> None:
    blobs = MemoryBlobs()
    candidate = SubjectManifest.build([regular(blobs, b"a", b"content")])

    with pytest.raises(AgentLoopError) as caught:
        render_diagnostic_patch(SubjectManifest.empty(), candidate, blobs, max_bytes=1)

    assert caught.value.reason is StopReason.DIAGNOSTIC_PATCH_FAILURE
    assert caught.value.exit_code is ExitCode.INTEGRITY_FAILURE


def test_projection_fails_closed_when_blob_does_not_match_manifest() -> None:
    blobs = MemoryBlobs()
    entry = regular(blobs, b"a", b"content")
    manifest = SubjectManifest.build([entry])
    assert entry.blob_sha256 is not None
    blobs.values[entry.blob_sha256] = b"tampered"

    with pytest.raises(AgentLoopError) as caught:
        render_diagnostic_patch(SubjectManifest.empty(), manifest, blobs)

    assert caught.value.reason is StopReason.DIAGNOSTIC_PATCH_FAILURE


def test_symlink_projection_contains_literal_target_not_target_contents() -> None:
    blobs = MemoryBlobs()
    candidate = SubjectManifest.build(
        [ManifestEntry.symlink(b"secret-link", target=b"/host/secret")]
    )

    rendered = render_diagnostic_patch(SubjectManifest.empty(), candidate, blobs)
    record = decode_lines(rendered)[1]
    after = record["after"]

    assert isinstance(after, dict)
    assert after["target_b64"] == "L2hvc3Qvc2VjcmV0"
    assert b"secret-value" not in rendered
