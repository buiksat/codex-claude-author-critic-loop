from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from typing import cast

import pytest

from agent_loop.constants import EXECUTABLE_MODE, REGULAR_MODE, SYMLINK_MODE, Limits
from agent_loop.manifests import (
    SubjectManifest,
    build_manifest_from_scan,
    build_manifest_from_scanner,
    diff_manifests,
    verify_manifest_blobs,
)
from agent_loop.models import ChangeKind, EntryKind, ManifestEntry, ScanRecord, sha256_hex


class MemoryBlobs:
    def __init__(self) -> None:
        self.values: dict[str, bytes] = {}

    def put_blob(self, data: bytes) -> str:
        digest = sha256_hex(data)
        self.values[digest] = data
        return digest

    def read_blob(self, sha256: str) -> bytes:
        return self.values[sha256]


class StaticScanner:
    def __init__(self, records: tuple[ScanRecord, ...]) -> None:
        self.records = records

    def scan_records(self) -> tuple[ScanRecord, ...]:
        return self.records


def regular(path: bytes, data: bytes, *, executable: bool = False) -> ManifestEntry:
    return ManifestEntry.regular(
        path,
        size=len(data),
        blob_sha256=sha256_hex(data),
        executable=executable,
    )


def test_047_arbitrary_path_bytes_round_trip_losslessly() -> None:
    entry = regular(b"line\n/non-utf8-\xff", b"content")
    manifest = SubjectManifest.build([entry])

    decoded = SubjectManifest.from_json_bytes(manifest.to_json_bytes())

    assert decoded == manifest
    assert decoded.entries[0].path == b"line\n/non-utf8-\xff"
    assert decoded.entries[0].display_path == r"line\n/non-utf8-\xff"
    assert decoded.fingerprint == manifest.fingerprint


def test_manifest_entries_are_immutable_and_require_raw_bytes() -> None:
    entry = regular(b"file", b"value")
    with pytest.raises(FrozenInstanceError):
        setattr(entry, "path", b"changed")
    with pytest.raises(TypeError, match="bytes"):
        ManifestEntry.regular(
            cast(bytes, "file"), size=1, blob_sha256=sha256_hex(b"x")
        )


@pytest.mark.parametrize("path", [b"", b"/absolute", b"a//b", b"a/./b", b"a/../b", b"nul\0x"])
def test_manifest_rejects_unsafe_or_ambiguous_paths(path: bytes) -> None:
    with pytest.raises(ValueError):
        regular(path, b"x")


def test_manifest_rejects_duplicate_and_file_prefix_paths() -> None:
    duplicate = regular(b"same", b"x")
    with pytest.raises(ValueError, match="unique"):
        SubjectManifest.build([duplicate, duplicate])
    with pytest.raises(ValueError, match="cannot contain"):
        SubjectManifest.build([regular(b"a", b"x"), regular(b"a/b", b"y")])


def test_canonical_fingerprint_is_order_independent_but_content_and_mode_sensitive() -> None:
    first = regular(b"a", b"one")
    second = ManifestEntry.symlink(b"z", target=b"../target")
    left = SubjectManifest.build([second, first])
    right = SubjectManifest.build([first, second])
    changed_content = SubjectManifest.build([regular(b"a", b"two"), second])
    changed_mode = SubjectManifest.build([regular(b"a", b"one", executable=True), second])

    assert left.entries == (first, second)
    assert left.canonical_bytes() == right.canonical_bytes()
    assert left.fingerprint == right.fingerprint
    assert left.fingerprint != changed_content.fingerprint
    assert left.fingerprint != changed_mode.fingerprint
    assert len(left.fingerprint) == 64


def test_canonical_encoding_length_prefixes_raw_fields() -> None:
    path = b"a\n\xff"
    manifest = SubjectManifest.build([regular(path, b"payload")])
    canonical = manifest.canonical_bytes()

    assert len(path).to_bytes(8, "big") + path in canonical
    assert len(b"regular").to_bytes(8, "big") + b"regular" in canonical
    assert len(b"100644").to_bytes(8, "big") + b"100644" in canonical


def test_json_parser_rejects_tampering_unknown_fields_duplicates_and_noncanonical_order() -> None:
    manifest = SubjectManifest.build([regular(b"a", b"a"), regular(b"b", b"b")])
    value = manifest.to_json_obj()

    tampered = dict(value)
    tampered["fingerprint"] = "0" * 64
    with pytest.raises(ValueError, match="fingerprint"):
        SubjectManifest.from_json_obj(tampered)

    unknown = dict(value)
    unknown["surprise"] = True
    with pytest.raises(ValueError, match="unknown"):
        SubjectManifest.from_json_obj(unknown)

    reversed_value = dict(value)
    raw_entries = value["entries"]
    assert isinstance(raw_entries, list)
    reversed_value["entries"] = list(reversed(raw_entries))
    with pytest.raises(ValueError, match="sorted"):
        SubjectManifest.from_json_obj(reversed_value)

    raw = manifest.to_json_bytes().decode("ascii").rstrip()
    duplicate = raw[:-1] + ',"schema_version":1}'
    with pytest.raises(ValueError, match="duplicate"):
        SubjectManifest.from_json_bytes(duplicate.encode("ascii"))


def test_json_parser_rejects_display_alias_and_noncanonical_base64() -> None:
    manifest = SubjectManifest.build([regular(b"a", b"x")])
    value = manifest.to_json_obj()
    entries = value["entries"]
    assert isinstance(entries, list)
    entry = dict(entries[0])
    entry["path_display"] = "not-a"
    value["entries"] = [entry]
    with pytest.raises(ValueError, match="path_display"):
        SubjectManifest.from_json_obj(value)

    entry["path_display"] = "a"
    entry["path_b64"] = "YQ==\n"
    with pytest.raises(ValueError, match="base64"):
        SubjectManifest.from_json_obj(value)


def test_manifest_limits_are_enforced_before_blob_writes() -> None:
    blobs = MemoryBlobs()
    limits = Limits(max_files=1, max_file_bytes=1, max_total_subject_bytes=1)
    records = [
        ScanRecord(b"a", EntryKind.REGULAR, REGULAR_MODE, b"x"),
        ScanRecord(b"b", EntryKind.REGULAR, REGULAR_MODE, b"y"),
    ]

    with pytest.raises(ValueError, match="max_files"):
        build_manifest_from_scan(records, blobs, limits=limits)
    assert blobs.values == {}


def test_scan_to_manifest_writes_and_verifies_regular_blobs_but_embeds_symlink_target() -> None:
    blobs = MemoryBlobs()
    records = (
        ScanRecord(b"exec", EntryKind.REGULAR, EXECUTABLE_MODE, b"#!/bin/sh\n"),
        ScanRecord(b"link", EntryKind.SYMLINK, SYMLINK_MODE, b"exec"),
    )

    manifest = build_manifest_from_scanner(StaticScanner(records), blobs)
    verify_manifest_blobs(manifest, blobs)

    assert len(blobs.values) == 1
    assert manifest.entries[0].executable
    assert manifest.entries[1].symlink_target == b"exec"


def test_blob_writer_identity_and_reader_bytes_are_verified() -> None:
    class LyingWriter:
        def put_blob(self, data: bytes) -> str:
            return "0" * 64

    with pytest.raises(ValueError, match="identity"):
        build_manifest_from_scan(
            [ScanRecord(b"a", EntryKind.REGULAR, REGULAR_MODE, b"x")],
            LyingWriter(),
        )

    blobs = MemoryBlobs()
    manifest = build_manifest_from_scan(
        [ScanRecord(b"a", EntryKind.REGULAR, REGULAR_MODE, b"x")], blobs
    )
    digest = manifest.entries[0].blob_sha256
    assert digest is not None
    blobs.values[digest] = b"tampered"
    with pytest.raises(ValueError, match="size mismatch"):
        verify_manifest_blobs(manifest, blobs)


def test_041_delta_covers_create_delete_modify_rename_binary_mode_symlink_and_ignored() -> None:
    base = SubjectManifest.build(
        [
            regular(b".gitignore", b"*.ignored\n"),
            regular(b"binary", b"\x00old\xff"),
            regular(b"delete", b"gone"),
            regular(b"modify", b"old"),
            regular(b"mode", b"same"),
            regular(b"old-name", b"renamed"),
            ManifestEntry.symlink(b"link", target=b"old-target"),
        ]
    )
    candidate = SubjectManifest.build(
        [
            regular(b".gitignore", b"*.ignored\n"),
            regular(b"binary", b"\x00new\xff"),
            regular(b"create", b"new"),
            regular(b"generated.ignored", b"still-authoritative"),
            regular(b"modify", b"new"),
            regular(b"mode", b"same", executable=True),
            regular(b"new-name", b"renamed"),
            ManifestEntry.symlink(b"link", target=b"new-target"),
        ]
    )

    changes = diff_manifests(base, candidate)
    by_kind: dict[ChangeKind, list[tuple[bytes | None, bytes | None]]] = {}
    for change in changes:
        by_kind.setdefault(change.kind, []).append((change.old_path, change.new_path))

    assert by_kind[ChangeKind.CREATE] == [
        (None, b"create"),
        (None, b"generated.ignored"),
    ]
    assert by_kind[ChangeKind.DELETE] == [(b"delete", None)]
    assert by_kind[ChangeKind.RENAME] == [(b"old-name", b"new-name")]
    assert set(by_kind[ChangeKind.MODIFY]) == {
        (b"binary", b"binary"),
        (b"link", b"link"),
        (b"mode", b"mode"),
        (b"modify", b"modify"),
    }


def test_041_rename_pairing_is_deterministic_with_duplicate_content() -> None:
    base = SubjectManifest.build([regular(b"old-a", b"x"), regular(b"old-b", b"x")])
    candidate = SubjectManifest.build([regular(b"new-a", b"x"), regular(b"new-b", b"x")])

    changes = diff_manifests(base, candidate)

    assert [(change.old_path, change.new_path) for change in changes] == [
        (b"old-a", b"new-a"),
        (b"old-b", b"new-b"),
    ]


def test_symlink_hash_must_match_literal_target() -> None:
    with pytest.raises(ValueError, match="does not match"):
        ManifestEntry(
            path=b"link",
            kind=EntryKind.SYMLINK,
            mode=SYMLINK_MODE,
            symlink_target=b"literal",
            target_sha256="0" * 64,
        )


def test_manifest_json_is_deterministic_ascii_json() -> None:
    manifest = SubjectManifest.build([regular(b"\xff", b"x")])
    encoded = manifest.to_json_bytes()

    assert encoded.endswith(b"\n")
    assert encoded == manifest.to_json_bytes()
    parsed = json.loads(encoded)
    assert parsed["fingerprint"] == manifest.fingerprint
