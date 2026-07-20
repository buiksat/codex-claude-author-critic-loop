"""Canonical subject manifests, policy reconciliation, and blob integration."""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass

from .constants import SUBJECT_SCHEMA_VERSION, Limits
from .errors import StopReason, fail
from .models import (
    BlobReader,
    BlobWriter,
    ChangeKind,
    CompleteScanner,
    EntryKind,
    ManifestChange,
    ManifestEntry,
    PathDisposition,
    PathPolicy,
    ReconciliationResult,
    ScanRecord,
    display_path,
    path_from_b64,
    path_to_b64,
    sha256_hex,
)

_CANONICAL_DOMAIN = b"agent-loop/subject-manifest"
_U64_MAX = (1 << 64) - 1


def _length_prefix(value: bytes) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError("canonical values must be bytes")
    if len(value) > _U64_MAX:
        raise ValueError("canonical value is too large")
    return len(value).to_bytes(8, "big") + value


def _encode_atoms(*atoms: bytes) -> bytes:
    return b"".join(_length_prefix(atom) for atom in atoms)


def _canonical_entry(entry: ManifestEntry) -> bytes:
    common = (
        b"entry",
        entry.path,
        entry.kind.value.encode("ascii"),
        f"{entry.mode:06o}".encode("ascii"),
    )
    if entry.kind is EntryKind.REGULAR:
        assert entry.size is not None
        assert entry.blob_sha256 is not None
        return _encode_atoms(
            *common,
            str(entry.size).encode("ascii"),
            bytes.fromhex(entry.blob_sha256),
        )
    assert entry.symlink_target is not None
    assert entry.target_sha256 is not None
    return _encode_atoms(*common, entry.symlink_target, bytes.fromhex(entry.target_sha256))


def _entry_to_json(entry: ManifestEntry) -> dict[str, object]:
    result: dict[str, object] = {
        "path_b64": entry.path_b64,
        "path_display": entry.display_path,
        "kind": entry.kind.value,
        "mode": f"{entry.mode:06o}",
    }
    if entry.kind is EntryKind.REGULAR:
        result["size"] = entry.size
        result["blob_sha256"] = entry.blob_sha256
    else:
        assert entry.symlink_target is not None
        result["target_b64"] = path_to_b64(entry.symlink_target)
        result["target_sha256"] = entry.target_sha256
    return result


def _require_exact_keys(value: dict[str, object], expected: set[str], context: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise ValueError(f"{context} has missing keys {missing!r} and unknown keys {unknown!r}")


def _entry_from_json(value: object) -> ManifestEntry:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise TypeError("manifest entry must be a JSON object with string keys")
    kind_value = value.get("kind")
    if kind_value == EntryKind.REGULAR.value:
        _require_exact_keys(
            value,
            {"path_b64", "path_display", "kind", "mode", "size", "blob_sha256"},
            "regular manifest entry",
        )
    elif kind_value == EntryKind.SYMLINK.value:
        _require_exact_keys(
            value,
            {
                "path_b64",
                "path_display",
                "kind",
                "mode",
                "target_b64",
                "target_sha256",
            },
            "symlink manifest entry",
        )
    else:
        raise ValueError("manifest entry kind is unsupported")

    path_value = value["path_b64"]
    if not isinstance(path_value, str):
        raise TypeError("path_b64 must be a string")
    path = path_from_b64(path_value)
    if value["path_display"] != display_path(path):
        raise ValueError("path_display does not match path_b64")

    mode_value = value["mode"]
    if not isinstance(mode_value, str) or len(mode_value) != 6:
        raise ValueError("entry mode must be a six-digit octal string")
    try:
        mode = int(mode_value, 8)
    except ValueError as exc:
        raise ValueError("entry mode must be a six-digit octal string") from exc
    if f"{mode:06o}" != mode_value:
        raise ValueError("entry mode is not canonical")

    if kind_value == EntryKind.REGULAR.value:
        size = value["size"]
        digest = value["blob_sha256"]
        if not isinstance(size, int) or isinstance(size, bool):
            raise TypeError("regular entry size must be an integer")
        if not isinstance(digest, str):
            raise TypeError("blob_sha256 must be a string")
        return ManifestEntry(
            path=path,
            kind=EntryKind.REGULAR,
            mode=mode,
            size=size,
            blob_sha256=digest,
        )

    target_value = value["target_b64"]
    target_digest = value["target_sha256"]
    if not isinstance(target_value, str):
        raise TypeError("target_b64 must be a string")
    if not isinstance(target_digest, str):
        raise TypeError("target_sha256 must be a string")
    return ManifestEntry(
        path=path,
        kind=EntryKind.SYMLINK,
        mode=mode,
        symlink_target=path_from_b64(target_value),
        target_sha256=target_digest,
    )


def _strict_json_loads(data: bytes) -> object:
    if not isinstance(data, bytes):
        raise TypeError("manifest JSON must be bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("manifest JSON must be UTF-8") from exc

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise ValueError(f"non-finite JSON number is forbidden: {value}")

    try:
        value: object = json.loads(
            text,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
        return value
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("manifest JSON is malformed") from exc


@dataclass(frozen=True, slots=True)
class SubjectManifest:
    """The sole canonical identity of one normalized subject state."""

    entries: tuple[ManifestEntry, ...]
    schema_version: int = SUBJECT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not isinstance(self.schema_version, int) or isinstance(self.schema_version, bool):
            raise TypeError("subject schema_version must be an integer")
        if self.schema_version != SUBJECT_SCHEMA_VERSION:
            raise ValueError("unsupported subject schema_version")
        if not isinstance(self.entries, tuple):
            raise TypeError("manifest entries must be an immutable tuple")
        if any(not isinstance(entry, ManifestEntry) for entry in self.entries):
            raise TypeError("manifest entries must contain only ManifestEntry values")
        paths = tuple(entry.path for entry in self.entries)
        if paths != tuple(sorted(paths)):
            raise ValueError("manifest entries must be sorted by raw path bytes")
        if len(paths) != len(set(paths)):
            raise ValueError("manifest paths must be unique")
        seen: set[bytes] = set()
        for path in paths:
            parts = path.split(b"/")
            for end in range(1, len(parts)):
                if b"/".join(parts[:end]) in seen:
                    raise ValueError("a manifest file or symlink cannot contain another entry")
            seen.add(path)

    @classmethod
    def empty(cls) -> SubjectManifest:
        return cls(entries=())

    @classmethod
    def build(
        cls,
        entries: Iterable[ManifestEntry],
        *,
        limits: Limits | None = None,
    ) -> SubjectManifest:
        materialized = tuple(entries)
        manifest = cls(entries=tuple(sorted(materialized, key=lambda entry: entry.path)))
        manifest.validate_limits(limits or Limits())
        return manifest

    def validate_limits(self, limits: Limits) -> None:
        if not isinstance(limits, Limits):
            raise TypeError("limits must be a Limits instance")
        if len(self.entries) > limits.max_files:
            raise ValueError("manifest exceeds max_files")
        total_bytes = 0
        for entry in self.entries:
            if len(entry.path) > limits.max_path_bytes:
                raise ValueError(f"manifest path exceeds max_path_bytes: {entry.display_path}")
            if len(entry.path.split(b"/")) > limits.max_path_depth:
                raise ValueError(f"manifest path exceeds max_path_depth: {entry.display_path}")
            if entry.kind is EntryKind.REGULAR:
                assert entry.size is not None
                if entry.size > limits.max_file_bytes:
                    raise ValueError(f"regular file exceeds max_file_bytes: {entry.display_path}")
                total_bytes += entry.size
            else:
                assert entry.symlink_target is not None
                if len(entry.symlink_target) > limits.max_path_bytes:
                    raise ValueError(f"symlink target exceeds max_path_bytes: {entry.display_path}")
                total_bytes += len(entry.symlink_target)
            if total_bytes > limits.max_total_subject_bytes:
                raise ValueError("manifest exceeds max_total_subject_bytes")

    def canonical_bytes(self) -> bytes:
        header = _encode_atoms(
            _CANONICAL_DOMAIN,
            str(self.schema_version).encode("ascii"),
            str(len(self.entries)).encode("ascii"),
        )
        return header + b"".join(_canonical_entry(entry) for entry in self.entries)

    @property
    def fingerprint(self) -> str:
        return sha256_hex(self.canonical_bytes())

    def to_json_obj(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "fingerprint": self.fingerprint,
            "entries": [_entry_to_json(entry) for entry in self.entries],
        }

    def to_json_bytes(self) -> bytes:
        encoded = json.dumps(
            self.to_json_obj(),
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return encoded.encode("ascii") + b"\n"

    @classmethod
    def from_json_obj(
        cls,
        value: object,
        *,
        limits: Limits | None = None,
    ) -> SubjectManifest:
        if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
            raise TypeError("subject manifest must be a JSON object with string keys")
        _require_exact_keys(value, {"schema_version", "fingerprint", "entries"}, "manifest")
        schema_version = value["schema_version"]
        if not isinstance(schema_version, int) or isinstance(schema_version, bool):
            raise TypeError("manifest schema_version must be an integer")
        if schema_version != SUBJECT_SCHEMA_VERSION:
            raise ValueError("unsupported manifest schema_version")
        raw_entries = value["entries"]
        if not isinstance(raw_entries, list):
            raise TypeError("manifest entries must be an array")
        entries = tuple(_entry_from_json(entry) for entry in raw_entries)
        if tuple(entry.path for entry in entries) != tuple(sorted(entry.path for entry in entries)):
            raise ValueError("JSON manifest entries must be sorted by raw path bytes")
        manifest = cls(entries=entries, schema_version=schema_version)
        manifest.validate_limits(limits or Limits())
        fingerprint = value["fingerprint"]
        if not isinstance(fingerprint, str):
            raise TypeError("manifest fingerprint must be a string")
        if fingerprint != manifest.fingerprint:
            raise ValueError("manifest fingerprint does not match canonical entries")
        return manifest

    @classmethod
    def from_json_bytes(
        cls,
        data: bytes,
        *,
        limits: Limits | None = None,
    ) -> SubjectManifest:
        return cls.from_json_obj(_strict_json_loads(data), limits=limits)


def build_manifest_from_scan(
    records: Iterable[ScanRecord],
    blobs: BlobWriter,
    *,
    limits: Limits | None = None,
) -> SubjectManifest:
    """Build from every safe scan record; ignore rules are intentionally absent."""

    selected_limits = limits or Limits()
    if not isinstance(blobs, BlobWriter):
        raise TypeError("blobs must implement BlobWriter")
    materialized: list[ScanRecord] = []
    total_bytes = 0
    for record in records:
        if not isinstance(record, ScanRecord):
            raise TypeError("scanner emitted a non-ScanRecord value")
        materialized.append(record)
        if len(materialized) > selected_limits.max_files:
            raise ValueError("scan exceeds max_files")
        if len(record.path) > selected_limits.max_path_bytes:
            raise ValueError(f"scanned path exceeds max_path_bytes: {display_path(record.path)}")
        if len(record.path.split(b"/")) > selected_limits.max_path_depth:
            raise ValueError(f"scanned path exceeds max_path_depth: {display_path(record.path)}")
        if len(record.payload) > selected_limits.max_file_bytes:
            raise ValueError(f"scanned payload exceeds max_file_bytes: {display_path(record.path)}")
        total_bytes += len(record.payload)
        if total_bytes > selected_limits.max_total_subject_bytes:
            raise ValueError("scan exceeds max_total_subject_bytes")

    entries: list[ManifestEntry] = []
    for record in materialized:
        if record.kind is EntryKind.REGULAR:
            expected = sha256_hex(record.payload)
            observed = blobs.put_blob(record.payload)
            if observed != expected:
                raise ValueError("blob writer returned an identity that does not match its bytes")
            entries.append(
                ManifestEntry(
                    path=record.path,
                    kind=EntryKind.REGULAR,
                    mode=record.mode,
                    size=len(record.payload),
                    blob_sha256=expected,
                )
            )
        else:
            entries.append(ManifestEntry.symlink(record.path, target=record.payload))
    return SubjectManifest.build(entries, limits=selected_limits)


def build_manifest_from_scanner(
    scanner: CompleteScanner,
    blobs: BlobWriter,
    *,
    limits: Limits | None = None,
) -> SubjectManifest:
    if not isinstance(scanner, CompleteScanner):
        raise TypeError("scanner must implement CompleteScanner")
    return build_manifest_from_scan(scanner.scan_records(), blobs, limits=limits)


def verify_manifest_blobs(manifest: SubjectManifest, blobs: BlobReader) -> None:
    """Verify every referenced regular blob before materialization or rendering."""

    if not isinstance(manifest, SubjectManifest):
        raise TypeError("manifest must be a SubjectManifest")
    if not isinstance(blobs, BlobReader):
        raise TypeError("blobs must implement BlobReader")
    for entry in manifest.entries:
        if entry.kind is EntryKind.SYMLINK:
            continue
        assert entry.blob_sha256 is not None
        assert entry.size is not None
        data = blobs.read_blob(entry.blob_sha256)
        if not isinstance(data, bytes):
            raise TypeError("blob reader returned non-bytes content")
        if len(data) != entry.size:
            raise ValueError(f"blob size mismatch for {entry.display_path}")
        if sha256_hex(data) != entry.blob_sha256:
            raise ValueError(f"blob hash mismatch for {entry.display_path}")


def _change_sort_key(change: ManifestChange) -> tuple[bytes, int, bytes]:
    kind_order = {
        ChangeKind.DELETE: 0,
        ChangeKind.RENAME: 1,
        ChangeKind.MODIFY: 2,
        ChangeKind.CREATE: 3,
    }
    if change.after is not None:
        anchor = change.after.path
    else:
        assert change.before is not None
        anchor = change.before.path
    old_path = b"" if change.before is None else change.before.path
    return (anchor, kind_order[change.kind], old_path)


def diff_manifests(
    base: SubjectManifest,
    candidate: SubjectManifest,
) -> tuple[ManifestChange, ...]:
    """Return a deterministic exact delta, including exact-identity renames."""

    if not isinstance(base, SubjectManifest) or not isinstance(candidate, SubjectManifest):
        raise TypeError("base and candidate must be SubjectManifest values")
    base_by_path = {entry.path: entry for entry in base.entries}
    candidate_by_path = {entry.path: entry for entry in candidate.entries}

    changes: list[ManifestChange] = []
    shared_paths = sorted(base_by_path.keys() & candidate_by_path.keys())
    for path in shared_paths:
        before = base_by_path[path]
        after = candidate_by_path[path]
        if before != after:
            changes.append(ManifestChange(ChangeKind.MODIFY, before, after))

    removed = [base_by_path[path] for path in sorted(base_by_path.keys() - candidate_by_path)]
    added = [candidate_by_path[path] for path in sorted(candidate_by_path.keys() - base_by_path)]
    added_by_identity: dict[tuple[object, ...], list[ManifestEntry]] = {}
    for entry in added:
        added_by_identity.setdefault(entry.identity_without_path(), []).append(entry)

    paired_added_paths: set[bytes] = set()
    unpaired_removed: list[ManifestEntry] = []
    for before in removed:
        matching = added_by_identity.get(before.identity_without_path(), [])
        if matching:
            after = matching.pop(0)
            paired_added_paths.add(after.path)
            changes.append(ManifestChange(ChangeKind.RENAME, before, after))
        else:
            unpaired_removed.append(before)

    changes.extend(ManifestChange(ChangeKind.DELETE, entry, None) for entry in unpaired_removed)
    changes.extend(
        ManifestChange(ChangeKind.CREATE, None, entry)
        for entry in added
        if entry.path not in paired_added_paths
    )
    return tuple(sorted(changes, key=_change_sort_key))


def reconcile_candidate(
    base: SubjectManifest,
    candidate: SubjectManifest,
    policy: PathPolicy,
    *,
    limits: Limits | None = None,
) -> ReconciliationResult:
    """Apply frozen protection, discard, and semantic-completeness policy."""

    if not isinstance(policy, PathPolicy):
        raise TypeError("policy must be a PathPolicy")
    candidate_delta = diff_manifests(base, candidate)

    # Protection is checked against the unfiltered candidate delta.  A path may
    # never evade protection by also matching a discard or opaque pattern.
    for change in candidate_delta:
        protected = [
            path for path in change.paths if policy.classify(path) is PathDisposition.PROTECTED
        ]
        if protected:
            rendered = ", ".join(display_path(path) for path in protected)
            raise fail(
                StopReason.PROTECTED_SUBJECT_PATH_CHANGED,
                f"candidate changed protected subject path(s): {rendered}",
            )

    authoritative_entries = tuple(
        entry
        for entry in candidate.entries
        if policy.classify(entry.path) is not PathDisposition.DISCARD_ONLY
    )
    authoritative = SubjectManifest.build(authoritative_entries, limits=limits or Limits())
    authoritative_delta = diff_manifests(base, authoritative)

    semantic: list[ManifestChange] = []
    opaque: list[ManifestChange] = []
    for change in authoritative_delta:
        disposition = policy.classify_change(change)
        if disposition is PathDisposition.OPAQUE_NONSEMANTIC:
            opaque.append(change)
        elif disposition is PathDisposition.SEMANTIC:
            semantic.append(change)

    discarded = tuple(
        change
        for change in candidate_delta
        if any(
            policy.classify(path) is PathDisposition.DISCARD_ONLY for path in change.paths
        )
    )
    return ReconciliationResult(
        candidate_delta=candidate_delta,
        authoritative_manifest=authoritative,
        authoritative_delta=authoritative_delta,
        semantic_changes=tuple(semantic),
        opaque_changes=tuple(opaque),
        discarded_changes=discarded,
    )


__all__ = [
    "SubjectManifest",
    "build_manifest_from_scan",
    "build_manifest_from_scanner",
    "diff_manifests",
    "reconcile_candidate",
    "verify_manifest_blobs",
]
