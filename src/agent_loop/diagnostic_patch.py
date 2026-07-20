"""Bounded manifest-native diagnostic projection.

The JSONL produced here is intentionally a human diagnostic, never an
authoritative state-discovery input.  Every record carries the canonical entry
hashes needed to compare it with its source manifests.
"""

from __future__ import annotations

import json

from .constants import MAX_BUNDLE_BYTES
from .errors import StopReason, fail
from .manifests import SubjectManifest, diff_manifests, verify_manifest_blobs
from .models import BlobReader, ChangeKind, EntryKind, ManifestChange, ManifestEntry, path_to_b64


def _entry_descriptor(entry: ManifestEntry) -> dict[str, object]:
    descriptor: dict[str, object] = {
        "path_b64": entry.path_b64,
        "path_display": entry.display_path,
        "kind": entry.kind.value,
        "mode": f"{entry.mode:06o}",
    }
    if entry.kind is EntryKind.REGULAR:
        descriptor["size"] = entry.size
        descriptor["blob_sha256"] = entry.blob_sha256
    else:
        assert entry.symlink_target is not None
        descriptor["target_b64"] = path_to_b64(entry.symlink_target)
        descriptor["target_sha256"] = entry.target_sha256
    return descriptor


def _is_binary(data: bytes) -> bool:
    if b"\x00" in data:
        return True
    try:
        data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return True
    return False


def _regular_bytes(entry: ManifestEntry, blobs: BlobReader) -> bytes:
    assert entry.kind is EntryKind.REGULAR
    assert entry.blob_sha256 is not None
    return blobs.read_blob(entry.blob_sha256)


def _change_aspects(change: ManifestChange, blobs: BlobReader) -> list[str]:
    aspects: list[str] = []
    before = change.before
    after = change.after
    entries = tuple(entry for entry in (before, after) if entry is not None)

    if change.kind is ChangeKind.RENAME:
        aspects.append("rename-equivalent")

    if any(entry.kind is EntryKind.SYMLINK for entry in entries):
        aspects.append("symlink")

    regular_entries = tuple(entry for entry in entries if entry.kind is EntryKind.REGULAR)
    content_changed = (
        change.kind in {ChangeKind.CREATE, ChangeKind.DELETE}
        or before is None
        or after is None
        or before.kind is not after.kind
        or before.content_sha256 != after.content_sha256
    )
    if regular_entries and content_changed:
        binary = any(_is_binary(_regular_bytes(entry, blobs)) for entry in regular_entries)
        aspects.append("binary" if binary else "content")

    before_executable = before.executable if before is not None else False
    after_executable = after.executable if after is not None else False
    if before_executable != after_executable:
        aspects.append("executable-mode")

    if not aspects:
        # A same-path modification always changes some canonical field.  This
        # fallback covers representation transitions without inventing a diff.
        aspects.append("metadata")
    return aspects


def _record(change: ManifestChange, blobs: BlobReader) -> dict[str, object]:
    return {
        "operation": change.kind.value,
        "aspects": _change_aspects(change, blobs),
        "before": None if change.before is None else _entry_descriptor(change.before),
        "after": None if change.after is None else _entry_descriptor(change.after),
    }


def _json_line(value: dict[str, object]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )


def render_diagnostic_patch(
    base: SubjectManifest,
    candidate: SubjectManifest,
    blobs: BlobReader,
    *,
    max_bytes: int = MAX_BUNDLE_BYTES,
) -> bytes:
    """Render a deterministic, bounded JSONL projection of a canonical delta."""

    if not isinstance(base, SubjectManifest) or not isinstance(candidate, SubjectManifest):
        raise TypeError("base and candidate must be SubjectManifest values")
    if not isinstance(blobs, BlobReader):
        raise TypeError("blobs must implement BlobReader")
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    if max_bytes > MAX_BUNDLE_BYTES:
        raise ValueError("diagnostic patch max_bytes exceeds the frozen 8 MiB ceiling")

    try:
        verify_manifest_blobs(base, blobs)
        verify_manifest_blobs(candidate, blobs)
    except (KeyError, OSError, TypeError, ValueError) as exc:
        raise fail(StopReason.DIAGNOSTIC_PATCH_FAILURE, f"blob verification failed: {exc}") from exc

    changes = diff_manifests(base, candidate)
    lines = [
        _json_line(
            {
                "format": "agent-loop-diagnostic-patch",
                "version": 1,
                "base_fingerprint": base.fingerprint,
                "candidate_fingerprint": candidate.fingerprint,
                "change_count": len(changes),
            }
        )
    ]
    size = len(lines[0])
    if size > max_bytes:
        raise fail(StopReason.DIAGNOSTIC_PATCH_FAILURE, "diagnostic patch exceeds max_bytes")

    for change in changes:
        try:
            line = _json_line(_record(change, blobs))
        except (KeyError, OSError, TypeError, ValueError) as exc:
            raise fail(
                StopReason.DIAGNOSTIC_PATCH_FAILURE,
                f"could not project canonical change: {exc}",
            ) from exc
        size += len(line)
        if size > max_bytes:
            raise fail(StopReason.DIAGNOSTIC_PATCH_FAILURE, "diagnostic patch exceeds max_bytes")
        lines.append(line)
    return b"".join(lines)


__all__ = ["render_diagnostic_patch"]
