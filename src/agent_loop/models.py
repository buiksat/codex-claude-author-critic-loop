"""Immutable domain models for the canonical subject runtime.

Paths remain bytes throughout this module.  Display strings are derived data and
must never be used as filesystem identities.
"""

from __future__ import annotations

import base64
import fnmatch
import functools
import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from .constants import (
    DEFAULT_MAX_PATH_BYTES,
    DEFAULT_MAX_PATH_DEPTH,
    DEFAULT_PROTECTED_PATTERNS,
    EXECUTABLE_MODE,
    REGULAR_MODE,
    SYMLINK_MODE,
)

if TYPE_CHECKING:
    from .manifests import SubjectManifest

_HEX_DIGITS = frozenset("0123456789abcdef")
_MAX_PATH_POLICY_PATTERNS = 256


def sha256_hex(data: bytes) -> str:
    """Return the lowercase SHA-256 digest used by all content identities."""

    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    return hashlib.sha256(data).hexdigest()


def path_to_b64(path: bytes) -> str:
    """Encode a raw path losslessly for JSON artifacts."""

    if not isinstance(path, bytes):
        raise TypeError("path must be bytes")
    return base64.b64encode(path).decode("ascii")


def path_from_b64(encoded: str) -> bytes:
    """Decode a canonical base64 path, rejecting aliases and malformed input."""

    if not isinstance(encoded, str):
        raise TypeError("encoded path must be a string")
    try:
        raw = encoded.encode("ascii")
        decoded = base64.b64decode(raw, validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise ValueError("path_b64 is not valid canonical base64") from exc
    if base64.b64encode(decoded) != raw:
        raise ValueError("path_b64 is not canonical base64")
    return decoded


def display_path(path: bytes) -> str:
    """Produce an ASCII-only, unambiguous display form for a raw byte path."""

    if not isinstance(path, bytes):
        raise TypeError("path must be bytes")
    pieces: list[str] = []
    for value in path:
        if value == 0x5C:
            pieces.append("\\\\")
        elif value == 0x0A:
            pieces.append("\\n")
        elif value == 0x0D:
            pieces.append("\\r")
        elif value == 0x09:
            pieces.append("\\t")
        elif 0x20 <= value <= 0x7E:
            pieces.append(chr(value))
        else:
            pieces.append(f"\\x{value:02x}")
    return "".join(pieces)


def validate_subject_path(path: bytes) -> None:
    """Validate the normalized relative POSIX path representation."""

    if not isinstance(path, bytes):
        raise TypeError("subject path must be bytes")
    if not path:
        raise ValueError("subject path must not be empty")
    if path.startswith(b"/"):
        raise ValueError("subject path must be relative")
    if b"\x00" in path:
        raise ValueError("subject path must not contain NUL")
    components = path.split(b"/")
    if any(component in {b"", b".", b".."} for component in components):
        raise ValueError("subject path contains an empty, dot, or dot-dot component")


def _validate_sha256(value: str, field_name: str) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    if len(value) != 64 or any(character not in _HEX_DIGITS for character in value):
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")


class EntryKind(StrEnum):
    REGULAR = "regular"
    SYMLINK = "symlink"


@dataclass(frozen=True, slots=True)
class ManifestEntry:
    """One normalized regular file or literal symlink in a subject manifest."""

    path: bytes
    kind: EntryKind
    mode: int
    size: int | None = None
    blob_sha256: str | None = None
    symlink_target: bytes | None = None
    target_sha256: str | None = None

    def __post_init__(self) -> None:
        validate_subject_path(self.path)
        if not isinstance(self.kind, EntryKind):
            raise TypeError("kind must be an EntryKind")
        if not isinstance(self.mode, int) or isinstance(self.mode, bool):
            raise TypeError("mode must be an integer")

        if self.kind is EntryKind.REGULAR:
            if self.mode not in {REGULAR_MODE, EXECUTABLE_MODE}:
                raise ValueError("regular entry mode must be 100644 or 100755")
            if not isinstance(self.size, int) or isinstance(self.size, bool) or self.size < 0:
                raise ValueError("regular entry size must be a non-negative integer")
            if self.blob_sha256 is None:
                raise ValueError("regular entry requires blob_sha256")
            _validate_sha256(self.blob_sha256, "blob_sha256")
            if self.symlink_target is not None or self.target_sha256 is not None:
                raise ValueError("regular entry cannot contain symlink fields")
            return

        if self.mode != SYMLINK_MODE:
            raise ValueError("symlink entry mode must be 120000")
        if self.size is not None or self.blob_sha256 is not None:
            raise ValueError("symlink entry cannot contain regular-file fields")
        if not isinstance(self.symlink_target, bytes):
            raise TypeError("symlink_target must be bytes")
        if not self.symlink_target:
            raise ValueError("symlink target must not be empty")
        if b"\x00" in self.symlink_target:
            raise ValueError("symlink target must not contain NUL")
        if self.target_sha256 is None:
            raise ValueError("symlink entry requires target_sha256")
        _validate_sha256(self.target_sha256, "target_sha256")
        if sha256_hex(self.symlink_target) != self.target_sha256:
            raise ValueError("target_sha256 does not match literal symlink target")

    @classmethod
    def regular(
        cls,
        path: bytes,
        *,
        size: int,
        blob_sha256: str,
        executable: bool = False,
    ) -> ManifestEntry:
        return cls(
            path=path,
            kind=EntryKind.REGULAR,
            mode=EXECUTABLE_MODE if executable else REGULAR_MODE,
            size=size,
            blob_sha256=blob_sha256,
        )

    @classmethod
    def symlink(cls, path: bytes, *, target: bytes) -> ManifestEntry:
        return cls(
            path=path,
            kind=EntryKind.SYMLINK,
            mode=SYMLINK_MODE,
            symlink_target=target,
            target_sha256=sha256_hex(target),
        )

    @property
    def path_b64(self) -> str:
        return path_to_b64(self.path)

    @property
    def display_path(self) -> str:
        return display_path(self.path)

    @property
    def executable(self) -> bool:
        return self.kind is EntryKind.REGULAR and self.mode == EXECUTABLE_MODE

    @property
    def content_sha256(self) -> str:
        if self.kind is EntryKind.REGULAR:
            assert self.blob_sha256 is not None
            return self.blob_sha256
        assert self.target_sha256 is not None
        return self.target_sha256

    def identity_without_path(self) -> tuple[object, ...]:
        """Return the exact identity used for deterministic rename pairing."""

        return (
            self.kind.value,
            self.mode,
            self.size,
            self.blob_sha256,
            self.symlink_target,
            self.target_sha256,
        )


@dataclass(frozen=True, slots=True)
class ScanRecord:
    """A safely-read scanner result; payload bytes are never path-followed here."""

    path: bytes
    kind: EntryKind
    mode: int
    payload: bytes

    def __post_init__(self) -> None:
        validate_subject_path(self.path)
        if not isinstance(self.kind, EntryKind):
            raise TypeError("kind must be an EntryKind")
        if not isinstance(self.mode, int) or isinstance(self.mode, bool):
            raise TypeError("mode must be an integer")
        if not isinstance(self.payload, bytes):
            raise TypeError("scan payload must be bytes")
        if self.kind is EntryKind.REGULAR:
            if self.mode not in {REGULAR_MODE, EXECUTABLE_MODE}:
                raise ValueError("scanned regular mode must be 100644 or 100755")
        elif self.mode != SYMLINK_MODE:
            raise ValueError("scanned symlink mode must be 120000")


@runtime_checkable
class BlobReader(Protocol):
    """Read content-addressed regular-file bytes by lowercase SHA-256."""

    def read_blob(self, sha256: str) -> bytes: ...


@runtime_checkable
class BlobWriter(Protocol):
    """Persist immutable bytes and return their lowercase SHA-256 identity."""

    def put_blob(self, data: bytes) -> str: ...


@runtime_checkable
class CompleteScanner(Protocol):
    """Yield every namespace entry, independently of ignore configuration."""

    def scan_records(self) -> Iterable[ScanRecord]: ...


class ChangeKind(StrEnum):
    CREATE = "create"
    DELETE = "delete"
    MODIFY = "modify"
    RENAME = "rename-equivalent"


@dataclass(frozen=True, slots=True)
class ManifestChange:
    """A deterministic change between two canonical manifests."""

    kind: ChangeKind
    before: ManifestEntry | None
    after: ManifestEntry | None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ChangeKind):
            raise TypeError("change kind must be a ChangeKind")
        if self.kind is ChangeKind.CREATE:
            if self.before is not None or self.after is None:
                raise ValueError("create requires only an after entry")
        elif self.kind is ChangeKind.DELETE:
            if self.before is None or self.after is not None:
                raise ValueError("delete requires only a before entry")
        elif self.kind is ChangeKind.MODIFY:
            if self.before is None or self.after is None:
                raise ValueError("modify requires before and after entries")
            if self.before.path != self.after.path or self.before == self.after:
                raise ValueError("modify requires different entries at one path")
        else:
            if self.before is None or self.after is None:
                raise ValueError("rename requires before and after entries")
            if self.before.path == self.after.path:
                raise ValueError("rename requires distinct paths")
            if self.before.identity_without_path() != self.after.identity_without_path():
                raise ValueError("rename entries must be exactly equivalent except for path")

    @property
    def old_path(self) -> bytes | None:
        return None if self.before is None else self.before.path

    @property
    def new_path(self) -> bytes | None:
        return None if self.after is None else self.after.path

    @property
    def paths(self) -> tuple[bytes, ...]:
        if self.before is None:
            assert self.after is not None
            return (self.after.path,)
        if self.after is None or self.before.path == self.after.path:
            return (self.before.path,)
        return (self.before.path, self.after.path)


class PathDisposition(StrEnum):
    PROTECTED = "protected"
    DISCARD_ONLY = "discard-only"
    OPAQUE_NONSEMANTIC = "opaque-nonsemantic"
    SEMANTIC = "semantic"


def _default_protected_bytes() -> tuple[bytes, ...]:
    return tuple(pattern.encode("ascii") for pattern in DEFAULT_PROTECTED_PATTERNS)


def _validate_pattern(pattern: bytes) -> None:
    if not isinstance(pattern, bytes):
        raise TypeError("path patterns must be bytes")
    if not pattern or pattern.startswith(b"/") or b"\x00" in pattern:
        raise ValueError("path pattern must be non-empty, relative, and NUL-free")
    components = pattern.split(b"/")
    if any(component in {b"", b".", b".."} for component in components):
        raise ValueError("path pattern contains an empty, dot, or dot-dot component")
    if len(pattern) > DEFAULT_MAX_PATH_BYTES or len(components) > DEFAULT_MAX_PATH_DEPTH:
        raise ValueError("path pattern exceeds the frozen path bounds")


def _component_glob_match(path: bytes, pattern: bytes) -> bool:
    """Match byte paths with component-aware `*` and recursive `**`."""

    path_parts = path.split(b"/")
    pattern_parts = pattern.split(b"/")

    @functools.cache
    def match(path_index: int, pattern_index: int) -> bool:
        while pattern_index < len(pattern_parts):
            pattern_part = pattern_parts[pattern_index]
            if pattern_part == b"**":
                while (
                    pattern_index + 1 < len(pattern_parts)
                    and pattern_parts[pattern_index + 1] == b"**"
                ):
                    pattern_index += 1
                if pattern_index + 1 == len(pattern_parts):
                    return True
                return any(
                    match(candidate_index, pattern_index + 1)
                    for candidate_index in range(path_index, len(path_parts) + 1)
                )
            if path_index >= len(path_parts):
                return False
            if not fnmatch.fnmatchcase(path_parts[path_index], pattern_part):
                return False
            path_index += 1
            pattern_index += 1
        return path_index == len(path_parts)

    return match(0, 0)


def path_matches_pattern(path: bytes, pattern: bytes) -> bool:
    """Expose the canonical component-aware matcher to policy-adjacent boundaries."""

    validate_subject_path(path)
    _validate_pattern(pattern)
    return _component_glob_match(path, pattern)


@dataclass(frozen=True, slots=True)
class PathPolicy:
    """Frozen path classification, with protection evaluated before omission."""

    protected_patterns: tuple[bytes, ...] = field(default_factory=_default_protected_bytes)
    discard_only_patterns: tuple[bytes, ...] = ()
    opaque_nonsemantic_patterns: tuple[bytes, ...] = ()
    protected_opt_in_patterns: tuple[bytes, ...] = ()

    def __post_init__(self) -> None:
        for patterns in (
            self.protected_patterns,
            self.discard_only_patterns,
            self.opaque_nonsemantic_patterns,
            self.protected_opt_in_patterns,
        ):
            if not isinstance(patterns, tuple):
                raise TypeError("path policy pattern collections must be tuples")
            if len(patterns) > _MAX_PATH_POLICY_PATTERNS:
                raise ValueError("path policy pattern collection exceeds its bound")
            for pattern in patterns:
                _validate_pattern(pattern)
            if len(set(patterns)) != len(patterns):
                raise ValueError("path policy patterns must not contain duplicates")

    @classmethod
    def from_strings(
        cls,
        *,
        protected_patterns: Iterable[str] = DEFAULT_PROTECTED_PATTERNS,
        discard_only_patterns: Iterable[str] = (),
        opaque_nonsemantic_patterns: Iterable[str] = (),
        protected_opt_in_patterns: Iterable[str] = (),
    ) -> PathPolicy:
        def encode(values: Iterable[str]) -> tuple[bytes, ...]:
            encoded: list[bytes] = []
            for value in values:
                if not isinstance(value, str):
                    raise TypeError("path policy string patterns must be strings")
                encoded.append(value.encode("utf-8"))
            return tuple(encoded)

        return cls(
            protected_patterns=encode(protected_patterns),
            discard_only_patterns=encode(discard_only_patterns),
            opaque_nonsemantic_patterns=encode(opaque_nonsemantic_patterns),
            protected_opt_in_patterns=encode(protected_opt_in_patterns),
        )

    @staticmethod
    def _matches(path: bytes, patterns: tuple[bytes, ...]) -> bool:
        validate_subject_path(path)
        return any(_component_glob_match(path, pattern) for pattern in patterns)

    def classify(self, path: bytes) -> PathDisposition:
        validate_subject_path(path)
        # Instruction and harness paths may be deliberately opted in, but no
        # project exception can restore a Git staging/history control plane.
        if (
            path == b".git"
            or path.startswith(b".git/")
            or path.endswith(b"/.git")
            or b"/.git/" in path
        ):
            return PathDisposition.PROTECTED
        opted_in = self._matches(path, self.protected_opt_in_patterns)
        if self._matches(path, self.protected_patterns) and not opted_in:
            return PathDisposition.PROTECTED
        if self._matches(path, self.discard_only_patterns):
            return PathDisposition.DISCARD_ONLY
        if self._matches(path, self.opaque_nonsemantic_patterns):
            return PathDisposition.OPAQUE_NONSEMANTIC
        return PathDisposition.SEMANTIC

    def classify_change(self, change: ManifestChange) -> PathDisposition:
        dispositions = {self.classify(path) for path in change.paths}
        if PathDisposition.PROTECTED in dispositions:
            return PathDisposition.PROTECTED
        # A cross-boundary rename/deletion must remain semantic by default.  It
        # is discard-only or opaque only when every affected path was declared
        # in that class before the author ran.
        if dispositions == {PathDisposition.DISCARD_ONLY}:
            return PathDisposition.DISCARD_ONLY
        if dispositions == {PathDisposition.OPAQUE_NONSEMANTIC}:
            return PathDisposition.OPAQUE_NONSEMANTIC
        return PathDisposition.SEMANTIC


@dataclass(frozen=True, slots=True)
class ReconciliationResult:
    """Policy-classified candidate and the state allowed into the next round."""

    candidate_delta: tuple[ManifestChange, ...]
    authoritative_manifest: SubjectManifest
    authoritative_delta: tuple[ManifestChange, ...]
    semantic_changes: tuple[ManifestChange, ...]
    opaque_changes: tuple[ManifestChange, ...]
    discarded_changes: tuple[ManifestChange, ...]
