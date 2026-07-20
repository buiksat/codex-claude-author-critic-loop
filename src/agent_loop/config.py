"""Strict project configuration that cannot silently select a weaker backend."""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath
from typing import Any

from .constants import (
    DEFAULT_AUTHOR_TIMEOUT_SECONDS,
    DEFAULT_CRITIC_TIMEOUT_SECONDS,
    DEFAULT_MAX_PATH_BYTES,
    DEFAULT_MAX_PATH_DEPTH,
    DEFAULT_MAX_ROUNDS,
    DEFAULT_MAX_RUNTIME_SECONDS,
    DEFAULT_PROTECTED_PATTERNS,
    DEFAULT_VALIDATION_TIMEOUT_SECONDS,
    Limits,
)
from .errors import AgentLoopError
from .filesystem import read_confined_absolute_file

_CONFIG_KEYS = {
    "schema_version",
    "checks",
    "protected_paths",
    "protected_opt_in_paths",
    "discard_only_paths",
    "opaque_nonsemantic_paths",
    "review_context_paths",
    "read_only_toolchain_mounts",
    "author_model",
    "author_effort",
    "critic_model",
    "critic_effort",
    "codex_credential_id",
    "claude_credential_id",
    "max_rounds",
    "max_runtime_seconds",
    "author_timeout_seconds",
    "critic_timeout_seconds",
    "validation_timeout_seconds",
    "limits",
}
_LIMIT_KEYS = set(Limits.__dataclass_fields__)
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_MAX_CONFIG_LIST_ITEMS = 256


@dataclass(frozen=True, slots=True)
class ProjectConfig:
    schema_version: int = 1
    checks: tuple[str, ...] = ()
    protected_paths: tuple[str, ...] = DEFAULT_PROTECTED_PATTERNS
    protected_opt_in_paths: tuple[str, ...] = ()
    discard_only_paths: tuple[str, ...] = ()
    opaque_nonsemantic_paths: tuple[str, ...] = ()
    review_context_paths: tuple[str, ...] = ()
    read_only_toolchain_mounts: tuple[str, ...] = ()
    author_model: str | None = None
    author_effort: str | None = None
    critic_model: str | None = None
    critic_effort: str | None = None
    codex_credential_id: str | None = None
    claude_credential_id: str | None = None
    max_rounds: int = DEFAULT_MAX_ROUNDS
    max_runtime_seconds: int = DEFAULT_MAX_RUNTIME_SECONDS
    author_timeout_seconds: int = DEFAULT_AUTHOR_TIMEOUT_SECONDS
    critic_timeout_seconds: int = DEFAULT_CRITIC_TIMEOUT_SECONDS
    validation_timeout_seconds: int = DEFAULT_VALIDATION_TIMEOUT_SECONDS
    limits: Limits = field(default_factory=Limits)

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("unsupported project configuration schema_version")
        for name in (
            "max_rounds",
            "max_runtime_seconds",
            "author_timeout_seconds",
            "critic_timeout_seconds",
            "validation_timeout_seconds",
        ):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if self.author_timeout_seconds > self.max_runtime_seconds:
            raise ValueError("author timeout cannot exceed total runtime")
        if self.critic_timeout_seconds > self.max_runtime_seconds:
            raise ValueError("critic timeout cannot exceed total runtime")
        if self.validation_timeout_seconds > self.max_runtime_seconds:
            raise ValueError("validation timeout cannot exceed total runtime")


def _strict_keys(value: dict[str, Any], allowed: set[str], where: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        raise ValueError(f"unknown {where} keys: {sorted(unknown)!r}")


def _strings(value: object, *, name: str, allow_empty: bool = True) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{name} must be an array of strings")
    result = tuple(value)
    if len(result) > _MAX_CONFIG_LIST_ITEMS:
        raise ValueError(f"{name} exceeds its item-count bound")
    if not allow_empty and not result:
        raise ValueError(f"{name} cannot be empty")
    for item in result:
        if not item or "\x00" in item or len(item.encode("utf-8")) > 32_768:
            raise ValueError(f"{name} contains an empty, NUL, or oversized value")
    if len(result) != len(set(result)):
        raise ValueError(f"{name} contains duplicates")
    return result


def _patterns(value: object, *, name: str) -> tuple[str, ...]:
    result = _strings(value, name=name)
    for pattern in result:
        encoded = pattern.encode("utf-8")
        parts = PurePosixPath(pattern).parts
        if (
            len(encoded) > DEFAULT_MAX_PATH_BYTES
            or len(parts) > DEFAULT_MAX_PATH_DEPTH
        ):
            raise ValueError(f"{name} exceeds the path-pattern bound")
        if pattern.startswith("/") or "\\" in pattern:
            raise ValueError(f"{name} patterns must be relative POSIX paths")
        if any(part in {"", ".", ".."} for part in parts):
            raise ValueError(f"{name} contains an ambiguous path component")
    return result


def _protected_opt_ins(value: object) -> tuple[str, ...]:
    result = _patterns(value, name="protected_opt_in_paths")
    for path in result:
        if any(character in path for character in "*?["):
            raise ValueError("protected_opt_in_paths must contain exact paths")
        if (
            path == ".git"
            or path.startswith(".git/")
            or path.endswith("/.git")
            or "/.git/" in path
        ):
            raise ValueError("protected_opt_in_paths cannot select a Git control path")
    return result


def _optional_string(value: object, *, name: str, identifier: bool = False) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{name} must be a non-empty string or absent")
    if len(value.encode("utf-8")) > 256:
        raise ValueError(f"{name} exceeds its byte limit")
    if identifier and _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{name} is not a safe identifier")
    return value


def _positive_int(value: object, *, name: str, default: int) -> int:
    if value is None:
        return default
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _limits(value: object) -> Limits:
    if value is None:
        return Limits()
    if not isinstance(value, dict):
        raise ValueError("limits must be a table")
    _strict_keys(value, _LIMIT_KEYS, "limits")
    defaults = Limits()
    kwargs: dict[str, int] = {}
    for key, raw in value.items():
        if not isinstance(raw, int) or isinstance(raw, bool) or raw <= 0:
            raise ValueError(f"limits.{key} must be a positive integer")
        # Lower ceilings are tighter except for the amount held back for model
        # output: reserving *more* output is tighter.  Limits validates the
        # combined input/output context budget after all overrides are applied.
        weakens = (
            raw < defaults.reserved_output_tokens
            if key == "reserved_output_tokens"
            else raw > getattr(defaults, key)
        )
        if weakens:
            raise ValueError(f"limits.{key} may only tighten the version-1 default")
        kwargs[key] = raw
    return replace(defaults, **kwargs)


def project_config_from_mapping(raw: dict[str, Any]) -> ProjectConfig:
    _strict_keys(raw, _CONFIG_KEYS, "top-level configuration")
    version = raw.get("schema_version", 1)
    if not isinstance(version, int) or isinstance(version, bool):
        raise ValueError("schema_version must be an integer")
    extra_protected = _patterns(raw.get("protected_paths", []), name="protected_paths")
    protected = tuple(dict.fromkeys((*DEFAULT_PROTECTED_PATTERNS, *extra_protected)))
    if len(protected) > _MAX_CONFIG_LIST_ITEMS:
        raise ValueError("protected_paths exceeds its item-count bound")
    mounts = _strings(raw.get("read_only_toolchain_mounts", []), name="read_only_toolchain_mounts")
    for mount in mounts:
        path = Path(mount)
        if (
            not path.is_absolute()
            or mount == "/"
            or mount.startswith("//")
            or os.path.normpath(mount) != mount
            or ".." in path.parts
        ):
            raise ValueError("toolchain mounts must be normalized absolute paths")
    return ProjectConfig(
        schema_version=version,
        checks=_strings(raw.get("checks", []), name="checks"),
        protected_paths=protected,
        protected_opt_in_paths=_protected_opt_ins(raw.get("protected_opt_in_paths", [])),
        discard_only_paths=_patterns(raw.get("discard_only_paths", []), name="discard_only_paths"),
        opaque_nonsemantic_paths=_patterns(
            raw.get("opaque_nonsemantic_paths", []), name="opaque_nonsemantic_paths"
        ),
        review_context_paths=_patterns(
            raw.get("review_context_paths", []), name="review_context_paths"
        ),
        read_only_toolchain_mounts=mounts,
        author_model=_optional_string(raw.get("author_model"), name="author_model"),
        author_effort=_optional_string(raw.get("author_effort"), name="author_effort"),
        critic_model=_optional_string(raw.get("critic_model"), name="critic_model"),
        critic_effort=_optional_string(raw.get("critic_effort"), name="critic_effort"),
        codex_credential_id=_optional_string(
            raw.get("codex_credential_id"), name="codex_credential_id", identifier=True
        ),
        claude_credential_id=_optional_string(
            raw.get("claude_credential_id"), name="claude_credential_id", identifier=True
        ),
        max_rounds=_positive_int(
            raw.get("max_rounds"), name="max_rounds", default=DEFAULT_MAX_ROUNDS
        ),
        max_runtime_seconds=_positive_int(
            raw.get("max_runtime_seconds"),
            name="max_runtime_seconds",
            default=DEFAULT_MAX_RUNTIME_SECONDS,
        ),
        author_timeout_seconds=_positive_int(
            raw.get("author_timeout_seconds"),
            name="author_timeout_seconds",
            default=DEFAULT_AUTHOR_TIMEOUT_SECONDS,
        ),
        critic_timeout_seconds=_positive_int(
            raw.get("critic_timeout_seconds"),
            name="critic_timeout_seconds",
            default=DEFAULT_CRITIC_TIMEOUT_SECONDS,
        ),
        validation_timeout_seconds=_positive_int(
            raw.get("validation_timeout_seconds"),
            name="validation_timeout_seconds",
            default=DEFAULT_VALIDATION_TIMEOUT_SECONDS,
        ),
        limits=_limits(raw.get("limits")),
    )


def load_project_config(path: Path) -> ProjectConfig:
    """Read a confined regular TOML file and reject every unknown property."""

    try:
        data = read_confined_absolute_file(path, max_bytes=1024 * 1024)
    except AgentLoopError as exc:
        cause = exc.__cause__
        if isinstance(cause, OSError) and cause.errno == 2:
            raise FileNotFoundError(path) from exc
        raise ValueError("project configuration cannot be read safely") from exc
    try:
        raw = tomllib.loads(data.decode("utf-8", "strict"))
    except UnicodeDecodeError as exc:
        raise ValueError("project configuration must be UTF-8") from exc
    return project_config_from_mapping(raw)
