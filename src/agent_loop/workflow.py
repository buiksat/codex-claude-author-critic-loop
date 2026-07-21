"""Fail-closed production composition for ``agent-loop run``.

The serial runner intentionally knows nothing about host discovery, credentials,
or operator confirmation.  This module joins those boundaries in the normative
order and keeps the joins dependency-injectable so orchestration failure paths
can be tested without launching either model CLI.
"""

from __future__ import annotations

import argparse
import errno
import glob
import json
import math
import os
import re
import stat
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Protocol

from .artifacts import ArtifactStore, ContentAddressedBlobStore
from .capabilities import (
    CAPABILITY_RECEIPT_RELATIVE_PATH,
    CapabilityReceiptError,
    LiveCapabilityBinding,
    ManagedClaudeBoundaryCapabilityBinding,
    verify_live_capability_receipt,
)
from .claude_managed_policy import (
    ManagedClaudeBoundary,
    inspect_managed_claude_boundary,
)
from .codex_client import (
    SanitizedCodexConfig,
    build_codex_parent_environment,
    install_sanitized_codex_config,
)
from .config import ProjectConfig, load_project_config, project_config_from_mapping
from .constants import DEFAULT_MAX_FIELD_BYTES, Limits
from .credentials import (
    CodexCredentialTransaction,
    codex_credential_root,
    load_claude_setup_token,
    xdg_state_home,
)
from .declassify import KnownSecret, raw_log_contains_known_secret
from .errors import AgentLoopError, ExitCode, StopReason, exit_code_for, fail
from .filesystem import ConfinedFilesystem, read_confined_absolute_file
from .git_source import GitSourceSnapshot, extract_committed_head
from .locks import SourceRunLock
from .manifests import (
    SubjectManifest,
    build_manifest_from_scan,
    verify_manifest_blobs,
)
from .models import BlobReader, BlobWriter, EntryKind, PathPolicy, sha256_hex
from .preflight import EnvironmentReport, run_preflight
from .provenance import (
    closure_sha256,
    installed_runtime_closure_sha256,
    safe_owned_mode,
    verify_safe_ancestors,
)
from .runner import (
    ArtifactRunJournal,
    AuthorAdapter,
    AuthorRequest,
    AuthorTurn,
    CriticAdapter,
    LoopResult,
    LoopRunner,
    LoopSettings,
    ValidationAdapter,
    ValidationRequest,
    ValidationTurn,
    _json_tree_contains_known_secret,
    _manifest_contains_known_secret,
    _manifest_metadata_contains_known_secret,
)
from .runtime_adapters import (
    SandboxExecution,
    SandboxExecutor,
    SandboxedClaudeCriticAdapter,
    SandboxedCodexAuthorAdapter,
    SandboxedValidationAdapter,
    ValidationCheck,
)
from .sandbox import SandboxMount, SandboxRole
from .sandbox_init import SandboxRequest, parse_result
from .schemas import parse_json_object
from .service import ServiceResult
from .validation_batch import (
    parse_validation_batch_request,
    parse_validation_batch_result,
)

_OPAQUE_NONSEMANTIC_ASSERTION = (
    "The operator asserts that every predeclared opaque path is behaviorally "
    "non-semantic and cannot affect configured validation or acceptance; the runner "
    "will independently counterfactual-test that assertion before omission."
)
_MODEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_EFFORT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_AUTH_MAX_BYTES = 4 * 1024 * 1024
_AUTH_FIELD_MAX_BYTES = 64 * 1024
_AUTH_TOP_LEVEL = {
    "auth_mode",
    "OPENAI_API_KEY",
    "tokens",
    "last_refresh",
}
_AUTH_TOKEN_KEYS = {
    "id_token",
    "access_token",
    "refresh_token",
    "account_id",
}
_CODEX_HOME_NAMES = {"auth.json", "config.toml", "sessions"}


class Closeable(Protocol):
    def close(self) -> None: ...


class BlobStore(BlobReader, BlobWriter, Protocol):
    """The minimal immutable blob interface shared by staging and retention."""


class _PrecredentialBlobStore:
    """Bounded memory-only committed-source staging before credentials exist.

    A crash can leave files in a disk-backed temporary directory.  Keeping the
    authoritative Git snapshot in this private object until every credential
    collision scan succeeds makes that pre-ledger failure mode content-free.
    """

    def __init__(self, limits: Limits) -> None:
        if not isinstance(limits, Limits):
            raise TypeError("precredential blob limits must be a Limits instance")
        self._limits = limits
        self._values: dict[str, bytes] = {}
        self._total_bytes = 0

    def put_blob(self, data: bytes) -> str:
        if not isinstance(data, bytes):
            raise TypeError("blob data must be bytes")
        if len(data) > self._limits.max_file_bytes:
            raise fail(
                StopReason.GIT_POLICY_OR_OUTPUT_FAILURE,
                "committed source blob exceeded the configured file limit",
            )
        digest = sha256_hex(data)
        existing = self._values.get(digest)
        if existing is not None:
            if existing != data:
                raise fail(
                    StopReason.OUT_OF_BAND_CHANGE,
                    "in-memory source blob did not match its content identity",
                )
            return digest
        if len(self._values) >= self._limits.max_files:
            raise fail(
                StopReason.GIT_POLICY_OR_OUTPUT_FAILURE,
                "committed source exceeded the configured file-count limit",
            )
        if self._total_bytes + len(data) > self._limits.max_total_subject_bytes:
            raise fail(
                StopReason.GIT_POLICY_OR_OUTPUT_FAILURE,
                "committed source exceeded the configured aggregate byte limit",
            )
        self._values[digest] = data
        self._total_bytes += len(data)
        return digest

    def read_blob(self, sha256: str) -> bytes:
        try:
            data = self._values[sha256]
        except KeyError:
            raise fail(
                StopReason.OUT_OF_BAND_CHANGE,
                "committed source manifest references a missing staged blob",
            ) from None
        if sha256_hex(data) != sha256:
            raise fail(
                StopReason.OUT_OF_BAND_CHANGE,
                "in-memory source blob failed identity verification",
            )
        return data


class WorkflowCredentialTransaction(Protocol):
    @property
    def codex_home(self) -> Path: ...

    @property
    def auth_generations(self) -> tuple[bytes, ...]: ...

    def capture_candidate_generation(self) -> bool: ...

    def remove_candidate_config(self) -> None: ...

    def reconcile_after_turn(self) -> bool: ...

    def complete(self) -> None: ...

    def finalize_reconciled(self) -> None: ...

    def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class RunConfiguration:
    """Strict project policy plus the two explicitly selected CLI binaries."""

    project: ProjectConfig
    codex_executable: Path
    claude_executable: Path


@dataclass(frozen=True, slots=True)
class RuntimeAdapters:
    author: AuthorAdapter
    validator: ValidationAdapter
    critic: CriticAdapter
    known_secret_provider: Callable[[], tuple[KnownSecret, ...]] | None = None


_MAX_KNOWN_SECRET_HISTORY = 256
_MAX_KNOWN_SECRET_HISTORY_BYTES = 4 * 1024 * 1024


class _KnownSecretLedger:
    """In-memory, append-only secret history for every later declassification gate."""

    def __init__(self, initial: tuple[KnownSecret, ...]) -> None:
        self._values: list[KnownSecret] = []
        self._keys: set[tuple[str, bytes]] = set()
        self._total_bytes = 0
        self.extend(initial)

    def extend(self, values: tuple[KnownSecret, ...]) -> bool:
        if not isinstance(values, tuple) or not all(
            isinstance(value, KnownSecret) for value in values
        ):
            raise TypeError("secret history accepts only tuples of KnownSecret values")
        additions: list[KnownSecret] = []
        seen = set(self._keys)
        for value in values:
            key = (value.identifier, value.value)
            if key in seen:
                continue
            additions.append(value)
            seen.add(key)
        prospective_count = len(self._values) + len(additions)
        prospective_bytes = self._total_bytes + sum(len(value.value) for value in additions)
        if (
            prospective_count > _MAX_KNOWN_SECRET_HISTORY
            or prospective_bytes > _MAX_KNOWN_SECRET_HISTORY_BYTES
        ):
            raise fail(
                StopReason.CREDENTIAL_REFRESH_FAILURE,
                "credential secret history exceeded its private in-memory bound",
            )
        for value in additions:
            self._values.append(value)
            self._keys.add((value.identifier, value.value))
            self._total_bytes += len(value.value)
        return bool(additions)

    def snapshot(self) -> tuple[KnownSecret, ...]:
        return tuple(self._values)


@dataclass(frozen=True, slots=True)
class ReviewedInstall:
    """One exact, immutable-by-witness CLI package mount."""

    mount: SandboxMount
    executable: str
    closure_sha256: str


@dataclass(frozen=True, slots=True)
class RunPreparation:
    run_id: str
    source: Path
    state_home: Path
    run_root: Path
    task: str
    configuration: RunConfiguration
    environment: EnvironmentReport | Mapping[str, object]
    snapshot: GitSourceSnapshot
    artifacts: ArtifactStore
    blobs: BlobStore


@dataclass(frozen=True, slots=True)
class WorkflowIO:
    """Narrow, testable operator I/O surface."""

    write: Callable[[str], None] = print
    read: Callable[[str], str] = input


class WorkflowBackend(Protocol):
    """Side-effect seams used by :func:`execute_run`."""

    def clock(self) -> float: ...

    def new_run_id(self) -> str: ...

    def canonical_source(self) -> Path: ...

    def acquire_source_lock(
        self,
        source: Path,
        run_id: str,
        *,
        state_home: Path,
    ) -> Closeable: ...

    def create_artifacts(self, run_root: Path) -> ArtifactStore: ...

    def preflight(
        self,
        configuration: RunConfiguration,
    ) -> EnvironmentReport | Mapping[str, object]: ...

    def extract_source(
        self,
        source: Path,
        blobs: BlobWriter,
        *,
        limits: Limits,
    ) -> GitSourceSnapshot: ...

    def acquire_codex_credential(
        self,
        preparation: RunPreparation,
    ) -> WorkflowCredentialTransaction: ...

    def load_claude_token(self, preparation: RunPreparation) -> str: ...

    def build_runtime(
        self,
        preparation: RunPreparation,
        transaction: WorkflowCredentialTransaction,
        claude_token: str,
        known_secrets: tuple[KnownSecret, ...],
    ) -> RuntimeAdapters: ...

    def known_secrets(
        self,
        preparation: RunPreparation,
        transaction: WorkflowCredentialTransaction,
        claude_token: str,
    ) -> tuple[KnownSecret, ...]: ...

    def prepare_codex_credential(
        self,
        preparation: RunPreparation,
        transaction: WorkflowCredentialTransaction,
        known_secrets: tuple[KnownSecret, ...],
    ) -> tuple[KnownSecret, ...]: ...

    def install_codex_configuration(
        self,
        preparation: RunPreparation,
        transaction: WorkflowCredentialTransaction,
        known_secrets: tuple[KnownSecret, ...],
    ) -> None: ...

    def prove_capabilities(
        self,
        preparation: RunPreparation,
    ) -> None: ...


def _unique(*groups: Sequence[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value for group in groups for value in group))


def _configuration_mapping(config: ProjectConfig) -> dict[str, object]:
    return {
        "schema_version": config.schema_version,
        "checks": list(config.checks),
        "protected_paths": list(config.protected_paths),
        "protected_opt_in_paths": list(config.protected_opt_in_paths),
        "discard_only_paths": list(config.discard_only_paths),
        "opaque_nonsemantic_paths": list(config.opaque_nonsemantic_paths),
        "review_context_paths": list(config.review_context_paths),
        "read_only_toolchain_mounts": list(config.read_only_toolchain_mounts),
        "author_model": config.author_model,
        "author_effort": config.author_effort,
        "critic_model": config.critic_model,
        "critic_effort": config.critic_effort,
        "codex_credential_id": config.codex_credential_id,
        "claude_credential_id": config.claude_credential_id,
        "max_rounds": config.max_rounds,
        "max_runtime_seconds": config.max_runtime_seconds,
        "author_timeout_seconds": config.author_timeout_seconds,
        "critic_timeout_seconds": config.critic_timeout_seconds,
        "validation_timeout_seconds": config.validation_timeout_seconds,
        "limits": asdict(config.limits),
    }


def _optional_argument(args: argparse.Namespace, name: str) -> object | None:
    value: object | None = getattr(args, name, None)
    return value


def _normalized_executable(value: object, *, name: str) -> Path:
    if not isinstance(value, Path):
        raise fail(StopReason.SANDBOX_SETUP_FAILURE, f"{name} must be selected explicitly")
    raw = os.fspath(value)
    path = Path(raw)
    if (
        not path.is_absolute()
        or raw == "/"
        or raw.startswith("//")
        or raw != os.path.normpath(raw)
        or ".." in path.parts
    ):
        raise fail(
            StopReason.SANDBOX_SETUP_FAILURE,
            f"{name} must be a normalized absolute non-root path",
        )
    return path


def _load_base_configuration(path: Path) -> ProjectConfig:
    try:
        return load_project_config(path)
    except FileNotFoundError:
        if path == Path(".agent-loop.toml"):
            return ProjectConfig()
        raise fail(
            StopReason.SANDBOX_SETUP_FAILURE,
            "the explicitly selected project configuration does not exist",
        ) from None
    except (OSError, TypeError, ValueError):
        raise fail(
            StopReason.SANDBOX_SETUP_FAILURE,
            "the project configuration is missing, unsafe, or invalid",
        ) from None


def resolve_run_configuration(args: argparse.Namespace) -> RunConfiguration:
    """Merge additive CLI declarations over strict project configuration."""

    config_path = _optional_argument(args, "config")
    if not isinstance(config_path, Path):
        config_path = Path(".agent-loop.toml")
    base = _load_base_configuration(config_path)
    raw = _configuration_mapping(base)

    additive = {
        "checks": (base.checks, tuple(args.check)),
        "protected_paths": (
            base.protected_paths,
            tuple(args.protected_validation_path),
        ),
        "discard_only_paths": (
            base.discard_only_paths,
            tuple(args.discard_only_path),
        ),
        "opaque_nonsemantic_paths": (
            base.opaque_nonsemantic_paths,
            tuple(args.opaque_nonsemantic_path),
        ),
        "review_context_paths": (
            base.review_context_paths,
            tuple(args.review_context_path),
        ),
        "read_only_toolchain_mounts": (
            base.read_only_toolchain_mounts,
            tuple(args.read_only_toolchain_mount),
        ),
    }
    for key, groups in additive.items():
        raw[key] = list(_unique(*groups))

    scalar_arguments = {
        "author_model": "author_model",
        "author_effort": "author_effort",
        "critic_model": "critic_model",
        "critic_effort": "critic_effort",
        "codex_credential_id": "codex_credential_id",
        "claude_credential_id": "claude_credential_id",
        "max_rounds": "max_rounds",
        "max_runtime_seconds": "max_runtime",
        "author_timeout_seconds": "author_timeout",
        "critic_timeout_seconds": "critic_timeout",
        "validation_timeout_seconds": "validation_timeout",
    }
    for config_name, argument_name in scalar_arguments.items():
        selected = _optional_argument(args, argument_name)
        if selected is not None:
            raw[config_name] = selected

    try:
        merged = project_config_from_mapping(raw)
    except (TypeError, ValueError):
        raise fail(
            StopReason.SANDBOX_SETUP_FAILURE,
            "the merged project and CLI run configuration is invalid",
        ) from None
    if not merged.checks:
        raise fail(
            StopReason.SANDBOX_SETUP_FAILURE,
            "at least one fixed validation check is required",
        )

    required = {
        "author model": merged.author_model,
        "author effort": merged.author_effort,
        "critic model": merged.critic_model,
        "critic effort": merged.critic_effort,
        "Codex credential ID": merged.codex_credential_id,
        "Claude credential ID": merged.claude_credential_id,
    }
    missing = [name for name, value in required.items() if value is None]
    if missing:
        raise fail(
            StopReason.SANDBOX_SETUP_FAILURE,
            "explicit run selections are missing: " + ", ".join(missing),
        )
    assert merged.author_model is not None
    assert merged.critic_model is not None
    assert merged.author_effort is not None
    assert merged.critic_effort is not None
    if (
        _MODEL.fullmatch(merged.author_model) is None
        or _MODEL.fullmatch(merged.critic_model) is None
    ):
        raise fail(StopReason.SANDBOX_SETUP_FAILURE, "model selections are not safe exact IDs")
    if _EFFORT.fullmatch(merged.author_effort) is None or _EFFORT.fullmatch(
        merged.critic_effort
    ) is None:
        raise fail(StopReason.SANDBOX_SETUP_FAILURE, "effort selections are not safe exact IDs")

    return RunConfiguration(
        merged,
        _normalized_executable(
            _optional_argument(args, "codex_executable"),
            name="Codex executable",
        ),
        _normalized_executable(
            _optional_argument(args, "claude_executable"),
            name="Claude executable",
        ),
    )


def read_task(path: Path, *, max_bytes: int = DEFAULT_MAX_FIELD_BYTES) -> str:
    """Read one stable, confined, bounded regular task file."""

    if (
        not isinstance(max_bytes, int)
        or isinstance(max_bytes, bool)
        or max_bytes <= 0
    ):
        raise ValueError("task byte limit must be positive")
    try:
        data = read_confined_absolute_file(path, max_bytes=max_bytes)
    except AgentLoopError as exc:
        detail = (
            "task input exceeds its byte limit"
            if "max_bytes" in exc.detail
            else "task input is missing, unsafe, or inaccessible"
        )
        raise fail(
            StopReason.SANDBOX_SETUP_FAILURE,
            detail,
        ) from None
    except (OSError, TypeError, ValueError):
        raise fail(
            StopReason.SANDBOX_SETUP_FAILURE,
            "task input is missing, unsafe, or inaccessible",
        ) from None
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise fail(StopReason.SANDBOX_SETUP_FAILURE, "task input is not UTF-8") from None
    if not text.strip() or "\x00" in text:
        raise fail(StopReason.SANDBOX_SETUP_FAILURE, "task input is empty or contains NUL")
    return text


def _protect_control_inputs(
    configuration: RunConfiguration,
    source: Path,
    paths: Sequence[Path],
) -> RunConfiguration:
    """Protect in-subject task/config files using exact escaped glob patterns."""

    additions: list[str] = []
    for path in paths:
        try:
            absolute = path if path.is_absolute() else Path.cwd() / path
            if ".." in absolute.parts or os.path.normpath(absolute) != os.fspath(absolute):
                raise ValueError("control input is not normalized")
            relative = absolute.relative_to(source)
            rendered = relative.as_posix()
            rendered.encode("utf-8", "strict")
        except UnicodeEncodeError:
            raise fail(
                StopReason.UNSAFE_OR_AMBIGUOUS_PATH,
                "a runner control input inside the subject has a non-UTF-8 path",
            ) from None
        except ValueError:
            continue
        if not rendered or rendered == "." or "\\" in rendered:
            raise fail(
                StopReason.UNSAFE_OR_AMBIGUOUS_PATH,
                "a runner control input has an ambiguous subject-relative path",
            )
        additions.append(glob.escape(rendered))
    if not additions:
        return configuration
    protected = _unique(configuration.project.protected_paths, tuple(additions))
    return replace(
        configuration,
        project=replace(configuration.project, protected_paths=protected),
    )


def _parsed_codex_file_auth(data: bytes) -> dict[str, object] | None:
    if not isinstance(data, bytes) or not 0 < len(data) <= _AUTH_MAX_BYTES:
        return None

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    def reject_number(_value: str) -> object:
        raise ValueError("numbers are unsupported")

    try:
        value = json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_number,
            parse_float=reject_number,
            parse_int=reject_number,
        )
    except (UnicodeDecodeError, ValueError, RecursionError, MemoryError):
        return None
    if not isinstance(value, dict) or set(value) != _AUTH_TOP_LEVEL:
        return None
    if value.get("auth_mode") != "chatgpt" or value.get("OPENAI_API_KEY") is not None:
        return None
    tokens = value.get("tokens")
    if not isinstance(tokens, dict) or set(tokens) != _AUTH_TOKEN_KEYS:
        return None
    fields = (*_AUTH_TOKEN_KEYS,)
    for name in fields:
        item = tokens.get(name)
        if not isinstance(item, str) or not item or "\x00" in item:
            return None
        try:
            encoded_item = item.encode("utf-8", "strict")
        except UnicodeEncodeError:
            return None
        if len(encoded_item) > _AUTH_FIELD_MAX_BYTES:
            return None
    refreshed = value.get("last_refresh")
    if not isinstance(refreshed, str) or not refreshed or "\x00" in refreshed:
        return None
    try:
        encoded_refreshed = refreshed.encode("utf-8", "strict")
    except UnicodeEncodeError:
        return None
    if len(encoded_refreshed) > _AUTH_FIELD_MAX_BYTES:
        return None
    return value


def parse_codex_file_auth(data: bytes) -> bool:
    """Validate the pinned ChatGPT-managed file-auth shape without exceptions.

    The parser is deliberately total: malformed encodings, duplicate keys,
    non-finite or otherwise unexpected numbers, excessive nesting, and every
    unsupported authentication adapter return ``False`` without including
    credential bytes in an exception.
    """

    return _parsed_codex_file_auth(data) is not None


def _read_codex_auth(codex_home: Path) -> dict[str, object]:
    try:
        descriptor = os.open(
            codex_home / "auth.json",
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o600
            ):
                raise ValueError("unsafe auth file")
            data = os.read(descriptor, _AUTH_MAX_BYTES + 1)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if len(data) > _AUTH_MAX_BYTES or (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mode,
            before.st_uid,
            before.st_nlink,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mode,
            after.st_uid,
            after.st_nlink,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ValueError("unstable auth file")
        parsed = _parsed_codex_file_auth(data)
    except (OSError, TypeError, ValueError):
        raise fail(
            StopReason.CREDENTIAL_REFRESH_FAILURE,
            "transactional Codex credential could not be scanned safely",
        ) from None
    if parsed is None:
        raise fail(
            StopReason.CREDENTIAL_REFRESH_FAILURE,
            "transactional Codex credential failed strict parsing",
        )
    return parsed


def _codex_known_secrets_from_auth(data: bytes) -> tuple[KnownSecret, ...]:
    parsed = _parsed_codex_file_auth(data)
    if parsed is None:
        raise fail(
            StopReason.CREDENTIAL_REFRESH_FAILURE,
            "transactional Codex credential generation failed strict parsing",
        )
    tokens = parsed.get("tokens")
    if not isinstance(tokens, dict):
        raise fail(
            StopReason.CREDENTIAL_REFRESH_FAILURE,
            "transactional Codex credential token map is unavailable",
        )
    result: list[KnownSecret] = []
    for name in sorted(_AUTH_TOKEN_KEYS):
        value = tokens.get(name)
        if not isinstance(value, str):
            raise fail(
                StopReason.CREDENTIAL_REFRESH_FAILURE,
                "transactional Codex credential token field is unavailable",
            )
        result.append(KnownSecret(f"codex-{name}", value.encode("utf-8")))
    return tuple(result)


def _codex_known_secrets(codex_home: Path) -> tuple[KnownSecret, ...]:
    parsed = _read_codex_auth(codex_home)
    return _codex_known_secrets_from_auth(
        json.dumps(
            parsed,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    )


def _transaction_codex_known_secrets(
    transaction: WorkflowCredentialTransaction,
) -> tuple[KnownSecret, ...]:
    """Capture and flatten every in-memory auth generation without persistence."""

    transaction.capture_candidate_generation()
    values: list[KnownSecret] = []
    for generation in transaction.auth_generations:
        values.extend(_codex_known_secrets_from_auth(generation))
    return tuple(dict.fromkeys(values))


def _codex_artifact_evidence_barrier(
    state_home: Path,
    credential_id: str | None = None,
) -> Callable[[str, tuple[bytes, ...]], None]:
    """Bind credential promotion to durable prior-run evidence classification."""

    def classify(run_id: str, generations: tuple[bytes, ...]) -> None:
        # Recovery first calls the barrier with no generations.  That signal
        # cannot classify candidate bytes; it exists solely to finish a
        # marker-backed whole-run wipe before an invalid candidate can stop
        # recovery ahead of the ordinary generation-aware barrier.
        replay_withholding_only = not generations
        secrets = tuple(
            dict.fromkeys(
                secret
                for generation in generations
                for secret in _codex_known_secrets_from_auth(generation)
            )
        )
        config_collision = False
        if credential_id is not None and not replay_withholding_only:
            codex_home = (
                codex_credential_root(credential_id, state_home=state_home)
                / "transactions"
                / run_id
                / "codex-home"
            )
            try:
                control = ConfinedFilesystem.open(codex_home)
            except AgentLoopError:
                raise fail(
                    StopReason.CREDENTIAL_REFRESH_FAILURE,
                    "pending Codex control home could not be inspected",
                ) from None
            try:
                try:
                    rendered = control.read_bytes(
                        b"config.toml",
                        max_bytes=_AUTH_MAX_BYTES,
                    )
                except AgentLoopError as exc:
                    cause = exc.__cause__
                    if not isinstance(cause, OSError) or cause.errno != errno.ENOENT:
                        raise
                else:
                    if raw_log_contains_known_secret(rendered, secrets):
                        try:
                            os.unlink(b"config.toml", dir_fd=control.fileno())
                            os.fsync(control.fileno())
                        except OSError:
                            raise fail(
                                StopReason.CREDENTIAL_REFRESH_FAILURE,
                                "pending Codex configuration could not be withheld",
                            ) from None
                        config_collision = True
            finally:
                control.close()
        run_root = state_home / "agent-loop" / "runs" / run_id
        try:
            info = os.lstat(run_root)
        except FileNotFoundError:
            return
        except OSError:
            raise fail(
                StopReason.CREDENTIAL_REFRESH_FAILURE,
                "pending run evidence could not be inspected before credential promotion",
            ) from None
        if not stat.S_ISDIR(info.st_mode):
            raise fail(
                StopReason.CREDENTIAL_REFRESH_FAILURE,
                "pending run evidence root is not a private directory",
            )
        with ArtifactStore.open(run_root) as retained:
            if retained.content_withheld_due_to_secret:
                retained.withhold_all_content()
            elif not replay_withholding_only:
                retained.scrub_known_secrets(secrets)
        if config_collision:
            raise fail(
                StopReason.CREDENTIAL_REFRESH_FAILURE,
                "pending Codex configuration collided with refreshed credentials",
            )

    return classify


def _environment_json(
    environment: EnvironmentReport | Mapping[str, object],
) -> dict[str, object]:
    if isinstance(environment, EnvironmentReport):
        return environment.to_json_obj()
    if not isinstance(environment, Mapping) or any(
        not isinstance(key, str) for key in environment
    ):
        raise TypeError("preflight environment evidence must be a string-keyed mapping")
    return dict(environment)


def _resolved_cli(environment: EnvironmentReport, *, name: str) -> str:
    trusted = environment.codex if name == "codex" else environment.claude
    return trusted.resolved_path


def _paths_overlap(first: Path, second: Path) -> bool:
    first_value = os.path.normpath(os.fspath(first))
    second_value = os.path.normpath(os.fspath(second))
    try:
        common = os.path.commonpath((first_value, second_value))
    except ValueError:
        return False
    return common in {first_value, second_value}


def _reject_control_path_overlaps(
    source: Path,
    state_home: Path,
    configuration: RunConfiguration,
) -> None:
    canonical_source = Path(os.path.realpath(source))
    canonical_state = Path(os.path.realpath(state_home))
    if _paths_overlap(canonical_source, canonical_state):
        raise fail(
            StopReason.SANDBOX_SETUP_FAILURE,
            "state home and canonical source must not overlap in either direction",
        )
    reviewed_paths = (
        configuration.codex_executable,
        configuration.claude_executable,
        *(Path(path) for path in configuration.project.read_only_toolchain_mounts),
    )
    for reviewed in reviewed_paths:
        canonical = Path(os.path.realpath(reviewed))
        if _paths_overlap(canonical, canonical_source) or _paths_overlap(
            canonical,
            canonical_state,
        ):
            raise fail(
                StopReason.SANDBOX_SETUP_FAILURE,
                "a reviewed executable or toolchain path overlaps source or runner state",
            )


def _derive_reviewed_install(
    preparation: RunPreparation,
    *,
    name: str,
) -> ReviewedInstall:
    environment = preparation.environment
    if not isinstance(environment, EnvironmentReport):
        raise TypeError("production preflight did not return EnvironmentReport")
    resolved = Path(_resolved_cli(environment, name=name))
    roots = (preparation.source, preparation.state_home, preparation.run_root)
    if any(_paths_overlap(resolved, root) for root in roots):
        raise fail(
            StopReason.SANDBOX_SETUP_FAILURE,
            f"reviewed {name} install overlaps source or private runner state",
        )
    try:
        verify_safe_ancestors(resolved)
        with resolved.open("rb") as stream:
            magic = stream.read(4)
        if magic == b"\x7fELF":
            source = resolved
            target = f"/opt/agent-loop-tools/{name}"
            executable = target
        elif name == "codex" and resolved.name == "codex.js" and resolved.parent.name == "bin":
            source = resolved.parent.parent
            package = json.loads((source / "package.json").read_text(encoding="utf-8"))
            if not isinstance(package, dict) or (
                package.get("name"), package.get("version")
            ) != ("@openai/codex", environment.codex.version.removeprefix("codex-cli ")):
                raise ValueError("Codex package identity does not match preflight")
            target = "/opt/agent-loop-tools/codex-package"
            executable = target + "/bin/codex.js"
        else:
            raise ValueError("unsupported CLI package layout")
        if any(_paths_overlap(source, root) for root in roots):
            raise ValueError("CLI package closure overlaps runner state")
        closure = closure_sha256(source)
    except (OSError, TypeError, ValueError):
        raise fail(
            StopReason.SANDBOX_SETUP_FAILURE,
            f"reviewed {name} install closure is unsafe or unsupported",
        ) from None
    return ReviewedInstall(
        SandboxMount(
            os.fspath(source),
            target,
            read_only=True,
            closure_sha256=closure,
        ),
        executable,
        closure,
    )


def _reviewed_toolchain_mount(path: str, preparation: RunPreparation) -> SandboxMount:
    try:
        info = os.lstat(path)
        selected = Path(path)
        verify_safe_ancestors(selected)
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise ValueError("toolchain root is a special file")
        if not safe_owned_mode(info):
            raise ValueError("toolchain root ownership or mode is unsafe")
        if any(
            _paths_overlap(selected, root)
            for root in (
                preparation.source,
                preparation.state_home,
                preparation.run_root,
            )
        ):
            raise ValueError("toolchain overlaps source or runner state")
        closure = closure_sha256(selected)
    except (OSError, TypeError, ValueError):
        raise fail(
            StopReason.SANDBOX_SETUP_FAILURE,
            "a reviewed toolchain mount is missing, unsafe, special, or overlaps private state",
        ) from None
    if stat.S_ISLNK(info.st_mode) or os.path.realpath(path) != path:
        raise fail(
            StopReason.SANDBOX_SETUP_FAILURE,
            "reviewed toolchain mounts cannot traverse symbolic links",
        )
    return SandboxMount(path, path, read_only=True, closure_sha256=closure)


def _codex_status_probe(
    executor: SandboxExecutor,
    install: ReviewedInstall,
    codex_home: Path,
) -> bool:
    """Run the pinned non-model auth command inside the service/sandbox boundary."""

    try:
        execution = executor.execute(
            role=SandboxRole.AUTHOR,
            manifest=SubjectManifest.empty(),
            argv=(
                install.executable,
                "-c",
                'cli_auth_credentials_store="file"',
                "login",
                "status",
            ),
            environment=build_codex_parent_environment(),
            cwd="/runtime/author-cwd",
            timeout_seconds=15,
            mounts=(
                install.mount,
                SandboxMount(
                    os.fspath(codex_home),
                    "/control/codex-home",
                    read_only=False,
                ),
            ),
            output_max_bytes=64 * 1024,
        )
        names = set(os.listdir(codex_home))
    except (AgentLoopError, OSError, TypeError, ValueError):
        return False
    process = execution.result.process
    return bool(
        process.returncode == 0
        and not process.timed_out
        and not process.output_limited
        and names <= _CODEX_HOME_NAMES
    )


def _bounded_attempt_streams(
    stdout: bytes,
    stderr: bytes,
    *,
    max_bytes: int,
) -> tuple[bytes, bytes, bool]:
    retained_stdout = stdout[:max_bytes]
    remaining = max_bytes - len(retained_stdout)
    retained_stderr = stderr[:remaining]
    return (
        retained_stdout,
        retained_stderr,
        len(retained_stdout) != len(stdout) or len(retained_stderr) != len(stderr),
    )


def _decoded_agent_output_secret_status(
    role: SandboxRole,
    data: bytes,
    secrets: tuple[KnownSecret, ...],
) -> tuple[bool, bool]:
    """Return (strictly decodable, contains secret) for model protocol output."""

    try:
        if role is SandboxRole.AUTHOR:
            lines = data.splitlines()
            if not lines or any(not line for line in lines):
                return False, False
            values = tuple(parse_json_object(line) for line in lines)
            return True, _json_tree_contains_known_secret(values, secrets)
        if role is SandboxRole.CRITIC:
            value = parse_json_object(data)
            return True, _json_tree_contains_known_secret(value, secrets)
    except AgentLoopError:
        return False, False
    return True, False


def _safe_outer_attempt_streams(
    role: SandboxRole,
    request: SandboxRequest,
    service: ServiceResult,
    secrets: tuple[KnownSecret, ...],
    *,
    max_bytes: int,
) -> tuple[bytes, bytes, bool, bool]:
    """Retain opaque service bytes only after control output can be decoded safely."""

    try:
        decoded = parse_result(service.process.stdout, request=request)
    except AgentLoopError as error:
        try:
            detail_bytes = error.detail.encode("utf-8", "strict")
        except UnicodeEncodeError:
            raise fail(
                StopReason.CREDENTIAL_REFRESH_FAILURE,
                "sandbox error detail could not cross the credential-safe text boundary",
            ) from None
        if raw_log_contains_known_secret(detail_bytes, secrets):
            raise fail(
                StopReason.CREDENTIAL_REFRESH_FAILURE,
                "sandbox error detail contained dedicated credential bytes",
            ) from None
        # A valid typed error still has no releasable result streams.  The
        # caller persists only non-content process facts and re-parsing later
        # propagates the already-scanned typed error.
        return (
            b"",
            b"",
            bool(service.process.stdout or service.process.stderr),
            True,
        )
    except ValueError:
        # An opaque malformed/base64-fragmented response could contain a
        # credential form that is invisible until decoding.  Retain only typed
        # lengths/termination facts for every sandbox role in that case.
        return (
            b"",
            b"",
            bool(service.process.stdout or service.process.stderr),
            True,
        )
    request_manifest_sensitive = _manifest_metadata_contains_known_secret(
        request.manifest,
        secrets,
    )
    candidate_manifest_sensitive = _manifest_metadata_contains_known_secret(
        decoded.candidate,
        secrets,
    )
    if request_manifest_sensitive:
        raise fail(
            StopReason.CREDENTIAL_REFRESH_FAILURE,
            "sandbox input manifest collided with refreshed credential bytes",
        )
    if candidate_manifest_sensitive:
        if role is SandboxRole.VALIDATION:
            return b"", b"", True, True
        raise fail(
            StopReason.CREDENTIAL_REFRESH_FAILURE,
            "sandbox candidate manifest contained dedicated credential bytes",
        )
    validation_fields: tuple[bytes, ...] = ()
    if role is SandboxRole.VALIDATION:
        try:
            batch_request = parse_validation_batch_request(request.stdin_bytes)
            batch_records = parse_validation_batch_result(
                decoded.process.stdout,
                expected_checks=len(batch_request.checks),
                max_raw_output_bytes=batch_request.max_raw_output_bytes,
            )
        except ValueError:
            return (
                b"",
                b"",
                bool(service.process.stdout or service.process.stderr),
                True,
            )
        validation_fields = tuple(
            field
            for record in batch_records
            for field in (record.stdout, record.stderr)
        ) + tuple(
            field.encode("utf-8", "strict")
            for check in batch_request.checks
            for field in (check.check_id, check.command)
        )
    elif role in {SandboxRole.AUTHOR, SandboxRole.CRITIC}:
        decodable, contains_secret = _decoded_agent_output_secret_status(
            role,
            decoded.process.stdout,
            secrets,
        )
        if not decodable:
            return (
                b"",
                b"",
                bool(service.process.stdout or service.process.stderr),
                True,
            )
        if contains_secret:
            raise fail(
                StopReason.CREDENTIAL_REFRESH_FAILURE,
                "decoded model protocol contained dedicated credential bytes",
            )
    # Scan each already-bounded decoded field independently.  Never join a
    # maximum-size export into another large host allocation, and do not scan
    # the encoded stdout after authoritative decoding succeeded.
    sensitive_fields = (
        service.process.stderr,
        decoded.process.stdout,
        decoded.process.stderr,
        *(entry.path for entry in decoded.candidate.entries),
        *(
            entry.symlink_target
            for entry in decoded.candidate.entries
            if entry.symlink_target is not None
        ),
        *validation_fields,
    )
    for field in sensitive_fields:
        if raw_log_contains_known_secret(field, secrets):
            if role is SandboxRole.VALIDATION:
                return b"", b"", True, True
            raise fail(
                StopReason.CREDENTIAL_REFRESH_FAILURE,
                "decoded sandbox evidence contained dedicated credential bytes",
            )
    for _, data in decoded.new_blobs:
        if raw_log_contains_known_secret(data, secrets):
            if role is SandboxRole.VALIDATION:
                return b"", b"", True, True
            raise fail(
                StopReason.CREDENTIAL_REFRESH_FAILURE,
                "decoded sandbox export contained dedicated credential bytes",
            )
    retained_stdout, retained_stderr, truncated = _bounded_attempt_streams(
        service.process.stdout,
        service.process.stderr,
        max_bytes=max_bytes,
    )
    return retained_stdout, retained_stderr, truncated, False


def _attempt_sink(
    preparation: RunPreparation,
    secret_provider: Callable[[], tuple[KnownSecret, ...]],
) -> Callable[[SandboxRole, int, SandboxExecution], None]:
    def persist(role: SandboxRole, attempt_number: int, execution: SandboxExecution) -> None:
        process = execution.result.process
        current_secrets = secret_provider()
        input_content_withheld = _manifest_metadata_contains_known_secret(
            execution.request.manifest,
            current_secrets,
        )
        candidate_content_withheld = _manifest_metadata_contains_known_secret(
            execution.result.candidate,
            current_secrets,
        )
        validation_content_withheld = False
        control_content_withheld = False
        credential_error = input_content_withheld
        if role is SandboxRole.VALIDATION:
            validation_content_withheld = candidate_content_withheld
            try:
                batch_request = parse_validation_batch_request(
                    execution.request.stdin_bytes
                )
                batch_records = parse_validation_batch_result(
                    process.stdout,
                    expected_checks=len(batch_request.checks),
                    max_raw_output_bytes=batch_request.max_raw_output_bytes,
                )
            except ValueError:
                validation_content_withheld = True
            else:
                validation_content_withheld = any(
                    raw_log_contains_known_secret(field, current_secrets)
                    for record in batch_records
                    for field in (record.stdout, record.stderr)
                ) or _json_tree_contains_known_secret(
                    tuple(
                        (check.check_id, check.command)
                        for check in batch_request.checks
                    ),
                    current_secrets,
                )
        elif role in {SandboxRole.AUTHOR, SandboxRole.CRITIC}:
            credential_error = credential_error or candidate_content_withheld
            decodable, contains_secret = _decoded_agent_output_secret_status(
                role,
                process.stdout,
                current_secrets,
            )
            control_content_withheld = not decodable
            credential_error = credential_error or contains_secret
        for stream in (process.stdout, process.stderr):
            if raw_log_contains_known_secret(stream, current_secrets):
                if role is SandboxRole.VALIDATION:
                    validation_content_withheld = True
                else:
                    credential_error = True
        if role is SandboxRole.AUTHOR:
            for digest, data in execution.result.new_blobs:
                if raw_log_contains_known_secret(
                    digest.encode("ascii"),
                    current_secrets,
                ) or raw_log_contains_known_secret(data, current_secrets):
                    credential_error = True
            if not credential_error:
                for digest, data in execution.result.new_blobs:
                    if preparation.blobs.put_blob(data) != digest:
                        raise fail(
                            StopReason.OUT_OF_BAND_CHANGE,
                            "candidate attempt blob did not match its exported identity",
                        )
        prefix = (
            f"artifacts/validation-attempts/{attempt_number:03d}"
            if role is SandboxRole.VALIDATION
            else f"artifacts/rounds/{attempt_number:03d}"
        )
        preparation.artifacts.ensure_directory(prefix)
        stream_cap = (
            preparation.configuration.project.limits.max_raw_log_bytes
            if role is SandboxRole.VALIDATION
            else preparation.configuration.project.limits.max_agent_output_bytes
        )
        content_withheld = (
            validation_content_withheld
            or control_content_withheld
            or credential_error
        )
        if content_withheld:
            retained_stdout, retained_stderr, streams_truncated = (
                b"",
                b"",
                bool(process.stdout or process.stderr),
            )
        else:
            retained_stdout, retained_stderr, streams_truncated = _bounded_attempt_streams(
                process.stdout,
                process.stderr,
                max_bytes=stream_cap,
            )
        preparation.artifacts.write_bytes(
            f"{prefix}/{role.value}-attempt.stdout",
            retained_stdout,
        )
        preparation.artifacts.write_bytes(
            f"{prefix}/{role.value}-attempt.stderr",
            retained_stderr,
        )
        preparation.artifacts.write_bytes(
            f"{prefix}/{role.value}-attempt.input-subject.json",
            b"" if input_content_withheld else execution.request.manifest.to_json_bytes(),
        )
        preparation.artifacts.write_bytes(
            f"{prefix}/{role.value}-attempt.candidate-subject.json",
            b""
            if content_withheld
            else execution.result.candidate.to_json_bytes(),
        )
        preparation.artifacts.write_json(
            f"{prefix}/{role.value}-attempt.json",
            {
                "role": role.value,
                "attempt": attempt_number,
                "round": (
                    None if role is SandboxRole.VALIDATION else attempt_number
                ),
                "returncode": process.returncode,
                "timed_out": process.timed_out,
                "output_limited": process.output_limited,
                "duration_ms": process.duration_ms,
                "stdout_bytes": len(process.stdout),
                "stderr_bytes": len(process.stderr),
                "retained_stream_bytes": len(retained_stdout) + len(retained_stderr),
                "streams_truncated": streams_truncated,
                "content_withheld": content_withheld,
                "retention_failure_reason": (
                    StopReason.CREDENTIAL_REFRESH_FAILURE.value
                    if credential_error
                    else None
                ),
                "namespace_empty": execution.result.cleanup.namespace_empty,
                "terminated_pids": execution.result.cleanup.terminated_pids,
                "service_unit": execution.service.unit_name,
                "service_cgroup_empty": execution.service.cgroup_empty,
                "service_returncode": execution.service.process.returncode,
                "service_timed_out": execution.service.process.timed_out,
                "service_output_limited": execution.service.process.output_limited,
                "input_subject_fingerprint": (
                    None
                    if input_content_withheld
                    else execution.request.manifest.fingerprint
                ),
                "candidate_subject_fingerprint": (
                    None
                    if candidate_content_withheld
                    else execution.result.candidate.fingerprint
                ),
            },
        )
        if credential_error:
            raise fail(
                StopReason.CREDENTIAL_REFRESH_FAILURE,
                "decoded sandbox attempt contained dedicated credential bytes",
            )

    return persist


def _service_attempt_sink(
    preparation: RunPreparation,
    secret_provider: Callable[[], tuple[KnownSecret, ...]],
) -> Callable[[SandboxRole, int, SandboxRequest, ServiceResult, float], None]:
    """Retain the bounded outer-service prefix before sandbox-result parsing."""

    def persist(
        role: SandboxRole,
        attempt_number: int,
        request: SandboxRequest,
        service: ServiceResult,
        completed_at: float,
    ) -> None:
        prefix = (
            f"artifacts/sandbox-service-attempts/{attempt_number:03d}-{role.value}"
        )
        preparation.artifacts.ensure_directory(prefix)
        stream_cap = (
            preparation.configuration.project.limits.max_raw_log_bytes
            if role is SandboxRole.VALIDATION
            else preparation.configuration.project.limits.max_agent_output_bytes
        )
        retention_error: AgentLoopError | None = None
        input_content_withheld = True
        try:
            current_secrets = secret_provider()
            input_content_withheld = _manifest_metadata_contains_known_secret(
                request.manifest,
                current_secrets,
            )
            (
                retained_stdout,
                retained_stderr,
                streams_truncated,
                streams_withheld_unparseable,
            ) = _safe_outer_attempt_streams(
                role,
                request,
                service,
                current_secrets,
                max_bytes=stream_cap,
            )
        except AgentLoopError as exc:
            # The subprocess attempt itself is still forensic fact.  Preserve
            # only non-content metadata when credential classification cannot
            # safely release either stream, then propagate the typed failure.
            retained_stdout = b""
            retained_stderr = b""
            streams_truncated = bool(service.process.stdout or service.process.stderr)
            streams_withheld_unparseable = True
            retention_error = exc
        preparation.artifacts.write_bytes(
            f"{prefix}/stdout",
            retained_stdout,
        )
        preparation.artifacts.write_bytes(
            f"{prefix}/stderr",
            retained_stderr,
        )
        preparation.artifacts.write_bytes(
            f"{prefix}/input-subject.json",
            b"" if input_content_withheld else request.manifest.to_json_bytes(),
        )
        preparation.artifacts.write_json(
            f"{prefix}/attempt.json",
            {
                "schema_version": 1,
                "role": role.value,
                "attempt": attempt_number,
                "input_subject_fingerprint": (
                    None if input_content_withheld else request.manifest.fingerprint
                ),
                "service_unit": service.unit_name,
                "service_returncode": service.process.returncode,
                "service_timed_out": service.process.timed_out,
                "service_output_limited": service.process.output_limited,
                "service_cgroup_empty": service.cgroup_empty,
                "stdout_bytes": len(service.process.stdout),
                "stderr_bytes": len(service.process.stderr),
                "retained_stream_bytes": len(retained_stdout) + len(retained_stderr),
                "streams_truncated": streams_truncated,
                "streams_withheld_unparseable": streams_withheld_unparseable,
                "retention_failure_reason": (
                    None if retention_error is None else retention_error.reason.value
                ),
                "completed_at": completed_at,
            },
        )
        if retention_error is not None:
            raise retention_error

    return persist


class ProductionWorkflowBackend:
    """The sole version-1 production backend; there is no weaker fallback."""

    def __init__(self) -> None:
        self._install_cache: dict[tuple[str, str, str, str], ReviewedInstall] = {}
        self._managed_claude_boundary: ManagedClaudeBoundary | None = None

    def clock(self) -> float:
        return time.monotonic()

    def new_run_id(self) -> str:
        return f"run-{uuid.uuid4().hex}"

    def canonical_source(self) -> Path:
        source = Path(os.getcwd())
        try:
            resolved = source.resolve(strict=True)
            info = os.stat(resolved, follow_symlinks=False)
        except OSError:
            raise fail(
                StopReason.REPOSITORY_SHAPE_UNSUPPORTED,
                "the source repository root is inaccessible",
            ) from None
        if not stat.S_ISDIR(info.st_mode) or not resolved.is_absolute():
            raise fail(
                StopReason.REPOSITORY_SHAPE_UNSUPPORTED,
                "the source repository root is not a directory",
            )
        return resolved

    def acquire_source_lock(
        self,
        source: Path,
        run_id: str,
        *,
        state_home: Path,
    ) -> SourceRunLock:
        try:
            return SourceRunLock.acquire(source, run_id, state_home=state_home)
        except TimeoutError:
            raise fail(
                StopReason.OUT_OF_BAND_CHANGE,
                "another agent-loop run holds the source lock",
            ) from None

    def create_artifacts(self, run_root: Path) -> ArtifactStore:
        return ArtifactStore.create(run_root)

    def preflight(self, configuration: RunConfiguration) -> EnvironmentReport:
        return run_preflight(
            codex_path=os.fspath(configuration.codex_executable),
            claude_path=os.fspath(configuration.claude_executable),
        )

    def extract_source(
        self,
        source: Path,
        blobs: BlobWriter,
        *,
        limits: Limits,
    ) -> GitSourceSnapshot:
        return extract_committed_head(source, blobs, limits=limits)

    def _install(self, preparation: RunPreparation, *, name: str) -> ReviewedInstall:
        environment = preparation.environment
        if not isinstance(environment, EnvironmentReport):
            raise TypeError("production preflight did not return EnvironmentReport")
        key = (
            name,
            _resolved_cli(environment, name=name),
            os.fspath(preparation.source),
            os.fspath(preparation.state_home),
        )
        selected = self._install_cache.get(key)
        if selected is None:
            selected = _derive_reviewed_install(preparation, name=name)
            self._install_cache[key] = selected
        return selected

    def _claude_boundary(self, preparation: RunPreparation) -> ManagedClaudeBoundary:
        selected = self._managed_claude_boundary
        if selected is None:
            try:
                selected = inspect_managed_claude_boundary()
            except (OSError, TypeError, ValueError):
                raise fail(
                    StopReason.GITLESS_INVOCATION_PROBE_FAILED,
                    "the fixed administrator-managed Claude boundary is absent or unsafe",
                ) from None
        try:
            for mount in (selected.policy_mount, selected.helper_mount):
                mounted = Path(mount.source)
                if any(
                    _paths_overlap(mounted, private_root)
                    for private_root in (
                        preparation.source,
                        preparation.state_home,
                        preparation.run_root,
                    )
                ):
                    raise ValueError(
                        "managed Claude boundary overlaps source or private runner state"
                    )
        except (OSError, TypeError, ValueError):
            raise fail(
                StopReason.GITLESS_INVOCATION_PROBE_FAILED,
                "the fixed administrator-managed Claude boundary is absent, unsafe, or overlaps "
                "private runner authority",
            ) from None
        if self._managed_claude_boundary is None:
            self._managed_claude_boundary = selected
        return selected

    def acquire_codex_credential(
        self,
        preparation: RunPreparation,
    ) -> CodexCredentialTransaction:
        config = preparation.configuration.project
        environment = preparation.environment
        if not isinstance(environment, EnvironmentReport):
            raise TypeError("production preflight did not return EnvironmentReport")
        assert config.codex_credential_id is not None
        install = self._install(preparation, name="codex")
        executor = SandboxExecutor(
            preparation.blobs,
            limits=config.limits,
            clock=self.clock,
        )
        transaction = CodexCredentialTransaction.acquire(
            config.codex_credential_id,
            preparation.run_id,
            auth_parser=parse_codex_file_auth,
            auth_probe=lambda home: _codex_status_probe(executor, install, home),
            state_home=preparation.state_home,
            evidence_barrier=_codex_artifact_evidence_barrier(
                preparation.state_home,
                config.codex_credential_id,
            ),
        )
        return transaction

    def load_claude_token(self, preparation: RunPreparation) -> str:
        credential_id = preparation.configuration.project.claude_credential_id
        assert credential_id is not None
        return load_claude_setup_token(credential_id, state_home=preparation.state_home)

    def known_secrets(
        self,
        preparation: RunPreparation,
        transaction: WorkflowCredentialTransaction,
        claude_token: str,
    ) -> tuple[KnownSecret, ...]:
        del preparation
        secrets = list(_transaction_codex_known_secrets(transaction))
        secrets.append(KnownSecret("claude-setup-token", claude_token.encode("utf-8")))
        return tuple(secrets)

    def prepare_codex_credential(
        self,
        preparation: RunPreparation,
        transaction: WorkflowCredentialTransaction,
        known_secrets: tuple[KnownSecret, ...],
    ) -> tuple[KnownSecret, ...]:
        if not isinstance(transaction, CodexCredentialTransaction):
            raise fail(
                StopReason.CREDENTIAL_REFRESH_FAILURE,
                "production credential transaction has an unexpected implementation",
            )
        config = preparation.configuration.project
        generated = SanitizedCodexConfig(
            model=config.author_model,
            effort=config.author_effort,
            additional_workspace_denies=config.protected_paths,
            workspace_opt_ins=config.protected_opt_in_paths,
            additional_host_denies=(os.fspath(preparation.run_root),),
        )
        rendered = generated.render()
        try:
            if raw_log_contains_known_secret(rendered, known_secrets):
                raise fail(
                    StopReason.CREDENTIAL_REFRESH_FAILURE,
                    "generated Codex configuration contained dedicated credential bytes",
                )
            environment = preparation.environment
            if not isinstance(environment, EnvironmentReport):
                raise fail(
                    StopReason.CREDENTIAL_REFRESH_FAILURE,
                    "production credential preparation requires exact preflight evidence",
                )
            install = self._install(preparation, name="codex")
            executor = SandboxExecutor(
                preparation.blobs,
                limits=config.limits,
                clock=self.clock,
            )
            authenticated = False
            try:
                authenticated = _codex_status_probe(
                    executor,
                    install,
                    transaction.codex_home,
                )
            finally:
                transaction.capture_candidate_generation()
            if not authenticated:
                raise fail(
                    StopReason.CREDENTIAL_REFRESH_FAILURE,
                    "transactional Codex file authentication failed its status probe",
                )
            refreshed = tuple(
                dict.fromkeys(
                    (*known_secrets, *_transaction_codex_known_secrets(transaction))
                )
            )
            if raw_log_contains_known_secret(rendered, refreshed):
                raise fail(
                    StopReason.CREDENTIAL_REFRESH_FAILURE,
                    "generated Codex configuration collided with refreshed credential bytes",
                )
            return refreshed
        finally:
            # Preparation is deliberately config-free.  The workflow first
            # rescans every task/source/metadata surface against the refreshed
            # generation, then calls install_codex_configuration.
            transaction.remove_candidate_config()

    def install_codex_configuration(
        self,
        preparation: RunPreparation,
        transaction: WorkflowCredentialTransaction,
        known_secrets: tuple[KnownSecret, ...],
    ) -> None:
        if not isinstance(transaction, CodexCredentialTransaction):
            raise fail(
                StopReason.CREDENTIAL_REFRESH_FAILURE,
                "production credential transaction has an unexpected implementation",
            )
        config = preparation.configuration.project
        generated = SanitizedCodexConfig(
            model=config.author_model,
            effort=config.author_effort,
            additional_workspace_denies=config.protected_paths,
            workspace_opt_ins=config.protected_opt_in_paths,
            additional_host_denies=(os.fspath(preparation.run_root),),
        )
        rendered = generated.render()
        installed = False
        try:
            if raw_log_contains_known_secret(rendered, known_secrets):
                raise fail(
                    StopReason.CREDENTIAL_REFRESH_FAILURE,
                    "generated Codex configuration contained dedicated credential bytes",
                )
            install_sanitized_codex_config(transaction, generated)
            installed = True
        finally:
            if not installed:
                transaction.remove_candidate_config()

    def build_runtime(
        self,
        preparation: RunPreparation,
        transaction: WorkflowCredentialTransaction,
        claude_token: str,
        known_secrets: tuple[KnownSecret, ...],
    ) -> RuntimeAdapters:
        environment = preparation.environment
        if not isinstance(environment, EnvironmentReport):
            raise TypeError("production preflight did not return EnvironmentReport")
        config = preparation.configuration.project
        try:
            secret_ledger = _KnownSecretLedger(known_secrets)
            runtime_codex_config = SanitizedCodexConfig(
                model=config.author_model,
                effort=config.author_effort,
                additional_workspace_denies=config.protected_paths,
                workspace_opt_ins=config.protected_opt_in_paths,
                additional_host_denies=(os.fspath(preparation.run_root),),
            ).render()

            def current_secrets() -> tuple[KnownSecret, ...]:
                # Snapshot before every author launch and again at every output
                # boundary.  A refresh from B to C therefore leaves both B and
                # C in the private ledger, alongside the initial A value.
                if preparation.artifacts.content_withheld_due_to_secret:
                    raise fail(
                        StopReason.CREDENTIAL_REFRESH_FAILURE,
                        "credential-tainted evidence remains permanently withheld",
                    )
                try:
                    discovered = _transaction_codex_known_secrets(transaction)
                except (AgentLoopError, UnicodeError, ValueError):
                    preparation.artifacts.withhold_all_content()
                    raise fail(
                        StopReason.CREDENTIAL_REFRESH_FAILURE,
                        "a refreshed credential could not be classified safely",
                    ) from None
                try:
                    changed = secret_ledger.extend(discovered)
                except AgentLoopError:
                    preparation.artifacts.withhold_all_content()
                    raise
                snapshot = secret_ledger.snapshot()
                if changed and raw_log_contains_known_secret(
                    runtime_codex_config,
                    snapshot,
                ):
                    transaction.remove_candidate_config()
                    preparation.artifacts.scrub_known_secrets(snapshot)
                    raise fail(
                        StopReason.CREDENTIAL_REFRESH_FAILURE,
                        "refreshed credential collided with generated Codex configuration",
                    )
                if changed and preparation.artifacts.scrub_known_secrets(snapshot):
                    raise fail(
                        StopReason.CREDENTIAL_REFRESH_FAILURE,
                        "a refreshed credential collided with previously retained evidence",
                    )
                return snapshot

            current_secrets()
            sink = _attempt_sink(
                preparation,
                current_secrets,
            )
            service_sink = _service_attempt_sink(
                preparation,
                current_secrets,
            )
            executor = SandboxExecutor(
                preparation.blobs,
                limits=config.limits,
                service_attempt_sink=service_sink,
                clock=self.clock,
            )
            toolchain = tuple(
                _reviewed_toolchain_mount(path, preparation)
                for path in config.read_only_toolchain_mounts
            )
            codex_install = self._install(preparation, name="codex")
            claude_install = self._install(preparation, name="claude")
            managed_boundary = self._claude_boundary(preparation)
            preparation.artifacts.ensure_directory("control/claude-home")
            claude_config = preparation.run_root / "control" / "claude-home"
            validator = SandboxedValidationAdapter(
                executor,
                tuple(
                    ValidationCheck(
                        f"check-{index:03d}",
                        command,
                        config.validation_timeout_seconds,
                    )
                    for index, command in enumerate(config.checks, start=1)
                ),
                mounts=toolchain,
                max_raw_log_bytes=config.limits.max_raw_log_bytes,
                output_max_bytes=config.limits.max_agent_output_bytes,
                attempt_sink=sink,
                clock=self.clock,
            )
            author = SandboxedCodexAuthorAdapter(
                executor,
                transaction,
                install_mount=codex_install.mount,
                executable=codex_install.executable,
                toolchain_mounts=toolchain,
                timeout_seconds=config.author_timeout_seconds,
                output_max_bytes=config.limits.max_agent_output_bytes,
                model=config.author_model,
                effort=config.author_effort,
                attempt_sink=sink,
                secret_refresh=current_secrets,
                clock=self.clock,
            )
            critic = SandboxedClaudeCriticAdapter(
                executor,
                claude_token,
                install_mount=claude_install.mount,
                executable=claude_install.executable,
                config_dir=claude_config,
                managed_boundary=managed_boundary,
                timeout_seconds=config.critic_timeout_seconds,
                model=config.critic_model,
                effort=config.critic_effort,
                attempt_sink=sink,
                clock=self.clock,
            )
        except AgentLoopError:
            raise
        except (OSError, TypeError, ValueError):
            raise fail(
                StopReason.SANDBOX_SETUP_FAILURE,
                "production runtime adapter construction failed",
            ) from None
        return RuntimeAdapters(author, validator, critic, current_secrets)

    def prove_capabilities(
        self,
        preparation: RunPreparation,
    ) -> None:
        config = preparation.configuration.project
        installs = {
            "codex": self._install(preparation, name="codex"),
            "claude": self._install(preparation, name="claude"),
        }
        managed_boundary = self._claude_boundary(preparation)
        environment = preparation.environment
        if not isinstance(environment, EnvironmentReport):
            raise fail(
                StopReason.GITLESS_INVOCATION_PROBE_FAILED,
                "production capability proof requires the exact preflight report",
            )
        assert config.codex_credential_id is not None
        assert config.claude_credential_id is not None
        assert config.author_model is not None
        assert config.author_effort is not None
        assert config.critic_model is not None
        assert config.critic_effort is not None
        try:
            binding = LiveCapabilityBinding.from_environment_report(
                environment,
                codex_credential_id=config.codex_credential_id,
                claude_credential_id=config.claude_credential_id,
                author_model=config.author_model,
                author_effort=config.author_effort,
                critic_model=config.critic_model,
                critic_effort=config.critic_effort,
                managed_claude_boundary=ManagedClaudeBoundaryCapabilityBinding(
                    policy_path=managed_boundary.policy_mount.source,
                    helper_path=managed_boundary.helper_mount.source,
                    policy_sha256=managed_boundary.policy_sha256,
                    helper_sha256=managed_boundary.helper_sha256,
                    probe_protocol=managed_boundary.protocol,
                    probe_id=managed_boundary.probe_id,
                ),
                codex_install_closure_sha256=installs["codex"].closure_sha256,
                claude_install_closure_sha256=installs["claude"].closure_sha256,
                runtime_closure_sha256=installed_runtime_closure_sha256(),
            )
            verify_live_capability_receipt(
                preparation.state_home / CAPABILITY_RECEIPT_RELATIVE_PATH,
                binding,
            )
        except (CapabilityReceiptError, OSError, TypeError, ValueError):
            raise fail(
                StopReason.GITLESS_INVOCATION_PROBE_FAILED,
                "no fresh private live-gate receipt matches the exact preflight binding",
            ) from None


class _CapturingValidator:
    def __init__(self, delegate: ValidationAdapter) -> None:
        self._delegate = delegate
        self.baseline: ValidationTurn | None = None

    def validate(self, request: ValidationRequest) -> ValidationTurn:
        turn = self._delegate.validate(request)
        if request.baseline is None:
            if self.baseline is not None:
                raise fail(
                    StopReason.RUNNER_INTERNAL_ERROR,
                    "validation adapter produced more than one baseline",
                )
            self.baseline = turn
        return turn


def _confirmation_document(
    preparation: RunPreparation,
    baseline: ValidationTurn,
) -> dict[str, object]:
    config = preparation.configuration.project
    file_bytes = sum(
        entry.size or 0
        for entry in preparation.snapshot.manifest.entries
        if entry.kind is EntryKind.REGULAR
    )
    checks = [
        {
            "check_id": check.check_id,
            "command": check.command,
            "outcome": check.outcome.value,
            "exit_code": check.exit_code,
            "signal": check.signal,
            "timed_out": check.timed_out,
            "output_limited": check.output_limited,
        }
        for check in baseline.summary.checks
    ]
    return {
        "run_id": preparation.run_id,
        "committed_source_revision": preparation.snapshot.revision,
        "committed_tree_object_id": preparation.snapshot.tree_object_id,
        "excluded_source_state": list(preparation.snapshot.warnings),
        "estimated_scope": {
            "subject_entries": len(preparation.snapshot.manifest.entries),
            "regular_file_bytes": file_bytes,
            "max_rounds": config.max_rounds,
            "max_runtime_seconds": config.max_runtime_seconds,
            "author_timeout_seconds": config.author_timeout_seconds,
            "critic_timeout_seconds": config.critic_timeout_seconds,
            "validation_timeout_seconds": config.validation_timeout_seconds,
        },
        "validation_baseline": {
            "subject_fingerprint": baseline.summary.subject_fingerprint,
            "all_pass": baseline.summary.all_pass,
            "checks": checks,
        },
        "paths": {
            "protected": list(config.protected_paths),
            "protected_opt_in": list(config.protected_opt_in_paths),
            "discard_only": list(config.discard_only_paths),
            "opaque_nonsemantic": list(config.opaque_nonsemantic_paths),
            "review_context": list(config.review_context_paths),
            "read_only_toolchain_mounts": list(config.read_only_toolchain_mounts),
        },
        "opaque_nonsemantic_operator_assertion": (
            _OPAQUE_NONSEMANTIC_ASSERTION if config.opaque_nonsemantic_paths else None
        ),
        "permissions": {
            "author": "writable canonical workspace; no Git control plane; generated-command "
            "network denied",
            "validation": "fresh no-network workspace; no credentials or retained artifacts",
            "critic": "fresh empty tool-disabled workspace; sanitized bundle on stdin only",
            "approval_policy": "never",
        },
        "credential_adapters": {
            "codex": "locked ChatGPT-managed file auth",
            "codex_credential_id": config.codex_credential_id,
            "claude": "dedicated setup token",
            "claude_credential_id": config.claude_credential_id,
        },
        "models": {
            "author_model": config.author_model,
            "author_effort": config.author_effort,
            "critic_model": config.critic_model,
            "critic_effort": config.critic_effort,
        },
        "stop_conditions": [
            "critic LGTM plus passing validation",
            "round cap or repeated non-success state",
            "wall-clock or per-process timeout",
            "validation, containment, credential, or integrity failure",
            "operator interrupt",
        ],
    }


class _ConfirmingAuthor:
    def __init__(
        self,
        delegate: AuthorAdapter,
        validator: _CapturingValidator,
        preparation: RunPreparation,
        io: WorkflowIO,
        *,
        assume_yes: bool,
    ) -> None:
        self._delegate = delegate
        self._validator = validator
        self._preparation = preparation
        self._io = io
        self._assume_yes = assume_yes
        self._confirmed = False

    def turn(self, request: AuthorRequest) -> AuthorTurn:
        if not self._confirmed:
            baseline = self._validator.baseline
            if baseline is None:
                raise fail(
                    StopReason.RUNNER_INTERNAL_ERROR,
                    "operator confirmation was reached before baseline validation",
                )
            rendered = json.dumps(
                _confirmation_document(self._preparation, baseline),
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                indent=2,
            )
            self._io.write("Paid-run preflight (no credential values):\n" + rendered)
            if not self._assume_yes:
                try:
                    response = self._io.read("Type yes to begin model spending: ")
                except EOFError:
                    response = ""
                if response != "yes":
                    raise fail(
                        StopReason.USER_INTERRUPT,
                        "operator declined paid-run confirmation",
                    )
            self._confirmed = True
        return self._delegate.turn(request)


def _settings(config: ProjectConfig) -> LoopSettings:
    return LoopSettings(
        max_rounds=config.max_rounds,
        max_runtime_seconds=config.max_runtime_seconds,
        protected_patterns=config.protected_paths,
        opaque_patterns=config.opaque_nonsemantic_paths,
        context_paths=tuple(path.encode("utf-8") for path in config.review_context_paths),
        requested_author_model=config.author_model,
        requested_author_effort=config.author_effort,
        requested_critic_model=config.critic_model,
        requested_critic_effort=config.critic_effort,
        max_raw_log_bytes=config.limits.max_raw_log_bytes,
        limits=config.limits,
    )


def _result_from_exception(
    exception: BaseException,
    subject: SubjectManifest,
    *,
    rounds_completed: int = 0,
    thread_id: str | None = None,
    known_secrets: tuple[KnownSecret, ...] = (),
    precredential: bool = False,
) -> LoopResult:
    if isinstance(exception, AgentLoopError):
        reason = exception.reason
        detail = exception.detail
        if precredential:
            detail = "pre-credential operation failed closed"
        else:
            try:
                encoded_detail = detail.encode("utf-8", "strict")
            except UnicodeEncodeError:
                encoded_detail = b""
                detail_unsafe = True
            else:
                detail_unsafe = raw_log_contains_known_secret(
                    encoded_detail,
                    known_secrets,
                )
            if detail_unsafe:
                reason = StopReason.CREDENTIAL_REFRESH_FAILURE
                detail = "typed failure detail was withheld at the credential boundary"
    elif isinstance(exception, KeyboardInterrupt):
        reason = StopReason.USER_INTERRUPT
        detail = "operator interrupted the active run"
    else:
        reason = StopReason.RUNNER_INTERNAL_ERROR
        detail = f"unexpected internal exception: {type(exception).__name__}"
    return LoopResult(
        exit_code_for(reason),
        reason,
        rounds_completed,
        subject,
        thread_id,
        detail,
    )


class _ExistingBlobWitness:
    """Manifest builder sink that refuses to persist newly observed bytes."""

    def __init__(self, blobs: BlobReader) -> None:
        self._blobs = blobs

    def put_blob(self, data: bytes) -> str:
        digest = sha256_hex(data)
        if self._blobs.read_blob(digest) != data:
            raise fail(
                StopReason.OUT_OF_BAND_CHANGE,
                "authoritative subject bytes do not match retained blob identity",
            )
        return digest


def _relative_directory_filesystem(
    root: ConfinedFilesystem,
    destination: bytes,
    *,
    create: bool,
) -> ConfinedFilesystem:
    descriptor = (
        root.mkdirs(destination)
        if create
        else root.open_directory(destination)
    )
    try:
        return ConfinedFilesystem.from_fd(descriptor)
    finally:
        os.close(descriptor)


def _materialized_manifest_locked(
    preparation: RunPreparation,
    root: ConfinedFilesystem,
    destination: bytes,
) -> SubjectManifest:
    filesystem = _relative_directory_filesystem(
        root,
        destination,
        create=False,
    )
    try:
        records = filesystem.scan_records(limits=preparation.configuration.project.limits)
        return build_manifest_from_scan(
            records,
            _ExistingBlobWitness(preparation.blobs),
            limits=preparation.configuration.project.limits,
        )
    finally:
        filesystem.close()


def _materialized_manifest(
    preparation: RunPreparation,
    destination: bytes,
) -> SubjectManifest:
    with preparation.artifacts.retained_filesystem() as root:
        return _materialized_manifest_locked(preparation, root, destination)


def _materialize_subject_directory(
    preparation: RunPreparation,
    subject: SubjectManifest,
    destination: bytes,
) -> None:
    verify_manifest_blobs(subject, preparation.blobs)
    with preparation.artifacts.retained_filesystem() as root:
        filesystem = _relative_directory_filesystem(
            root,
            destination,
            create=True,
        )
        try:
            if filesystem.scan_records(limits=preparation.configuration.project.limits):
                raise fail(
                    StopReason.OUT_OF_BAND_CHANGE,
                    "authoritative subject destination was not empty",
                )
            filesystem.materialize_manifest(
                subject,
                preparation.blobs,
                limits=preparation.configuration.project.limits,
            )
        finally:
            filesystem.close()
        observed = _materialized_manifest_locked(preparation, root, destination)
        if observed != subject:
            raise fail(
                StopReason.OUT_OF_BAND_CHANGE,
                "authoritative subject failed normalized materialization verification",
            )


class _AuthoritativeSubjectGuard:
    """Publish and verify one live private authoritative-tree witness per state."""

    def __init__(self, preparation: RunPreparation) -> None:
        self._preparation = preparation
        self._current: SubjectManifest | None = None
        self._generation = 0

    def initialize(self, subject: SubjectManifest) -> None:
        if self._current is not None:
            raise fail(StopReason.RUNNER_INTERNAL_ERROR, "subject guard initialized twice")
        self._preparation.artifacts.ensure_directory("subjects/history")
        _materialize_subject_directory(
            self._preparation,
            subject,
            b"subjects/base",
        )
        _materialize_subject_directory(
            self._preparation,
            subject,
            b"subjects/current",
        )
        self._current = subject

    def verify(self, subject: SubjectManifest) -> None:
        if self._current != subject:
            raise fail(
                StopReason.OUT_OF_BAND_CHANGE,
                "runner subject and authoritative-tree witness diverged",
            )
        verify_manifest_blobs(subject, self._preparation.blobs)
        try:
            observed = _materialized_manifest(
                self._preparation,
                b"subjects/current",
            )
        except AgentLoopError as exception:
            if exception.reason is StopReason.CREDENTIAL_REFRESH_FAILURE:
                raise
            raise fail(
                StopReason.OUT_OF_BAND_CHANGE,
                "authoritative subject witness cannot be verified",
            ) from None
        except (OSError, TypeError, ValueError):
            raise fail(
                StopReason.OUT_OF_BAND_CHANGE,
                "authoritative subject witness cannot be verified",
            ) from None
        if observed != subject:
            raise fail(
                StopReason.OUT_OF_BAND_CHANGE,
                "authoritative subject witness changed out of band",
            )

    def publish(self, subject: SubjectManifest) -> None:
        if self._current is None:
            raise fail(StopReason.RUNNER_INTERNAL_ERROR, "subject guard is not initialized")
        self.verify(self._current)
        staging_name = f".next-{self._generation + 1:03d}"
        staging = b"subjects/" + staging_name.encode("ascii")
        _materialize_subject_directory(self._preparation, subject, staging)

        with self._preparation.artifacts.retained_filesystem() as root:
            subjects_fd = root.open_directory(b"subjects")
            try:
                history_fd = root.open_directory(b"subjects/history")
            except BaseException:
                os.close(subjects_fd)
                raise
            try:
                history_name = f"{self._generation:03d}".encode("ascii")
                try:
                    os.stat(history_name, dir_fd=history_fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise fail(
                        StopReason.OUT_OF_BAND_CHANGE,
                        "authoritative subject history destination already exists",
                    )
                os.rename(
                    b"current",
                    history_name,
                    src_dir_fd=subjects_fd,
                    dst_dir_fd=history_fd,
                )
                os.fsync(history_fd)
                os.rename(
                    staging_name.encode("ascii"),
                    b"current",
                    src_dir_fd=subjects_fd,
                    dst_dir_fd=subjects_fd,
                )
                os.fsync(subjects_fd)
            except OSError:
                raise fail(
                    StopReason.OUT_OF_BAND_CHANGE,
                    "authoritative subject witness could not be atomically advanced",
                ) from None
            finally:
                os.close(history_fd)
                os.close(subjects_fd)
        self._generation += 1
        self._current = subject
        self.verify(subject)


def _materialize_final(preparation: RunPreparation, subject: SubjectManifest) -> None:
    observed = _materialized_manifest(
        preparation,
        b"subjects/current",
    )
    if observed != subject:
        raise fail(
            StopReason.OUT_OF_BAND_CHANGE,
            "final authoritative subject witness does not match the loop result",
        )


def _promote_snapshot_blobs(
    snapshot: GitSourceSnapshot,
    source: BlobReader,
    destination: BlobStore,
) -> None:
    for entry in snapshot.manifest.entries:
        if entry.kind is not EntryKind.REGULAR:
            continue
        assert entry.blob_sha256 is not None
        data = source.read_blob(entry.blob_sha256)
        if destination.put_blob(data) != entry.blob_sha256:
            raise fail(
                StopReason.OUT_OF_BAND_CHANGE,
                "staged source blob changed while entering retained storage",
            )
    verify_manifest_blobs(snapshot.manifest, destination)


def _journal_metadata(preparation: RunPreparation) -> dict[str, object]:
    config = preparation.configuration.project
    return {
        "source_revision": preparation.snapshot.revision,
        "source_tree_object_id": preparation.snapshot.tree_object_id,
        "canonical_source": os.fspath(preparation.source),
        "source_warnings": list(preparation.snapshot.warnings),
        "environment": _environment_json(preparation.environment),
        "credential_identifiers": {
            "codex": config.codex_credential_id,
            "claude": config.claude_credential_id,
        },
    }


def _safe_finish(journal: ArtifactRunJournal, result: LoopResult) -> LoopResult:
    journal.finish(result)
    return result


def _secondary_error(
    exception: BaseException,
    *,
    phase: str,
    known_secrets: tuple[KnownSecret, ...],
) -> dict[str, object]:
    if isinstance(exception, AgentLoopError):
        safe = _result_from_exception(
            exception,
            SubjectManifest.empty(),
            known_secrets=known_secrets,
        )
        return {
            "phase": phase,
            "stop_reason": safe.stop_reason.value,
            "detail": safe.detail,
        }
    if isinstance(exception, KeyboardInterrupt):
        return {
            "phase": phase,
            "stop_reason": StopReason.USER_INTERRUPT.value,
            "detail": "operator interrupted finalization",
        }
    return {
        "phase": phase,
        "stop_reason": StopReason.RUNNER_INTERNAL_ERROR.value,
        "detail": f"unexpected finalization exception: {type(exception).__name__}",
    }


def _post_result_failure(
    journal: ArtifactRunJournal,
    artifacts: ArtifactStore,
    result: LoopResult,
    exception: BaseException,
    *,
    phase: str,
    secondary_errors: list[dict[str, object]],
    known_secrets: tuple[KnownSecret, ...],
) -> LoopResult:
    classified = _result_from_exception(
        exception,
        result.subject,
        rounds_completed=result.rounds_completed,
        thread_id=result.thread_id,
        known_secrets=known_secrets,
    )
    if classified.stop_reason is StopReason.CREDENTIAL_REFRESH_FAILURE:
        return _safe_finish(journal, classified)
    if result.exit_code is not ExitCode.SUCCESS:
        secondary_errors.append(
            _secondary_error(
                exception,
                phase=phase,
                known_secrets=known_secrets,
            )
        )
        artifacts.write_json("artifacts/finalization-errors.json", secondary_errors)
        return result
    return _safe_finish(
        journal,
        classified,
    )


def _precredential_execution_inputs(
    args: argparse.Namespace,
    backend: WorkflowBackend,
) -> tuple[
    RunConfiguration,
    Path,
    str,
    Path,
    Path,
    str,
    Path,
]:
    """Resolve operator inputs while no credential-derived diagnostic is safe."""

    configuration = resolve_run_configuration(args)
    task_path = _optional_argument(args, "task")
    if not isinstance(task_path, Path):
        raise fail(StopReason.SANDBOX_SETUP_FAILURE, "a task file is required")
    task = read_task(task_path, max_bytes=configuration.project.limits.max_field_bytes)
    state_home_argument = _optional_argument(args, "state_home")
    if state_home_argument is not None and not isinstance(state_home_argument, Path):
        raise fail(
            StopReason.SANDBOX_SETUP_FAILURE,
            "state home must be a normalized absolute non-root path",
        )
    try:
        state_home = xdg_state_home(state_home=state_home_argument)
    except (TypeError, ValueError):
        raise fail(
            StopReason.SANDBOX_SETUP_FAILURE,
            "state home must be a normalized absolute non-root path",
        ) from None
    source = backend.canonical_source()
    config_path = _optional_argument(args, "config")
    if not isinstance(config_path, Path):
        config_path = Path(".agent-loop.toml")
    configuration = _protect_control_inputs(
        configuration,
        source,
        (task_path, config_path),
    )
    _reject_control_path_overlaps(source, state_home, configuration)
    run_id = backend.new_run_id()
    run_root = state_home / "agent-loop" / "runs" / run_id
    return configuration, task_path, task, state_home, source, run_id, run_root


def execute_run(
    args: argparse.Namespace,
    *,
    backend: WorkflowBackend | None = None,
    io: WorkflowIO | None = None,
) -> int:
    """Execute one new non-resumable run and return its stable exit category."""

    selected_backend = backend or ProductionWorkflowBackend()
    selected_io = io or WorkflowIO()
    try:
        (
            configuration,
            task_path,
            task,
            state_home,
            source,
            run_id,
            run_root,
        ) = _precredential_execution_inputs(args, selected_backend)
    except AgentLoopError as exception:
        raise fail(
            exception.reason,
            "pre-credential run input preparation failed closed",
        ) from None

    source_lock: Closeable | None = None
    artifacts: ArtifactStore | None = None
    transaction: WorkflowCredentialTransaction | None = None
    preparation: RunPreparation | None = None
    journal: ArtifactRunJournal | None = None
    result: LoopResult | None = None
    subject_storage_ready = False
    result_subject_fingerprint_withheld = False
    retained_known_secrets: tuple[KnownSecret, ...] = ()
    runtime_secret_provider: Callable[[], tuple[KnownSecret, ...]] | None = None
    pending_exception: BaseException | None = None
    secondary_errors: list[dict[str, object]] = []
    all_optional_output_withheld = False
    try:
        try:
            source_lock = selected_backend.acquire_source_lock(
                source,
                run_id,
                state_home=state_home,
            )
            artifacts = selected_backend.create_artifacts(run_root)
        except AgentLoopError as exception:
            raise fail(
                exception.reason,
                "pre-credential private run initialization failed closed",
            ) from None
        blobs: BlobStore = _PrecredentialBlobStore(configuration.project.limits)
        try:
            environment = selected_backend.preflight(configuration)
            snapshot = selected_backend.extract_source(
                source,
                blobs,
                limits=configuration.project.limits,
            )
        except AgentLoopError as exception:
            raise fail(
                exception.reason,
                "pre-credential environment or committed-source preparation failed closed",
            ) from None
        preparation = RunPreparation(
            run_id,
            source,
            state_home,
            run_root,
            task,
            configuration,
            environment,
            snapshot,
            artifacts,
            blobs,
        )
        journal = ArtifactRunJournal(artifacts, run_id, _journal_metadata(preparation))
        settings = _settings(configuration.project)
        started = selected_backend.clock()
        deadline = started + settings.max_runtime_seconds
        if not math.isfinite(deadline) or deadline < 0:
            raise fail(StopReason.RUNNER_INTERNAL_ERROR, "monotonic run deadline is invalid")
        journal.precredential_start(
            base=snapshot.manifest,
            deadline=deadline,
            settings=settings,
        )

        try:
            selected_backend.prove_capabilities(preparation)
            transaction = selected_backend.acquire_codex_credential(preparation)
            claude_token = selected_backend.load_claude_token(preparation)
            known_secrets = selected_backend.known_secrets(
                preparation,
                transaction,
                claude_token,
            )
            retained_known_secrets = known_secrets
            project_config_document = {
                **_configuration_mapping(configuration.project),
                "opaque_nonsemantic_operator_assertion": (
                    _OPAQUE_NONSEMANTIC_ASSERTION
                    if configuration.project.opaque_nonsemantic_paths
                    else None
                ),
                "codex_executable": os.fspath(configuration.codex_executable),
                "claude_executable": os.fspath(configuration.claude_executable),
            }
            configuration_withheld = _json_tree_contains_known_secret(
                project_config_document,
                known_secrets,
            )
            metadata_withheld = journal.pending_metadata_contains_known_secret(known_secrets)
            task_withheld = raw_log_contains_known_secret(
                task.encode("utf-8"),
                known_secrets,
            )
            subject_withheld = _manifest_contains_known_secret(
                snapshot.manifest,
                blobs,
                known_secrets,
            )
            result_subject_fingerprint_withheld = subject_withheld
            if (
                configuration_withheld
                or metadata_withheld
                or task_withheld
                or subject_withheld
            ):
                journal.task_input(task, content_withheld=task_withheld)
                journal.subject_input(snapshot.manifest, content_withheld=subject_withheld)
                artifacts.write_json(
                    "artifacts/project-config.meta.json",
                    {
                        "schema_version": 1,
                        "content_withheld": configuration_withheld,
                    },
                )
                raise fail(
                    StopReason.CREDENTIAL_REFRESH_FAILURE,
                    "run metadata, configuration, task, or committed source contained dedicated "
                    "credential bytes",
                )
            known_secrets = selected_backend.prepare_codex_credential(
                preparation,
                transaction,
                known_secrets,
            )
            retained_known_secrets = known_secrets
            configuration_withheld = _json_tree_contains_known_secret(
                project_config_document,
                known_secrets,
            )
            metadata_withheld = journal.pending_metadata_contains_known_secret(known_secrets)
            task_withheld = raw_log_contains_known_secret(
                task.encode("utf-8"),
                known_secrets,
            )
            subject_withheld = _manifest_contains_known_secret(
                snapshot.manifest,
                blobs,
                known_secrets,
            )
            result_subject_fingerprint_withheld = (
                result_subject_fingerprint_withheld or subject_withheld
            )
            journal.task_input(task, content_withheld=task_withheld)
            journal.subject_input(snapshot.manifest, content_withheld=subject_withheld)
            artifacts.write_json(
                "artifacts/project-config.meta.json",
                {
                    "schema_version": 1,
                    "content_withheld": configuration_withheld,
                },
            )
            if (
                configuration_withheld
                or metadata_withheld
                or task_withheld
                or subject_withheld
            ):
                transaction.remove_candidate_config()
                raise fail(
                    StopReason.CREDENTIAL_REFRESH_FAILURE,
                    "refreshed credential collided with run metadata, configuration, task, or "
                    "committed source bytes",
                )
            selected_backend.install_codex_configuration(
                preparation,
                transaction,
                known_secrets,
            )
            journal.start(
                task=task,
                base=snapshot.manifest,
                deadline=deadline,
                settings=settings,
            )
            artifacts.write_json(
                "artifacts/project-config.json",
                project_config_document,
            )
            retained_blobs = ContentAddressedBlobStore(
                artifacts,
                max_blob_bytes=configuration.project.limits.max_file_bytes,
            )
            _promote_snapshot_blobs(snapshot, blobs, retained_blobs)
            preparation = replace(preparation, blobs=retained_blobs)
            blobs = retained_blobs
            subject_guard = _AuthoritativeSubjectGuard(preparation)
            subject_guard.initialize(snapshot.manifest)
            subject_storage_ready = True
            runtime = selected_backend.build_runtime(
                preparation,
                transaction,
                claude_token,
                known_secrets,
            )
            runtime_secret_provider = runtime.known_secret_provider
            validator = _CapturingValidator(runtime.validator)
            author = _ConfirmingAuthor(
                runtime.author,
                validator,
                preparation,
                selected_io,
                assume_yes=bool(args.yes),
            )
            policy = PathPolicy.from_strings(
                protected_patterns=configuration.project.protected_paths,
                discard_only_patterns=configuration.project.discard_only_paths,
                opaque_nonsemantic_patterns=configuration.project.opaque_nonsemantic_paths,
                protected_opt_in_patterns=configuration.project.protected_opt_in_paths,
            )
            result = LoopRunner(
                author=author,
                validator=validator,
                critic=runtime.critic,
                blobs=blobs,
                policy=policy,
                journal=journal,
                clock=selected_backend.clock,
                integrity_guard=subject_guard.verify,
                publish_subject=subject_guard.publish,
                known_secrets=known_secrets,
                known_secret_provider=runtime.known_secret_provider,
            ).run(
                task,
                snapshot.manifest,
                settings,
                monotonic_deadline=deadline,
                journal_prestarted=True,
            )
        except (KeyboardInterrupt, Exception) as exception:
            result = _safe_finish(
                journal,
                _result_from_exception(
                    exception,
                    snapshot.manifest,
                    known_secrets=retained_known_secrets,
                    precredential=not retained_known_secrets,
                ),
            )

        assert result is not None
        if subject_storage_ready:
            try:
                _materialize_final(preparation, result.subject)
            except (KeyboardInterrupt, Exception) as exception:
                result = _post_result_failure(
                    journal,
                    artifacts,
                    result,
                    exception,
                    phase="final_subject_materialization",
                    secondary_errors=secondary_errors,
                    known_secrets=retained_known_secrets,
                )

        if transaction is not None:
            finalization_safe = True
            try:
                transaction.reconcile_after_turn()
            except (KeyboardInterrupt, Exception) as exception:
                finalization_safe = False
                result = _post_result_failure(
                    journal,
                    artifacts,
                    result,
                    exception,
                    phase="credential_final_reconcile",
                    secondary_errors=secondary_errors,
                    known_secrets=retained_known_secrets,
                )
            try:
                discovered = (
                    runtime_secret_provider()
                    if runtime_secret_provider is not None
                    else _transaction_codex_known_secrets(transaction)
                )
                retained_known_secrets = tuple(
                    dict.fromkeys((*retained_known_secrets, *discovered))
                )
                final_generated_config = SanitizedCodexConfig(
                    model=configuration.project.author_model,
                    effort=configuration.project.author_effort,
                    additional_workspace_denies=configuration.project.protected_paths,
                    workspace_opt_ins=(
                        configuration.project.protected_opt_in_paths
                    ),
                    additional_host_denies=(os.fspath(preparation.run_root),),
                ).render()
                if raw_log_contains_known_secret(
                    final_generated_config,
                    retained_known_secrets,
                ):
                    transaction.remove_candidate_config()
                    raise fail(
                        StopReason.CREDENTIAL_REFRESH_FAILURE,
                        "final credential generation collided with Codex configuration",
                    )
                if artifacts.scrub_known_secrets(retained_known_secrets):
                    raise fail(
                        StopReason.CREDENTIAL_REFRESH_FAILURE,
                        "final credential generation collided with retained evidence",
                    )
            except (KeyboardInterrupt, Exception) as exception:
                finalization_safe = False
                if runtime_secret_provider is not None:
                    try:
                        recovered_history = runtime_secret_provider()
                    except (KeyboardInterrupt, Exception):
                        recovered_history = ()
                    else:
                        retained_known_secrets = tuple(
                            dict.fromkeys(
                                (*retained_known_secrets, *recovered_history)
                            )
                        )
                if not artifacts.content_withheld_due_to_secret:
                    artifacts.withhold_all_content()
                if (
                    isinstance(exception, AgentLoopError)
                    and exception.reason is StopReason.CREDENTIAL_REFRESH_FAILURE
                ):
                    classified_exception: BaseException = exception
                else:
                    classified_exception = fail(
                        StopReason.CREDENTIAL_REFRESH_FAILURE,
                        "final credential generation could not be classified safely",
                    )
                result = _post_result_failure(
                    journal,
                    artifacts,
                    result,
                    classified_exception,
                    phase="credential_history_snapshot",
                    secondary_errors=secondary_errors,
                    known_secrets=retained_known_secrets,
                )
            if finalization_safe:
                try:
                    transaction.finalize_reconciled()
                except (KeyboardInterrupt, Exception) as exception:
                    result = _post_result_failure(
                        journal,
                        artifacts,
                        result,
                        exception,
                        phase="credential_completion",
                        secondary_errors=secondary_errors,
                        known_secrets=retained_known_secrets,
                    )
    except BaseException as exception:
        pending_exception = exception
    finally:
        if transaction is not None:
            try:
                transaction.close()
            except BaseException as exception:
                if pending_exception is None and journal is not None and result is not None:
                    assert artifacts is not None
                    result = _post_result_failure(
                        journal,
                        artifacts,
                        result,
                        exception,
                        phase="credential_close",
                        secondary_errors=secondary_errors,
                        known_secrets=retained_known_secrets,
                    )
                elif pending_exception is None:
                    pending_exception = exception
        if source_lock is not None:
            try:
                source_lock.close()
            except BaseException as exception:
                if (
                    pending_exception is None
                    and journal is not None
                    and artifacts is not None
                    and result is not None
                ):
                    result = _post_result_failure(
                        journal,
                        artifacts,
                        result,
                        exception,
                        phase="source_lock_close",
                        secondary_errors=secondary_errors,
                        known_secrets=retained_known_secrets,
                    )
                elif pending_exception is None:
                    pending_exception = exception
        if artifacts is not None:
            try:
                all_optional_output_withheld = (
                    artifacts.content_withheld_due_to_secret
                )
            except BaseException as exception:
                # If the durable latch cannot be inspected, release no optional
                # operator output.  Preserve the inspection failure only when
                # it would not replace an earlier primary failure.
                all_optional_output_withheld = True
                if pending_exception is None and (
                    result is None or result.exit_code is ExitCode.SUCCESS
                ):
                    pending_exception = exception
            try:
                artifacts.close()
            except BaseException as exception:
                if pending_exception is None and (
                    result is None or result.exit_code is ExitCode.SUCCESS
                ):
                    pending_exception = exception

    if pending_exception is not None:
        raise pending_exception
    if preparation is None or result is None:
        raise fail(StopReason.RUNNER_INTERNAL_ERROR, "run orchestration produced no result")
    output: dict[str, object] = {
        "stop_reason": result.stop_reason.value,
        "exit_code": int(result.exit_code),
        "rounds_completed": result.rounds_completed,
    }
    run_id_withheld = all_optional_output_withheld or _json_tree_contains_known_secret(
        preparation.run_id,
        retained_known_secrets,
    )
    run_root_withheld = all_optional_output_withheld or _json_tree_contains_known_secret(
        os.fspath(preparation.run_root),
        retained_known_secrets,
    )
    fingerprint_withheld = (
        all_optional_output_withheld
        or result_subject_fingerprint_withheld
        or _manifest_metadata_contains_known_secret(
            result.subject,
            retained_known_secrets,
        )
    )
    if not run_id_withheld:
        output["run_id"] = preparation.run_id
    if not run_root_withheld:
        output["run_root"] = os.fspath(preparation.run_root)
    if not fingerprint_withheld:
        output["subject_fingerprint"] = result.subject.fingerprint
    if run_id_withheld or run_root_withheld or fingerprint_withheld:
        output["operator_output_content_withheld"] = True
    selected_io.write(
        json.dumps(
            output,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
        )
    )
    return int(result.exit_code)


__all__ = [
    "ProductionWorkflowBackend",
    "ReviewedInstall",
    "RunConfiguration",
    "RunPreparation",
    "RuntimeAdapters",
    "WorkflowBackend",
    "WorkflowCredentialTransaction",
    "WorkflowIO",
    "execute_run",
    "parse_codex_file_auth",
    "read_task",
    "resolve_run_configuration",
]
