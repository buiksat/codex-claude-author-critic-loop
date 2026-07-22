"""Serial composition of already-proven author, validation, and critic boundaries."""

from __future__ import annotations

import json
import os
import socket
import time
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field
from typing import Literal, Protocol

from .artifacts import ArtifactStore
from .constants import DEFAULT_MAX_RAW_LOG_BYTES, Limits
from .declassify import (
    KnownSecret,
    ValidationCriticEvidence,
    declassify_validation,
    raw_log_contains_known_secret,
)
from .diagnostic_patch import render_diagnostic_patch
from .errors import AgentLoopError, ExitCode, StopReason, exit_code_for, fail
from .manifests import SubjectManifest, reconcile_candidate
from .models import BlobReader, ManifestChange, PathDisposition, PathPolicy
from .progress import FindingProgress, ProgressState, StallDetector, ValidationProgress
from .prompts import (
    FindingLedgerItem,
    ReviewBundle,
    build_initial_author_prompt,
    build_review_bundle,
    build_revision_author_prompt,
)
from .schemas import ApprovalContext, CriticReview, Finding, validate_critic_review
from .state_machine import FatalLatch, RoundObservation, decide
from .validation import (
    CheckExecution,
    CheckOutcome,
    ClassifiedCheck,
    ValidationSummary,
    classify_validations,
    verify_validation_mutation,
)

Clock = Callable[[], float]
ValidationAttemptPhase = Literal["baseline", "validation", "opaque"]
_WITHHELD_SUBJECT_FINGERPRINT = "0" * 64


@dataclass(frozen=True, slots=True)
class AuthorRequest:
    round_number: int
    subject: SubjectManifest
    prompt: str
    thread_id: str | None
    deadline: float


@dataclass(frozen=True, slots=True)
class AuthorTurn:
    candidate: SubjectManifest
    thread_id: str
    final_message: str
    events: tuple[dict[str, object], ...] = ()
    usage: dict[str, object] | None = None
    observed_model: str | None = None
    observed_effort: str | None = None


class AuthorAdapter(Protocol):
    def turn(self, request: AuthorRequest) -> AuthorTurn: ...


@dataclass(frozen=True, slots=True)
class ValidationRequest:
    subject: SubjectManifest
    baseline: ValidationSummary | None
    deadline: float


@dataclass(frozen=True, slots=True)
class ValidationTurn:
    summary: ValidationSummary
    result_manifest: SubjectManifest
    raw_log: bytes


class ValidationAdapter(Protocol):
    def validate(self, request: ValidationRequest) -> ValidationTurn: ...


def _without_validation_raw(turn: ValidationTurn) -> ValidationTurn:
    return ValidationTurn(turn.summary, turn.result_manifest, b"")


@dataclass(frozen=True, slots=True)
class CriticRequest:
    round_number: int
    bundle: ReviewBundle
    approval: ApprovalContext
    deadline: float


@dataclass(frozen=True, slots=True)
class CriticTurn:
    review: CriticReview
    completed_at: float
    envelope: dict[str, object]
    total_cost_usd: float | None = None
    observed_model: str | None = None
    observed_effort: str | None = None


class CriticAdapter(Protocol):
    def review(self, request: CriticRequest) -> CriticTurn: ...


@dataclass(frozen=True, slots=True)
class LoopSettings:
    max_rounds: int = 3
    max_runtime_seconds: float = 45 * 60
    protected_patterns: tuple[str, ...] = ()
    opaque_patterns: tuple[str, ...] = ()
    context_paths: tuple[bytes, ...] = ()
    requested_author_model: str | None = None
    requested_author_effort: str | None = None
    requested_critic_model: str | None = None
    requested_critic_effort: str | None = None
    max_raw_log_bytes: int = DEFAULT_MAX_RAW_LOG_BYTES
    limits: Limits = field(default_factory=Limits)

    def __post_init__(self) -> None:
        if self.max_rounds < 1 or self.max_runtime_seconds <= 0 or self.max_raw_log_bytes <= 0:
            raise ValueError("round and runtime limits must be positive")
        if not isinstance(self.limits, Limits):
            raise TypeError("limits must be a Limits instance")


@dataclass(frozen=True, slots=True)
class LoopResult:
    exit_code: ExitCode
    stop_reason: StopReason
    rounds_completed: int
    subject: SubjectManifest
    thread_id: str | None
    detail: str


class RunJournal(Protocol):
    def start(
        self,
        *,
        task: str,
        base: SubjectManifest,
        deadline: float,
        settings: LoopSettings,
    ) -> None: ...

    def baseline(self, turn: ValidationTurn, evidence: ValidationCriticEvidence) -> None: ...

    def task_input(self, task: str, *, content_withheld: bool) -> None: ...

    def subject_input(
        self,
        subject: SubjectManifest,
        *,
        content_withheld: bool,
    ) -> None: ...

    def validation_attempt(
        self,
        round_number: int | None,
        phase: ValidationAttemptPhase,
        expected_subject: SubjectManifest,
        turn: ValidationTurn,
        retained_raw_log: bytes,
        raw_log_truncated: bool,
        raw_log_withheld: bool,
        result_subject_withheld: bool,
        summary_withheld: bool,
    ) -> None: ...

    def opaque_proof(
        self,
        round_number: int | None,
        counterfactual: SubjectManifest,
        turn: ValidationTurn,
        equivalent: bool,
    ) -> None: ...

    def author_attempt(
        self,
        round_number: int,
        turn: AuthorTurn,
        max_output_bytes: int,
        content_withheld: bool,
    ) -> None: ...

    def author(
        self,
        round_number: int,
        turn: AuthorTurn,
        authoritative: SubjectManifest,
        semantic: tuple[ManifestChange, ...],
        opaque: tuple[ManifestChange, ...],
        discarded: tuple[ManifestChange, ...],
        base: SubjectManifest,
        blobs: BlobReader,
    ) -> None: ...

    def validation(
        self,
        round_number: int,
        turn: ValidationTurn,
        evidence: ValidationCriticEvidence,
        classified: tuple[ClassifiedCheck, ...],
    ) -> None: ...

    def critic(self, round_number: int, turn: CriticTurn, bundle: ReviewBundle) -> None: ...

    def critic_attempt(
        self,
        round_number: int,
        turn: CriticTurn,
        max_output_bytes: int,
        content_withheld: bool,
    ) -> None: ...

    def finish(self, result: LoopResult) -> None: ...


class NullRunJournal:
    def start(self, **_values: object) -> None:
        return None

    def baseline(self, _turn: ValidationTurn, _evidence: ValidationCriticEvidence) -> None:
        return None

    def task_input(self, _task: str, *, content_withheld: bool) -> None:
        del content_withheld
        return None

    def subject_input(
        self,
        _subject: SubjectManifest,
        *,
        content_withheld: bool,
    ) -> None:
        del content_withheld
        return None

    def validation_attempt(self, *_values: object, **_named: object) -> None:
        return None

    def opaque_proof(self, *_values: object, **_named: object) -> None:
        return None

    def author_attempt(self, *_values: object, **_named: object) -> None:
        return None

    def author(self, *_values: object, **_named: object) -> None:
        return None

    def validation(self, *_values: object, **_named: object) -> None:
        return None

    def critic(self, *_values: object, **_named: object) -> None:
        return None

    def critic_attempt(self, *_values: object, **_named: object) -> None:
        return None

    def finish(self, _result: LoopResult) -> None:
        return None


def _check_json(check: CheckExecution) -> dict[str, object]:
    return {
        "check_id": check.check_id,
        "command": check.command,
        "started_at": check.started_at,
        "completed_at": check.completed_at,
        "exit_code": check.exit_code,
        "signal": check.signal,
        "timed_out": check.timed_out,
        "infrastructure_failure": check.infrastructure_failure,
        "process_started": check.process_started,
        "output_limited": check.output_limited,
        "outcome": check.outcome.value,
    }


def _validation_behavior_signature(turn: ValidationTurn) -> tuple[object, ...]:
    checks = tuple(
        (
            check.check_id,
            check.command,
            check.exit_code,
            check.signal,
            check.timed_out,
            check.infrastructure_failure,
            check.process_started,
            check.output_limited,
            check.outcome.value,
        )
        for check in turn.summary.checks
    )
    return checks, turn.raw_log


def _without_opaque_entries(
    subject: SubjectManifest,
    policy: PathPolicy,
    limits: Limits,
) -> SubjectManifest:
    return SubjectManifest.build(
        (
            entry
            for entry in subject.entries
            if policy.classify(entry.path) is not PathDisposition.OPAQUE_NONSEMANTIC
        ),
        limits=limits,
    )


def _restore_opaque_base_entries(
    base: SubjectManifest,
    subject: SubjectManifest,
    changes: tuple[ManifestChange, ...],
    limits: Limits,
) -> SubjectManifest:
    restored = {entry.path: entry for entry in subject.entries}
    base_entries = {entry.path: entry for entry in base.entries}
    for path in {path for change in changes for path in change.paths}:
        if path in base_entries:
            restored[path] = base_entries[path]
        else:
            restored.pop(path, None)
    return SubjectManifest.build(restored.values(), limits=limits)


def _require_opaque_validation_independence(
    authoritative: ValidationTurn,
    counterfactual: ValidationTurn,
) -> None:
    if _validation_behavior_signature(authoritative) != _validation_behavior_signature(
        counterfactual
    ):
        raise fail(
            StopReason.REVIEW_CONTENT_WITHHELD,
            "predeclared opaque changes altered configured validation behavior",
        )


def _finding_json(finding: Finding) -> dict[str, object]:
    return {
        "id": finding.finding_id,
        "severity": finding.severity,
        "category": finding.category,
        "file": finding.file,
        "symbol": finding.symbol,
        "line_start": finding.line_start,
        "line_end": finding.line_end,
        "problem": finding.problem,
        "evidence": finding.evidence,
        "required_fix": finding.required_fix,
    }


def _review_json(review: CriticReview) -> dict[str, object]:
    return {
        "schema_version": review.schema_version,
        "verdict": review.verdict.value,
        "summary": review.summary,
        "blocked_reason": review.blocked_reason,
        "blocking_findings": [_finding_json(finding) for finding in review.blocking_findings],
        "non_blocking_findings": [
            _finding_json(finding) for finding in review.non_blocking_findings
        ],
    }


def _paths(changes: tuple[ManifestChange, ...]) -> list[dict[str, object]]:
    return [
        {
            "operation": change.kind.value,
            "old": None if change.before is None else change.before.display_path,
            "new": None if change.after is None else change.after.display_path,
        }
        for change in changes
    ]


def _bounded_author_events(
    events: tuple[dict[str, object], ...],
    max_bytes: int,
) -> tuple[bytes, bool, bool]:
    """Retain a bounded private prefix even when an injected event is malformed."""

    retained = bytearray()
    truncated = False
    invalid = False
    for event in events:
        try:
            encoded = (
                json.dumps(
                    event,
                    ensure_ascii=True,
                    allow_nan=False,
                    sort_keys=True,
                ).encode("ascii")
                + b"\n"
            )
        except TypeError, ValueError:
            invalid = True
            encoded = b'{"type":"unserializable-author-event"}\n'
        remaining = max_bytes - len(retained)
        if len(encoded) > remaining:
            retained.extend(encoded[: max(0, remaining)])
            truncated = True
            break
        retained.extend(encoded)
    return bytes(retained), truncated, invalid


def _json_tree_contains_known_secret(
    value: object,
    secrets: tuple[KnownSecret, ...],
) -> bool:
    """Scan decoded model fields so JSON escapes cannot hide credential bytes."""

    stack = [value]
    visited = 0
    while stack:
        visited += 1
        if visited > 1_000_000:
            raise fail(StopReason.AGENT_OUTPUT_LIMIT, "decoded model output has too many values")
        current = stack.pop()
        if isinstance(current, str):
            try:
                encoded = current.encode("utf-8", "strict")
            except UnicodeEncodeError:
                # JSON permits lone surrogate escapes even though they cannot
                # cross our strict UTF-8 artifact/model boundary.  Treat them
                # as unsafe content so the caller retains only typed attempt
                # metadata instead of losing evidence to a later encode error.
                return True
            if raw_log_contains_known_secret(encoded, secrets):
                return True
        elif isinstance(current, bytes):
            if raw_log_contains_known_secret(current, secrets):
                return True
        elif isinstance(current, Mapping):
            stack.extend(current.keys())
            stack.extend(current.values())
        elif isinstance(current, (tuple, list)):
            stack.extend(current)
    return False


def _manifest_contains_known_secret(
    manifest: SubjectManifest,
    blobs: BlobReader,
    secrets: tuple[KnownSecret, ...],
) -> bool:
    # The canonical document contains security-relevant structural strings in
    # addition to paths: the manifest fingerprint and every content digest.
    # Scan it as well as the decoded byte fields so neither representation can
    # hide a credential collision from the retention gate.
    if raw_log_contains_known_secret(manifest.to_json_bytes(), secrets):
        return True
    for entry in manifest.entries:
        if raw_log_contains_known_secret(entry.path, secrets):
            return True
        if entry.symlink_target is not None:
            if raw_log_contains_known_secret(entry.symlink_target, secrets):
                return True
        elif entry.blob_sha256 is not None:
            if raw_log_contains_known_secret(blobs.read_blob(entry.blob_sha256), secrets):
                return True
    return False


def _manifest_metadata_contains_known_secret(
    manifest: SubjectManifest,
    secrets: tuple[KnownSecret, ...],
) -> bool:
    return raw_log_contains_known_secret(manifest.to_json_bytes(), secrets) or any(
        raw_log_contains_known_secret(entry.path, secrets)
        or (
            entry.symlink_target is not None
            and raw_log_contains_known_secret(entry.symlink_target, secrets)
        )
        for entry in manifest.entries
    )


def _author_turn_contains_known_secret(
    turn: AuthorTurn,
    blobs: BlobReader,
    secrets: tuple[KnownSecret, ...],
) -> bool:
    return _manifest_contains_known_secret(turn.candidate, blobs, secrets) or (
        _json_tree_contains_known_secret(
            (
                turn.thread_id,
                turn.final_message,
                turn.events,
                turn.usage,
                turn.observed_model,
                turn.observed_effort,
            ),
            secrets,
        )
    )


def _critic_turn_contains_known_secret(
    turn: CriticTurn,
    secrets: tuple[KnownSecret, ...],
) -> bool:
    return _json_tree_contains_known_secret(
        (
            turn.envelope,
            _review_json(turn.review),
            turn.observed_model,
            turn.observed_effort,
        ),
        secrets,
    )


def _settings_document(
    settings: LoopSettings,
    *,
    retain_operator_strings: bool,
) -> dict[str, object]:
    """Return the retained settings record, optionally without user strings."""

    return {
        "max_rounds": settings.max_rounds,
        "max_runtime_seconds": settings.max_runtime_seconds,
        "protected_patterns": (
            list(settings.protected_patterns) if retain_operator_strings else []
        ),
        "opaque_patterns": (list(settings.opaque_patterns) if retain_operator_strings else []),
        "requested_author_model": (
            settings.requested_author_model if retain_operator_strings else None
        ),
        "requested_author_effort": (
            settings.requested_author_effort if retain_operator_strings else None
        ),
        "requested_critic_model": (
            settings.requested_critic_model if retain_operator_strings else None
        ),
        "requested_critic_effort": (
            settings.requested_critic_effort if retain_operator_strings else None
        ),
        "max_raw_log_bytes": settings.max_raw_log_bytes,
        "limits": asdict(settings.limits),
    }


def _settings_contains_known_secret(
    settings: LoopSettings,
    secrets: tuple[KnownSecret, ...],
) -> bool:
    return _json_tree_contains_known_secret(
        (
            _settings_document(settings, retain_operator_strings=True),
            settings.context_paths,
        ),
        secrets,
    )


def _withheld_environment_document() -> dict[str, object]:
    """Schema-shaped marker used before operator metadata may be retained."""

    withheld_executable = {
        "requested_path": "/withheld",
        "resolved_path": "/withheld",
        "owner_uid": 0,
        "mode": "0000",
        "sha256": "0" * 64,
    }
    return {
        "os_id": "ubuntu",
        "os_version": "26.04",
        "machine": "x86_64",
        "kernel": "withheld",
        "python": "3.14.4",
        "git": "git version 2.53.0",
        "systemd": "systemd 259 (259.5-0ubuntu3)",
        "bash": "version 5.3.",
        "bubblewrap": {
            "package_version": "0.11.1-1ubuntu0.1",
            "upstream_version": "0.11.1",
            "executable": "/usr/bin/bwrap",
            "owner_uid": 0,
            "owner_gid": 0,
            "mode": "0755",
            "sha256": "0abea81db798ebf6b4742ac0664802d97521547a353c2a0dbdc21d76cbbfd2c0",
        },
        "python_executable": {
            **withheld_executable,
            "version": "Python 3.14.4",
        },
        "codex": {
            **withheld_executable,
            "version": "codex-cli 0.144.6",
        },
        "claude": {
            **withheld_executable,
            "version": "2.1.215 (Claude Code)",
        },
        "author_service": {
            "protocol": 1,
            "build_id": "fixed-system-author-v1",
            "authorized_uid": os.geteuid(),
            "socket_path": "/run/agent-loop/author.sock",
            "socket_owner_uid": os.geteuid(),
            "socket_mode": "0600",
            "socket_unit_sha256": "0" * 64,
            "broker_unit_sha256": "0" * 64,
            "socket_dropin_sha256": "0" * 64,
            "config_sha256": "0" * 64,
            "install_record_sha256": "0" * 64,
            "runtime_closure_sha256": "0" * 64,
            "wheel_sha256": "0" * 64,
            "codex_closure_sha256": "0" * 64,
            "effective_units_sha256": "0" * 64,
            "package_version": "1.1.0",
            "broker_probe": False,
        },
        "openat2": True,
        "namespace_probe": False,
        "transient_service_probe": False,
    }


class ArtifactRunJournal:
    """Crash-consistent private evidence layout for one non-resumable run."""

    def __init__(
        self,
        artifacts: ArtifactStore,
        run_id: str,
        metadata: Mapping[str, object],
    ) -> None:
        allowed_metadata = {
            "source_revision",
            "source_tree_object_id",
            "canonical_source",
            "source_warnings",
            "environment",
            "credential_identifiers",
        }
        unknown = set(metadata) - allowed_metadata
        if unknown:
            raise ValueError(f"unknown run metadata fields: {sorted(unknown)!r}")
        self._artifacts = artifacts
        self._run_id = run_id
        self._pending_metadata = dict(metadata)
        self._pending_hostname = socket.gethostname()
        self._subject_content_withheld = False
        self._metadata_released = False
        self._manifest: dict[str, object] = {
            "schema_version": 1,
            "run_id": run_id,
            "pid": os.getpid(),
            "hostname": "withheld",
            "status": "initializing",
            "metadata_content_withheld": True,
            "source_revision": "0" * 40,
            "source_tree_object_id": "0" * 40,
            "canonical_source": "/withheld",
            "source_warnings": ["operator metadata withheld pending credential scan"],
            "environment": _withheld_environment_document(),
            "credential_identifiers": {
                "codex": "withheld",
                "claude": "withheld",
            },
        }
        artifacts.ensure_directory("artifacts/rounds")

    def _write_run(self) -> None:
        if self._artifacts.content_withheld_due_to_secret:
            status = self._manifest.get("status", "running")
            finalized = status in {"converged", "stopped"}
            retained_rounds = self._manifest.get("rounds_completed", 0)
            safe_config = {
                "max_rounds": self._manifest.get("max_rounds", 1),
                "max_runtime_seconds": self._manifest.get(
                    "max_runtime_seconds",
                    1.0,
                ),
                "protected_patterns": [],
                "opaque_patterns": [],
                "requested_author_model": None,
                "requested_author_effort": None,
                "requested_critic_model": None,
                "requested_critic_effort": None,
                "max_raw_log_bytes": self._manifest.get(
                    "max_raw_log_bytes",
                    DEFAULT_MAX_RAW_LOG_BYTES,
                ),
                "limits": self._manifest.get("limits", asdict(Limits())),
            }
            self._manifest = {
                "schema_version": 1,
                "run_id": self._run_id,
                "pid": os.getpid(),
                "hostname": "withheld",
                "status": "stopped" if finalized else "running",
                "metadata_content_withheld": True,
                "base_subject_fingerprint": _WITHHELD_SUBJECT_FINGERPRINT,
                "current_subject_fingerprint": _WITHHELD_SUBJECT_FINGERPRINT,
                "monotonic_deadline": self._manifest.get("monotonic_deadline", 0.0),
                "current_round": self._manifest.get("current_round", 0),
                "source_revision": "0" * 40,
                "source_tree_object_id": "0" * 40,
                "canonical_source": "/withheld",
                "source_warnings": ["retained content withheld after credential refresh"],
                "environment": _withheld_environment_document(),
                "credential_identifiers": {
                    "codex": "withheld",
                    "claude": "withheld",
                },
                **safe_config,
            }
            if finalized:
                self._manifest.update(
                    {
                        "stop_reason": StopReason.CREDENTIAL_REFRESH_FAILURE.value,
                        "exit_code": int(exit_code_for(StopReason.CREDENTIAL_REFRESH_FAILURE)),
                        "stop_detail": (
                            "retained evidence was withheld after a credential refresh"
                        ),
                        "rounds_completed": retained_rounds,
                        "codex_thread_id": None,
                    }
                )
            self._metadata_released = False
            self._subject_content_withheld = True
        self._artifacts.write_json("artifacts/run.json", self._manifest)

    def pending_metadata_contains_known_secret(
        self,
        secrets: tuple[KnownSecret, ...],
    ) -> bool:
        return _json_tree_contains_known_secret(
            (self._pending_hostname, self._pending_metadata),
            secrets,
        )

    def start(
        self,
        *,
        task: str,
        base: SubjectManifest,
        deadline: float,
        settings: LoopSettings,
    ) -> None:
        config = _settings_document(settings, retain_operator_strings=True)
        self._subject_content_withheld = False
        self._metadata_released = True
        self._artifacts.write_json("artifacts/config.json", config)
        self._manifest.update(
            {
                **self._pending_metadata,
                "hostname": self._pending_hostname,
                "metadata_content_withheld": False,
                "status": "running",
                "base_subject_fingerprint": base.fingerprint,
                "current_subject_fingerprint": base.fingerprint,
                "monotonic_deadline": deadline,
                "current_round": 0,
                **config,
            }
        )
        self._write_run()

    def precredential_start(
        self,
        *,
        base: SubjectManifest,
        deadline: float,
        settings: LoopSettings,
    ) -> None:
        """Journal a schema-valid run without retaining operator-controlled strings."""

        config = _settings_document(settings, retain_operator_strings=False)
        self._artifacts.write_json(
            "artifacts/config.json",
            {**config, "operator_content_withheld_pending_credential_scan": True},
        )
        self._manifest.update(
            {
                "status": "running",
                "base_subject_fingerprint": _WITHHELD_SUBJECT_FINGERPRINT,
                "current_subject_fingerprint": _WITHHELD_SUBJECT_FINGERPRINT,
                "monotonic_deadline": deadline,
                "current_round": 0,
                **config,
            }
        )
        self._write_run()

    def task_input(self, task: str, *, content_withheld: bool) -> None:
        if not isinstance(content_withheld, bool):
            raise TypeError("task content_withheld must be boolean")
        encoded = task.encode("utf-8")
        self._artifacts.write_bytes(
            "artifacts/task.md",
            b"" if content_withheld else encoded,
        )
        self._artifacts.write_json(
            "artifacts/task.meta.json",
            {
                "schema_version": 1,
                "task_bytes": len(encoded),
                "content_withheld": content_withheld,
            },
        )

    def subject_input(
        self,
        subject: SubjectManifest,
        *,
        content_withheld: bool,
    ) -> None:
        if not isinstance(content_withheld, bool):
            raise TypeError("subject content_withheld must be boolean")
        self._subject_content_withheld = self._subject_content_withheld or content_withheld
        self._artifacts.write_bytes(
            "artifacts/base-subject.json",
            b"" if content_withheld else subject.to_json_bytes(),
        )
        self._artifacts.write_json(
            "artifacts/base-subject.meta.json",
            {
                "schema_version": 1,
                "subject_fingerprint": (
                    _WITHHELD_SUBJECT_FINGERPRINT if content_withheld else subject.fingerprint
                ),
                "content_withheld": content_withheld,
            },
        )

    def baseline(self, turn: ValidationTurn, evidence: ValidationCriticEvidence) -> None:
        self._artifacts.write_json(
            "artifacts/baseline.validation.summary.json",
            {
                "schema_version": turn.summary.schema_version,
                "subject_fingerprint": turn.summary.subject_fingerprint,
                "checks": [_check_json(check) for check in turn.summary.checks],
            },
        )
        self._artifacts.write_bytes("artifacts/baseline.validation.raw.log", turn.raw_log)
        self._artifacts.write_bytes(
            "artifacts/baseline.validation.critic.json", evidence.to_json_bytes()
        )

    def validation_attempt(
        self,
        round_number: int | None,
        phase: ValidationAttemptPhase,
        expected_subject: SubjectManifest,
        turn: ValidationTurn,
        retained_raw_log: bytes,
        raw_log_truncated: bool,
        raw_log_withheld: bool,
        result_subject_withheld: bool,
        summary_withheld: bool,
    ) -> None:
        if phase == "baseline":
            if round_number is not None:
                raise ValueError("baseline validation attempts cannot name a round")
            prefix = "artifacts/baseline.validation.attempt"
        elif phase == "validation":
            if round_number is None or round_number < 1:
                raise ValueError("round validation attempts require a positive round")
            prefix = f"artifacts/rounds/{round_number:03d}/validation.attempt"
        elif phase == "opaque":
            prefix = (
                "artifacts/baseline.opaque-validation.attempt"
                if round_number is None
                else f"artifacts/rounds/{round_number:03d}/opaque-validation.attempt"
            )
        else:
            raise ValueError("unknown validation attempt phase")
        if not isinstance(retained_raw_log, bytes):
            raise TypeError("retained validation output must be bytes")
        if not isinstance(raw_log_truncated, bool):
            raise TypeError("raw_log_truncated must be boolean")
        if not isinstance(raw_log_withheld, bool):
            raise TypeError("raw_log_withheld must be boolean")
        if not isinstance(result_subject_withheld, bool):
            raise TypeError("result_subject_withheld must be boolean")
        if not isinstance(summary_withheld, bool):
            raise TypeError("summary_withheld must be boolean")
        if raw_log_withheld and retained_raw_log:
            raise ValueError("withheld validation output cannot retain raw bytes")
        self._artifacts.write_json(
            f"{prefix}.summary.json",
            {
                "schema_version": turn.summary.schema_version,
                "subject_fingerprint": (
                    _WITHHELD_SUBJECT_FINGERPRINT
                    if summary_withheld
                    else turn.summary.subject_fingerprint
                ),
                "checks": (
                    []
                    if summary_withheld
                    else [_check_json(check) for check in turn.summary.checks]
                ),
                "raw_log_bytes": len(turn.raw_log),
                "retained_raw_log_bytes": len(retained_raw_log),
                "raw_log_truncated": raw_log_truncated,
                "raw_log_withheld": raw_log_withheld,
                "result_subject_withheld": result_subject_withheld,
                "summary_withheld": summary_withheld,
            },
        )
        self._artifacts.write_bytes(f"{prefix}.raw.log", retained_raw_log)
        self._artifacts.write_bytes(
            f"{prefix}.input-subject.json",
            b"" if result_subject_withheld else expected_subject.to_json_bytes(),
        )
        self._artifacts.write_bytes(
            f"{prefix}.result-subject.json",
            b"" if result_subject_withheld else turn.result_manifest.to_json_bytes(),
        )

    def opaque_proof(
        self,
        round_number: int | None,
        counterfactual: SubjectManifest,
        turn: ValidationTurn,
        equivalent: bool,
    ) -> None:
        prefix = (
            "artifacts/baseline.opaque-validation-proof"
            if round_number is None
            else f"artifacts/rounds/{round_number:03d}/opaque-validation-proof"
        )
        self._artifacts.write_bytes(f"{prefix}.subject.json", counterfactual.to_json_bytes())
        self._artifacts.write_json(
            f"{prefix}.summary.json",
            {
                "schema_version": 1,
                "equivalent_to_authoritative_validation": equivalent,
                "subject_fingerprint": turn.summary.subject_fingerprint,
                "checks": [_check_json(check) for check in turn.summary.checks],
            },
        )
        self._artifacts.write_bytes(f"{prefix}.raw.log", turn.raw_log)

    def author_attempt(
        self,
        round_number: int,
        turn: AuthorTurn,
        max_output_bytes: int,
        content_withheld: bool,
    ) -> None:
        if round_number < 1:
            raise ValueError("author attempts require a positive round")
        if max_output_bytes < 1:
            raise ValueError("author attempt output limit must be positive")
        prefix = f"artifacts/rounds/{round_number:03d}/author-attempt"
        if not isinstance(content_withheld, bool):
            raise TypeError("author attempt content_withheld must be boolean")
        candidate_bytes = b"" if content_withheld else turn.candidate.to_json_bytes()
        self._artifacts.write_bytes(f"{prefix}.candidate-subject.json", candidate_bytes)
        if content_withheld:
            final_bytes = turn.final_message.encode("utf-8", "surrogatepass")
            retained_final = b""
            events, events_truncated, events_invalid = b"", False, False
        else:
            final_bytes = turn.final_message.encode("utf-8", "strict")
            retained_final = final_bytes[:max_output_bytes]
            events, events_truncated, events_invalid = _bounded_author_events(
                turn.events,
                max_output_bytes,
            )
        self._artifacts.write_bytes(f"{prefix}.final.md", retained_final)
        self._artifacts.write_bytes(f"{prefix}.events.jsonl", events)
        self._artifacts.write_json(
            f"{prefix}.summary.json",
            {
                "schema_version": 1,
                "candidate_subject_fingerprint": (
                    _WITHHELD_SUBJECT_FINGERPRINT
                    if content_withheld
                    else turn.candidate.fingerprint
                ),
                "thread_id": None if content_withheld else turn.thread_id,
                "observed_model": None if content_withheld else turn.observed_model,
                "observed_effort": None if content_withheld else turn.observed_effort,
                "final_message_bytes": len(final_bytes),
                "retained_final_message_bytes": len(retained_final),
                "final_message_truncated": len(retained_final) != len(final_bytes),
                "events_truncated": events_truncated,
                "events_contained_unserializable_value": events_invalid,
                "content_withheld": content_withheld,
            },
        )

    def critic_attempt(
        self,
        round_number: int,
        turn: CriticTurn,
        max_output_bytes: int,
        content_withheld: bool,
    ) -> None:
        if round_number < 1 or max_output_bytes < 1:
            raise ValueError("critic attempts require a positive round and output limit")
        if not isinstance(content_withheld, bool):
            raise TypeError("critic attempt content_withheld must be boolean")
        prefix = f"artifacts/rounds/{round_number:03d}/critic-attempt"
        if content_withheld:
            envelope_bytes = b""
            review_bytes = b""
        else:
            envelope_bytes = (
                json.dumps(
                    turn.envelope,
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                + b"\n"
            )
            review_bytes = (
                json.dumps(
                    _review_json(turn.review),
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                + b"\n"
            )
        envelope = envelope_bytes[:max_output_bytes]
        review = review_bytes[:max_output_bytes]
        self._artifacts.write_bytes(f"{prefix}.envelope.json.prefix", envelope)
        self._artifacts.write_bytes(f"{prefix}.review.json.prefix", review)
        self._artifacts.write_json(
            f"{prefix}.summary.json",
            {
                "schema_version": 1,
                "content_withheld": content_withheld,
                "envelope_bytes": len(envelope_bytes),
                "envelope_retained_bytes": len(envelope),
                "envelope_truncated": len(envelope) != len(envelope_bytes),
                "review_bytes": len(review_bytes),
                "review_retained_bytes": len(review),
                "review_truncated": len(review) != len(review_bytes),
                "observed_model": None if content_withheld else turn.observed_model,
                "observed_effort": None if content_withheld else turn.observed_effort,
                "completed_at": turn.completed_at,
            },
        )

    def author(
        self,
        round_number: int,
        turn: AuthorTurn,
        authoritative: SubjectManifest,
        semantic: tuple[ManifestChange, ...],
        opaque: tuple[ManifestChange, ...],
        discarded: tuple[ManifestChange, ...],
        base: SubjectManifest,
        blobs: BlobReader,
    ) -> None:
        prefix = f"artifacts/rounds/{round_number:03d}"
        self._artifacts.ensure_directory(prefix)
        events = b"".join(
            json.dumps(event, ensure_ascii=True, allow_nan=False, sort_keys=True).encode("ascii")
            + b"\n"
            for event in turn.events
        )
        self._artifacts.write_bytes(f"{prefix}/author-events.jsonl", events)
        self._artifacts.write_text(f"{prefix}/author-final.md", turn.final_message)
        self._artifacts.write_bytes(
            f"{prefix}/candidate-subject.json", turn.candidate.to_json_bytes()
        )
        self._artifacts.write_bytes(
            f"{prefix}/authoritative-subject.json", authoritative.to_json_bytes()
        )
        self._artifacts.write_text(
            f"{prefix}/subject-fingerprint.txt", authoritative.fingerprint + "\n"
        )
        self._artifacts.write_json(
            f"{prefix}/paths.json",
            {
                "semantic": _paths(semantic),
                "opaque_nonsemantic": _paths(opaque),
                "discarded": _paths(discarded),
            },
        )
        patch = render_diagnostic_patch(base, turn.candidate, blobs)
        self._artifacts.write_bytes(f"{prefix}/diagnostic.patch", patch)
        self._manifest.update(
            {
                "current_round": round_number,
                "current_subject_fingerprint": authoritative.fingerprint,
                "codex_thread_id": turn.thread_id,
                "observed_author_model": turn.observed_model,
                "observed_author_effort": turn.observed_effort,
                "codex_usage": turn.usage,
            }
        )
        self._write_run()

    def validation(
        self,
        round_number: int,
        turn: ValidationTurn,
        evidence: ValidationCriticEvidence,
        classified: tuple[ClassifiedCheck, ...],
    ) -> None:
        prefix = f"artifacts/rounds/{round_number:03d}"
        self._artifacts.write_json(
            f"{prefix}/validation.summary.json",
            {
                "schema_version": turn.summary.schema_version,
                "subject_fingerprint": turn.summary.subject_fingerprint,
                "checks": [_check_json(check) for check in turn.summary.checks],
                "classified": [
                    {
                        "check_id": check.check_id,
                        "transition": check.transition.value,
                        "regression": check.regression,
                    }
                    for check in classified
                ],
            },
        )
        self._artifacts.write_bytes(f"{prefix}/validation.raw.log", turn.raw_log)
        self._artifacts.write_bytes(f"{prefix}/validation.critic.json", evidence.to_json_bytes())
        self._artifacts.write_bytes(
            f"{prefix}/validation-mutation.json", turn.result_manifest.to_json_bytes()
        )

    def critic(self, round_number: int, turn: CriticTurn, bundle: ReviewBundle) -> None:
        prefix = f"artifacts/rounds/{round_number:03d}"
        self._artifacts.write_bytes(f"{prefix}/review-bundle.json", bundle.encoded)
        self._artifacts.write_json(
            f"{prefix}/review-bundle.meta.json",
            {
                "fingerprint": bundle.fingerprint,
                "estimated_input_tokens": bundle.estimated_input_tokens,
                "bytes": len(bundle.encoded),
            },
        )
        self._artifacts.write_json(f"{prefix}/critic-envelope.json", turn.envelope)
        self._artifacts.write_json(f"{prefix}/critic.json", _review_json(turn.review))
        self._artifacts.write_json(
            f"{prefix}/findings-ledger.json",
            {
                "findings": [
                    {
                        "id": finding.finding_id,
                        "required_fix": finding.required_fix,
                        "status": "open",
                    }
                    for finding in turn.review.blocking_findings
                ],
                "bundle_fingerprint": bundle.fingerprint,
            },
        )
        self._manifest.update(
            {
                "critic_completed_at": turn.completed_at,
                "observed_critic_model": turn.observed_model,
                "observed_critic_effort": turn.observed_effort,
                "claude_total_cost_usd": turn.total_cost_usd,
            }
        )
        self._write_run()

    def finish(self, result: LoopResult) -> None:
        self._manifest.update(
            {
                "status": "converged" if result.exit_code is ExitCode.SUCCESS else "stopped",
                "stop_reason": result.stop_reason.value,
                "exit_code": int(result.exit_code),
                "stop_detail": result.detail,
                "rounds_completed": result.rounds_completed,
                "current_subject_fingerprint": (
                    _WITHHELD_SUBJECT_FINGERPRINT
                    if self._subject_content_withheld or not self._metadata_released
                    else result.subject.fingerprint
                ),
                "codex_thread_id": result.thread_id,
            }
        )
        self._write_run()


def _progress_state(
    subject: SubjectManifest,
    classified: tuple[ClassifiedCheck, ...],
    review: CriticReview,
) -> ProgressState:
    validations = tuple(
        ValidationProgress(
            check_id=check.check_id,
            outcome=check.current_outcome.value,
            transition=check.transition.value,
            regression=check.regression,
            evidence_complete=check.current_outcome.value in {"passed", "failed"},
        )
        for check in classified
    )
    findings = tuple(
        FindingProgress(
            finding_id=finding.finding_id,
            severity=finding.severity,
            category=finding.category,
            file=finding.file,
            line_start=finding.line_start,
            line_end=finding.line_end,
            problem=finding.problem,
            evidence=finding.evidence,
            required_fix=finding.required_fix,
        )
        for finding in review.blocking_findings
    )
    return ProgressState(
        subject_fingerprint=subject.fingerprint,
        validations=validations,
        verdict=review.verdict.value,
        blocking_findings=findings,
        blocked_reason=review.blocked_reason,
    )


def _require_observed_selection(
    *,
    role: str,
    expected_model: str | None,
    expected_effort: str | None,
    observed_model: str | None,
    observed_effort: str | None,
) -> None:
    if expected_model is not None and observed_model != expected_model:
        raise fail(
            StopReason.SANDBOX_SETUP_FAILURE,
            f"{role} did not report the exact requested model selection",
        )
    if expected_effort is not None and observed_effort != expected_effort:
        raise fail(
            StopReason.SANDBOX_SETUP_FAILURE,
            f"{role} did not report the exact requested effort selection",
        )


class LoopRunner:
    def __init__(
        self,
        *,
        author: AuthorAdapter,
        validator: ValidationAdapter,
        critic: CriticAdapter,
        blobs: BlobReader,
        policy: PathPolicy,
        journal: RunJournal | None = None,
        clock: Clock = time.monotonic,
        integrity_guard: Callable[[SubjectManifest], None] | None = None,
        publish_subject: Callable[[SubjectManifest], None] | None = None,
        known_secrets: tuple[KnownSecret, ...] = (),
        known_secret_provider: Callable[[], tuple[KnownSecret, ...]] | None = None,
    ) -> None:
        self._author = author
        self._validator = validator
        self._critic = critic
        self._blobs = blobs
        self._policy = policy
        self._journal = journal or NullRunJournal()
        self._clock = clock
        self._integrity_guard = integrity_guard or (lambda _subject: None)
        self._publish_subject = publish_subject or (lambda _subject: None)
        self._known_secrets = known_secrets
        if known_secret_provider is not None and not callable(known_secret_provider):
            raise TypeError("known_secret_provider must be callable")
        self._known_secret_provider = known_secret_provider

    def _current_known_secrets(self) -> tuple[KnownSecret, ...]:
        supplied = () if self._known_secret_provider is None else self._known_secret_provider()
        if not isinstance(supplied, tuple) or not all(
            isinstance(secret, KnownSecret) for secret in supplied
        ):
            raise TypeError("known_secret_provider must return a tuple of KnownSecret values")
        return tuple(dict.fromkeys((*self._known_secrets, *supplied)))

    def run(
        self,
        task: str,
        base: SubjectManifest,
        settings: LoopSettings,
        *,
        prepared_baseline: ValidationTurn | None = None,
        monotonic_deadline: float | None = None,
        journal_prestarted: bool = False,
    ) -> LoopResult:
        started = self._clock()
        deadline = (
            started + settings.max_runtime_seconds
            if monotonic_deadline is None
            else monotonic_deadline
        )
        if deadline < 0:
            raise ValueError("monotonic deadline cannot be negative")
        current = base
        thread_id: str | None = None
        rounds_completed = 0
        fatal = FatalLatch()
        stall = StallDetector()
        ledger: tuple[FindingLedgerItem, ...] = ()
        prompt = build_initial_author_prompt(task)

        def stop(reason: StopReason, detail: str) -> LoopResult:
            result = LoopResult(
                exit_code_for(reason), reason, rounds_completed, current, thread_id, detail
            )
            self._journal.finish(result)
            return result

        try:
            initial_secrets = self._current_known_secrets()
            task_withheld = raw_log_contains_known_secret(
                task.encode("utf-8"),
                initial_secrets,
            )
            base_withheld = _manifest_contains_known_secret(
                base,
                self._blobs,
                initial_secrets,
            )
            settings_withheld = _settings_contains_known_secret(settings, initial_secrets)
            metadata_withheld = (
                self._journal.pending_metadata_contains_known_secret(initial_secrets)
                if isinstance(self._journal, ArtifactRunJournal)
                else False
            )
            if not journal_prestarted:
                if isinstance(self._journal, ArtifactRunJournal):
                    self._journal.precredential_start(
                        base=base,
                        deadline=deadline,
                        settings=settings,
                    )
                if not (task_withheld or base_withheld or settings_withheld or metadata_withheld):
                    self._journal.start(
                        task=task,
                        base=base,
                        deadline=deadline,
                        settings=settings,
                    )
            self._journal.task_input(task, content_withheld=task_withheld)
            self._journal.subject_input(base, content_withheld=base_withheld)
            if task_withheld or base_withheld or settings_withheld or metadata_withheld:
                raise fail(
                    StopReason.CREDENTIAL_REFRESH_FAILURE,
                    "run metadata, task, settings, or initial subject contained dedicated "
                    "credential bytes",
                )
            self._ensure_deadline(deadline)
            baseline_turn = prepared_baseline or self._validator.validate(
                ValidationRequest(base, None, deadline)
            )
            baseline_raw_withheld = self._journal_validation_attempt(
                None,
                "baseline",
                base,
                baseline_turn,
                settings,
            )
            self._verify_raw_log_limit(baseline_turn, settings)
            self._verify_validation_turn(base, baseline_turn)
            # Baseline infrastructure evidence must be journaled before the
            # fatal stop.  Passing it as both baseline and current would make
            # the classifier raise before evidence retention.
            baseline_classified = classify_validations(None, baseline_turn.summary)
            baseline_evidence = declassify_validation(
                base.fingerprint,
                baseline_classified,
                raw_log=baseline_turn.raw_log,
                known_secrets=self._current_known_secrets(),
            )
            self._journal.baseline(
                _without_validation_raw(baseline_turn) if baseline_raw_withheld else baseline_turn,
                baseline_evidence,
            )
            self._ensure_validation_can_continue(
                baseline_turn.summary,
                baseline_evidence,
                baseline=True,
            )
            opaque_free_base = _without_opaque_entries(base, self._policy, settings.limits)
            if opaque_free_base != base:
                self._prove_opaque_validation_independence(
                    authoritative=baseline_turn,
                    counterfactual_subject=opaque_free_base,
                    baseline=baseline_turn.summary,
                    deadline=deadline,
                    settings=settings,
                    round_number=None,
                    baseline_phase=True,
                )

            for round_number in range(1, settings.max_rounds + 1):
                self._ensure_deadline(deadline)
                self._integrity_guard(current)
                if raw_log_contains_known_secret(
                    prompt.encode("utf-8"),
                    self._current_known_secrets(),
                ):
                    raise fail(
                        StopReason.CREDENTIAL_REFRESH_FAILURE,
                        "author prompt contained dedicated credential bytes",
                    )
                author_turn = self._author.turn(
                    AuthorRequest(round_number, current, prompt, thread_id, deadline)
                )
                author_content_withheld = _author_turn_contains_known_secret(
                    author_turn,
                    self._blobs,
                    self._current_known_secrets(),
                )
                self._journal.author_attempt(
                    round_number,
                    author_turn,
                    settings.limits.max_agent_output_bytes,
                    author_content_withheld,
                )
                if author_content_withheld:
                    raise fail(
                        StopReason.CREDENTIAL_REFRESH_FAILURE,
                        "decoded author output contained dedicated credential bytes",
                    )
                _require_observed_selection(
                    role="Codex author",
                    expected_model=settings.requested_author_model,
                    expected_effort=settings.requested_author_effort,
                    observed_model=author_turn.observed_model,
                    observed_effort=author_turn.observed_effort,
                )
                if not author_turn.thread_id:
                    raise fail(StopReason.AUTHOR_PROCESS_FAILURE, "author returned no thread ID")
                if thread_id is None:
                    thread_id = author_turn.thread_id
                elif author_turn.thread_id != thread_id:
                    raise fail(
                        StopReason.GITLESS_INVOCATION_PROBE_FAILED,
                        "author resume returned a different thread ID",
                    )
                self._ensure_deadline(deadline)
                reconciliation = reconcile_candidate(base, author_turn.candidate, self._policy)
                current = reconciliation.authoritative_manifest
                self._publish_subject(current)
                self._integrity_guard(current)
                self._journal.author(
                    round_number,
                    author_turn,
                    current,
                    reconciliation.semantic_changes,
                    reconciliation.opaque_changes,
                    reconciliation.discarded_changes,
                    base,
                    self._blobs,
                )

                validation_turn = self._validator.validate(
                    ValidationRequest(current, baseline_turn.summary, deadline)
                )
                validation_raw_withheld = self._journal_validation_attempt(
                    round_number,
                    "validation",
                    current,
                    validation_turn,
                    settings,
                )
                self._verify_raw_log_limit(validation_turn, settings)
                self._integrity_guard(current)
                self._verify_validation_turn(current, validation_turn)
                classified = classify_validations(baseline_turn.summary, validation_turn.summary)
                evidence = declassify_validation(
                    current.fingerprint,
                    classified,
                    raw_log=validation_turn.raw_log,
                    known_secrets=self._current_known_secrets(),
                )
                self._journal.validation(
                    round_number,
                    _without_validation_raw(validation_turn)
                    if validation_raw_withheld
                    else validation_turn,
                    evidence,
                    classified,
                )
                self._ensure_validation_can_continue(
                    validation_turn.summary,
                    evidence,
                    baseline=False,
                )
                if reconciliation.opaque_changes:
                    opaque_counterfactual = _restore_opaque_base_entries(
                        base,
                        current,
                        reconciliation.opaque_changes,
                        settings.limits,
                    )
                    self._prove_opaque_validation_independence(
                        authoritative=validation_turn,
                        counterfactual_subject=opaque_counterfactual,
                        baseline=baseline_turn.summary,
                        deadline=deadline,
                        settings=settings,
                        round_number=round_number,
                        baseline_phase=False,
                    )
                    self._integrity_guard(current)
                self._ensure_deadline(deadline)

                bundle = build_review_bundle(
                    task=task,
                    base=base,
                    subject=current,
                    semantic_changes=reconciliation.semantic_changes,
                    opaque_changes=reconciliation.opaque_changes,
                    blobs=self._blobs,
                    validation=evidence,
                    protected_patterns=settings.protected_patterns,
                    opaque_patterns=settings.opaque_patterns,
                    context_paths=settings.context_paths,
                    prior_findings=ledger,
                    known_secrets=self._current_known_secrets(),
                    limits=settings.limits,
                )
                current_secrets = self._current_known_secrets()
                if raw_log_contains_known_secret(
                    bundle.encoded,
                    current_secrets,
                ) or _json_tree_contains_known_secret(
                    (bundle.document, bundle.fingerprint),
                    current_secrets,
                ):
                    raise fail(
                        StopReason.CREDENTIAL_REFRESH_FAILURE,
                        "critic bundle contained dedicated credential bytes",
                    )
                approval = ApprovalContext(
                    validation_turn.summary.all_pass,
                    True,
                    evidence.approval_eligible,
                )
                critic_turn = self._critic.review(
                    CriticRequest(round_number, bundle, approval, deadline)
                )
                critic_content_withheld = _critic_turn_contains_known_secret(
                    critic_turn,
                    self._current_known_secrets(),
                )
                self._journal.critic_attempt(
                    round_number,
                    critic_turn,
                    settings.limits.max_agent_output_bytes,
                    critic_content_withheld,
                )
                if critic_content_withheld:
                    raise fail(
                        StopReason.CREDENTIAL_REFRESH_FAILURE,
                        "decoded critic output contained dedicated credential bytes",
                    )
                _require_observed_selection(
                    role="Claude critic",
                    expected_model=settings.requested_critic_model,
                    expected_effort=settings.requested_critic_effort,
                    observed_model=critic_turn.observed_model,
                    observed_effort=critic_turn.observed_effort,
                )
                self._integrity_guard(current)
                # Re-run the local semantic validator even for injected/fake adapters.
                review = validate_critic_review(_review_json(critic_turn.review), approval=approval)
                critic_turn = CriticTurn(
                    review,
                    critic_turn.completed_at,
                    critic_turn.envelope,
                    critic_turn.total_cost_usd,
                    critic_turn.observed_model,
                    critic_turn.observed_effort,
                )
                self._journal.critic(round_number, critic_turn, bundle)
                rounds_completed = round_number

                progress = _progress_state(current, classified, review)
                repeated = stall.observe(progress)
                outcome = decide(
                    RoundObservation(
                        round_count=round_number,
                        max_rounds=settings.max_rounds,
                        all_validations_pass=validation_turn.summary.all_pass,
                        semantic_deltas_visible=True,
                        evidence_approval_eligible=evidence.approval_eligible,
                        critic_verdict=review.verdict.value,
                        critic_completed_at=critic_turn.completed_at,
                        monotonic_deadline=deadline,
                        repeated_non_success_state=repeated,
                    ),
                    fatal,
                )
                if outcome.reason is not None:
                    detail = {
                        StopReason.CONVERGED: "all validations passed and critic returned LGTM",
                        StopReason.CRITIC_BLOCKED: review.blocked_reason or "critic blocked",
                        StopReason.ROUND_CAP_REACHED: "maximum author rounds reached",
                        StopReason.STALLED: "two adjacent normalized non-success states matched",
                    }.get(outcome.reason, fatal.detail or outcome.reason.value)
                    return stop(outcome.reason, detail)
                ledger = tuple(
                    FindingLedgerItem(finding.finding_id, finding.required_fix, "open")
                    for finding in review.blocking_findings
                )
                prompt = build_revision_author_prompt(
                    original_task=task, review=review, validation=evidence
                )
            raise AssertionError("loop exhausted without the round-cap decision")
        except KeyboardInterrupt:
            return stop(StopReason.USER_INTERRUPT, "operator interrupted the active run")
        except AgentLoopError as exc:
            try:
                encoded_detail = exc.detail.encode("utf-8", "strict")
                detail_contains_secret = raw_log_contains_known_secret(
                    encoded_detail,
                    self._current_known_secrets(),
                )
            except AgentLoopError, UnicodeEncodeError:
                detail_contains_secret = True
            if detail_contains_secret:
                return stop(
                    StopReason.CREDENTIAL_REFRESH_FAILURE,
                    "typed failure detail was withheld because it contained credential bytes",
                )
            return stop(exc.reason, exc.detail)
        except Exception as exc:
            return stop(
                StopReason.RUNNER_INTERNAL_ERROR,
                f"unexpected internal exception: {type(exc).__name__}",
            )

    def _ensure_deadline(self, deadline: float) -> None:
        if self._clock() > deadline:
            raise fail(
                StopReason.WALL_CLOCK_DEADLINE_EXCEEDED,
                "total monotonic run deadline elapsed",
            )

    def _verify_validation_turn(
        self,
        subject: SubjectManifest,
        turn: ValidationTurn,
    ) -> None:
        if turn.summary.subject_fingerprint != subject.fingerprint:
            raise fail(
                StopReason.OUT_OF_BAND_CHANGE,
                "validation summary names a different subject fingerprint",
            )
        verify_validation_mutation(subject, turn.result_manifest, self._policy)

    @staticmethod
    def _verify_raw_log_limit(turn: ValidationTurn, settings: LoopSettings) -> None:
        if len(turn.raw_log) > settings.max_raw_log_bytes:
            raise fail(
                StopReason.AGENT_OUTPUT_LIMIT,
                "validation raw log exceeded its retained byte limit",
            )

    def _journal_validation_attempt(
        self,
        round_number: int | None,
        phase: ValidationAttemptPhase,
        expected_subject: SubjectManifest,
        turn: ValidationTurn,
        settings: LoopSettings,
    ) -> bool:
        current_secrets = self._current_known_secrets()
        raw_log_withheld = raw_log_contains_known_secret(turn.raw_log, current_secrets)
        input_subject_withheld = _manifest_metadata_contains_known_secret(
            expected_subject,
            current_secrets,
        )
        result_subject_withheld = (
            input_subject_withheld
            or _manifest_metadata_contains_known_secret(
                turn.result_manifest,
                current_secrets,
            )
        )
        summary_withheld = _json_tree_contains_known_secret(
            {
                "schema_version": turn.summary.schema_version,
                "subject_fingerprint": turn.summary.subject_fingerprint,
                "checks": tuple(_check_json(check) for check in turn.summary.checks),
            },
            current_secrets,
        )
        retained = b"" if raw_log_withheld else turn.raw_log[: settings.max_raw_log_bytes]
        self._journal.validation_attempt(
            round_number,
            phase,
            expected_subject,
            turn,
            retained,
            not raw_log_withheld and len(retained) != len(turn.raw_log),
            raw_log_withheld,
            result_subject_withheld,
            summary_withheld,
        )
        if result_subject_withheld or summary_withheld:
            raise fail(
                StopReason.CREDENTIAL_REFRESH_FAILURE,
                "validation input, result, or summary metadata contained dedicated "
                "credential bytes",
            )
        return raw_log_withheld

    def _prove_opaque_validation_independence(
        self,
        *,
        authoritative: ValidationTurn,
        counterfactual_subject: SubjectManifest,
        baseline: ValidationSummary,
        deadline: float,
        settings: LoopSettings,
        round_number: int | None,
        baseline_phase: bool,
    ) -> None:
        self._ensure_deadline(deadline)
        counterfactual = self._validator.validate(
            ValidationRequest(counterfactual_subject, baseline, deadline)
        )
        raw_log_withheld = self._journal_validation_attempt(
            round_number,
            "opaque",
            counterfactual_subject,
            counterfactual,
            settings,
        )
        self._verify_raw_log_limit(counterfactual, settings)
        self._verify_validation_turn(counterfactual_subject, counterfactual)
        classified = classify_validations(baseline, counterfactual.summary)
        evidence = declassify_validation(
            counterfactual_subject.fingerprint,
            classified,
            raw_log=counterfactual.raw_log,
            known_secrets=self._current_known_secrets(),
        )
        # Retain the complete counterfactual before any typed stop so a failed
        # non-semantic assertion has durable, reviewable evidence.
        equivalent = _validation_behavior_signature(
            authoritative
        ) == _validation_behavior_signature(counterfactual)
        self._journal.opaque_proof(
            round_number,
            counterfactual_subject,
            _without_validation_raw(counterfactual) if raw_log_withheld else counterfactual,
            equivalent,
        )
        self._ensure_validation_can_continue(
            counterfactual.summary,
            evidence,
            baseline=baseline_phase,
        )
        _require_opaque_validation_independence(authoritative, counterfactual)
        self._ensure_deadline(deadline)

    @staticmethod
    def _ensure_validation_can_continue(
        summary: ValidationSummary,
        evidence: ValidationCriticEvidence,
        *,
        baseline: bool,
    ) -> None:
        """Stop non-reviewable validation states before either model boundary."""

        for check in summary.checks:
            outcome = check.outcome
            if outcome is CheckOutcome.INFRASTRUCTURE_FAILURE:
                reason = (
                    StopReason.BASELINE_INFRASTRUCTURE_FAILURE
                    if baseline
                    else StopReason.VALIDATION_PROCESS_FAILURE
                )
                raise fail(reason, f"validation infrastructure failed for {check.check_id}")
            if outcome is CheckOutcome.TIMED_OUT:
                raise fail(
                    StopReason.VALIDATION_TIMEOUT,
                    f"validation timed out for {check.check_id}",
                )
            if outcome is CheckOutcome.OUTPUT_LIMITED:
                raise fail(
                    StopReason.AGENT_OUTPUT_LIMIT,
                    f"validation output exceeded its cap for {check.check_id}",
                )
            if outcome is CheckOutcome.PROCESS_FAILURE:
                raise fail(
                    StopReason.VALIDATION_PROCESS_FAILURE,
                    f"validation process failed for {check.check_id}",
                )
        if not evidence.approval_eligible:
            raise fail(
                StopReason.REVIEW_EVIDENCE_WITHHELD,
                "validation evidence is incomplete and cannot be reviewed safely",
            )
