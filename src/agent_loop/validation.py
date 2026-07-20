"""Validation result classification independent of the sandbox implementation."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .errors import StopReason, fail
from .manifests import SubjectManifest, diff_manifests
from .models import PathDisposition, PathPolicy


class CheckOutcome(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    OUTPUT_LIMITED = "output_limited"
    PROCESS_FAILURE = "process_failure"
    INFRASTRUCTURE_FAILURE = "infrastructure_failure"


class ValidationTransition(StrEnum):
    PASS_TO_PASS = "pass_to_pass"
    PASS_TO_FAIL = "pass_to_fail"
    FAIL_TO_PASS = "fail_to_pass"
    FAIL_TO_FAIL = "fail_to_fail"
    NO_BASELINE = "no_baseline"


@dataclass(frozen=True, slots=True)
class CheckExecution:
    check_id: str
    command: str
    started_at: float
    completed_at: float
    exit_code: int | None
    signal: int | None = None
    timed_out: bool = False
    infrastructure_failure: bool = False
    process_started: bool = True
    output_limited: bool = False

    def __post_init__(self) -> None:
        if not self.check_id or not self.command:
            raise ValueError("check_id and command must be non-empty")
        if self.started_at < 0 or self.completed_at < self.started_at:
            raise ValueError("validation timestamps must be monotonic and ordered")
        terminal = sum(
            (
                self.exit_code is not None,
                self.signal is not None,
                self.timed_out,
                self.infrastructure_failure,
                not self.process_started,
                self.output_limited,
            )
        )
        if terminal == 0:
            raise ValueError("validation execution has no terminal state")
        if self.exit_code is not None and (self.signal is not None or self.timed_out):
            raise ValueError("exit code contradicts signal or timeout")
        if self.infrastructure_failure and self.process_started:
            raise ValueError("infrastructure failure must precede check process start")
        if self.output_limited and not self.process_started:
            raise ValueError("an output-limited validation process must have started")

    @property
    def outcome(self) -> CheckOutcome:
        if self.output_limited:
            return CheckOutcome.OUTPUT_LIMITED
        if self.timed_out:
            return CheckOutcome.TIMED_OUT
        if self.infrastructure_failure or not self.process_started:
            return CheckOutcome.INFRASTRUCTURE_FAILURE
        if self.signal is not None:
            return CheckOutcome.PROCESS_FAILURE
        return CheckOutcome.PASSED if self.exit_code == 0 else CheckOutcome.FAILED


@dataclass(frozen=True, slots=True)
class ValidationSummary:
    schema_version: int
    subject_fingerprint: str
    checks: tuple[CheckExecution, ...]

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("unsupported validation summary schema")
        if len(self.subject_fingerprint) != 64:
            raise ValueError("subject fingerprint must be a SHA-256 hex string")
        identifiers = [check.check_id for check in self.checks]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("validation check IDs must be unique")

    @property
    def all_pass(self) -> bool:
        return bool(self.checks) and all(
            check.outcome is CheckOutcome.PASSED for check in self.checks
        )

    @property
    def has_infrastructure_failure(self) -> bool:
        return any(check.outcome is CheckOutcome.INFRASTRUCTURE_FAILURE for check in self.checks)


@dataclass(frozen=True, slots=True)
class ClassifiedCheck:
    check_id: str
    command: str
    baseline_outcome: CheckOutcome | None
    current_outcome: CheckOutcome
    transition: ValidationTransition
    regression: bool
    exit_code: int | None
    signal: int | None


def classify_validations(
    baseline: ValidationSummary | None,
    current: ValidationSummary,
) -> tuple[ClassifiedCheck, ...]:
    if baseline is not None and baseline.has_infrastructure_failure:
        raise fail(
            StopReason.BASELINE_INFRASTRUCTURE_FAILURE,
            "pristine validation sandbox or toolchain failed before check execution",
        )
    baseline_by_id = (
        {} if baseline is None else {check.check_id: check for check in baseline.checks}
    )
    if baseline is not None:
        baseline_ids = tuple(check.check_id for check in baseline.checks)
        current_ids = tuple(check.check_id for check in current.checks)
        exact_sequence = current_ids == baseline_ids
        terminal_prefix = bool(
            current.checks
            and len(current_ids) < len(baseline_ids)
            and current_ids == baseline_ids[: len(current_ids)]
            and current.checks[-1].outcome
            in {
                CheckOutcome.TIMED_OUT,
                CheckOutcome.OUTPUT_LIMITED,
                CheckOutcome.PROCESS_FAILURE,
                CheckOutcome.INFRASTRUCTURE_FAILURE,
            }
        )
        if not exact_sequence and not terminal_prefix:
            raise ValueError("baseline and current validation sequences differ")
    result: list[ClassifiedCheck] = []
    for check in current.checks:
        old = baseline_by_id.get(check.check_id)
        if old is not None and old.command != check.command:
            raise fail(
                StopReason.VALIDATION_MUTATED_SUBJECT,
                f"validation command changed for {check.check_id}",
            )
        old_outcome = None if old is None else old.outcome
        old_pass = old_outcome is CheckOutcome.PASSED
        new_pass = check.outcome is CheckOutcome.PASSED
        if old_outcome is None:
            transition = ValidationTransition.NO_BASELINE
        elif old_pass and new_pass:
            transition = ValidationTransition.PASS_TO_PASS
        elif old_pass:
            transition = ValidationTransition.PASS_TO_FAIL
        elif new_pass:
            transition = ValidationTransition.FAIL_TO_PASS
        else:
            transition = ValidationTransition.FAIL_TO_FAIL
        result.append(
            ClassifiedCheck(
                check_id=check.check_id,
                command=check.command,
                baseline_outcome=old_outcome,
                current_outcome=check.outcome,
                transition=transition,
                regression=old_pass and not new_pass,
                exit_code=check.exit_code,
                signal=check.signal,
            )
        )
    return tuple(result)


def verify_validation_mutation(
    subject: SubjectManifest,
    result_manifest: SubjectManifest,
    policy: PathPolicy,
) -> tuple[bytes, ...]:
    """Allow only predeclared discard-only tmpfs output, never subject mutation."""

    allowed: list[bytes] = []
    for change in diff_manifests(subject, result_manifest):
        if change.paths and all(
            policy.classify(path) is PathDisposition.DISCARD_ONLY for path in change.paths
        ):
            allowed.extend(change.paths)
            continue
        raise fail(
            StopReason.VALIDATION_MUTATED_SUBJECT,
            "validation changed authoritative or protected subject state",
        )
    return tuple(sorted(set(allowed)))
