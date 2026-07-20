"""Typed fail-closed errors and the stable public exit contract."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, StrEnum


class ExitCode(IntEnum):
    SUCCESS = 0
    ROUND_CAP = 10
    STALLED = 11
    TIMEOUT = 12
    INTERRUPTED = 13
    INVALID_CRITIC = 14
    CRITIC_BLOCKED = 15
    PROCESS_FAILURE = 16
    INTEGRITY_FAILURE = 17
    INTERNAL_ERROR = 18


class StopReason(StrEnum):
    CONVERGED = "converged"
    ROUND_CAP_REACHED = "round_cap_reached"
    STALLED = "stalled"
    AUTHOR_TIMEOUT = "author_timeout"
    CRITIC_TIMEOUT = "critic_timeout"
    VALIDATION_TIMEOUT = "validation_timeout"
    WALL_CLOCK_DEADLINE_EXCEEDED = "wall_clock_deadline_exceeded"
    USER_INTERRUPT = "user_interrupt"
    INVALID_STRUCTURED_OUTPUT = "invalid_structured_output"
    CRITIC_LGTM_WITH_FAILED_VALIDATION = "critic_lgtm_with_failed_validation"
    CRITIC_BLOCKED = "critic_blocked"
    AUTHOR_PROCESS_FAILURE = "author_process_failure"
    CRITIC_PROCESS_FAILURE = "critic_process_failure"
    VALIDATION_PROCESS_FAILURE = "validation_process_failure"
    CRITIC_MAX_TURNS_EXHAUSTED = "critic_max_turns_exhausted"
    AGENT_OUTPUT_LIMIT = "agent_output_limit"
    STRUCTURED_OUTPUT_RETRIES = "structured_output_retries"
    REVIEW_BUNDLE_TOO_LARGE = "review_bundle_too_large"
    REVIEW_CONTENT_WITHHELD = "review_content_withheld"
    REVIEW_EVIDENCE_WITHHELD = "review_evidence_withheld"
    UNSAFE_OR_AMBIGUOUS_PATH = "unsafe_or_ambiguous_path"
    UNSAFE_FILE_TYPE_OR_HARD_LINK = "unsafe_file_type_or_hard_link"
    PROTECTED_SUBJECT_PATH_CHANGED = "protected_subject_path_changed"
    VALIDATION_MUTATED_SUBJECT = "validation_mutated_subject"
    OUT_OF_BAND_CHANGE = "out_of_band_change"
    SANDBOX_SETUP_FAILURE = "sandbox_setup_failure"
    BASELINE_INFRASTRUCTURE_FAILURE = "baseline_infrastructure_failure"
    GIT_POLICY_OR_OUTPUT_FAILURE = "git_policy_or_output_failure"
    AUTHOR_SERVICE_NOT_EMPTY = "author_service_not_empty"
    BWRAP_PACKAGE_OR_MODE_UNSAFE = "bwrap_package_or_mode_unsafe"
    REPOSITORY_SHAPE_UNSUPPORTED = "repository_shape_unsupported"
    PROJECT_INSTRUCTION_ISOLATION = "project_instruction_isolation"
    GITLESS_INVOCATION_PROBE_FAILED = "gitless_invocation_probe_failed"
    CREDENTIAL_STATE_CONFLICT = "credential_state_conflict"
    CREDENTIAL_REFRESH_FAILURE = "credential_refresh_failure"
    DIAGNOSTIC_PATCH_FAILURE = "diagnostic_patch_failure"
    SERVICE_LIFECYCLE_MISMATCH = "service_lifecycle_mismatch"
    RUNNER_INTERNAL_ERROR = "runner_internal_error"


_EXIT_BY_REASON: dict[StopReason, ExitCode] = {
    StopReason.CONVERGED: ExitCode.SUCCESS,
    StopReason.ROUND_CAP_REACHED: ExitCode.ROUND_CAP,
    StopReason.STALLED: ExitCode.STALLED,
    StopReason.AUTHOR_TIMEOUT: ExitCode.TIMEOUT,
    StopReason.CRITIC_TIMEOUT: ExitCode.TIMEOUT,
    StopReason.VALIDATION_TIMEOUT: ExitCode.TIMEOUT,
    StopReason.WALL_CLOCK_DEADLINE_EXCEEDED: ExitCode.TIMEOUT,
    StopReason.USER_INTERRUPT: ExitCode.INTERRUPTED,
    StopReason.INVALID_STRUCTURED_OUTPUT: ExitCode.INVALID_CRITIC,
    StopReason.CRITIC_LGTM_WITH_FAILED_VALIDATION: ExitCode.INVALID_CRITIC,
    StopReason.CRITIC_BLOCKED: ExitCode.CRITIC_BLOCKED,
    StopReason.AUTHOR_PROCESS_FAILURE: ExitCode.PROCESS_FAILURE,
    StopReason.CRITIC_PROCESS_FAILURE: ExitCode.PROCESS_FAILURE,
    StopReason.VALIDATION_PROCESS_FAILURE: ExitCode.PROCESS_FAILURE,
    StopReason.CRITIC_MAX_TURNS_EXHAUSTED: ExitCode.PROCESS_FAILURE,
    StopReason.AGENT_OUTPUT_LIMIT: ExitCode.PROCESS_FAILURE,
    StopReason.STRUCTURED_OUTPUT_RETRIES: ExitCode.PROCESS_FAILURE,
    StopReason.REVIEW_BUNDLE_TOO_LARGE: ExitCode.INTEGRITY_FAILURE,
    StopReason.REVIEW_CONTENT_WITHHELD: ExitCode.INTEGRITY_FAILURE,
    StopReason.REVIEW_EVIDENCE_WITHHELD: ExitCode.INTEGRITY_FAILURE,
    StopReason.UNSAFE_OR_AMBIGUOUS_PATH: ExitCode.INTEGRITY_FAILURE,
    StopReason.UNSAFE_FILE_TYPE_OR_HARD_LINK: ExitCode.INTEGRITY_FAILURE,
    StopReason.PROTECTED_SUBJECT_PATH_CHANGED: ExitCode.INTEGRITY_FAILURE,
    StopReason.VALIDATION_MUTATED_SUBJECT: ExitCode.INTEGRITY_FAILURE,
    StopReason.OUT_OF_BAND_CHANGE: ExitCode.INTEGRITY_FAILURE,
    StopReason.SANDBOX_SETUP_FAILURE: ExitCode.INTEGRITY_FAILURE,
    StopReason.BASELINE_INFRASTRUCTURE_FAILURE: ExitCode.INTEGRITY_FAILURE,
    StopReason.GIT_POLICY_OR_OUTPUT_FAILURE: ExitCode.INTEGRITY_FAILURE,
    StopReason.AUTHOR_SERVICE_NOT_EMPTY: ExitCode.INTEGRITY_FAILURE,
    StopReason.BWRAP_PACKAGE_OR_MODE_UNSAFE: ExitCode.INTEGRITY_FAILURE,
    StopReason.REPOSITORY_SHAPE_UNSUPPORTED: ExitCode.INTEGRITY_FAILURE,
    StopReason.PROJECT_INSTRUCTION_ISOLATION: ExitCode.INTEGRITY_FAILURE,
    StopReason.GITLESS_INVOCATION_PROBE_FAILED: ExitCode.INTEGRITY_FAILURE,
    StopReason.CREDENTIAL_STATE_CONFLICT: ExitCode.INTEGRITY_FAILURE,
    StopReason.CREDENTIAL_REFRESH_FAILURE: ExitCode.INTEGRITY_FAILURE,
    StopReason.DIAGNOSTIC_PATCH_FAILURE: ExitCode.INTEGRITY_FAILURE,
    StopReason.SERVICE_LIFECYCLE_MISMATCH: ExitCode.INTEGRITY_FAILURE,
    StopReason.RUNNER_INTERNAL_ERROR: ExitCode.INTERNAL_ERROR,
}


def exit_code_for(reason: StopReason) -> ExitCode:
    """Return the stable category for a precise stop reason."""

    return _EXIT_BY_REASON[reason]


@dataclass(eq=False)
class AgentLoopError(Exception):
    """Expected fail-closed error with stable externally visible semantics."""

    reason: StopReason
    detail: str

    @property
    def exit_code(self) -> ExitCode:
        return exit_code_for(self.reason)

    def __str__(self) -> str:
        return f"{self.reason}: {self.detail}"


def fail(reason: StopReason, detail: str) -> AgentLoopError:
    return AgentLoopError(reason=reason, detail=detail)
