"""Fatal-first convergence state machine driven only by monotonic timestamps."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from .errors import ExitCode, StopReason, exit_code_for


class Action(StrEnum):
    CONTINUE = "continue"
    STOP = "stop"


_NON_FATAL_REASONS = frozenset(
    {
        StopReason.CONVERGED,
        StopReason.ROUND_CAP_REACHED,
        StopReason.STALLED,
        StopReason.CRITIC_BLOCKED,
    }
)


@dataclass(slots=True)
class FatalLatch:
    """First-failure-wins latch; later failures are retained but never replace it."""

    reason: StopReason | None = None
    detail: str | None = None
    latched_at: float | None = None
    secondary: list[tuple[StopReason, str, float]] = field(default_factory=list)

    @property
    def is_set(self) -> bool:
        return self.reason is not None

    def latch(self, reason: StopReason, detail: str, *, now: float) -> None:
        if reason in _NON_FATAL_REASONS:
            raise ValueError(f"{reason} is not a fatal reason")
        if now < 0:
            raise ValueError("monotonic timestamp cannot be negative")
        if self.reason is None:
            self.reason = reason
            self.detail = detail
            self.latched_at = now
        else:
            self.secondary.append((reason, detail, now))

    def clear(self) -> None:
        """Explicitly forbidden: fatal state is monotonic for a run."""

        raise RuntimeError("a fatal latch cannot be cleared")


@dataclass(frozen=True, slots=True)
class RoundObservation:
    round_count: int
    max_rounds: int
    all_validations_pass: bool
    semantic_deltas_visible: bool
    evidence_approval_eligible: bool
    critic_verdict: str | None
    critic_completed_at: float | None
    monotonic_deadline: float
    repeated_non_success_state: bool = False

    def __post_init__(self) -> None:
        if self.round_count < 1:
            raise ValueError("round_count must be positive")
        if self.max_rounds < 1:
            raise ValueError("max_rounds must be positive")
        if self.monotonic_deadline < 0:
            raise ValueError("deadline cannot be negative")
        if self.critic_completed_at is not None and self.critic_completed_at < 0:
            raise ValueError("completion timestamp cannot be negative")
        if self.critic_verdict not in {None, "LGTM", "REVISE", "BLOCKED"}:
            raise ValueError("unknown critic verdict")


@dataclass(frozen=True, slots=True)
class Decision:
    action: Action
    reason: StopReason | None = None
    exit_code: ExitCode | None = None


def decide(observation: RoundObservation, fatal: FatalLatch) -> Decision:
    """Apply the exact plan-v1.1 fatal/success/BLOCKED/cap/stall order."""

    if (
        observation.critic_completed_at is not None
        and observation.critic_completed_at > observation.monotonic_deadline
    ):
        fatal.latch(
            StopReason.WALL_CLOCK_DEADLINE_EXCEEDED,
            "critic envelope completed after the run deadline",
            now=observation.critic_completed_at,
        )

    if observation.critic_verdict == "LGTM" and not (
        observation.all_validations_pass
        and observation.semantic_deltas_visible
        and observation.evidence_approval_eligible
    ):
        fatal.latch(
            StopReason.CRITIC_LGTM_WITH_FAILED_VALIDATION,
            "LGTM contradicted local validation or evidence state",
            now=observation.critic_completed_at or observation.monotonic_deadline,
        )

    if fatal.reason is not None:
        return Decision(Action.STOP, fatal.reason, exit_code_for(fatal.reason))

    success = (
        observation.all_validations_pass
        and observation.semantic_deltas_visible
        and observation.evidence_approval_eligible
        and observation.critic_verdict == "LGTM"
        and observation.critic_completed_at is not None
        and observation.critic_completed_at <= observation.monotonic_deadline
    )
    if success:
        return Decision(Action.STOP, StopReason.CONVERGED, ExitCode.SUCCESS)
    if observation.critic_verdict == "BLOCKED":
        return Decision(Action.STOP, StopReason.CRITIC_BLOCKED, ExitCode.CRITIC_BLOCKED)
    if observation.round_count >= observation.max_rounds:
        return Decision(Action.STOP, StopReason.ROUND_CAP_REACHED, ExitCode.ROUND_CAP)
    if observation.repeated_non_success_state:
        return Decision(Action.STOP, StopReason.STALLED, ExitCode.STALLED)
    return Decision(Action.CONTINUE)
