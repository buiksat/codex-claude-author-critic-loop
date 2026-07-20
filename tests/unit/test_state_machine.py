from agent_loop.errors import ExitCode, StopReason
from agent_loop.state_machine import Action, FatalLatch, RoundObservation, decide


def observation(**changes: object) -> RoundObservation:
    values: dict[str, object] = {
        "round_count": 1,
        "max_rounds": 3,
        "all_validations_pass": True,
        "semantic_deltas_visible": True,
        "evidence_approval_eligible": True,
        "critic_verdict": "LGTM",
        "critic_completed_at": 90.0,
        "monotonic_deadline": 100.0,
        "repeated_non_success_state": False,
    }
    values.update(changes)
    return RoundObservation(**values)  # type: ignore[arg-type]


def test_015_fatal_integrity_beats_lgtm() -> None:
    fatal = FatalLatch()
    fatal.latch(StopReason.OUT_OF_BAND_CHANGE, "changed", now=80.0)
    result = decide(observation(), fatal)
    assert result.exit_code is ExitCode.INTEGRITY_FAILURE
    assert result.reason is StopReason.OUT_OF_BAND_CHANGE


def test_016_late_approval() -> None:
    result = decide(observation(critic_completed_at=100.001), FatalLatch())
    assert result.exit_code is ExitCode.TIMEOUT


def test_017_final_round_success() -> None:
    result = decide(observation(round_count=3), FatalLatch())
    assert result.exit_code is ExitCode.SUCCESS


def test_018_fatal_latch_is_monotonic() -> None:
    fatal = FatalLatch()
    fatal.latch(StopReason.AUTHOR_TIMEOUT, "first", now=1.0)
    fatal.latch(StopReason.OUT_OF_BAND_CHANGE, "second", now=2.0)
    assert fatal.reason is StopReason.AUTHOR_TIMEOUT
    assert fatal.secondary == [(StopReason.OUT_OF_BAND_CHANGE, "second", 2.0)]
    try:
        fatal.clear()
    except RuntimeError:
        pass
    else:
        raise AssertionError("fatal latch was cleared")


def test_027_blocked_review() -> None:
    result = decide(
        observation(
            all_validations_pass=False,
            critic_verdict="BLOCKED",
            semantic_deltas_visible=True,
            evidence_approval_eligible=False,
        ),
        FatalLatch(),
    )
    assert result.exit_code is ExitCode.CRITIC_BLOCKED


def test_058_round_cap_after_success_and_fatal_checks() -> None:
    capped = decide(
        observation(round_count=3, critic_verdict="REVISE", all_validations_pass=False),
        FatalLatch(),
    )
    assert capped.exit_code is ExitCode.ROUND_CAP
    continued = decide(
        observation(
            round_count=1,
            critic_verdict="REVISE",
            all_validations_pass=False,
            repeated_non_success_state=False,
        ),
        FatalLatch(),
    )
    assert continued.action is Action.CONTINUE


def test_lgtm_with_failed_validation_is_invalid() -> None:
    result = decide(observation(all_validations_pass=False), FatalLatch())
    assert result.exit_code is ExitCode.INVALID_CRITIC
    assert result.reason is StopReason.CRITIC_LGTM_WITH_FAILED_VALIDATION
