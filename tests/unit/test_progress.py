from agent_loop.progress import ProgressState, StallDetector, ValidationProgress


def make_state(subject: str = "a") -> ProgressState:
    return ProgressState(
        subject_fingerprint=subject * 64,
        validations=(ValidationProgress("test", "failed", "red_to_red", False, True),),
        verdict="REVISE",
    )


def test_057_exact_state_stall() -> None:
    detector = StallDetector()
    assert detector.observe(make_state()) is False
    assert detector.observe(make_state()) is True


def test_057_changed_state_relies_on_cap() -> None:
    detector = StallDetector()
    assert detector.observe(make_state("a")) is False
    assert detector.observe(make_state("b")) is False


def test_progress_ignores_no_implicit_unstable_envelope_fields() -> None:
    state = make_state()
    assert state.canonical_bytes() == make_state().canonical_bytes()
