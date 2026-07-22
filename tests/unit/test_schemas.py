import json

import pytest

from agent_loop.errors import AgentLoopError, StopReason
from agent_loop.schemas import ApprovalContext, Verdict, parse_critic_envelope


def finding(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "id": "C1",
        "severity": "high",
        "category": "correctness",
        "file": "src/a.py",
        "symbol": "f",
        "line_start": 1,
        "line_end": 2,
        "problem": "wrong result",
        "evidence": "the complete delta returns zero",
        "required_fix": "return one",
    }
    value.update(changes)
    return value


def review(verdict: str = "LGTM") -> dict[str, object]:
    return {
        "schema_version": 1,
        "verdict": verdict,
        "summary": "assessment",
        "blocked_reason": None,
        "blocking_findings": [],
        "non_blocking_findings": [],
    }


def envelope(value: object) -> bytes:
    return json.dumps({"type": "result", "structured_output": {"review": value}}).encode()


def green() -> ApprovalContext:
    return ApprovalContext(True, True, True)


def test_valid_lgtm_is_extracted_only_from_structured_output_review() -> None:
    raw, parsed = parse_critic_envelope(envelope(review()), approval=green())
    assert raw["type"] == "result"
    assert parsed.verdict is Verdict.LGTM


def test_028_lgtm_with_failed_validation_rejected() -> None:
    with pytest.raises(AgentLoopError) as caught:
        parse_critic_envelope(
            envelope(review()),
            approval=ApprovalContext(False, True, True),
        )
    assert caught.value.reason is StopReason.CRITIC_LGTM_WITH_FAILED_VALIDATION


@pytest.mark.parametrize(
    "bad",
    [
        {**review(), "schema_version": 2},
        {**review(), "unknown": True},
        {**review("REVISE")},
        {**review("BLOCKED")},
        {**review(), "blocking_findings": [finding()]},
        {**review("REVISE"), "blocking_findings": [finding(line_start=3, line_end=2)]},
        {**review("REVISE"), "blocking_findings": [finding(severity="urgent")]},
        {**review("REVISE"), "blocking_findings": [finding(category="style")]},
        {**review(), "summary": "x" * 32769},
    ],
)
def test_052_schema_semantics(bad: dict[str, object]) -> None:
    with pytest.raises(AgentLoopError) as caught:
        parse_critic_envelope(envelope(bad), approval=green())
    assert caught.value.reason in {
        StopReason.INVALID_STRUCTURED_OUTPUT,
        StopReason.CRITIC_LGTM_WITH_FAILED_VALIDATION,
    }


def test_052_valid_revise_and_blocked() -> None:
    revise = review("REVISE")
    revise["blocking_findings"] = [finding()]
    assert parse_critic_envelope(envelope(revise))[1].verdict is Verdict.REVISE
    blocked = review("BLOCKED")
    blocked["blocked_reason"] = "missing external specification"
    assert parse_critic_envelope(envelope(blocked))[1].verdict is Verdict.BLOCKED


def test_052_prose_approval_and_missing_structured_output_are_rejected() -> None:
    with pytest.raises(AgentLoopError):
        parse_critic_envelope(json.dumps({"result": "LGTM"}).encode())
    with pytest.raises(AgentLoopError):
        parse_critic_envelope(b'{"structured_output":{},"structured_output":{}}')


@pytest.mark.parametrize(
    "structured_output",
    [
        review(),
        {},
        {"review": review(), "unknown": True},
        {"review": []},
    ],
)
def test_structured_output_requires_exact_review_wrapper(structured_output: object) -> None:
    with pytest.raises(AgentLoopError) as caught:
        parse_critic_envelope(
            json.dumps({"type": "result", "structured_output": structured_output}).encode()
        )
    assert caught.value.reason is StopReason.INVALID_STRUCTURED_OUTPUT


def test_hostile_json_depth_and_integer_size_are_invalid_not_internal() -> None:
    hostile_values = (
        b'{"value":' + b"[" * 2_000 + b"]" * 2_000 + b"}",
        b'{"value":' + b"9" * 100_000 + b"}",
    )
    for hostile in hostile_values:
        with pytest.raises(AgentLoopError) as captured:
            parse_critic_envelope(hostile)
        assert captured.value.reason is StopReason.INVALID_STRUCTURED_OUTPUT
