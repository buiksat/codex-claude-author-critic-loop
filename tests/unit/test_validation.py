import hashlib

import pytest

from agent_loop.errors import AgentLoopError, StopReason
from agent_loop.manifests import SubjectManifest
from agent_loop.models import ManifestEntry, PathPolicy
from agent_loop.validation import (
    CheckExecution,
    ValidationSummary,
    ValidationTransition,
    classify_validations,
    verify_validation_mutation,
)


def check(code: int, *, ident: str = "tests") -> CheckExecution:
    return CheckExecution(ident, "pytest -q", 1.0, 2.0, code)


def summary(code: int) -> ValidationSummary:
    return ValidationSummary(1, "a" * 64, (check(code),))


def test_020_baseline_ordinary_failure() -> None:
    classified = classify_validations(summary(1), summary(1))
    assert classified[0].transition is ValidationTransition.FAIL_TO_FAIL
    assert classified[0].regression is False


def test_021_regression_classification() -> None:
    classified = classify_validations(summary(0), summary(1))
    assert classified[0].transition is ValidationTransition.PASS_TO_FAIL
    assert classified[0].regression is True


def test_terminal_current_prefix_is_classified_but_other_omissions_are_rejected() -> None:
    baseline = ValidationSummary(
        1,
        "a" * 64,
        (check(0, ident="build"), check(0, ident="tests")),
    )
    terminal = CheckExecution(
        "build",
        "pytest -q",
        1.0,
        2.0,
        None,
        timed_out=True,
    )
    classified = classify_validations(
        baseline,
        ValidationSummary(1, "a" * 64, (terminal,)),
    )
    assert classified[0].current_outcome.value == "timed_out"

    ordinary_prefix = ValidationSummary(1, "a" * 64, (check(1, ident="build"),))
    with pytest.raises(ValueError, match="sequences differ"):
        classify_validations(baseline, ordinary_prefix)

    reordered = ValidationSummary(
        1,
        "a" * 64,
        (check(0, ident="tests"), check(0, ident="build")),
    )
    with pytest.raises(ValueError, match="sequences differ"):
        classify_validations(baseline, reordered)


def test_deadline_before_check_start_remains_a_timeout_not_infrastructure() -> None:
    execution = CheckExecution(
        "tests",
        "pytest -q",
        1.0,
        1.0,
        None,
        timed_out=True,
        process_started=False,
    )
    assert execution.outcome.value == "timed_out"


def test_baseline_infrastructure_failure_is_fatal() -> None:
    broken = ValidationSummary(
        1,
        "a" * 64,
        (
            CheckExecution(
                "tests",
                "pytest -q",
                1.0,
                1.0,
                None,
                infrastructure_failure=True,
                process_started=False,
            ),
        ),
    )
    with pytest.raises(AgentLoopError) as caught:
        classify_validations(broken, summary(0))
    assert caught.value.reason is StopReason.BASELINE_INFRASTRUCTURE_FAILURE


def _entry(path: bytes, data: bytes) -> ManifestEntry:
    return ManifestEntry.regular(
        path,
        size=len(data),
        blob_sha256=hashlib.sha256(data).hexdigest(),
    )


@pytest.mark.parametrize(
    ("subject", "mutated", "policy"),
    [
        pytest.param(
            SubjectManifest.build((_entry(b"a.py", b"one"),)),
            SubjectManifest.build((_entry(b"a.py", b"two"),)),
            PathPolicy(),
            id="content",
        ),
        pytest.param(
            SubjectManifest.build((_entry(b"tool", b"same"),)),
            SubjectManifest.build(
                (
                    ManifestEntry.regular(
                        b"tool",
                        size=4,
                        blob_sha256=hashlib.sha256(b"same").hexdigest(),
                        executable=True,
                    ),
                )
            ),
            PathPolicy(),
            id="mode",
        ),
        pytest.param(
            SubjectManifest.build((ManifestEntry.symlink(b"link", target=b"old"),)),
            SubjectManifest.build((ManifestEntry.symlink(b"link", target=b"new"),)),
            PathPolicy(),
            id="symlink",
        ),
        pytest.param(
            SubjectManifest.empty(),
            SubjectManifest.build((_entry(b".git/config", b"mutation"),)),
            PathPolicy(discard_only_patterns=(b".git/**",)),
            id="protected-path-cannot-be-discarded",
        ),
    ],
)
def test_023_validation_mutation(
    subject: SubjectManifest,
    mutated: SubjectManifest,
    policy: PathPolicy,
) -> None:
    with pytest.raises(AgentLoopError) as caught:
        verify_validation_mutation(subject, mutated, policy)
    assert caught.value.reason is StopReason.VALIDATION_MUTATED_SUBJECT


def test_024_allowed_validation_output() -> None:
    subject = SubjectManifest.build((_entry(b"a.py", b"one"),))
    output = SubjectManifest.build((*subject.entries, _entry(b"build/cache", b"data")))
    policy = PathPolicy(discard_only_patterns=(b"build/**",))
    assert verify_validation_mutation(subject, output, policy) == (b"build/cache",)
