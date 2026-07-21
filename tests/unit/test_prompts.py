import hashlib

import pytest

from agent_loop.constants import DEFAULT_REVIEW_CONTEXT_TOKENS, Limits
from agent_loop.declassify import ValidationCriticEvidence
from agent_loop.errors import AgentLoopError, StopReason
from agent_loop.manifests import SubjectManifest, diff_manifests
from agent_loop.models import ManifestEntry
from agent_loop.prompts import CRITIC_PROMPT, FindingLedgerItem, build_review_bundle


class Blobs:
    def __init__(self, values: dict[str, bytes]) -> None:
        self.values = values

    def read_blob(self, digest: str) -> bytes:
        return self.values[digest]


def entry(path: bytes, data: bytes) -> tuple[ManifestEntry, dict[str, bytes]]:
    digest = hashlib.sha256(data).hexdigest()
    return ManifestEntry.regular(path, size=len(data), blob_sha256=digest), {digest: data}


def evidence(fingerprint: str) -> ValidationCriticEvidence:
    return ValidationCriticEvidence(1, fingerprint, True, ())


def test_critic_prompt_states_exact_verdict_field_invariants() -> None:
    assert "LGTM: blocked_reason must be JSON null and blocking_findings must be []" in (
        CRITIC_PROMPT
    )
    assert (
        "REVISE: blocked_reason must be JSON null and blocking_findings must be non-empty"
        in CRITIC_PROMPT
    )
    assert (
        "BLOCKED: blocked_reason must be a non-empty, non-whitespace string "
        "and\n  blocking_findings must be []"
        in CRITIC_PROMPT
    )
    assert 'Never substitute a phrase such as "none" for JSON null.' in CRITIC_PROMPT


def test_053_bundle_budgets() -> None:
    changed, values = entry(b"large.bin", b"x" * 200)
    base = SubjectManifest.empty()
    subject = SubjectManifest.build((changed,))
    with pytest.raises(AgentLoopError) as caught:
        build_review_bundle(
            task="do it",
            base=base,
            subject=subject,
            semantic_changes=diff_manifests(base, subject),
            opaque_changes=(),
            blobs=Blobs(values),
            validation=evidence(subject.fingerprint),
            protected_patterns=(),
            opaque_patterns=(),
            limits=Limits(max_bundle_bytes=128, max_estimated_input_tokens=128),
        )
    assert caught.value.reason is StopReason.REVIEW_CONTENT_WITHHELD

    with pytest.raises(AgentLoopError) as context_caught:
        build_review_bundle(
            task="review context",
            base=subject,
            subject=subject,
            semantic_changes=(),
            opaque_changes=(),
            blobs=Blobs(values),
            validation=evidence(subject.fingerprint),
            protected_patterns=(),
            opaque_patterns=(),
            context_paths=(b"large.bin",),
            limits=Limits(max_bundle_bytes=128, max_estimated_input_tokens=128),
        )
    assert context_caught.value.reason is StopReason.REVIEW_BUNDLE_TOO_LARGE

    with pytest.raises(ValueError, match="reserved output"):
        Limits(
            max_estimated_input_tokens=DEFAULT_REVIEW_CONTEXT_TOKENS,
            reserved_output_tokens=1,
        )


def test_053_changed_file_limit_withholds_the_complete_semantic_delta() -> None:
    first, first_values = entry(b"first.py", b"first = 1\n")
    second, second_values = entry(b"second.py", b"second = 2\n")
    base = SubjectManifest.empty()
    subject = SubjectManifest.build((first, second))

    with pytest.raises(AgentLoopError) as caught:
        build_review_bundle(
            task="review all changes",
            base=base,
            subject=subject,
            semantic_changes=diff_manifests(base, subject),
            opaque_changes=(),
            blobs=Blobs(first_values | second_values),
            validation=evidence(subject.fingerprint),
            protected_patterns=(),
            opaque_patterns=(),
            limits=Limits(max_files=1),
        )

    assert caught.value.reason is StopReason.REVIEW_CONTENT_WITHHELD


def test_053_findings_limit_fails_before_bundle_construction() -> None:
    subject = SubjectManifest.empty()
    findings = (
        FindingLedgerItem("C1", "fix the first issue", "open"),
        FindingLedgerItem("C2", "fix the second issue", "claimed_resolved"),
    )

    with pytest.raises(AgentLoopError) as caught:
        build_review_bundle(
            task="review findings",
            base=subject,
            subject=subject,
            semantic_changes=(),
            opaque_changes=(),
            blobs=Blobs({}),
            validation=evidence(subject.fingerprint),
            protected_patterns=(),
            opaque_patterns=(),
            prior_findings=findings,
            limits=Limits(max_findings=1),
        )

    assert caught.value.reason is StopReason.REVIEW_BUNDLE_TOO_LARGE


def test_053_task_field_limit_fails_before_bundle_construction() -> None:
    subject = SubjectManifest.empty()

    with pytest.raises(AgentLoopError) as caught:
        build_review_bundle(
            task="12345",
            base=subject,
            subject=subject,
            semantic_changes=(),
            opaque_changes=(),
            blobs=Blobs({}),
            validation=evidence(subject.fingerprint),
            protected_patterns=(),
            opaque_patterns=(),
            limits=Limits(max_field_bytes=4),
        )

    assert caught.value.reason is StopReason.REVIEW_BUNDLE_TOO_LARGE


@pytest.mark.parametrize(
    ("limits", "detail"),
    [
        (Limits(max_bundle_bytes=128), "max_bundle_bytes"),
        (Limits(max_estimated_input_tokens=128), "max_estimated_input_tokens"),
    ],
)
def test_053_byte_and_estimated_input_limits_are_independent(
    limits: Limits,
    detail: str,
) -> None:
    subject = SubjectManifest.empty()

    with pytest.raises(AgentLoopError) as caught:
        build_review_bundle(
            task="review",
            base=subject,
            subject=subject,
            semantic_changes=(),
            opaque_changes=(),
            blobs=Blobs({}),
            validation=evidence(subject.fingerprint),
            protected_patterns=(),
            opaque_patterns=(),
            limits=limits,
        )

    assert caught.value.reason is StopReason.REVIEW_BUNDLE_TOO_LARGE
    assert detail in caught.value.detail


def test_054_review_limitation_recorded() -> None:
    base = SubjectManifest.empty()
    bundle = build_review_bundle(
        task="already done",
        base=base,
        subject=base,
        semantic_changes=(),
        opaque_changes=(),
        blobs=Blobs({}),
        validation=evidence(base.fingerprint),
        protected_patterns=(),
        opaque_patterns=(),
    )
    limitations = bundle.document["review_context_limitations"]
    assert isinstance(limitations, dict)
    assert limitations["repository_wide_access"] is False
    assert limitations["unchanged_context_omitted"] is True


def test_054_configured_context_obeys_sensitive_path_rules() -> None:
    context_entry, values = entry(b".env", b"TOKEN=not-for-review\n")
    subject = SubjectManifest.build((context_entry,))

    with pytest.raises(AgentLoopError) as caught:
        build_review_bundle(
            task="review configured context",
            base=subject,
            subject=subject,
            semantic_changes=(),
            opaque_changes=(),
            blobs=Blobs(values),
            validation=evidence(subject.fingerprint),
            protected_patterns=(),
            opaque_patterns=(),
            context_paths=(b".env",),
        )

    assert caught.value.reason is StopReason.REVIEW_CONTENT_WITHHELD


@pytest.mark.parametrize("path", [b".env", b".npmrc", b"service/package-auth.json"])
def test_068_withheld_semantic_delta(path: bytes) -> None:
    changed, values = entry(path, b"credential=value")
    base = SubjectManifest.empty()
    subject = SubjectManifest.build((changed,))
    with pytest.raises(AgentLoopError) as caught:
        build_review_bundle(
            task="change config",
            base=base,
            subject=subject,
            semantic_changes=diff_manifests(base, subject),
            opaque_changes=(),
            blobs=Blobs(values),
            validation=evidence(subject.fingerprint),
            protected_patterns=(),
            opaque_patterns=(),
        )
    assert caught.value.reason is StopReason.REVIEW_CONTENT_WITHHELD


def test_068_oversized_complete_semantic_delta_is_never_replaced_by_hash_only() -> None:
    changed, values = entry(b"large.bin", b"\x00" + b"x" * 512)
    subject = SubjectManifest.build((changed,))

    with pytest.raises(AgentLoopError) as caught:
        build_review_bundle(
            task="change binary",
            base=SubjectManifest.empty(),
            subject=subject,
            semantic_changes=diff_manifests(SubjectManifest.empty(), subject),
            opaque_changes=(),
            blobs=Blobs(values),
            validation=evidence(subject.fingerprint),
            protected_patterns=(),
            opaque_patterns=(),
            limits=Limits(max_bundle_bytes=256, max_estimated_input_tokens=256),
        )

    assert caught.value.reason is StopReason.REVIEW_CONTENT_WITHHELD
