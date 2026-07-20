"""Deterministic in-memory boundaries for serial-loop acceptance tests."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from agent_loop.constants import REGULAR_MODE
from agent_loop.declassify import ValidationCriticEvidence
from agent_loop.manifests import SubjectManifest, build_manifest_from_scan
from agent_loop.models import BlobReader, EntryKind, ManifestChange, ScanRecord
from agent_loop.prompts import ReviewBundle
from agent_loop.runner import (
    AuthorRequest,
    AuthorTurn,
    CriticRequest,
    CriticTurn,
    LoopResult,
    LoopSettings,
    ValidationAttemptPhase,
    ValidationRequest,
    ValidationTurn,
)
from agent_loop.schemas import CriticReview, Finding, Verdict
from agent_loop.validation import CheckExecution, ClassifiedCheck, ValidationSummary


class MemoryBlobStore(BlobReader):
    """Exact SHA-256 blob reader/writer used by real manifest and bundle code."""

    def __init__(self) -> None:
        self.values: dict[str, bytes] = {}

    def put_blob(self, data: bytes) -> str:
        digest = hashlib.sha256(data).hexdigest()
        self.values.setdefault(digest, data)
        return digest

    def read_blob(self, sha256: str) -> bytes:
        return self.values[sha256]


def manifest_from_files(
    blobs: MemoryBlobStore,
    files: Mapping[bytes, bytes],
    *,
    executable_paths: Sequence[bytes] = (),
) -> SubjectManifest:
    executable = frozenset(executable_paths)
    records = (
        ScanRecord(
            path=path,
            kind=EntryKind.REGULAR,
            mode=0o100755 if path in executable else REGULAR_MODE,
            payload=content,
        )
        for path, content in sorted(files.items())
    )
    return build_manifest_from_scan(records, blobs)


class FakeClock:
    def __init__(self, now: float = 100.0) -> None:
        self.now = now
        self.calls = 0

    def __call__(self) -> float:
        self.calls += 1
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class FakeAuthor:
    def __init__(
        self,
        candidates: Sequence[SubjectManifest | BaseException],
        *,
        thread_id: str = "thread-exact-001",
    ) -> None:
        self._candidates = tuple(candidates)
        self._thread_id = thread_id
        self.requests: list[AuthorRequest] = []

    def turn(self, request: AuthorRequest) -> AuthorTurn:
        self.requests.append(request)
        index = len(self.requests) - 1
        if index >= len(self._candidates):
            raise AssertionError("unexpected extra author turn")
        candidate = self._candidates[index]
        if isinstance(candidate, BaseException):
            raise candidate
        return AuthorTurn(
            candidate=candidate,
            thread_id=self._thread_id,
            final_message=f"fake author round {request.round_number}",
            events=(
                {
                    "type": "thread.started" if request.thread_id is None else "turn.resumed",
                    "thread_id": self._thread_id,
                },
            ),
            usage={"input_tokens": request.round_number},
            observed_model="fake-author-model",
            observed_effort="high",
        )


ValidationOutcome = bool | str


class FakeValidator:
    def __init__(
        self,
        outcomes: Sequence[ValidationOutcome],
        *,
        raw_logs: Sequence[bytes] = (),
        result_manifests: Sequence[SubjectManifest | None] = (),
        summary_fingerprints: Sequence[str | None] = (),
    ) -> None:
        self._outcomes = tuple(outcomes)
        self._raw_logs = tuple(raw_logs)
        self._result_manifests = tuple(result_manifests)
        self._summary_fingerprints = tuple(summary_fingerprints)
        self.requests: list[ValidationRequest] = []

    def validate(self, request: ValidationRequest) -> ValidationTurn:
        self.requests.append(request)
        index = len(self.requests) - 1
        if index >= len(self._outcomes):
            raise AssertionError("unexpected extra validation turn")
        outcome = self._outcomes[index]
        if outcome == "infra":
            check = CheckExecution(
                "check-1",
                "python -m pytest",
                1.0,
                2.0,
                None,
                infrastructure_failure=True,
                process_started=False,
            )
        elif outcome == "timeout":
            check = CheckExecution(
                "check-1",
                "python -m pytest",
                1.0,
                2.0,
                None,
                timed_out=True,
            )
        elif outcome == "signal":
            check = CheckExecution(
                "check-1",
                "python -m pytest",
                1.0,
                2.0,
                None,
                signal=9,
            )
        elif outcome == "output":
            check = CheckExecution(
                "check-1",
                "python -m pytest",
                1.0,
                2.0,
                None,
                output_limited=True,
            )
        else:
            check = CheckExecution(
                "check-1",
                "python -m pytest",
                1.0,
                2.0,
                0 if outcome is True else 1,
            )
        fingerprint = request.subject.fingerprint
        if index < len(self._summary_fingerprints):
            fingerprint = self._summary_fingerprints[index] or fingerprint
        result_manifest = request.subject
        if index < len(self._result_manifests):
            result_manifest = self._result_manifests[index] or result_manifest
        raw_log = b"validation raw log"
        if index < len(self._raw_logs):
            raw_log = self._raw_logs[index]
        return ValidationTurn(
            summary=ValidationSummary(1, fingerprint, (check,)),
            result_manifest=result_manifest,
            raw_log=raw_log,
        )


class FakeCritic:
    def __init__(
        self,
        reviews: Sequence[CriticReview],
        *,
        completed_at: Sequence[float] = (),
    ) -> None:
        self._reviews = tuple(reviews)
        self._completed_at = tuple(completed_at)
        self.requests: list[CriticRequest] = []

    def review(self, request: CriticRequest) -> CriticTurn:
        self.requests.append(request)
        index = len(self.requests) - 1
        if index >= len(self._reviews):
            raise AssertionError("unexpected extra critic turn")
        review = self._reviews[index]
        completion = request.deadline - 1.0
        if index < len(self._completed_at):
            completion = self._completed_at[index]
        return CriticTurn(
            review=review,
            completed_at=completion,
            envelope={"type": "result", "structured_output": {"verdict": review.verdict.value}},
            total_cost_usd=0.0,
            observed_model="fake-critic-model",
            observed_effort="high",
        )


@dataclass(frozen=True, slots=True)
class AuthorJournalRecord:
    round_number: int
    turn: AuthorTurn
    authoritative: SubjectManifest
    semantic: tuple[ManifestChange, ...]
    opaque: tuple[ManifestChange, ...]
    discarded: tuple[ManifestChange, ...]


@dataclass(frozen=True, slots=True)
class ValidationJournalRecord:
    round_number: int
    turn: ValidationTurn
    evidence: ValidationCriticEvidence
    classified: tuple[ClassifiedCheck, ...]


@dataclass(frozen=True, slots=True)
class CriticJournalRecord:
    round_number: int
    turn: CriticTurn
    bundle: ReviewBundle


class FakeJournal:
    def __init__(self) -> None:
        self.starts: list[tuple[str, SubjectManifest, float, LoopSettings]] = []
        self.task_inputs: list[tuple[str | None, bool]] = []
        self.subject_inputs: list[tuple[SubjectManifest | None, str, bool]] = []
        self.baselines: list[tuple[ValidationTurn, ValidationCriticEvidence]] = []
        self.validation_attempts: list[
            tuple[
                int | None,
                ValidationAttemptPhase,
                SubjectManifest,
                ValidationTurn,
                bytes,
                bool,
                bool,
                bool,
                bool,
            ]
        ] = []
        self.opaque_proofs: list[
            tuple[int | None, SubjectManifest, ValidationTurn, bool]
        ] = []
        self.author_attempts: list[tuple[int, AuthorTurn, int, bool]] = []
        self.critic_attempts: list[tuple[int, CriticTurn, int, bool]] = []
        self.authors: list[AuthorJournalRecord] = []
        self.validations: list[ValidationJournalRecord] = []
        self.critics: list[CriticJournalRecord] = []
        self.finishes: list[LoopResult] = []

    def start(
        self,
        *,
        task: str,
        base: SubjectManifest,
        deadline: float,
        settings: LoopSettings,
    ) -> None:
        self.starts.append((task, base, deadline, settings))

    def baseline(self, turn: ValidationTurn, evidence: ValidationCriticEvidence) -> None:
        self.baselines.append((turn, evidence))

    def task_input(self, task: str, *, content_withheld: bool) -> None:
        self.task_inputs.append((None if content_withheld else task, content_withheld))

    def subject_input(
        self,
        subject: SubjectManifest,
        *,
        content_withheld: bool,
    ) -> None:
        self.subject_inputs.append(
            (None if content_withheld else subject, subject.fingerprint, content_withheld)
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
        self.validation_attempts.append(
            (
                round_number,
                phase,
                expected_subject,
                turn,
                retained_raw_log,
                raw_log_truncated,
                raw_log_withheld,
                result_subject_withheld,
                summary_withheld,
            )
        )

    def opaque_proof(
        self,
        round_number: int | None,
        counterfactual: SubjectManifest,
        turn: ValidationTurn,
        equivalent: bool,
    ) -> None:
        self.opaque_proofs.append((round_number, counterfactual, turn, equivalent))

    def author_attempt(
        self,
        round_number: int,
        turn: AuthorTurn,
        max_output_bytes: int,
        content_withheld: bool,
    ) -> None:
        self.author_attempts.append(
            (round_number, turn, max_output_bytes, content_withheld)
        )

    def critic_attempt(
        self,
        round_number: int,
        turn: CriticTurn,
        max_output_bytes: int,
        content_withheld: bool,
    ) -> None:
        self.critic_attempts.append(
            (round_number, turn, max_output_bytes, content_withheld)
        )

    def author(
        self,
        round_number: int,
        turn: AuthorTurn,
        authoritative: SubjectManifest,
        semantic: tuple[ManifestChange, ...],
        opaque: tuple[ManifestChange, ...],
        discarded: tuple[ManifestChange, ...],
        _base: SubjectManifest,
        _blobs: BlobReader,
    ) -> None:
        self.authors.append(
            AuthorJournalRecord(
                round_number,
                turn,
                authoritative,
                semantic,
                opaque,
                discarded,
            )
        )

    def validation(
        self,
        round_number: int,
        turn: ValidationTurn,
        evidence: ValidationCriticEvidence,
        classified: tuple[ClassifiedCheck, ...],
    ) -> None:
        self.validations.append(
            ValidationJournalRecord(round_number, turn, evidence, classified)
        )

    def critic(self, round_number: int, turn: CriticTurn, bundle: ReviewBundle) -> None:
        self.critics.append(CriticJournalRecord(round_number, turn, bundle))

    def finish(self, result: LoopResult) -> None:
        self.finishes.append(result)


def finding(*, finding_id: str = "F-1", required_fix: str = "fix the defect") -> Finding:
    return Finding(
        finding_id,
        "high",
        "correctness",
        "app.py",
        None,
        1,
        1,
        "the implementation is incorrect",
        "the deterministic evidence demonstrates the defect",
        required_fix,
    )


def lgtm_review() -> CriticReview:
    return CriticReview(1, Verdict.LGTM, "approved", None, (), ())


def revise_review(
    *,
    finding_id: str = "F-1",
    required_fix: str = "fix the defect",
) -> CriticReview:
    return CriticReview(
        1,
        Verdict.REVISE,
        "revision required",
        None,
        (finding(finding_id=finding_id, required_fix=required_fix),),
        (),
    )


def blocked_review(reason: str = "operator input is required") -> CriticReview:
    return CriticReview(1, Verdict.BLOCKED, "blocked", reason, (), ())
