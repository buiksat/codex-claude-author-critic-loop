from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator, Draft202012Validator, ValidationError

from agent_loop.artifacts import ArtifactStore
from agent_loop.constants import SUPPORTED_BWRAP_SHA256
from agent_loop.declassify import declassify_validation
from agent_loop.errors import ExitCode, StopReason
from agent_loop.manifests import SubjectManifest
from agent_loop.models import ManifestEntry, sha256_hex
from agent_loop.preflight import EnvironmentReport, TrustedExecutable
from agent_loop.prompts import ReviewBundle
from agent_loop.runner import (
    ArtifactRunJournal,
    AuthorTurn,
    CriticTurn,
    LoopResult,
    LoopSettings,
    ValidationTurn,
)
from agent_loop.sandbox import BubblewrapProvenance
from agent_loop.schemas import CriticReview, Verdict, critic_schema_document
from agent_loop.validation import CheckExecution, ValidationSummary, classify_validations


SCHEMA_ROOT = Path(__file__).parents[2] / "schemas"


def schema(name: str) -> dict[str, object]:
    value = json.loads((SCHEMA_ROOT / name).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(schema(name))


def environment_record() -> dict[str, object]:
    bwrap_digest = next(iter(SUPPORTED_BWRAP_SHA256))
    bwrap = BubblewrapProvenance(
        "0.11.1-1ubuntu0.1",
        "0.11.1",
        "/usr/bin/bwrap",
        0,
        0,
        0o755,
        bwrap_digest,
    )
    codex = TrustedExecutable(
        "/opt/codex",
        "/opt/codex",
        1000,
        0o755,
        "c" * 64,
        "codex-cli 0.144.6",
    )
    claude = TrustedExecutable(
        "/opt/claude",
        "/opt/claude",
        1000,
        0o755,
        "d" * 64,
        "2.1.215 (Claude Code)",
    )
    python_executable = TrustedExecutable(
        "/usr/bin/python3",
        "/usr/bin/python3.14",
        0,
        0o755,
        "e" * 64,
        "Python 3.14.4",
    )
    return EnvironmentReport(
        "ubuntu",
        "26.04",
        "x86_64",
        "7.0.0-test",
        "3.14.4",
        "git version 2.53.0",
        "systemd 259 (259.5-0ubuntu3)",
        "GNU bash, version 5.3.3(1)-release",
        bwrap,
        python_executable,
        codex,
        claude,
        True,
        True,
        True,
    ).to_json_obj()


def run_metadata() -> dict[str, object]:
    return {
        "source_revision": "a" * 40,
        "source_tree_object_id": "b" * 40,
        "canonical_source": "/source/project",
        "source_warnings": ["local checkout changes are excluded"],
        "environment": environment_record(),
        "credential_identifiers": {"codex": "author-account", "claude": "critic-token"},
    }


class EmptyBlobs:
    def read_blob(self, sha256: str) -> bytes:
        raise AssertionError(f"unexpected blob read: {sha256}")


def test_every_schema_document_is_valid_in_its_declared_dialect() -> None:
    documents = sorted(SCHEMA_ROOT.glob("*.schema.json"))
    assert {path.name for path in documents} >= {
        "subject-manifest-v1.schema.json",
        "run-manifest-v1.schema.json",
        "validation-evidence-v1.schema.json",
    }
    identifiers: set[str] = set()
    for path in documents:
        document = json.loads(path.read_text(encoding="utf-8"))
        if path.name == "critic-v1.schema.json":
            Draft7Validator.check_schema(document)
            assert document["$schema"] == "http://json-schema.org/draft-07/schema#"
            assert "definitions" in document and "$defs" not in document
        else:
            Draft202012Validator.check_schema(document)
            assert document["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert document["$id"] not in identifiers
        identifiers.add(document["$id"])


def test_packaged_critic_schema_matches_operational_schema() -> None:
    assert schema("critic-v1.schema.json") == critic_schema_document()


def test_critic_draft_07_definition_reference_enforces_finding_contract() -> None:
    selected = Draft7Validator(critic_schema_document())
    finding: dict[str, object] = {
        "id": "C1",
        "severity": "high",
        "category": "correctness",
        "file": "src/example.py",
        "symbol": None,
        "line_start": 1,
        "line_end": 1,
        "problem": "The result is incorrect.",
        "evidence": "The focused check fails.",
        "required_fix": "Return the expected value.",
    }
    review = {
        "schema_version": 1,
        "verdict": "REVISE",
        "summary": "One correction is required.",
        "blocked_reason": None,
        "blocking_findings": [finding],
        "non_blocking_findings": [],
    }

    selected.validate(review)
    del finding["required_fix"]
    with pytest.raises(ValidationError):
        selected.validate(review)


def _critic_finding() -> dict[str, object]:
    return {
        "id": "C1",
        "severity": "high",
        "category": "correctness",
        "file": "src/example.py",
        "symbol": None,
        "line_start": 1,
        "line_end": 1,
        "problem": "The result is incorrect.",
        "evidence": "The focused check fails.",
        "required_fix": "Return the expected value.",
    }


def _critic_review(
    verdict: str,
    *,
    blocked_reason: str | None,
    blocking: bool,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "verdict": verdict,
        "summary": "Assessment complete.",
        "blocked_reason": blocked_reason,
        "blocking_findings": [_critic_finding()] if blocking else [],
        "non_blocking_findings": [],
    }


@pytest.mark.parametrize(
    ("review",),
    [
        (_critic_review("LGTM", blocked_reason="No blocking issues.", blocking=False),),
        (_critic_review("LGTM", blocked_reason=None, blocking=True),),
        (_critic_review("REVISE", blocked_reason=None, blocking=False),),
        (_critic_review("REVISE", blocked_reason="External input missing.", blocking=True),),
        (_critic_review("BLOCKED", blocked_reason=None, blocking=False),),
        (_critic_review("BLOCKED", blocked_reason=" \t\n", blocking=False),),
        (_critic_review("BLOCKED", blocked_reason="External input missing.", blocking=True),),
    ],
    ids=(
        "lgtm-reason",
        "lgtm-blocking",
        "revise-empty",
        "revise-reason",
        "blocked-no-reason",
        "blocked-whitespace-reason",
        "blocked-finding",
    ),
)
def test_critic_draft_07_schema_rejects_cross_verdict_contradictions(
    review: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        Draft7Validator(critic_schema_document()).validate(review)


@pytest.mark.parametrize(
    ("review",),
    [
        (_critic_review("LGTM", blocked_reason=None, blocking=False),),
        (_critic_review("REVISE", blocked_reason=None, blocking=True),),
        (_critic_review("BLOCKED", blocked_reason="External input missing.", blocking=False),),
    ],
    ids=("lgtm", "revise", "blocked"),
)
def test_critic_draft_07_schema_accepts_each_canonical_verdict_shape(
    review: dict[str, object],
) -> None:
    Draft7Validator(critic_schema_document()).validate(review)


def test_subject_schema_accepts_actual_regular_and_symlink_serializer_output() -> None:
    regular_data = b"print('ok')\n"
    manifest = SubjectManifest.build(
        (
            ManifestEntry.regular(
                b"bin/tool",
                size=len(regular_data),
                blob_sha256=sha256_hex(regular_data),
                executable=True,
            ),
            ManifestEntry.symlink(b"current", target=b"bin/tool"),
        )
    )
    document = json.loads(manifest.to_json_bytes())
    selected = validator("subject-manifest-v1.schema.json")

    selected.validate(document)

    unknown = copy.deepcopy(document)
    unknown["ambient"] = {"hooks": True}
    with pytest.raises(ValidationError):
        selected.validate(unknown)
    wrong_version = copy.deepcopy(document)
    wrong_version["schema_version"] = 2
    with pytest.raises(ValidationError):
        selected.validate(wrong_version)
    confused = copy.deepcopy(document)
    confused["entries"][0]["target_b64"] = "YQ=="
    with pytest.raises(ValidationError):
        selected.validate(confused)


def test_validation_schema_accepts_only_declassified_serializer_output() -> None:
    fingerprint = "e" * 64
    baseline = ValidationSummary(
        1,
        fingerprint,
        (CheckExecution("tests", "pytest -q", 1.0, 2.0, 0),),
    )
    current = ValidationSummary(
        1,
        fingerprint,
        (CheckExecution("tests", "pytest -q", 3.0, 4.0, 1),),
    )
    evidence = declassify_validation(
        fingerprint,
        classify_validations(baseline, current),
        raw_log=b"sensitive untrusted output",
    )
    document = json.loads(evidence.to_json_bytes())
    selected = validator("validation-evidence-v1.schema.json")

    selected.validate(document)
    assert "sensitive untrusted output" not in json.dumps(document)

    contradictory = copy.deepcopy(document)
    contradictory["checks"][0]["evidence_complete"] = False
    with pytest.raises(ValidationError):
        selected.validate(contradictory)
    unknown = copy.deepcopy(document)
    unknown["raw_log"] = "must never cross this boundary"
    with pytest.raises(ValidationError):
        selected.validate(unknown)
    wrong_version = copy.deepcopy(document)
    wrong_version["schema_version"] = 2
    with pytest.raises(ValidationError):
        selected.validate(wrong_version)


def test_run_schema_tracks_actual_progressive_journal_and_rejects_unknowns(
    tmp_path: Path,
) -> None:
    manifest = SubjectManifest.empty()
    selected = validator("run-manifest-v1.schema.json")
    root = tmp_path / "run"

    with ArtifactStore.create(root) as artifacts:
        journal = ArtifactRunJournal(artifacts, "run-001", run_metadata())
        settings = LoopSettings(
            max_rounds=2,
            max_runtime_seconds=60,
            protected_patterns=("AGENTS.md",),
            requested_author_model="gpt-pinned",
            requested_author_effort="high",
            requested_critic_model="claude-pinned",
            requested_critic_effort="high",
        )
        journal.start(
            task="implement the requested change",
            base=manifest,
            deadline=61.0,
            settings=settings,
        )
        selected.validate(artifacts.read_json("artifacts/run.json", max_bytes=1024 * 1024))

        author = AuthorTurn(
            manifest,
            "thread-001",
            "done",
            usage={"input_tokens": 4, "output_tokens": 2},
            observed_model="gpt-pinned",
            observed_effort="high",
        )
        journal.author(1, author, manifest, (), (), (), manifest, EmptyBlobs())
        selected.validate(artifacts.read_json("artifacts/run.json", max_bytes=1024 * 1024))

        review = CriticReview(1, Verdict.LGTM, "approved", None, (), ())
        critic = CriticTurn(
            review,
            50.0,
            {"type": "result"},
            0.01,
            "claude-pinned",
            "high",
        )
        bundle = ReviewBundle({}, b"{}", 1, "f" * 64)
        journal.critic(1, critic, bundle)
        assert artifacts.read_bytes(
            "artifacts/rounds/001/review-bundle.json",
            max_bytes=1024,
        ) == b"{}"
        selected.validate(artifacts.read_json("artifacts/run.json", max_bytes=1024 * 1024))

        result = LoopResult(
            ExitCode.SUCCESS,
            StopReason.CONVERGED,
            1,
            manifest,
            "thread-001",
            "all validations passed",
        )
        journal.finish(result)
        finished = artifacts.read_json("artifacts/run.json", max_bytes=1024 * 1024)
        assert isinstance(finished, dict)
        selected.validate(finished)

    unknown = copy.deepcopy(finished)
    unknown["ambient_auth"] = "forbidden"
    with pytest.raises(ValidationError):
        selected.validate(unknown)
    inconsistent = copy.deepcopy(finished)
    inconsistent["status"] = "stopped"
    with pytest.raises(ValidationError):
        selected.validate(inconsistent)
    wrong_version = copy.deepcopy(finished)
    wrong_version["schema_version"] = 2
    with pytest.raises(ValidationError):
        selected.validate(wrong_version)


def test_precredential_failure_run_remains_schema_valid_and_withheld(
    tmp_path: Path,
) -> None:
    manifest = SubjectManifest.empty()
    selected = validator("run-manifest-v1.schema.json")

    with ArtifactStore.create(tmp_path / "precredential-run") as artifacts:
        journal = ArtifactRunJournal(
            artifacts,
            "run-precredential",
            run_metadata(),
        )
        journal.precredential_start(
            base=manifest,
            deadline=61.0,
            settings=LoopSettings(),
        )
        journal.finish(
            LoopResult(
                ExitCode.INTEGRITY_FAILURE,
                StopReason.GITLESS_INVOCATION_PROBE_FAILED,
                0,
                manifest,
                None,
                "capability proof failed closed",
            )
        )
        retained = artifacts.read_json("artifacts/run.json", max_bytes=1024 * 1024)

    selected.validate(retained)
    assert retained["metadata_content_withheld"] is True
    assert retained["hostname"] == "withheld"
    assert retained["canonical_source"] == "/withheld"
    assert retained["base_subject_fingerprint"] == "0" * 64
    assert retained["current_subject_fingerprint"] == "0" * 64


def test_064_run_record_contains_requested_and_observed_models_effort_usage_and_cost(
    tmp_path: Path,
) -> None:
    manifest = SubjectManifest.empty()
    with ArtifactStore.create(tmp_path / "run") as artifacts:
        journal = ArtifactRunJournal(artifacts, "run-model-record", run_metadata())
        settings = LoopSettings(
            requested_author_model="gpt-pinned",
            requested_author_effort="high",
            requested_critic_model="claude-pinned",
            requested_critic_effort="medium",
        )
        journal.start(
            task="record exact selections",
            base=manifest,
            deadline=60.0,
            settings=settings,
        )
        journal.author(
            1,
            AuthorTurn(
                manifest,
                "thread-model-record",
                "done",
                usage={"input_tokens": 10, "output_tokens": 2},
                observed_model="gpt-pinned",
                observed_effort="high",
            ),
            manifest,
            (),
            (),
            (),
            manifest,
            EmptyBlobs(),
        )
        review = CriticReview(1, Verdict.LGTM, "approved", None, (), ())
        journal.critic(
            1,
            CriticTurn(
                review,
                50.0,
                {"type": "result"},
                0.125,
                "claude-pinned",
                "medium",
            ),
            ReviewBundle({}, b"{}", 1, "f" * 64),
        )
        recorded = artifacts.read_json("artifacts/run.json", max_bytes=1024 * 1024)

    assert isinstance(recorded, dict)
    assert recorded["requested_author_model"] == recorded["observed_author_model"]
    assert recorded["requested_author_effort"] == recorded["observed_author_effort"]
    assert recorded["requested_critic_model"] == recorded["observed_critic_model"]
    assert recorded["requested_critic_effort"] == recorded["observed_critic_effort"]
    assert recorded["codex_usage"] == {"input_tokens": 10, "output_tokens": 2}
    assert recorded["claude_total_cost_usd"] == 0.125


def test_attempt_journal_retains_bounded_preverification_evidence(tmp_path: Path) -> None:
    manifest = SubjectManifest.empty()
    check = CheckExecution("tests", "pytest -q", 1.0, 2.0, 0)
    validation = ValidationTurn(
        ValidationSummary(1, manifest.fingerprint, (check,)),
        manifest,
        b"abcdef",
    )
    with ArtifactStore.create(tmp_path / "attempt-run") as artifacts:
        journal = ArtifactRunJournal(artifacts, "run-attempts", run_metadata())
        journal.start(
            task="retain failed attempts",
            base=manifest,
            deadline=60.0,
            settings=LoopSettings(),
        )
        journal.validation_attempt(
            None,
            "baseline",
            manifest,
            validation,
            b"abc",
            True,
            False,
            False,
            False,
        )
        journal.author_attempt(
            1,
            AuthorTurn(
                manifest,
                "thread-attempt",
                "abcdef",
                events=({"type": "large-event", "value": "abcdef"},),
            ),
            4,
            False,
        )
        journal.opaque_proof(1, manifest, validation, False)

        summary = artifacts.read_json(
            "artifacts/baseline.validation.attempt.summary.json",
            max_bytes=4096,
        )
        assert isinstance(summary, dict)
        assert summary["raw_log_truncated"] is True
        assert summary["raw_log_bytes"] == 6
        assert artifacts.read_bytes(
            "artifacts/baseline.validation.attempt.raw.log",
            max_bytes=16,
        ) == b"abc"
        assert artifacts.read_bytes(
            "artifacts/baseline.validation.attempt.input-subject.json",
            max_bytes=4096,
        ) == manifest.to_json_bytes()
        assert artifacts.read_bytes(
            "artifacts/rounds/001/author-attempt.final.md",
            max_bytes=16,
        ) == b"abcd"
        proof = artifacts.read_json(
            "artifacts/rounds/001/opaque-validation-proof.summary.json",
            max_bytes=4096,
        )
        assert isinstance(proof, dict)
        assert proof["equivalent_to_authoritative_validation"] is False
