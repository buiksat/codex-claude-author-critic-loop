from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

import agent_loop.workflow as workflow
from agent_loop.artifacts import ArtifactStore
from agent_loop.cli import build_parser
from agent_loop.constants import REGULAR_MODE, Limits
from agent_loop.declassify import KnownSecret
from agent_loop.errors import AgentLoopError, StopReason, fail
from agent_loop.git_source import GitSourceSnapshot
from agent_loop.manifests import build_manifest_from_scan
from agent_loop.models import BlobWriter, EntryKind, ScanRecord
from agent_loop.runner import (
    AuthorRequest,
    AuthorTurn,
    CriticRequest,
    CriticTurn,
    ValidationRequest,
    ValidationTurn,
)
from agent_loop.schemas import CriticReview, Verdict
from agent_loop.validation import CheckExecution, ValidationSummary
from agent_loop.workflow import (
    RunConfiguration,
    RunPreparation,
    RuntimeAdapters,
    WorkflowCredentialTransaction,
    WorkflowIO,
    execute_run,
)


class _FakeLock:
    def __init__(self, events: list[str]) -> None:
        self._events = events

    def close(self) -> None:
        self._events.append("source_lock_close")


class _FakeTransaction:
    def __init__(self, events: list[str], codex_home: Path) -> None:
        self._events = events
        self._codex_home = codex_home
        codex_home.mkdir(mode=0o700, parents=True)

    @property
    def codex_home(self) -> Path:
        return self._codex_home

    @property
    def auth_generations(self) -> tuple[bytes, ...]:
        return ()

    def capture_candidate_generation(self) -> bool:
        return False

    def reconcile_after_turn(self) -> bool:
        self._events.append("credential_reconcile")
        return False

    def remove_candidate_config(self) -> None:
        self._events.append("credential_config_remove")

    def complete(self) -> None:
        self._events.append("credential_complete")

    def finalize_reconciled(self) -> None:
        self._events.append("credential_complete")

    def close(self) -> None:
        self._events.append("credential_close")


class _FakeValidator:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.requests: list[ValidationRequest] = []

    def validate(self, request: ValidationRequest) -> ValidationTurn:
        self.requests.append(request)
        self.events.append("baseline" if request.baseline is None else "validation")
        check = CheckExecution(
            "check-001",
            "python -m pytest",
            1.0,
            2.0,
            0,
        )
        return ValidationTurn(
            ValidationSummary(1, request.subject.fingerprint, (check,)),
            request.subject,
            b"private validation log\n",
        )


class _FakeAuthor:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.requests: list[AuthorRequest] = []

    def turn(self, request: AuthorRequest) -> AuthorTurn:
        self.requests.append(request)
        self.events.append("author")
        return AuthorTurn(
            request.subject,
            "thread-workflow-1",
            "finished",
            observed_model="author-exact",
            observed_effort="high",
        )


class _FakeCritic:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.requests: list[CriticRequest] = []

    def review(self, request: CriticRequest) -> CriticTurn:
        self.requests.append(request)
        self.events.append("critic")
        review = CriticReview(1, Verdict.LGTM, "approved", None, (), ())
        return CriticTurn(
            review,
            request.deadline - 1,
            {"type": "result", "structured_output": {"verdict": "LGTM"}},
            observed_model="critic-exact",
            observed_effort="medium",
        )


class _FakeBackend:
    def __init__(self, tmp_path: Path, *, capability_failure: bool = False) -> None:
        self.events: list[str] = []
        self.source = tmp_path / "source"
        self.source.mkdir()
        self.capability_failure = capability_failure
        self.run_root: Path | None = None
        self.transaction: _FakeTransaction | None = None
        self.validator = _FakeValidator(self.events)
        self.author = _FakeAuthor(self.events)
        self.critic = _FakeCritic(self.events)

    def clock(self) -> float:
        return 1_000.0

    def new_run_id(self) -> str:
        return "run-workflow-test"

    def canonical_source(self) -> Path:
        self.events.append("canonical_source")
        return self.source

    def acquire_source_lock(
        self,
        source: Path,
        run_id: str,
        *,
        state_home: Path,
    ) -> _FakeLock:
        del source, run_id, state_home
        self.events.append("source_lock")
        return _FakeLock(self.events)

    def create_artifacts(self, run_root: Path) -> ArtifactStore:
        self.events.append("artifacts")
        self.run_root = run_root
        return ArtifactStore.create(run_root)

    def preflight(self, configuration: RunConfiguration) -> dict[str, object]:
        del configuration
        self.events.append("preflight")
        return {"backend": "fake-no-live-models", "capabilities": "injected"}

    def extract_source(
        self,
        source: Path,
        blobs: BlobWriter,
        *,
        limits: Limits,
    ) -> GitSourceSnapshot:
        del source
        self.events.append("extract")
        manifest = build_manifest_from_scan(
            (ScanRecord(b"app.py", EntryKind.REGULAR, REGULAR_MODE, b"value = 1\n"),),
            blobs,
            limits=limits,
        )
        return GitSourceSnapshot(
            "a" * 40,
            "b" * 40,
            manifest,
            ("working-tree, index, ignored, and untracked changes are excluded",),
        )

    def acquire_codex_credential(
        self,
        preparation: RunPreparation,
    ) -> _FakeTransaction:
        self.events.append("credential_acquire")
        transaction = _FakeTransaction(
            self.events,
            preparation.state_home / "fake-credential-transaction",
        )
        self.transaction = transaction
        return transaction

    def load_claude_token(self, preparation: RunPreparation) -> str:
        del preparation
        self.events.append("claude_token")
        return "fake-token-never-persisted"

    def build_runtime(
        self,
        preparation: RunPreparation,
        transaction: WorkflowCredentialTransaction,
        claude_token: str,
        known_secrets: tuple[KnownSecret, ...],
    ) -> RuntimeAdapters:
        del preparation, transaction, claude_token, known_secrets
        self.events.append("runtime")
        return RuntimeAdapters(self.author, self.validator, self.critic)

    def known_secrets(
        self,
        preparation: RunPreparation,
        transaction: WorkflowCredentialTransaction,
        claude_token: str,
    ) -> tuple[KnownSecret, ...]:
        del preparation, transaction
        self.events.append("known_secrets")
        return (KnownSecret("claude-setup-token", claude_token.encode()),)

    def prepare_codex_credential(
        self,
        preparation: RunPreparation,
        transaction: WorkflowCredentialTransaction,
        known_secrets: tuple[KnownSecret, ...],
    ) -> tuple[KnownSecret, ...]:
        del preparation, transaction
        self.events.append("credential_prepare")
        return known_secrets

    def install_codex_configuration(
        self,
        preparation: RunPreparation,
        transaction: WorkflowCredentialTransaction,
        known_secrets: tuple[KnownSecret, ...],
    ) -> None:
        del preparation, transaction, known_secrets
        self.events.append("credential_install")

    def prove_capabilities(
        self,
        preparation: RunPreparation,
    ) -> None:
        del preparation
        self.events.append("capability")
        if self.capability_failure:
            raise fail(
                StopReason.GITLESS_INVOCATION_PROBE_FAILED,
                "injected capability failure",
            )


def _args(tmp_path: Path, *, assume_yes: bool = False) -> argparse.Namespace:
    task = tmp_path / "task.md"
    task.write_text("Keep the workflow deterministic.\n", encoding="utf-8")
    values = [
        "--state-home",
        str(tmp_path / "state"),
        "run",
        "--task",
        str(task),
        "--check",
        "python -m pytest",
        "--author-model",
        "author-exact",
        "--author-effort",
        "high",
        "--critic-model",
        "critic-exact",
        "--critic-effort",
        "medium",
        "--codex-credential-id",
        "codex-test",
        "--claude-credential-id",
        "claude-test",
        "--codex-executable",
        "/opt/codex",
        "--claude-executable",
        "/opt/claude",
    ]
    if assume_yes:
        values.append("--yes")
    return build_parser().parse_args(values)


def _run_json(backend: _FakeBackend) -> dict[str, object]:
    assert backend.run_root is not None
    value = json.loads((backend.run_root / "artifacts" / "run.json").read_text())
    assert isinstance(value, dict)
    assert all(isinstance(key, str) for key in value)
    return value


def test_declined_confirmation_follows_baseline_and_never_calls_a_model(
    tmp_path: Path,
) -> None:
    backend = _FakeBackend(tmp_path)
    output: list[str] = []

    def write(value: str) -> None:
        if value.startswith("Paid-run preflight"):
            backend.events.append("preflight_print")
            assert backend.run_root is not None
            assert (backend.run_root / "artifacts" / "baseline.validation.summary.json").is_file()
        output.append(value)

    def decline(prompt: str) -> str:
        assert "Type yes" in prompt
        backend.events.append("confirmation_read")
        return "no"

    exit_code = execute_run(
        _args(tmp_path),
        backend=backend,
        io=WorkflowIO(write=write, read=decline),
    )

    assert exit_code == 13
    assert "author" not in backend.events and "critic" not in backend.events
    ordered = [
        "source_lock",
        "artifacts",
        "preflight",
        "extract",
        "capability",
        "credential_acquire",
        "claude_token",
        "known_secrets",
        "credential_prepare",
        "credential_install",
        "runtime",
        "baseline",
        "preflight_print",
        "confirmation_read",
        "credential_complete",
        "credential_close",
        "source_lock_close",
    ]
    assert [backend.events.index(item) for item in ordered] == sorted(
        backend.events.index(item) for item in ordered
    )
    manifest = _run_json(backend)
    assert manifest["status"] == "stopped"
    assert manifest["stop_reason"] == "user_interrupt"
    assert manifest["exit_code"] == 13
    assert backend.run_root is not None
    assert (backend.run_root / "subjects" / "current" / "app.py").read_bytes() == b"value = 1\n"
    joined = "\n".join(output)
    assert "private validation log" not in joined
    assert "fake-token-never-persisted" not in joined


def test_accepted_confirmation_runs_loop_and_materializes_authoritative_subject(
    tmp_path: Path,
) -> None:
    backend = _FakeBackend(tmp_path)
    writes: list[str] = []
    exit_code = execute_run(
        _args(tmp_path),
        backend=backend,
        io=WorkflowIO(write=writes.append, read=lambda _prompt: "yes"),
    )

    assert exit_code == 0
    assert backend.events.index("baseline") < backend.events.index("author")
    assert backend.events.index("author") < backend.events.index("validation")
    assert backend.events.index("validation") < backend.events.index("critic")
    assert len(backend.author.requests) == len(backend.critic.requests) == 1
    retained_run = _run_json(backend)
    assert retained_run["status"] == "converged"
    assert retained_run["metadata_content_withheld"] is False
    assert backend.run_root is not None
    project_config = json.loads(
        (backend.run_root / "artifacts" / "project-config.json").read_text()
    )
    assert project_config["checks"] == ["python -m pytest"]
    assert project_config["author_timeout_seconds"] == 900
    assert project_config["codex_executable"] == "/opt/codex"
    current = backend.run_root / "subjects" / "current" / "app.py"
    assert current.read_bytes() == b"value = 1\n"
    assert current.stat().st_mode & 0o777 == 0o600
    assert backend.events[-2:] == ["credential_close", "source_lock_close"]
    assert any('"stop_reason": "converged"' in value for value in writes)


def test_capability_failure_is_durable_and_precedes_all_credential_access(
    tmp_path: Path,
) -> None:
    backend = _FakeBackend(tmp_path, capability_failure=True)
    exit_code = execute_run(
        _args(tmp_path, assume_yes=True),
        backend=backend,
        io=WorkflowIO(write=lambda _value: None, read=lambda _prompt: "unexpected"),
    )

    assert exit_code == 17
    assert "baseline" not in backend.events
    assert "author" not in backend.events and "critic" not in backend.events
    assert "credential_acquire" not in backend.events
    assert "claude_token" not in backend.events
    assert "runtime" not in backend.events
    manifest = _run_json(backend)
    assert manifest["status"] == "stopped"
    assert manifest["stop_reason"] == "gitless_invocation_probe_failed"
    assert manifest["exit_code"] == 17
    assert manifest["metadata_content_withheld"] is True
    assert manifest["hostname"] == "withheld"
    assert manifest["canonical_source"] == "/withheld"
    assert manifest["credential_identifiers"] == {
        "claude": "withheld",
        "codex": "withheld",
    }
    assert "credential_complete" not in backend.events
    assert "credential_close" not in backend.events
    assert backend.events[-1] == "source_lock_close"
    assert backend.run_root is not None
    assert not (backend.run_root / "subjects" / "current").exists()
    assert not (backend.run_root / "artifacts" / "base-subject.json").exists()
    assert not (backend.run_root / "artifacts" / "project-config.json").exists()
    staged_config = json.loads(
        (backend.run_root / "artifacts" / "config.json").read_text()
    )
    assert staged_config["protected_patterns"] == []
    assert staged_config["requested_author_model"] is None
    assert staged_config["operator_content_withheld_pending_credential_scan"] is True


def test_configuration_matching_a_known_credential_is_never_retained(
    tmp_path: Path,
) -> None:
    backend = _FakeBackend(tmp_path)
    args = _args(tmp_path, assume_yes=True)
    args.check = ["printf fake-token-never-persisted"]

    assert execute_run(
        args,
        backend=backend,
        io=WorkflowIO(write=lambda _value: None, read=lambda _prompt: "unexpected"),
    ) == 17

    assert "runtime" not in backend.events
    assert "baseline" not in backend.events
    assert backend.run_root is not None
    assert not (backend.run_root / "artifacts" / "project-config.json").exists()
    metadata = json.loads(
        (backend.run_root / "artifacts" / "project-config.meta.json").read_text()
    )
    assert metadata["content_withheld"] is True
    forbidden = b"fake-token-never-persisted"
    for path in backend.run_root.rglob("*"):
        if path.is_file():
            assert forbidden not in path.read_bytes(), path


def test_run_metadata_matching_a_known_credential_is_never_released(
    tmp_path: Path,
) -> None:
    backend = _FakeBackend(tmp_path)
    backend.source = tmp_path / "fake-token-never-persisted"
    backend.source.mkdir()

    assert execute_run(
        _args(tmp_path, assume_yes=True),
        backend=backend,
        io=WorkflowIO(write=lambda _value: None, read=lambda _prompt: "unexpected"),
    ) == 17

    assert "runtime" not in backend.events
    manifest = _run_json(backend)
    assert manifest["metadata_content_withheld"] is True
    assert manifest["canonical_source"] == "/withheld"
    assert backend.run_root is not None
    forbidden = b"fake-token-never-persisted"
    for path in backend.run_root.rglob("*"):
        if path.is_file():
            assert forbidden not in path.read_bytes(), path


@pytest.mark.parametrize("surface", ("task", "source"))
def test_task_and_committed_source_credentials_never_enter_retained_storage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    surface: str,
) -> None:
    backend = _FakeBackend(tmp_path)
    args = _args(tmp_path, assume_yes=True)
    forbidden = b"fake-token-never-persisted"
    if surface == "task":
        args.task.write_bytes(forbidden)
    else:
        def extract_secret_source(
            source: Path,
            blobs: BlobWriter,
            *,
            limits: Limits,
        ) -> GitSourceSnapshot:
            del source
            backend.events.append("extract")
            manifest = build_manifest_from_scan(
                (ScanRecord(b"app.py", EntryKind.REGULAR, REGULAR_MODE, forbidden),),
                blobs,
                limits=limits,
            )
            return GitSourceSnapshot(
                "a" * 40,
                "b" * 40,
                manifest,
                ("working-tree changes are excluded",),
            )

        monkeypatch.setattr(backend, "extract_source", extract_secret_source)

    assert execute_run(
        args,
        backend=backend,
        io=WorkflowIO(write=lambda _value: None, read=lambda _prompt: "unexpected"),
    ) == 17

    assert "runtime" not in backend.events
    assert backend.run_root is not None
    assert not (backend.run_root / "subjects").exists()
    subject_meta = json.loads(
        (backend.run_root / "artifacts" / "base-subject.meta.json").read_text()
    )
    task_meta = json.loads(
        (backend.run_root / "artifacts" / "task.meta.json").read_text()
    )
    assert subject_meta["content_withheld"] is (surface == "source")
    assert task_meta["content_withheld"] is (surface == "task")
    for path in backend.run_root.rglob("*"):
        if path.is_file():
            assert forbidden not in path.read_bytes(), path


def test_refreshed_preparation_secret_rescans_task_before_any_release(
    tmp_path: Path,
) -> None:
    forbidden = b"Keep the workflow deterministic."

    class RefreshCollisionBackend(_FakeBackend):
        def prepare_codex_credential(
            self,
            preparation: RunPreparation,
            transaction: WorkflowCredentialTransaction,
            known_secrets: tuple[KnownSecret, ...],
        ) -> tuple[KnownSecret, ...]:
            del preparation, transaction
            self.events.append("credential_prepare")
            return (*known_secrets, KnownSecret("refreshed-task-token", forbidden))

    backend = RefreshCollisionBackend(tmp_path)
    writes: list[str] = []

    assert execute_run(
        _args(tmp_path, assume_yes=True),
        backend=backend,
        io=WorkflowIO(write=writes.append, read=lambda _prompt: "unexpected"),
    ) == 17

    assert "credential_config_remove" in backend.events
    assert "credential_install" not in backend.events
    assert "runtime" not in backend.events
    assert backend.run_root is not None
    task_meta = json.loads(
        (backend.run_root / "artifacts" / "task.meta.json").read_text()
    )
    assert task_meta["content_withheld"] is True
    for path in backend.run_root.rglob("*"):
        if path.is_file():
            assert forbidden not in path.read_bytes(), path
    assert all(forbidden not in value.encode("utf-8") for value in writes)


def test_structural_source_fingerprint_secret_is_withheld_from_operator_output(
    tmp_path: Path,
) -> None:
    class StructuralSecretBackend(_FakeBackend):
        def known_secrets(
            self,
            preparation: RunPreparation,
            transaction: WorkflowCredentialTransaction,
            claude_token: str,
        ) -> tuple[KnownSecret, ...]:
            del transaction, claude_token
            self.events.append("known_secrets")
            return (
                KnownSecret(
                    "structural-fingerprint-token",
                    preparation.snapshot.manifest.fingerprint.encode("ascii"),
                ),
            )

    backend = StructuralSecretBackend(tmp_path)
    writes: list[str] = []

    assert execute_run(
        _args(tmp_path, assume_yes=True),
        backend=backend,
        io=WorkflowIO(write=writes.append, read=lambda _prompt: "unexpected"),
    ) == 17

    assert not backend.validator.requests
    output = json.loads(writes[-1])
    assert "subject_fingerprint" not in output
    assert output["operator_output_content_withheld"] is True


def test_post_author_generation_scrubs_prior_task_source_and_baseline_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generation_c = b"post-author-generation-c"
    backend = _FakeBackend(tmp_path)
    args = _args(tmp_path, assume_yes=True)
    args.task.write_bytes(b"task includes " + generation_c)

    def extract_source(
        source: Path,
        blobs: BlobWriter,
        *,
        limits: Limits,
    ) -> GitSourceSnapshot:
        del source
        backend.events.append("extract")
        manifest = build_manifest_from_scan(
            (
                ScanRecord(
                    b"app.py",
                    EntryKind.REGULAR,
                    REGULAR_MODE,
                    b"source includes " + generation_c,
                ),
            ),
            blobs,
            limits=limits,
        )
        return GitSourceSnapshot(
            "a" * 40,
            "b" * 40,
            manifest,
            ("working-tree changes are excluded",),
        )

    original_validate = backend.validator.validate

    def validate_with_secret(request: ValidationRequest) -> ValidationTurn:
        turn = original_validate(request)
        return ValidationTurn(
            turn.summary,
            turn.result_manifest,
            b"baseline includes " + generation_c,
        )

    def build_refreshing_runtime(
        preparation: RunPreparation,
        transaction: WorkflowCredentialTransaction,
        claude_token: str,
        known_secrets: tuple[KnownSecret, ...],
    ) -> RuntimeAdapters:
        del transaction, claude_token
        backend.events.append("runtime")
        refreshed = (
            *known_secrets,
            KnownSecret("post-author-generation", generation_c),
        )

        def current_secrets() -> tuple[KnownSecret, ...]:
            if backend.author.requests:
                if preparation.artifacts.content_withheld_due_to_secret:
                    raise fail(
                        StopReason.CREDENTIAL_REFRESH_FAILURE,
                        "credential-tainted evidence remains withheld",
                    )
                if preparation.artifacts.scrub_known_secrets(refreshed):
                    raise fail(
                        StopReason.CREDENTIAL_REFRESH_FAILURE,
                        "new generation collided with prior evidence",
                    )
                return refreshed
            return known_secrets

        return RuntimeAdapters(
            backend.author,
            backend.validator,
            backend.critic,
            current_secrets,
        )

    monkeypatch.setattr(backend, "extract_source", extract_source)
    monkeypatch.setattr(backend.validator, "validate", validate_with_secret)
    monkeypatch.setattr(backend, "build_runtime", build_refreshing_runtime)
    writes: list[str] = []

    assert execute_run(
        args,
        backend=backend,
        io=WorkflowIO(write=writes.append, read=lambda _prompt: "unexpected"),
    ) == 17

    assert backend.run_root is not None
    assert list(backend.run_root.iterdir()) == []
    with ArtifactStore.open(backend.run_root) as artifacts:
        assert artifacts.content_withheld_due_to_secret is True
        with pytest.raises(AgentLoopError):
            artifacts.read_json("artifacts/run.json", max_bytes=1024 * 1024)
    assert all(generation_c not in value.encode("utf-8") for value in writes)
    assert "operator_output_content_withheld" in writes[-1]


def test_yes_prints_baseline_summary_without_reading_confirmation(tmp_path: Path) -> None:
    backend = _FakeBackend(tmp_path)
    writes: list[str] = []

    def forbidden_read(_prompt: str) -> str:
        raise AssertionError("--yes must not read interactive input")

    assert execute_run(
        _args(tmp_path, assume_yes=True),
        backend=backend,
        io=WorkflowIO(write=writes.append, read=forbidden_read),
    ) == 0
    preflight = next(value for value in writes if value.startswith("Paid-run preflight"))
    assert '"validation_baseline"' in preflight
    assert '"outcome": "passed"' in preflight


def test_state_home_source_overlap_stops_before_locks_or_artifacts(tmp_path: Path) -> None:
    backend = _FakeBackend(tmp_path)
    overlapping = tmp_path / "state" / "source"
    overlapping.mkdir(parents=True)
    backend.source = overlapping

    with pytest.raises(AgentLoopError, match="pre-credential run input preparation"):
        execute_run(
            _args(tmp_path, assume_yes=True),
            backend=backend,
            io=WorkflowIO(write=lambda _value: None, read=lambda _prompt: "yes"),
        )

    assert "source_lock" not in backend.events
    assert "artifacts" not in backend.events


def test_precredential_source_error_detail_is_content_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _FakeBackend(tmp_path)
    forbidden = "precredential-source-token"

    def unsafe_source_error(
        source: Path,
        blobs: BlobWriter,
        *,
        limits: Limits,
    ) -> GitSourceSnapshot:
        del source, blobs, limits
        raise fail(
            StopReason.GIT_POLICY_OR_OUTPUT_FAILURE,
            f"hostile committed path: {forbidden}",
        )

    monkeypatch.setattr(backend, "extract_source", unsafe_source_error)
    with pytest.raises(AgentLoopError) as caught:
        execute_run(
            _args(tmp_path, assume_yes=True),
            backend=backend,
            io=WorkflowIO(write=lambda _value: None, read=lambda _prompt: "unexpected"),
        )

    assert caught.value.reason is StopReason.GIT_POLICY_OR_OUTPUT_FAILURE
    assert forbidden not in str(caught.value)


def test_subject_control_inputs_are_added_as_exact_protected_patterns(
    tmp_path: Path,
) -> None:
    backend = _FakeBackend(tmp_path)
    task = backend.source / "task*.md"
    config = backend.source / "config[1].toml"
    task.write_text("Keep control inputs immutable.\n", encoding="utf-8")
    config.write_text("schema_version = 1\n", encoding="utf-8")
    args = _args(tmp_path, assume_yes=True)
    args.task = task
    args.config = config

    assert execute_run(
        args,
        backend=backend,
        io=WorkflowIO(write=lambda _value: None, read=lambda _prompt: "unexpected"),
    ) == 0

    manifest = _run_json(backend)
    assert "task[*].md" in manifest["protected_patterns"]
    assert "config[[]1].toml" in manifest["protected_patterns"]


def test_060_production_composition_detects_live_authoritative_tree_tampering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _FakeBackend(tmp_path)
    original_turn = backend.author.turn

    def tampering_turn(request: AuthorRequest) -> AuthorTurn:
        assert backend.run_root is not None
        current = backend.run_root / "subjects" / "current" / "app.py"
        current.write_bytes(b"out-of-band mutation\n")
        return original_turn(request)

    monkeypatch.setattr(backend.author, "turn", tampering_turn)
    assert execute_run(
        _args(tmp_path, assume_yes=True),
        backend=backend,
        io=WorkflowIO(write=lambda _value: None, read=lambda _prompt: "unexpected"),
    ) == 17

    manifest = _run_json(backend)
    assert manifest["stop_reason"] == "out_of_band_change"
    assert "critic" not in backend.events


def test_finalization_error_does_not_replace_an_earlier_primary_fatal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _FakeBackend(tmp_path)
    original_turn = backend.author.turn

    def tampering_turn(request: AuthorRequest) -> AuthorTurn:
        assert backend.run_root is not None
        current = backend.run_root / "subjects" / "current" / "app.py"
        current.write_bytes(b"out-of-band mutation\n")
        return original_turn(request)

    def fail_materialization(_preparation: object, _subject: object) -> None:
        raise fail(StopReason.OUT_OF_BAND_CHANGE, "injected finalization failure")

    monkeypatch.setattr(backend.author, "turn", tampering_turn)
    monkeypatch.setattr(workflow, "_materialize_final", fail_materialization)
    assert execute_run(
        _args(tmp_path, assume_yes=True),
        backend=backend,
        io=WorkflowIO(write=lambda _value: None, read=lambda _prompt: "yes"),
    ) == 17

    manifest = _run_json(backend)
    assert manifest["stop_reason"] == "out_of_band_change"
    assert backend.run_root is not None
    secondary = json.loads(
        (backend.run_root / "artifacts" / "finalization-errors.json").read_text()
    )
    assert secondary == [
        {
            "detail": "injected finalization failure",
            "phase": "final_subject_materialization",
            "stop_reason": "out_of_band_change",
        }
    ]
