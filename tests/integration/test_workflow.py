from __future__ import annotations

import argparse
import json
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

import agent_loop.credentials as credential_module
import agent_loop.workflow as workflow
from agent_loop.artifacts import ArtifactStore
from agent_loop.author_service import AuthorServiceProvenance
from agent_loop.capabilities import (
    CAPABILITY_RECEIPT_RELATIVE_PATH,
    CapabilityReceiptError,
    LiveCapabilityBinding,
    ManagedClaudeBoundaryCapabilityBinding,
)
from agent_loop.claude_client import (
    CLAUDE_REAUTHENTICATION_FAILURE_DETAIL,
    CLAUDE_REAUTHENTICATION_NEXT_ACTION,
)
from agent_loop.claude_managed_policy import (
    MANAGED_CLAUDE_HELPER_SOURCE,
    MANAGED_CLAUDE_HELPER_TARGET,
    MANAGED_CLAUDE_POLICY_SOURCE,
    MANAGED_CLAUDE_POLICY_TARGET,
    ManagedClaudeBoundary,
)
from agent_loop.cli import build_parser
from agent_loop.codex_client import (
    CODEX_REAUTHENTICATION_FAILURE_DETAIL,
    CODEX_REAUTHENTICATION_NEXT_ACTION,
    classify_codex_process_result,
)
from agent_loop.config import ProjectConfig
from agent_loop.constants import REGULAR_MODE, Limits
from agent_loop.declassify import KnownSecret
from agent_loop.errors import AgentLoopError, StopReason, fail
from agent_loop.git_source import GitSourceSnapshot
from agent_loop.manifests import SubjectManifest, build_manifest_from_scan
from agent_loop.models import BlobWriter, EntryKind, ScanRecord
from agent_loop.preflight import EnvironmentReport, TrustedExecutable
from agent_loop.runner import (
    AuthorRequest,
    AuthorTurn,
    CriticRequest,
    CriticTurn,
    ValidationRequest,
    ValidationTurn,
)
from agent_loop.sandbox import BubblewrapProvenance, SandboxMount
from agent_loop.schemas import CriticReview, Verdict
from agent_loop.service import BoundedProcessResult
from agent_loop.validation import CheckExecution, ValidationSummary
from agent_loop.workflow import (
    ProductionWorkflowBackend,
    ReviewedInstall,
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
            {
                "type": "result",
                "structured_output": {"review": {"verdict": "LGTM"}},
            },
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


def _production_environment() -> EnvironmentReport:
    bubblewrap = BubblewrapProvenance(
        "0.11.1-1ubuntu0.1",
        "0.11.1",
        "/usr/bin/bwrap",
        0,
        0,
        0o755,
        "a" * 64,
    )
    python = TrustedExecutable(
        "/usr/bin/python3.14",
        "/usr/bin/python3.14",
        0,
        0o755,
        "b" * 64,
        "Python 3.14.4",
    )
    codex = TrustedExecutable(
        "/opt/codex",
        "/opt/codex",
        0,
        0o755,
        "c" * 64,
        "codex-cli 0.144.6",
    )
    claude = TrustedExecutable(
        "/opt/claude",
        "/opt/claude",
        0,
        0o755,
        "d" * 64,
        "2.1.215 (Claude Code)",
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
        bubblewrap,
        python,
        codex,
        claude,
        AuthorServiceProvenance(
            protocol=1,
            build_id="fixed-system-author-v1",
            authorized_uid=1000,
            socket_path="/run/agent-loop/author.sock",
            socket_owner_uid=1000,
            socket_mode=0o600,
            socket_unit_sha256="e" * 64,
            broker_unit_sha256="f" * 64,
            socket_dropin_sha256="1" * 64,
            config_sha256="2" * 64,
            install_record_sha256="3" * 64,
            runtime_closure_sha256="4" * 64,
            wheel_sha256="5" * 64,
            codex_closure_sha256="6" * 64,
            effective_units_sha256="7" * 64,
            package_version="1.1.0",
            broker_probe=True,
        ),
        True,
        True,
        True,
    )


def _production_configuration() -> RunConfiguration:
    return RunConfiguration(
        ProjectConfig(
            author_model="gpt-5.4",
            author_effort="high",
            critic_model="claude-opus-4-6",
            critic_effort="medium",
            codex_credential_id="author-account",
            claude_credential_id="critic-token",
        ),
        Path("/opt/codex"),
        Path("/opt/claude"),
    )


def _production_preparation(
    tmp_path: Path,
    *,
    artifacts: ArtifactStore | None = None,
) -> SimpleNamespace:
    source = tmp_path / "source"
    state_home = tmp_path / "state"
    run_root = state_home / "agent-loop" / "runs" / "run-production-test"
    source.mkdir(exist_ok=True)
    state_home.mkdir(exist_ok=True)
    return SimpleNamespace(
        run_id="run-production-test",
        source=source,
        state_home=state_home,
        run_root=run_root,
        task="test",
        configuration=_production_configuration(),
        environment=_production_environment(),
        snapshot=None,
        artifacts=artifacts,
        blobs=object(),
    )


def _managed_boundary(
    *,
    policy_sha256: str = "e" * 64,
    helper_sha256: str = "f" * 64,
) -> ManagedClaudeBoundary:
    return ManagedClaudeBoundary(
        policy_mount=SandboxMount(
            MANAGED_CLAUDE_POLICY_SOURCE,
            MANAGED_CLAUDE_POLICY_TARGET,
            read_only=True,
            closure_sha256=policy_sha256,
        ),
        helper_mount=SandboxMount(
            MANAGED_CLAUDE_HELPER_SOURCE,
            MANAGED_CLAUDE_HELPER_TARGET,
            read_only=True,
            closure_sha256=helper_sha256,
        ),
    )


def _reviewed_install(name: str) -> ReviewedInstall:
    target = f"/opt/reviewed-{name}"
    digest = "1" * 64 if name == "codex" else "2" * 64
    return ReviewedInstall(
        SandboxMount(f"/opt/{name}", target, closure_sha256=digest),
        target + "/executable",
        digest,
    )


@pytest.mark.parametrize("failure", (FileNotFoundError("missing"), ValueError("unsafe")))
def test_production_managed_claude_boundary_missing_or_unsafe_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: BaseException,
) -> None:
    backend = ProductionWorkflowBackend()
    preparation = _production_preparation(tmp_path)

    def reject() -> ManagedClaudeBoundary:
        raise failure

    monkeypatch.setattr(workflow, "inspect_managed_claude_boundary", reject)
    with pytest.raises(AgentLoopError) as caught:
        backend._claude_boundary(preparation)  # type: ignore[arg-type]

    assert caught.value.reason is StopReason.GITLESS_INVOCATION_PROBE_FAILED
    assert backend._managed_claude_boundary is None


def test_production_managed_claude_boundary_rejects_private_authority_overlap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = ProductionWorkflowBackend()
    preparation = _production_preparation(tmp_path)
    preparation.source = Path("/etc")
    monkeypatch.setattr(
        workflow,
        "inspect_managed_claude_boundary",
        _managed_boundary,
    )

    with pytest.raises(AgentLoopError) as caught:
        backend._claude_boundary(preparation)  # type: ignore[arg-type]

    assert caught.value.reason is StopReason.GITLESS_INVOCATION_PROBE_FAILED
    assert backend._managed_claude_boundary is None


def test_production_capability_binding_contains_exact_managed_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = ProductionWorkflowBackend()
    preparation = _production_preparation(tmp_path)
    boundary = _managed_boundary()
    inspections = 0

    def inspect() -> ManagedClaudeBoundary:
        nonlocal inspections
        inspections += 1
        return boundary

    monkeypatch.setattr(workflow, "inspect_managed_claude_boundary", inspect)
    monkeypatch.setattr(
        backend,
        "_install",
        lambda _preparation, *, name: _reviewed_install(name),
    )
    monkeypatch.setattr(
        workflow,
        "installed_runtime_closure_sha256",
        lambda: "3" * 64,
    )
    captured: list[tuple[Path, object]] = []
    monkeypatch.setattr(
        workflow,
        "verify_live_capability_receipt",
        lambda path, expected: captured.append((path, expected)),
    )

    backend.prove_capabilities(preparation)  # type: ignore[arg-type]

    assert inspections == 1
    assert len(captured) == 1
    receipt_path, binding = captured[0]
    assert receipt_path == preparation.state_home / CAPABILITY_RECEIPT_RELATIVE_PATH
    assert isinstance(binding, LiveCapabilityBinding)
    assert binding.managed_claude_boundary == ManagedClaudeBoundaryCapabilityBinding(
        policy_path=boundary.policy_mount.source,
        helper_path=boundary.helper_mount.source,
        policy_sha256=boundary.policy_sha256,
        helper_sha256=boundary.helper_sha256,
        probe_protocol=boundary.protocol,
        probe_id=boundary.probe_id,
    )


def test_production_managed_boundary_receipt_mismatch_fails_before_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = ProductionWorkflowBackend()
    preparation = _production_preparation(tmp_path)
    monkeypatch.setattr(
        workflow,
        "inspect_managed_claude_boundary",
        _managed_boundary,
    )
    monkeypatch.setattr(
        backend,
        "_install",
        lambda _preparation, *, name: _reviewed_install(name),
    )
    monkeypatch.setattr(
        workflow,
        "installed_runtime_closure_sha256",
        lambda: "3" * 64,
    )

    def mismatch(_path: Path, _expected: object) -> None:
        raise CapabilityReceiptError("managed boundary digest mismatch")

    monkeypatch.setattr(workflow, "verify_live_capability_receipt", mismatch)
    with pytest.raises(AgentLoopError) as caught:
        backend.prove_capabilities(preparation)  # type: ignore[arg-type]

    assert caught.value.reason is StopReason.GITLESS_INVOCATION_PROBE_FAILED


def test_missing_receipt_still_auto_enrolls_absent_default_cli_logins_without_spend(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    codex_source = home / ".codex" / "auth.json"
    claude_source = home / ".claude" / ".credentials.json"
    codex_source.parent.mkdir(mode=0o700, parents=True)
    claude_source.parent.mkdir(mode=0o700, parents=True)
    codex_source.write_text(
        json.dumps(
            {
                "auth_mode": "chatgpt",
                "OPENAI_API_KEY": None,
                "tokens": {
                    "id_token": "codex-id-secret",
                    "access_token": "codex-access-secret",
                    "refresh_token": "codex-refresh-secret",
                    "account_id": "00000000-0000-0000-0000-000000000000",
                },
                "last_refresh": "2026-07-21T00:00:00.000000Z",
            }
        ),
        encoding="utf-8",
    )
    claude_source.write_text(
        json.dumps(
            {
                "claudeAiOauth": {
                    "accessToken": "claude-access-secret",
                    "refreshToken": "claude-refresh-secret",
                    "expiresAt": 1_800_000_000_000,
                    "refreshTokenExpiresAt": 1_900_000_000_000,
                    "scopes": ["user:inference"],
                    "subscriptionType": "pro",
                    "rateLimitTier": "default",
                },
                "organizationUuid": "00000000-0000-0000-0000-000000000000",
            }
        ),
        encoding="utf-8",
    )
    codex_source.chmod(0o600)
    claude_source.chmod(0o600)
    monkeypatch.setattr(credential_module, "_authorized_passwd_home", lambda: home)

    preparation = _production_preparation(tmp_path)
    preparation.configuration = RunConfiguration(
        ProjectConfig(
            author_model="gpt-5.4",
            author_effort="high",
            critic_model="claude-opus-4-6",
            critic_effort="medium",
        ),
        Path("/opt/codex"),
        Path("/opt/claude"),
    )
    backend = ProductionWorkflowBackend()
    monkeypatch.setattr(workflow, "inspect_managed_claude_boundary", _managed_boundary)
    monkeypatch.setattr(
        backend,
        "_install",
        lambda _preparation, *, name: _reviewed_install(name),
    )
    monkeypatch.setattr(workflow, "installed_runtime_closure_sha256", lambda: "3" * 64)
    monkeypatch.setattr(
        workflow,
        "verify_live_capability_receipt",
        lambda *_args: (_ for _ in ()).throw(CapabilityReceiptError("missing")),
    )

    with pytest.raises(AgentLoopError) as caught:
        backend.prove_capabilities(preparation)  # type: ignore[arg-type]

    assert caught.value.reason is StopReason.GITLESS_INVOCATION_PROBE_FAILED
    codex_copy = (
        preparation.state_home / "agent-loop" / "credentials" / "codex" / "default" / "auth.json"
    )
    claude_copy = (
        preparation.state_home
        / "agent-loop"
        / "credentials"
        / "claude"
        / "default"
        / "credentials.json"
    )
    assert codex_copy.read_bytes() == codex_source.read_bytes()
    assert claude_copy.read_bytes() == claude_source.read_bytes()
    assert stat.S_IMODE(codex_copy.stat().st_mode) == 0o600
    assert stat.S_IMODE(claude_copy.stat().st_mode) == 0o600
    assert not preparation.run_root.exists()


def test_claude_status_probe_is_non_model_transactional_and_token_free(
    tmp_path: Path,
) -> None:
    calls: list[dict[str, object]] = []

    class ProbeExecutor:
        def execute(self, **kwargs: object) -> SimpleNamespace:
            calls.append(dict(kwargs))
            process = SimpleNamespace(
                returncode=0,
                timed_out=False,
                output_limited=False,
                stdout=b'{"loggedIn":true,"authMethod":"claude.ai"}',
            )
            return SimpleNamespace(result=SimpleNamespace(process=process))

    claude_home = tmp_path / "claude-home"
    claude_home.mkdir()
    assert workflow._claude_status_probe(
        ProbeExecutor(),  # type: ignore[arg-type]
        _reviewed_install("claude"),
        claude_home,
        _managed_boundary(),
    )
    assert len(calls) == 1
    call = calls[0]
    assert call["argv"] == (
        "/opt/reviewed-claude/executable",
        "--safe-mode",
        "auth",
        "status",
        "--json",
    )
    environment = call["environment"]
    assert isinstance(environment, dict)
    assert "CLAUDE_CODE_OAUTH_TOKEN" not in environment
    assert environment["CLAUDE_CONFIG_DIR"] == "/control/claude-home"
    assert call["manifest"] == SubjectManifest.empty()


def test_production_runtime_reuses_and_propagates_receipt_witnessed_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_root = tmp_path / "state" / "agent-loop" / "runs" / "run-production-test"
    with ArtifactStore.create(run_root) as artifacts:
        preparation = _production_preparation(tmp_path, artifacts=artifacts)
        backend = ProductionWorkflowBackend()
        witnessed = _managed_boundary()
        replacement = _managed_boundary(
            policy_sha256="4" * 64,
            helper_sha256="5" * 64,
        )
        inspections = 0

        def inspect() -> ManagedClaudeBoundary:
            nonlocal inspections
            inspections += 1
            return witnessed if inspections == 1 else replacement

        monkeypatch.setattr(workflow, "inspect_managed_claude_boundary", inspect)
        assert backend._claude_boundary(preparation) is witnessed  # type: ignore[arg-type]
        monkeypatch.setattr(
            backend,
            "_install",
            lambda _preparation, *, name: _reviewed_install(name),
        )
        monkeypatch.setattr(workflow, "SandboxExecutor", lambda *args, **kwargs: object())
        author = object()
        validator = object()
        critic = object()
        monkeypatch.setattr(
            workflow,
            "SandboxedCodexAuthorAdapter",
            lambda *args, **kwargs: author,
        )
        monkeypatch.setattr(
            workflow,
            "SandboxedValidationAdapter",
            lambda *args, **kwargs: validator,
        )
        propagated: list[ManagedClaudeBoundary] = []

        def critic_adapter(*args: object, **kwargs: object) -> object:
            boundary = kwargs["managed_boundary"]
            assert isinstance(boundary, ManagedClaudeBoundary)
            propagated.append(boundary)
            return critic

        monkeypatch.setattr(workflow, "SandboxedClaudeCriticAdapter", critic_adapter)
        transaction = _FakeTransaction([], tmp_path / "codex-home")

        runtime = backend.build_runtime(
            preparation,  # type: ignore[arg-type]
            transaction,
            "fake-claude-token",
            (),
        )

    assert runtime.author is author
    assert runtime.validator is validator
    assert runtime.critic is critic
    assert propagated == [witnessed]
    assert inspections == 1


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


def test_dry_run_resolves_static_contract_without_auth_artifacts_or_models(
    tmp_path: Path,
) -> None:
    backend = _FakeBackend(tmp_path)
    output: list[str] = []
    args = _args(tmp_path)
    args.dry_run = True

    exit_code = execute_run(
        args,
        backend=backend,
        io=WorkflowIO(write=output.append, read=lambda _prompt: "unexpected"),
    )

    assert exit_code == 0
    assert backend.events == [
        "canonical_source",
        "source_lock",
        "preflight",
        "extract",
        "source_lock_close",
    ]
    assert backend.run_root is None
    preview = json.loads(output[0])
    assert preview["mode"] == "dry-run"
    assert preview["spending_authorized"] is False
    assert preview["models_called"] is False
    assert preview["credentials_loaded_or_imported"] is False
    assert preview["artifacts_created"] is False
    assert preview["validation_executed"] is False
    assert preview["live_receipt_checked"] is False
    assert preview["source"]["committed_revision"] == "a" * 40
    assert preview["configuration"]["checks"] == ["python -m pytest"]
    assert preview["next_steps"]["qualification"] == ("agent-loop qualify --live --accept-paid")


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


def test_remote_codex_reauthentication_failure_reaches_terminal_json_safely(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _FakeBackend(tmp_path)

    def rejected_session(_request: AuthorRequest) -> AuthorTurn:
        backend.events.append("author")
        classify_codex_process_result(
            BoundedProcessResult(
                1,
                (
                    b'{"type":"thread.started","thread_id":"thread-safe"}\n'
                    b'{"type":"turn.failed","error":{"message":"access token refresh '
                    b'failed: refresh_token_invalidated"}}\n'
                ),
                b"private vendor stderr",
                1.0,
                2.0,
                False,
                False,
            )
        )
        raise AssertionError("the rejected Codex session must stop the author turn")

    monkeypatch.setattr(backend.author, "turn", rejected_session)
    writes: list[str] = []

    assert (
        execute_run(
            _args(tmp_path, assume_yes=True),
            backend=backend,
            io=WorkflowIO(write=writes.append, read=lambda _prompt: "unexpected"),
        )
        == 17
    )

    terminal = json.loads(writes[-1])
    assert terminal["stop_reason"] == "credential_refresh_failure"
    assert terminal["detail"] == CODEX_REAUTHENTICATION_FAILURE_DETAIL
    assert terminal["next_action"] == CODEX_REAUTHENTICATION_NEXT_ACTION
    assert "claude auth" not in terminal["next_action"].lower()
    assert "refresh_token_invalidated" not in writes[-1]
    assert "private vendor stderr" not in writes[-1]
    assert _run_json(backend)["stop_detail"] == CODEX_REAUTHENTICATION_FAILURE_DETAIL


def test_remote_claude_reauthentication_failure_reaches_terminal_json_safely(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _FakeBackend(tmp_path)

    def rejected_session(_request: CriticRequest) -> CriticTurn:
        backend.events.append("critic")
        raise fail(
            StopReason.CREDENTIAL_REFRESH_FAILURE,
            CLAUDE_REAUTHENTICATION_FAILURE_DETAIL,
        )

    monkeypatch.setattr(backend.critic, "review", rejected_session)
    writes: list[str] = []

    assert (
        execute_run(
            _args(tmp_path, assume_yes=True),
            backend=backend,
            io=WorkflowIO(write=writes.append, read=lambda _prompt: "unexpected"),
        )
        == 17
    )

    terminal = json.loads(writes[-1])
    assert terminal["stop_reason"] == "credential_refresh_failure"
    assert terminal["detail"] == CLAUDE_REAUTHENTICATION_FAILURE_DETAIL
    assert terminal["next_action"] == CLAUDE_REAUTHENTICATION_NEXT_ACTION
    assert "codex login" not in terminal["next_action"].lower()
    assert _run_json(backend)["stop_detail"] == CLAUDE_REAUTHENTICATION_FAILURE_DETAIL


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
    staged_config = json.loads((backend.run_root / "artifacts" / "config.json").read_text())
    assert staged_config["protected_patterns"] == []
    assert staged_config["requested_author_model"] is None
    assert staged_config["operator_content_withheld_pending_credential_scan"] is True


def test_configuration_matching_a_known_credential_is_never_retained(
    tmp_path: Path,
) -> None:
    backend = _FakeBackend(tmp_path)
    args = _args(tmp_path, assume_yes=True)
    args.check = ["printf fake-token-never-persisted"]

    assert (
        execute_run(
            args,
            backend=backend,
            io=WorkflowIO(write=lambda _value: None, read=lambda _prompt: "unexpected"),
        )
        == 17
    )

    assert "runtime" not in backend.events
    assert "baseline" not in backend.events
    assert backend.run_root is not None
    assert not (backend.run_root / "artifacts" / "project-config.json").exists()
    metadata = json.loads((backend.run_root / "artifacts" / "project-config.meta.json").read_text())
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

    assert (
        execute_run(
            _args(tmp_path, assume_yes=True),
            backend=backend,
            io=WorkflowIO(write=lambda _value: None, read=lambda _prompt: "unexpected"),
        )
        == 17
    )

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

    assert (
        execute_run(
            args,
            backend=backend,
            io=WorkflowIO(write=lambda _value: None, read=lambda _prompt: "unexpected"),
        )
        == 17
    )

    assert "runtime" not in backend.events
    assert backend.run_root is not None
    assert not (backend.run_root / "subjects").exists()
    subject_meta = json.loads(
        (backend.run_root / "artifacts" / "base-subject.meta.json").read_text()
    )
    task_meta = json.loads((backend.run_root / "artifacts" / "task.meta.json").read_text())
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

    assert (
        execute_run(
            _args(tmp_path, assume_yes=True),
            backend=backend,
            io=WorkflowIO(write=writes.append, read=lambda _prompt: "unexpected"),
        )
        == 17
    )

    assert "credential_config_remove" in backend.events
    assert "credential_install" not in backend.events
    assert "runtime" not in backend.events
    assert backend.run_root is not None
    task_meta = json.loads((backend.run_root / "artifacts" / "task.meta.json").read_text())
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

    assert (
        execute_run(
            _args(tmp_path, assume_yes=True),
            backend=backend,
            io=WorkflowIO(write=writes.append, read=lambda _prompt: "unexpected"),
        )
        == 17
    )

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

    assert (
        execute_run(
            args,
            backend=backend,
            io=WorkflowIO(write=writes.append, read=lambda _prompt: "unexpected"),
        )
        == 17
    )

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

    assert (
        execute_run(
            _args(tmp_path, assume_yes=True),
            backend=backend,
            io=WorkflowIO(write=writes.append, read=forbidden_read),
        )
        == 0
    )
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

    assert (
        execute_run(
            args,
            backend=backend,
            io=WorkflowIO(write=lambda _value: None, read=lambda _prompt: "unexpected"),
        )
        == 0
    )

    manifest = _run_json(backend)
    protected_patterns = manifest["protected_patterns"]
    assert isinstance(protected_patterns, list)
    assert "task[*].md" in protected_patterns
    assert "config[[]1].toml" in protected_patterns


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
    assert (
        execute_run(
            _args(tmp_path, assume_yes=True),
            backend=backend,
            io=WorkflowIO(write=lambda _value: None, read=lambda _prompt: "unexpected"),
        )
        == 17
    )

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
    assert (
        execute_run(
            _args(tmp_path, assume_yes=True),
            backend=backend,
            io=WorkflowIO(write=lambda _value: None, read=lambda _prompt: "yes"),
        )
        == 17
    )

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
