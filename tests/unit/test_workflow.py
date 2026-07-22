from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path

import pytest

from agent_loop.artifacts import ArtifactStore
from agent_loop.claude_client import (
    CLAUDE_REAUTHENTICATION_FAILURE_DETAIL,
    CLAUDE_REAUTHENTICATION_NEXT_ACTION,
)
from agent_loop.cli import build_parser
from agent_loop.codex_client import (
    CODEX_REAUTHENTICATION_FAILURE_DETAIL,
    CODEX_REAUTHENTICATION_NEXT_ACTION,
)
from agent_loop.constants import Limits
from agent_loop.declassify import KnownSecret, raw_log_contains_known_secret
from agent_loop.errors import AgentLoopError, StopReason
from agent_loop.manifests import SubjectManifest
from agent_loop.sandbox import SandboxRole
from agent_loop.sandbox_init import (
    CleanupResult,
    PrimaryResult,
    SandboxRequest,
    SandboxResult,
    SupervisorLimits,
    encode_result,
)
from agent_loop.service import BoundedProcessResult, ServiceResult
from agent_loop.workflow import (
    _codex_artifact_evidence_barrier,
    _credential_failure_operator_fields,
    _KnownSecretLedger,
    _safe_outer_attempt_streams,
    _transaction_codex_known_secrets,
    parse_codex_file_auth,
    read_task,
    resolve_run_configuration,
)


def _outer_service_result(request: SandboxRequest, inner_stdout: bytes) -> ServiceResult:
    result = SandboxResult(
        request.manifest.fingerprint,
        request.manifest,
        (),
        PrimaryResult(0, inner_stdout, b"", False, False, 1),
        CleanupResult(0, True),
    )
    process = BoundedProcessResult(
        0,
        encode_result(result, max_bytes=2 * 1024 * 1024),
        b"",
        1,
        2,
        False,
        False,
    )
    return ServiceResult("agent-loop-test.service", process, {}, "/test", True)


def _outer_request() -> SandboxRequest:
    return SandboxRequest(
        SubjectManifest.empty(),
        (),
        ("/usr/bin/true",),
        (),
        "/runtime/author-cwd",
        b"",
        SupervisorLimits(1_000, 100, 64 * 1024, 2 * 1024 * 1024, Limits()),
    )


def test_outer_attempt_scans_decoded_base64_control_streams() -> None:
    secret = KnownSecret("historical-codex-token", b"refresh-token-0123456789")
    request = _outer_request()
    service = _outer_service_result(request, b"x" + secret.value)
    assert not raw_log_contains_known_secret(service.process.stdout, (secret,))

    stdout, stderr, truncated, withheld = _safe_outer_attempt_streams(
        SandboxRole.AUTHOR,
        request,
        service,
        (secret,),
        max_bytes=64 * 1024,
    )

    assert (stdout, stderr) == (b"", b"")
    assert truncated is True
    assert withheld is True


def test_outer_attempt_withholds_json_with_a_lone_surrogate() -> None:
    request = _outer_request()
    service = _outer_service_result(request, b'{"value":"\\ud800"}\n')

    with pytest.raises(AgentLoopError) as caught:
        _safe_outer_attempt_streams(
            SandboxRole.AUTHOR,
            request,
            service,
            (),
            max_bytes=64 * 1024,
        )

    assert caught.value.reason is StopReason.CREDENTIAL_REFRESH_FAILURE


def test_malformed_control_attempt_withholds_undecodable_streams() -> None:
    secret = KnownSecret("historical-codex-token", b"refresh-token-0123456789")
    request = _outer_request()
    encoded_fragment = base64.b64encode(b"x" + secret.value)
    process = BoundedProcessResult(
        2,
        b'{"partial":"' + encoded_fragment + b'"}',
        b"malformed",
        1,
        2,
        False,
        False,
    )
    service = ServiceResult("agent-loop-test.service", process, {}, "/test", True)
    assert not raw_log_contains_known_secret(process.stdout, (secret,))

    stdout, stderr, truncated, withheld = _safe_outer_attempt_streams(
        SandboxRole.AUTHOR,
        request,
        service,
        (secret,),
        max_bytes=64 * 1024,
    )

    assert (stdout, stderr) == (b"", b"")
    assert truncated is True
    assert withheld is True


def test_typed_sandbox_error_detail_cannot_persist_a_secret() -> None:
    secret = KnownSecret("historical-codex-token", b"refresh-token-0123456789")
    request = _outer_request()
    encoded = json.dumps(
        {
            "protocol_version": 1,
            "kind": "error",
            "error": {
                "reason": StopReason.SANDBOX_SETUP_FAILURE.value,
                "detail": secret.value.decode("ascii"),
            },
        },
        separators=(",", ":"),
    ).encode("ascii")
    process = BoundedProcessResult(1, encoded, b"", 1, 2, False, False)
    service = ServiceResult("agent-loop-test.service", process, {}, "/test", True)

    with pytest.raises(AgentLoopError) as caught:
        _safe_outer_attempt_streams(
            SandboxRole.AUTHOR,
            request,
            service,
            (secret,),
            max_bytes=64 * 1024,
        )

    assert caught.value.reason is StopReason.CREDENTIAL_REFRESH_FAILURE
    assert secret.value.decode("ascii") not in caught.value.detail


def test_only_fixed_codex_reauthentication_guidance_is_declassified() -> None:
    fields, withheld = _credential_failure_operator_fields(
        CODEX_REAUTHENTICATION_FAILURE_DETAIL,
        (),
    )

    assert withheld is False
    assert fields == {
        "detail": CODEX_REAUTHENTICATION_FAILURE_DETAIL,
        "next_action": CODEX_REAUTHENTICATION_NEXT_ACTION,
    }
    assert "claude" not in fields["next_action"].lower()

    hostile = "remote process said credential-private-diagnostic"
    generic, generic_withheld = _credential_failure_operator_fields(hostile, ())
    assert generic_withheld is False
    assert "detail" not in generic
    assert hostile not in json.dumps(generic)
    assert "codex login status" in generic["next_action"]
    assert "claude auth status" in generic["next_action"]


def test_only_fixed_claude_reauthentication_guidance_is_declassified() -> None:
    fields, withheld = _credential_failure_operator_fields(
        CLAUDE_REAUTHENTICATION_FAILURE_DETAIL,
        (),
    )

    assert withheld is False
    assert fields == {
        "detail": CLAUDE_REAUTHENTICATION_FAILURE_DETAIL,
        "next_action": CLAUDE_REAUTHENTICATION_NEXT_ACTION,
    }
    assert "codex login" not in fields["next_action"].lower()


def test_terminal_credential_guidance_is_withheld_on_secret_collision() -> None:
    fields, withheld = _credential_failure_operator_fields(
        CODEX_REAUTHENTICATION_FAILURE_DETAIL,
        (
            KnownSecret(
                "synthetic-collision",
                CODEX_REAUTHENTICATION_NEXT_ACTION.encode("utf-8"),
            ),
        ),
    )

    assert fields == {}
    assert withheld is True


def test_secret_ledger_keeps_every_refresh_generation() -> None:
    first = KnownSecret("codex-access_token", b"generation-a")
    second = KnownSecret("codex-access_token", b"generation-b")
    third = KnownSecret("codex-access_token", b"generation-c")
    ledger = _KnownSecretLedger((first,))

    ledger.extend((second,))
    ledger.extend((second, third))

    assert ledger.snapshot() == (first, second, third)


def test_secret_ledger_deduplicates_one_refresh_snapshot() -> None:
    repeated = KnownSecret("codex-access_token", b"generation-a")
    ledger = _KnownSecretLedger(())

    ledger.extend((repeated, repeated))

    assert ledger.snapshot() == (repeated,)


def test_credential_promotion_barrier_durably_marks_and_scrubs_prior_run(
    tmp_path: Path,
) -> None:
    state_home = tmp_path / "state"
    run_root = state_home / "agent-loop" / "runs" / "prior-run"
    auth = json.loads(_valid_auth())
    token = "post-crash-generation-token"
    auth["tokens"]["access_token"] = token
    generation = json.dumps(auth, separators=(",", ":")).encode("ascii")

    with ArtifactStore.create(run_root) as artifacts:
        artifacts.write_bytes("artifacts/prior.log", token.encode("ascii"))

    _codex_artifact_evidence_barrier(state_home)("prior-run", (generation,))

    with ArtifactStore.open(run_root) as artifacts:
        assert artifacts.content_withheld_due_to_secret is True
        with pytest.raises(AgentLoopError) as withheld:
            artifacts.read_bytes("artifacts/prior.log", max_bytes=1)
        assert withheld.value.reason is StopReason.CREDENTIAL_REFRESH_FAILURE
    assert list(run_root.iterdir()) == []


def test_credential_recovery_barrier_replays_marker_backed_whole_run_withholding(
    tmp_path: Path,
) -> None:
    state_home = tmp_path / "state"
    run_root = state_home / "agent-loop" / "runs" / "prior-run"
    with ArtifactStore.create(run_root) as artifacts:
        artifacts.withhold_all_content()
        # Simulate a hard interruption that left content after the durable
        # marker had already committed the whole-run withholding decision.
        leftover = run_root / "artifacts" / "leftover.log"
        leftover.parent.mkdir(mode=0o700)
        leftover.write_bytes(b"unclassified candidate bytes")
        leftover.chmod(0o600)

    _codex_artifact_evidence_barrier(state_home)("prior-run", ())

    with ArtifactStore.open(run_root) as artifacts:
        assert artifacts.content_withheld_due_to_secret is True
        assert not (run_root / "artifacts" / "leftover.log").exists()


def test_transaction_secret_snapshot_contains_pre_and_post_capture_generations() -> None:
    def generation(access_token: str) -> bytes:
        value = json.loads(_valid_auth())
        value["tokens"]["access_token"] = access_token
        return json.dumps(value, separators=(",", ":")).encode("utf-8")

    first = generation("access-generation-a")
    second = generation("access-generation-b")

    class Transaction:
        def __init__(self) -> None:
            self.values = [first]

        @property
        def auth_generations(self) -> tuple[bytes, ...]:
            return tuple(self.values)

        def capture_candidate_generation(self) -> bool:
            self.values.append(second)
            return True

    secrets = _transaction_codex_known_secrets(Transaction())  # type: ignore[arg-type]

    access_values = {
        secret.value for secret in secrets if secret.identifier == "codex-access_token"
    }
    assert access_values == {b"access-generation-a", b"access-generation-b"}


def _run_args(tmp_path: Path, *extra: str) -> argparse.Namespace:
    task = tmp_path / "task.md"
    task.write_text("Implement the reviewed change.\n", encoding="utf-8")
    return build_parser().parse_args(
        [
            "--state-home",
            str(tmp_path / "state"),
            "run",
            "--task",
            str(task),
            *extra,
        ]
    )


def test_run_configuration_adds_and_deduplicates_cli_declarations(tmp_path: Path) -> None:
    config = tmp_path / "project.toml"
    config.write_text(
        """
schema_version = 1
checks = ["python -m pytest"]
protected_paths = ["harness/**"]
discard_only_paths = ["build/**"]
review_context_paths = ["docs/design.md"]
read_only_toolchain_mounts = ["/opt/reviewed-one"]
author_model = "gpt-author-exact"
author_effort = "high"
critic_model = "claude-critic-exact"
critic_effort = "medium"
codex_credential_id = "codex-account"
claude_credential_id = "claude-account"
max_rounds = 2
""".strip()
        + "\n",
        encoding="utf-8",
    )
    args = _run_args(
        tmp_path,
        "--config",
        str(config),
        "--check",
        "python -m pytest",
        "--check",
        "python -m compileall src",
        "--protected-validation-path",
        "harness/**",
        "--protected-validation-path",
        "acceptance/**",
        "--discard-only-path",
        "coverage/**",
        "--review-context-path",
        "README.md",
        "--read-only-toolchain-mount",
        "/opt/reviewed-two",
        "--max-rounds",
        "4",
        "--codex-executable",
        "/opt/codex/bin/codex",
        "--claude-executable",
        "/opt/claude/bin/claude",
    )

    selected = resolve_run_configuration(args)

    assert selected.project.checks == (
        "python -m pytest",
        "python -m compileall src",
    )
    assert selected.project.max_rounds == 4
    assert selected.project.protected_paths.count("harness/**") == 1
    assert "acceptance/**" in selected.project.protected_paths
    assert selected.project.discard_only_paths == ("build/**", "coverage/**")
    assert selected.project.review_context_paths == ("docs/design.md", "README.md")
    assert selected.project.read_only_toolchain_mounts == (
        "/opt/reviewed-one",
        "/opt/reviewed-two",
    )


def test_run_configuration_uses_one_exact_receipt_bindable_model_pair_by_default(
    tmp_path: Path,
) -> None:
    args = _run_args(
        tmp_path,
        "--check",
        "python -m pytest",
        "--codex-executable",
        "/opt/codex/bin/codex",
        "--claude-executable",
        "/opt/claude/bin/claude",
    )

    selected = resolve_run_configuration(args)

    assert selected.project.author_model == "gpt-5.4"
    assert selected.project.author_effort == "high"
    assert selected.project.critic_model == "claude-opus-4-6"
    assert selected.project.critic_effort == "medium"
    assert selected.project.codex_credential_id == "default"
    assert selected.project.claude_credential_id == "default"


def test_run_configuration_discovers_the_pinned_cli_pair_when_paths_are_omitted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import agent_loop.qualification as qualification

    monkeypatch.setattr(
        qualification,
        "discover_pinned_cli_executables",
        lambda: (Path("/opt/pinned/codex"), Path("/opt/pinned/claude")),
    )
    args = _run_args(tmp_path, "--check", "python -m pytest")

    selected = resolve_run_configuration(args)

    assert selected.codex_executable == Path("/opt/pinned/codex")
    assert selected.claude_executable == Path("/opt/pinned/claude")


def test_run_configuration_rejects_zero_validation_checks(tmp_path: Path) -> None:
    args = _run_args(tmp_path)
    with pytest.raises(AgentLoopError) as caught:
        resolve_run_configuration(args)
    assert caught.value.reason is StopReason.SANDBOX_SETUP_FAILURE
    assert "at least one" in caught.value.detail


def test_task_reader_is_bounded_utf8_and_does_not_follow_leaf_symlink(tmp_path: Path) -> None:
    task = tmp_path / "task.md"
    task.write_text("bounded task\n", encoding="utf-8")
    assert read_task(task, max_bytes=32) == "bounded task\n"

    link = tmp_path / "task-link.md"
    link.symlink_to(task)
    with pytest.raises(AgentLoopError) as linked:
        read_task(link, max_bytes=32)
    assert linked.value.reason is StopReason.SANDBOX_SETUP_FAILURE

    directory = tmp_path / "actual"
    directory.mkdir()
    nested = directory / "nested-task.md"
    nested.write_text("nested task\n", encoding="utf-8")
    (tmp_path / "linked-directory").symlink_to(directory, target_is_directory=True)
    with pytest.raises(AgentLoopError) as intermediate:
        read_task(tmp_path / "linked-directory" / nested.name, max_bytes=32)
    assert intermediate.value.reason is StopReason.SANDBOX_SETUP_FAILURE

    task.write_bytes(b"x" * 33)
    with pytest.raises(AgentLoopError, match="byte limit"):
        read_task(task, max_bytes=32)


def _valid_auth() -> bytes:
    return json.dumps(
        {
            "auth_mode": "chatgpt",
            "OPENAI_API_KEY": None,
            "tokens": {
                "id_token": "id-secret",
                "access_token": "access-secret",
                "refresh_token": "refresh-secret",
                "account_id": "account-id",
            },
            "last_refresh": "2026-07-19T12:00:00Z",
        },
        separators=(",", ":"),
    ).encode("utf-8")


def test_codex_file_auth_parser_is_total_duplicate_safe_and_shape_closed() -> None:
    assert parse_codex_file_auth(_valid_auth()) is True
    assert parse_codex_file_auth(b'{"auth_mode":"chatgpt","auth_mode":"chatgpt"}') is False
    assert parse_codex_file_auth(b'{"value":NaN}') is False
    assert parse_codex_file_auth(b'{"value":1e999999}') is False
    assert parse_codex_file_auth(b"\xff") is False
    assert parse_codex_file_auth(b"[" * 2_000 + b"]" * 2_000) is False
    assert parse_codex_file_auth(_valid_auth().replace(b"id-secret", b"\\ud800")) is False

    api_key = json.loads(_valid_auth())
    api_key["auth_mode"] = "apikey"
    api_key["OPENAI_API_KEY"] = "must-not-be-accepted"
    assert parse_codex_file_auth(json.dumps(api_key).encode()) is False

    broadened = json.loads(_valid_auth())
    broadened["ambient"] = "unsupported"
    assert parse_codex_file_auth(json.dumps(broadened).encode()) is False
