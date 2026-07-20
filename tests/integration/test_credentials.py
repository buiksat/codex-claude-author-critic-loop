from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
import threading
import time
from pathlib import Path

import pytest

import agent_loop.credentials as credential_module
from agent_loop.credentials import (
    CodexCredentialTransaction,
    build_claude_parent_environment,
    claude_credential_root,
    codex_credential_root,
    load_claude_setup_token,
    scrub_claude_child_environment,
    xdg_state_home,
)
from agent_loop.errors import AgentLoopError, ExitCode, StopReason, fail


OLD_AUTH = b'{"access_token":"old-secret"}'
NEW_AUTH = b'{"access_token":"new-secret"}'
OTHER_AUTH = b'{"access_token":"other-secret"}'


def valid_auth(data: bytes) -> bool:
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    return isinstance(value, dict) and isinstance(value.get("access_token"), str)


def passing_probe(codex_home: Path) -> bool:
    return valid_auth((codex_home / "auth.json").read_bytes())


def write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    path.write_bytes(data)
    path.chmod(0o600)


def provision_codex(state_home: Path, credential_id: str, data: bytes = OLD_AUTH) -> Path:
    root = codex_credential_root(credential_id, state_home=state_home)
    write_private(root / "auth.json", data)
    return root


def provision_claude(state_home: Path, credential_id: str, token: bytes) -> Path:
    root = claude_credential_root(credential_id, state_home=state_home)
    write_private(root / "oauth-token", token)
    return root


def test_032_codex_transaction_is_private_locked_and_contains_no_secret_metadata(
    tmp_path: Path,
) -> None:
    root = provision_codex(tmp_path, "account-a")
    parser_inputs: list[bytes] = []

    def parser(data: bytes) -> bool:
        parser_inputs.append(data)
        return valid_auth(data)

    with CodexCredentialTransaction.acquire(
        "account-a",
        "run-a",
        auth_parser=parser,
        auth_probe=passing_probe,
        state_home=tmp_path,
    ) as transaction:
        assert transaction.candidate_auth_path.read_bytes() == OLD_AUTH
        assert transaction.codex_home.parent.parent == root / "transactions"
        assert stat.S_IMODE(root.stat().st_mode) == 0o700
        assert stat.S_IMODE((root / "auth.json").stat().st_mode) == 0o600
        assert stat.S_IMODE(transaction.transaction_root.stat().st_mode) == 0o700
        assert stat.S_IMODE(transaction.codex_home.stat().st_mode) == 0o700
        assert stat.S_IMODE(transaction.candidate_auth_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(transaction.metadata_path.stat().st_mode) == 0o600
        metadata = transaction.metadata_path.read_bytes()
        assert b"old-secret" not in metadata
        assert transaction.baseline_sha256.encode("ascii") in metadata

        competing_fd = os.open(root / "lock", os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(competing_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(competing_fd)

    assert parser_inputs and set(parser_inputs) == {OLD_AUTH}
    assert not (root / "transactions" / "run-a").exists()
    assert (root / "auth.json").read_bytes() == OLD_AUTH


def test_067_changed_candidate_is_probed_promoted_and_rebaselined_before_acceptance(
    tmp_path: Path,
) -> None:
    root = provision_codex(tmp_path, "account-refresh")
    probed_homes: list[Path] = []

    def probe(codex_home: Path) -> bool:
        probed_homes.append(codex_home)
        return (codex_home / "auth.json").read_bytes() == NEW_AUTH

    with CodexCredentialTransaction.acquire(
        "account-refresh",
        "run-refresh",
        auth_parser=valid_auth,
        auth_probe=probe,
        state_home=tmp_path,
    ) as transaction:
        transaction.candidate_auth_path.write_bytes(NEW_AUTH)
        transaction.candidate_auth_path.chmod(0o600)

        assert transaction.reconcile_after_turn()
        assert (root / "auth.json").read_bytes() == NEW_AUTH
        assert probed_homes == [transaction.codex_home]
        assert transaction.baseline_sha256 == hashlib.sha256(NEW_AUTH).hexdigest()
        metadata = json.loads(transaction.metadata_path.read_bytes())
        assert metadata["baseline_sha256"] == transaction.baseline_sha256
        assert not transaction.reconcile_after_turn()

    assert not (root / "transactions" / "run-refresh").exists()


def test_credential_history_keeps_pre_probe_and_post_probe_generations_in_memory(
    tmp_path: Path,
) -> None:
    root = provision_codex(tmp_path, "history-refresh")

    def mutating_probe(codex_home: Path) -> bool:
        candidate = codex_home / "auth.json"
        assert candidate.read_bytes() == NEW_AUTH
        candidate.write_bytes(OTHER_AUTH)
        candidate.chmod(0o600)
        return True

    with CodexCredentialTransaction.acquire(
        "history-refresh",
        "history-run",
        auth_parser=valid_auth,
        auth_probe=mutating_probe,
        state_home=tmp_path,
    ) as transaction:
        assert transaction.auth_generations == (OLD_AUTH,)
        transaction.candidate_auth_path.write_bytes(NEW_AUTH)
        transaction.candidate_auth_path.chmod(0o600)

        assert transaction.reconcile_after_turn()
        assert transaction.auth_generations == (OLD_AUTH, NEW_AUTH, OTHER_AUTH)
        assert (root / "auth.json").read_bytes() == OTHER_AUTH
        metadata = transaction.metadata_path.read_bytes()
        assert b"old-secret" not in metadata
        assert b"new-secret" not in metadata
        assert b"other-secret" not in metadata


def test_external_candidate_capture_is_validated_deduplicated_and_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provision_codex(tmp_path, "history-capture")
    transaction = CodexCredentialTransaction.acquire(
        "history-capture",
        "history-run",
        auth_parser=valid_auth,
        auth_probe=passing_probe,
        state_home=tmp_path,
    )
    try:
        assert not transaction.capture_candidate_generation()
        transaction.candidate_auth_path.write_bytes(NEW_AUTH)
        transaction.candidate_auth_path.chmod(0o600)
        assert transaction.capture_candidate_generation()
        assert not transaction.capture_candidate_generation()
        assert transaction.auth_generations == (OLD_AUTH, NEW_AUTH)

        monkeypatch.setattr(credential_module, "_MAX_AUTH_GENERATION_HISTORY", 2)
        transaction.candidate_auth_path.write_bytes(OTHER_AUTH)
        transaction.candidate_auth_path.chmod(0o600)
        with pytest.raises(AgentLoopError) as caught:
            transaction.capture_candidate_generation()

        assert caught.value.reason is StopReason.CREDENTIAL_REFRESH_FAILURE
        assert "other-secret" not in str(caught.value)
        assert transaction.auth_generations == (OLD_AUTH, NEW_AUTH)
    finally:
        transaction.close()


def test_candidate_config_removal_is_private_durable_and_idempotent(
    tmp_path: Path,
) -> None:
    root = provision_codex(tmp_path, "config-removal")
    transaction = CodexCredentialTransaction.acquire(
        "config-removal",
        "config-run",
        auth_parser=valid_auth,
        auth_probe=passing_probe,
        state_home=tmp_path,
    )
    try:
        config = transaction.codex_home / "config.toml"
        write_private(config, b'model = "reviewed"\n')

        transaction.remove_candidate_config()
        transaction.remove_candidate_config()

        assert not config.exists()
        assert not transaction.reconcile_after_turn()
        transaction.finalize_reconciled()
        assert not (root / "transactions" / "config-run").exists()
    finally:
        transaction.close()


def test_failed_probe_still_captures_its_valid_post_probe_generation(
    tmp_path: Path,
) -> None:
    root = provision_codex(tmp_path, "history-failed-probe")

    def failing_mutating_probe(codex_home: Path) -> bool:
        candidate = codex_home / "auth.json"
        assert candidate.read_bytes() == NEW_AUTH
        candidate.write_bytes(OTHER_AUTH)
        candidate.chmod(0o600)
        return False

    transaction = CodexCredentialTransaction.acquire(
        "history-failed-probe",
        "history-run",
        auth_parser=valid_auth,
        auth_probe=failing_mutating_probe,
        state_home=tmp_path,
    )
    transaction.candidate_auth_path.write_bytes(NEW_AUTH)
    transaction.candidate_auth_path.chmod(0o600)
    try:
        with pytest.raises(AgentLoopError) as caught:
            transaction.reconcile_after_turn()

        assert caught.value.reason is StopReason.CREDENTIAL_REFRESH_FAILURE
        assert transaction.auth_generations == (OLD_AUTH, NEW_AUTH, OTHER_AUTH)
        assert (root / "auth.json").read_bytes() == OLD_AUTH
        assert "other-secret" not in str(caught.value)
    finally:
        transaction.close()


def test_interrupted_probe_still_captures_its_valid_post_probe_generation(
    tmp_path: Path,
) -> None:
    root = provision_codex(tmp_path, "history-interrupted-probe")

    def interrupting_mutating_probe(codex_home: Path) -> bool:
        candidate = codex_home / "auth.json"
        assert candidate.read_bytes() == NEW_AUTH
        candidate.write_bytes(OTHER_AUTH)
        candidate.chmod(0o600)
        raise KeyboardInterrupt

    transaction = CodexCredentialTransaction.acquire(
        "history-interrupted-probe",
        "history-run",
        auth_parser=valid_auth,
        auth_probe=interrupting_mutating_probe,
        state_home=tmp_path,
    )
    transaction.candidate_auth_path.write_bytes(NEW_AUTH)
    transaction.candidate_auth_path.chmod(0o600)
    try:
        with pytest.raises(KeyboardInterrupt):
            transaction.reconcile_after_turn()

        assert transaction.auth_generations == (OLD_AUTH, NEW_AUTH, OTHER_AUTH)
        assert (root / "auth.json").read_bytes() == OLD_AUTH
    finally:
        transaction.close()


def test_067_same_account_lock_serializes_runs_for_different_repositories(
    tmp_path: Path,
) -> None:
    provision_codex(tmp_path, "shared-account")
    first_acquired = threading.Event()
    release_first = threading.Event()
    second_attempting = threading.Event()
    second_acquired = threading.Event()
    failures: list[BaseException] = []

    def first_repository() -> None:
        try:
            with CodexCredentialTransaction.acquire(
                "shared-account",
                "repo-one-run",
                auth_parser=valid_auth,
                auth_probe=passing_probe,
                state_home=tmp_path,
                lock_timeout_seconds=2,
            ):
                first_acquired.set()
                assert release_first.wait(2)
        except BaseException as exc:
            failures.append(exc)

    def second_repository() -> None:
        try:
            second_attempting.set()
            with CodexCredentialTransaction.acquire(
                "shared-account",
                "repo-two-run",
                auth_parser=valid_auth,
                auth_probe=passing_probe,
                state_home=tmp_path,
                lock_timeout_seconds=2,
            ):
                second_acquired.set()
        except BaseException as exc:
            failures.append(exc)

    first = threading.Thread(target=first_repository)
    second = threading.Thread(target=second_repository)
    first.start()
    assert first_acquired.wait(2)
    second.start()
    assert second_attempting.wait(2)
    time.sleep(0.05)
    assert not second_acquired.is_set()
    release_first.set()
    first.join(2)
    second.join(2)

    assert failures == []
    assert not first.is_alive()
    assert not second.is_alive()
    assert second_acquired.is_set()


def test_036_crash_recovery_promotes_only_valid_candidate_at_matching_baseline(
    tmp_path: Path,
) -> None:
    root = provision_codex(tmp_path, "recover-account")
    old_transaction = CodexCredentialTransaction.acquire(
        "recover-account",
        "crashed-run",
        auth_parser=valid_auth,
        auth_probe=passing_probe,
        state_home=tmp_path,
    )
    old_transaction.candidate_auth_path.write_bytes(NEW_AUTH)
    old_transaction.candidate_auth_path.chmod(0o600)
    old_transaction.close()  # Simulated runner crash: preserve transaction state.

    with CodexCredentialTransaction.acquire(
        "recover-account",
        "next-run",
        auth_parser=valid_auth,
        auth_probe=passing_probe,
        state_home=tmp_path,
    ) as recovered:
        assert (root / "auth.json").read_bytes() == NEW_AUTH
        assert recovered.candidate_auth_path.read_bytes() == NEW_AUTH
        assert not (root / "transactions" / "crashed-run").exists()


def test_crash_recovery_retries_evidence_barrier_before_candidate_promotion(
    tmp_path: Path,
) -> None:
    root = provision_codex(tmp_path, "recover-evidence-barrier")
    crashed = CodexCredentialTransaction.acquire(
        "recover-evidence-barrier",
        "crashed-run",
        auth_parser=valid_auth,
        auth_probe=passing_probe,
        state_home=tmp_path,
    )
    crashed.candidate_auth_path.write_bytes(NEW_AUTH)
    crashed.candidate_auth_path.chmod(0o600)
    crashed.close()
    observed: list[tuple[str, tuple[bytes, ...]]] = []

    def interrupted_barrier(run_id: str, generations: tuple[bytes, ...]) -> None:
        observed.append((run_id, generations))
        if not generations:
            return
        assert (root / "auth.json").read_bytes() == OLD_AUTH
        raise fail(
            StopReason.CREDENTIAL_REFRESH_FAILURE,
            "injected evidence scrub interruption",
        )

    with pytest.raises(AgentLoopError):
        CodexCredentialTransaction.acquire(
            "recover-evidence-barrier",
            "next-run",
            auth_parser=valid_auth,
            auth_probe=passing_probe,
            state_home=tmp_path,
            evidence_barrier=interrupted_barrier,
        )

    assert (root / "auth.json").read_bytes() == OLD_AUTH
    assert (root / "transactions" / "crashed-run").exists()
    assert observed == [
        ("crashed-run", ()),
        ("crashed-run", (OLD_AUTH, NEW_AUTH)),
    ]

    completed: list[str] = []

    def completed_barrier(run_id: str, generations: tuple[bytes, ...]) -> None:
        if not generations:
            return
        assert generations == (OLD_AUTH, NEW_AUTH)
        completed.append(run_id)

    recovered = CodexCredentialTransaction.acquire(
        "recover-evidence-barrier",
        "next-run",
        auth_parser=valid_auth,
        auth_probe=passing_probe,
        state_home=tmp_path,
        evidence_barrier=completed_barrier,
    )
    try:
        assert completed == ["crashed-run"]
        assert (root / "auth.json").read_bytes() == NEW_AUTH
    finally:
        recovered.close()


def test_recovery_replays_whole_run_withholding_before_invalid_candidate_validation(
    tmp_path: Path,
) -> None:
    root = provision_codex(tmp_path, "recover-invalid-after-withhold")
    crashed = CodexCredentialTransaction.acquire(
        "recover-invalid-after-withhold",
        "crashed-run",
        auth_parser=valid_auth,
        auth_probe=passing_probe,
        state_home=tmp_path,
    )
    invalid_candidate = b'{"access_token":'
    crashed.candidate_auth_path.write_bytes(invalid_candidate)
    crashed.close()

    leftover = tmp_path / "leftover-evidence"
    leftover.write_bytes(b"must be withheld before candidate parsing")
    replayed: list[tuple[str, tuple[bytes, ...]]] = []

    def replay_barrier(run_id: str, generations: tuple[bytes, ...]) -> None:
        replayed.append((run_id, generations))
        assert generations == ()
        leftover.unlink()

    def parser(data: bytes) -> bool:
        if data == OLD_AUTH:
            return True
        assert data == invalid_candidate
        assert not leftover.exists()
        return False

    with pytest.raises(AgentLoopError) as caught:
        CodexCredentialTransaction.acquire(
            "recover-invalid-after-withhold",
            "next-run",
            auth_parser=parser,
            auth_probe=passing_probe,
            state_home=tmp_path,
            evidence_barrier=replay_barrier,
        )

    assert caught.value.reason is StopReason.CREDENTIAL_STATE_CONFLICT
    assert replayed == [("crashed-run", ())]
    assert (root / "auth.json").read_bytes() == OLD_AUTH
    assert (root / "transactions" / "crashed-run").exists()


def test_crash_recovery_history_keeps_initial_candidate_and_probe_rewrite(
    tmp_path: Path,
) -> None:
    root = provision_codex(tmp_path, "recover-history")
    crashed = CodexCredentialTransaction.acquire(
        "recover-history",
        "crashed-run",
        auth_parser=valid_auth,
        auth_probe=passing_probe,
        state_home=tmp_path,
    )
    crashed.candidate_auth_path.write_bytes(NEW_AUTH)
    crashed.candidate_auth_path.chmod(0o600)
    crashed.close()

    def mutating_recovery_probe(codex_home: Path) -> bool:
        candidate = codex_home / "auth.json"
        assert candidate.read_bytes() == NEW_AUTH
        candidate.write_bytes(OTHER_AUTH)
        candidate.chmod(0o600)
        return True

    with CodexCredentialTransaction.acquire(
        "recover-history",
        "next-run",
        auth_parser=valid_auth,
        auth_probe=mutating_recovery_probe,
        state_home=tmp_path,
    ) as recovered:
        assert recovered.auth_generations == (OLD_AUTH, NEW_AUTH, OTHER_AUTH)
        assert recovered.candidate_auth_path.read_bytes() == OTHER_AUTH
        assert (root / "auth.json").read_bytes() == OTHER_AUTH
        assert not (root / "transactions" / "crashed-run").exists()


def test_interrupted_recovery_probe_validates_and_records_its_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = provision_codex(tmp_path, "recover-interrupted-history")
    crashed = CodexCredentialTransaction.acquire(
        "recover-interrupted-history",
        "crashed-run",
        auth_parser=valid_auth,
        auth_probe=passing_probe,
        state_home=tmp_path,
    )
    crashed.candidate_auth_path.write_bytes(NEW_AUTH)
    crashed.candidate_auth_path.chmod(0o600)
    candidate_path = crashed.candidate_auth_path
    crashed.close()

    appended: list[bytes] = []
    original_append = credential_module._AuthGenerationHistory.append

    def recording_append(
        history: credential_module._AuthGenerationHistory,
        value: bytes,
    ) -> bool:
        appended.append(value)
        return original_append(history, value)

    monkeypatch.setattr(
        credential_module._AuthGenerationHistory,
        "append",
        recording_append,
    )

    def interrupting_recovery_probe(codex_home: Path) -> bool:
        candidate = codex_home / "auth.json"
        assert candidate.read_bytes() == NEW_AUTH
        candidate.write_bytes(OTHER_AUTH)
        candidate.chmod(0o600)
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        CodexCredentialTransaction.acquire(
            "recover-interrupted-history",
            "next-run",
            auth_parser=valid_auth,
            auth_probe=interrupting_recovery_probe,
            state_home=tmp_path,
        )

    assert appended == [OLD_AUTH, NEW_AUTH, OTHER_AUTH]
    assert candidate_path.read_bytes() == OTHER_AUTH
    assert (root / "auth.json").read_bytes() == OLD_AUTH


def test_036_baseline_conflict_preserves_durable_and_candidate_without_secret_error(
    tmp_path: Path,
) -> None:
    root = provision_codex(tmp_path, "conflict-account")
    crashed = CodexCredentialTransaction.acquire(
        "conflict-account",
        "crashed-run",
        auth_parser=valid_auth,
        auth_probe=passing_probe,
        state_home=tmp_path,
    )
    crashed.candidate_auth_path.write_bytes(NEW_AUTH)
    crashed.candidate_auth_path.chmod(0o600)
    candidate_path = crashed.candidate_auth_path
    crashed.close()
    write_private(root / "auth.json", OTHER_AUTH)
    replayed: list[tuple[str, tuple[bytes, ...]]] = []

    with pytest.raises(AgentLoopError) as caught:
        CodexCredentialTransaction.acquire(
            "conflict-account",
            "next-run",
            auth_parser=valid_auth,
            auth_probe=passing_probe,
            state_home=tmp_path,
            evidence_barrier=lambda run_id, generations: replayed.append(
                (run_id, generations)
            ),
        )

    assert caught.value.reason is StopReason.CREDENTIAL_STATE_CONFLICT
    assert caught.value.exit_code is ExitCode.INTEGRITY_FAILURE
    assert (root / "auth.json").read_bytes() == OTHER_AUTH
    assert candidate_path.read_bytes() == NEW_AUTH
    assert replayed == [("crashed-run", ())]
    message = str(caught.value)
    assert "old-secret" not in message
    assert "new-secret" not in message
    assert "other-secret" not in message


def test_036_invalid_recovery_candidate_is_not_promoted_or_deleted(tmp_path: Path) -> None:
    root = provision_codex(tmp_path, "invalid-recovery")
    crashed = CodexCredentialTransaction.acquire(
        "invalid-recovery",
        "crashed-run",
        auth_parser=valid_auth,
        auth_probe=passing_probe,
        state_home=tmp_path,
    )
    invalid = b"invalid-secret-candidate"
    crashed.candidate_auth_path.write_bytes(invalid)
    crashed.candidate_auth_path.chmod(0o600)
    candidate_path = crashed.candidate_auth_path
    crashed.close()

    with pytest.raises(AgentLoopError) as caught:
        CodexCredentialTransaction.acquire(
            "invalid-recovery",
            "next-run",
            auth_parser=valid_auth,
            auth_probe=passing_probe,
            state_home=tmp_path,
        )

    assert caught.value.reason is StopReason.CREDENTIAL_STATE_CONFLICT
    assert (root / "auth.json").read_bytes() == OLD_AUTH
    assert candidate_path.read_bytes() == invalid
    assert "invalid-secret-candidate" not in str(caught.value)


def test_032_invalid_or_symlink_candidate_never_reaches_durable_store(tmp_path: Path) -> None:
    root = provision_codex(tmp_path, "unsafe-candidate")
    transaction = CodexCredentialTransaction.acquire(
        "unsafe-candidate",
        "run",
        auth_parser=valid_auth,
        auth_probe=passing_probe,
        state_home=tmp_path,
    )
    host_secret = tmp_path / "host-secret"
    host_secret.write_bytes(OTHER_AUTH)
    transaction.candidate_auth_path.unlink()
    transaction.candidate_auth_path.symlink_to(host_secret)

    try:
        with pytest.raises(AgentLoopError) as caught:
            transaction.reconcile_after_turn()
    finally:
        transaction.close()

    assert caught.value.reason is StopReason.CREDENTIAL_REFRESH_FAILURE
    assert (root / "auth.json").read_bytes() == OLD_AUTH
    assert "other-secret" not in str(caught.value)


def test_callback_exception_text_cannot_leak_candidate_secret(tmp_path: Path) -> None:
    root = provision_codex(tmp_path, "callback-error")

    def leaking_parser(data: bytes) -> bool:
        if data == NEW_AUTH:
            raise ValueError(data.decode("ascii"))
        return valid_auth(data)

    transaction = CodexCredentialTransaction.acquire(
        "callback-error",
        "run",
        auth_parser=leaking_parser,
        auth_probe=passing_probe,
        state_home=tmp_path,
    )
    transaction.candidate_auth_path.write_bytes(NEW_AUTH)
    transaction.candidate_auth_path.chmod(0o600)
    try:
        with pytest.raises(AgentLoopError) as caught:
            transaction.reconcile_after_turn()
    finally:
        transaction.close()

    assert caught.value.reason is StopReason.CREDENTIAL_REFRESH_FAILURE
    assert "new-secret" not in str(caught.value)
    assert (root / "auth.json").read_bytes() == OLD_AUTH


@pytest.mark.parametrize("mode", [0o644, 0o400])
def test_032_durable_codex_auth_requires_exact_mode_0600(tmp_path: Path, mode: int) -> None:
    root = provision_codex(tmp_path, f"mode-{mode:o}")
    (root / "auth.json").chmod(mode)

    with pytest.raises(AgentLoopError) as caught:
        CodexCredentialTransaction.acquire(
            f"mode-{mode:o}",
            "run",
            auth_parser=valid_auth,
            auth_probe=passing_probe,
            state_home=tmp_path,
        )

    assert caught.value.reason is StopReason.CREDENTIAL_REFRESH_FAILURE


def test_072_only_private_dedicated_claude_setup_token_is_loaded(tmp_path: Path) -> None:
    token = "dedicated-automation-token"
    root = provision_claude(tmp_path, "claude-account", (token + "\n").encode())

    loaded = load_claude_setup_token("claude-account", state_home=tmp_path)

    assert loaded == token
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE((root / "oauth-token").stat().st_mode) == 0o600


def test_072_claude_token_symlink_and_permissive_mode_fail_without_reading_target(
    tmp_path: Path,
) -> None:
    secret = tmp_path / "ambient-keychain-secret"
    secret.write_text("must-not-be-read")
    symlink_root = claude_credential_root("symlink-token", state_home=tmp_path)
    symlink_root.mkdir(mode=0o700, parents=True)
    (symlink_root / "oauth-token").symlink_to(secret)

    with pytest.raises(AgentLoopError) as symlink_error:
        load_claude_setup_token("symlink-token", state_home=tmp_path)
    assert "must-not-be-read" not in str(symlink_error.value)

    mode_root = provision_claude(tmp_path, "mode-token", b"dedicated-token")
    (mode_root / "oauth-token").chmod(0o644)
    with pytest.raises(AgentLoopError):
        load_claude_setup_token("mode-token", state_home=tmp_path)


def test_072_parent_environment_ignores_ambient_auth_and_child_has_no_token(
    tmp_path: Path,
) -> None:
    token = "dedicated-parent-only-token"
    hostile_ambient = {
        "HOME": "/host/home",
        "ANTHROPIC_API_KEY": "ambient-anthropic",
        "CLAUDE_CODE_OAUTH_TOKEN": "ambient-claude",
        "AWS_SECRET_ACCESS_KEY": "ambient-cloud",
        "GOOGLE_APPLICATION_CREDENTIALS": "/host/google.json",
        "SSH_AUTH_SOCK": "/host/agent.sock",
        "HTTPS_PROXY": "http://credential@proxy",
    }
    config = tmp_path / "control" / "claude-home"
    temporary = tmp_path / "control" / "critic-tmp"
    parent = build_claude_parent_environment(
        token,
        config_dir=config,
        tmp_dir=temporary,
        ambient=hostile_ambient,
    )

    assert parent["CLAUDE_CODE_OAUTH_TOKEN"] == token
    assert parent["CLAUDE_CODE_SUBPROCESS_ENV_SCRUB"] == "1"
    assert parent["HOME"] == "/runtime/home"
    assert not (set(hostile_ambient) - {"HOME", "CLAUDE_CODE_OAUTH_TOKEN"}) & set(parent)
    assert "ambient-claude" not in parent.values()
    child = scrub_claude_child_environment(parent)
    assert child["CLAUDE_CODE_SUBPROCESS_ENV_SCRUB"] == "1"
    assert "CLAUDE_CODE_OAUTH_TOKEN" not in child
    assert token not in child.values()


@pytest.mark.parametrize(
    "identifier",
    ["../escape", "slash/name", ".", "..", " space", "name\n", "x" * 129],
)
def test_identifier_derived_credential_roots_reject_path_escapes(
    tmp_path: Path, identifier: str
) -> None:
    with pytest.raises(ValueError, match="safe identifier"):
        codex_credential_root(identifier, state_home=tmp_path)
    with pytest.raises(ValueError, match="safe identifier"):
        claude_credential_root(identifier, state_home=tmp_path)


def test_xdg_state_resolution_rejects_relative_roots_and_never_expands_tilde() -> None:
    with pytest.raises(ValueError, match="absolute"):
        xdg_state_home(environ={"XDG_STATE_HOME": "relative", "HOME": "/home/user"})
    with pytest.raises(ValueError, match="absolute"):
        xdg_state_home(environ={"XDG_STATE_HOME": "~/state", "HOME": "/home/user"})
    assert xdg_state_home(environ={"HOME": "/home/user"}) == Path(
        "/home/user/.local/state"
    )
