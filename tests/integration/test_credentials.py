from __future__ import annotations

import fcntl
import hashlib
import json
import os
import pwd
import stat
import threading
import time
from pathlib import Path

import pytest

import agent_loop.credentials as credential_module
from agent_loop.credentials import (
    ClaudeCredentialTransaction,
    CodexCredentialTransaction,
    CombinedCredentialTransaction,
    auto_enroll_default_cli_credentials,
    build_claude_parent_environment,
    claude_cli_credentials_enrolled,
    claude_credential_root,
    claude_setup_token_enrolled,
    codex_credential_root,
    codex_file_auth_enrolled,
    enroll_claude_cli_credentials,
    enroll_claude_setup_token,
    enroll_codex_file_auth,
    load_claude_setup_token,
    repair_default_cli_credentials,
    scrub_claude_child_environment,
    xdg_state_home,
)
from agent_loop.errors import AgentLoopError, ExitCode, StopReason, fail
from agent_loop.filesystem import ConfinedFilesystem

OLD_AUTH = b'{"access_token":"old-secret"}'
NEW_AUTH = b'{"access_token":"new-secret"}'
OTHER_AUTH = b'{"access_token":"other-secret"}'
CLAUDE_CREDENTIALS = json.dumps(
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
    },
    separators=(",", ":"),
).encode()


def valid_auth(data: bytes) -> bool:
    try:
        value = json.loads(data)
    except UnicodeDecodeError, json.JSONDecodeError:
        return False
    return isinstance(value, dict) and isinstance(value.get("access_token"), str)


def codex_generation(secret: str, refreshed: str) -> bytes:
    return json.dumps(
        {"access_token": secret, "last_refresh": refreshed},
        separators=(",", ":"),
    ).encode()


def newer_claude_generation() -> bytes:
    value = json.loads(CLAUDE_CREDENTIALS)
    oauth = value["claudeAiOauth"]
    oauth["accessToken"] = "claude-newer-access-secret"
    oauth["refreshToken"] = "claude-newer-refresh-secret"
    oauth["expiresAt"] += 1000
    oauth["refreshTokenExpiresAt"] += 1000
    return json.dumps(value, separators=(",", ":")).encode()


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


def test_one_time_enrollment_imports_private_cli_auth_and_is_idempotent(
    tmp_path: Path,
) -> None:
    ambient = tmp_path / "ambient" / "codex" / "auth.json"
    write_private(ambient, OLD_AUTH)

    first = enroll_codex_file_auth(
        source_auth_path=ambient,
        auth_parser=valid_auth,
        state_home=tmp_path / "state",
    )
    second = enroll_codex_file_auth(
        source_auth_path=ambient,
        auth_parser=valid_auth,
        state_home=tmp_path / "state",
    )

    assert first.credential_id == "default" and first.installed is True
    assert second.credential_id == "default" and second.installed is False
    assert codex_file_auth_enrolled(
        auth_parser=valid_auth,
        state_home=tmp_path / "state",
    )
    durable = codex_credential_root("default", state_home=tmp_path / "state") / "auth.json"
    assert durable.read_bytes() == OLD_AUTH
    assert stat.S_IMODE(durable.stat().st_mode) == 0o600


def test_one_time_enrollment_never_silently_replaces_an_account(tmp_path: Path) -> None:
    first = tmp_path / "ambient" / "first" / "auth.json"
    second = tmp_path / "ambient" / "second" / "auth.json"
    write_private(first, OLD_AUTH)
    write_private(second, OTHER_AUTH)
    enroll_codex_file_auth(
        source_auth_path=first,
        auth_parser=valid_auth,
        state_home=tmp_path / "state",
    )

    with pytest.raises(AgentLoopError) as caught:
        enroll_codex_file_auth(
            source_auth_path=second,
            auth_parser=valid_auth,
            state_home=tmp_path / "state",
        )

    assert caught.value.reason is StopReason.CREDENTIAL_STATE_CONFLICT
    assert "old-secret" not in str(caught.value) and "other-secret" not in str(caught.value)


def test_one_time_claude_token_enrollment_is_private_and_prompt_free_afterward(
    tmp_path: Path,
) -> None:
    first = enroll_claude_setup_token(
        "one-year-inference-only-token",
        state_home=tmp_path,
    )
    second = enroll_claude_setup_token(
        "one-year-inference-only-token\n",
        state_home=tmp_path,
    )

    assert first.installed is True and second.installed is False
    assert claude_setup_token_enrolled(state_home=tmp_path)
    assert load_claude_setup_token("default", state_home=tmp_path) == (
        "one-year-inference-only-token"
    )


def test_existing_claude_login_import_is_refresh_persistent_and_locked(tmp_path: Path) -> None:
    credential_id = "standalone-claude"
    source = tmp_path / "ambient" / ".claude" / ".credentials.json"
    write_private(source, CLAUDE_CREDENTIALS)
    enrolled = enroll_claude_cli_credentials(
        credential_id,
        source_credentials_path=source,
        state_home=tmp_path / "state",
    )
    assert enrolled.installed is True
    assert claude_cli_credentials_enrolled(credential_id, state_home=tmp_path / "state")

    transaction = ClaudeCredentialTransaction.acquire(
        credential_id,
        "run-claude",
        state_home=tmp_path / "state",
    )
    try:
        root = claude_credential_root(credential_id, state_home=tmp_path / "state")
        competing_fd = os.open(root / "lock", os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(competing_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(competing_fd)
        assert (transaction.claude_home / ".credentials.json").read_bytes() == (CLAUDE_CREDENTIALS)
        refreshed = CLAUDE_CREDENTIALS.replace(b"claude-access-secret", b"claude-new-access-secret")
        write_private(transaction.claude_home / ".credentials.json", refreshed)
        assert transaction.reconcile_after_turn() is True
        assert set(transaction.auth_generations) == {CLAUDE_CREDENTIALS, refreshed}
        transaction.finalize_reconciled()
    finally:
        transaction.close()

    durable = (
        claude_credential_root(credential_id, state_home=tmp_path / "state") / "credentials.json"
    )
    assert durable.read_bytes() == refreshed


def test_normal_run_auto_enrolls_absent_defaults_once_and_never_replaces_them(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    write_private(home / ".codex" / "auth.json", OLD_AUTH)
    write_private(home / ".claude" / ".credentials.json", CLAUDE_CREDENTIALS)
    state = tmp_path / "state"
    monkeypatch.setattr(credential_module, "_authorized_passwd_home", lambda: home)

    first = auto_enroll_default_cli_credentials(
        codex_credential_id="default",
        claude_credential_id="default",
        codex_auth_parser=valid_auth,
        state_home=state,
    )
    assert first.codex is not None and first.codex.installed is True
    assert first.claude is not None and first.claude.installed is True

    write_private(home / ".codex" / "auth.json", OTHER_AUTH)
    changed_claude = CLAUDE_CREDENTIALS.replace(b"claude-access-secret", b"ambient-account-changed")
    write_private(home / ".claude" / ".credentials.json", changed_claude)
    second = auto_enroll_default_cli_credentials(
        codex_credential_id="default",
        claude_credential_id="default",
        codex_auth_parser=valid_auth,
        state_home=state,
    )

    assert second.codex is None and second.claude is None
    assert (codex_credential_root("default", state_home=state) / "auth.json").read_bytes() == (
        OLD_AUTH
    )
    assert (
        claude_credential_root("default", state_home=state) / "credentials.json"
    ).read_bytes() == CLAUDE_CREDENTIALS
    metadata = state / "agent-loop" / "credentials" / "default-profile.json"
    assert stat.S_IMODE(metadata.stat().st_mode) == 0o600


def test_default_pair_silently_adopts_strictly_newer_standard_codex_login(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old = codex_generation("old-secret", "2026-07-01T00:00:00.000000000Z")
    newer = codex_generation("new-secret", "2026-07-02T00:00:00.000000000Z")
    home = tmp_path / "home"
    write_private(home / ".codex" / "auth.json", old)
    write_private(home / ".claude" / ".credentials.json", CLAUDE_CREDENTIALS)
    state = tmp_path / "state"
    monkeypatch.setattr(credential_module, "_authorized_passwd_home", lambda: home)
    auto_enroll_default_cli_credentials(
        codex_credential_id="default",
        claude_credential_id="default",
        codex_auth_parser=valid_auth,
        state_home=state,
    )
    write_private(home / ".codex" / "auth.json", newer)

    transaction = _acquire_default_pair(state, "silent-codex-relogin")
    try:
        transaction.finalize_reconciled()
    finally:
        transaction.close()

    assert (codex_credential_root("default", state_home=state) / "auth.json").read_bytes() == newer
    assert (
        claude_credential_root("default", state_home=state) / "credentials.json"
    ).read_bytes() == CLAUDE_CREDENTIALS


def test_default_pair_recovers_unchanged_pending_run_with_newer_standard_login(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old = codex_generation("old-secret", "2026-07-01T00:00:00Z")
    newer = codex_generation("new-secret", "2026-07-03T00:00:00Z")
    home = tmp_path / "home"
    write_private(home / ".codex" / "auth.json", old)
    write_private(home / ".claude" / ".credentials.json", CLAUDE_CREDENTIALS)
    state = tmp_path / "state"
    monkeypatch.setattr(credential_module, "_authorized_passwd_home", lambda: home)
    auto_enroll_default_cli_credentials(
        codex_credential_id="default",
        claude_credential_id="default",
        codex_auth_parser=valid_auth,
        state_home=state,
    )
    interrupted = _acquire_default_pair(state, "failed-auth-run")
    interrupted.close()
    write_private(home / ".codex" / "auth.json", newer)

    recovered = _acquire_default_pair(state, "after-vendor-login")
    try:
        recovered.finalize_reconciled()
    finally:
        recovered.close()

    assert (codex_credential_root("default", state_home=state) / "auth.json").read_bytes() == newer


def test_stale_standard_login_never_reverts_newer_private_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = codex_generation("private-new", "2026-07-04T00:00:00Z")
    stale = codex_generation("ambient-stale", "2026-07-03T00:00:00Z")
    home = tmp_path / "home"
    write_private(home / ".codex" / "auth.json", private)
    write_private(home / ".claude" / ".credentials.json", CLAUDE_CREDENTIALS)
    state = tmp_path / "state"
    monkeypatch.setattr(credential_module, "_authorized_passwd_home", lambda: home)
    auto_enroll_default_cli_credentials(
        codex_credential_id="default",
        claude_credential_id="default",
        codex_auth_parser=valid_auth,
        state_home=state,
    )
    write_private(home / ".codex" / "auth.json", stale)

    transaction = _acquire_default_pair(state, "stale-source")
    try:
        transaction.finalize_reconciled()
    finally:
        transaction.close()

    assert (
        codex_credential_root("default", state_home=state) / "auth.json"
    ).read_bytes() == private


def test_failed_newer_source_probe_restores_working_private_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old = codex_generation("working-private", "2026-07-01T00:00:00Z")
    unusable = codex_generation("unusable-source", "2026-07-05T00:00:00Z")
    home = tmp_path / "home"
    write_private(home / ".codex" / "auth.json", old)
    write_private(home / ".claude" / ".credentials.json", CLAUDE_CREDENTIALS)
    state = tmp_path / "state"
    monkeypatch.setattr(credential_module, "_authorized_passwd_home", lambda: home)
    auto_enroll_default_cli_credentials(
        codex_credential_id="default",
        claude_credential_id="default",
        codex_auth_parser=valid_auth,
        state_home=state,
    )
    write_private(home / ".codex" / "auth.json", unusable)

    transaction = CombinedCredentialTransaction.acquire(
        "default",
        "default",
        "source-probe-fallback",
        codex_auth_parser=valid_auth,
        codex_auth_probe=lambda codex_home: (codex_home / "auth.json").read_bytes() == old,
        claude_auth_probe=lambda claude_home: credential_module.parse_claude_cli_credentials(
            (claude_home / ".credentials.json").read_bytes()
        ),
        state_home=state,
    )
    try:
        transaction.finalize_reconciled()
    finally:
        transaction.close()

    assert (codex_credential_root("default", state_home=state) / "auth.json").read_bytes() == old


def test_default_pair_silently_adopts_strictly_newer_standard_claude_login(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    codex = codex_generation("codex-secret", "2026-07-01T00:00:00Z")
    newer_claude = newer_claude_generation()
    home = tmp_path / "home"
    write_private(home / ".codex" / "auth.json", codex)
    write_private(home / ".claude" / ".credentials.json", CLAUDE_CREDENTIALS)
    state = tmp_path / "state"
    monkeypatch.setattr(credential_module, "_authorized_passwd_home", lambda: home)
    auto_enroll_default_cli_credentials(
        codex_credential_id="default",
        claude_credential_id="default",
        codex_auth_parser=valid_auth,
        state_home=state,
    )
    write_private(home / ".claude" / ".credentials.json", newer_claude)

    transaction = _acquire_default_pair(state, "silent-claude-relogin")
    try:
        transaction.finalize_reconciled()
    finally:
        transaction.close()

    assert (
        claude_credential_root("default", state_home=state) / "credentials.json"
    ).read_bytes() == newer_claude


@pytest.mark.parametrize("pending_vendor", ("codex", "claude"))
def test_newer_standard_login_recovers_one_sided_unchanged_pending_acquisition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pending_vendor: str,
) -> None:
    old_codex = codex_generation("old-secret", "2026-07-01T00:00:00Z")
    newer_codex = codex_generation("new-secret", "2026-07-02T00:00:00Z")
    newer_claude = newer_claude_generation()
    home = tmp_path / "home"
    write_private(home / ".codex" / "auth.json", old_codex)
    write_private(home / ".claude" / ".credentials.json", CLAUDE_CREDENTIALS)
    state = tmp_path / "state"
    monkeypatch.setattr(credential_module, "_authorized_passwd_home", lambda: home)
    auto_enroll_default_cli_credentials(
        codex_credential_id="default",
        claude_credential_id="default",
        codex_auth_parser=valid_auth,
        state_home=state,
    )
    pending: CodexCredentialTransaction | ClaudeCredentialTransaction
    if pending_vendor == "codex":
        pending = CodexCredentialTransaction._acquire_for_combined(
            "default",
            "partial-source-adoption",
            auth_parser=valid_auth,
            auth_probe=passing_probe,
            state_home=state,
        )
        write_private(home / ".codex" / "auth.json", newer_codex)
    else:
        pending = ClaudeCredentialTransaction._acquire_for_combined(
            "default",
            "partial-source-adoption",
            state_home=state,
        )
        write_private(home / ".claude" / ".credentials.json", newer_claude)
    pending.close()

    recovered = _acquire_default_pair(state, "after-partial-source-adoption")
    try:
        recovered.finalize_reconciled()
    finally:
        recovered.close()

    expected_codex = newer_codex if pending_vendor == "codex" else old_codex
    expected_claude = newer_claude if pending_vendor == "claude" else CLAUDE_CREDENTIALS
    assert (codex_credential_root("default", state_home=state) / "auth.json").read_bytes() == (
        expected_codex
    )
    assert (
        claude_credential_root("default", state_home=state) / "credentials.json"
    ).read_bytes() == expected_claude


def test_newer_standard_login_supersedes_an_older_changed_paired_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old = codex_generation("old-secret", "2026-07-01T00:00:00Z")
    failed_pending = codex_generation("failed-pending", "2026-07-02T00:00:00Z")
    newer = codex_generation("new-login", "2026-07-03T00:00:00Z")
    home = tmp_path / "home"
    write_private(home / ".codex" / "auth.json", old)
    write_private(home / ".claude" / ".credentials.json", CLAUDE_CREDENTIALS)
    state = tmp_path / "state"
    monkeypatch.setattr(credential_module, "_authorized_passwd_home", lambda: home)
    auto_enroll_default_cli_credentials(
        codex_credential_id="default",
        claude_credential_id="default",
        codex_auth_parser=valid_auth,
        state_home=state,
    )
    interrupted = _acquire_default_pair(state, "failed-paired-candidate")
    write_private(interrupted.codex.candidate_auth_path, failed_pending)
    interrupted.close()
    write_private(home / ".codex" / "auth.json", newer)

    recovered = CombinedCredentialTransaction.acquire(
        "default",
        "default",
        "newer-than-pending",
        codex_auth_parser=valid_auth,
        codex_auth_probe=lambda codex_home: (codex_home / "auth.json").read_bytes() == newer,
        claude_auth_probe=lambda claude_home: credential_module.parse_claude_cli_credentials(
            (claude_home / ".credentials.json").read_bytes()
        ),
        state_home=state,
    )
    try:
        recovered.finalize_reconciled()
    finally:
        recovered.close()

    assert (codex_credential_root("default", state_home=state) / "auth.json").read_bytes() == newer


def test_interrupted_initial_source_probe_never_stages_or_displaces_durable_login(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old = codex_generation("working-private", "2026-07-01T00:00:00Z")
    newer = codex_generation("interrupted-source", "2026-07-02T00:00:00Z")
    home = tmp_path / "home"
    write_private(home / ".codex" / "auth.json", old)
    write_private(home / ".claude" / ".credentials.json", CLAUDE_CREDENTIALS)
    state = tmp_path / "state"
    monkeypatch.setattr(credential_module, "_authorized_passwd_home", lambda: home)
    auto_enroll_default_cli_credentials(
        codex_credential_id="default",
        claude_credential_id="default",
        codex_auth_parser=valid_auth,
        state_home=state,
    )
    write_private(home / ".codex" / "auth.json", newer)

    def interrupt_source_probe(codex_home: Path) -> bool:
        if codex_home.name == "source-probe-codex":
            raise KeyboardInterrupt
        return (codex_home / "auth.json").read_bytes() == old

    with pytest.raises(KeyboardInterrupt):
        CombinedCredentialTransaction.acquire(
            "default",
            "default",
            "interrupted-source-probe",
            codex_auth_parser=valid_auth,
            codex_auth_probe=interrupt_source_probe,
            claude_auth_probe=lambda claude_home: credential_module.parse_claude_cli_credentials(
                (claude_home / ".credentials.json").read_bytes()
            ),
            state_home=state,
        )

    pending_home = (
        codex_credential_root("default", state_home=state)
        / "transactions"
        / "interrupted-source-probe"
    )
    assert (pending_home / "codex-home" / "auth.json").read_bytes() == old
    assert not (pending_home / "source-probe-codex").exists()

    recovered = CombinedCredentialTransaction.acquire(
        "default",
        "default",
        "after-interrupted-source-probe",
        codex_auth_parser=valid_auth,
        codex_auth_probe=lambda codex_home: (codex_home / "auth.json").read_bytes() == old,
        claude_auth_probe=lambda claude_home: credential_module.parse_claude_cli_credentials(
            (claude_home / ".credentials.json").read_bytes()
        ),
        state_home=state,
    )
    try:
        recovered.finalize_reconciled()
    finally:
        recovered.close()

    assert (codex_credential_root("default", state_home=state) / "auth.json").read_bytes() == old


def test_default_bootstrap_rejects_partial_pair_without_creating_other_side(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    write_private(home / ".codex" / "auth.json", OLD_AUTH)
    write_private(home / ".claude" / ".credentials.json", CLAUDE_CREDENTIALS)
    state = tmp_path / "state"
    provision_codex(state, "default")
    monkeypatch.setattr(credential_module, "_authorized_passwd_home", lambda: home)

    with pytest.raises(AgentLoopError) as caught:
        auto_enroll_default_cli_credentials(
            codex_credential_id="default",
            claude_credential_id="default",
            codex_auth_parser=valid_auth,
            state_home=state,
        )

    assert caught.value.reason is StopReason.CREDENTIAL_STATE_CONFLICT
    assert not claude_credential_root("default", state_home=state).exists()
    assert not (state / "agent-loop" / "credentials" / "default-profile.json").exists()


def test_default_bootstrap_rolls_back_both_sides_when_second_install_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    write_private(home / ".codex" / "auth.json", OLD_AUTH)
    write_private(home / ".claude" / ".credentials.json", CLAUDE_CREDENTIALS)
    state = tmp_path / "state"
    monkeypatch.setattr(credential_module, "_authorized_passwd_home", lambda: home)
    original = ConfinedFilesystem.atomic_write

    def fail_claude(
        filesystem: ConfinedFilesystem,
        path: bytes,
        data: bytes,
        **kwargs: object,
    ) -> None:
        if path == b"credentials.json":
            raise fail(StopReason.CREDENTIAL_REFRESH_FAILURE, "injected second-side failure")
        original(filesystem, path, data, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(ConfinedFilesystem, "atomic_write", fail_claude)
    with pytest.raises(AgentLoopError) as caught:
        auto_enroll_default_cli_credentials(
            codex_credential_id="default",
            claude_credential_id="default",
            codex_auth_parser=valid_auth,
            state_home=state,
        )

    assert caught.value.reason is StopReason.CREDENTIAL_REFRESH_FAILURE
    assert not codex_credential_root("default", state_home=state).exists()
    assert not claude_credential_root("default", state_home=state).exists()
    assert not (state / "agent-loop" / "credentials" / "default-profile.json").exists()


def test_default_repair_completes_valid_partial_pair_and_writes_profile_metadata(
    tmp_path: Path,
) -> None:
    codex_source = tmp_path / "sources" / "codex.json"
    claude_source = tmp_path / "sources" / "claude.json"
    write_private(codex_source, OTHER_AUTH)
    write_private(claude_source, CLAUDE_CREDENTIALS)
    state = tmp_path / "state"
    provision_codex(state, "default", OLD_AUTH)

    result = repair_default_cli_credentials(
        codex_auth_parser=valid_auth,
        state_home=state,
        codex_source_path=codex_source,
        claude_source_path=claude_source,
    )

    assert result.codex is not None and result.codex.installed is True
    assert result.claude is not None and result.claude.installed is True
    assert (codex_credential_root("default", state_home=state) / "auth.json").read_bytes() == (
        OTHER_AUTH
    )
    assert (
        claude_credential_root("default", state_home=state) / "credentials.json"
    ).read_bytes() == CLAUDE_CREDENTIALS
    metadata = state / "agent-loop" / "credentials" / "default-profile.json"
    assert stat.S_IMODE(metadata.stat().st_mode) == 0o600


def test_default_repair_refuses_active_account_transaction(tmp_path: Path) -> None:
    codex_source = tmp_path / "sources" / "codex.json"
    claude_source = tmp_path / "sources" / "claude.json"
    write_private(codex_source, OTHER_AUTH)
    write_private(claude_source, CLAUDE_CREDENTIALS)
    state = tmp_path / "state"
    root = provision_codex(state, "default", OLD_AUTH)
    (root / "transactions" / "active-run").mkdir(mode=0o700, parents=True)
    with pytest.raises(AgentLoopError) as caught:
        repair_default_cli_credentials(
            codex_auth_parser=valid_auth,
            state_home=state,
            codex_source_path=codex_source,
            claude_source_path=claude_source,
        )

    assert caught.value.reason is StopReason.CREDENTIAL_STATE_CONFLICT
    assert (codex_credential_root("default", state_home=state) / "auth.json").read_bytes() == (
        OLD_AUTH
    )
    assert not claude_credential_root("default", state_home=state).exists()


def test_default_source_discovery_ignores_inherited_auth_path_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    passwd_home = tmp_path / "passwd-home"
    malicious_home = tmp_path / "redirected-home"
    monkeypatch.setattr(
        pwd,
        "getpwuid",
        lambda _uid: type("Passwd", (), {"pw_dir": str(passwd_home)})(),
    )
    monkeypatch.setenv("HOME", str(malicious_home))
    monkeypatch.setenv("CODEX_HOME", str(malicious_home / "codex"))
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(malicious_home / "claude"))

    assert credential_module.active_codex_auth_path() == passwd_home / ".codex" / "auth.json"
    assert credential_module.active_claude_credentials_path() == (
        passwd_home / ".claude" / ".credentials.json"
    )


def _acquire_default_pair(state: Path, run_id: str) -> CombinedCredentialTransaction:
    return CombinedCredentialTransaction.acquire(
        "default",
        "default",
        run_id,
        codex_auth_parser=valid_auth,
        codex_auth_probe=passing_probe,
        claude_auth_probe=lambda home: credential_module.parse_claude_cli_credentials(
            (home / ".credentials.json").read_bytes()
        ),
        state_home=state,
        lock_timeout_seconds=0.1,
    )


@pytest.mark.parametrize(
    ("vendor", "status_command", "login_command"),
    (
        ("codex", "codex login status", "codex login"),
        ("claude", "claude auth status", "claude auth login"),
    ),
)
def test_unconfirmed_local_auth_probe_recommends_status_before_login(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    vendor: str,
    status_command: str,
    login_command: str,
) -> None:
    home = tmp_path / "home"
    write_private(home / ".codex" / "auth.json", OLD_AUTH)
    write_private(home / ".claude" / ".credentials.json", CLAUDE_CREDENTIALS)
    state = tmp_path / "state"
    monkeypatch.setattr(credential_module, "_authorized_passwd_home", lambda: home)
    auto_enroll_default_cli_credentials(
        codex_credential_id="default",
        claude_credential_id="default",
        codex_auth_parser=valid_auth,
        state_home=state,
    )

    with pytest.raises(AgentLoopError) as caught:
        CombinedCredentialTransaction.acquire(
            "default",
            "default",
            f"failed-{vendor}-probe",
            codex_auth_parser=valid_auth,
            codex_auth_probe=(lambda _home: vendor != "codex"),
            claude_auth_probe=(lambda _home: vendor != "claude"),
            state_home=state,
            lock_timeout_seconds=0.1,
        )

    assert caught.value.reason is StopReason.CREDENTIAL_REFRESH_FAILURE
    assert f"Run `{status_command}`" in caught.value.detail
    assert f"only if it reports signed out, run `{login_command}`" in caught.value.detail
    assert "No `agent-loop auth` command is required." in caught.value.detail


def test_default_vendor_transactions_require_combined_pair_authority(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="combined default profile"):
        CodexCredentialTransaction.acquire(
            "default",
            "standalone-codex",
            auth_parser=valid_auth,
            auth_probe=passing_probe,
            state_home=tmp_path,
        )
    with pytest.raises(ValueError, match="combined default profile"):
        ClaudeCredentialTransaction.acquire(
            "default",
            "standalone-claude",
            state_home=tmp_path,
        )
    assert not (tmp_path / "agent-loop").exists()


def test_combined_default_acquisition_serializes_the_complete_pair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    write_private(home / ".codex" / "auth.json", OLD_AUTH)
    write_private(home / ".claude" / ".credentials.json", CLAUDE_CREDENTIALS)
    state = tmp_path / "state"
    monkeypatch.setattr(credential_module, "_authorized_passwd_home", lambda: home)
    auto_enroll_default_cli_credentials(
        codex_credential_id="default",
        claude_credential_id="default",
        codex_auth_parser=valid_auth,
        state_home=state,
    )
    first = _acquire_default_pair(state, "first-run")
    observed: list[AgentLoopError] = []

    def competing_acquire() -> None:
        try:
            _acquire_default_pair(state, "competing-run")
        except AgentLoopError as exc:
            observed.append(exc)

    contender = threading.Thread(target=competing_acquire)
    contender.start()
    contender.join(timeout=2)
    try:
        assert not contender.is_alive()
        assert len(observed) == 1
        assert observed[0].reason is StopReason.CREDENTIAL_STATE_CONFLICT
    finally:
        first.finalize_reconciled()
        first.close()

    after_release = _acquire_default_pair(state, "after-release")
    after_release.finalize_reconciled()
    after_release.close()


def test_combined_live_style_refresh_completion_preserves_ready_pair_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    write_private(home / ".codex" / "auth.json", OLD_AUTH)
    write_private(home / ".claude" / ".credentials.json", CLAUDE_CREDENTIALS)
    state = tmp_path / "state"
    monkeypatch.setattr(credential_module, "_authorized_passwd_home", lambda: home)
    auto_enroll_default_cli_credentials(
        codex_credential_id="default",
        claude_credential_id="default",
        codex_auth_parser=valid_auth,
        state_home=state,
    )
    refreshed_claude = CLAUDE_CREDENTIALS.replace(
        b"claude-access-secret",
        b"claude-live-access-secret",
    )

    transaction = _acquire_default_pair(state, "live-style")
    try:
        write_private(transaction.codex.candidate_auth_path, NEW_AUTH)
        write_private(transaction.claude_home / ".credentials.json", refreshed_claude)
        assert transaction.reconcile_after_turn() is True
        transaction.finalize_reconciled()
    finally:
        transaction.close()

    assert (
        credential_module.default_cli_credential_pair_state(
            codex_auth_parser=valid_auth,
            state_home=state,
        )
        == "ready"
    )
    assert (codex_credential_root("default", state_home=state) / "auth.json").read_bytes() == (
        NEW_AUTH
    )
    assert (
        claude_credential_root("default", state_home=state) / "credentials.json"
    ).read_bytes() == refreshed_claude


@pytest.mark.parametrize(
    "crash_phase",
    (
        "after_first_provider",
        "after_second_provider",
        "after_metadata",
        "after_cleanup",
    ),
)
def test_default_pair_journal_rolls_forward_every_commit_crash_window(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    crash_phase: str,
) -> None:
    home = tmp_path / "home"
    write_private(home / ".codex" / "auth.json", OLD_AUTH)
    write_private(home / ".claude" / ".credentials.json", CLAUDE_CREDENTIALS)
    state = tmp_path / "state"
    monkeypatch.setattr(credential_module, "_authorized_passwd_home", lambda: home)
    auto_enroll_default_cli_credentials(
        codex_credential_id="default",
        claude_credential_id="default",
        codex_auth_parser=valid_auth,
        state_home=state,
    )
    refreshed_claude = CLAUDE_CREDENTIALS.replace(
        b"claude-access-secret",
        b"claude-journal-access-secret",
    )
    crashed = _acquire_default_pair(state, "journaled-run")
    write_private(crashed.codex.candidate_auth_path, NEW_AUTH)
    write_private(crashed.claude_home / ".credentials.json", refreshed_claude)

    def interrupt(selected_phase: str) -> None:
        if selected_phase == crash_phase:
            raise KeyboardInterrupt

    try:
        with monkeypatch.context() as fault:
            fault.setattr(credential_module, "_pair_transition_checkpoint", interrupt)
            with pytest.raises(KeyboardInterrupt):
                crashed.reconcile_after_turn()
    finally:
        crashed.close()

    transition_path = state / "agent-loop" / "credentials" / "default-profile-transition.json"
    assert transition_path.exists()
    assert stat.S_IMODE(transition_path.stat().st_mode) == 0o600
    assert (
        credential_module.default_cli_credential_pair_state(
            codex_auth_parser=valid_auth,
            state_home=state,
        )
        == "recovery_pending"
    )
    # Ordinary preflight must preserve the journal for Combined acquisition,
    # not misclassify a mixed durable pair as a manual-repair condition.
    assert auto_enroll_default_cli_credentials(
        codex_credential_id="default",
        claude_credential_id="default",
        codex_auth_parser=valid_auth,
        state_home=state,
    ) == credential_module.DefaultCredentialEnrollment(None, None)

    recovered = _acquire_default_pair(state, f"recover-{crash_phase}")
    try:
        recovered.finalize_reconciled()
    finally:
        recovered.close()

    assert not transition_path.exists()
    assert (codex_credential_root("default", state_home=state) / "auth.json").read_bytes() == (
        NEW_AUTH
    )
    assert (
        claude_credential_root("default", state_home=state) / "credentials.json"
    ).read_bytes() == refreshed_claude
    assert (
        credential_module.default_cli_credential_pair_state(
            codex_auth_parser=valid_auth,
            state_home=state,
        )
        == "ready"
    )


def test_initial_status_probe_refreshes_commit_through_the_pair_journal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    write_private(home / ".codex" / "auth.json", OLD_AUTH)
    write_private(home / ".claude" / ".credentials.json", CLAUDE_CREDENTIALS)
    state = tmp_path / "state"
    monkeypatch.setattr(credential_module, "_authorized_passwd_home", lambda: home)
    auto_enroll_default_cli_credentials(
        codex_credential_id="default",
        claude_credential_id="default",
        codex_auth_parser=valid_auth,
        state_home=state,
    )
    refreshed_claude = CLAUDE_CREDENTIALS.replace(
        b"claude-access-secret",
        b"claude-probe-access-secret",
    )

    def codex_probe(control_home: Path) -> bool:
        write_private(control_home / "auth.json", NEW_AUTH)
        return True

    def claude_probe(control_home: Path) -> bool:
        write_private(control_home / ".credentials.json", refreshed_claude)
        return True

    transaction = CombinedCredentialTransaction.acquire(
        "default",
        "default",
        "probe-refresh",
        codex_auth_parser=valid_auth,
        codex_auth_probe=codex_probe,
        claude_auth_probe=claude_probe,
        state_home=state,
        lock_timeout_seconds=0.1,
    )
    try:
        transaction.finalize_reconciled()
    finally:
        transaction.close()

    assert (codex_credential_root("default", state_home=state) / "auth.json").read_bytes() == (
        NEW_AUTH
    )
    assert (
        claude_credential_root("default", state_home=state) / "credentials.json"
    ).read_bytes() == refreshed_claude
    assert (
        credential_module.default_cli_credential_pair_state(
            codex_auth_parser=valid_auth,
            state_home=state,
        )
        == "ready"
    )


def test_default_pair_journal_fails_closed_when_a_candidate_witness_disappears(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    write_private(home / ".codex" / "auth.json", OLD_AUTH)
    write_private(home / ".claude" / ".credentials.json", CLAUDE_CREDENTIALS)
    state = tmp_path / "state"
    monkeypatch.setattr(credential_module, "_authorized_passwd_home", lambda: home)
    auto_enroll_default_cli_credentials(
        codex_credential_id="default",
        claude_credential_id="default",
        codex_auth_parser=valid_auth,
        state_home=state,
    )
    transaction = _acquire_default_pair(state, "missing-witness")
    write_private(transaction.codex.candidate_auth_path, NEW_AUTH)
    write_private(
        transaction.claude_home / ".credentials.json",
        CLAUDE_CREDENTIALS.replace(b"claude-access-secret", b"missing-witness-secret"),
    )
    candidate_path = transaction.codex.candidate_auth_path

    def interrupt(phase: str) -> None:
        if phase == "after_first_provider":
            raise KeyboardInterrupt

    try:
        with monkeypatch.context() as fault:
            fault.setattr(credential_module, "_pair_transition_checkpoint", interrupt)
            with pytest.raises(KeyboardInterrupt):
                transaction.reconcile_after_turn()
    finally:
        transaction.close()
    candidate_path.unlink()

    assert (
        credential_module.default_cli_credential_pair_state(
            codex_auth_parser=valid_auth,
            state_home=state,
        )
        == "repair_required"
    )

    with pytest.raises(AgentLoopError) as caught:
        _acquire_default_pair(state, "must-not-guess")

    assert caught.value.reason is StopReason.CREDENTIAL_STATE_CONFLICT
    assert "missing or unsafe" in caught.value.detail
    assert (state / "agent-loop" / "credentials" / "default-profile-transition.json").exists()


def test_default_commit_marker_rejects_a_torn_pair_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    write_private(home / ".codex" / "auth.json", OLD_AUTH)
    write_private(home / ".claude" / ".credentials.json", CLAUDE_CREDENTIALS)
    state = tmp_path / "state"
    monkeypatch.setattr(credential_module, "_authorized_passwd_home", lambda: home)
    auto_enroll_default_cli_credentials(
        codex_credential_id="default",
        claude_credential_id="default",
        codex_auth_parser=valid_auth,
        state_home=state,
    )
    write_private(
        codex_credential_root("default", state_home=state) / "auth.json",
        OTHER_AUTH,
    )

    with pytest.raises(AgentLoopError) as caught:
        _acquire_default_pair(state, "torn-pair")

    assert caught.value.reason is StopReason.CREDENTIAL_STATE_CONFLICT
    assert "committed matching generation" in caught.value.detail


@pytest.mark.parametrize(
    ("refresh_codex", "refresh_claude"),
    ((True, False), (False, True), (True, True)),
)
def test_combined_default_crash_recovery_commits_one_validated_pair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    refresh_codex: bool,
    refresh_claude: bool,
) -> None:
    home = tmp_path / "home"
    write_private(home / ".codex" / "auth.json", OLD_AUTH)
    write_private(home / ".claude" / ".credentials.json", CLAUDE_CREDENTIALS)
    state = tmp_path / "state"
    monkeypatch.setattr(credential_module, "_authorized_passwd_home", lambda: home)
    auto_enroll_default_cli_credentials(
        codex_credential_id="default",
        claude_credential_id="default",
        codex_auth_parser=valid_auth,
        state_home=state,
    )
    refreshed_claude = CLAUDE_CREDENTIALS.replace(
        b"claude-access-secret",
        b"claude-recovered-access-secret",
    )
    crashed = _acquire_default_pair(state, "crashed-pair")
    if refresh_codex:
        write_private(crashed.codex.candidate_auth_path, OTHER_AUTH)
    if refresh_claude:
        write_private(
            crashed.claude_home / ".credentials.json",
            refreshed_claude,
        )
    crashed.close()

    recovered = _acquire_default_pair(state, "recovery-run")
    try:
        assert (codex_credential_root("default", state_home=state) / "auth.json").read_bytes() == (
            OTHER_AUTH if refresh_codex else OLD_AUTH
        )
        assert (
            claude_credential_root("default", state_home=state) / "credentials.json"
        ).read_bytes() == (refreshed_claude if refresh_claude else CLAUDE_CREDENTIALS)
        recovered.finalize_reconciled()
    finally:
        recovered.close()

    assert (
        credential_module.default_cli_credential_pair_state(
            codex_auth_parser=valid_auth,
            state_home=state,
        )
        == "ready"
    )


def test_default_pair_status_distinguishes_busy_and_recovery_pending(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    write_private(home / ".codex" / "auth.json", OLD_AUTH)
    write_private(home / ".claude" / ".credentials.json", CLAUDE_CREDENTIALS)
    state = tmp_path / "state"
    monkeypatch.setattr(credential_module, "_authorized_passwd_home", lambda: home)
    auto_enroll_default_cli_credentials(
        codex_credential_id="default",
        claude_credential_id="default",
        codex_auth_parser=valid_auth,
        state_home=state,
    )
    active = _acquire_default_pair(state, "active-run")
    try:
        assert (
            credential_module.default_cli_credential_pair_state(
                codex_auth_parser=valid_auth,
                state_home=state,
            )
            == "busy"
        )
        active.finalize_reconciled()
    finally:
        active.close()

    crashed = _acquire_default_pair(state, "pending-run")
    write_private(
        crashed.claude_home / ".credentials.json",
        CLAUDE_CREDENTIALS.replace(b"claude-access-secret", b"pending-access-secret"),
    )
    crashed.close()
    assert (
        credential_module.default_cli_credential_pair_state(
            codex_auth_parser=valid_auth,
            state_home=state,
        )
        == "recovery_pending"
    )


def test_normal_run_never_auto_enrolls_custom_profile_names(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    write_private(home / ".codex" / "auth.json", OLD_AUTH)
    write_private(home / ".claude" / ".credentials.json", CLAUDE_CREDENTIALS)
    monkeypatch.setattr(credential_module, "_authorized_passwd_home", lambda: home)

    result = auto_enroll_default_cli_credentials(
        codex_credential_id="team-codex",
        claude_credential_id="team-claude",
        codex_auth_parser=valid_auth,
        state_home=tmp_path / "state",
    )

    assert result.codex is None and result.claude is None
    assert not (tmp_path / "state" / "agent-loop" / "credentials").exists()


def test_claude_refresh_survives_interruption_and_is_recovered_under_lock(
    tmp_path: Path,
) -> None:
    credential_id = "crash-claude"
    source = tmp_path / "ambient" / ".claude" / ".credentials.json"
    write_private(source, CLAUDE_CREDENTIALS)
    state = tmp_path / "state"
    enroll_claude_cli_credentials(
        credential_id,
        source_credentials_path=source,
        state_home=state,
    )
    refreshed = CLAUDE_CREDENTIALS.replace(b"claude-access-secret", b"post-crash-access-secret")

    interrupted = ClaudeCredentialTransaction.acquire(
        credential_id,
        "interrupted-run",
        state_home=state,
    )
    write_private(interrupted.claude_home / ".credentials.json", refreshed)
    interrupted.close()

    barriers: list[tuple[str, tuple[bytes, ...]]] = []
    recovered = ClaudeCredentialTransaction.acquire(
        credential_id,
        "next-run",
        state_home=state,
        evidence_barrier=lambda run_id, generations: barriers.append((run_id, generations)),
    )
    try:
        assert (recovered.claude_home / ".credentials.json").read_bytes() == refreshed
        recovered.reconcile_after_turn()
        recovered.finalize_reconciled()
    finally:
        recovered.close()

    durable = claude_credential_root(credential_id, state_home=state) / "credentials.json"
    assert durable.read_bytes() == refreshed
    assert barriers[0] == ("interrupted-run", ())
    assert set(barriers[1][1]) == {CLAUDE_CREDENTIALS, refreshed}


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
        initial_generations = transaction.auth_generations
        assert initial_generations == (OLD_AUTH,)
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
            evidence_barrier=lambda run_id, generations: replayed.append((run_id, generations)),
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
    assert xdg_state_home(environ={"HOME": "/home/user"}) == Path("/home/user/.local/state")
