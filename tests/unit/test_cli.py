import argparse
import json
from pathlib import Path

import pytest

from agent_loop.artifacts import ArtifactStore
from agent_loop.cli import _duration, build_parser, main


def test_cli_exposes_bounded_run_inspection_and_automatic_auth_reuse(
    capsys: pytest.CaptureFixture[str],
) -> None:
    parser = build_parser()
    help_text = parser.format_help()
    assert all(command in help_text for command in ("run", "status", "show", "auth"))
    assert "resume" not in help_text
    parsed = parser.parse_args(["run", "--task", "task.md", "--dry-run"])
    assert parsed.dry_run is True
    assert parsed.codex_credential_id is None
    assert parsed.claude_credential_id is None

    with pytest.raises(SystemExit) as help_exit:
        parser.parse_args(["run", "--help"])
    assert help_exit.value.code == 0
    run_help = " ".join(capsys.readouterr().out.split())
    assert "default reuses the existing Codex CLI login" in run_help
    assert "default reuses the existing Claude CLI login" in run_help


def test_auth_repair_alias_and_reauthentication_are_explicit_and_secret_free(
    capsys: pytest.CaptureFixture[str],
) -> None:
    parser = build_parser()
    parsed = parser.parse_args(["auth", "init", "--repair"])
    assert parsed.replace is True

    assert main(["auth", "reauthenticate", "claude"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output == {
        "after_login": "rerun the original agent-loop command",
        "login_command": "claude auth login",
        "status_command": "claude auth status",
        "note": (
            "Routine runs need no agent-loop auth command. Use the vendor login only if its "
            "status command confirms you are signed out, then rerun the failed agent-loop "
            "command. The newer standard login is adopted automatically under the credential "
            "locks; no import or repair step is required."
        ),
        "vendor": "claude",
    }
    assert "token" not in json.dumps(output).lower()


def test_auth_init_cannot_skip_both_providers(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert (
        main(
            [
                "--state-home",
                str(tmp_path),
                "auth",
                "init",
                "--skip-codex",
                "--skip-claude",
            ]
        )
        == 18
    )
    assert "cannot skip both" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("skip_flag", "message"),
    (
        ("--skip-codex", "single-provider Claude import requires a non-default"),
        ("--skip-claude", "single-provider Codex import requires a non-default"),
    ),
)
def test_auth_init_cannot_mutate_one_side_of_the_default_pair(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    skip_flag: str,
    message: str,
) -> None:
    assert main(["--state-home", str(tmp_path), "auth", "init", skip_flag]) == 18
    assert message in capsys.readouterr().err


def test_absent_default_login_error_does_not_require_a_redundant_auth_repair(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    missing = tmp_path / "missing-codex-auth.json"
    assert (
        main(
            [
                "--state-home",
                str(tmp_path / "state"),
                "auth",
                "init",
                "--codex-auth",
                str(missing),
            ]
        )
        == 17
    )
    error = capsys.readouterr().err
    assert "run `codex login` if needed, then retry" in error
    assert "auth init --repair" not in error


def test_duration_parser_is_bounded() -> None:
    assert _duration("45m") == 2700
    assert _duration("2h") == 7200
    with pytest.raises(argparse.ArgumentTypeError):
        _duration("0s")


def test_status_and_show_read_private_artifacts(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = tmp_path / "state"
    root = state / "agent-loop" / "runs" / "run-1"
    with ArtifactStore.create(root) as artifacts:
        artifacts.write_json(
            "artifacts/run.json",
            {
                "run_id": "run-1",
                "status": "stopped",
                "source_revision": "a" * 40,
                "current_round": 0,
                "max_rounds": 3,
                "current_subject_fingerprint": "b" * 64,
                "stop_reason": "round_cap_reached",
                "exit_code": 10,
            },
        )
    assert main(["--state-home", str(state), "status", "run-1"]) == 0
    assert '"exit_code": 10' in capsys.readouterr().out
    assert main(["--state-home", str(state), "show", "run-1"]) == 0
    assert '"run_id": "run-1"' in capsys.readouterr().out


def test_invalid_run_id_fails_without_path_traversal(tmp_path: Path) -> None:
    assert main(["--state-home", str(tmp_path), "status", "../escape"]) == 18


def test_auth_init_reuses_existing_cli_login_and_never_prints_tokens(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import agent_loop.workflow as workflow

    codex = tmp_path / "codex" / "auth.json"
    codex.parent.mkdir(mode=0o700)
    codex.write_bytes(b'{"access_token":"codex-enrollment-secret"}')
    codex.chmod(0o600)
    monkeypatch.setattr(
        workflow,
        "parse_codex_file_auth",
        lambda data: data == b'{"access_token":"codex-enrollment-secret"}',
    )
    claude = tmp_path / "claude" / ".credentials.json"
    claude.parent.mkdir(mode=0o700)
    claude.write_text(
        json.dumps(
            {
                "claudeAiOauth": {
                    "accessToken": "claude-enrollment-secret",
                    "refreshToken": "claude-refresh-secret",
                    "expiresAt": 1_800_000_000_000,
                    "refreshTokenExpiresAt": 1_900_000_000_000,
                    "scopes": ["user:inference"],
                    "subscriptionType": "pro",
                    "rateLimitTier": "default",
                },
                "organizationUuid": "00000000-0000-0000-0000-000000000000",
            }
        )
    )
    claude.chmod(0o600)

    argv = [
        "--state-home",
        str(tmp_path / "state"),
        "auth",
        "init",
        "--codex-auth",
        str(codex),
        "--claude-credentials",
        str(claude),
    ]
    assert main(argv) == 0
    first_output = capsys.readouterr().out
    assert "codex-enrollment-secret" not in first_output
    assert "claude-enrollment-secret" not in first_output
    assert '"installed_now": true' in first_output

    assert main(argv) == 0
    second_output = capsys.readouterr().out
    assert second_output.count('"installed_now": false') == 2

    assert main(["--state-home", str(tmp_path / "state"), "auth", "status"]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["codex"]["local_copy_present_and_parseable"] is True
    assert status["codex"]["vendor_session_validity"] == "not_checked"
    assert status["claude"]["local_copy_present_and_parseable"] is True
    assert status["claude"]["vendor_session_validity"] == "not_checked"
    assert status["default_profile"] == {
        "locally_ready": True,
        "next_action": "no local authentication action is required; start the intended run",
        "recovery_command": None,
        "repair_required": False,
        "state": "ready",
    }

    metadata = tmp_path / "state" / "agent-loop" / "credentials" / "default-profile.json"
    metadata.write_text('{"schema_version":1,"profile":"default"}\n')
    metadata.chmod(0o600)
    assert main(["--state-home", str(tmp_path / "state"), "auth", "status"]) == 0
    legacy_status = json.loads(capsys.readouterr().out)
    assert legacy_status["codex"]["local_copy_present_and_parseable"] is True
    assert legacy_status["claude"]["local_copy_present_and_parseable"] is True
    assert legacy_status["default_profile"] == {
        "locally_ready": False,
        "next_action": "review the credential state, then run the recovery command",
        "recovery_command": "agent-loop auth init --repair",
        "repair_required": True,
        "state": "repair_required",
    }


def test_auth_repair_reports_the_successful_pair_operation(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import agent_loop.workflow as workflow

    codex = tmp_path / "codex" / "auth.json"
    codex.parent.mkdir(mode=0o700)
    codex.write_bytes(b'{"access_token":"codex-enrollment-secret"}')
    codex.chmod(0o600)
    monkeypatch.setattr(
        workflow,
        "parse_codex_file_auth",
        lambda data: data == b'{"access_token":"codex-enrollment-secret"}',
    )
    claude = tmp_path / "claude" / ".credentials.json"
    claude.parent.mkdir(mode=0o700)
    claude.write_text(
        json.dumps(
            {
                "claudeAiOauth": {
                    "accessToken": "claude-enrollment-secret",
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
    claude.chmod(0o600)
    base = [
        "--state-home",
        str(tmp_path / "state"),
        "auth",
        "init",
        "--codex-auth",
        str(codex),
        "--claude-credentials",
        str(claude),
    ]
    assert main(base) == 0
    capsys.readouterr()

    assert main([*base, "--repair"]) == 0
    repaired = json.loads(capsys.readouterr().out)
    assert repaired["codex"]["installed_now"] is False
    assert repaired["claude"]["installed_now"] is False
    assert repaired["codex"]["repaired_now"] is True
    assert repaired["claude"]["repaired_now"] is True


@pytest.mark.parametrize(
    ("codex_id", "claude_id"),
    (("default", "custom-claude"), ("custom-codex", "default")),
)
def test_auth_init_rejects_a_mixed_default_and_custom_pair(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    codex_id: str,
    claude_id: str,
) -> None:
    assert (
        main(
            [
                "--state-home",
                str(tmp_path / "state"),
                "auth",
                "init",
                "--codex-credential-id",
                codex_id,
                "--claude-credential-id",
                claude_id,
            ]
        )
        == 18
    )
    assert "must be selected as a pair" in capsys.readouterr().err
    assert not (tmp_path / "state").exists()


@pytest.mark.parametrize(
    ("pair_state", "recovery_command", "next_action"),
    (
        (
            "absent",
            None,
            (
                "start the intended run; your standard Codex and Claude logins are reused "
                "automatically"
            ),
        ),
        (
            "busy",
            "agent-loop auth status",
            "wait for the active credential operation, then retry status",
        ),
        (
            "recovery_pending",
            None,
            "start the intended run; locked crash recovery is automatic before spending",
        ),
    ),
)
def test_auth_status_gives_plain_guidance_for_non_repairable_states(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    pair_state: str,
    recovery_command: str | None,
    next_action: str,
) -> None:
    import agent_loop.cli as cli_module

    monkeypatch.setattr(
        cli_module,
        "default_cli_credential_pair_state",
        lambda **_kwargs: pair_state,
    )
    assert main(["--state-home", str(tmp_path), "auth", "status"]) == 0
    profile = json.loads(capsys.readouterr().out)["default_profile"]
    assert profile == {
        "locally_ready": False,
        "next_action": next_action,
        "recovery_command": recovery_command,
        "repair_required": False,
        "state": pair_state,
    }
