from __future__ import annotations

import json
import shutil
import stat
import tomllib
from pathlib import Path

import pytest

from agent_loop.codex_client import (
    AUTHOR_CWD,
    AUTHOR_PERMISSION_PROFILE,
    AUTHOR_WORKSPACE,
    CodexClient,
    CodexInvocation,
    SanitizedCodexConfig,
    build_codex_exec_help_argv,
    build_codex_first_argv,
    build_codex_parent_environment,
    build_codex_prompt_input_argv,
    build_codex_resume_argv,
    build_codex_resume_help_argv,
    build_codex_version_argv,
    classify_codex_process_result,
    install_sanitized_codex_config,
    parse_codex_jsonl,
)
from agent_loop.credentials import CodexCredentialTransaction, codex_credential_root
from agent_loop.errors import AgentLoopError, ExitCode, StopReason
from agent_loop.service import BoundedProcessResult, run_bounded_process


AUTH = b'{"access_token":"fake-only-secret"}'


def valid_auth(data: bytes) -> bool:
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    return isinstance(value, dict) and isinstance(value.get("access_token"), str)


def valid_probe(codex_home: Path) -> bool:
    return valid_auth((codex_home / "auth.json").read_bytes())


def provision_transaction(tmp_path: Path, run_id: str) -> CodexCredentialTransaction:
    root = codex_credential_root("codex-adapter", state_home=tmp_path)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.chmod(0o700)
    (root / "auth.json").write_bytes(AUTH)
    (root / "auth.json").chmod(0o600)
    return CodexCredentialTransaction.acquire(
        "codex-adapter",
        run_id,
        auth_parser=valid_auth,
        auth_probe=valid_probe,
        state_home=tmp_path,
    )


@pytest.fixture
def fake_codex(tmp_path: Path) -> Path:
    source = Path(__file__).parents[1] / "fakes" / "fake_codex.py"
    destination = tmp_path / "fake-codex"
    shutil.copyfile(source, destination)
    destination.chmod(0o755)
    return destination


def local_transport(
    invocation: CodexInvocation,
    timeout_seconds: float,
    output_max_bytes: int,
) -> BoundedProcessResult:
    return run_bounded_process(
        invocation.argv,
        timeout_seconds=timeout_seconds,
        output_max_bytes=output_max_bytes,
        env=invocation.launch_environment(),
    )


def test_031_generated_config_is_sanitized_and_mandatory_profile_is_exact() -> None:
    config = SanitizedCodexConfig(
        model="gpt-explicit",
        effort="high",
        additional_workspace_denies=("secrets/**",),
        additional_host_denies=("/runtime/artifacts",),
    )

    encoded = config.render()
    parsed = tomllib.loads(encoded.decode("ascii"))
    profile = parsed["permissions"][AUTHOR_PERMISSION_PROFILE]

    assert parsed["default_permissions"] == AUTHOR_PERMISSION_PROFILE
    assert parsed["approval_policy"] == "never"
    assert parsed["web_search"] == "disabled"
    assert parsed["cli_auth_credentials_store"] == "file"
    assert parsed["features"] == {"hooks": False}
    assert parsed["projects"][AUTHOR_WORKSPACE]["trust_level"] == "untrusted"
    assert parsed["shell_environment_policy"]["inherit"] == "none"
    assert profile["extends"] == ":workspace"
    assert profile["network"]["enabled"] is False
    assert profile["filesystem"]["glob_scan_max_depth"] == 128
    assert profile["filesystem"][":tmpdir"] == "deny"
    assert profile["filesystem"][":slash_tmp"] == "deny"
    assert profile["filesystem"]["/control"] == "deny"
    assert profile["filesystem"]["/runtime/artifacts"] == "deny"
    workspace_denies = profile["filesystem"][":workspace_roots"]
    for path in (".git", ".codex", "AGENTS.md", "**/AGENTS.override.md", "secrets/**"):
        assert workspace_denies[path] == "deny"
    assert b"MCP" not in encoded
    assert b"plugin" not in encoded
    assert b"skills" not in encoded


def test_007_explicit_instruction_opt_in_relaxes_only_profile_prevention_layer() -> None:
    config = SanitizedCodexConfig(
        additional_workspace_denies=("scripts/ci/**",),
        workspace_opt_ins=(".codex/task/settings.toml",),
    )
    parsed = tomllib.loads(config.render().decode("ascii"))
    denies = parsed["permissions"][AUTHOR_PERMISSION_PROFILE]["filesystem"][
        ":workspace_roots"
    ]
    assert ".codex" not in denies
    assert ".codex/**" not in denies
    assert denies["scripts/ci/**"] == "deny"
    assert denies[".git"] == "deny"
    assert denies["**/.git/**"] == "deny"


def test_031_config_is_installed_mode_0600_in_locked_transaction_home(
    tmp_path: Path,
) -> None:
    with provision_transaction(tmp_path, "install-run") as transaction:
        config_path = install_sanitized_codex_config(
            transaction,
            SanitizedCodexConfig(model="gpt-explicit", effort="medium"),
        )

        assert config_path.parent == transaction.codex_home
        assert stat.S_IMODE(config_path.stat().st_mode) == 0o600
        assert config_path.read_bytes() == SanitizedCodexConfig(
            model="gpt-explicit", effort="medium"
        ).render()
        assert {path.name for path in transaction.codex_home.iterdir()} == {
            "auth.json",
            "config.toml",
            "sessions",
        }


def test_031_unreviewed_ambient_codex_home_state_is_rejected(tmp_path: Path) -> None:
    transaction = provision_transaction(tmp_path, "hostile-home")
    hostile = transaction.codex_home / "hooks.json"
    hostile.write_text('{"command":"steal"}')
    hostile.chmod(0o600)
    try:
        with pytest.raises(AgentLoopError) as caught:
            install_sanitized_codex_config(transaction, SanitizedCodexConfig())
    finally:
        transaction.close()

    assert caught.value.reason is StopReason.PROJECT_INSTRUCTION_ISOLATION


def test_031_parent_environment_is_an_exact_allowlist_and_ignores_ambient() -> None:
    hostile = {
        "CODEX_HOME": "/host/.codex",
        "OPENAI_API_KEY": "ambient-secret",
        "RUST_LOG": "trace",
        "HTTP_PROXY": "http://credential@proxy",
        "SSH_AUTH_SOCK": "/host/agent.sock",
        "HOME": "/host/home",
        "PATH": "/host/bin",
    }

    environment = build_codex_parent_environment(ambient=hostile)

    assert environment == {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": "/runtime/home",
        "TMPDIR": "/runtime/tmp",
        "LANG": "C.UTF-8",
        "CODEX_HOME": "/control/codex-home",
    }
    assert "ambient-secret" not in environment.values()


def test_065_first_and_resume_argv_have_exact_pinned_ordering() -> None:
    executable = "/opt/reviewed/codex"
    first = build_codex_first_argv("author task", executable=executable)
    resume = build_codex_resume_argv("thread-123", "revision", executable=executable)

    assert first == (
        executable,
        "-a",
        "never",
        "-C",
        AUTHOR_CWD,
        "--add-dir",
        AUTHOR_WORKSPACE,
        "-c",
        'default_permissions="agent_loop_author"',
        "exec",
        "--json",
        "--strict-config",
        "--skip-git-repo-check",
        "author task",
    )
    assert resume == (
        executable,
        "-a",
        "never",
        "-C",
        AUTHOR_CWD,
        "--add-dir",
        AUTHOR_WORKSPACE,
        "-c",
        'default_permissions="agent_loop_author"',
        "exec",
        "resume",
        "--json",
        "--strict-config",
        "--skip-git-repo-check",
        "thread-123",
        "revision",
    )
    for argv in (first, resume):
        assert "--last" not in argv
        assert "--sandbox" not in argv
        assert "--dangerously-bypass-approvals-and-sandbox" not in argv
        assert argv.index("-C") < argv.index("exec")
        assert argv.index("--add-dir") < argv.index("exec")
    assert resume.index("--json") > resume.index("resume")


def test_034_resume_rejects_implicit_or_unsafe_session_identifiers() -> None:
    for thread_id in ("", "--last", "../thread", "thread id", "x" * 257):
        with pytest.raises(ValueError, match="thread ID"):
            build_codex_resume_argv(thread_id, "revision")


def test_non_model_capability_builders_are_bounded_and_explicit(tmp_path: Path) -> None:
    executable = "/opt/reviewed/codex"
    assert build_codex_version_argv(executable=executable) == (executable, "--version")
    assert build_codex_exec_help_argv(executable=executable) == (
        executable,
        "exec",
        "--help",
    )
    assert build_codex_resume_help_argv(executable=executable) == (
        executable,
        "exec",
        "resume",
        "--help",
    )
    probe = build_codex_prompt_input_argv(
        "instruction isolation probe",
        executable=executable,
        control_cwd=str(tmp_path / "empty"),
        workspace=str(tmp_path / "workspace"),
    )
    assert probe[-3:] == ("debug", "prompt-input", "instruction isolation probe")
    assert "--add-dir" in probe
    # Pinned 0.144.6 rejects --strict-config for the debug command. Runtime
    # first/resume invocations still require it.
    assert "--strict-config" not in probe
    assert "exec" not in probe


def test_jsonl_parser_captures_only_thread_started_id_and_model_usage_facts() -> None:
    events = [
        {
            "type": "thread.started",
            "thread_id": "thread-right",
            "model": "gpt-pinned",
            "reasoning_effort": "high",
        },
        {"type": "turn.started", "thread_id": "thread-wrong"},
        {
            "type": "item.completed",
            "thread_id": "thread-wrong-again",
            "item": {"type": "agent_message", "text": "complete"},
        },
        {
            "type": "turn.completed",
            "usage": {"input_tokens": 9, "output_tokens": 4},
            "model": "gpt-pinned",
            "effort": "high",
        },
    ]
    payload = b"\n".join(
        json.dumps(event, separators=(",", ":")).encode("utf-8") for event in events
    )

    result = parse_codex_jsonl(payload, expected_thread_id="thread-right", completed_at=7.0)

    assert result.thread_id == "thread-right"
    assert result.final_message == "complete"
    assert result.observed_model == "gpt-pinned"
    assert result.observed_effort == "high"
    assert result.usage.input_tokens == 9
    assert result.usage.cached_input_tokens == 0
    assert result.usage.output_tokens == 4
    assert result.event_json[0] == payload.splitlines()[0]
    assert result.completed_at == 7.0


@pytest.mark.parametrize(
    "payload",
    [
        b"{not-json\n",
        b'{"type":"thread.started","thread_id":"one","thread_id":"two"}\n',
        b'{"type":"turn.started"}\n',
        b'{"type":"thread.started","thread_id":"thread"}\n\n',
        b'{"type":"thread.started","thread_id":NaN}\n',
    ],
)
def test_jsonl_parser_rejects_malformed_duplicate_or_incomplete_events(payload: bytes) -> None:
    with pytest.raises(AgentLoopError) as caught:
        parse_codex_jsonl(payload)
    assert caught.value.reason is StopReason.AUTHOR_PROCESS_FAILURE


def test_jsonl_parser_rejects_nested_duplicate_keys() -> None:
    payload = (
        b'{"type":"thread.started","thread_id":"thread"}\n'
        b'{"type":"item.completed","item":{"type":"agent_message",'
        b'"text":"one","text":"two"}}\n'
    )
    with pytest.raises(AgentLoopError, match="duplicate-key"):
        parse_codex_jsonl(payload)


@pytest.mark.parametrize(
    "events",
    (
        (
            {
                "type": "thread.started",
                "thread_id": "thread",
                "model": "\ud800",
            },
        ),
        (
            {"type": "thread.started", "thread_id": "thread"},
            {
                "type": "item.completed",
                "item": {"type": "agent_message", "text": "\ud800"},
            },
        ),
    ),
)
def test_jsonl_parser_rejects_escaped_lone_surrogates_as_typed_protocol_failures(
    events: tuple[dict[str, object], ...],
) -> None:
    payload = b"\n".join(
        json.dumps(event, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        for event in events
    )

    with pytest.raises(AgentLoopError) as caught:
        parse_codex_jsonl(payload)

    assert caught.value.reason is StopReason.AUTHOR_PROCESS_FAILURE
    assert "\\ud800" not in caught.value.detail


def test_fake_first_and_exact_resume_round_trip(fake_codex: Path) -> None:
    client = CodexClient(local_transport)

    first = client.first_turn(
        "scenario:success",
        timeout_seconds=2,
        executable=str(fake_codex),
    )
    resumed = client.resume_turn(
        first.thread_id,
        "scenario:success",
        timeout_seconds=2,
        executable=str(fake_codex),
    )

    assert first.thread_id == "thread-001"
    assert resumed.thread_id == first.thread_id
    assert resumed.final_message == "fake author completed"
    assert resumed.usage.reasoning_output_tokens == 2
    assert resumed.observed_model == "gpt-fake-pinned"


def test_034_fake_resume_rejects_a_different_returned_thread(fake_codex: Path) -> None:
    client = CodexClient(local_transport)

    with pytest.raises(AgentLoopError) as caught:
        client.resume_turn(
            "thread-001",
            "scenario:different-thread",
            timeout_seconds=2,
            executable=str(fake_codex),
        )

    assert caught.value.reason is StopReason.AUTHOR_PROCESS_FAILURE


@pytest.mark.parametrize(
    "scenario",
    [
        "malformed",
        "duplicate-key",
        "missing-thread",
        "unsafe-thread",
        "missing-final",
        "missing-usage",
        "error-event",
    ],
)
def test_fake_protocol_failures_are_author_process_failures(
    fake_codex: Path, scenario: str
) -> None:
    client = CodexClient(local_transport)

    with pytest.raises(AgentLoopError) as caught:
        client.first_turn(
            f"scenario:{scenario}",
            timeout_seconds=2,
            executable=str(fake_codex),
        )

    assert caught.value.reason is StopReason.AUTHOR_PROCESS_FAILURE
    assert caught.value.exit_code is ExitCode.PROCESS_FAILURE


def test_fake_nonzero_timeout_and_output_limit_have_distinct_classification(
    fake_codex: Path,
) -> None:
    client = CodexClient(local_transport)

    with pytest.raises(AgentLoopError) as nonzero:
        client.first_turn(
            "scenario:nonzero",
            timeout_seconds=2,
            executable=str(fake_codex),
        )
    assert nonzero.value.reason is StopReason.AUTHOR_PROCESS_FAILURE

    with pytest.raises(AgentLoopError) as timeout:
        client.first_turn(
            "scenario:timeout",
            timeout_seconds=0.05,
            executable=str(fake_codex),
        )
    assert timeout.value.reason is StopReason.AUTHOR_TIMEOUT
    assert timeout.value.exit_code is ExitCode.TIMEOUT

    with pytest.raises(AgentLoopError) as output:
        client.first_turn(
            "scenario:output-limit",
            timeout_seconds=2,
            executable=str(fake_codex),
            output_max_bytes=1024,
        )
    assert output.value.reason is StopReason.AGENT_OUTPUT_LIMIT


def test_process_classification_checks_output_and_timeout_before_exit_code() -> None:
    both = BoundedProcessResult(9, b"", b"", 1.0, 2.0, True, True)
    with pytest.raises(AgentLoopError) as caught:
        classify_codex_process_result(both)
    assert caught.value.reason is StopReason.AGENT_OUTPUT_LIMIT


def test_unflagged_oversized_nonzero_result_is_still_an_output_limit() -> None:
    oversized = BoundedProcessResult(9, b"123456", b"12345", 1.0, 2.0, False, False)
    with pytest.raises(AgentLoopError) as unflagged:
        classify_codex_process_result(oversized, max_bytes=10)
    assert unflagged.value.reason is StopReason.AGENT_OUTPUT_LIMIT


def test_nonzero_process_reports_only_strict_structural_failure_facts() -> None:
    secret = "credential-and-model-content-must-not-cross"
    stdout = b"\n".join(
        (
            b'{"type":"thread.started","thread_id":"thread-safe"}',
            json.dumps(
                {"type": "error", "message": secret}, separators=(",", ":")
            ).encode(),
            json.dumps(
                {"type": "turn.failed", "error": {"message": secret}},
                separators=(",", ":"),
            ).encode(),
        )
    ) + b"\n"
    result = BoundedProcessResult(
        1,
        stdout,
        secret.encode(),
        1.0,
        2.0,
        False,
        False,
    )

    with pytest.raises(AgentLoopError) as caught:
        classify_codex_process_result(result)

    assert caught.value.reason is StopReason.AUTHOR_PROCESS_FAILURE
    assert caught.value.detail == (
        "Codex process exited unsuccessfully (1; stdout_protocol=valid; "
        "thread_started=true; terminal_event=turn.failed; stderr_present=true)"
    )
    assert secret not in caught.value.detail


@pytest.mark.parametrize(
    ("stdout", "max_bytes", "expected_protocol"),
    (
        (b"{not-json\n", 1024, "invalid"),
        (
            b'{"type":"thread.started","thread_id":"thread-safe"}\n'
            b'{"type":"turn.failed","error":{"message":"one","message":"two"}}\n',
            1024,
            "invalid",
        ),
        (
            b'{"type":"thread.started","thread_id":"thread-safe"}\n'
            b'{"type":"turn.failed","error":{"message":"\\ud800"}}\n',
            1024,
            "invalid",
        ),
        (
            b'{"type":"thread.started","thread_id":"thread-safe"}\n'
            b'{"type":"error","message":"private","unexpected":true}\n'
            b'{"type":"turn.failed","error":{"message":"private"}}\n',
            1024,
            "invalid",
        ),
    ),
)
def test_nonzero_diagnostic_fails_closed_for_malformed_or_duplicate_jsonl(
    stdout: bytes,
    max_bytes: int,
    expected_protocol: str,
) -> None:
    result = BoundedProcessResult(7, stdout, b"", 1.0, 2.0, False, False)

    with pytest.raises(AgentLoopError) as caught:
        classify_codex_process_result(result, max_bytes=max_bytes)

    assert caught.value.reason is StopReason.AUTHOR_PROCESS_FAILURE
    assert caught.value.detail == (
        f"Codex process exited unsuccessfully (7; stdout_protocol={expected_protocol}; "
        "thread_started=unverified; terminal_event=unverified; stderr_present=false)"
    )
    assert "one" not in caught.value.detail
    assert "two" not in caught.value.detail


@pytest.mark.parametrize(
    ("last_event", "expected_terminal"),
    (
        ({"type": "error", "message": "private failure"}, "error"),
        ({"type": "turn.started"}, "none"),
    ),
)
def test_nonzero_diagnostic_classifies_only_exact_terminal_event_shape(
    last_event: dict[str, object], expected_terminal: str
) -> None:
    stdout = b"\n".join(
        (
            b'{"type":"thread.started","thread_id":"thread-safe"}',
            json.dumps(last_event, separators=(",", ":")).encode(),
        )
    ) + b"\n"
    result = BoundedProcessResult(1, stdout, b"", 1.0, 2.0, False, False)

    with pytest.raises(AgentLoopError) as caught:
        classify_codex_process_result(result)

    assert caught.value.detail == (
        "Codex process exited unsuccessfully (1; stdout_protocol=valid; "
        f"thread_started=true; terminal_event={expected_terminal}; "
        "stderr_present=false)"
    )
    assert "private failure" not in caught.value.detail


def test_parser_enforces_its_own_byte_bound() -> None:
    with pytest.raises(AgentLoopError) as caught:
        parse_codex_jsonl(b"x" * 11, max_bytes=10)
    assert caught.value.reason is StopReason.AGENT_OUTPUT_LIMIT


def test_invocation_environment_cannot_be_broadened() -> None:
    client = CodexClient(local_transport)
    broadened = build_codex_parent_environment()
    broadened["OPENAI_API_KEY"] = "forbidden"
    with pytest.raises(ValueError, match="exact allowlist"):
        client.first_turn(
            "scenario:success",
            timeout_seconds=1,
            parent_environment=broadened,
        )
