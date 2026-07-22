from __future__ import annotations

import errno
import json
import os
import shutil
import stat
import tomllib
from pathlib import Path

import pytest

from agent_loop.codex_client import (
    AUTHOR_CWD,
    AUTHOR_PERMISSION_PROFILE,
    AUTHOR_WORKSPACE,
    SANDBOX_CODEX_HOME,
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
    parse_codex_rollout_selection,
    read_codex_rollout_selection,
)
from agent_loop.credentials import CodexCredentialTransaction, codex_credential_root
from agent_loop.errors import AgentLoopError, ExitCode, StopReason
from agent_loop.service import BoundedProcessResult, run_bounded_process

AUTH = b'{"access_token":"fake-only-secret"}'
ROLLOUT_THREAD_ID = "019f825d-5ede-7793-831d-884ce62c2caa"
ROLLOUT_TURN_IDS = (
    "019f825d-5f0c-7b33-a270-65c1adbdeb8a",
    "019f825d-98f2-7c61-a58e-dd0175c9191c",
    "019f825d-a001-7000-8000-000000000001",
    "019f825d-a002-7000-8000-000000000002",
    "019f825d-a003-7000-8000-000000000003",
)


def codex_rollout(turn_ids: tuple[str, ...]) -> bytes:
    events: list[dict[str, object]] = [
        {
            "timestamp": "2026-07-21T01:49:45.000Z",
            "type": "session_meta",
            "payload": {
                "id": ROLLOUT_THREAD_ID,
                "session_id": ROLLOUT_THREAD_ID,
                "timestamp": "2026-07-21T01:49:45.000Z",
                "cwd": "/runtime/author-cwd",
                "originator": "codex_exec",
                "cli_version": "0.144.6",
                "source": "exec",
                "model_provider": "openai",
                "base_instructions": None,
                "history_mode": "legacy",
            },
        }
    ]
    cursor = 0
    while cursor < len(turn_ids):
        turn_id = turn_ids[cursor]
        run_end = cursor + 1
        while run_end < len(turn_ids) and turn_ids[run_end] == turn_id:
            run_end += 1
        events.append(
            {
                "timestamp": "2026-07-21T01:49:46.000Z",
                "type": "event_msg",
                "payload": {
                    "type": "task_started",
                    "turn_id": turn_id,
                    "trace_id": f"trace-{turn_id}",
                    "started_at": 1_774_000_000,
                    "model_context_window": 128_000,
                    "collaboration_mode_kind": "default",
                },
            }
        )
        for duplicate_index in range(run_end - cursor):
            if duplicate_index:
                events.append(
                    {
                        "timestamp": "2026-07-21T01:49:47.000Z",
                        "type": "compacted",
                        "payload": {"message": "sanitized compaction"},
                    }
                )
            events.append(
                {
                    "timestamp": "2026-07-21T01:49:47.000Z",
                    "type": "turn_context",
                    "payload": {
                        "turn_id": turn_id,
                        "cwd": "/runtime/author-cwd",
                        "approval_policy": "never",
                        "sandbox_policy": {
                            "type": "workspace-write",
                            "network_access": False,
                            "exclude_tmpdir_env_var": True,
                            "exclude_slash_tmp": True,
                        },
                        "model": "gpt-5.4",
                        "effort": "high",
                        "summary": "auto",
                    },
                }
            )
        events.extend(
            (
                {
                    "timestamp": "2026-07-21T01:49:48.000Z",
                    "type": "response_item",
                    "payload": {
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": "sanitized output"}],
                    },
                },
                {
                    "timestamp": "2026-07-21T01:49:49.000Z",
                    "type": "event_msg",
                    "payload": {
                        "type": "task_complete",
                        "turn_id": turn_id,
                        "last_agent_message": "sanitized output",
                        "completed_at": 1_774_000_001,
                        "duration_ms": 1_000,
                        "time_to_first_token_ms": 100,
                    },
                },
            )
        )
        cursor = run_end
    return (
        b"\n".join(json.dumps(event, separators=(",", ":")).encode("utf-8") for event in events)
        + b"\n"
    )


def install_rollout(codex_home: Path, data: bytes) -> Path:
    day = codex_home / "sessions" / "2026" / "07" / "21"
    day.mkdir(mode=0o700, parents=True)
    for directory in (codex_home, codex_home / "sessions", *day.parents):
        if directory == codex_home.parent:
            break
        directory.chmod(0o700)
    rollout = day / (f"rollout-2026-07-21T01-49-45-{ROLLOUT_THREAD_ID}.jsonl")
    rollout.write_bytes(data)
    rollout.chmod(0o600)
    return rollout


def valid_auth(data: bytes) -> bool:
    try:
        value = json.loads(data)
    except UnicodeDecodeError, json.JSONDecodeError:
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
    assert parsed["include_apps_instructions"] is False
    assert parsed["include_collaboration_mode_instructions"] is False
    assert parsed["features"] == {
        "apps": False,
        "goals": False,
        "hooks": False,
        "memories": False,
        "multi_agent": False,
        "personality": False,
        "remote_plugin": False,
        "shell_snapshot": False,
        "skill_mcp_dependency_install": False,
        "tool_call_mcp_elicitation": False,
    }
    assert parsed["skills"]["config"] == [
        {
            "path": f"{SANDBOX_CODEX_HOME}/skills/.system/{name}/SKILL.md",
            "enabled": False,
        }
        for name in (
            "imagegen",
            "openai-docs",
            "plugin-creator",
            "skill-creator",
            "skill-installer",
        )
    ]
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
    for path in (
        ".git/**",
        ".codex/**",
        "AGENTS.md",
        "**/AGENTS.override.md",
        "secrets/**",
    ):
        assert workspace_denies[path] == "deny"
    # These exact names are reserved mount targets in the pinned :workspace
    # profile.  Adding a second exact deny makes Bubblewrap collide with its
    # own directory mounts; descendant denies and the built-in profile retain
    # the protection.
    assert ".git" not in workspace_denies
    assert ".codex" not in workspace_denies
    assert b"mcp_servers" not in encoded


def test_007_explicit_instruction_opt_in_relaxes_only_profile_prevention_layer() -> None:
    config = SanitizedCodexConfig(
        additional_workspace_denies=("scripts/ci/**",),
        workspace_opt_ins=(".codex/task/settings.toml",),
    )
    parsed = tomllib.loads(config.render().decode("ascii"))
    denies = parsed["permissions"][AUTHOR_PERMISSION_PROFILE]["filesystem"][":workspace_roots"]
    assert ".codex" not in denies
    assert ".codex/**" not in denies
    assert denies["scripts/ci/**"] == "deny"
    assert ".git" not in denies
    assert denies[".git/**"] == "deny"
    assert denies["**/.git/**"] == "deny"


def test_reserved_workspace_mount_targets_cannot_be_reintroduced_by_project_policy() -> None:
    parsed = tomllib.loads(
        SanitizedCodexConfig(
            additional_workspace_denies=(
                ".git",
                ".git/**",
                ".codex",
                ".codex/**",
                "scripts/ci/**",
            )
        )
        .render()
        .decode("ascii")
    )
    denies = parsed["permissions"][AUTHOR_PERMISSION_PROFILE]["filesystem"][":workspace_roots"]

    assert ".git" not in denies
    assert ".codex" not in denies
    assert denies[".git/**"] == "deny"
    assert denies[".codex/**"] == "deny"
    assert denies["scripts/ci/**"] == "deny"


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
        assert (
            config_path.read_bytes()
            == SanitizedCodexConfig(model="gpt-explicit", effort="medium").render()
        )
        assert {path.name for path in transaction.codex_home.iterdir()} == {
            ".tmp",
            "auth.json",
            "config.toml",
            "plugins",
            "sessions",
            "skills",
            "tmp",
        }
        for name in (".tmp", "plugins", "skills", "tmp"):
            mountpoint = transaction.codex_home / name
            assert mountpoint.is_dir()
            assert stat.S_IMODE(mountpoint.stat().st_mode) == 0o700


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


def test_pinned_jsonl_contract_has_no_model_or_effort_metadata() -> None:
    events = (
        {"type": "thread.started", "thread_id": ROLLOUT_THREAD_ID},
        {"type": "turn.started"},
        {
            "type": "item.completed",
            "item": {"type": "agent_message", "text": "complete"},
        },
        {
            "type": "turn.completed",
            "usage": {"input_tokens": 9, "output_tokens": 4},
        },
    )
    payload = (
        b"\n".join(json.dumps(event, separators=(",", ":")).encode() for event in events) + b"\n"
    )

    result = parse_codex_jsonl(payload, expected_thread_id=ROLLOUT_THREAD_ID)

    assert result.observed_model is None
    assert result.observed_effort is None


def test_pinned_jsonl_model_reroute_signal_fails_closed() -> None:
    events = (
        {"type": "thread.started", "thread_id": ROLLOUT_THREAD_ID},
        {"type": "turn.started"},
        {
            "type": "item.completed",
            "item": {
                "id": "item_0",
                "type": "error",
                "message": ("model rerouted: gpt-5.4 -> gpt-5.2 (HighRiskCyberActivity)"),
            },
        },
        {
            "type": "item.completed",
            "item": {"type": "agent_message", "text": "complete"},
        },
        {
            "type": "turn.completed",
            "usage": {"input_tokens": 9, "output_tokens": 4},
        },
    )
    payload = (
        b"\n".join(json.dumps(event, separators=(",", ":")).encode() for event in events) + b"\n"
    )

    with pytest.raises(AgentLoopError, match="rerouted the requested model"):
        parse_codex_jsonl(payload, expected_thread_id=ROLLOUT_THREAD_ID)


@pytest.mark.parametrize(
    "diagnostic",
    (
        "bwrap: No permissions to create a new namespace, likely because the kernel "
        "does not allow non-privileged user namespaces.",
        "failed to create synthetic bubblewrap mount registry /runtime/tmp/example: "
        "Permission denied",
        "bwrap: Can't create file at /workspace/.git: Is a directory",
        "bwrap: Can't create file at /workspace/.codex: Is a directory",
        "permission profiles requiring direct runtime enforcement are incompatible with "
        "--use-legacy-landlock",
    ),
)
def test_command_sandbox_setup_failure_dominates_completion_prose(diagnostic: str) -> None:
    events = (
        {"type": "thread.started", "thread_id": ROLLOUT_THREAD_ID},
        {"type": "turn.started"},
        {
            "type": "item.completed",
            "item": {
                "id": "item_0",
                "type": "command_execution",
                "command": "/usr/bin/python3 /workspace/capability_probe.py first",
                "aggregated_output": diagnostic,
                "exit_code": 1,
                "status": "failed",
            },
        },
        {
            "type": "item.completed",
            "item": {
                "id": "item_1",
                "type": "agent_message",
                "text": "LIVE_FIRST_PROBE_COMPLETE",
            },
        },
        {
            "type": "turn.completed",
            "usage": {"input_tokens": 9, "output_tokens": 4},
        },
    )
    payload = (
        b"\n".join(json.dumps(event, separators=(",", ":")).encode() for event in events) + b"\n"
    )

    with pytest.raises(AgentLoopError) as caught:
        parse_codex_jsonl(payload, expected_thread_id=ROLLOUT_THREAD_ID)

    assert caught.value.reason is StopReason.SANDBOX_SETUP_FAILURE
    assert caught.value.detail == "Codex command sandbox could not initialize"
    assert diagnostic not in caught.value.detail


def test_rollout_selection_tracks_first_resume_and_same_turn_compaction() -> None:
    first = parse_codex_rollout_selection(
        codex_rollout((ROLLOUT_TURN_IDS[0], ROLLOUT_TURN_IDS[0])),
        expected_thread_id=ROLLOUT_THREAD_ID,
    )
    resumed = parse_codex_rollout_selection(
        codex_rollout(
            (
                ROLLOUT_TURN_IDS[0],
                ROLLOUT_TURN_IDS[0],
                ROLLOUT_TURN_IDS[1],
                ROLLOUT_TURN_IDS[1],
            )
        ),
        expected_thread_id=ROLLOUT_THREAD_ID,
        expected_previous_turn_ids=first.turn_ids,
        expected_prefix_witness=first.rollout_prefix,
    )

    assert (first.model, first.effort) == ("gpt-5.4", "high")
    assert first.turn_id == ROLLOUT_TURN_IDS[0]
    assert first.turn_ids == ROLLOUT_TURN_IDS[:1]
    assert resumed.turn_id == ROLLOUT_TURN_IDS[1]
    assert resumed.turn_ids == ROLLOUT_TURN_IDS[:2]


def test_rollout_selection_rejects_stale_resume_and_surrogate_metadata() -> None:
    first_data = codex_rollout((ROLLOUT_TURN_IDS[0],))
    first = parse_codex_rollout_selection(
        first_data,
        expected_thread_id=ROLLOUT_THREAD_ID,
    )
    trailing_item = json.dumps(
        {
            "timestamp": "2026-07-21T01:49:50.000Z",
            "type": "response_item",
            "payload": {
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": "sanitized"}],
            },
        },
        separators=(",", ":"),
    ).encode()
    with pytest.raises(AgentLoopError, match="did not advance"):
        parse_codex_rollout_selection(
            first_data + trailing_item + b"\n",
            expected_thread_id=ROLLOUT_THREAD_ID,
            expected_previous_turn_ids=first.turn_ids,
            expected_prefix_witness=first.rollout_prefix,
        )

    hostile = codex_rollout((ROLLOUT_TURN_IDS[0],)).replace(
        b'"2026-07-21T01:49:45.000Z"', b'"\\ud800"', 1
    )
    with pytest.raises(AgentLoopError) as caught:
        parse_codex_rollout_selection(
            hostile,
            expected_thread_id=ROLLOUT_THREAD_ID,
        )
    assert "ud800" not in caught.value.detail


@pytest.mark.parametrize(
    "observed_turn_ids",
    (
        # Prepend an unaccepted turn before the exact accepted history.
        (
            ROLLOUT_TURN_IDS[4],
            ROLLOUT_TURN_IDS[0],
            ROLLOUT_TURN_IDS[1],
            ROLLOUT_TURN_IDS[2],
            ROLLOUT_TURN_IDS[3],
        ),
        # Insert an unaccepted turn into the accepted history.
        (
            ROLLOUT_TURN_IDS[0],
            ROLLOUT_TURN_IDS[4],
            ROLLOUT_TURN_IDS[1],
            ROLLOUT_TURN_IDS[2],
            ROLLOUT_TURN_IDS[3],
        ),
        # Delete a previously accepted turn.
        (
            ROLLOUT_TURN_IDS[0],
            ROLLOUT_TURN_IDS[2],
            ROLLOUT_TURN_IDS[3],
        ),
        # Reorder previously accepted turns.
        (
            ROLLOUT_TURN_IDS[1],
            ROLLOUT_TURN_IDS[0],
            ROLLOUT_TURN_IDS[2],
            ROLLOUT_TURN_IDS[3],
        ),
    ),
    ids=("prepend", "insertion", "deletion", "reorder"),
)
def test_rollout_selection_rejects_mutated_accepted_history(
    observed_turn_ids: tuple[str, ...],
) -> None:
    accepted = parse_codex_rollout_selection(
        codex_rollout(ROLLOUT_TURN_IDS[:1]),
        expected_thread_id=ROLLOUT_THREAD_ID,
    )
    for turn_count in (2, 3):
        accepted = parse_codex_rollout_selection(
            codex_rollout(ROLLOUT_TURN_IDS[:turn_count]),
            expected_thread_id=ROLLOUT_THREAD_ID,
            expected_previous_turn_ids=accepted.turn_ids,
            expected_prefix_witness=accepted.rollout_prefix,
        )
    with pytest.raises(AgentLoopError, match="accepted byte prefix"):
        parse_codex_rollout_selection(
            codex_rollout(observed_turn_ids),
            expected_thread_id=ROLLOUT_THREAD_ID,
            expected_previous_turn_ids=accepted.turn_ids,
            expected_prefix_witness=accepted.rollout_prefix,
        )


@pytest.mark.parametrize("nested_type", ("model_reroute", "model_verification"))
def test_rollout_selection_rejects_transient_event_types(nested_type: str) -> None:
    base = codex_rollout(ROLLOUT_TURN_IDS[:1]).rstrip(b"\n")
    transient = {
        "timestamp": "2026-07-21T01:49:48.000Z",
        "type": "event_msg",
        "payload": {
            "type": nested_type,
        },
    }

    with pytest.raises(AgentLoopError, match="event type is unsupported"):
        parse_codex_rollout_selection(
            base + b"\n" + json.dumps(transient).encode() + b"\n",
            expected_thread_id=ROLLOUT_THREAD_ID,
        )


@pytest.mark.parametrize(
    "marker",
    (
        "<apps_instructions>",
        "<plugins_instructions>",
        "<skills_instructions>",
        "request_plugin_install",
        "tool_search",
    ),
)
def test_073_rollout_rejects_ambient_control_context(marker: str) -> None:
    lines = codex_rollout((ROLLOUT_TURN_IDS[0],)).splitlines()
    injected = json.dumps(
        {
            "timestamp": "2026-07-21T01:49:45.001Z",
            "type": "response_item",
            "payload": {
                "type": "message",
                "role": "developer",
                "content": [{"type": "input_text", "text": marker}],
            },
        },
        separators=(",", ":"),
    ).encode("utf-8")
    data = b"\n".join((lines[0], injected, *lines[1:])) + b"\n"

    with pytest.raises(AgentLoopError, match="forbidden skill, plugin, or app"):
        parse_codex_rollout_selection(data, expected_thread_id=ROLLOUT_THREAD_ID)


@pytest.mark.parametrize(
    ("outer_type", "payload"),
    (
        ("future_rollout_item", {}),
        ("event_msg", {"type": "future_event"}),
        ("event_msg", {"type": "turn_started"}),
        ("event_msg", {"type": "turn_complete"}),
    ),
    ids=("outer", "nested", "started-alias", "complete-alias"),
)
def test_rollout_selection_rejects_unknown_outer_and_nested_types(
    outer_type: str,
    payload: dict[str, object],
) -> None:
    extra = json.dumps(
        {
            "timestamp": "2026-07-21T01:49:50.000Z",
            "type": outer_type,
            "payload": payload,
        },
        separators=(",", ":"),
    ).encode()

    with pytest.raises(AgentLoopError, match="type is unsupported"):
        parse_codex_rollout_selection(
            codex_rollout(ROLLOUT_TURN_IDS[:1]) + extra + b"\n",
            expected_thread_id=ROLLOUT_THREAD_ID,
        )


@pytest.mark.parametrize(
    "scenario",
    ("missing-start", "missing-context", "missing-complete", "wrong-complete", "bad-start"),
)
def test_rollout_selection_requires_exact_real_turn_lifecycle(scenario: str) -> None:
    events = [json.loads(line) for line in codex_rollout(ROLLOUT_TURN_IDS[:1]).splitlines()]
    started_index = next(
        index
        for index, event in enumerate(events)
        if event["type"] == "event_msg" and event["payload"]["type"] == "task_started"
    )
    context_index = next(
        index for index, event in enumerate(events) if event["type"] == "turn_context"
    )
    completed_index = next(
        index
        for index, event in enumerate(events)
        if event["type"] == "event_msg" and event["payload"]["type"] == "task_complete"
    )
    if scenario == "missing-start":
        del events[started_index]
    elif scenario == "missing-context":
        del events[context_index]
    elif scenario == "missing-complete":
        del events[completed_index]
    elif scenario == "wrong-complete":
        events[completed_index]["payload"]["turn_id"] = ROLLOUT_TURN_IDS[1]
    else:
        del events[started_index]["payload"]["model_context_window"]
    data = b"\n".join(json.dumps(event, separators=(",", ":")).encode() for event in events) + b"\n"

    with pytest.raises(AgentLoopError):
        parse_codex_rollout_selection(data, expected_thread_id=ROLLOUT_THREAD_ID)


@pytest.mark.parametrize("nested_type", ("turn_aborted", "thread_rolled_back"))
def test_rollout_selection_rejects_history_transitions(nested_type: str) -> None:
    transition = json.dumps(
        {
            "timestamp": "2026-07-21T01:49:50.000Z",
            "type": "event_msg",
            "payload": {"type": nested_type},
        },
        separators=(",", ":"),
    ).encode()

    with pytest.raises(AgentLoopError, match="rejected history transition"):
        parse_codex_rollout_selection(
            codex_rollout(ROLLOUT_TURN_IDS[:1]) + transition + b"\n",
            expected_thread_id=ROLLOUT_THREAD_ID,
        )


def test_rollout_selection_rejects_rewritten_prior_selection_with_same_ids() -> None:
    first_data = codex_rollout(ROLLOUT_TURN_IDS[:1])
    first = parse_codex_rollout_selection(
        first_data,
        expected_thread_id=ROLLOUT_THREAD_ID,
    )
    rewritten = codex_rollout(ROLLOUT_TURN_IDS[:2]).replace(
        b'"model":"gpt-5.4"',
        b'"model":"gpt-5.3"',
        1,
    )

    with pytest.raises(AgentLoopError, match="accepted byte prefix"):
        parse_codex_rollout_selection(
            rewritten,
            expected_thread_id=ROLLOUT_THREAD_ID,
            expected_previous_turn_ids=first.turn_ids,
            expected_prefix_witness=first.rollout_prefix,
        )


def test_confined_rollout_reader_selects_exact_private_thread(tmp_path: Path) -> None:
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir(mode=0o700)
    install_rollout(codex_home, codex_rollout((ROLLOUT_TURN_IDS[0],)))

    selected = read_codex_rollout_selection(
        codex_home,
        expected_thread_id=ROLLOUT_THREAD_ID,
    )

    assert selected.turn_id == ROLLOUT_TURN_IDS[0]
    assert selected.model == "gpt-5.4"
    assert selected.effort == "high"


def test_confined_rollout_reader_rejects_nonprivate_file(tmp_path: Path) -> None:
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir(mode=0o700)
    rollout = install_rollout(codex_home, codex_rollout((ROLLOUT_TURN_IDS[0],)))
    rollout.chmod(0o640)

    with pytest.raises(AgentLoopError, match="unsafe entry"):
        read_codex_rollout_selection(
            codex_home,
            expected_thread_id=ROLLOUT_THREAD_ID,
        )


def test_confined_rollout_reader_rejects_hardlink_and_symlink_boundaries(
    tmp_path: Path,
) -> None:
    codex_home = tmp_path / "hardlink-home"
    codex_home.mkdir(mode=0o700)
    rollout = install_rollout(codex_home, codex_rollout((ROLLOUT_TURN_IDS[0],)))
    os.link(rollout, tmp_path / "second-rollout-link")
    with pytest.raises(AgentLoopError, match="unsafe entry"):
        read_codex_rollout_selection(
            codex_home,
            expected_thread_id=ROLLOUT_THREAD_ID,
        )

    symlink_home = tmp_path / "symlink-home"
    symlink_home.mkdir(mode=0o700)
    symlink_home.chmod(0o700)
    external_sessions = tmp_path / "external-sessions"
    external_sessions.mkdir(mode=0o700)
    (symlink_home / "sessions").symlink_to(external_sessions, target_is_directory=True)
    with pytest.raises(AgentLoopError, match="root cannot be opened safely"):
        read_codex_rollout_selection(
            symlink_home,
            expected_thread_id=ROLLOUT_THREAD_ID,
        )


def test_confined_rollout_reader_rejects_xattrs_and_ignores_compressed_decoy(
    tmp_path: Path,
) -> None:
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir(mode=0o700)
    rollout = install_rollout(codex_home, codex_rollout((ROLLOUT_TURN_IDS[0],)))
    compressed = rollout.with_name(
        "rollout-2026-07-21T01-49-44-019f825d-0000-7000-8000-000000000001.jsonl.zst"
    )
    compressed.write_bytes(b"opaque compressed decoy")
    compressed.chmod(0o600)
    assert (
        read_codex_rollout_selection(
            codex_home,
            expected_thread_id=ROLLOUT_THREAD_ID,
        ).model
        == "gpt-5.4"
    )

    try:
        os.setxattr(rollout, b"user.agent-loop-test", b"forbidden")
    except OSError as error:
        if error.errno in {errno.ENOTSUP, errno.EOPNOTSUPP, errno.EPERM}:
            pytest.skip("test filesystem does not support user xattrs")
        raise
    with pytest.raises(AgentLoopError, match="metadata is ambiguous"):
        read_codex_rollout_selection(
            codex_home,
            expected_thread_id=ROLLOUT_THREAD_ID,
        )


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
    stdout = (
        b"\n".join(
            (
                b'{"type":"thread.started","thread_id":"thread-safe"}',
                json.dumps({"type": "error", "message": secret}, separators=(",", ":")).encode(),
                json.dumps(
                    {"type": "turn.failed", "error": {"message": secret}},
                    separators=(",", ":"),
                ).encode(),
            )
        )
        + b"\n"
    )
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


def test_revoked_codex_session_has_fixed_one_step_reauthentication_guidance() -> None:
    stdout = (
        b'{"type":"thread.started","thread_id":"thread-safe"}\n'
        b'{"type":"turn.failed","error":{"message":"Your access token could not be '
        b'refreshed because your refresh token was revoked. Please log out and sign in again."}}\n'
    )
    result = BoundedProcessResult(1, stdout, b"private stderr", 1.0, 2.0, False, False)

    with pytest.raises(AgentLoopError) as caught:
        classify_codex_process_result(result)

    assert caught.value.reason is StopReason.CREDENTIAL_REFRESH_FAILURE
    assert caught.value.detail == (
        "Codex vendor session ended; run `codex login` once, then rerun. "
        "No `agent-loop auth` command is required."
    )
    assert "access token" not in caught.value.detail


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
    stdout = (
        b"\n".join(
            (
                b'{"type":"thread.started","thread_id":"thread-safe"}',
                json.dumps(last_event, separators=(",", ":")).encode(),
            )
        )
        + b"\n"
    )
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
