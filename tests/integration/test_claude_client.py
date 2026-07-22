import json
import shutil
import time
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from agent_loop.claude_client import (
    CLAUDE_REAUTHENTICATION_FAILURE_DETAIL,
    ClaudeClient,
    ClaudeInvocation,
    ClaudeTransport,
    build_claude_argv,
    build_claude_invocation,
)
from agent_loop.constants import CLAUDE_API_RETRIES, CLAUDE_STRUCTURED_OUTPUT_RETRIES
from agent_loop.credentials import build_claude_parent_environment
from agent_loop.errors import AgentLoopError, StopReason
from agent_loop.prompts import ReviewBundle
from agent_loop.schemas import (
    ApprovalContext,
    Verdict,
    critic_schema_document,
)
from agent_loop.service import BoundedProcessResult, run_bounded_process

_MAX_API_REQUEST_DETAILS = (CLAUDE_API_RETRIES + 1) * (CLAUDE_STRUCTURED_OUTPUT_RETRIES + 1)


def bundle() -> ReviewBundle:
    return ReviewBundle({}, b"{}", 2, "a" * 64)


def env() -> dict[str, str]:
    return build_claude_parent_environment(
        "dedicated-token", config_dir="/control/claude-home", tmp_dir="/runtime/critic-tmp"
    )


def process(
    payload: dict[str, object], *, code: int = 0, stderr: bytes = b""
) -> BoundedProcessResult:
    return BoundedProcessResult(code, json.dumps(payload).encode(), stderr, 1.0, 2.0, False, False)


def api_request_detail(
    *,
    model: str = "claude-pinned",
    effort: str | None = "high",
    extra: dict[str, object] | None = None,
    include_format: bool = False,
) -> bytes:
    output_config: dict[str, object] = {}
    if effort is not None:
        output_config["effort"] = effort
    if include_format:
        output_config["format"] = {
            "type": "json_schema",
            "schema": critic_schema_document(),
        }
    payload: dict[str, object] = {
        "model": model,
        "thinking": {"type": "adaptive", "display": "omitted"},
        "output_config": output_config,
        "betas": [],
    }
    if extra:
        payload.update(extra)
    return (
        b"2026-07-20T16:42:22.627Z [VERBOSE] [API REQUEST DETAIL] "
        + json.dumps(payload, separators=(",", ":")).encode()
        + b"\n"
    )


@pytest.fixture
def fake_claude(tmp_path: Path) -> Path:
    source = Path(__file__).parents[1] / "fakes" / "fake_claude.py"
    destination = tmp_path / "fake-claude"
    shutil.copyfile(source, destination)
    destination.chmod(0o755)
    return destination


def fake_transport(scenario: str) -> ClaudeTransport:
    def transport(
        invocation: ClaudeInvocation,
        timeout_seconds: float,
        output_max_bytes: int,
    ) -> BoundedProcessResult:
        environment = invocation.launch_environment()
        environment["AGENT_LOOP_FAKE_SCENARIO"] = scenario
        return run_bounded_process(
            invocation.argv,
            input_bytes=invocation.stdin,
            timeout_seconds=timeout_seconds,
            output_max_bytes=output_max_bytes,
            env=environment,
        )

    return transport


def lgtm() -> dict[str, object]:
    return {
        "type": "result",
        "structured_output": {
            "review": {
                "schema_version": 1,
                "verdict": "LGTM",
                "summary": "done",
                "blocked_reason": None,
                "blocking_findings": [],
                "non_blocking_findings": [],
            }
        },
    }


def test_048_critic_invocation_is_tool_disabled_and_fresh() -> None:
    invocation = build_claude_invocation(bundle(), env())
    argv = invocation.argv
    assert "--safe-mode" in argv
    assert "--no-session-persistence" in argv
    assert argv[argv.index("--tools") + 1] == ""
    assert argv[argv.index("--disallowedTools") + 1] == "mcp__*"
    assert "--max-turns" in argv and argv[argv.index("--max-turns") + 1] == "2"
    assert invocation.cwd == "/runtime/critic-cwd"


def test_050_hostile_claude_project_config_is_not_in_environment_or_cwd() -> None:
    invocation = build_claude_invocation(bundle(), env())
    launch = invocation.launch_environment()
    assert set(launch).isdisjoint({"CLAUDE_PROJECT_DIR", "MCP_CONFIG", "ANTHROPIC_API_KEY"})
    assert launch["HOME"] == "/runtime/home"


def test_051_retry_budget_is_exact_and_watchdog_absent() -> None:
    launch = build_claude_invocation(bundle(), env()).launch_environment()
    assert set(launch) == set(env()) | {
        "CLAUDE_CODE_MAX_RETRIES",
        "API_TIMEOUT_MS",
        "MAX_STRUCTURED_OUTPUT_RETRIES",
        "CLAUDE_CODE_DEBUG_LOG_LEVEL",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
    }
    assert launch["MAX_STRUCTURED_OUTPUT_RETRIES"] == "1"
    assert launch["CLAUDE_CODE_MAX_RETRIES"] == "2"
    assert launch["API_TIMEOUT_MS"] == "300000"
    assert launch["CLAUDE_CODE_DEBUG_LOG_LEVEL"] == "verbose"
    assert launch["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] == "1"
    assert "CLAUDE_CODE_RETRY_WATCHDOG" not in launch


@pytest.mark.parametrize("second_attempt_valid", [True, False])
def test_051_one_internal_schema_retry_is_bounded_and_never_becomes_an_outer_loop(
    second_attempt_valid: bool,
) -> None:
    invalid_payload = lgtm()
    invalid_wrapper = invalid_payload["structured_output"]
    assert isinstance(invalid_wrapper, dict)
    invalid_review = invalid_wrapper["review"]
    assert isinstance(invalid_review, dict)
    # Exercise Claude's wire-schema correction path with a structurally invalid
    # object. Cross-field verdict contradictions are intentionally deferred to
    # the independent local semantic validator because the Messages API rejects
    # top-level schema combinators.
    del invalid_review["summary"]
    invalid = process(invalid_payload)
    candidates = (invalid, process(lgtm()) if second_attempt_valid else invalid, process(lgtm()))
    transport_calls = 0
    schema_attempts = 0
    schema_validator = Draft7Validator(critic_schema_document())

    def transport(
        invocation: ClaudeInvocation,
        _timeout_seconds: float,
        _output_max_bytes: int,
    ) -> BoundedProcessResult:
        nonlocal schema_attempts, transport_calls
        transport_calls += 1
        retry_budget = int(invocation.launch_environment()["MAX_STRUCTURED_OUTPUT_RETRIES"])
        for attempt_index, candidate in enumerate(candidates):
            schema_attempts += 1
            candidate_envelope = json.loads(candidate.stdout)
            candidate_structured_output = candidate_envelope.get("structured_output")
            if not schema_validator.is_valid(candidate_structured_output):
                if attempt_index == retry_budget:
                    return process(
                        {
                            "type": "error",
                            "subtype": "error_max_structured_output_retries",
                        },
                        code=1,
                    )
                continue
            return candidate
        raise AssertionError("schema retry simulation exceeded its finite candidates")

    client = ClaudeClient(transport)
    if second_attempt_valid:
        result = client.review(
            bundle(),
            env(),
            approval=ApprovalContext(True, True, True),
            timeout_seconds=301,
        )
        assert result.review.verdict is Verdict.LGTM
    else:
        with pytest.raises(AgentLoopError) as caught:
            client.review(
                bundle(),
                env(),
                approval=ApprovalContext(True, True, True),
                timeout_seconds=301,
            )
        assert caught.value.reason is StopReason.STRUCTURED_OUTPUT_RETRIES

    assert schema_attempts == 2
    assert transport_calls == 1


@pytest.mark.parametrize(
    ("subtype", "reason"),
    [
        ("error_max_turns", StopReason.CRITIC_MAX_TURNS_EXHAUSTED),
        ("error_max_structured_output_retries", StopReason.STRUCTURED_OUTPUT_RETRIES),
    ],
)
def test_051_exhaustion_classification(subtype: str, reason: StopReason) -> None:
    client = ClaudeClient(
        lambda _inv, _timeout, _cap: process({"type": "error", "subtype": subtype}, code=1)
    )
    with pytest.raises(AgentLoopError) as caught:
        client.review(
            bundle(),
            env(),
            approval=ApprovalContext(True, True, True),
            timeout_seconds=301,
        )
    assert caught.value.reason is reason


@pytest.mark.parametrize(
    "payload",
    [
        {
            "type": "result",
            "subtype": "success",
            "is_error": True,
            "api_error_status": None,
            "result": "Not logged in \u00b7 Please run /login",
            "terminal_reason": "api_error",
        },
        {
            "type": "result",
            "subtype": "success",
            "is_error": True,
            "api_error_status": None,
            "result": "OAuth token revoked \u00b7 Please run /login",
            "terminal_reason": "api_error",
        },
        {
            "type": "result",
            "subtype": "success",
            "is_error": True,
            "api_error_status": None,
            "result": "Login expired \u00b7 Please run /login",
            "terminal_reason": "api_error",
        },
        {
            "type": "result",
            "subtype": "success",
            "is_error": True,
            "api_error_status": None,
            "result": "Failed to authenticate: OAuth session expired and could not be refreshed",
            "terminal_reason": "api_error",
        },
        {
            "type": "result",
            "subtype": "success",
            "is_error": True,
            "api_error_status": 401,
            "result": "Failed to authenticate. API Error: 401 Invalid bearer token",
            "terminal_reason": "api_error",
        },
    ],
    ids=[
        "not-logged-in",
        "oauth-revoked",
        "login-expired",
        "oauth-refresh-expired",
        "http-401",
    ],
)
def test_claude_authentication_envelopes_require_one_normal_vendor_login(
    payload: dict[str, object],
) -> None:
    client = ClaudeClient(lambda _inv, _timeout, _cap: process(payload, code=1))

    with pytest.raises(AgentLoopError) as caught:
        client.review(
            bundle(),
            env(),
            approval=ApprovalContext(True, True, True),
            timeout_seconds=301,
        )

    assert caught.value.reason is StopReason.CREDENTIAL_REFRESH_FAILURE
    assert caught.value.detail == CLAUDE_REAUTHENTICATION_FAILURE_DETAIL


@pytest.mark.parametrize(
    "payload",
    [
        {
            "type": "result",
            "subtype": "success",
            "is_error": True,
            "api_error_status": 403,
            "result": "Not logged in \u00b7 Please run /login",
            "terminal_reason": "api_error",
        },
        {
            "type": "result",
            "subtype": "success",
            "is_error": True,
            "api_error_status": None,
            "result": "Not logged in - Please run /login",
            "terminal_reason": "api_error",
        },
        {
            "type": "result",
            "subtype": "success",
            "is_error": True,
            "api_error_status": None,
            "result": "Failed to authenticate: OAuth session expired and could not be refreshed.",
            "terminal_reason": "api_error",
        },
        {
            "type": "result",
            "subtype": "success",
            "is_error": True,
            "api_error_status": 401,
            "result": "untrusted-marker",
            "terminal_reason": "other",
        },
        {
            "type": "error",
            "subtype": "success",
            "is_error": True,
            "api_error_status": 401,
            "result": "untrusted-marker",
            "terminal_reason": "api_error",
        },
        {
            "type": "result",
            "subtype": "success",
            "is_error": True,
            "api_error_status": 401.0,
            "result": {"hostile": "untrusted-marker"},
            "terminal_reason": "api_error",
        },
    ],
    ids=[
        "non-401-status",
        "near-local-marker",
        "near-oauth-refresh-marker",
        "wrong-terminal-reason",
        "wrong-envelope-type",
        "non-integer-status-and-non-string-result",
    ],
)
def test_claude_authentication_classification_fails_closed_on_near_matches(
    payload: dict[str, object],
) -> None:
    with pytest.raises(AgentLoopError) as caught:
        ClaudeClient(lambda _inv, _timeout, _cap: process(payload, code=1)).review(
            bundle(),
            env(),
            approval=ApprovalContext(True, True, True),
            timeout_seconds=301,
        )

    assert caught.value.reason is StopReason.CRITIC_PROCESS_FAILURE
    assert "untrusted-marker" not in caught.value.detail


def test_valid_envelope_is_locally_revalidated() -> None:
    client = ClaudeClient(lambda _inv, _timeout, _cap: process(lgtm()))
    result = client.review(
        bundle(), env(), approval=ApprovalContext(True, True, True), timeout_seconds=301
    )
    assert result.review.verdict is Verdict.LGTM


@pytest.mark.parametrize(
    ("scenario", "verdict"),
    [
        ("lgtm", Verdict.LGTM),
        ("revise", Verdict.REVISE),
        ("blocked", Verdict.BLOCKED),
        ("hostile-revise", Verdict.REVISE),
    ],
)
def test_fake_claude_process_round_trips_real_argv_stdin_and_envelope_parser(
    fake_claude: Path,
    scenario: str,
    verdict: Verdict,
) -> None:
    result = ClaudeClient(fake_transport(scenario)).review(
        bundle(),
        env(),
        approval=ApprovalContext(True, True, True),
        timeout_seconds=301,
        executable=str(fake_claude),
    )
    assert result.review.verdict is verdict
    assert b"dedicated-token" not in json.dumps(result.envelope).encode()
    if scenario == "hostile-revise":
        assert "quoted-hostile-marker" in result.review.blocking_findings[0].required_fix


@pytest.mark.parametrize(
    ("scenario", "reason"),
    [
        ("malformed", StopReason.INVALID_STRUCTURED_OUTPUT),
        ("top-level-array", StopReason.INVALID_STRUCTURED_OUTPUT),
        ("duplicate-envelope-key", StopReason.INVALID_STRUCTURED_OUTPUT),
        ("missing", StopReason.INVALID_STRUCTURED_OUTPUT),
        ("structured-not-object", StopReason.INVALID_STRUCTURED_OUTPUT),
        ("invalid-verdict", StopReason.INVALID_STRUCTURED_OUTPUT),
        ("wrong-schema", StopReason.INVALID_STRUCTURED_OUTPUT),
        ("unknown-field", StopReason.INVALID_STRUCTURED_OUTPUT),
        ("missing-field", StopReason.INVALID_STRUCTURED_OUTPUT),
        ("lgtm-blocking", StopReason.INVALID_STRUCTURED_OUTPUT),
        ("revise-empty", StopReason.INVALID_STRUCTURED_OUTPUT),
        ("blocked-no-reason", StopReason.INVALID_STRUCTURED_OUTPUT),
        ("finding-range", StopReason.INVALID_STRUCTURED_OUTPUT),
        ("oversized-summary", StopReason.INVALID_STRUCTURED_OUTPUT),
        ("error-envelope", StopReason.CRITIC_PROCESS_FAILURE),
        ("is-error-result", StopReason.CRITIC_PROCESS_FAILURE),
        ("max_turns", StopReason.CRITIC_MAX_TURNS_EXHAUSTED),
        ("structured_retries", StopReason.STRUCTURED_OUTPUT_RETRIES),
    ],
)
def test_fake_claude_process_failure_scenarios_are_typed(
    fake_claude: Path,
    scenario: str,
    reason: StopReason,
) -> None:
    with pytest.raises(AgentLoopError) as caught:
        ClaudeClient(fake_transport(scenario)).review(
            bundle(),
            env(),
            approval=ApprovalContext(True, True, True),
            timeout_seconds=301,
            executable=str(fake_claude),
        )
    assert caught.value.reason is reason


def test_phase3_fake_claude_late_scenario_records_real_process_completion(
    fake_claude: Path,
) -> None:
    started = time.monotonic()
    result = ClaudeClient(fake_transport("late")).review(
        bundle(),
        env(),
        approval=ApprovalContext(True, True, True),
        timeout_seconds=301,
        executable=str(fake_claude),
    )

    assert result.review.verdict is Verdict.LGTM
    assert result.completed_at >= started + 0.08


def test_command_has_exact_tool_and_schema_flags() -> None:
    argv = build_claude_argv(model="claude-pinned", effort="high")
    assert argv[argv.index("--model") + 1] == "claude-pinned"
    assert argv[argv.index("--effort") + 1] == "high"
    assert argv[argv.index("--debug") + 1] == "api"
    assert "--debug-to-stderr" in argv
    assert argv.index("--debug-to-stderr") < argv.index("--output-format")
    assert argv[-2] != ""
    assert argv[-1].startswith("You are the independent")


@pytest.mark.parametrize("include_format", [False, True])
def test_api_request_diagnostic_records_exact_model_and_effort(
    include_format: bool,
) -> None:
    stderr = b"2026-07-20T16:42:22.000Z [VERBOSE] harmless diagnostic\n" + api_request_detail(
        include_format=include_format
    )
    result = ClaudeClient(lambda _inv, _timeout, _cap: process(lgtm(), stderr=stderr)).review(
        bundle(),
        env(),
        approval=ApprovalContext(True, True, True),
        timeout_seconds=301,
        model="claude-pinned",
        effort="high",
    )

    assert result.observed_model == "claude-pinned"
    assert result.observed_effort == "high"


def test_api_request_diagnostics_allow_the_complete_exact_retry_budget() -> None:
    stderr = api_request_detail() * _MAX_API_REQUEST_DETAILS
    result = ClaudeClient(lambda _inv, _timeout, _cap: process(lgtm(), stderr=stderr)).review(
        bundle(),
        env(),
        approval=ApprovalContext(True, True, True),
        timeout_seconds=301,
        model="claude-pinned",
        effort="high",
    )

    assert result.observed_model == "claude-pinned"
    assert result.observed_effort == "high"


@pytest.mark.parametrize(
    "stderr",
    [
        b"",
        b'spoof [API REQUEST DETAIL] {"model":"claude-pinned"}\n',
        api_request_detail(model="claude-other"),
        api_request_detail(effort="medium"),
        api_request_detail() + api_request_detail(effort=None),
        api_request_detail(extra={"prompt": "secret-canary"}),
        api_request_detail(
            extra={
                "output_config": {
                    "effort": "high",
                    "format": {
                        "type": "json_schema",
                        "schema": {
                            "type": "object",
                            "properties": {"title": {"type": "string"}},
                            "required": ["title"],
                            "additionalProperties": False,
                        },
                    },
                }
            }
        ),
        api_request_detail() + api_request_detail(model="claude-other", effort="medium"),
        api_request_detail() * (_MAX_API_REQUEST_DETAILS + 1),
        (
            b"2026-07-20T16:42:22.627Z [VERBOSE] [API REQUEST DETAIL] "
            b'{"model":"claude-pinned","model":"claude-pinned",'
            b'"output_config":{"effort":"high"}}\n'
        ),
    ],
    ids=[
        "missing",
        "spoofed-framing",
        "wrong-model",
        "wrong-effort",
        "effort-removed-on-retry",
        "unknown-field",
        "wrong-output-schema",
        "conflicting-retry",
        "retry-budget-exceeded",
        "duplicate-key",
    ],
)
def test_api_request_diagnostics_fail_closed_without_echoing_raw_data(
    stderr: bytes,
) -> None:
    with pytest.raises(AgentLoopError) as caught:
        ClaudeClient(lambda _inv, _timeout, _cap: process(lgtm(), stderr=stderr)).review(
            bundle(),
            env(),
            approval=ApprovalContext(True, True, True),
            timeout_seconds=301,
            model="claude-pinned",
            effort="high",
        )

    assert caught.value.reason is StopReason.SANDBOX_SETUP_FAILURE
    assert "secret-canary" not in caught.value.detail


@pytest.mark.parametrize("field", ["model", "effort"])
def test_model_and_effort_reject_unsafe_identifiers(field: str) -> None:
    with pytest.raises(ValueError):
        build_claude_argv(**{field: "../unsafe value"})
