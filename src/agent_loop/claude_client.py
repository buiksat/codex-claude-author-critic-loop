"""Pinned fresh, tool-disabled Claude critic protocol adapter."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from .constants import (
    CLAUDE_API_RETRIES,
    CLAUDE_API_TIMEOUT_MS,
    CLAUDE_MAX_TURNS,
    CLAUDE_STRUCTURED_OUTPUT_RETRIES,
    DEFAULT_MAX_AGENT_OUTPUT_BYTES,
)
from .errors import AgentLoopError, StopReason, fail
from .prompts import CRITIC_PROMPT, ReviewBundle
from .schemas import (
    ApprovalContext,
    CriticReview,
    critic_schema_document,
    critic_schema_json,
    parse_critic_envelope,
    parse_json_object,
)
from .service import BoundedProcessResult

ClaudeTransport = Callable[["ClaudeInvocation", float, int], BoundedProcessResult]

_MODEL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_EFFORT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_API_REQUEST_DETAIL_LINE = re.compile(
    rb"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z "
    rb"\[VERBOSE\] \[API REQUEST DETAIL\] (?P<payload>\{.*\})$"
)
_API_REQUEST_DETAIL_MARKER = b"[API REQUEST DETAIL]"
_API_REQUEST_DETAIL_FIELDS = frozenset(
    {"model", "thinking", "output_config", "temperature", "betas", "anthropic_beta"}
)
_MAX_API_REQUEST_DETAIL_BYTES = 128 * 1_024
_MAX_API_REQUEST_DETAILS = (CLAUDE_API_RETRIES + 1) * (
    CLAUDE_STRUCTURED_OUTPUT_RETRIES + 1
)


@dataclass(frozen=True, slots=True)
class ClaudeInvocation:
    argv: tuple[str, ...]
    stdin: bytes
    cwd: str
    _environment: dict[str, str] = field(repr=False)

    def launch_environment(self) -> dict[str, str]:
        """Return a copy so callers cannot mutate the recorded launch contract."""

        return dict(self._environment)


@dataclass(frozen=True, slots=True)
class ClaudeUsage:
    total_cost_usd: float | None
    model_usage: dict[str, object]


@dataclass(frozen=True, slots=True)
class ClaudeReviewResult:
    review: CriticReview
    envelope: dict[str, object]
    usage: ClaudeUsage
    completed_at: float
    observed_model: str | None
    observed_effort: str | None


def build_claude_argv(
    executable: str = "/usr/local/bin/claude",
    *,
    model: str | None = None,
    effort: str | None = None,
) -> tuple[str, ...]:
    if not executable.startswith("/") or "\x00" in executable:
        raise ValueError("Claude executable must be an absolute reviewed path")
    if model is not None and _MODEL_ID.fullmatch(model) is None:
        raise ValueError("Claude model must be an explicit safe identifier")
    if effort is not None and _EFFORT.fullmatch(effort) is None:
        raise ValueError("Claude effort must be an explicit safe identifier")
    selection: tuple[str, ...] = ()
    if model is not None:
        selection += ("--model", model)
    if effort is not None:
        selection += ("--effort", effort)
    return (
        executable,
        "--safe-mode",
        "-p",
        *selection,
        "--no-session-persistence",
        "--permission-mode",
        "dontAsk",
        "--tools",
        "",
        "--disallowedTools",
        "mcp__*",
        "--max-turns",
        str(CLAUDE_MAX_TURNS),
        "--debug",
        "api",
        "--debug-to-stderr",
        "--output-format",
        "json",
        "--json-schema",
        critic_schema_json(),
        CRITIC_PROMPT,
    )


def complete_claude_environment(parent: Mapping[str, str]) -> dict[str, str]:
    """Add pinned retry controls to an already allowlisted credential environment."""

    required = {
        "PATH",
        "HOME",
        "TMPDIR",
        "LANG",
        "CLAUDE_CONFIG_DIR",
        "CLAUDE_CODE_TMPDIR",
        "CLAUDE_CODE_OAUTH_TOKEN",
        "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB",
    }
    if set(parent) != required:
        raise ValueError("Claude parent environment is not the dedicated allowlist")
    if parent["CLAUDE_CODE_SUBPROCESS_ENV_SCRUB"] != "1":
        raise ValueError("Claude subprocess credential scrubbing must be enabled")
    result = dict(parent)
    result.update(
        {
            "CLAUDE_CODE_MAX_RETRIES": str(CLAUDE_API_RETRIES),
            "API_TIMEOUT_MS": str(CLAUDE_API_TIMEOUT_MS),
            "MAX_STRUCTURED_OUTPUT_RETRIES": str(CLAUDE_STRUCTURED_OUTPUT_RETRIES),
            "CLAUDE_CODE_DEBUG_LOG_LEVEL": "verbose",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        }
    )
    if "CLAUDE_CODE_RETRY_WATCHDOG" in result:
        raise ValueError("Claude retry watchdog must remain absent")
    return result


def build_claude_invocation(
    bundle: ReviewBundle,
    parent_environment: Mapping[str, str],
    *,
    executable: str = "/usr/local/bin/claude",
    cwd: str = "/runtime/critic-cwd",
    model: str | None = None,
    effort: str | None = None,
) -> ClaudeInvocation:
    if not cwd.startswith("/") or ".." in Path(cwd).parts:
        raise ValueError("Claude cwd must be an absolute normalized private directory")
    return ClaudeInvocation(
        argv=build_claude_argv(executable, model=model, effort=effort),
        stdin=bundle.encoded,
        cwd=cwd,
        _environment=complete_claude_environment(parent_environment),
    )


def _classify_envelope_failure(data: bytes) -> None:
    """Classify workflow/retry/max-turn errors before structured output parsing."""

    envelope = parse_json_object(data)
    subtype = envelope.get("subtype")
    stop_reason = envelope.get("stop_reason")
    if subtype in {"error_max_turns", "max_turns"} or stop_reason == "max_turns":
        raise fail(StopReason.CRITIC_MAX_TURNS_EXHAUSTED, "Claude exhausted its max-turn budget")
    if subtype in {
        "error_max_structured_output_retries",
        "structured_output_retries_exhausted",
    }:
        raise fail(
            StopReason.STRUCTURED_OUTPUT_RETRIES,
            "Claude exhausted its structured-output retry budget",
        )
    if envelope.get("is_error") is True or envelope.get("type") == "error":
        raise fail(StopReason.CRITIC_PROCESS_FAILURE, "Claude returned an error envelope")


def _duplicate_rejecting_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate property {key!r}")
        result[key] = value
    return result


def _reject_non_finite(token: str) -> None:
    raise ValueError(f"non-finite number {token}")


def _selection_failure(detail: str) -> AgentLoopError:
    return fail(StopReason.SANDBOX_SETUP_FAILURE, detail)


def _parse_api_request_selection(
    stderr: bytes,
    *,
    requested_model: str | None,
    requested_effort: str | None,
) -> tuple[str | None, str | None]:
    """Extract pinned-CLI request selection evidence from safe verbose diagnostics."""

    observed_model: str | None = None
    observed_effort: str | None = None
    request_count = 0
    for line in stderr.splitlines():
        if _API_REQUEST_DETAIL_MARKER not in line:
            continue
        if len(line) > _MAX_API_REQUEST_DETAIL_BYTES:
            raise _selection_failure("Claude API request diagnostic exceeded its byte limit")
        match = _API_REQUEST_DETAIL_LINE.fullmatch(line)
        if match is None:
            raise _selection_failure("Claude API request diagnostic had an invalid framing")
        try:
            detail = json.loads(
                match.group("payload").decode("utf-8", "strict"),
                object_pairs_hook=_duplicate_rejecting_object,
                parse_constant=_reject_non_finite,
            )
        except (UnicodeDecodeError, ValueError, RecursionError) as exc:
            raise _selection_failure("Claude API request diagnostic was invalid JSON") from exc
        if not isinstance(detail, dict):
            raise _selection_failure("Claude API request diagnostic was not an object")
        if not set(detail).issubset(_API_REQUEST_DETAIL_FIELDS):
            raise _selection_failure("Claude API request diagnostic had unknown fields")

        raw_model = detail.get("model")
        output_config = detail.get("output_config")
        if (
            not isinstance(raw_model, str)
            or _MODEL_ID.fullmatch(raw_model) is None
            or not isinstance(output_config, dict)
            or not set(output_config).issubset({"effort", "format"})
        ):
            raise _selection_failure("Claude API request diagnostic had invalid selection fields")
        output_format = output_config.get("format")
        if output_format is not None:
            try:
                format_matches = output_format == {
                    "type": "json_schema",
                    "schema": critic_schema_document(),
                }
            except RecursionError:
                format_matches = False
            if not format_matches:
                raise _selection_failure(
                    "Claude API request diagnostic had an invalid structured-output format"
                )
        raw_effort = output_config.get("effort")
        if raw_effort is not None and (
            not isinstance(raw_effort, str) or _EFFORT.fullmatch(raw_effort) is None
        ):
            raise _selection_failure("Claude API request diagnostic had invalid effort")

        if requested_model is not None and raw_model != requested_model:
            raise _selection_failure("Claude API request used a different model than requested")
        if requested_effort is not None and raw_effort != requested_effort:
            raise _selection_failure("Claude API request used a different effort than requested")
        if observed_model is not None and raw_model != observed_model:
            raise _selection_failure("Claude API retries used conflicting models")
        if request_count and raw_effort != observed_effort:
            raise _selection_failure("Claude API retries used conflicting efforts")

        observed_model = raw_model
        observed_effort = raw_effort
        request_count += 1
        if request_count > _MAX_API_REQUEST_DETAILS:
            raise _selection_failure(
                "Claude API request diagnostics exceeded the bounded retry budget"
            )

    if requested_model is not None or requested_effort is not None:
        if request_count == 0:
            raise _selection_failure("Claude emitted no API request selection diagnostic")
    return observed_model, observed_effort


class ClaudeClient:
    def __init__(self, transport: ClaudeTransport) -> None:
        self._transport = transport

    def review(
        self,
        bundle: ReviewBundle,
        parent_environment: Mapping[str, str],
        *,
        approval: ApprovalContext,
        timeout_seconds: float,
        executable: str = "/usr/local/bin/claude",
        model: str | None = None,
        effort: str | None = None,
    ) -> ClaudeReviewResult:
        if timeout_seconds * 1000 <= CLAUDE_API_TIMEOUT_MS:
            raise ValueError("outer critic timeout must exceed API_TIMEOUT_MS")
        invocation = build_claude_invocation(
            bundle,
            parent_environment,
            executable=executable,
            model=model,
            effort=effort,
        )
        result = self._transport(invocation, timeout_seconds, DEFAULT_MAX_AGENT_OUTPUT_BYTES)
        if result.output_limited:
            raise fail(StopReason.AGENT_OUTPUT_LIMIT, "Claude output exceeded its byte limit")
        if result.timed_out:
            raise fail(StopReason.CRITIC_TIMEOUT, "Claude exceeded the outer critic timeout")
        # A bounded JSON error envelope may provide a more precise process reason.
        if result.stdout:
            _classify_envelope_failure(result.stdout)
        if result.returncode != 0:
            raise fail(
                StopReason.CRITIC_PROCESS_FAILURE,
                f"Claude process exited unsuccessfully ({result.returncode})",
            )
        envelope, review = parse_critic_envelope(result.stdout, approval=approval)
        cost_raw = envelope.get("total_cost_usd")
        if cost_raw is None:
            cost = None
        elif (
            isinstance(cost_raw, (int, float))
            and not isinstance(cost_raw, bool)
            and math.isfinite(float(cost_raw))
            and float(cost_raw) >= 0
        ):
            cost = float(cost_raw)
        else:
            raise fail(StopReason.INVALID_STRUCTURED_OUTPUT, "invalid Claude cost metadata")
        model_usage_raw = envelope.get("modelUsage", {})
        if not isinstance(model_usage_raw, dict) or len(model_usage_raw) > 64:
            raise fail(StopReason.INVALID_STRUCTURED_OUTPUT, "invalid Claude model-usage metadata")
        observed_model, observed_effort = _parse_api_request_selection(
            result.stderr,
            requested_model=model,
            requested_effort=effort,
        )
        return ClaudeReviewResult(
            review=review,
            envelope=envelope,
            usage=ClaudeUsage(cost, model_usage_raw),
            completed_at=result.completed_at,
            observed_model=observed_model,
            observed_effort=observed_effort,
        )
