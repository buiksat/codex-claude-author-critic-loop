"""Pinned fresh, tool-disabled Claude critic protocol adapter."""

from __future__ import annotations

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
from .errors import StopReason, fail
from .prompts import CRITIC_PROMPT, ReviewBundle
from .schemas import (
    ApprovalContext,
    CriticReview,
    critic_schema_json,
    parse_critic_envelope,
    parse_json_object,
)
from .service import BoundedProcessResult

ClaudeTransport = Callable[["ClaudeInvocation", float, int], BoundedProcessResult]

_MODEL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_EFFORT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


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
        return ClaudeReviewResult(
            review=review,
            envelope=envelope,
            usage=ClaudeUsage(cost, model_usage_raw),
            completed_at=result.completed_at,
        )
