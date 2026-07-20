"""Pinned Git-less Codex author protocol adapter.

This module constructs and parses the trusted Codex control process.  It does
not provide a direct host launcher: production callers must supply the proven
author sandbox/service transport.
"""

from __future__ import annotations

import json
import math
import os
import re
import tomllib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from .constants import DEFAULT_MAX_AGENT_OUTPUT_BYTES, DEFAULT_MAX_FIELD_BYTES, PRIVATE_FILE_MODE
from .credentials import CodexCredentialTransaction
from .errors import StopReason, fail
from .filesystem import ConfinedFilesystem
from .models import path_matches_pattern
from .service import BoundedProcessResult

CodexTransport = Callable[["CodexInvocation", float, int], BoundedProcessResult]

AUTHOR_CWD = "/runtime/author-cwd"
AUTHOR_WORKSPACE = "/workspace"
SANDBOX_CODEX_HOME = "/control/codex-home"
AUTHOR_PERMISSION_PROFILE = "agent_loop_author"

_MODEL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_EFFORT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_THREAD_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,255}$")
_MAX_JSONL_EVENTS = 100_000
_MAX_JSONL_LINE_BYTES = 2 * 1024 * 1024
_FIXED_WORKSPACE_DENIES = (
    ".git",
    ".git/**",
    "**/.git",
    "**/.git/**",
    ".codex",
    ".codex/**",
    "AGENTS.md",
    "AGENTS.override.md",
    "**/AGENTS.md",
    "**/AGENTS.override.md",
)
_FIXED_GIT_DENIES = frozenset(_FIXED_WORKSPACE_DENIES[:4])
_ALLOWED_CODEX_HOME_NAMES = {b"auth.json", b"config.toml", b"sessions"}


def _quoted(value: str) -> str:
    if not isinstance(value, str) or "\x00" in value:
        raise ValueError("TOML values must be NUL-free strings")
    return json.dumps(value, ensure_ascii=True)


def _validate_workspace_pattern(pattern: str) -> None:
    if not isinstance(pattern, str) or not pattern or "\x00" in pattern:
        raise ValueError("workspace deny patterns must be non-empty NUL-free strings")
    if pattern.startswith("/") or "\\" in pattern:
        raise ValueError("workspace deny patterns must be relative POSIX patterns")
    if any(component in {"", ".", ".."} for component in pattern.split("/")):
        raise ValueError("workspace deny patterns contain an ambiguous component")


def _validate_host_deny(path: str) -> None:
    if not isinstance(path, str) or "\x00" in path:
        raise ValueError("host denies must be NUL-free strings")
    parsed = PurePosixPath(path)
    if (
        not parsed.is_absolute()
        or str(parsed) == "/"
        or str(parsed) != path
        or ".." in parsed.parts
    ):
        raise ValueError("host denies must be normalized non-root absolute paths")


def _deny_blocks_opt_in(pattern: str, path: str) -> bool:
    pattern_bytes = pattern.encode("utf-8")
    path_bytes = path.encode("utf-8")
    if path_matches_pattern(path_bytes, pattern_bytes):
        return True
    return not any(character in pattern for character in "*?[") and path.startswith(
        pattern.rstrip("/") + "/"
    )


@dataclass(frozen=True, slots=True)
class SanitizedCodexConfig:
    """Only reviewed settings admitted to the transactional ``CODEX_HOME``."""

    model: str | None = None
    effort: str | None = None
    additional_workspace_denies: tuple[str, ...] = ()
    workspace_opt_ins: tuple[str, ...] = ()
    additional_host_denies: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.model is not None and _MODEL_ID.fullmatch(self.model) is None:
            raise ValueError("Codex model must be an explicit safe identifier")
        if self.effort is not None and _EFFORT.fullmatch(self.effort) is None:
            raise ValueError("Codex effort must be an explicit safe identifier")
        if not all(
            isinstance(values, tuple)
            for values in (
                self.additional_workspace_denies,
                self.workspace_opt_ins,
                self.additional_host_denies,
            )
        ):
            raise TypeError("Codex deny collections must be immutable tuples")
        for pattern in self.additional_workspace_denies:
            _validate_workspace_pattern(pattern)
        for path in self.workspace_opt_ins:
            _validate_workspace_pattern(path)
            if any(character in path for character in "*?["):
                raise ValueError("Codex protected opt-ins must name exact paths")
            if path == ".git" or path.startswith(".git/") or "/.git/" in path:
                raise ValueError("Codex protected opt-ins cannot expose a Git control path")
        for path in self.additional_host_denies:
            _validate_host_deny(path)
        if len(set(self.additional_workspace_denies)) != len(self.additional_workspace_denies):
            raise ValueError("workspace deny patterns contain duplicates")
        if len(set(self.workspace_opt_ins)) != len(self.workspace_opt_ins):
            raise ValueError("workspace protected opt-ins contain duplicates")
        if len(set(self.additional_host_denies)) != len(self.additional_host_denies):
            raise ValueError("host deny paths contain duplicates")

    def render(self) -> bytes:
        candidates = tuple(
            dict.fromkeys((*_FIXED_WORKSPACE_DENIES, *self.additional_workspace_denies))
        )
        workspace_denies = tuple(
            pattern
            for pattern in candidates
            if pattern in _FIXED_GIT_DENIES
            or not any(
                _deny_blocks_opt_in(pattern, path)
                for path in self.workspace_opt_ins
            )
        )
        lines: list[str] = []
        if self.model is not None:
            lines.append(f"model = {_quoted(self.model)}")
        if self.effort is not None:
            lines.append(f"model_reasoning_effort = {_quoted(self.effort)}")
        lines.extend(
            (
                f'default_permissions = "{AUTHOR_PERMISSION_PROFILE}"',
                'approval_policy = "never"',
                'web_search = "disabled"',
                'cli_auth_credentials_store = "file"',
                "",
                "[features]",
                "hooks = false",
                "",
                f'[projects."{AUTHOR_WORKSPACE}"]',
                'trust_level = "untrusted"',
                "",
                "[shell_environment_policy]",
                'inherit = "none"',
                "set = { PATH = \"/usr/local/bin:/usr/bin:/bin\", "
                'HOME = "/runtime/home", TMPDIR = "/runtime/tmp", LANG = "C.UTF-8" }',
                "",
                f"[permissions.{AUTHOR_PERMISSION_PROFILE}]",
                'description = "Bounded author workspace with no Git control plane"',
                'extends = ":workspace"',
                "",
                f"[permissions.{AUTHOR_PERMISSION_PROFILE}.filesystem]",
                "glob_scan_max_depth = 128",
                '":tmpdir" = "deny"',
                '":slash_tmp" = "deny"',
                '"/control" = "deny"',
            )
        )
        lines.extend(f"{_quoted(path)} = \"deny\"" for path in self.additional_host_denies)
        lines.extend(
            (
                "",
                f'[permissions.{AUTHOR_PERMISSION_PROFILE}.filesystem.":workspace_roots"]',
            )
        )
        lines.extend(f"{_quoted(pattern)} = \"deny\"" for pattern in workspace_denies)
        lines.extend(
            (
                "",
                f"[permissions.{AUTHOR_PERMISSION_PROFILE}.network]",
                "enabled = false",
                "",
            )
        )
        encoded = "\n".join(lines).encode("ascii")
        _validate_rendered_config(encoded, self)
        return encoded


def _validate_rendered_config(data: bytes, expected: SanitizedCodexConfig) -> None:
    try:
        parsed = tomllib.loads(data.decode("ascii"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        raise ValueError("generated Codex config is not valid TOML") from None
    if parsed.get("default_permissions") != AUTHOR_PERMISSION_PROFILE:
        raise ValueError("generated Codex config lost the mandatory permission profile")
    if parsed.get("approval_policy") != "never" or parsed.get("web_search") != "disabled":
        raise ValueError("generated Codex config weakened approval or search policy")
    if parsed.get("cli_auth_credentials_store") != "file":
        raise ValueError("generated Codex config selected an unsupported credential adapter")
    if parsed.get("features") != {"hooks": False}:
        raise ValueError("generated Codex config did not disable hooks")
    shell_policy = parsed.get("shell_environment_policy")
    if not isinstance(shell_policy, dict) or shell_policy.get("inherit") != "none":
        raise ValueError("generated Codex config did not scrub command environments")
    permissions = parsed.get("permissions")
    if not isinstance(permissions, dict):
        raise ValueError("generated Codex config omitted permissions")
    profile = permissions.get(AUTHOR_PERMISSION_PROFILE)
    if not isinstance(profile, dict) or profile.get("extends") != ":workspace":
        raise ValueError("generated Codex config does not extend :workspace")
    filesystem = profile.get("filesystem")
    if not isinstance(filesystem, dict) or filesystem.get("glob_scan_max_depth") != 128:
        raise ValueError("generated Codex profile lost its bounded deny-glob expansion")
    for path in (":tmpdir", ":slash_tmp", "/control", *expected.additional_host_denies):
        if filesystem.get(path) != "deny":
            raise ValueError("generated Codex profile lost a host filesystem deny")
    workspace = filesystem.get(":workspace_roots")
    candidates = {
        *_FIXED_WORKSPACE_DENIES,
        *expected.additional_workspace_denies,
    }
    required_workspace_denies = {
        pattern
        for pattern in candidates
        if pattern in _FIXED_GIT_DENIES
        or not any(
            _deny_blocks_opt_in(pattern, path)
            for path in expected.workspace_opt_ins
        )
    }
    if not isinstance(workspace, dict) or any(
        workspace.get(path) != "deny" for path in required_workspace_denies
    ):
        raise ValueError("generated Codex profile lost a workspace filesystem deny")
    network = profile.get("network")
    if not isinstance(network, dict) or network.get("enabled") is not False:
        raise ValueError("generated Codex profile did not disable generated-command network")
    if expected.model is not None and parsed.get("model") != expected.model:
        raise ValueError("generated Codex config lost the requested model")
    if expected.effort is not None and parsed.get("model_reasoning_effort") != expected.effort:
        raise ValueError("generated Codex config lost the requested effort")


def install_sanitized_codex_config(
    transaction: CodexCredentialTransaction,
    config: SanitizedCodexConfig,
) -> Path:
    """Install config in the locked transaction home, rejecting ambient state."""

    if not isinstance(transaction, CodexCredentialTransaction):
        raise TypeError("transaction must be a CodexCredentialTransaction")
    if not isinstance(config, SanitizedCodexConfig):
        raise TypeError("config must be a SanitizedCodexConfig")
    filesystem = ConfinedFilesystem.open(transaction.codex_home)
    try:
        directory_fd = filesystem.open_directory()
        try:
            names = {os.fsencode(name) for name in os.listdir(directory_fd)}
        finally:
            os.close(directory_fd)
        unexpected = names - _ALLOWED_CODEX_HOME_NAMES
        if unexpected:
            raise fail(
                StopReason.PROJECT_INSTRUCTION_ISOLATION,
                "transactional Codex home contains unreviewed ambient state",
            )
        filesystem.atomic_write(
            b"config.toml",
            config.render(),
            mode=PRIVATE_FILE_MODE,
            create_parents=False,
        )
    finally:
        filesystem.close()
    return transaction.codex_home / "config.toml"


def _normalized_absolute(value: str, *, name: str) -> str:
    if not isinstance(value, str) or "\x00" in value:
        raise ValueError(f"{name} must be an absolute NUL-free path")
    parsed = PurePosixPath(value)
    if (
        not parsed.is_absolute()
        or str(parsed) == "/"
        or str(parsed) != value
        or ".." in parsed.parts
    ):
        raise ValueError(f"{name} must be a normalized non-root absolute path")
    return value


def build_codex_parent_environment(
    *,
    codex_home: str = SANDBOX_CODEX_HOME,
    ambient: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Build the complete parent allowlist without copying ambient values."""

    del ambient
    return {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": "/runtime/home",
        "TMPDIR": "/runtime/tmp",
        "LANG": "C.UTF-8",
        "CODEX_HOME": _normalized_absolute(codex_home, name="CODEX_HOME"),
    }


def _validate_executable(executable: str) -> str:
    return _normalized_absolute(executable, name="Codex executable")


def _validate_prompt(prompt: str) -> str:
    if not isinstance(prompt, str) or not prompt or "\x00" in prompt:
        raise ValueError("Codex prompt must be a non-empty NUL-free string")
    if len(prompt.encode("utf-8")) > DEFAULT_MAX_FIELD_BYTES:
        raise ValueError("Codex prompt exceeds max_field_bytes")
    return prompt


def _author_prefix(executable: str) -> tuple[str, ...]:
    return (
        _validate_executable(executable),
        "-a",
        "never",
        "-C",
        AUTHOR_CWD,
        "--add-dir",
        AUTHOR_WORKSPACE,
        "-c",
        f'default_permissions="{AUTHOR_PERMISSION_PROFILE}"',
    )


def build_codex_first_argv(
    prompt: str,
    *,
    executable: str = "/usr/local/bin/codex",
) -> tuple[str, ...]:
    return (
        *_author_prefix(executable),
        "exec",
        "--json",
        "--strict-config",
        "--skip-git-repo-check",
        _validate_prompt(prompt),
    )


def _validate_thread_id(thread_id: str) -> str:
    if not isinstance(thread_id, str) or _THREAD_ID.fullmatch(thread_id) is None:
        raise ValueError("Codex thread ID is missing or unsafe")
    return thread_id


def build_codex_resume_argv(
    thread_id: str,
    prompt: str,
    *,
    executable: str = "/usr/local/bin/codex",
) -> tuple[str, ...]:
    return (
        *_author_prefix(executable),
        "exec",
        "resume",
        "--json",
        "--strict-config",
        "--skip-git-repo-check",
        _validate_thread_id(thread_id),
        _validate_prompt(prompt),
    )


def build_codex_version_argv(*, executable: str = "/usr/local/bin/codex") -> tuple[str, ...]:
    return (_validate_executable(executable), "--version")


def build_codex_exec_help_argv(*, executable: str = "/usr/local/bin/codex") -> tuple[str, ...]:
    return (_validate_executable(executable), "exec", "--help")


def build_codex_resume_help_argv(*, executable: str = "/usr/local/bin/codex") -> tuple[str, ...]:
    return (_validate_executable(executable), "exec", "resume", "--help")


def build_codex_prompt_input_argv(
    prompt: str,
    *,
    executable: str = "/usr/local/bin/codex",
    control_cwd: str = AUTHOR_CWD,
    workspace: str = AUTHOR_WORKSPACE,
) -> tuple[str, ...]:
    """Build the non-model instruction-discovery capability probe."""

    return (
        _validate_executable(executable),
        "-C",
        _normalized_absolute(control_cwd, name="Codex probe cwd"),
        "--add-dir",
        _normalized_absolute(workspace, name="Codex probe workspace"),
        "-c",
        f'default_permissions="{AUTHOR_PERMISSION_PROFILE}"',
        "debug",
        "prompt-input",
        _validate_prompt(prompt),
    )


@dataclass(frozen=True, slots=True)
class CodexInvocation:
    argv: tuple[str, ...]
    cwd: str
    _environment: dict[str, str] = field(repr=False)

    def launch_environment(self) -> dict[str, str]:
        return dict(self._environment)


def build_codex_first_invocation(
    prompt: str,
    *,
    executable: str = "/usr/local/bin/codex",
    parent_environment: Mapping[str, str] | None = None,
) -> CodexInvocation:
    environment = (
        build_codex_parent_environment()
        if parent_environment is None
        else _validate_parent_environment(parent_environment)
    )
    return CodexInvocation(
        argv=build_codex_first_argv(prompt, executable=executable),
        cwd=AUTHOR_CWD,
        _environment=environment,
    )


def build_codex_resume_invocation(
    thread_id: str,
    prompt: str,
    *,
    executable: str = "/usr/local/bin/codex",
    parent_environment: Mapping[str, str] | None = None,
) -> CodexInvocation:
    environment = (
        build_codex_parent_environment()
        if parent_environment is None
        else _validate_parent_environment(parent_environment)
    )
    return CodexInvocation(
        argv=build_codex_resume_argv(thread_id, prompt, executable=executable),
        cwd=AUTHOR_CWD,
        _environment=environment,
    )


def _validate_parent_environment(parent: Mapping[str, str]) -> dict[str, str]:
    required = {"PATH", "HOME", "TMPDIR", "LANG", "CODEX_HOME"}
    if set(parent) != required:
        raise ValueError("Codex parent environment is not the exact allowlist")
    expected = build_codex_parent_environment(codex_home=parent["CODEX_HOME"])
    if dict(parent) != expected:
        raise ValueError("Codex parent environment changes a pinned value")
    return expected


@dataclass(frozen=True, slots=True)
class CodexUsage:
    input_tokens: int
    cached_input_tokens: int
    output_tokens: int
    reasoning_output_tokens: int


@dataclass(frozen=True, slots=True)
class CodexTurnResult:
    thread_id: str
    final_message: str
    usage: CodexUsage
    observed_model: str | None
    observed_effort: str | None
    event_json: tuple[bytes, ...]
    completed_at: float


def _invalid_protocol(detail: str) -> Exception:
    return fail(StopReason.AUTHOR_PROCESS_FAILURE, detail)


def _parse_json_object(line: bytes) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def reject_constant(_value: str) -> object:
        raise ValueError("non-finite JSON number")

    try:
        decoded = line.decode("utf-8", errors="strict")
        value = json.loads(
            decoded,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise _invalid_protocol("Codex emitted malformed or duplicate-key JSONL") from None
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise _invalid_protocol("Codex JSONL event must be an object with string keys")
    return value


def _bounded_fact(value: object, *, name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value or "\x00" in value:
        raise _invalid_protocol(f"Codex {name} metadata is invalid")
    if len(value.encode("utf-8")) > 256:
        raise _invalid_protocol(f"Codex {name} metadata exceeds its bound")
    return value


def _coalesce_fact(current: str | None, observed: str | None, *, name: str) -> str | None:
    if observed is None:
        return current
    if current is not None and current != observed:
        raise _invalid_protocol(f"Codex reported contradictory {name} metadata")
    return observed


def _usage(value: object) -> CodexUsage:
    if not isinstance(value, dict):
        raise _invalid_protocol("Codex turn.completed event omitted usage")

    def count(name: str, *, required: bool) -> int:
        raw = value.get(name)
        if raw is None and not required:
            return 0
        if not isinstance(raw, int) or isinstance(raw, bool) or raw < 0:
            raise _invalid_protocol(f"Codex usage field {name} is invalid")
        return raw

    return CodexUsage(
        input_tokens=count("input_tokens", required=True),
        cached_input_tokens=count("cached_input_tokens", required=False),
        output_tokens=count("output_tokens", required=True),
        reasoning_output_tokens=count("reasoning_output_tokens", required=False),
    )


def parse_codex_jsonl(
    data: bytes,
    *,
    expected_thread_id: str | None = None,
    max_bytes: int = DEFAULT_MAX_AGENT_OUTPUT_BYTES,
    max_events: int = _MAX_JSONL_EVENTS,
    max_line_bytes: int = _MAX_JSONL_LINE_BYTES,
    completed_at: float = 0.0,
) -> CodexTurnResult:
    """Parse one complete pinned JSONL turn without trusting model prose."""

    if not isinstance(data, bytes):
        raise TypeError("Codex JSONL must be bytes")
    for name, value in (
        ("max_bytes", max_bytes),
        ("max_events", max_events),
        ("max_line_bytes", max_line_bytes),
    ):
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise ValueError(f"{name} must be a positive integer")
    if len(data) > max_bytes:
        raise fail(StopReason.AGENT_OUTPUT_LIMIT, "Codex JSONL exceeded its byte limit")
    if expected_thread_id is not None:
        _validate_thread_id(expected_thread_id)
    if (
        not isinstance(completed_at, (int, float))
        or isinstance(completed_at, bool)
        or not math.isfinite(float(completed_at))
        or completed_at < 0
    ):
        raise ValueError("completed_at must be a finite non-negative monotonic timestamp")

    raw_lines = data.split(b"\n")
    if raw_lines and raw_lines[-1] == b"":
        raw_lines.pop()
    lines: list[bytes] = []
    for raw_line in raw_lines:
        if raw_line.endswith(b"\r"):
            raw_line = raw_line[:-1]
        if b"\r" in raw_line:
            raise _invalid_protocol("Codex JSONL contains a non-canonical line ending")
        lines.append(raw_line)
    if not lines or len(lines) > max_events:
        raise _invalid_protocol("Codex JSONL has an invalid event count")
    if any(not line or len(line) > max_line_bytes for line in lines):
        raise _invalid_protocol("Codex JSONL contains an empty or oversized event")

    thread_id: str | None = None
    final_message: str | None = None
    usage: CodexUsage | None = None
    observed_model: str | None = None
    observed_effort: str | None = None
    completed_count = 0
    event_json: list[bytes] = []

    for index, line in enumerate(lines):
        event = _parse_json_object(line)
        event_type = event.get("type")
        if not isinstance(event_type, str) or not event_type:
            raise _invalid_protocol("Codex JSONL event type is missing or invalid")
        if index == 0 and event_type != "thread.started":
            raise _invalid_protocol("Codex JSONL must start with thread.started")
        event_json.append(line)

        if event_type == "thread.started":
            if thread_id is not None:
                raise _invalid_protocol("Codex emitted multiple thread.started events")
            raw_thread_id = event.get("thread_id")
            if (
                not isinstance(raw_thread_id, str)
                or _THREAD_ID.fullmatch(raw_thread_id) is None
            ):
                raise _invalid_protocol("Codex thread.started event has no valid thread ID")
            thread_id = raw_thread_id
        elif event_type == "item.completed":
            item = event.get("item")
            if not isinstance(item, dict):
                raise _invalid_protocol("Codex item.completed event has no item object")
            if item.get("type") == "agent_message":
                text = item.get("text")
                if not isinstance(text, str) or "\x00" in text:
                    raise _invalid_protocol("Codex agent message is invalid")
                if len(text.encode("utf-8")) > DEFAULT_MAX_FIELD_BYTES:
                    raise _invalid_protocol("Codex final message exceeds max_field_bytes")
                final_message = text
        elif event_type == "turn.completed":
            completed_count += 1
            if completed_count > 1:
                raise _invalid_protocol("Codex emitted multiple turn.completed events")
            usage = _usage(event.get("usage"))
        elif event_type in {"turn.failed", "error"}:
            raise _invalid_protocol("Codex reported an unsuccessful author turn")

        if event_type in {"thread.started", "turn.started", "turn.completed"}:
            observed_model = _coalesce_fact(
                observed_model,
                _bounded_fact(event.get("model"), name="model"),
                name="model",
            )
            effort_value = event.get("reasoning_effort", event.get("effort"))
            observed_effort = _coalesce_fact(
                observed_effort,
                _bounded_fact(effort_value, name="effort"),
                name="effort",
            )

    if thread_id is None:
        raise _invalid_protocol("Codex JSONL omitted thread.started")
    if expected_thread_id is not None and thread_id != expected_thread_id:
        raise _invalid_protocol("Codex resume returned a different thread ID")
    if final_message is None:
        raise _invalid_protocol("Codex JSONL omitted the final agent message")
    if usage is None or completed_count != 1:
        raise _invalid_protocol("Codex JSONL omitted turn.completed usage")
    return CodexTurnResult(
        thread_id=thread_id,
        final_message=final_message,
        usage=usage,
        observed_model=observed_model,
        observed_effort=observed_effort,
        event_json=tuple(event_json),
        completed_at=completed_at,
    )


def classify_codex_process_result(
    result: BoundedProcessResult,
    *,
    expected_thread_id: str | None = None,
    max_bytes: int = DEFAULT_MAX_AGENT_OUTPUT_BYTES,
) -> CodexTurnResult:
    if not isinstance(result, BoundedProcessResult):
        raise TypeError("result must be a BoundedProcessResult")
    if result.output_limited:
        raise fail(StopReason.AGENT_OUTPUT_LIMIT, "Codex output exceeded its byte limit")
    if result.timed_out:
        raise fail(StopReason.AUTHOR_TIMEOUT, "Codex exceeded the outer author timeout")
    if result.returncode != 0:
        raise fail(
            StopReason.AUTHOR_PROCESS_FAILURE,
            f"Codex process exited unsuccessfully ({result.returncode})",
        )
    return parse_codex_jsonl(
        result.stdout,
        expected_thread_id=expected_thread_id,
        max_bytes=max_bytes,
        completed_at=result.completed_at,
    )


class CodexClient:
    def __init__(self, transport: CodexTransport) -> None:
        self._transport = transport

    def first_turn(
        self,
        prompt: str,
        *,
        timeout_seconds: float,
        executable: str = "/usr/local/bin/codex",
        parent_environment: Mapping[str, str] | None = None,
        output_max_bytes: int = DEFAULT_MAX_AGENT_OUTPUT_BYTES,
    ) -> CodexTurnResult:
        invocation = build_codex_first_invocation(
            prompt,
            executable=executable,
            parent_environment=parent_environment,
        )
        result = self._transport(invocation, timeout_seconds, output_max_bytes)
        return classify_codex_process_result(result, max_bytes=output_max_bytes)

    def resume_turn(
        self,
        thread_id: str,
        prompt: str,
        *,
        timeout_seconds: float,
        executable: str = "/usr/local/bin/codex",
        parent_environment: Mapping[str, str] | None = None,
        output_max_bytes: int = DEFAULT_MAX_AGENT_OUTPUT_BYTES,
    ) -> CodexTurnResult:
        invocation = build_codex_resume_invocation(
            thread_id,
            prompt,
            executable=executable,
            parent_environment=parent_environment,
        )
        result = self._transport(invocation, timeout_seconds, output_max_bytes)
        return classify_codex_process_result(
            result,
            expected_thread_id=thread_id,
            max_bytes=output_max_bytes,
        )


__all__ = [
    "AUTHOR_CWD",
    "AUTHOR_PERMISSION_PROFILE",
    "AUTHOR_WORKSPACE",
    "CodexClient",
    "CodexInvocation",
    "CodexTurnResult",
    "CodexUsage",
    "SANDBOX_CODEX_HOME",
    "SanitizedCodexConfig",
    "build_codex_exec_help_argv",
    "build_codex_first_argv",
    "build_codex_first_invocation",
    "build_codex_parent_environment",
    "build_codex_prompt_input_argv",
    "build_codex_resume_argv",
    "build_codex_resume_help_argv",
    "build_codex_resume_invocation",
    "build_codex_version_argv",
    "classify_codex_process_result",
    "install_sanitized_codex_config",
    "parse_codex_jsonl",
]
