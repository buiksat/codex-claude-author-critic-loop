#!/usr/bin/python3
"""Deterministic Codex JSONL fake; it never reads credentials or calls a model."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path


_REFRESHED_AUTH = {
    "auth_mode": "chatgpt",
    "OPENAI_API_KEY": None,
    "tokens": {
        "id_token": "fake-refreshed-id-token",
        "access_token": "fake-refreshed-access-token",
        "refresh_token": "fake-refreshed-refresh-token",
        "account_id": "fake-refreshed-account",
    },
    "last_refresh": "2099-01-01T00:00:00Z",
}


def emit(value: dict[str, object]) -> None:
    sys.stdout.write(json.dumps(value, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def parse_turn(argv: list[str]) -> tuple[bool, str | None, str]:
    try:
        exec_index = argv.index("exec")
    except ValueError:
        return False, None, ""
    resume = exec_index + 1 < len(argv) and argv[exec_index + 1] == "resume"
    expected_prefix = [
        "-a",
        "never",
        "-C",
        "/runtime/author-cwd",
        "--add-dir",
        "/workspace",
        "-c",
        'default_permissions="agent_loop_author"',
    ]
    if argv[:exec_index] != expected_prefix:
        return resume, None, "scenario:bad-argv"
    local = argv[exec_index + 2 :] if resume else argv[exec_index + 1 :]
    expected_flags = ["--json", "--strict-config", "--skip-git-repo-check"]
    if local[:3] != expected_flags:
        return resume, None, "scenario:bad-argv"
    if resume:
        if len(local) != 5:
            return True, None, "scenario:bad-argv"
        return True, local[3], local[4]
    if len(local) != 4:
        return False, None, "scenario:bad-argv"
    return False, None, local[3]


def main() -> int:
    argv = sys.argv[1:]
    if argv == ["--version"]:
        print("codex-cli 0.144.6")
        return 0
    if "--help" in argv:
        print("deterministic fake help")
        return 0
    if "debug" in argv and "prompt-input" in argv:
        print('{"input_items":[]}')
        return 0

    resume, expected_thread, prompt = parse_turn(argv)
    scenario = prompt.removeprefix("scenario:")
    thread_id = expected_thread if resume and expected_thread is not None else "thread-001"
    if scenario == "bad-argv":
        print("fake received an invalid invocation", file=sys.stderr)
        return 64
    if scenario == "nonzero":
        print("fake process failure", file=sys.stderr)
        return 23
    if scenario == "timeout":
        time.sleep(5)
        return 0
    if scenario == "output-limit":
        sys.stdout.write("x" * (2 * 1024 * 1024))
        sys.stdout.flush()
        return 0
    if scenario == "credential-refresh-truncated-crash":
        codex_home = Path(os.environ["CODEX_HOME"])
        destination = codex_home / "auth.json"
        with destination.open("wb") as stream:
            stream.write(b'{"auth_mode":"chatgpt","tokens":{"access_token":"truncated')
            stream.flush()
            os.fsync(stream.fileno())
        destination.chmod(0o600)
        os._exit(23)
    if scenario in {"credential-refresh", "credential-refresh-crash"}:
        codex_home = Path(os.environ["CODEX_HOME"])
        destination = codex_home / "auth.json"
        destination.write_text(
            json.dumps(_REFRESHED_AUTH, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        destination.chmod(0o600)
        if scenario == "credential-refresh-crash":
            return 23
    if scenario == "malformed":
        print("{not-json")
        return 0
    if scenario == "duplicate-key":
        print('{"type":"thread.started","thread_id":"one","thread_id":"two"}')
        return 0
    if scenario == "missing-thread":
        emit({"type": "turn.started"})
        return 0
    if scenario == "unsafe-thread":
        thread_id = "../untrusted"
    if scenario == "different-thread":
        thread_id = "thread-stolen"

    emit(
        {
            "type": "thread.started",
            "thread_id": thread_id,
            "model": "gpt-fake-pinned",
            "reasoning_effort": "high",
        }
    )
    emit({"type": "turn.started", "thread_id": "untrusted-other-location"})
    if scenario == "error-event":
        emit({"type": "error", "message": "fake error"})
        return 0
    if scenario != "missing-final":
        emit(
            {
                "type": "item.completed",
                "item": {
                    "id": "item-1",
                    "type": "agent_message",
                    "text": "fake author completed",
                },
            }
        )
    if scenario != "missing-usage":
        emit(
            {
                "type": "turn.completed",
                "usage": {
                    "input_tokens": 11,
                    "cached_input_tokens": 3,
                    "output_tokens": 7,
                    "reasoning_output_tokens": 2,
                },
                "model": "gpt-fake-pinned",
                "effort": "high",
            }
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
