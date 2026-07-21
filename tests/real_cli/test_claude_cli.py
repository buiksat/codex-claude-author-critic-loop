from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, ClassVar

import pytest

from agent_loop.constants import SUPPORTED_CLAUDE_VERSION
from agent_loop.schemas import critic_schema_document, critic_schema_json
from agent_loop.service import run_bounded_process
from tests.real_cli.live_support import require_live, required_install

pytestmark = pytest.mark.real_cli

_MAX_PROBE_REQUEST_BYTES = 1024 * 1024


class _LocalProbeHandler(BaseHTTPRequestHandler):
    requests: ClassVar[list[bytes]] = []

    def _record_request(self) -> bool:
        try:
            length = int(self.headers.get("content-length", "0"))
        except ValueError:
            self.send_error(400)
            return False
        if length < 0 or length > _MAX_PROBE_REQUEST_BYTES:
            self.send_error(413)
            return False
        self.requests.append(self.rfile.read(length))
        return True

    def _respond_json(self, status: int, payload: dict[str, object]) -> None:
        response = json.dumps(payload, separators=(",", ":")).encode("ascii")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, format: str, *args: Any) -> None:
        del format, args


class _SchemaProbeHandler(_LocalProbeHandler):
    requests: ClassVar[list[bytes]] = []

    def do_POST(self) -> None:  # noqa: N802 - stdlib HTTP handler API
        if not self._record_request():
            return
        self._respond_json(
            400,
            {
                "type": "error",
                "error": {
                    "type": "invalid_request_error",
                    "message": "deterministic local schema probe stop",
                },
            },
        )


def _blocked_review(reason: str) -> dict[str, object]:
    return {
        "schema_version": 1,
        "verdict": "BLOCKED",
        "summary": "Assessment complete.",
        "blocked_reason": reason,
        "blocking_findings": [],
        "non_blocking_findings": [],
    }


_WHITESPACE_BLOCKED_REVIEW = _blocked_review(" \t\n")
_CANONICAL_BLOCKED_REVIEW = _blocked_review("External input is missing.")


class _SchemaCorrectionProbeHandler(_LocalProbeHandler):
    requests: ClassVar[list[bytes]] = []

    def do_POST(self) -> None:  # noqa: N802 - stdlib HTTP handler API
        if not self._record_request():
            return
        request_number = len(self.requests)
        if request_number == 1:
            review = _WHITESPACE_BLOCKED_REVIEW
        elif request_number == 2:
            review = _CANONICAL_BLOCKED_REVIEW
        else:
            self._respond_json(
                500,
                {
                    "type": "error",
                    "error": {
                        "type": "api_error",
                        "message": "schema correction exceeded one retry",
                    },
                },
            )
            return
        self._respond_json(
            200,
            {
                "id": f"msg_local_{request_number}",
                "type": "message",
                "role": "assistant",
                "model": "claude-nonmodel-schema-probe",
                "content": [
                    {
                        "type": "tool_use",
                        "id": f"toolu_local_{request_number}",
                        "name": "StructuredOutput",
                        "input": review,
                    }
                ],
                "stop_reason": "tool_use",
                "stop_sequence": None,
                "usage": {"input_tokens": 1, "output_tokens": 1},
            },
        )


def _private_probe_environment(tmp_path: Path) -> dict[str, str]:
    home = tmp_path / "home"
    scratch = tmp_path / "tmp"
    home.mkdir(mode=0o700)
    scratch.mkdir(mode=0o700)
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(home),
        "TMPDIR": str(scratch),
        "LANG": "C.UTF-8",
    }


def _assert_pinned_claude_version(executable: Path, environment: dict[str, str]) -> None:
    version = run_bounded_process(
        (str(executable), "--version"),
        timeout_seconds=10,
        output_max_bytes=256 * 1024,
        env=environment,
    )
    assert not version.timed_out and not version.output_limited and version.returncode == 0
    assert version.stdout.strip() == f"{SUPPORTED_CLAUDE_VERSION} (Claude Code)".encode("ascii")


@contextmanager
def _local_probe_server(
    handler: type[_LocalProbeHandler],
) -> Iterator[str]:
    server = HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _probe_argv(executable: Path, *, max_turns: int) -> tuple[str, ...]:
    return (
        str(executable),
        "--bare",
        "-p",
        "--no-session-persistence",
        "--tools",
        "",
        "--max-turns",
        str(max_turns),
        "--model",
        "claude-nonmodel-schema-probe",
        "--effort",
        "medium",
        "--output-format",
        "json",
        "--json-schema",
        critic_schema_json(),
        "Return one valid object for the supplied schema.",
    )


def test_pinned_claude_accepts_canonical_schema_without_nonessential_sidecalls(
    tmp_path: Path,
) -> None:
    """Exercise only local CLI/schema behavior; the fake endpoint cannot call a model."""

    require_live()
    install = required_install("claude")
    _SchemaProbeHandler.requests = []
    base_environment = _private_probe_environment(tmp_path)
    _assert_pinned_claude_version(install.host_executable, base_environment)

    with _local_probe_server(_SchemaProbeHandler) as endpoint:
        result = run_bounded_process(
            _probe_argv(install.host_executable, max_turns=1),
            timeout_seconds=10,
            output_max_bytes=1024 * 1024,
            env={
                **base_environment,
                "ANTHROPIC_API_KEY": "local-schema-probe-not-a-credential",
                "ANTHROPIC_BASE_URL": endpoint,
                "API_TIMEOUT_MS": "1000",
                "CLAUDE_CODE_MAX_RETRIES": "0",
                "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            },
            input_bytes=b"LOCAL_SCHEMA_PROBE_INPUT",
        )

    assert not result.timed_out and not result.output_limited
    assert result.returncode == 1
    assert b"--json-schema is not a valid JSON Schema" not in result.stderr
    assert len(_SchemaProbeHandler.requests) == 1

    request = json.loads(_SchemaProbeHandler.requests[0])
    assert isinstance(request, dict)
    assert request.get("model") == "claude-nonmodel-schema-probe"
    assert request.get("output_config") == {"effort": "medium"}
    tools = request.get("tools")
    assert isinstance(tools, list) and len(tools) == 1
    structured_output = tools[0]
    assert isinstance(structured_output, dict)
    assert structured_output.get("name") == "StructuredOutput"
    assert structured_output.get("input_schema") == critic_schema_document()


def test_051_pinned_claude_retries_conditional_schema_once_without_strict_warnings(
    tmp_path: Path,
) -> None:
    """Prove the pinned CLI's local validator enforces the cross-verdict schema."""

    require_live()
    install = required_install("claude")
    _SchemaCorrectionProbeHandler.requests = []
    base_environment = _private_probe_environment(tmp_path)
    _assert_pinned_claude_version(install.host_executable, base_environment)

    with _local_probe_server(_SchemaCorrectionProbeHandler) as endpoint:
        result = run_bounded_process(
            _probe_argv(install.host_executable, max_turns=2),
            timeout_seconds=10,
            output_max_bytes=1024 * 1024,
            env={
                **base_environment,
                "ANTHROPIC_API_KEY": "local-schema-probe-not-a-credential",
                "ANTHROPIC_BASE_URL": endpoint,
                "API_TIMEOUT_MS": "1000",
                "CLAUDE_CODE_MAX_RETRIES": "0",
                "MAX_STRUCTURED_OUTPUT_RETRIES": "1",
                "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            },
            input_bytes=b"LOCAL_SCHEMA_PROBE_INPUT",
        )

    assert not result.timed_out and not result.output_limited
    assert result.returncode == 0
    assert len(_SchemaCorrectionProbeHandler.requests) == 2
    assert b"strict mode:" not in result.stderr
    envelope = json.loads(result.stdout)
    assert isinstance(envelope, dict)
    assert envelope.get("structured_output") == _CANONICAL_BLOCKED_REVIEW
