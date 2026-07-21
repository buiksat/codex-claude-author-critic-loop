from __future__ import annotations

import json
import threading
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


class _SchemaProbeHandler(BaseHTTPRequestHandler):
    requests: ClassVar[list[bytes]] = []

    def do_POST(self) -> None:  # noqa: N802 - stdlib HTTP handler API
        length = int(self.headers.get("content-length", "0"))
        if length < 0 or length > _MAX_PROBE_REQUEST_BYTES:
            self.send_error(413)
            return
        self.requests.append(self.rfile.read(length))
        response = json.dumps(
            {
                "type": "error",
                "error": {
                    "type": "invalid_request_error",
                    "message": "deterministic local schema probe stop",
                },
            },
            separators=(",", ":"),
        ).encode("ascii")
        self.send_response(400)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, format: str, *args: Any) -> None:
        del format, args


def test_pinned_claude_accepts_canonical_schema_without_nonessential_sidecalls(
    tmp_path: Path,
) -> None:
    """Exercise only local CLI/schema behavior; the fake endpoint cannot call a model."""

    require_live()
    install = required_install("claude")
    _SchemaProbeHandler.requests = []
    home = tmp_path / "home"
    scratch = tmp_path / "tmp"
    home.mkdir(mode=0o700)
    scratch.mkdir(mode=0o700)
    base_environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(home),
        "TMPDIR": str(scratch),
        "LANG": "C.UTF-8",
    }
    version = run_bounded_process(
        (str(install.host_executable), "--version"),
        timeout_seconds=10,
        output_max_bytes=256 * 1024,
        env=base_environment,
    )
    assert not version.timed_out and not version.output_limited and version.returncode == 0
    assert version.stdout.strip() == f"{SUPPORTED_CLAUDE_VERSION} (Claude Code)".encode("ascii")

    server = HTTPServer(("127.0.0.1", 0), _SchemaProbeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = run_bounded_process(
            (
                str(install.host_executable),
                "--bare",
                "-p",
                "--no-session-persistence",
                "--tools",
                "",
                "--max-turns",
                "1",
                "--model",
                "claude-nonmodel-schema-probe",
                "--effort",
                "medium",
                "--output-format",
                "json",
                "--json-schema",
                critic_schema_json(),
                "Return one valid object for the supplied schema.",
            ),
            timeout_seconds=10,
            output_max_bytes=1024 * 1024,
            env={
                **base_environment,
                "ANTHROPIC_API_KEY": "local-schema-probe-not-a-credential",
                "ANTHROPIC_BASE_URL": f"http://127.0.0.1:{server.server_port}",
                "API_TIMEOUT_MS": "1000",
                "CLAUDE_CODE_MAX_RETRIES": "0",
                "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            },
            input_bytes=b"LOCAL_SCHEMA_PROBE_INPUT",
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

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
