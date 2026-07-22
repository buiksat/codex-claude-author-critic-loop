from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from agent_loop.constants import Limits
from agent_loop.manifests import SubjectManifest
from agent_loop.sandbox import SandboxMount, SandboxPolicy, build_bwrap_argv
from agent_loop.sandbox_init import SandboxRequest, SupervisorLimits, encode_request
from agent_loop.service import ServiceLimits, ServiceResult, TransientServiceRunner


def _object(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    return value


def _request(code: str, *, timeout_ms: int = 2_000) -> SandboxRequest:
    return SandboxRequest(
        manifest=SubjectManifest.empty(),
        blobs=(),
        argv=("/usr/bin/python3", "-c", code),
        env=(("HOME", "/runtime/home"), ("LANG", "C.UTF-8"), ("PATH", "/usr/bin:/bin")),
        cwd="/workspace",
        stdin_bytes=b"",
        limits=SupervisorLimits(
            timeout_ms=timeout_ms,
            terminate_grace_ms=300,
            max_output_bytes=64 * 1024,
            max_export_bytes=2 * 1024 * 1024,
            subject=Limits(
                max_files=128,
                max_file_bytes=1024 * 1024,
                max_total_subject_bytes=4 * 1024 * 1024,
            ),
        ),
    )


def _sandbox_command() -> tuple[str, ...]:
    source = Path("src").resolve()
    policy = SandboxPolicy.validation(mounts=(SandboxMount(os.fspath(source), "/opt/agent-loop"),))
    return build_bwrap_argv(
        policy,
        (
            "/usr/bin/env",
            "PYTHONPATH=/opt/agent-loop",
            "/usr/bin/python3",
            "-m",
            "agent_loop.sandbox_init",
        ),
    )


def _run_service(request: SandboxRequest) -> tuple[dict[str, object], ServiceResult]:
    service = TransientServiceRunner().run(
        _sandbox_command(),
        role="sandbox-cleanup",
        input_bytes=encode_request(request),
        timeout_seconds=8,
        limits=ServiceLimits(
            runtime_max_seconds=8,
            timeout_stop_seconds=1,
            output_max_bytes=2 * 1024 * 1024,
        ),
    )
    decoded: object = json.loads(service.process.stdout)
    result = _object(decoded)
    return result, service


@pytest.mark.host
def test_029_sets_id_orphan_is_reaped_before_export_and_cgroup_collection() -> None:
    code = """
import os, pathlib, time
pid = os.fork()
if pid == 0:
    os.setsid()
    pathlib.Path('daemon-ready').write_text(str(os.getpid()))
    while True: time.sleep(1)
while not pathlib.Path('daemon-ready').exists(): time.sleep(0.001)
"""
    result, service = _run_service(_request(code))
    assert result["kind"] == "result"
    cleanup = _object(result["cleanup"])
    assert cleanup["namespace_empty"] is True
    assert isinstance(cleanup["terminated_pids"], int)
    assert cleanup["terminated_pids"] >= 1
    assert cleanup["export_started_after_cleanup"] is True
    assert service.cgroup_empty is True
    assert service.process.returncode == 0


@pytest.mark.host
def test_029_timeout_kills_new_session_and_service_cgroup_is_empty() -> None:
    code = """
import os, time
if os.fork() == 0:
    os.setsid()
    while True: time.sleep(1)
while True: time.sleep(1)
"""
    result, service = _run_service(_request(code, timeout_ms=100))
    assert result["kind"] == "result"
    assert _object(result["process"])["timed_out"] is True
    cleanup = _object(result["cleanup"])
    assert cleanup["namespace_empty"] is True
    assert isinstance(cleanup["terminated_pids"], int)
    assert cleanup["terminated_pids"] >= 1
    assert service.cgroup_empty is True
