from __future__ import annotations

import base64
import errno
import json
import os
import subprocess
import time
from pathlib import Path

import pytest

from agent_loop.constants import Limits
from agent_loop.manifests import SubjectManifest
from agent_loop.sandbox import (
    SandboxMount,
    SandboxPolicy,
    SandboxRole,
    build_bwrap_argv,
)
from agent_loop.sandbox_init import SandboxRequest, SupervisorLimits, encode_request
from agent_loop.service import (
    ServiceLimits,
    ServiceResult,
    TransientServiceRunner,
    build_systemd_run_argv,
    new_unit_name,
    service_environment,
)


def _request(
    code: str,
    *,
    max_files: int = 64,
    max_output_bytes: int = 64 * 1024,
    timeout_ms: int = 2_000,
) -> SandboxRequest:
    return SandboxRequest(
        manifest=SubjectManifest.empty(),
        blobs=(),
        argv=("/usr/bin/python3", "-c", code),
        env=(("HOME", "/runtime/home"), ("LANG", "C.UTF-8"), ("PATH", "/usr/bin:/bin")),
        cwd="/workspace",
        stdin_bytes=b"",
        limits=SupervisorLimits(
            timeout_ms=timeout_ms,
            terminate_grace_ms=200,
            max_output_bytes=max_output_bytes,
            max_export_bytes=2 * 1024 * 1024,
            subject=Limits(
                max_files=max_files,
                max_file_bytes=2 * 1024 * 1024,
                max_total_subject_bytes=4 * 1024 * 1024,
            ),
        ),
    )


def _run(request: SandboxRequest, *, workspace_bytes: int) -> tuple[int, dict[str, object], bytes]:
    source = Path("src").resolve()
    policy = SandboxPolicy(
        role=SandboxRole.VALIDATION,
        workspace_bytes=workspace_bytes,
        mounts=(SandboxMount(os.fspath(source), "/opt/agent-loop"),),
        cwd="/workspace",
    )
    command = (
        "/usr/bin/env",
        "PYTHONPATH=/opt/agent-loop",
        "/usr/bin/python3",
        "-m",
        "agent_loop.sandbox_init",
    )
    completed = subprocess.run(
        build_bwrap_argv(policy, command),
        input=encode_request(request),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        close_fds=True,
        check=False,
        timeout=10,
    )
    return completed.returncode, json.loads(completed.stdout), completed.stderr


def _run_service(request: SandboxRequest, limits: ServiceLimits) -> ServiceResult:
    source = Path("src").resolve()
    policy = SandboxPolicy(
        role=SandboxRole.VALIDATION,
        workspace_bytes=4 * 1024 * 1024,
        mounts=(SandboxMount(os.fspath(source), "/opt/agent-loop"),),
        cwd="/workspace",
    )
    command = build_bwrap_argv(
        policy,
        (
            "/usr/bin/env",
            "PYTHONPATH=/opt/agent-loop",
            "/usr/bin/python3",
            "-m",
            "agent_loop.sandbox_init",
        ),
    )
    return TransientServiceRunner().run(
        command,
        role="limit-stress",
        input_bytes=encode_request(request),
        timeout_seconds=8,
        limits=limits,
    )


def _result_blob(response: dict[str, object], path: bytes) -> bytes:
    entries = {
        base64.b64decode(entry["path_b64"]): entry
        for entry in response["candidate_manifest"]["entries"]
    }
    blobs = {
        blob["sha256"]: base64.b64decode(blob["data_b64"])
        for blob in response["new_blobs"]
    }
    return blobs[entries[path]["blob_sha256"]]


@pytest.mark.host
def test_010_primary_output_limit_stops_process_and_still_proves_cleanup() -> None:
    returncode, result, stderr = _run(
        _request("import os,time; os.write(1,b'x'*1000000); time.sleep(10)", max_output_bytes=4096),
        workspace_bytes=4 * 1024 * 1024,
    )
    assert returncode == 0, stderr.decode("utf-8", "backslashreplace")
    assert result["kind"] == "result"
    assert result["process"]["output_limited"] is True
    assert result["cleanup"]["namespace_empty"] is True


@pytest.mark.host
def test_010_max_files_fails_closed_without_candidate_export() -> None:
    code = "from pathlib import Path; [Path(f'f{i}').touch() for i in range(10)]"
    returncode, result, _stderr = _run(
        _request(code, max_files=5),
        workspace_bytes=4 * 1024 * 1024,
    )
    assert returncode == 2
    assert result["kind"] == "error"
    assert result["error"]["reason"] == "unsafe_file_type_or_hard_link"
    assert "candidate_manifest" not in result


@pytest.mark.host
def test_010_tmpfs_byte_ceiling_is_a_real_enospc_boundary() -> None:
    code = "from pathlib import Path; Path('large').write_bytes(b'x'*(3*1024*1024))"
    returncode, result, stderr = _run(
        _request(code),
        workspace_bytes=1024 * 1024,
    )
    assert returncode == 0, stderr.decode("utf-8", "backslashreplace")
    assert result["kind"] == "result"
    assert result["process"]["returncode"] != 0
    assert b"No space left on device" in base64.b64decode(result["process"]["stderr_b64"])


@pytest.mark.host
def test_010_limit_nofile_is_inherited_and_fails_closed() -> None:
    code = """
import errno, pathlib
opened = []
while True:
    try:
        opened.append(open('/dev/null', 'rb'))
    except OSError as exc:
        observed = exc.errno
        break
for stream in opened:
    stream.close()
pathlib.Path('nofile.errno').write_text(str(observed))
"""
    service = _run_service(
        _request(code),
        ServiceLimits(
            runtime_max_seconds=8,
            timeout_stop_seconds=1,
            limit_nofile=32,
            output_max_bytes=2 * 1024 * 1024,
        ),
    )
    response = json.loads(service.process.stdout)
    assert response["kind"] == "result"
    assert _result_blob(response, b"nofile.errno") == str(errno.EMFILE).encode()
    assert service.observed_properties["LimitNOFILE"] == "32"
    assert service.cgroup_empty is True


@pytest.mark.host
def test_010_limit_fsize_stops_an_oversized_write() -> None:
    service = _run_service(
        _request("from pathlib import Path; Path('large').write_bytes(b'x'*(1024*1024))"),
        ServiceLimits(
            runtime_max_seconds=8,
            timeout_stop_seconds=1,
            limit_fsize_bytes=64 * 1024,
            output_max_bytes=2 * 1024 * 1024,
        ),
    )
    response = json.loads(service.process.stdout)
    assert response["kind"] == "result"
    assert response["process"]["returncode"] != 0
    assert b"File too large" in base64.b64decode(response["process"]["stderr_b64"])
    assert service.observed_properties["LimitFSIZE"] == str(64 * 1024)
    assert service.cgroup_empty is True


@pytest.mark.host
def test_010_tasks_max_rejects_forks_and_cleanup_still_completes() -> None:
    code = """
import os, pathlib, time
while True:
    try:
        pid = os.fork()
    except OSError as exc:
        pathlib.Path('fork.errno').write_text(str(exc.errno))
        break
    if pid == 0:
        while True:
            time.sleep(1)
"""
    service = _run_service(
        _request(code),
        ServiceLimits(
            tasks_max=16,
            runtime_max_seconds=8,
            timeout_stop_seconds=1,
            output_max_bytes=2 * 1024 * 1024,
        ),
    )
    response = json.loads(service.process.stdout)
    assert response["kind"] == "result"
    assert _result_blob(response, b"fork.errno") == str(errno.EAGAIN).encode()
    assert response["cleanup"]["terminated_pids"] >= 1
    assert service.observed_properties["TasksMax"] == "16"
    assert service.cgroup_empty is True


@pytest.mark.host
def test_010_runtime_max_terminates_the_whole_service() -> None:
    service = _run_service(
        _request("import time; time.sleep(60)"),
        ServiceLimits(
            runtime_max_seconds=1,
            timeout_stop_seconds=1,
            output_max_bytes=2 * 1024 * 1024,
        ),
    )
    assert service.process.returncode != 0
    response = json.loads(service.process.stdout)
    assert response["kind"] == "result"
    assert response["process"]["returncode"] < 0
    assert response["process"]["duration_ms"] < 2_000
    assert response["cleanup"]["namespace_empty"] is True
    assert service.observed_properties["RuntimeMaxUSec"] == "1s"
    assert service.cgroup_empty is True


@pytest.mark.host
def test_010_memory_max_cgroup_file_caps_stressed_workload() -> None:
    memory_max = 64 * 1024 * 1024
    unit_name = new_unit_name("memory-stress")
    limits = ServiceLimits(
        memory_max_bytes=memory_max,
        runtime_max_seconds=20,
        timeout_stop_seconds=1,
        output_max_bytes=64 * 1024,
    )
    code = (
        "import time; payload=bytearray(256*1024*1024); "
        "payload[::4096]=b'x'*(len(payload)//4096); time.sleep(60)"
    )
    process = subprocess.Popen(
        build_systemd_run_argv(unit_name, ("/usr/bin/python3", "-c", code), limits),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=service_environment(),
        close_fds=True,
        start_new_session=True,
    )
    control_group: str | None = None
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            observed = subprocess.run(
                (
                    "/usr/bin/systemctl",
                    "--user",
                    "show",
                    unit_name,
                    "--property=ControlGroup",
                    "--value",
                ),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=service_environment(),
                close_fds=True,
                check=False,
                timeout=2,
            )
            candidate = observed.stdout.decode("ascii", "strict").strip()
            if candidate.startswith("/") and ".." not in candidate.split("/"):
                control_group = candidate
                break
            time.sleep(0.02)
        if control_group is None:
            pytest.xfail("blocked: live user-service cgroup path is unavailable")
        cgroup = Path("/sys/fs/cgroup") / control_group.lstrip("/")
        try:
            assert (cgroup / "memory.max").read_text(encoding="ascii").strip() == str(
                memory_max
            )
        except FileNotFoundError:
            pytest.xfail("blocked: cgroup-v2 memory controller is unavailable")

        event_deadline = time.monotonic() + 5
        max_events = 0
        while time.monotonic() < event_deadline:
            events = dict(
                line.split()
                for line in (cgroup / "memory.events").read_text(encoding="ascii").splitlines()
            )
            max_events = int(events.get("max", "0"))
            if max_events > 0:
                break
            time.sleep(0.02)
        assert max_events > 0, "stressed workload never encountered the configured MemoryMax"
        assert int((cgroup / "memory.current").read_text(encoding="ascii")) <= memory_max
    finally:
        for selected_signal in ("TERM", "KILL"):
            subprocess.run(
                (
                    "/usr/bin/systemctl",
                    "--user",
                    "kill",
                    "--kill-whom=all",
                    f"--signal={selected_signal}",
                    unit_name,
                ),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=service_environment(),
                close_fds=True,
                check=False,
                timeout=2,
            )
        try:
            process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=2)
