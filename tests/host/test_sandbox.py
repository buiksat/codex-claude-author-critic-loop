from __future__ import annotations

import base64
import json
import os
import subprocess
from pathlib import Path

import pytest

from agent_loop.constants import Limits
from agent_loop.manifests import SubjectManifest
from agent_loop.sandbox import SandboxMount, SandboxPolicy, build_bwrap_argv
from agent_loop.sandbox_init import SandboxRequest, SupervisorLimits, encode_request


def _object(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    return value


def _string(value: object) -> str:
    assert isinstance(value, str)
    return value


def _empty_request(code: str) -> SandboxRequest:
    return SandboxRequest(
        manifest=SubjectManifest.empty(),
        blobs=(),
        argv=("/usr/bin/python3", "-c", code),
        env=(
            ("HOME", "/runtime/home"),
            ("LANG", "C.UTF-8"),
            ("PATH", "/usr/bin:/bin"),
            ("TMPDIR", "/runtime/tmp"),
        ),
        cwd="/workspace",
        stdin_bytes=b"",
        limits=SupervisorLimits(
            timeout_ms=2_000,
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


def _run_bwrap(
    request: SandboxRequest,
) -> tuple[subprocess.CompletedProcess[bytes], dict[str, object]]:
    source = Path("src").resolve()
    policy = SandboxPolicy.validation(mounts=(SandboxMount(os.fspath(source), "/opt/agent-loop"),))
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
        capture_output=True,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        close_fds=True,
        check=False,
        timeout=10,
    )
    decoded: object = json.loads(completed.stdout) if completed.stdout else {}
    result = _object(decoded)
    return completed, result


@pytest.mark.host
def test_009_full_tmpfs_is_exported_only_after_cleanup() -> None:
    request = _empty_request(
        "from pathlib import Path; Path('created').write_bytes(b'candidate'); print('ok')"
    )
    completed, result = _run_bwrap(request)
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "backslashreplace")
    assert result["kind"] == "result"
    assert result["cleanup"] == {
        "export_started_after_cleanup": True,
        "namespace_empty": True,
        "terminated_pids": 0,
    }
    process = _object(result["process"])
    assert base64.b64decode(_string(process["stdout_b64"])) == b"ok\n"
    candidate_manifest = _object(result["candidate_manifest"])
    entries = candidate_manifest["entries"]
    assert isinstance(entries, list)
    assert [base64.b64decode(_string(_object(entry)["path_b64"])) for entry in entries] == [
        b"created"
    ]
    new_blobs = result["new_blobs"]
    assert isinstance(new_blobs, list)
    assert [base64.b64decode(_string(_object(blob)["data_b64"])) for blob in new_blobs] == [
        b"candidate"
    ]


@pytest.mark.host
def test_009_sandbox_init_is_pid_one_and_workspace_has_no_host_backing() -> None:
    request = _empty_request(
        "from pathlib import Path; "
        "Path('identity').write_text(Path('/proc/1/comm').read_text().strip()); "
        "Path('mount').write_text(next(x for x in Path('/proc/mounts').read_text().splitlines() "
        "if x.split()[1]=='/workspace'))"
    )
    completed, result = _run_bwrap(request)
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "backslashreplace")
    raw_blobs = result["new_blobs"]
    assert isinstance(raw_blobs, list)
    exported: dict[str, bytes] = {}
    for value in raw_blobs:
        blob = _object(value)
        exported[_string(blob["sha256"])] = base64.b64decode(_string(blob["data_b64"]))
    candidate_manifest = _object(result["candidate_manifest"])
    raw_entries = candidate_manifest["entries"]
    assert isinstance(raw_entries, list)
    entry_by_path: dict[bytes, dict[str, object]] = {}
    for value in raw_entries:
        entry = _object(value)
        entry_by_path[base64.b64decode(_string(entry["path_b64"]))] = entry
    identity = exported[_string(entry_by_path[b"identity"]["blob_sha256"])]
    mount = exported[_string(entry_by_path[b"mount"]["blob_sha256"])]
    assert identity in {b"python3", b"python3.14"}
    assert b" /workspace tmpfs " in mount
