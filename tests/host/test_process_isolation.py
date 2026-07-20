from __future__ import annotations

import base64
import errno
import json
import os
import subprocess
from pathlib import Path

import pytest

from agent_loop.constants import Limits
from agent_loop.manifests import SubjectManifest
from agent_loop.sandbox import SandboxMount, SandboxPolicy, build_bwrap_argv
from agent_loop.sandbox_init import SandboxRequest, SupervisorLimits, encode_request


_ISOLATION_PROBE = r"""
import errno, fcntl, json, os, resource
from pathlib import Path

result = {}

open_fds = []
open_fd_targets = {}
for descriptor in range(3, 256):
    try:
        fcntl.fcntl(descriptor, fcntl.F_GETFD)
    except OSError as exc:
        if exc.errno != errno.EBADF:
            raise
    else:
        open_fds.append(descriptor)
        try:
            open_fd_targets[str(descriptor)] = os.readlink(f"/proc/self/fd/{descriptor}")
        except OSError as exc:
            open_fd_targets[str(descriptor)] = f"unreadable:{exc.errno}"
result["inherited_fds"] = open_fds
result["inherited_fd_targets"] = open_fd_targets

def attempt(name, operation):
    try:
        operation()
    except OSError as exc:
        result[name] = {"allowed": False, "errno": exc.errno}
    else:
        result[name] = {"allowed": True, "errno": 0}

attempt("proc_environ", lambda: open("/proc/1/environ", "rb").read(1))
attempt("proc_fds", lambda: os.listdir("/proc/1/fd"))
attempt("proc_mem", lambda: open("/proc/1/mem", "rb").read(1))

import ctypes
libc = ctypes.CDLL(None, use_errno=True)
ctypes.set_errno(0)
ptrace_result = libc.ptrace(16, 1, None, None)
result["ptrace"] = {"allowed": ptrace_result == 0, "errno": ctypes.get_errno()}
if ptrace_result == 0:
    libc.ptrace(17, 1, None, None)

class IOVec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("length", ctypes.c_size_t)]

local_byte = ctypes.c_char()
local = IOVec(ctypes.addressof(local_byte), 1)
remote = IOVec(1, 1)
ctypes.set_errno(0)
vm_result = libc.process_vm_readv(
    1, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0
)
result["process_vm_readv"] = {"allowed": vm_result >= 0, "errno": ctypes.get_errno()}

try:
    pidfd = os.pidfd_open(1)
except OSError as exc:
    result["pidfd_getfd"] = {"allowed": False, "errno": exc.errno}
else:
    try:
        ctypes.set_errno(0)
        duplicate = libc.syscall(438, pidfd, 1, 0)
        result["pidfd_getfd"] = {"allowed": duplicate >= 0, "errno": ctypes.get_errno()}
        if duplicate >= 0:
            os.close(duplicate)
    finally:
        os.close(pidfd)

result["core_limit"] = list(resource.getrlimit(resource.RLIMIT_CORE))
result["environment_keys"] = sorted(os.environ)
Path("isolation.json").write_text(json.dumps(result, sort_keys=True))
"""


_UNTRUSTED_CHILD_PROBE = r"""
import ctypes, errno, json, os

parent = os.getppid()
result = {"child_environment_keys": sorted(os.environ)}

def attempt(name, operation):
    try:
        operation()
    except OSError as exc:
        result[name] = {"allowed": False, "errno": exc.errno}
    else:
        result[name] = {"allowed": True, "errno": 0}

attempt("parent_environ", lambda: open(f"/proc/{parent}/environ", "rb").read(1))
attempt("parent_fds", lambda: os.listdir(f"/proc/{parent}/fd"))
attempt("parent_mem", lambda: open(f"/proc/{parent}/mem", "rb").read(1))

libc = ctypes.CDLL(None, use_errno=True)
ctypes.set_errno(0)
ptrace_result = libc.ptrace(16, parent, None, None)
result["parent_ptrace"] = {"allowed": ptrace_result == 0, "errno": ctypes.get_errno()}
if ptrace_result == 0:
    libc.ptrace(17, parent, None, None)

class IOVec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("length", ctypes.c_size_t)]

local_byte = ctypes.c_char()
local = IOVec(ctypes.addressof(local_byte), 1)
remote = IOVec(1, 1)
ctypes.set_errno(0)
vm_result = libc.process_vm_readv(
    parent, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0
)
result["parent_process_vm_readv"] = {
    "allowed": vm_result >= 0,
    "errno": ctypes.get_errno(),
}

try:
    pidfd = os.pidfd_open(parent)
except OSError as exc:
    result["parent_pidfd_getfd"] = {"allowed": False, "errno": exc.errno}
else:
    try:
        ctypes.set_errno(0)
        duplicate = libc.syscall(438, pidfd, 1, 0)
        result["parent_pidfd_getfd"] = {
            "allowed": duplicate >= 0,
            "errno": ctypes.get_errno(),
        }
        if duplicate >= 0:
            os.close(duplicate)
    finally:
        os.close(pidfd)

print(json.dumps(result, sort_keys=True))
"""


_PRIMARY_PARENT_PROBE = (
    r"""
import ctypes, json, os, pathlib, subprocess

libc = ctypes.CDLL(None, use_errno=True)
parent_dumpable = libc.prctl(3, 0, 0, 0, 0)
child = subprocess.run(
    ("/usr/bin/python3", "-c", CHILD_CODE),
    stdin=subprocess.DEVNULL,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    env={"PATH": "/usr/bin:/bin", "HOME": "/runtime/home", "LANG": "C.UTF-8"},
    close_fds=True,
    check=False,
    timeout=5,
)
result = json.loads(child.stdout)
result["child_returncode"] = child.returncode
result["child_stderr"] = child.stderr.decode("utf-8", "backslashreplace")
result["parent_dumpable"] = parent_dumpable
result["parent_held_sentinel"] = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN") == "parent-secret"
pathlib.Path("isolation.json").write_text(json.dumps(result, sort_keys=True))
""".replace("CHILD_CODE", repr(_UNTRUSTED_CHILD_PROBE))
)


def _request(
    code: str = _ISOLATION_PROBE,
    *,
    env: tuple[tuple[str, str], ...] | None = None,
) -> SandboxRequest:
    return SandboxRequest(
        manifest=SubjectManifest.empty(),
        blobs=(),
        argv=("/usr/bin/python3", "-c", code),
        env=env
        or (("HOME", "/runtime/home"), ("LANG", "C.UTF-8"), ("PATH", "/usr/bin:/bin")),
        cwd="/workspace",
        stdin_bytes=b"",
        limits=SupervisorLimits(
            timeout_ms=3_000,
            terminate_grace_ms=300,
            max_output_bytes=64 * 1024,
            max_export_bytes=2 * 1024 * 1024,
            subject=Limits(
                max_files=64,
                max_file_bytes=1024 * 1024,
                max_total_subject_bytes=2 * 1024 * 1024,
            ),
        ),
    )


def _run_probe(request: SandboxRequest | None = None) -> dict[str, object]:
    source = Path("src").resolve()
    policy = SandboxPolicy.validation(
        mounts=(SandboxMount(os.fspath(source), "/opt/agent-loop"),)
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
        input=encode_request(request or _request()),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        close_fds=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "backslashreplace")
    response = json.loads(completed.stdout)
    assert response["kind"] == "result"
    entries = {
        base64.b64decode(entry["path_b64"]): entry
        for entry in response["candidate_manifest"]["entries"]
    }
    blobs = {
        blob["sha256"]: base64.b64decode(blob["data_b64"])
        for blob in response["new_blobs"]
    }
    return json.loads(blobs[entries[b"isolation.json"]["blob_sha256"]])


@pytest.mark.host
def test_030_proc_parent_environment_descriptors_and_memory_are_denied() -> None:
    result = _run_probe()
    for name in ("proc_environ", "proc_fds", "proc_mem"):
        assert result[name]["allowed"] is False
        assert result[name]["errno"] in {errno.EPERM, errno.EACCES}


@pytest.mark.host
def test_030_ptrace_process_vm_and_pidfd_getfd_are_denied() -> None:
    result = _run_probe()
    for name in ("ptrace", "process_vm_readv", "pidfd_getfd"):
        if result[name]["errno"] == errno.ENOSYS:
            pytest.xfail(
                f"blocked: host kernel cannot prove {name} denial because syscall is absent"
            )
        assert result[name]["allowed"] is False
        assert result[name]["errno"] in {errno.EPERM, errno.EACCES}


@pytest.mark.host
def test_030_no_inherited_descriptors_core_or_ambient_credentials() -> None:
    result = _run_probe()
    assert result["inherited_fds"] == [], result["inherited_fd_targets"]
    assert result["core_limit"] == [0, 0]
    assert result["environment_keys"] == ["HOME", "LANG", "PATH"]


@pytest.mark.host
def test_030_untrusted_child_cannot_introspect_trusted_primary_parent() -> None:
    request = _request(
        _PRIMARY_PARENT_PROBE,
        env=(
            ("CLAUDE_CODE_OAUTH_TOKEN", "parent-secret"),
            ("HOME", "/runtime/home"),
            ("LANG", "C.UTF-8"),
            ("PATH", "/usr/bin:/bin"),
        ),
    )
    result = _run_probe(request)
    assert result["parent_held_sentinel"] is True
    assert result["parent_dumpable"] == 0
    assert result["child_returncode"] == 0, result["child_stderr"]
    assert result["child_environment_keys"] == ["HOME", "LANG", "PATH"]
    for name in ("parent_environ", "parent_fds", "parent_mem"):
        assert result[name]["allowed"] is False
        assert result[name]["errno"] in {errno.EPERM, errno.EACCES}
    for name in (
        "parent_ptrace",
        "parent_process_vm_readv",
        "parent_pidfd_getfd",
    ):
        if result[name]["errno"] == errno.ENOSYS:
            pytest.xfail(
                f"blocked: host kernel cannot prove {name} denial because syscall is absent"
            )
        assert result[name]["allowed"] is False
        assert result[name]["errno"] in {errno.EPERM, errno.EACCES}
