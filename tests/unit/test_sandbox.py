import hashlib
import os
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

import agent_loop.sandbox as sandbox_module
from agent_loop.errors import AgentLoopError, StopReason
from agent_loop.sandbox import SandboxMount, SandboxPolicy, build_bwrap_argv


def test_role_network_split_is_explicit() -> None:
    author = build_bwrap_argv(SandboxPolicy.author(), ("/usr/bin/true",))
    critic = build_bwrap_argv(SandboxPolicy.critic(), ("/usr/bin/true",))
    validation = build_bwrap_argv(SandboxPolicy.validation(), ("/usr/bin/true",))
    git = build_bwrap_argv(SandboxPolicy.git(), ("/usr/bin/true",))
    assert "--unshare-net" not in author
    assert "--unshare-net" not in critic
    assert "--unshare-net" in validation
    assert "--unshare-net" in git


def test_writable_host_mounts_are_control_only() -> None:
    with pytest.raises(ValueError):
        SandboxPolicy.author(mounts=(SandboxMount("/tmp", "/workspace/x", False),))
    with pytest.raises(ValueError):
        SandboxPolicy.validation(mounts=(SandboxMount("/tmp", "/control/x", False),))


def test_full_sized_tmpfs_not_overlay_is_used() -> None:
    argv = build_bwrap_argv(SandboxPolicy.validation(), ("/usr/bin/true",))
    assert "--tmp-overlay" not in argv
    workspace_index = argv.index("/workspace")
    assert argv[workspace_index - 1] == "--tmpfs"
    assert "--size" in argv[:workspace_index]


def test_mount_closure_witness_is_strict_and_read_only() -> None:
    SandboxMount("/tmp", "/opt/tool", closure_sha256="0" * 64)
    with pytest.raises(ValueError, match="lowercase SHA-256"):
        SandboxMount("/tmp", "/opt/tool", closure_sha256="A" * 64)
    with pytest.raises(ValueError, match="read-only"):
        SandboxMount("/tmp", "/control/tool", False, "0" * 64)


def _fake_bwrap_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> str:
    executable = tmp_path / "bwrap"
    executable.write_bytes(b"reviewed-bubblewrap")
    executable.chmod(0o755)
    actual = executable.stat()
    info = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o755,
        st_uid=0,
        st_gid=0,
        st_dev=actual.st_dev,
        st_ino=actual.st_ino,
    )
    original_open = os.open
    monkeypatch.setattr(sandbox_module.os, "lstat", lambda _path: info)
    monkeypatch.setattr(
        sandbox_module.os,
        "open",
        lambda _path, flags: original_open(executable, flags),
    )
    return hashlib.sha256(executable.read_bytes()).hexdigest()


def test_bubblewrap_probe_rejects_unverifiable_extended_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_bwrap_file(monkeypatch, tmp_path)
    monkeypatch.setattr(
        sandbox_module,
        "reject_extended_metadata_fd",
        lambda _descriptor: (_ for _ in ()).throw(ValueError("metadata unavailable")),
    )

    with pytest.raises(AgentLoopError) as caught:
        sandbox_module.probe_bubblewrap_package()

    assert caught.value.reason is StopReason.BWRAP_PACKAGE_OR_MODE_UNSAFE
    assert "extended metadata" in caught.value.detail


def test_011_bubblewrap_probe_rejects_setuid_unexpected_hash_and_vulnerable_revision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unsafe = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o4755,
        st_uid=0,
        st_gid=0,
    )
    monkeypatch.setattr(sandbox_module.os, "lstat", lambda _path: unsafe)
    with pytest.raises(AgentLoopError) as setuid:
        sandbox_module.probe_bubblewrap_package()
    assert setuid.value.reason is StopReason.BWRAP_PACKAGE_OR_MODE_UNSAFE

    digest = _fake_bwrap_file(monkeypatch, tmp_path)
    monkeypatch.setattr(sandbox_module, "SUPPORTED_BWRAP_SHA256", frozenset({"0" * 64}))
    with pytest.raises(AgentLoopError, match="unexpected Bubblewrap binary hash"):
        sandbox_module.probe_bubblewrap_package()

    monkeypatch.setattr(sandbox_module, "SUPPORTED_BWRAP_SHA256", frozenset({digest}))
    vulnerable = subprocess.CompletedProcess(
        ("dpkg-query",),
        0,
        b"0.11.0-unsafe",
        b"",
    )
    monkeypatch.setattr(sandbox_module, "_small_command", lambda _argv: vulnerable)
    with pytest.raises(AgentLoopError, match="unsupported Bubblewrap package revision"):
        sandbox_module.probe_bubblewrap_package()
