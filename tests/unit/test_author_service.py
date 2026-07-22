from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import cast

import pytest

import agent_loop.author_service as author_service_module
from agent_loop.author_service import (
    AUTHOR_SERVICE_PUBLICATION_ROOT,
    AuthorMountDescriptor,
    _broker_error_header,
    _limits_json,
    _mount_header,
    _raise_broker_error,
    _remove_closure_publication,
    _run_system_author,
    _safe_publication_directory,
    _validate_author_request_shape,
    _validate_broker_request,
    _validate_probe_request,
    build_system_author_argv,
)
from agent_loop.codex_client import (
    build_codex_first_argv,
    build_codex_parent_environment,
)
from agent_loop.constants import Limits
from agent_loop.errors import AgentLoopError, StopReason
from agent_loop.manifests import SubjectManifest
from agent_loop.provenance import (
    closure_sha256,
    normalized_closure_sha256,
    snapshot_descriptor_closure,
    snapshot_reviewed_closure,
)
from agent_loop.sandbox import SandboxMount
from agent_loop.sandbox_init import SandboxRequest, SupervisorLimits
from agent_loop.service import (
    BoundedProcessResult,
    BoundedProcessStartFailure,
    ServiceLimits,
)

CODEX_TARGET = "/opt/agent-loop-tools/codex-package"
CODEX_EXECUTABLE = CODEX_TARGET + "/bin/codex.js"
RUNTIME_TARGET = "/opt/agent-loop-runtime/agent_loop"


def _request(*, argv: tuple[str, ...] | None = None) -> SandboxRequest:
    return SandboxRequest(
        manifest=SubjectManifest.empty(),
        blobs=(),
        argv=argv or build_codex_first_argv("implement", executable=CODEX_EXECUTABLE),
        env=tuple(sorted(build_codex_parent_environment().items())),
        cwd="/runtime/author-cwd",
        stdin_bytes=b"",
        limits=SupervisorLimits(
            timeout_ms=15_000,
            terminate_grace_ms=1_000,
            max_output_bytes=1024,
            max_export_bytes=1024 * 1024,
            subject=Limits(max_files=16, max_total_subject_bytes=1024 * 1024),
        ),
    )


def _service_limits() -> ServiceLimits:
    return ServiceLimits(runtime_max_seconds=20, output_max_bytes=1024 * 1024)


def test_fixed_system_author_argv_has_manager_pid_minroot_and_exact_exec() -> None:
    unit_name = "agent-loop-author-1000-0123456789abcdef0123456789abcdef.service"
    publication = f"{AUTHOR_SERVICE_PUBLICATION_ROOT}/{unit_name.removesuffix('.service')}"
    argv = build_system_author_argv(
        unit_name=unit_name,
        broker_unit="agent-loop-author@1-0.service",
        peer_uid=1000,
        peer_gid=1000,
        workspace_bytes=4 * 1024 * 1024,
        mounts=(
            (f"{publication}/mount-00/agent_loop", RUNTIME_TARGET, True),
            (f"{publication}/mount-01/codex", CODEX_TARGET, True),
            (12, "/control/codex-home", False),
        ),
        limits=_service_limits(),
        broker_pid=4242,
    )

    rendered = "\n".join(argv)
    assert "--user" not in argv
    assert "--uid=1000" in argv
    assert "--gid=1000" in argv
    assert "PrivatePIDs=yes" in rendered
    assert "PrivateIPC=yes" in rendered
    assert "ProtectHostname=yes" in rendered
    assert "ProtectProc=invisible" in rendered
    assert "ProcSubset=all" in rendered
    assert "SupplementaryGroups=" in rendered
    assert "CapabilityBoundingSet=" in rendered
    assert "RestrictSUIDSGID=" not in rendered
    assert "TemporaryFileSystem=/opt:nodev,nosuid,size=4194304,mode=0755" in rendered
    assert "TemporaryFileSystem=/runtime/author-cwd:" in rendered
    assert "TemporaryFileSystem=/workspace:" in rendered
    assert (
        "TemporaryFileSystem=/control/codex-home/.tmp:nodev,nosuid,noexec,"
        "size=268435456,mode=0700,uid=1000,gid=1000" in rendered
    )
    assert (
        "TemporaryFileSystem=/control/codex-home/tmp:nodev,nosuid,noexec,"
        "size=16777216,mode=0700,uid=1000,gid=1000" in rendered
    )
    assert (
        "TemporaryFileSystem=/control/codex-home/skills:nodev,nosuid,noexec,"
        "size=16777216,mode=0700,uid=1000,gid=1000" in rendered
    )
    assert (
        "TemporaryFileSystem=/control/codex-home/plugins:nodev,nosuid,noexec,"
        "size=67108864,mode=0700,uid=1000,gid=1000" in rendered
    )
    assert f"BindReadOnlyPaths={publication}/mount-00/agent_loop:{RUNTIME_TARGET}" in rendered
    assert f"BindReadOnlyPaths={publication}/mount-01/codex:{CODEX_TARGET}" in rendered
    assert "BindPaths=/proc/4242/fd/12:/control/codex-home" in rendered
    assert argv[-6:-1] == ("/usr/bin/python3", "-I", "-B", "-S", "-c")
    assert "agent_loop.sandbox_init" in argv[-1]


@pytest.mark.parametrize(
    "target",
    (
        "/opt/bad:target",
        "/opt/bad%target",
        "/opt/bad target",
        "/opt/bad\\target",
        "/opt/../bad",
    ),
)
def test_fixed_system_author_rejects_systemd_path_syntax(target: str) -> None:
    unit_name = "agent-loop-author-1000-0123456789abcdef0123456789abcdef.service"
    source = (
        f"{AUTHOR_SERVICE_PUBLICATION_ROOT}/{unit_name.removesuffix('.service')}"
        "/mount-00/agent_loop"
    )
    with pytest.raises(ValueError):
        build_system_author_argv(
            unit_name=unit_name,
            broker_unit="agent-loop-author@1-0.service",
            peer_uid=1000,
            peer_gid=1000,
            workspace_bytes=1024,
            mounts=((source, target, True),),
            limits=_service_limits(),
            broker_pid=4242,
        )


def test_fixed_system_author_separates_published_read_only_and_live_control() -> None:
    unit_name = "agent-loop-author-1000-0123456789abcdef0123456789abcdef.service"
    publication = f"{AUTHOR_SERVICE_PUBLICATION_ROOT}/{unit_name.removesuffix('.service')}"

    def build(mounts: tuple[tuple[int | str, str, bool], ...]) -> tuple[str, ...]:
        return build_system_author_argv(
            unit_name=unit_name,
            broker_unit="agent-loop-author@1-0.service",
            peer_uid=1000,
            peer_gid=1000,
            workspace_bytes=1024,
            mounts=mounts,
            limits=_service_limits(),
            broker_pid=4242,
        )

    with pytest.raises(ValueError, match="read-only"):
        build(((f"{publication}/mount-00/agent_loop", RUNTIME_TARGET, False),))
    with pytest.raises(ValueError, match="only CODEX_HOME"):
        build(((10, RUNTIME_TARGET, True),))
    with pytest.raises(ValueError, match="request identity"):
        build(
            (
                (
                    f"{AUTHOR_SERVICE_PUBLICATION_ROOT}/agent-loop-author-1000-"
                    f"{'f' * 32}/mount-00/agent_loop",
                    RUNTIME_TARGET,
                    True,
                ),
            )
        )


def test_host_visible_publication_is_private_and_descriptor_safely_removed(
    tmp_path: Path,
) -> None:
    unit_name = "agent-loop-author-1000-0123456789abcdef0123456789abcdef.service"
    publication_root = tmp_path / "author-closures"
    publication = _safe_publication_directory(
        unit_name,
        publication_root=publication_root,
        owner_uid=os.getuid(),
        owner_gid=os.getgid(),
    )
    assert publication.is_dir()
    assert (publication_root.stat().st_mode & 0o777) == 0o700
    assert (publication.stat().st_mode & 0o777) == 0o700

    mount = publication / "mount-00"
    closure = mount / "agent_loop"
    mount.mkdir(mode=0o700)
    closure.mkdir(mode=0o700)
    payload = closure / "sandbox_init.py"
    payload.write_bytes(b"pass\n")
    payload.chmod(0o444)
    closure.chmod(0o555)

    _remove_closure_publication(
        publication,
        publication_root=publication_root,
        owner_uid=os.getuid(),
        owner_gid=os.getgid(),
    )
    assert not publication.exists()
    assert publication_root.is_dir()


def test_author_request_grammar_rejects_arbitrary_command_and_environment() -> None:
    targets = {RUNTIME_TARGET, CODEX_TARGET, "/control/codex-home"}
    _validate_author_request_shape(_request(), targets)

    with pytest.raises(ValueError, match="executable"):
        _validate_author_request_shape(_request(argv=("/usr/bin/id",)), targets)

    request = _request()
    broadened = SandboxRequest(
        request.manifest,
        request.blobs,
        request.argv,
        (*request.env, ("TERM", "xterm")),
        request.cwd,
        request.stdin_bytes,
        request.limits,
    )
    with pytest.raises(ValueError, match="environment"):
        _validate_author_request_shape(broadened, targets)


def test_broker_revalidates_fd_identities_mount_classes_and_fixed_limits(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    install = tmp_path / "codex"
    control = tmp_path / "control"
    toolchain = tmp_path / "toolchain"
    for directory in (runtime, install, control, toolchain):
        directory.mkdir(mode=0o700)
    authorities: list[AuthorMountDescriptor] = []
    descriptors: list[int] = []
    try:
        for source, target, read_only in (
            (runtime, RUNTIME_TARGET, True),
            (install, CODEX_TARGET, True),
            (toolchain, "/opt/agent-loop-toolchains/" + "a" * 64, True),
            (control, "/control/codex-home", False),
        ):
            descriptor = os.open(source, os.O_RDONLY | os.O_DIRECTORY)
            descriptors.append(descriptor)
            authorities.append(
                AuthorMountDescriptor(
                    SandboxMount(
                        str(source),
                        target,
                        read_only,
                        closure_sha256=("a" * 64 if read_only else None),
                    ),
                    descriptor,
                )
            )
        header = {
            "protocol": 1,
            "kind": "run",
            "request_bytes": 7,
            "request_sha256": "0" * 64,
            "workspace_bytes": 1024,
            "limits": _limits_json(_service_limits()),
            "mounts": _mount_header(authorities),
        }
        workspace, limits, mounts, digest = _validate_broker_request(
            header,
            descriptors,
            7,
            peer_uid=os.getuid(),
            allowed_codex_closure="a" * 64,
            installed_runtime_closure="a" * 64,
        )
        assert workspace == 1024
        assert limits == _service_limits()
        assert [target for _fd, target, _ro, *_metadata in mounts] == [
            RUNTIME_TARGET,
            CODEX_TARGET,
            "/opt/agent-loop-toolchains/" + "a" * 64,
            "/control/codex-home",
        ]
        assert digest == "0" * 64

        unsafe = dict(header)
        unsafe_mounts = [dict(value) for value in cast(list[dict[str, object]], header["mounts"])]
        unsafe_mounts[1]["target"] = "/home/operator/toolchain"
        unsafe["mounts"] = unsafe_mounts
        with pytest.raises(ValueError, match="unconfigured mount-target class"):
            _validate_broker_request(
                unsafe,
                descriptors,
                7,
                peer_uid=os.getuid(),
                allowed_codex_closure="a" * 64,
                installed_runtime_closure="a" * 64,
            )

        unreviewed = dict(header)
        unreviewed_mounts = [
            dict(value) for value in cast(list[dict[str, object]], header["mounts"])
        ]
        unreviewed_mounts[1]["closure_sha256"] = "b" * 64
        unreviewed["mounts"] = unreviewed_mounts
        with pytest.raises(ValueError, match="reviewed install"):
            _validate_broker_request(
                unreviewed,
                descriptors,
                7,
                peer_uid=os.getuid(),
                allowed_codex_closure="a" * 64,
                installed_runtime_closure="a" * 64,
            )
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def test_fixed_service_limits_reject_broadened_cgroup_contract() -> None:
    with pytest.raises(ValueError, match="fixed-service contract"):
        _limits_json(ServiceLimits(memory_max_bytes=2 * 1024 * 1024 * 1024))


def test_probe_and_run_protocol_reject_boolean_protocol_aliases() -> None:
    with pytest.raises(ValueError, match="probe contract"):
        _validate_probe_request(
            {"protocol": True, "kind": "probe", "build_id": "fixed-system-author-v1"}
        )


def test_broker_rejection_diagnostic_is_stable_and_does_not_reflect_exception_text() -> None:
    sensitive_marker = "operator-sensitive-path-and-value"
    response = _broker_error_header(ValueError(sensitive_marker), "closure_snapshot")

    assert response == {
        "protocol": 1,
        "kind": "error",
        "reason": StopReason.SANDBOX_SETUP_FAILURE.value,
        "detail": "fixed author broker rejected the request",
        "diagnostic_code": "closure_snapshot",
    }
    assert sensitive_marker not in repr(response)

    with pytest.raises(AgentLoopError) as caught:
        _raise_broker_error(response)
    assert caught.value.reason is StopReason.SANDBOX_SETUP_FAILURE
    assert caught.value.detail == (
        "fixed author broker rejected the request [broker diagnostic: closure_snapshot]"
    )


def test_broker_rejection_diagnostic_rejects_unrecognized_or_extra_fields() -> None:
    response = _broker_error_header(RuntimeError("do not reflect me"), "unknown-stage")
    assert response["diagnostic_code"] == "broker_bootstrap"

    response["diagnostic_code"] = "invented"
    with pytest.raises(AgentLoopError, match="error was malformed"):
        _raise_broker_error(response)

    response["diagnostic_code"] = "request_policy"
    response["untrusted"] = "value"
    with pytest.raises(AgentLoopError, match="error was malformed"):
        _raise_broker_error(response)

    header = {
        "protocol": True,
        "kind": "run",
        "request_bytes": 1,
        "request_sha256": "0" * 64,
        "workspace_bytes": 1,
        "limits": _limits_json(_service_limits()),
        "mounts": [],
    }
    with pytest.raises(ValueError, match="schema"):
        _validate_broker_request(
            header,
            (),
            1,
            peer_uid=os.getuid(),
            allowed_codex_closure="a" * 64,
            installed_runtime_closure="a" * 64,
        )


def test_broker_snapshot_rehashes_and_normalizes_an_open_closure(tmp_path: Path) -> None:
    source = tmp_path / "toolchain"
    source.mkdir(mode=0o700)
    payload = source / "tool"
    payload.write_bytes(b"reviewed-toolchain")
    payload.chmod(0o555)
    source.chmod(0o555)
    expected = closure_sha256(source)
    destination = tmp_path / "broker"
    destination.mkdir(mode=0o700)
    descriptor = os.open(source, os.O_RDONLY | os.O_DIRECTORY)
    try:
        snapshot, digest, entries, total_bytes = snapshot_descriptor_closure(
            descriptor,
            destination,
            expected,
            root_name=b"toolchain",
            allowed_owner_uid=os.getuid(),
        )
    finally:
        os.close(descriptor)
    assert digest == expected
    assert entries == 1
    assert total_bytes == len(b"reviewed-toolchain")
    assert (snapshot / "tool").read_bytes() == b"reviewed-toolchain"
    assert (snapshot / "tool").stat().st_mode & 0o777 == 0o555


def test_normalized_codex_digest_helper_matches_the_actual_mount_witness(
    tmp_path: Path,
) -> None:
    source = tmp_path / "codex"
    source.mkdir(mode=0o755)
    (source / "codex.js").write_bytes(b"reviewed-codex")
    raw = closure_sha256(source)
    expected = normalized_closure_sha256(source)
    snapshot_parent = tmp_path / "snapshot"
    snapshot_parent.mkdir(mode=0o700)
    _snapshot, mounted = snapshot_reviewed_closure(source, snapshot_parent, raw)
    assert mounted == expected
    assert mounted != raw


def test_author_start_failure_still_kills_and_proves_unit_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    primary = RuntimeError("post-spawn failure")
    bounded = BoundedProcessResult(1, b"", b"", 1.0, 2.0, False, False)
    killed: list[str] = []

    def fail_start(*_args: object, **_kwargs: object) -> BoundedProcessResult:
        raise BoundedProcessStartFailure(primary, bounded)

    monkeypatch.setattr(author_service_module, "run_bounded_process", fail_start)
    monkeypatch.setattr(
        author_service_module,
        "_kill_system_unit",
        lambda unit: killed.append(unit),
    )
    monkeypatch.setattr(author_service_module, "_author_unit_absent", lambda _unit: True)

    unit = "agent-loop-author-1000-0123456789abcdef0123456789abcdef.service"
    with pytest.raises(RuntimeError, match="post-spawn failure") as caught:
        _run_system_author(
            request=b"request",
            unit_name=unit,
            broker_unit="agent-loop-author@1-0.service",
            peer_uid=1000,
            peer_gid=1000,
            workspace_bytes=1024,
            mounts=(),
            timeout_seconds=1,
            limits=_service_limits(),
            cancelled=threading.Event(),
        )
    assert caught.value is primary
    assert killed == [unit]


def test_root_bootstrap_uses_only_hash_verified_wheel_assets() -> None:
    script = Path("support/author-service/install.sh").read_text(encoding="utf-8")
    uninstaller = Path("support/author-service/uninstall.sh").read_text(encoding="utf-8")
    socket_unit = Path("support/author-service/agent-loop-author.socket").read_text(
        encoding="utf-8"
    )
    broker_unit = Path("support/author-service/agent-loop-author@.service").read_text(
        encoding="utf-8"
    )
    assert "EXPECTED_SHA256" in script.upper()
    assert "asset_root=$install_root/runtime/share/agent-loop/support/author-service" in script
    assert '$(dirname "$0")/agent-loop-author' not in script
    assert "stat -c %u" in script
    assert "root-owned wheel copy failed verification" in script
    assert "SocketMode=0600" in script
    assert "agent_loop-1.1.0-py3-none-any.whl" in script
    assert 'find "$staging" -type d -exec chmod 0755 {} +' in script
    assert 'install_absent_file "$install_root/author-service.conf" "$config_file" 0644' in script
    assert "chmod 0644 \\" in script
    assert '"$asset_root/agent-loop-author.socket"' in script
    assert '"$asset_root/agent-loop-author@.service"' in script
    assert "AGENT_LOOP_AUTHOR_CODEX_CLOSURE_SHA256" in script
    assert "codex_closure_sha256" in script
    listen_stream = next(
        line.removeprefix("ListenStream=")
        for line in socket_unit.splitlines()
        if line.startswith("ListenStream=")
    )
    assert f"runtime_socket={listen_stream}" in script
    assert 'rm -f -- "$runtime_socket"' in script
    assert 'rmdir -- "$runtime_directory"' not in script
    assert "EXPECTED_INSTALLED_WHEEL_SHA256" in uninstaller.upper()
    assert "author-service-uninstall.txt" in uninstaller
    assert 'rm -rf --one-file-system -- "$install_root"' in uninstaller
    assert 'rm -rf -- "$config_directory"' not in uninstaller
    assert 'rm -rf -- "$runtime_directory"' not in uninstaller
    assert "/usr/bin/python3 -I -B -S -c" in broker_unit
    assert "runpy.run_module('agent_loop.author_service'" in broker_unit
    assert "CapabilityBoundingSet=CAP_DAC_READ_SEARCH" in broker_unit
    assert "AmbientCapabilities=CAP_DAC_READ_SEARCH" in broker_unit
    assert "CAP_DAC_OVERRIDE" not in broker_unit
    assert "CAP_DAC_WRITE" not in broker_unit
    assert "RuntimeDirectory=agent-loop/author-closures" in broker_unit
    assert "RuntimeDirectoryMode=0700" in broker_unit
    assert "RuntimeDirectoryPreserve=yes" in broker_unit
