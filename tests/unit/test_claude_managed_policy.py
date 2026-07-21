from __future__ import annotations

import json
import os
import shutil
import stat
from pathlib import Path

import pytest

import agent_loop.claude_managed_policy as managed_policy
from agent_loop.provenance import closure_sha256
from agent_loop.service import BoundedProcessResult, run_bounded_process


_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_SUPPORT_ROOT = _REPOSITORY_ROOT / "support" / "managed-claude-boundary"
_POLICY_TEMPLATE = _SUPPORT_ROOT / "managed-settings.json"
_HELPER_SOURCE = _SUPPORT_ROOT / "agent-loop-claude-boundary-attest.c"

_HELPER_ENVIRONMENT = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
}

# This is the exact pinned-Claude scrub set reviewed for the managed child,
# including its four background-auth transports.  The helper also rejects the
# INPUT_<name> spelling Claude removes for every entry.
_SENSITIVE_ENVIRONMENT_NAMES = (
    "ANTHROPIC_API_KEY",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_FOUNDRY_API_KEY",
    "ANTHROPIC_FOUNDRY_AUTH_TOKEN",
    "ANTHROPIC_AWS_API_KEY",
    "ANTHROPIC_CUSTOM_HEADERS",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_BEARER_TOKEN_BEDROCK",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "AZURE_CLIENT_SECRET",
    "AZURE_CLIENT_CERTIFICATE_PATH",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_URL",
    "ACTIONS_RUNTIME_TOKEN",
    "ACTIONS_RUNTIME_URL",
    "ALL_INPUTS",
    "OVERRIDE_GITHUB_TOKEN",
    "DEFAULT_WORKFLOW_TOKEN",
    "SSH_SIGNING_KEY",
    "CLAUDE_BG_AUTH_SNAPSHOT_PATH",
    "CLAUDE_BG_SOCKET_TOKENS_PATH",
    "CLAUDE_BG_RV_AUTH",
    "CLAUDE_BG_PTY_AUTH",
)


def _event_bytes(**changes: object) -> bytes:
    event: dict[str, object] = {
        "session_id": "synthetic-session",
        "transcript_path": "/runtime/critic-tmp/transcript.jsonl",
        "cwd": "/runtime/critic-cwd",
        "permission_mode": "dontAsk",
        "hook_event_name": "SessionStart",
        "source": "startup",
    }
    event.update(changes)
    return json.dumps(
        event,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _run(
    argv: tuple[str, ...],
    *,
    input_bytes: bytes = b"",
    environment: dict[str, str],
    timeout_seconds: float = 10,
) -> BoundedProcessResult:
    return run_bounded_process(
        argv,
        input_bytes=input_bytes,
        timeout_seconds=timeout_seconds,
        output_max_bytes=256 * 1024,
        env=environment,
    )


@pytest.fixture(scope="module")
def compiled_helper(tmp_path_factory: pytest.TempPathFactory) -> Path:
    build_root = tmp_path_factory.mktemp("managed-claude-helper")
    executable = build_root / "agent-loop-claude-boundary-attest"
    common = (
        "/usr/bin/cc",
        "-std=c11",
        "-O2",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
    )
    build_environment = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    # Prefer the deployable static form.  A target without static libc still
    # exercises the same source through a conventional no-extra-library build.
    result = _run(
        (*common, "-static", "-o", os.fspath(executable), os.fspath(_HELPER_SOURCE)),
        environment=build_environment,
        timeout_seconds=30,
    )
    if result.returncode != 0:
        result = _run(
            (*common, "-o", os.fspath(executable), os.fspath(_HELPER_SOURCE)),
            environment=build_environment,
            timeout_seconds=30,
        )
    assert not result.timed_out
    assert not result.output_limited
    assert result.returncode == 0, (result.stdout + result.stderr).decode(
        "utf-8", "backslashreplace"
    )
    assert executable.is_file()
    return executable


def _run_helper(
    executable: Path,
    input_bytes: bytes,
    *,
    environment: dict[str, str] | None = None,
) -> BoundedProcessResult:
    return _run(
        (os.fspath(executable),),
        input_bytes=input_bytes,
        environment=dict(_HELPER_ENVIRONMENT if environment is None else environment),
    )


def test_reviewed_policy_template_is_exactly_the_operational_document() -> None:
    expected = (
        json.dumps(
            managed_policy.managed_claude_policy_document(),
            ensure_ascii=True,
            allow_nan=False,
            indent=2,
        )
        + "\n"
    ).encode("ascii")
    assert _POLICY_TEMPLATE.read_bytes() == expected
    assert managed_policy.managed_claude_policy_document() == {
        "allowManagedHooksOnly": True,
        "disableAllHooks": False,
        "hooks": {
            "SessionStart": [
                {
                    "matcher": "startup",
                    "hooks": [
                        {
                            "type": "command",
                            "command": managed_policy.MANAGED_CLAUDE_HELPER_TARGET,
                            "args": [],
                            "timeout": 5,
                        }
                    ],
                }
            ]
        },
    }


@pytest.mark.parametrize("layout", ["source", "wheel"])
def test_installer_offline_check_resolves_source_and_wheel_runtime_layouts(
    tmp_path: Path,
    layout: str,
) -> None:
    if layout == "source":
        layout_root = tmp_path / "repository"
        support_root = layout_root / "support" / "managed-claude-boundary"
        runtime_root = layout_root / "src"
    else:
        install_prefix = tmp_path / "pipx-venv"
        support_root = (
            install_prefix
            / "share"
            / "agent-loop"
            / "support"
            / "managed-claude-boundary"
        )
        runtime_root = install_prefix / "lib" / "python3.14" / "site-packages"

    shutil.copytree(_SUPPORT_ROOT, support_root)
    shutil.copytree(
        _REPOSITORY_ROOT / "src" / "agent_loop",
        runtime_root / "agent_loop",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )

    result = _run(
        ("/bin/bash", os.fspath(support_root / "install.sh"), "--check"),
        environment={
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        },
        timeout_seconds=30,
    )
    assert not result.timed_out
    assert not result.output_limited
    assert result.returncode == 0, (result.stdout + result.stderr).decode(
        "utf-8", "backslashreplace"
    )
    assert result.stdout == (
        b"managed Claude boundary inputs and static helper passed offline checks\n"
    )
    assert result.stderr == b""


def test_boundary_constants_pin_the_admin_paths_and_attestation() -> None:
    assert managed_policy.MANAGED_CLAUDE_POLICY_SOURCE == "/etc/claude-code"
    assert managed_policy.MANAGED_CLAUDE_POLICY_TARGET == "/etc/claude-code"
    expected_helper = "/usr/local/libexec/agent-loop-claude-boundary-attest"
    assert managed_policy.MANAGED_CLAUDE_HELPER_SOURCE == expected_helper
    assert managed_policy.MANAGED_CLAUDE_HELPER_TARGET == expected_helper
    assert managed_policy.MANAGED_CLAUDE_BOUNDARY_PROTOCOL == "attested-v1"
    assert managed_policy.MANAGED_CLAUDE_BOUNDARY_ID == "reviewed-managed-boundary-v1"
    assert managed_policy.MANAGED_CLAUDE_BOUNDARY_MARKER == (
        "AGENT_LOOP_MANAGED_CLAUDE_BOUNDARY_OK:reviewed-managed-boundary-v1:"
        "credential_absent:scrub=1"
    )


def test_helper_accepts_only_the_reviewed_session_start_shape(
    compiled_helper: Path,
) -> None:
    inputs = (
        _event_bytes(),
        _event_bytes(
            future={"nested": [True, None, 3.5, "snowman \N{SNOWMAN}"]},
        ),
        (
            b'{"hook_event_\\u006eame":"Session\\u0053tart",'
            b'"source":"start\\u0075p","cwd":"\\/runtime\\/critic-cwd"}'
        ),
    )
    marker = managed_policy.MANAGED_CLAUDE_BOUNDARY_MARKER.encode("ascii")
    for input_bytes in inputs:
        result = _run_helper(compiled_helper, input_bytes)
        assert not result.timed_out
        assert not result.output_limited
        assert result.returncode == 2
        assert result.stdout == b""
        assert result.stderr == marker


@pytest.mark.parametrize("scrub", [None, "", "0", "true"])
def test_helper_rejects_a_missing_or_nonexact_scrub_flag(
    compiled_helper: Path,
    scrub: str | None,
) -> None:
    environment = dict(_HELPER_ENVIRONMENT)
    if scrub is None:
        environment.pop("CLAUDE_CODE_SUBPROCESS_ENV_SCRUB")
    else:
        environment["CLAUDE_CODE_SUBPROCESS_ENV_SCRUB"] = scrub
    result = _run_helper(compiled_helper, _event_bytes(), environment=environment)
    assert result.returncode == 3
    assert result.stdout == b""
    assert result.stderr == b""


def test_helper_rejects_every_pinned_sensitive_name_and_input_variant_without_leakage(
    compiled_helper: Path,
) -> None:
    secret = "must-not-enter-helper-output"
    for base_name in _SENSITIVE_ENVIRONMENT_NAMES:
        for name in (base_name, f"INPUT_{base_name}"):
            environment = dict(_HELPER_ENVIRONMENT)
            environment[name] = secret
            result = _run_helper(
                compiled_helper,
                _event_bytes(),
                environment=environment,
            )
            assert result.returncode == 3, name
            assert result.stdout == b"", name
            assert result.stderr == b"", name
            assert secret.encode("ascii") not in result.stdout + result.stderr, name


@pytest.mark.parametrize(
    "input_bytes",
    [
        b"",
        b"{",
        b"[]",
        b'{"hook_event_name":"SessionStart"} trailing',
        b'{"hook_event_name":"SessionStart","hook_event_name":"SessionStart",'
        b'"source":"startup","cwd":"/runtime/critic-cwd"}',
        b'{"hook_event_name":"SessionStart","source":"startup",'
        b'"source":"startup","cwd":"/runtime/critic-cwd"}',
        b'{"hook_event_name":"SessionStart","source":"startup",'
        b'"cwd":"/runtime/critic-cwd","bad":"\xff"}',
        _event_bytes(hook_event_name="PreToolUse"),
        _event_bytes(source="resume"),
        _event_bytes(cwd="/tmp"),
        b" " * 65_537,
    ],
)
def test_helper_fails_silently_for_malformed_or_wrong_hook_input(
    compiled_helper: Path,
    input_bytes: bytes,
) -> None:
    result = _run_helper(compiled_helper, input_bytes)
    assert result.returncode == 3
    assert result.stdout == b""
    assert result.stderr == b""


def _simulate_admin_fixture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    compiled_helper: Path,
) -> tuple[Path, Path, Path]:
    fixture_root = tmp_path / "admin-root"
    policy_root = fixture_root / "etc" / "claude-code"
    policy_root.mkdir(parents=True)
    policy_root.chmod(0o755)
    policy_file = policy_root / managed_policy.MANAGED_CLAUDE_POLICY_FILE
    policy_file.write_bytes(_POLICY_TEMPLATE.read_bytes())
    policy_file.chmod(0o644)

    helper = fixture_root / "usr" / "local" / "libexec" / compiled_helper.name
    helper.parent.mkdir(parents=True)
    helper.write_bytes(compiled_helper.read_bytes())
    helper.chmod(0o555)

    monkeypatch.setattr(
        managed_policy,
        "MANAGED_CLAUDE_POLICY_SOURCE",
        os.fspath(policy_root),
    )
    monkeypatch.setattr(
        managed_policy,
        "MANAGED_CLAUDE_HELPER_SOURCE",
        os.fspath(helper),
    )
    monkeypatch.setattr(managed_policy, "_ADMIN_UID", os.geteuid())
    monkeypatch.setattr(managed_policy, "_ADMIN_GID", os.getegid())

    # The production inspector insists on an entirely administrator-owned,
    # non-special ancestry.  Unit fixtures necessarily pass through root-owned
    # /tmp and user-owned pytest directories, so this narrow witness seam makes
    # those ancestors look like ordinary administrator directories while
    # preserving the real type, link count, and exact mode of all three assets.
    asset_paths = {policy_root, policy_file, helper}
    real_lstat = os.lstat

    def simulated_admin_lstat(
        path: str | os.PathLike[str],
        *,
        dir_fd: int | None = None,
    ) -> os.stat_result:
        info = real_lstat(path, dir_fd=dir_fd)
        values = list(info)
        values[4] = os.geteuid()
        values[5] = os.getegid()
        selected = Path(os.path.abspath(os.fspath(path)))
        if selected not in asset_paths and stat.S_ISDIR(info.st_mode):
            values[0] = stat.S_IFDIR | 0o755
        return os.stat_result(values)

    monkeypatch.setattr(managed_policy.os, "lstat", simulated_admin_lstat)
    return policy_root, policy_file, helper


def test_inspector_accepts_and_witnesses_only_the_reviewed_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    compiled_helper: Path,
) -> None:
    policy_root, _policy_file, helper = _simulate_admin_fixture(
        monkeypatch,
        tmp_path,
        compiled_helper,
    )
    boundary = managed_policy.inspect_managed_claude_boundary()

    assert boundary.protocol == managed_policy.MANAGED_CLAUDE_BOUNDARY_PROTOCOL
    assert boundary.probe_id == managed_policy.MANAGED_CLAUDE_BOUNDARY_ID
    assert boundary.policy_mount.source == os.fspath(policy_root)
    assert boundary.policy_mount.target == managed_policy.MANAGED_CLAUDE_POLICY_TARGET
    assert boundary.policy_mount.read_only is True
    assert boundary.helper_mount.source == os.fspath(helper)
    assert boundary.helper_mount.target == managed_policy.MANAGED_CLAUDE_HELPER_TARGET
    assert boundary.helper_mount.read_only is True
    assert boundary.policy_sha256 == closure_sha256(
        policy_root,
        max_files=managed_policy.MAX_MANAGED_POLICY_FILES,
        max_bytes=managed_policy.MAX_MANAGED_POLICY_BYTES,
    )
    assert boundary.helper_sha256 == closure_sha256(
        helper,
        max_files=1,
        max_bytes=managed_policy.MAX_MANAGED_HELPER_BYTES,
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "policy-directory-mode",
        "policy-file-mode",
        "policy-hardlink",
        "policy-symlink",
        "policy-duplicate",
        "policy-semantic-drift",
        "policy-invalid-utf8",
        "policy-oversized",
        "unexpected-entry",
        "helper-mode",
        "helper-owner",
        "helper-hardlink",
        "helper-symlink",
        "helper-fifo",
        "helper-xattr",
        "helper-empty",
        "helper-oversized",
    ],
)
def test_inspector_rejects_unreviewed_shape_content_or_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    compiled_helper: Path,
    mutation: str,
) -> None:
    policy_root, policy_file, helper = _simulate_admin_fixture(
        monkeypatch,
        tmp_path,
        compiled_helper,
    )
    if mutation == "policy-directory-mode":
        policy_root.chmod(0o700)
    elif mutation == "policy-file-mode":
        policy_file.chmod(0o600)
    elif mutation == "policy-hardlink":
        original = policy_root / "policy-original"
        policy_file.rename(original)
        os.link(original, policy_file)
        original.unlink()
        # Retain a second name outside the exact policy directory so the
        # directory-entry check reaches the hard-link witness.
        outside = policy_root.parent / "policy-hardlink"
        os.link(policy_file, outside)
    elif mutation == "policy-symlink":
        original = policy_root.parent / "policy-original"
        original.write_bytes(policy_file.read_bytes())
        original.chmod(0o644)
        policy_file.unlink()
        policy_file.symlink_to(original)
    elif mutation == "policy-duplicate":
        policy_file.write_bytes(
            b'{"allowManagedHooksOnly":true,"allowManagedHooksOnly":true,'
            b'"disableAllHooks":false,"hooks":{}}'
        )
    elif mutation == "policy-semantic-drift":
        document = managed_policy.managed_claude_policy_document()
        document["disableAllHooks"] = True
        policy_file.write_text(json.dumps(document), encoding="utf-8")
    elif mutation == "policy-invalid-utf8":
        policy_file.write_bytes(b"{\xff}")
    elif mutation == "policy-oversized":
        policy_file.write_bytes(b" " * (managed_policy.MAX_MANAGED_POLICY_BYTES + 1))
    elif mutation == "unexpected-entry":
        (policy_root / "unreviewed.json").write_text("{}", encoding="utf-8")
    elif mutation == "helper-mode":
        helper.chmod(0o700)
    elif mutation == "helper-owner":
        simulated_admin_lstat = managed_policy.os.lstat

        def foreign_helper_lstat(
            path: str | os.PathLike[str],
            *,
            dir_fd: int | None = None,
        ) -> os.stat_result:
            info = simulated_admin_lstat(path, dir_fd=dir_fd)
            if Path(os.path.abspath(os.fspath(path))) != helper:
                return info
            values = list(info)
            values[4] = os.geteuid() + 1
            return os.stat_result(values)

        monkeypatch.setattr(managed_policy.os, "lstat", foreign_helper_lstat)
    elif mutation == "helper-hardlink":
        outside = helper.parent.parent / "helper-hardlink"
        os.link(helper, outside)
    elif mutation == "helper-symlink":
        original = helper.parent / "helper-original"
        helper.rename(original)
        helper.symlink_to(original)
    elif mutation == "helper-fifo":
        helper.unlink()
        os.mkfifo(helper, mode=0o555)
    elif mutation == "helper-xattr":
        real_listxattr = os.listxattr

        def synthetic_xattr(
            path: int | str | os.PathLike[str],
            *,
            follow_symlinks: bool = True,
        ) -> list[str]:
            if not isinstance(path, int) and Path(path) == helper:
                return ["user.unreviewed"]
            return real_listxattr(path, follow_symlinks=follow_symlinks)

        monkeypatch.setattr(managed_policy.os, "listxattr", synthetic_xattr)
    elif mutation == "helper-empty":
        helper.chmod(0o755)
        helper.write_bytes(b"")
        helper.chmod(0o555)
    elif mutation == "helper-oversized":
        helper.chmod(0o755)
        helper.write_bytes(b"x" * (managed_policy.MAX_MANAGED_HELPER_BYTES + 1))
        helper.chmod(0o555)
    else:
        raise AssertionError(f"unhandled mutation {mutation}")

    with pytest.raises(ValueError):
        managed_policy.inspect_managed_claude_boundary()
