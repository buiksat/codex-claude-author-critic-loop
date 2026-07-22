from __future__ import annotations

import ast
import errno
import json
import shlex
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from agent_loop import qualification
from agent_loop.cli import build_parser, main
from agent_loop.errors import AgentLoopError, StopReason
from agent_loop.manifests import SubjectManifest
from agent_loop.qualification_payloads import AUTHOR_PROBE
from agent_loop.runner import AuthorTurn


def test_qualify_cli_has_only_explicit_live_and_paid_gates() -> None:
    parsed = build_parser().parse_args(["qualify", "--live", "--accept-paid"])
    assert parsed.command == "qualify"
    assert parsed.live is True
    assert parsed.accept_paid is True
    for forbidden in (
        "codex_credential_id",
        "claude_credential_id",
        "codex_executable",
        "claude_executable",
        "author_model",
        "author_effort",
        "critic_model",
        "critic_effort",
    ):
        assert not hasattr(parsed, forbidden)


@pytest.mark.parametrize("argv", (["qualify"], ["qualify", "--live"]))
def test_qualify_refuses_before_loading_or_calling_live_runner(
    argv: list[str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    called = False

    def forbidden_call(*, state_home: Path | None = None) -> None:
        del state_home
        nonlocal called
        called = True

    monkeypatch.setattr(qualification, "qualify_live", forbidden_call)
    assert main(argv) == 17
    assert called is False
    output = capsys.readouterr()
    assert output.out == ""
    assert "requires --" in output.err
    if "--live" in argv:
        assert '"model": "gpt-5.4"' in output.err
        assert '"model_calls": 2' in output.err
        assert '"model": "claude-opus-4-6"' in output.err
        assert '"model_calls": "1, plus at most 1 structured-output correction"' in output.err


def test_qualify_prints_only_runner_supplied_secret_free_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class Result:
        def to_json_obj(self) -> dict[str, object]:
            return {
                "status": "qualified",
                "receipt": str(tmp_path / "live-v3.json"),
                "credential_profile": "default",
                "acceptance_gates": 18,
            }

    observed: list[Path | None] = []

    def succeed(*, state_home: Path | None = None) -> Result:
        observed.append(state_home)
        return Result()

    monkeypatch.setattr(qualification, "qualify_live", succeed)
    state = tmp_path / "state"
    assert (
        main(
            [
                "--state-home",
                str(state),
                "qualify",
                "--live",
                "--accept-paid",
            ]
        )
        == 0
    )
    assert observed == [state]
    output = capsys.readouterr()
    assert "Paid live-qualification scope" in output.err
    assert '"model": "gpt-5.4"' in output.err
    assert '"model": "claude-opus-4-6"' in output.err
    value = json.loads(output.out)
    assert value["credential_profile"] == "default"
    assert "token" not in output.out.lower()
    assert "auth.json" not in output.out
    assert ".credentials.json" not in output.out


def test_pinned_discovery_prefers_exact_claude_version_and_resolved_codex_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    exact_claude = home / ".local/share/claude/versions/2.1.215"
    moving_claude = tmp_path / "bin/claude-current"
    codex = tmp_path / "npm/codex.js"
    for path in (exact_claude, moving_claude, codex):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(b"#!/bin/sh\n")
        path.chmod(0o700)

    monkeypatch.setattr(
        "agent_loop.qualification.pwd.getpwuid",
        lambda _uid: SimpleNamespace(pw_dir=str(home)),
    )
    monkeypatch.setattr(
        "agent_loop.qualification.shutil.which",
        lambda name, *, path: str(codex if name == "codex" else moving_claude),
    )
    monkeypatch.setattr(qualification, "_version_matches", lambda _path, _expected: True)

    selected_codex, selected_claude = qualification.discover_pinned_cli_executables()
    assert selected_codex == codex
    assert selected_claude == exact_claude


def test_qualification_production_module_has_no_test_tree_dependency() -> None:
    source = Path(qualification.__file__).read_text(encoding="utf-8")
    assert "import pytest" not in source
    assert "from tests" not in source
    assert "tests/" not in source


def test_author_probe_maps_inherited_procfs_labels_to_inner_namespace_pids() -> None:
    parsed = ast.parse(AUTHOR_PROBE)
    function = next(
        node
        for node in parsed.body
        if isinstance(node, ast.FunctionDef) and node.name == "procfs_snapshot"
    )
    statuses = {
        "/proc/501/status": "Name:\tbwrap\nNSpid:\t501\t1\n",
        "/proc/502/status": "Name:\tpython3\nNSpid:\t502\t2\n",
    }
    namespace: dict[str, object] = {
        "os": SimpleNamespace(listdir=lambda _path: ["501", "502", "net", "self"]),
        "Path": lambda path: SimpleNamespace(
            read_text=lambda *, encoding: statuses[str(path)] if encoding == "ascii" else ""
        ),
    }
    exec(  # noqa: S102 - execute only the parsed, package-owned probe function under test.
        compile(ast.fix_missing_locations(ast.Module([function], [])), "<probe>", "exec"),
        namespace,
    )
    probe = cast(Callable[[], dict[int, tuple[str, str]] | None], namespace["procfs_snapshot"])

    snapshot = probe()
    assert snapshot is not None
    assert sorted(snapshot) == [1, 2]
    assert snapshot[1][0] == "501"
    assert snapshot[2][0] == "502"

    statuses["/proc/502/status"] = "Name:\tpython3\nNSpid:\t502\t1\n"
    assert probe() is None


def test_author_probe_maps_procfs_parent_labels_to_inner_namespace_pids() -> None:
    parsed = ast.parse(AUTHOR_PROBE)
    function = next(
        node
        for node in parsed.body
        if isinstance(node, ast.FunctionDef) and node.name == "parent_pid"
    )
    namespace: dict[str, object] = {
        "errno": errno,
        "procfs_processes": {
            1: ("501", "Name:\tbwrap\nPPid:\t499\nNSpid:\t501\t1\n"),
            2: ("502", "Name:\tpython3\nPPid:\t501\nNSpid:\t502\t2\n"),
        },
        "procfs_label_to_namespace_pid": {"501": 1, "502": 2},
    }
    exec(  # noqa: S102 - execute only the parsed, package-owned probe function under test.
        compile(ast.fix_missing_locations(ast.Module([function], [])), "<probe>", "exec"),
        namespace,
    )
    probe = cast(
        Callable[[int], tuple[int | None, dict[str, object] | None]], namespace["parent_pid"]
    )

    assert probe(1) == (0, None)
    assert probe(2) == (1, None)
    assert probe(3) == (None, {"pid": 3, "errno": errno.ENOENT})


def test_author_probe_uses_innermost_nspid_for_bwrap_init() -> None:
    parsed = ast.parse(AUTHOR_PROBE)
    function = next(
        node
        for node in parsed.body
        if isinstance(node, ast.FunctionDef) and node.name == "bwrap_init_probe"
    )
    namespace: dict[str, object] = {
        "os": SimpleNamespace(readlink=lambda _path: "pid:[100]"),
        "parent_pid": lambda _pid: (0, None),
        "procfs_status": lambda _pid: "Name:\tbwrap\nNSpid:\t501\t1\nNoNewPrivs:\t1\n",
        "procfs_label": lambda _pid: "501",
        "link_matches": lambda _path, _expected: {"matches": True, "errno": 0},
        "bwrap_environment_probe": lambda _pid: {},
        "bwrap_fd_probe": lambda _pid: {},
        "sensitive_process_probes": lambda _pid: {},
    }
    exec(  # noqa: S102 - execute only the parsed, package-owned probe function under test.
        compile(ast.fix_missing_locations(ast.Module([function], [])), "<probe>", "exec"),
        namespace,
    )
    probe = cast(Callable[[int, str], dict[str, object]], namespace["bwrap_init_probe"])

    assert probe(1, "bwrap")["namespace_pid"] == 1


def test_author_probe_accepts_permission_profile_socket_creation_denial() -> None:
    parsed = ast.parse(AUTHOR_PROBE)
    function = next(
        node
        for node in parsed.body
        if isinstance(node, ast.FunctionDef) and node.name == "network_probe"
    )
    namespace: dict[str, object] = {
        "socket": SimpleNamespace(
            AF_INET=2,
            SOCK_STREAM=1,
            SOCK_DGRAM=2,
            socket=lambda _family, _kind: (_ for _ in ()).throw(
                PermissionError(errno.EPERM, "network denied")
            ),
        )
    }
    exec(  # noqa: S102 - execute only the parsed, package-owned probe function under test.
        compile(ast.fix_missing_locations(ast.Module([function], [])), "<probe>", "exec"), namespace
    )
    probe = cast(Callable[[str, int, int], dict[str, object]], namespace["network_probe"])

    assert probe("1.1.1.1", 443, 1) == {"allowed": False, "errno": errno.EPERM}


def test_author_probe_declassifies_only_bwrap_environment_names_and_fd_classes() -> None:
    parsed = ast.parse(AUTHOR_PROBE)
    functions = {
        node.name: node
        for node in parsed.body
        if isinstance(node, ast.FunctionDef)
        and node.name in {"bwrap_environment_probe", "bwrap_fd_probe"}
    }
    raw_environment = b"\0".join(
        (
            b"CODEX_CI=1",
            b"CODEX_PERMISSION_PROFILE=agent_loop_author",
            b"CODEX_SANDBOX_NETWORK_DISABLED=1",
            b"CODEX_THREAD_ID=00000000-0000-0000-0000-000000000001",
            b"HOME=/runtime/home",
            b"LANG=C.UTF-8",
            b"PAGER=cat",
            b"PATH=/usr/local/bin:/usr/bin:/bin",
            b"PWD=/runtime/author-cwd",
            b"TMPDIR=/runtime/tmp",
            b"",
        )
    )
    environment_namespace: dict[str, object] = {
        "Path": lambda _path: SimpleNamespace(read_bytes=lambda: raw_environment),
        "errno": errno,
        "procfs_label": lambda _pid: "501",
    }
    exec(  # noqa: S102 - execute only the parsed, package-owned probe function under test.
        compile(
            ast.fix_missing_locations(ast.Module([functions["bwrap_environment_probe"]], [])),
            "<probe>",
            "exec",
        ),
        environment_namespace,
    )
    environment_probe = cast(
        Callable[[int], dict[str, object]], environment_namespace["bwrap_environment_probe"]
    )
    environment = environment_probe(1)
    assert environment["matches_allowlist"] is True
    assert environment["name_count"] == 10
    assert "/runtime" not in json.dumps(environment, sort_keys=True)

    raw_environment = raw_environment.replace(b"PAGER=cat", b"PAGER=credential-like-value")
    rejected_environment = environment_probe(1)
    assert rejected_environment["matches_allowlist"] is False
    assert "credential-like-value" not in json.dumps(rejected_environment, sort_keys=True)

    targets = {
        "0": "/dev/null",
        "1": "pipe:[100]",
        "2": "pipe:[101]",
        "5": "anon_inode:[eventfd]",
        "6": "/control/codex-home/auth.json",
    }
    fd_namespace: dict[str, object] = {
        "errno": errno,
        "procfs_label": lambda _pid: "501",
        "os": SimpleNamespace(
            listdir=lambda _path: list(targets),
            readlink=lambda path: targets[str(path).rsplit("/", 1)[-1]],
        ),
    }
    exec(  # noqa: S102 - execute only the parsed, package-owned probe function under test.
        compile(
            ast.fix_missing_locations(ast.Module([functions["bwrap_fd_probe"]], [])),
            "<probe>",
            "exec",
        ),
        fd_namespace,
    )
    fd_probe = cast(Callable[[int], dict[str, object]], fd_namespace["bwrap_fd_probe"])
    descriptors = fd_probe(1)
    assert descriptors["classes"] == {"dev_null": 1, "eventfd": 1, "pipe": 2}
    assert descriptors["count"] == 5
    assert descriptors["unexpected_count"] == 1
    assert "/control" not in json.dumps(descriptors, sort_keys=True)


def _valid_author_report() -> dict[str, object]:
    denied = {"allowed": False, "errno": errno.EPERM}
    return {
        "phase": "first",
        "workspace_write": {"allowed": True, "errno": 0},
        **{
            name: {"allowed": False, "errno": errno.EPERM}
            for name in (
                "root_write",
                "slash_tmp_write",
                "runtime_tmp_write",
                "artifacts_write",
                "control_read",
                "unix_socket",
            )
        },
        "network": {"tcp": {"allowed": False, "errno": errno.EPERM}},
        "protected_reads": {"AGENTS.md": {"allowed": False, "errno": errno.EPERM}},
        "sensitive_environment_keys": [],
        "git_guard": {
            "present": True,
            "directory": True,
            "symlink": False,
            "mode": 0o555,
            "entries": [],
            "list_errno": 0,
            "mounts": [
                {
                    "filesystem": "tmpfs",
                    "mount_options": ["ro", "nosuid", "nodev"],
                    "super_options": ["rw", "mode=555"],
                }
            ],
            "git_recognized": False,
            "git_returncode": 128,
            "head_read": {"allowed": False, "errno": errno.ENOENT},
            "write": {"allowed": False, "errno": errno.EROFS},
        },
        "self_pid": 2,
        "self_ppid": 1,
        "visible_pids": [1, 2],
        "model_shell_chain": [],
        "inner_sandbox_init": {
            "pid": 1,
            "ppid": 0,
            "parent_lookup_denied": None,
            "comm": "bwrap",
            "namespace_pid": 1,
            "no_new_privs": 1,
            "executable": {"matches": True, "errno": 0},
            "same_pid_namespace": {"matches": True, "errno": 0},
            "environment": {
                "readable": True,
                "errno": 0,
                "allowlisted_names": sorted(
                    [
                        "CODEX_CI",
                        "CODEX_PERMISSION_PROFILE",
                        "CODEX_SANDBOX_NETWORK_DISABLED",
                        "CODEX_THREAD_ID",
                        "COLORTERM",
                        "GH_PAGER",
                        "GIT_PAGER",
                        "HOME",
                        "LANG",
                        "LC_ALL",
                        "LC_CTYPE",
                        "NO_COLOR",
                        "PAGER",
                        "PATH",
                        "PWD",
                        "SHLVL",
                        "TERM",
                        "TMPDIR",
                        "_",
                    ]
                ),
                "required_names": sorted(
                    [
                        "CODEX_CI",
                        "CODEX_PERMISSION_PROFILE",
                        "CODEX_SANDBOX_NETWORK_DISABLED",
                        "CODEX_THREAD_ID",
                        "HOME",
                        "LANG",
                        "PATH",
                        "TMPDIR",
                    ]
                ),
                "matches_allowlist": True,
                "name_count": 19,
            },
            "fds": {
                "readable": True,
                "errno": 0,
                "count": 4,
                "classes": {"dev_null": 1, "eventfd": 1, "pipe": 2},
                "unexpected_count": 0,
            },
            "probes": {
                name: dict(denied) for name in ("mem", "ptrace", "process_vm_readv", "pidfd_getfd")
            },
        },
        "trusted_control_ancestry": [],
        "ancestry_enumeration_denied": None,
    }


def _assert_author_report_rejected(report: dict[str, object]) -> None:
    with pytest.raises(AgentLoopError) as caught:
        qualification._assert_author_report(report, "first")
    assert caught.value.reason is StopReason.SANDBOX_SETUP_FAILURE


def test_author_report_requires_inert_git_and_exact_inner_bwrap_boundary() -> None:
    report = _valid_author_report()
    qualification._assert_author_report(report, "first")

    guard = report["git_guard"]
    assert isinstance(guard, dict)
    guard["entries"] = ["HEAD"]
    _assert_author_report_rejected(report)


def test_author_report_accepts_only_a_contiguous_attested_model_shell_chain() -> None:
    report = _valid_author_report()
    report["self_pid"] = 4
    report["self_ppid"] = 3
    report["visible_pids"] = [1, 2, 3, 4]
    report["model_shell_chain"] = [
        {
            "pid": 3,
            "ppid": 2,
            "parent_lookup_denied": None,
            "comm": "bash",
            "no_new_privs": 1,
            "executable": {"matches": True, "errno": 0},
            "same_pid_namespace": {"matches": True, "errno": 0},
        },
        {
            "pid": 2,
            "ppid": 1,
            "parent_lookup_denied": None,
            "comm": "sh",
            "no_new_privs": 1,
            "executable": {"matches": True, "errno": 0},
            "same_pid_namespace": {"matches": True, "errno": 0},
        },
    ]
    qualification._assert_author_report(report, "first")

    shells = report["model_shell_chain"]
    assert isinstance(shells, list)
    first = shells[0]
    assert isinstance(first, dict)
    first["ppid"] = 1
    _assert_author_report_rejected(report)

    report = _valid_author_report()
    report["self_pid"] = 3
    report["self_ppid"] = 2
    report["visible_pids"] = [1, 2, 3]
    report["model_shell_chain"] = [
        {
            "pid": 2,
            "ppid": 1,
            "parent_lookup_denied": None,
            "comm": "bash",
            "no_new_privs": 1,
            "executable": {"matches": False, "errno": 0},
            "same_pid_namespace": {"matches": True, "errno": 0},
        }
    ]
    _assert_author_report_rejected(report)


def test_author_report_rejects_any_unattested_or_visible_control_state() -> None:
    report = _valid_author_report()
    report["visible_pids"] = [1, 2, 3]
    _assert_author_report_rejected(report)

    report = _valid_author_report()
    report["trusted_control_ancestry"] = [{"pid": 3, "comm": "codex", "probes": {}}]
    _assert_author_report_rejected(report)

    report = _valid_author_report()
    inner = report["inner_sandbox_init"]
    assert isinstance(inner, dict)
    environment = inner["environment"]
    assert isinstance(environment, dict)
    environment["matches_allowlist"] = False
    _assert_author_report_rejected(report)

    report = _valid_author_report()
    inner = report["inner_sandbox_init"]
    assert isinstance(inner, dict)
    descriptors = inner["fds"]
    assert isinstance(descriptors, dict)
    descriptors["unexpected_count"] = 1
    _assert_author_report_rejected(report)

    report = _valid_author_report()
    inner = report["inner_sandbox_init"]
    assert isinstance(inner, dict)
    probes = inner["probes"]
    assert isinstance(probes, dict)
    memory = probes["mem"]
    assert isinstance(memory, dict)
    memory["allowed"] = True
    memory["errno"] = 0
    _assert_author_report_rejected(report)


def test_qualification_accepts_only_pinned_public_shell_command_shape() -> None:
    command = "/usr/bin/python3 /workspace/capability_probe.py first"
    item: dict[str, object] = {
        "type": "item.completed",
        "item": {
            "type": "command_execution",
            "command": f"/bin/bash -c {shlex.quote(command)}",
            "status": "completed",
            "exit_code": 0,
        },
    }
    turn = AuthorTurn(SubjectManifest.empty(), "thread-safe", "done", (item,))

    qualification._assert_exact_author_command(turn, command)

    login_shell_item: dict[str, object] = {
        "type": "item.completed",
        "item": {
            "type": "command_execution",
            "command": f"/bin/bash -lc {shlex.quote(command)}",
            "status": "completed",
            "exit_code": 0,
        },
    }
    qualification._assert_exact_author_command(
        AuthorTurn(SubjectManifest.empty(), "thread-safe", "done", (login_shell_item,)),
        command,
    )

    sh_item: dict[str, object] = {
        "type": "item.completed",
        "item": {
            "type": "command_execution",
            "command": f"/bin/sh -c {shlex.quote(command)}",
            "status": "completed",
            "exit_code": 0,
        },
    }
    qualification._assert_exact_author_command(
        AuthorTurn(SubjectManifest.empty(), "thread-safe", "done", (sh_item,)),
        command,
    )

    qualification._assert_exact_author_command(
        AuthorTurn(
            SubjectManifest.empty(),
            "thread-safe",
            "done",
            (
                {
                    "type": "item.completed",
                    "item": {
                        "type": "command_execution",
                        "command": command,
                        "status": "completed",
                        "exit_code": 0,
                    },
                },
            ),
        ),
        command,
    )

    wrong_item: dict[str, object] = {
        "type": "item.completed",
        "item": {
            "type": "command_execution",
            "command": f"/bin/zsh -c {shlex.quote(command)}",
            "status": "completed",
            "exit_code": 0,
        },
    }
    wrong = AuthorTurn(
        SubjectManifest.empty(),
        "thread-safe",
        "done",
        (wrong_item,),
    )
    with pytest.raises(AgentLoopError) as caught:
        qualification._assert_exact_author_command(wrong, command)
    assert caught.value.reason is StopReason.SANDBOX_SETUP_FAILURE
