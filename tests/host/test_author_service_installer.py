from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

_INSTALLER = Path("support/author-service/install.sh").resolve()
_UNINSTALLER = Path("support/author-service/uninstall.sh").resolve()
_WHEEL_NAME = "agent_loop-1.1.0-py3-none-any.whl"


def _write_executable(path: Path, source: str) -> None:
    path.write_text(source, encoding="utf-8")
    path.chmod(0o755)


def _sandbox(tmp_path: Path) -> tuple[list[str], Path, Path, Path]:
    if shutil.which("bwrap") is None:
        pytest.skip("Bubblewrap is required for the installer transaction test")

    opt = tmp_path / "opt"
    etc = tmp_path / "etc"
    run = tmp_path / "run"
    control = tmp_path / "control"
    installer = tmp_path / "installer"
    wheel_dir = tmp_path / "input"
    for directory in (opt, etc, run, control, installer, wheel_dir):
        directory.mkdir(mode=0o755)
    runtime_directory = run / "agent-loop"
    runtime_directory.mkdir(mode=0o755)
    (runtime_directory / "preserve-me").write_text("runtime-shared\n", encoding="utf-8")
    (etc / "systemd/system/sockets.target.wants").mkdir(parents=True, mode=0o755)
    for directory in (etc, etc / "systemd", etc / "systemd/system"):
        directory.chmod(0o755)
    shared_config = etc / "agent-loop"
    shared_config.mkdir(mode=0o755)
    (shared_config / "preserve-me").write_text("shared\n", encoding="utf-8")
    (etc / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/sh\noperator:x:1000:1000::/nonexistent:/bin/false\n",
        encoding="utf-8",
    )
    (etc / "group").write_text("root:x:0:\noperator:x:1000:\n", encoding="utf-8")

    installer_copy = installer / "install.sh"
    installer_copy.write_bytes(_INSTALLER.read_bytes())
    installer_copy.chmod(0o555)
    uninstaller_copy = installer / "uninstall.sh"
    uninstaller_copy.write_bytes(_UNINSTALLER.read_bytes())
    uninstaller_copy.chmod(0o555)
    wheel = wheel_dir / _WHEEL_NAME
    wheel.write_bytes(b"reviewed synthetic wheel\n")

    fake_python = control / "python3"
    _write_executable(
        fake_python,
        """#!/bin/sh
set -eu
if [ "$1" = -m ] && [ "$2" = venv ]; then
    runtime=$3
    mkdir -p "$runtime/bin" \
        "$runtime/lib/python3.14/site-packages/agent_loop" \
        "$runtime/share/agent-loop/support/author-service"
    cp /srv/python3 "$runtime/bin/python"
    chmod 0755 "$runtime/bin/python"
    printf '%s\n' '# synthetic package' > \
        "$runtime/lib/python3.14/site-packages/agent_loop/__init__.py"
    printf '%s\n' '[Socket]' > \
        "$runtime/share/agent-loop/support/author-service/agent-loop-author.socket"
    printf '%s\n' '[Service]' > \
        "$runtime/share/agent-loop/support/author-service/agent-loop-author@.service"
    exit 0
fi
if [ "$1" = -m ] && [ "$2" = pip ]; then
    exit 0
fi
if [ "$1" = -c ]; then
    printf '%s\n' '1.1.0'
    exit 0
fi
exit 64
""",
    )
    fake_id = control / "id"
    _write_executable(
        fake_id,
        """#!/bin/sh
set -eu
if [ "$#" -eq 1 ] && [ "$1" = -u ]; then
    printf '%s\n' 0
elif [ "$#" -eq 2 ] && [ "$1" = -u ] && [ "$2" = operator ]; then
    printf '%s\n' 1000
else
    exit 64
fi
""",
    )
    fake_stat = control / "stat"
    _write_executable(
        fake_stat,
        """#!/bin/sh
set -eu
if [ "$#" -eq 3 ] && [ "$1" = -c ] && [ "$2" = %u ] && [ "$3" = / ]; then
    printf '%s\n' 0
    exit 0
fi
exec /usr/bin/busybox stat "$@"
""",
    )
    fake_analyze = control / "systemd-analyze"
    _write_executable(
        fake_analyze,
        """#!/bin/sh
set -eu
printf '%s\n' "analyze $*" >> /srv/events
if [ -f /srv/fail-stage ] && \
    [ "$(cat /srv/fail-stage)" = verify ]; then
    rm -f /srv/fail-stage
    exit 70
fi
exit 0
""",
    )
    fake_systemctl = control / "systemctl"
    _write_executable(
        fake_systemctl,
        """#!/bin/sh
set -eu
command=$1
printf '%s\n' "systemctl $*" >> /srv/events
case "$command" in
    daemon-reload)
        ;;
    enable)
        ln -s /etc/systemd/system/agent-loop-author.socket \
            /etc/systemd/system/sockets.target.wants/agent-loop-author.socket
        ;;
    start)
        mkdir -p /run/agent-loop
        : > /run/agent-loop/author.sock
        ;;
    stop)
        if [ "$2" = agent-loop-author.socket ]; then
            rm -f /run/agent-loop/author.sock
        elif [ -f /srv/active-units ]; then
            : > /srv/active-units
        fi
        ;;
    disable)
        rm -f /etc/systemd/system/sockets.target.wants/agent-loop-author.socket
        ;;
    list-units)
        if [ -f /srv/active-units ]; then
            cat /srv/active-units
        fi
        ;;
    *)
        exit 64
        ;;
esac
if [ -f /srv/fail-stage ] && \
    [ "$(cat /srv/fail-stage)" = "$command" ]; then
    rm -f /srv/fail-stage
    exit 70
fi
exit 0
""",
    )

    command = [
        "/usr/bin/bwrap",
        "--die-with-parent",
        "--unshare-user",
        "--uid",
        "0",
        "--gid",
        "0",
        "--unshare-pid",
        "--unshare-net",
        "--ro-bind",
        "/",
        "/",
        "--bind",
        os.fspath(opt),
        "/opt",
        "--bind",
        os.fspath(etc),
        "/etc",
        "--bind",
        os.fspath(run),
        "/run",
        "--ro-bind",
        os.fspath(installer),
        "/mnt",
        "--ro-bind",
        os.fspath(wheel_dir),
        "/media",
        "--bind",
        os.fspath(control),
        "/srv",
        "--ro-bind",
        os.fspath(fake_python),
        "/usr/bin/python3",
        "--ro-bind",
        os.fspath(fake_id),
        "/usr/bin/id",
        "--ro-bind",
        os.fspath(fake_stat),
        "/usr/bin/stat",
        "--ro-bind",
        os.fspath(fake_analyze),
        "/usr/bin/systemd-analyze",
        "--ro-bind",
        os.fspath(fake_systemctl),
        "/usr/bin/systemctl",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "/mnt/install.sh",
        f"/media/{_WHEEL_NAME}",
        "operator",
        hashlib.sha256(wheel.read_bytes()).hexdigest(),
        "a" * 64,
    ]
    return command, opt, etc, run


def _run(command: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # noqa: S603 - fixed Bubblewrap transaction harness
        command,
        check=False,
        capture_output=True,
        timeout=20,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
    )


def _uninstall_command(command: list[str], expected_wheel_sha256: str) -> list[str]:
    command_index = command.index("/mnt/install.sh")
    return [*command[:command_index], "/mnt/uninstall.sh", expected_wheel_sha256]


def _restrictive_umask_command(command: list[str]) -> list[str]:
    command_index = command.index("/mnt/install.sh")
    return [
        *command[:command_index],
        "/bin/sh",
        "-c",
        'umask 077; exec "$@"',
        "agent-loop-installer",
        *command[command_index:],
    ]


def _assert_rolled_back(
    opt: Path,
    etc: Path,
    run: Path,
    *,
    preexisting_install_record: bool = False,
) -> None:
    assert not (opt / "agent-loop-author-service").exists()
    assert not tuple(opt.glob("agent-loop-author-service.install.*"))
    assert not (etc / "systemd/system/agent-loop-author.socket").exists()
    assert not (etc / "systemd/system/agent-loop-author@.service").exists()
    assert not (etc / "systemd/system/agent-loop-author.socket.d").exists()
    assert not (etc / "agent-loop/author-service.conf").exists()
    if not preexisting_install_record:
        assert not (etc / "agent-loop/author-service-install.txt").exists()
    assert not (etc / "agent-loop/author-service-uninstall.txt").exists()
    assert not (etc / "systemd/system/sockets.target.wants/agent-loop-author.socket").exists()
    assert not (run / "agent-loop/author.sock").exists()
    assert (run / "agent-loop/preserve-me").read_text(encoding="utf-8") == ("runtime-shared\n")
    assert (etc / "agent-loop/preserve-me").read_text(encoding="utf-8") == "shared\n"


@pytest.mark.host
def test_bootstrap_normalizes_inspected_assets_under_restrictive_umask(
    tmp_path: Path,
) -> None:
    command, opt, _etc, _run_root = _sandbox(tmp_path)

    installed = _run(_restrictive_umask_command(command))

    assert installed.returncode == 0, installed.stderr.decode("utf-8", "replace")
    assets = opt / "agent-loop-author-service/runtime/share/agent-loop/support/author-service"
    assert (assets / "agent-loop-author.socket").stat().st_mode & 0o777 == 0o644
    assert (assets / "agent-loop-author@.service").stat().st_mode & 0o777 == 0o644


@pytest.mark.host
@pytest.mark.parametrize("failure_stage", ["verify", "enable", "start"])
def test_bootstrap_failure_is_atomic_and_retryable(
    tmp_path: Path,
    failure_stage: str,
) -> None:
    command, opt, etc, run = _sandbox(tmp_path)
    (tmp_path / "control/fail-stage").write_text(failure_stage, encoding="ascii")

    failed = _run(command)
    assert failed.returncode != 0, failed.stderr.decode("utf-8", "replace")
    _assert_rolled_back(opt, etc, run)
    events = (tmp_path / "control/events").read_text(encoding="utf-8")
    assert "systemctl stop agent-loop-author.socket" in events
    assert "systemctl disable agent-loop-author.socket" in events
    assert events.count("systemctl daemon-reload") >= 1

    retried = _run(command)
    assert retried.returncode == 0, retried.stderr.decode("utf-8", "replace")
    assert (opt / "agent-loop-author-service").is_dir()
    assert (etc / "systemd/system/agent-loop-author.socket").is_file()
    assert (etc / "systemd/system/agent-loop-author@.service").is_file()
    assert (etc / "agent-loop/author-service.conf").is_file()
    assert (etc / "agent-loop/author-service-install.txt").is_file()
    assert (etc / "systemd/system/sockets.target.wants/agent-loop-author.socket").is_symlink()
    assert (run / "agent-loop/author.sock").is_file()


@pytest.mark.host
def test_exact_uninstall_preserves_shared_directories_and_allows_reinstall(
    tmp_path: Path,
) -> None:
    command, opt, etc, run = _sandbox(tmp_path)
    installed = _run(command)
    assert installed.returncode == 0, installed.stderr.decode("utf-8", "replace")
    wheel_sha256 = hashlib.sha256(b"reviewed synthetic wheel\n").hexdigest()
    (tmp_path / "control/active-units").write_text(
        "agent-loop-author@12-0.service loaded active running broker\n"
        "agent-loop-author-1000-0123456789abcdef0123456789abcdef.service "
        "loaded active running author\n",
        encoding="ascii",
    )

    removed = _run(_uninstall_command(command, wheel_sha256))
    assert removed.returncode == 0, removed.stderr.decode("utf-8", "replace")
    _assert_rolled_back(opt, etc, run)
    assert not (etc / "agent-loop/author-service-uninstall.txt").exists()
    events = (tmp_path / "control/events").read_text(encoding="utf-8")
    assert "systemctl stop agent-loop-author@12-0.service" in events
    assert (
        "systemctl stop agent-loop-author-1000-0123456789abcdef0123456789abcdef.service" in events
    )

    reinstalled = _run(command)
    assert reinstalled.returncode == 0, reinstalled.stderr.decode("utf-8", "replace")
    assert (opt / "agent-loop-author-service").is_dir()
    assert (etc / "systemd/system/agent-loop-author.socket").is_file()


@pytest.mark.host
def test_uninstall_refuses_drift_before_stopping_service(tmp_path: Path) -> None:
    command, opt, etc, _run_root = _sandbox(tmp_path)
    installed = _run(command)
    assert installed.returncode == 0, installed.stderr.decode("utf-8", "replace")
    wheel_sha256 = hashlib.sha256(b"reviewed synthetic wheel\n").hexdigest()
    service_unit = etc / "systemd/system/agent-loop-author@.service"
    service_unit.write_text("[Service]\nExecStart=/unexpected\n", encoding="utf-8")
    events_before = (tmp_path / "control/events").read_bytes()

    refused = _run(_uninstall_command(command, wheel_sha256))
    assert refused.returncode != 0
    assert b"differs from its reviewed asset" in refused.stderr
    assert (opt / "agent-loop-author-service").is_dir()
    assert service_unit.is_file()
    assert (tmp_path / "control/events").read_bytes() == events_before
    assert not (etc / "agent-loop/author-service-uninstall.txt").exists()


@pytest.mark.host
def test_interrupted_uninstall_is_resumable_without_broad_deletion(tmp_path: Path) -> None:
    command, opt, etc, run = _sandbox(tmp_path)
    installed = _run(command)
    assert installed.returncode == 0, installed.stderr.decode("utf-8", "replace")
    wheel_sha256 = hashlib.sha256(b"reviewed synthetic wheel\n").hexdigest()
    (tmp_path / "control/fail-stage").write_text("stop", encoding="ascii")

    interrupted = _run(_uninstall_command(command, wheel_sha256))
    assert interrupted.returncode != 0
    marker = etc / "agent-loop/author-service-uninstall.txt"
    assert marker.is_file()
    assert marker.stat().st_mode & 0o777 == 0o600
    assert (opt / "agent-loop-author-service").is_dir()
    assert (etc / "agent-loop/preserve-me").read_text(encoding="utf-8") == "shared\n"

    resumed = _run(_uninstall_command(command, wheel_sha256))
    assert resumed.returncode == 0, resumed.stderr.decode("utf-8", "replace")
    _assert_rolled_back(opt, etc, run)
    assert not marker.exists()


@pytest.mark.host
@pytest.mark.parametrize(
    ("root_name", "relative_target", "is_directory"),
    [
        ("opt", "agent-loop-author-service", True),
        ("etc", "systemd/system/agent-loop-author.socket", False),
        ("etc", "systemd/system/agent-loop-author@.service", False),
        ("etc", "agent-loop/author-service.conf", False),
        ("etc", "agent-loop/author-service-install.txt", False),
        ("etc", "agent-loop/author-service-uninstall.txt", False),
        ("etc", "systemd/system/agent-loop-author.socket.d", True),
        (
            "etc",
            "systemd/system/sockets.target.wants/agent-loop-author.socket",
            False,
        ),
        ("run", "agent-loop/author.sock", False),
    ],
)
def test_bootstrap_preflights_every_owned_target_without_touching_it(
    tmp_path: Path,
    root_name: str,
    relative_target: str,
    is_directory: bool,
) -> None:
    command, opt, etc, run = _sandbox(tmp_path)
    roots = {"opt": opt, "etc": etc, "run": run}
    target = roots[root_name] / relative_target
    if is_directory:
        target.mkdir(mode=0o755)
        sentinel = target / "do-not-overwrite"
    else:
        sentinel = target
    sentinel.write_text("do not overwrite\n", encoding="utf-8")

    result = _run(command)
    assert result.returncode != 0
    assert b"refusing to overwrite" in result.stderr
    assert sentinel.read_text(encoding="utf-8") == "do not overwrite\n"
    assert not tuple(opt.glob("agent-loop-author-service.install.*"))
    assert not (tmp_path / "control/events").exists()
