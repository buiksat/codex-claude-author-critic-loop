from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

from agent_loop.codex_auth_status import probe_codex_file_auth_status
from agent_loop.sandbox import SandboxMount, SandboxRole


class RecordingExecutor:
    def __init__(
        self,
        *,
        replace_auth: bytes | None = None,
        dirty_underlying_tmp: bool = False,
        populate_all_caches: bool = False,
        namespace_empty: bool = True,
        cgroup_empty: bool = True,
    ) -> None:
        self.replace_auth = replace_auth
        self.dirty_underlying_tmp = dirty_underlying_tmp
        self.populate_all_caches = populate_all_caches
        self.namespace_empty = namespace_empty
        self.cgroup_empty = cgroup_empty
        self.calls: list[dict[str, object]] = []

    def execute(self, **kwargs: object) -> SimpleNamespace:
        self.calls.append(dict(kwargs))
        mounts = kwargs["mounts"]
        assert isinstance(mounts, tuple)
        home_mount = next(mount for mount in mounts if mount.target == "/control/codex-home")
        scratch_mount = next(mount for mount in mounts if mount.target == "/control/codex-home/tmp")
        home = Path(home_mount.source)
        scratch = Path(scratch_mount.source)
        (scratch / "arg0").mkdir()
        if self.populate_all_caches:
            for mount in mounts:
                if mount.target.startswith("/control/codex-home/"):
                    (Path(mount.source) / "generated").write_bytes(b"cache")
        if self.replace_auth is not None:
            replacement = home / ".auth-replacement"
            replacement.write_bytes(self.replace_auth)
            replacement.chmod(0o600)
            os.replace(replacement, home / "auth.json")
        if self.dirty_underlying_tmp:
            (home / "tmp" / "unexpected").write_bytes(b"must-not-be-erased")
        process = SimpleNamespace(returncode=0, timed_out=False, output_limited=False)
        cleanup = SimpleNamespace(namespace_empty=self.namespace_empty)
        return SimpleNamespace(
            result=SimpleNamespace(process=process, cleanup=cleanup),
            service=SimpleNamespace(cgroup_empty=self.cgroup_empty),
        )


def _home(tmp_path: Path) -> Path:
    home = tmp_path / "codex-home"
    home.mkdir(mode=0o700)
    home.chmod(0o700)
    (home / "auth.json").write_bytes(b"old-auth")
    (home / "auth.json").chmod(0o600)
    (home / "sessions").mkdir(mode=0o700)
    return home


def _install(tmp_path: Path) -> SandboxMount:
    install = tmp_path / "codex-install"
    install.mkdir(mode=0o700)
    return SandboxMount(
        os.fspath(install),
        "/opt/agent-loop-tools/codex-package",
        read_only=True,
        closure_sha256="a" * 64,
    )


def test_status_probe_shadows_runtime_scratch_and_preserves_atomic_refresh(
    tmp_path: Path,
) -> None:
    home = _home(tmp_path)
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside-must-survive")
    runtime = home / "tmp"
    runtime.mkdir(mode=0o700)
    arg0 = runtime / "arg0" / "codex-arg0ABC123"
    arg0.mkdir(mode=0o775, parents=True)
    (arg0 / "apply_patch").symlink_to(outside)
    for cache_name in (".tmp", "plugins", "skills"):
        cache = home / cache_name
        cache.mkdir(mode=0o700)
        (cache / "generated").write_bytes(b"cache")
    (home / "installation_id").write_bytes(b"installation")
    (home / "installation_id").chmod(0o644)
    for state_name in (
        "goals_1.sqlite",
        "logs_2.sqlite",
        "logs_2.sqlite-shm",
        "logs_2.sqlite-wal",
        "memories_1.sqlite",
        "models_cache.json",
        "state_5.sqlite",
    ):
        (home / state_name).write_bytes(b"state")
        (home / state_name).chmod(0o600)
    executor = RecordingExecutor(replace_auth=b"refreshed-auth", populate_all_caches=True)

    assert probe_codex_file_auth_status(
        executor,  # type: ignore[arg-type]
        install_mount=_install(tmp_path),
        executable="/opt/agent-loop-tools/codex-package/bin/codex.js",
        codex_home=home,
        scratch_parent=tmp_path,
    )

    assert outside.read_bytes() == b"outside-must-survive"
    assert (home / "auth.json").read_bytes() == b"refreshed-auth"
    assert {path.name for path in home.iterdir()} == {
        "auth.json",
        "goals_1.sqlite",
        "installation_id",
        "logs_2.sqlite",
        "logs_2.sqlite-shm",
        "logs_2.sqlite-wal",
        "memories_1.sqlite",
        "models_cache.json",
        "sessions",
        "state_5.sqlite",
    }
    assert len(executor.calls) == 1
    call = executor.calls[0]
    assert call["role"] is SandboxRole.CRITIC
    assert call["cwd"] == "/runtime/critic-cwd"
    assert call["environment"] == {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": "/runtime/home",
        "TMPDIR": "/runtime/tmp",
        "LANG": "C.UTF-8",
        "CODEX_HOME": "/control/codex-home",
    }


def test_status_probe_rejects_symlink_runtime_mountpoint_without_following_it(
    tmp_path: Path,
) -> None:
    home = _home(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "sentinel").write_bytes(b"safe")
    (home / "tmp").symlink_to(outside, target_is_directory=True)
    executor = RecordingExecutor()

    assert not probe_codex_file_auth_status(
        executor,  # type: ignore[arg-type]
        install_mount=_install(tmp_path),
        executable="/opt/agent-loop-tools/codex-package/bin/codex.js",
        codex_home=home,
        scratch_parent=tmp_path,
    )

    assert not executor.calls
    assert (outside / "sentinel").read_bytes() == b"safe"
    assert (home / "tmp").is_symlink()


def test_status_probe_fails_closed_if_nested_mount_does_not_shadow_host_tmp(
    tmp_path: Path,
) -> None:
    home = _home(tmp_path)
    executor = RecordingExecutor(dirty_underlying_tmp=True)

    assert not probe_codex_file_auth_status(
        executor,  # type: ignore[arg-type]
        install_mount=_install(tmp_path),
        executable="/opt/agent-loop-tools/codex-package/bin/codex.js",
        codex_home=home,
        scratch_parent=tmp_path,
    )

    assert (home / "tmp" / "unexpected").read_bytes() == b"must-not-be-erased"


def test_status_probe_requires_namespace_and_cgroup_cleanup(tmp_path: Path) -> None:
    home = _home(tmp_path)
    executor = RecordingExecutor(namespace_empty=False, cgroup_empty=False)

    assert not probe_codex_file_auth_status(
        executor,  # type: ignore[arg-type]
        install_mount=_install(tmp_path),
        executable="/opt/agent-loop-tools/codex-package/bin/codex.js",
        codex_home=home,
        scratch_parent=tmp_path,
    )

    assert not (home / "tmp").exists()


def test_status_probe_rejects_unknown_or_unsafe_generated_root_state(tmp_path: Path) -> None:
    home = _home(tmp_path)
    (home / "unknown-state").write_bytes(b"unknown")
    executor = RecordingExecutor()

    assert not probe_codex_file_auth_status(
        executor,  # type: ignore[arg-type]
        install_mount=_install(tmp_path),
        executable="/opt/agent-loop-tools/codex-package/bin/codex.js",
        codex_home=home,
        scratch_parent=tmp_path,
    )
    assert not executor.calls


def test_status_probe_rejects_group_writable_cache_before_deleting_any(tmp_path: Path) -> None:
    home = _home(tmp_path)
    first = home / ".tmp"
    first.mkdir(mode=0o700)
    (first / "preserved").write_bytes(b"cache")
    unsafe = home / "plugins"
    unsafe.mkdir(mode=0o770)
    unsafe.chmod(0o770)
    executor = RecordingExecutor()

    assert not probe_codex_file_auth_status(
        executor,  # type: ignore[arg-type]
        install_mount=_install(tmp_path),
        executable="/opt/agent-loop-tools/codex-package/bin/codex.js",
        codex_home=home,
        scratch_parent=tmp_path,
    )
    assert (first / "preserved").read_bytes() == b"cache"
    assert not executor.calls
