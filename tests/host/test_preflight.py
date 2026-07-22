import pytest
from tests.real_cli.live_support import selected_host_preflight_executables

from agent_loop.preflight import _run_small_in_service, run_preflight
from agent_loop.service import TransientServiceRunner


@pytest.mark.host
def test_fast_version_process_cannot_race_transient_unit_inspection() -> None:
    runner = TransientServiceRunner()
    for _ in range(3):
        assert _run_small_in_service(("/usr/bin/true",), runner) == b""


@pytest.mark.host
def test_pinned_environment_preflight_without_model_calls() -> None:
    codex_path, claude_path = selected_host_preflight_executables()
    report = run_preflight(
        codex_path=str(codex_path),
        claude_path=str(claude_path),
    )
    assert report.openat2
    assert report.namespace_probe
    assert report.transient_service_probe
    assert report.author_service.broker_probe
    assert report.codex.version == "codex-cli 0.144.6"
    assert report.claude.version == "2.1.215 (Claude Code)"
    assert report.codex.requested_path == str(codex_path)
    assert report.claude.requested_path == str(claude_path)
