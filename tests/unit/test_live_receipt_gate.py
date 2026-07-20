from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests import conftest as root_conftest
from agent_loop.constants import SUPPORTED_CODEX_VERSION
from tests.real_cli import live_support
from tests.real_cli.live_support import (
    LiveGateConfigurationError,
    LiveGateReportLedger,
    inspect_live_install,
)


@pytest.fixture
def isolated_observations() -> Iterator[None]:
    values = dict(live_support._OBSERVED_VALUES)
    installs = dict(live_support._OBSERVED_INSTALLS)
    live_support._OBSERVED_VALUES.clear()
    live_support._OBSERVED_INSTALLS.clear()
    try:
        yield
    finally:
        live_support._OBSERVED_VALUES.clear()
        live_support._OBSERVED_VALUES.update(values)
        live_support._OBSERVED_INSTALLS.clear()
        live_support._OBSERVED_INSTALLS.update(installs)


def _report(
    nodeid: str,
    phase: str,
    outcome: str = "passed",
    *,
    wasxfail: str | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        nodeid=nodeid,
        when=phase,
        outcome=outcome,
        wasxfail=wasxfail,
    )


def _record_complete_passes(ledger: LiveGateReportLedger) -> None:
    for nodeid in ledger.phases:
        for phase in ("setup", "call", "teardown"):
            ledger.record(_report(nodeid, phase))


def test_receipt_ledger_requires_both_exact_tests_and_every_pass_phase() -> None:
    ledger = LiveGateReportLedger.create()
    nodeids = tuple(ledger.phases)
    for nodeid in nodeids[1:]:
        for phase in ("setup", "call", "teardown"):
            ledger.record(_report(nodeid, phase))
    assert ledger.eligible(int(pytest.ExitCode.OK)) is False

    for phase in ("setup", "call", "teardown"):
        ledger.record(_report(nodeids[0], phase))
    assert ledger.eligible(int(pytest.ExitCode.OK)) is True
    assert ledger.eligible(int(pytest.ExitCode.TESTS_FAILED)) is False


@pytest.mark.parametrize(
    ("outcome", "wasxfail"),
    [("skipped", None), ("skipped", "expected"), ("passed", "unexpected pass")],
)
def test_receipt_ledger_rejects_any_skip_xfail_or_xpass(
    outcome: str,
    wasxfail: str | None,
) -> None:
    ledger = LiveGateReportLedger.create()
    _record_complete_passes(ledger)
    ledger.record(
        _report(
            "tests/unit/test_unrelated.py::test_outcome",
            "call",
            outcome,
            wasxfail=wasxfail,
        )
    )
    assert ledger.eligible(int(pytest.ExitCode.OK)) is False


def test_receipt_ledger_rejects_a_collection_time_skip() -> None:
    ledger = LiveGateReportLedger.create()
    _record_complete_passes(ledger)
    ledger.record_collection_outcome("skipped")
    assert ledger.eligible(int(pytest.ExitCode.OK)) is False


def test_each_pytest_session_resets_receipt_ledger_and_observed_selectors() -> None:
    _record_complete_passes(root_conftest._LEDGER)
    live_support._OBSERVED_VALUES["AGENT_LOOP_STATE_HOME"] = "/stale"
    assert root_conftest._LEDGER.eligible(int(pytest.ExitCode.OK)) is True

    root_conftest.pytest_sessionstart(SimpleNamespace())

    assert root_conftest._LEDGER.eligible(int(pytest.ExitCode.OK)) is False
    assert live_support._OBSERVED_VALUES == {}


def test_live_installs_use_the_same_production_mount_boundaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    isolated_observations: None,
) -> None:
    codex_root = tmp_path / "codex-package"
    codex_executable = codex_root / "bin" / "codex.js"
    codex_executable.parent.mkdir(parents=True)
    codex_executable.write_bytes(b"#!/usr/bin/env node\n")
    codex_executable.chmod(0o755)
    (codex_root / "package.json").write_text(
        '{"name":"@openai/codex","version":"'
        + SUPPORTED_CODEX_VERSION
        + '"}',
        encoding="utf-8",
    )

    claude_root = tmp_path / "claude-versions"
    claude_executable = claude_root / "2.1.215"
    claude_root.mkdir()
    claude_executable.write_bytes(b"\x7fELFpayload")
    claude_executable.chmod(0o755)

    selections = {
        "AGENT_LOOP_CODEX_INSTALL_ROOT": os.fspath(codex_root),
        "AGENT_LOOP_CODEX_INSTALL_RELATIVE": "bin/codex.js",
        "AGENT_LOOP_CLAUDE_INSTALL_ROOT": os.fspath(claude_root),
        "AGENT_LOOP_CLAUDE_INSTALL_RELATIVE": claude_executable.name,
    }
    for name, value in selections.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(live_support, "verify_safe_ancestors", lambda path: None)
    monkeypatch.setattr(
        live_support,
        "closure_sha256",
        lambda path: "a" * 64 if Path(path).is_dir() else "b" * 64,
    )

    codex = inspect_live_install("codex")
    claude = inspect_live_install("claude")

    assert codex.host_executable == codex_executable
    assert codex.mount == live_support.SandboxMount(
        os.fspath(codex_root),
        "/opt/agent-loop-tools/codex-package",
        read_only=True,
        closure_sha256="a" * 64,
    )
    assert codex.sandbox_executable == "/opt/agent-loop-tools/codex-package/bin/codex.js"
    assert codex.closure_sha256 == "a" * 64
    assert claude.host_executable == claude_executable
    assert claude.mount == live_support.SandboxMount(
        os.fspath(claude_executable),
        "/opt/agent-loop-tools/claude",
        read_only=True,
        closure_sha256="b" * 64,
    )
    assert claude.sandbox_executable == "/opt/agent-loop-tools/claude"
    assert claude.closure_sha256 == "b" * 64


def test_codex_live_root_must_be_the_exact_npm_package_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    isolated_observations: None,
) -> None:
    package_root = tmp_path / "codex-package"
    executable = package_root / "bin" / "codex.js"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"#!/usr/bin/env node\n")
    executable.chmod(0o755)
    monkeypatch.setenv("AGENT_LOOP_CODEX_INSTALL_ROOT", os.fspath(tmp_path))
    monkeypatch.setenv(
        "AGENT_LOOP_CODEX_INSTALL_RELATIVE",
        "codex-package/bin/codex.js",
    )
    monkeypatch.setattr(live_support, "verify_safe_ancestors", lambda path: None)

    with pytest.raises(LiveGateConfigurationError, match="exact reviewed npm package root"):
        inspect_live_install("codex")
