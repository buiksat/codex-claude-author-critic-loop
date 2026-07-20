"""Session-wide gate for an exact target-host/live capability receipt."""

from __future__ import annotations

from collections.abc import Generator

import pytest

from agent_loop.errors import AgentLoopError
from tests.real_cli.live_support import (
    LiveGateReportLedger,
    reset_live_gate_session_state,
    write_live_gate_receipt_from_observed_environment,
)

_LEDGER = LiveGateReportLedger.create()


def pytest_sessionstart(session: pytest.Session) -> None:
    del session
    global _LEDGER
    _LEDGER = LiveGateReportLedger.create()
    reset_live_gate_session_state()


def pytest_collectreport(report: pytest.CollectReport) -> None:
    _LEDGER.record_collection_outcome(report.outcome)


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    _LEDGER.record(report)


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_sessionfinish(
    session: pytest.Session,
    exitstatus: int,
) -> Generator[None, None, None]:
    """Write only after every required host/live test and session hook stayed green."""

    yield
    final_status = int(session.exitstatus)
    if final_status != int(exitstatus) or not _LEDGER.eligible(final_status):
        return
    try:
        receipt_path = write_live_gate_receipt_from_observed_environment()
    except (AgentLoopError, OSError, TypeError, ValueError) as exc:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
        reporter = session.config.pluginmanager.get_plugin("terminalreporter")
        if reporter is not None:
            reporter.write_line(f"live capability receipt was not written: {exc}", red=True)
        return
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    if reporter is not None:
        reporter.write_line(f"live capability receipt written: {receipt_path}", green=True)
