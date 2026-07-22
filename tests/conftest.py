"""Session-wide diagnostic ledger for opt-in target-host/live tests.

Repository pytest sessions deliberately cannot mint production capability
receipts. Only the installed ``agent-loop qualify`` command owns that contract.
"""

from __future__ import annotations

from typing import cast

import pytest
from tests.real_cli.live_support import (
    LiveGateReportLedger,
    ReportLike,
    reset_live_gate_session_state,
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
    _LEDGER.record(cast(ReportLike, report))
