import json
import os
import socket
import stat
from pathlib import Path

import pytest

from agent_loop.locks import SourceRunLock


def test_source_run_lock_is_exclusive_and_private(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    source = tmp_path / "source"
    source.mkdir()
    first = SourceRunLock.acquire(source, "run-one", state_home=state)
    try:
        with pytest.raises(TimeoutError):
            SourceRunLock.acquire(source, "run-two", state_home=state, timeout_seconds=0.02)
        lock = next((state / "agent-loop" / "locks").iterdir())
        assert stat.S_IMODE(os.lstat(lock).st_mode) == 0o600
    finally:
        first.close()
    with SourceRunLock.acquire(source, "run-two", state_home=state):
        pass


def test_source_run_lock_records_required_holder_diagnostics(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    source = tmp_path / "source"
    source.mkdir()

    with SourceRunLock.acquire(source, "run-one", state_home=state):
        lock = next((state / "agent-loop" / "locks").iterdir())
        record = json.loads(lock.read_text(encoding="ascii"))

    assert set(record) == {
        "schema_version",
        "run_id",
        "pid",
        "hostname",
        "canonical_source",
        "source_sha256",
        "started_wall_time",
    }
    assert record["schema_version"] == 1
    assert record["run_id"] == "run-one"
    assert record["pid"] == os.getpid()
    assert record["hostname"] == socket.gethostname()
    assert record["canonical_source"] == os.fspath(source)
    assert record["source_sha256"] == lock.stem
    assert isinstance(record["started_wall_time"], float)


def test_different_sources_do_not_share_lock(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    first_source = tmp_path / "one"
    second_source = tmp_path / "two"
    first_source.mkdir()
    second_source.mkdir()
    with SourceRunLock.acquire(first_source, "one", state_home=state):
        with SourceRunLock.acquire(second_source, "two", state_home=state):
            pass
