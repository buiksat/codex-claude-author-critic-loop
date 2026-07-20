import argparse
from pathlib import Path

import pytest

from agent_loop.artifacts import ArtifactStore
from agent_loop.cli import _duration, build_parser, main


def test_cli_exposes_only_run_status_show() -> None:
    parser = build_parser()
    help_text = parser.format_help()
    assert "run" in help_text and "status" in help_text and "show" in help_text
    assert "resume" not in help_text


def test_duration_parser_is_bounded() -> None:
    assert _duration("45m") == 2700
    assert _duration("2h") == 7200
    with pytest.raises(argparse.ArgumentTypeError):
        _duration("0s")


def test_status_and_show_read_private_artifacts(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = tmp_path / "state"
    root = state / "agent-loop" / "runs" / "run-1"
    with ArtifactStore.create(root) as artifacts:
        artifacts.write_json(
            "artifacts/run.json",
            {
                "run_id": "run-1",
                "status": "stopped",
                "source_revision": "a" * 40,
                "current_round": 0,
                "max_rounds": 3,
                "current_subject_fingerprint": "b" * 64,
                "stop_reason": "round_cap_reached",
                "exit_code": 10,
            },
        )
    assert main(["--state-home", str(state), "status", "run-1"]) == 0
    assert '"exit_code": 10' in capsys.readouterr().out
    assert main(["--state-home", str(state), "show", "run-1"]) == 0
    assert '"run_id": "run-1"' in capsys.readouterr().out


def test_invalid_run_id_fails_without_path_traversal(tmp_path: Path) -> None:
    assert main(["--state-home", str(tmp_path), "status", "../escape"]) == 18
