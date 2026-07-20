"""Stable `agent-loop run/status/show` command-line interface."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from .artifacts import ArtifactStore
from .credentials import xdg_state_home
from .errors import AgentLoopError, ExitCode

_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_DURATION = re.compile(r"^([1-9][0-9]*)(s|m|h)$")


def _duration(value: str) -> int:
    match = _DURATION.fullmatch(value)
    if match is None:
        raise argparse.ArgumentTypeError(
            "duration must be a positive integer followed by s, m, or h"
        )
    amount = int(match.group(1))
    scale = {"s": 1, "m": 60, "h": 3600}[match.group(2)]
    seconds = amount * scale
    if seconds > 7 * 24 * 3600:
        raise argparse.ArgumentTypeError("duration exceeds the seven-day parser ceiling")
    return seconds


def _positive_int(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be a positive integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be a positive integer")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-loop",
        description="Bounded containment-first Codex author / Claude critic loop",
    )
    parser.add_argument(
        "--state-home",
        type=Path,
        help="explicit absolute XDG state root (primarily for controlled automation)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run = subparsers.add_parser("run", help="start one new non-resumable bounded run")
    run.add_argument("--task", required=True, type=Path, help="operator-authored task Markdown")
    run.add_argument("--config", type=Path, default=Path(".agent-loop.toml"))
    run.add_argument("--check", action="append", default=[], help="fixed validation command")
    run.add_argument("--max-rounds", type=_positive_int)
    run.add_argument("--max-runtime", type=_duration)
    run.add_argument("--author-timeout", type=_duration)
    run.add_argument("--critic-timeout", type=_duration)
    run.add_argument("--validation-timeout", type=_duration)
    run.add_argument("--protected-validation-path", action="append", default=[])
    run.add_argument("--discard-only-path", action="append", default=[])
    run.add_argument("--opaque-nonsemantic-path", action="append", default=[])
    run.add_argument("--review-context-path", action="append", default=[])
    run.add_argument("--read-only-toolchain-mount", action="append", default=[])
    run.add_argument("--author-model")
    run.add_argument("--author-effort")
    run.add_argument("--critic-model")
    run.add_argument("--critic-effort")
    run.add_argument("--codex-credential-id")
    run.add_argument("--claude-credential-id")
    run.add_argument("--codex-executable", type=Path)
    run.add_argument("--claude-executable", type=Path)
    run.add_argument("--yes", action="store_true", help="confirm the printed paid-run preflight")

    status = subparsers.add_parser("status", help="show the durable state of a retained run")
    status.add_argument("run_id")

    show = subparsers.add_parser("show", help="show retained bounded evidence for a run")
    show.add_argument("run_id")
    show.add_argument("--round", type=_positive_int)
    return parser


def _run_root(run_id: str, state_home: Path | None) -> Path:
    if _RUN_ID.fullmatch(run_id) is None or run_id in {".", ".."}:
        raise ValueError("run ID is not a safe identifier")
    base = xdg_state_home(state_home=state_home)
    return base / "agent-loop" / "runs" / run_id


def _status(args: argparse.Namespace) -> int:
    with ArtifactStore.open(_run_root(args.run_id, args.state_home)) as artifacts:
        value = artifacts.read_json("artifacts/run.json", max_bytes=1024 * 1024)
    if not isinstance(value, dict):
        raise ValueError("run manifest is not an object")
    selected = {
        key: value.get(key)
        for key in (
            "run_id",
            "status",
            "source_revision",
            "current_round",
            "max_rounds",
            "current_subject_fingerprint",
            "stop_reason",
            "exit_code",
        )
    }
    print(json.dumps(selected, ensure_ascii=True, sort_keys=True, indent=2))
    return 0


def _optional_json(artifacts: ArtifactStore, path: str) -> object | None:
    try:
        return artifacts.read_json(path, max_bytes=16 * 1024 * 1024)
    except AgentLoopError as exc:
        cause = exc.__cause__
        if isinstance(cause, OSError) and cause.errno == 2:
            return None
        raise


def _show(args: argparse.Namespace) -> int:
    with ArtifactStore.open(_run_root(args.run_id, args.state_home)) as artifacts:
        run = artifacts.read_json("artifacts/run.json", max_bytes=1024 * 1024)
        if not isinstance(run, dict):
            raise ValueError("run manifest is not an object")
        round_number = args.round if args.round is not None else run.get("current_round")
        result: dict[str, object] = {"run": run, "round": None}
        if (
            isinstance(round_number, int)
            and not isinstance(round_number, bool)
            and round_number > 0
        ):
            prefix = f"artifacts/rounds/{round_number:03d}"
            result["round"] = {
                "number": round_number,
                "paths": _optional_json(artifacts, f"{prefix}/paths.json"),
                "validation": _optional_json(artifacts, f"{prefix}/validation.summary.json"),
                "validation_critic": _optional_json(
                    artifacts, f"{prefix}/validation.critic.json"
                ),
                "critic": _optional_json(artifacts, f"{prefix}/critic.json"),
                "findings_ledger": _optional_json(
                    artifacts, f"{prefix}/findings-ledger.json"
                ),
            }
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "status":
            return _status(args)
        if args.command == "show":
            return _show(args)
        from .workflow import execute_run

        return int(execute_run(args))
    except AgentLoopError as exc:
        print(f"agent-loop: {exc.reason.value}: {exc.detail}", file=sys.stderr)
        return int(exc.exit_code)
    except KeyboardInterrupt:
        print("agent-loop: interrupted", file=sys.stderr)
        return int(ExitCode.INTERRUPTED)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"agent-loop: internal error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return int(ExitCode.INTERNAL_ERROR)


if __name__ == "__main__":
    raise SystemExit(main())
