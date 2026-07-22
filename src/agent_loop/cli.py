"""Stable `agent-loop run/qualify/status/show` command-line interface."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from .artifacts import ArtifactStore
from .credentials import (
    DEFAULT_CLAUDE_CREDENTIAL_ID,
    DEFAULT_CODEX_CREDENTIAL_ID,
    active_claude_credentials_path,
    active_codex_auth_path,
    auto_enroll_default_cli_credentials,
    claude_cli_credentials_enrolled,
    codex_file_auth_enrolled,
    default_cli_credential_pair_state,
    enroll_claude_cli_credentials,
    enroll_codex_file_auth,
    repair_default_cli_credentials,
    xdg_state_home,
)
from .errors import AgentLoopError, ExitCode, StopReason, fail

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
        help=(
            "override the normal XDG state location (usually omit; intended for controlled "
            "automation)"
        ),
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
    run.add_argument(
        "--codex-credential-id",
        help="advanced custom profile override (default reuses the existing Codex CLI login)",
    )
    run.add_argument(
        "--claude-credential-id",
        help="advanced custom profile override (default reuses the existing Claude CLI login)",
    )
    run.add_argument("--codex-executable", type=Path)
    run.add_argument("--claude-executable", type=Path)
    run.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "resolve static inputs and pinned host boundaries without loading credentials, "
            "running validation, creating artifacts, or calling a model"
        ),
    )
    run.add_argument("--yes", action="store_true", help="confirm the printed paid-run preflight")

    auth = subparsers.add_parser(
        "auth",
        help="optional inspection/recovery for automatically reused CLI logins",
    )
    auth_subparsers = auth.add_subparsers(dest="auth_command", required=True)
    auth_init = auth_subparsers.add_parser(
        "init",
        help="advanced: import custom paths/profiles or repair private login copies",
    )
    auth_init.add_argument("--codex-credential-id", default=DEFAULT_CODEX_CREDENTIAL_ID)
    auth_init.add_argument("--claude-credential-id", default=DEFAULT_CLAUDE_CREDENTIAL_ID)
    auth_init.add_argument(
        "--codex-auth",
        type=Path,
        help=("Codex auth.json to import (default: the authorized user's ~/.codex/auth.json)"),
    )
    auth_init.add_argument(
        "--claude-credentials",
        type=Path,
        help=(
            "Claude .credentials.json to import "
            "(default: the authorized user's ~/.claude/.credentials.json)"
        ),
    )
    auth_init.add_argument(
        "--skip-codex",
        action="store_true",
        help="import only a non-default custom Claude credential ID",
    )
    auth_init.add_argument(
        "--skip-claude",
        action="store_true",
        help="import only a non-default custom Codex credential ID",
    )
    auth_init.add_argument(
        "--replace",
        "--repair",
        dest="replace",
        action="store_true",
        help=(
            "rotate both defaults or complete a valid partial pair; unsafe or incomplete "
            "account directories require manual review"
        ),
    )

    auth_status = auth_subparsers.add_parser(
        "status",
        help="inspect local credential copies without contacting either vendor",
    )
    auth_status.add_argument("--codex-credential-id", default=DEFAULT_CODEX_CREDENTIAL_ID)
    auth_status.add_argument("--claude-credential-id", default=DEFAULT_CLAUDE_CREDENTIAL_ID)

    reauthenticate = auth_subparsers.add_parser(
        "reauthenticate",
        help="show the one-time vendor login command to use after a real sign-out",
    )
    reauthenticate.add_argument("vendor", choices=("codex", "claude"))

    qualify = subparsers.add_parser(
        "qualify",
        help="run the pinned installed host and paid live gates, then mint a receipt",
    )
    qualify.add_argument(
        "--live",
        action="store_true",
        help="required acknowledgement that real installed CLIs and containment are exercised",
    )
    qualify.add_argument(
        "--accept-paid",
        action="store_true",
        help="authorize the printed Codex/Claude model-call cost scope (not a login step)",
    )

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
                "validation_critic": _optional_json(artifacts, f"{prefix}/validation.critic.json"),
                "critic": _optional_json(artifacts, f"{prefix}/critic.json"),
                "findings_ledger": _optional_json(artifacts, f"{prefix}/findings-ledger.json"),
            }
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2))
    return 0


def _auth_status(args: argparse.Namespace) -> int:
    # Import lazily to avoid making the workflow module part of status/show startup.
    from .workflow import parse_codex_file_auth

    value = {
        "codex": {
            "credential_id": args.codex_credential_id,
            "local_copy_present_and_parseable": codex_file_auth_enrolled(
                args.codex_credential_id,
                auth_parser=parse_codex_file_auth,
                state_home=args.state_home,
            ),
            "vendor_session_validity": "not_checked",
        },
        "claude": {
            "credential_id": args.claude_credential_id,
            "local_copy_present_and_parseable": claude_cli_credentials_enrolled(
                args.claude_credential_id,
                state_home=args.state_home,
            ),
            "vendor_session_validity": "not_checked",
        },
    }
    if (
        args.codex_credential_id == DEFAULT_CODEX_CREDENTIAL_ID
        and args.claude_credential_id == DEFAULT_CLAUDE_CREDENTIAL_ID
    ):
        pair_state = default_cli_credential_pair_state(
            codex_auth_parser=parse_codex_file_auth,
            state_home=args.state_home,
        )
        value["default_profile"] = {
            "state": pair_state,
            "locally_ready": pair_state == "ready",
            "repair_required": pair_state == "repair_required",
            "recovery_command": (
                "agent-loop auth init --repair"
                if pair_state == "repair_required"
                else "agent-loop auth status"
                if pair_state == "busy"
                else None
            ),
            "next_action": {
                "absent": (
                    "start the intended run; your standard Codex and Claude logins are reused "
                    "automatically"
                ),
                "ready": "no local authentication action is required; start the intended run",
                "busy": "wait for the active credential operation, then retry status",
                "recovery_pending": (
                    "start the intended run; locked crash recovery is automatic before spending"
                ),
                "repair_required": "review the credential state, then run the recovery command",
            }[pair_state],
        }
    print(json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2))
    return 0


def _auth_init(args: argparse.Namespace) -> int:
    from .workflow import parse_codex_file_auth

    if args.skip_codex and args.skip_claude:
        raise ValueError("auth init cannot skip both credential providers")
    codex_is_default = args.codex_credential_id == DEFAULT_CODEX_CREDENTIAL_ID
    claude_is_default = args.claude_credential_id == DEFAULT_CLAUDE_CREDENTIAL_ID
    if codex_is_default != claude_is_default:
        raise ValueError("the default Codex and Claude credentials must be selected as a pair")
    if args.skip_codex and args.claude_credential_id == DEFAULT_CLAUDE_CREDENTIAL_ID:
        raise ValueError("single-provider Claude import requires a non-default credential ID")
    if args.skip_claude and args.codex_credential_id == DEFAULT_CODEX_CREDENTIAL_ID:
        raise ValueError("single-provider Codex import requires a non-default credential ID")
    result: dict[str, object] = {}
    if (
        not args.skip_codex
        and not args.skip_claude
        and args.codex_credential_id == DEFAULT_CODEX_CREDENTIAL_ID
        and args.claude_credential_id == DEFAULT_CLAUDE_CREDENTIAL_ID
    ):
        if args.replace:
            enrollment = repair_default_cli_credentials(
                codex_auth_parser=parse_codex_file_auth,
                state_home=args.state_home,
                codex_source_path=args.codex_auth,
                claude_source_path=args.claude_credentials,
            )
        else:
            enrollment = auto_enroll_default_cli_credentials(
                codex_credential_id=args.codex_credential_id,
                claude_credential_id=args.claude_credential_id,
                codex_auth_parser=parse_codex_file_auth,
                state_home=args.state_home,
                codex_source_path=args.codex_auth,
                claude_source_path=args.claude_credentials,
            )
        for name, item in (("codex", enrollment.codex), ("claude", enrollment.claude)):
            result[name] = {
                "credential_id": (
                    args.codex_credential_id if name == "codex" else args.claude_credential_id
                ),
                "local_copy_present_and_parseable": True,
                "installed_now": item is not None and item.installed,
                "repaired_now": bool(args.replace),
            }
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2))
        return 0
    if not args.skip_codex:
        already = codex_file_auth_enrolled(
            args.codex_credential_id,
            auth_parser=parse_codex_file_auth,
            state_home=args.state_home,
        )
        if already and not args.replace:
            installed = False
        else:
            source = args.codex_auth or active_codex_auth_path()
            installed = enroll_codex_file_auth(
                args.codex_credential_id,
                source_auth_path=source,
                auth_parser=parse_codex_file_auth,
                state_home=args.state_home,
                replace=args.replace,
            ).installed
        result["codex"] = {
            "credential_id": args.codex_credential_id,
            "local_copy_present_and_parseable": True,
            "installed_now": installed,
        }
    if not args.skip_claude:
        already = claude_cli_credentials_enrolled(
            args.claude_credential_id,
            state_home=args.state_home,
        )
        if already and not args.replace:
            installed = False
        else:
            source = args.claude_credentials or active_claude_credentials_path()
            installed = enroll_claude_cli_credentials(
                args.claude_credential_id,
                source_credentials_path=source,
                state_home=args.state_home,
                replace=args.replace,
            ).installed
        result["claude"] = {
            "credential_id": args.claude_credential_id,
            "local_copy_present_and_parseable": True,
            "installed_now": installed,
        }
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2))
    return 0


def _auth_reauthenticate(args: argparse.Namespace) -> int:
    vendor_login = "codex login" if args.vendor == "codex" else "claude auth login"
    vendor_status = "codex login status" if args.vendor == "codex" else "claude auth status"
    print(
        json.dumps(
            {
                "vendor": args.vendor,
                "status_command": vendor_status,
                "login_command": vendor_login,
                "after_login": "rerun the original agent-loop command",
                "note": (
                    "Routine runs need no agent-loop auth command. Use the vendor login only if "
                    "its status command confirms you are signed out, then rerun the failed "
                    "agent-loop command. The newer standard login is adopted automatically under "
                    "the credential locks; no import or repair step is required."
                ),
            },
            ensure_ascii=True,
            sort_keys=True,
            indent=2,
        )
    )
    return 0


def _qualify(args: argparse.Namespace) -> int:
    if not args.live:
        raise fail(
            StopReason.SANDBOX_SETUP_FAILURE,
            "qualification requires --live; no probes or model calls were made",
        )
    from .constants import (
        DEFAULT_AUTHOR_EFFORT,
        DEFAULT_AUTHOR_MODEL,
        DEFAULT_CRITIC_EFFORT,
        DEFAULT_CRITIC_MODEL,
        SUPPORTED_CLAUDE_VERSION,
        SUPPORTED_CODEX_VERSION,
    )

    paid_scope = {
        "credential_profile": "default (existing CLI file logins; no token input)",
        "codex": {
            "cli_version": SUPPORTED_CODEX_VERSION,
            "model": DEFAULT_AUTHOR_MODEL,
            "effort": DEFAULT_AUTHOR_EFFORT,
            "model_calls": 2,
            "purpose": "one Git-less first turn and one exact-thread resume",
        },
        "claude": {
            "cli_version": SUPPORTED_CLAUDE_VERSION,
            "model": DEFAULT_CRITIC_MODEL,
            "effort": DEFAULT_CRITIC_EFFORT,
            "model_calls": "1, plus at most 1 structured-output correction",
            "purpose": "one fresh tool-disabled review",
        },
        "receipt_validity": "at most 7 days and invalidated by any bound host/CLI selection drift",
    }
    print(
        "Paid live-qualification scope (no credential values):\n"
        + json.dumps(paid_scope, ensure_ascii=True, sort_keys=True, indent=2),
        file=sys.stderr,
    )
    if not args.accept_paid:
        raise fail(
            StopReason.SANDBOX_SETUP_FAILURE,
            "qualification requires --accept-paid after reviewing the printed scope; "
            "no model calls were made",
        )
    # Import only after both explicit gates.  The installed module performs all
    # probes itself and never imports pytest or a repository-local tests tree.
    from .qualification import qualify_live

    result = qualify_live(state_home=args.state_home)
    print(json.dumps(result.to_json_obj(), ensure_ascii=True, sort_keys=True, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "auth":
            if args.auth_command == "status":
                return _auth_status(args)
            if args.auth_command == "reauthenticate":
                return _auth_reauthenticate(args)
            return _auth_init(args)
        if args.command == "qualify":
            return _qualify(args)
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
