"""Hardened, read-only extraction of the committed Git ``HEAD`` tree.

The source checkout is never an authoritative input.  This module asks Git only
for committed object data, with a fixed read-only command set, an allowlisted
environment, bounded pipes, and (by default) a no-network Bubblewrap boundary
that mounts the complete source repository read-only.

No API in this module exposes checkout, index, status, diff, worktree, ref, or
remote operations.  Candidate diagnostics are manifest-native elsewhere.
"""

from __future__ import annotations

import errno
import math
import os
import selectors
import signal
import stat
import subprocess  # noqa: S404 - the reviewed runner is necessarily subprocess-based
import time
from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import NoReturn, Protocol

from .constants import (
    DEFAULT_MAX_AGENT_OUTPUT_BYTES,
    SYMLINK_MODE,
    Limits,
)
from .errors import AgentLoopError, StopReason, fail
from .filesystem import ConfinedFilesystem, open_beneath
from .manifests import SubjectManifest, build_manifest_from_scan
from .models import BlobWriter, EntryKind, ScanRecord, display_path
from .service import ServiceLimits, ServiceResult, TransientServiceRunner

_READ_ONLY_GIT_CONFIG = (
    "core.hooksPath=/dev/null",
    "core.fsmonitor=false",
    "core.untrackedCache=false",
    "credential.helper=",
    "credential.interactive=never",
    "core.pager=cat",
    "pager.status=false",
    "pager.diff=false",
    "diff.external=",
    "diff.trustExitCode=false",
    "protocol.allow=never",
    "protocol.file.allow=never",
    "protocol.ext.allow=never",
)

_ALLOWED_GIT_SUBCOMMANDS = frozenset(
    {"cat-file", "config", "for-each-ref", "ls-tree", "rev-parse"}
)
_HEX_BYTES = frozenset(b"0123456789abcdef")
_SOURCE_EXCLUSION_WARNING = (
    "all staged, unstaged, untracked, and ignored source-checkout changes are excluded; "
    "only committed HEAD object data is authoritative"
)
_SERVICE_GATE_MARKER = b"\x00"
_SERVICE_GATE_CODE = (
    "import os,stat,sys\n"
    "marker=os.read(0,1)\n"
    "if marker != b'\\x00': raise SystemExit(125)\n"
    "source=sys.argv[1];expected=(int(sys.argv[2]),int(sys.argv[3]))\n"
    "fd=os.open(source,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)\n"
    "opened=os.fstat(fd)\n"
    "if (opened.st_dev,opened.st_ino) != expected: raise SystemExit(124)\n"
    "os.set_inheritable(fd,True)\n"
    "argv=sys.argv[4:]\n"
    "for index in range(len(argv)-2):\n"
    " if argv[index:index+3] == ['--ro-bind',source,'/source']:\n"
    "  argv[index+1]=f'/proc/self/fd/{fd}';break\n"
    "else: raise SystemExit(123)\n"
    "os.execv(argv[0],argv)\n"
)


class GitSandboxMode(StrEnum):
    """Whether the no-network, read-only Bubblewrap boundary is mandatory.

    ``DISABLED`` exists only for pure tests on synthetic repositories.
    Production preflight must retain the default ``REQUIRED`` mode.  ``OPTIONAL``
    is useful for portable parser tests, but is not a version-1 fallback.
    """

    REQUIRED = "required"
    OPTIONAL = "optional"
    DISABLED = "disabled"


@dataclass(frozen=True, slots=True)
class GitProcessResult:
    """Bounded result from one fixed read-only Git invocation."""

    argv: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True, slots=True)
class GitTreeEntry:
    """One raw NUL-safe ``ls-tree`` record before object materialization."""

    path: bytes
    mode: int
    object_type: str
    object_id: str


@dataclass(frozen=True, slots=True)
class GitSourceSnapshot:
    """Canonical committed source plus explicit source-exclusion evidence."""

    revision: str
    tree_object_id: str
    manifest: SubjectManifest
    warnings: tuple[str, ...] = (_SOURCE_EXCLUSION_WARNING,)


class GitServiceRunner(Protocol):
    """Narrow transient-service authority used by production Git reads."""

    def run(
        self,
        command: tuple[str, ...],
        *,
        role: str,
        input_bytes: bytes = b"",
        timeout_seconds: float,
        limits: ServiceLimits | None = None,
    ) -> ServiceResult: ...


@dataclass(frozen=True, slots=True)
class _WitnessEntry:
    path: bytes
    mode: int
    size: int
    mtime_ns: int
    ctime_ns: int
    inode: int
    device: int
    links: int


@dataclass(frozen=True, slots=True)
class _SourceWitness:
    entries: tuple[_WitnessEntry, ...]
    nested_git_paths: tuple[bytes, ...]


def sanitized_git_environment() -> dict[str, str]:
    """Return the complete child environment; ambient variables are not copied."""

    return {
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "GIT_ASKPASS": "/bin/false",
        "SSH_ASKPASS": "/bin/false",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_DISCOVERY_ACROSS_FILESYSTEM": "0",
        "GIT_INDEX_FILE": "/nonexistent/index",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "GIT_TERMINAL_PROMPT": "0",
        "PAGER": "cat",
    }


def _safe_detail(data: bytes, *, limit: int = 1_024) -> str:
    rendered = data[:limit].decode("utf-8", "backslashreplace")
    return rendered.replace("\x00", "\\0").replace("\r", "\\r").replace("\n", "\\n")


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return


def _bounded_process(
    argv: Sequence[str],
    *,
    cwd: Path | None,
    environment: Mapping[str, str],
    stdin_data: bytes,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    timeout_seconds: float,
) -> GitProcessResult:
    """Run without a shell while streaming all three pipes under hard bounds."""

    if max_stdout_bytes < 0 or max_stderr_bytes < 0:
        raise ValueError("process output bounds must be non-negative")
    if timeout_seconds <= 0:
        raise ValueError("process timeout must be positive")
    command = tuple(argv)
    if not command:
        raise ValueError("process argv must not be empty")

    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    try:
        try:
            process = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
                command,
                cwd=cwd,
                env=dict(environment),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                start_new_session=True,
            )
        except OSError as exc:
            raise fail(
                StopReason.GIT_POLICY_OR_OUTPUT_FAILURE,
                f"unable to execute hardened Git command: errno {exc.errno}",
            ) from exc

        active_process = process
        stdin_pipe = active_process.stdin
        stdout_pipe = active_process.stdout
        stderr_pipe = active_process.stderr
        if stdin_pipe is None or stdout_pipe is None or stderr_pipe is None:
            raise RuntimeError("spawned Git process has no configured standard streams")
        active_selector = selectors.DefaultSelector()
        selector = active_selector
        output = bytearray()
        errors = bytearray()
        pending_input = memoryview(stdin_data)
        input_offset = 0

        for stream in (stdin_pipe, stdout_pipe, stderr_pipe):
            os.set_blocking(stream.fileno(), False)
        if pending_input:
            active_selector.register(stdin_pipe, selectors.EVENT_WRITE, "stdin")
        else:
            stdin_pipe.close()
        active_selector.register(stdout_pipe, selectors.EVENT_READ, "stdout")
        active_selector.register(stderr_pipe, selectors.EVENT_READ, "stderr")
        deadline = time.monotonic() + timeout_seconds

        def close_registered(tag: str) -> None:
            pipe = {
                "stdin": stdin_pipe,
                "stdout": stdout_pipe,
                "stderr": stderr_pipe,
            }[tag]
            try:
                active_selector.unregister(pipe)
            except (KeyError, ValueError):
                pass  # noqa: S110 - best-effort idempotent cleanup
            try:
                pipe.close()
            except OSError:
                pass  # noqa: S110 - process termination remains authoritative

        def abort(reason: str) -> NoReturn:
            _kill_process_group(active_process)
            for tag in ("stdin", "stdout", "stderr"):
                close_registered(tag)
            try:
                active_process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                active_process.kill()
                active_process.wait()
            raise fail(StopReason.GIT_POLICY_OR_OUTPUT_FAILURE, reason)

        while active_selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                abort("hardened Git command exceeded its monotonic timeout")
            events = active_selector.select(remaining)
            if not events:
                abort("hardened Git command exceeded its monotonic timeout")
            for key, _ in events:
                if key.data == "stdin":
                    try:
                        chunk = pending_input[input_offset : input_offset + 65_536]
                        written = os.write(key.fd, chunk)
                    except BlockingIOError:
                        continue
                    except BrokenPipeError:
                        written = 0
                        input_offset = len(pending_input)
                    else:
                        input_offset += written
                    if input_offset >= len(pending_input):
                        close_registered("stdin")
                    continue

                try:
                    chunk = os.read(key.fd, 65_536)
                except BlockingIOError:
                    continue
                if not chunk:
                    close_registered(key.data)
                    continue
                target = output if key.data == "stdout" else errors
                target.extend(chunk)
                limit = max_stdout_bytes if key.data == "stdout" else max_stderr_bytes
                if len(target) > limit:
                    abort(f"hardened Git {key.data} exceeded its byte limit")

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            abort("hardened Git command exceeded its monotonic timeout")
        try:
            returncode = active_process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            abort("hardened Git command exceeded its monotonic timeout")
    except BaseException as primary_error:
        cleanup_errors: list[BaseException] = []
        if process is not None:
            try:
                _kill_process_group(process)
            except BaseException as cleanup_error:
                cleanup_errors.append(cleanup_error)
        if selector is not None:
            try:
                selector.close()
            except BaseException as cleanup_error:
                cleanup_errors.append(cleanup_error)
        if process is not None:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except BaseException as cleanup_error:
                        cleanup_errors.append(cleanup_error)
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                try:
                    process.kill()
                except BaseException as cleanup_error:
                    cleanup_errors.append(cleanup_error)
                try:
                    process.wait(timeout=1)
                except BaseException as cleanup_error:
                    cleanup_errors.append(cleanup_error)
            except BaseException as cleanup_error:
                cleanup_errors.append(cleanup_error)
        for cleanup_error in cleanup_errors:
            primary_error.add_note(
                f"post-spawn Git cleanup also failed: {type(cleanup_error).__name__}"
            )
        raise
    else:
        active_selector.close()

    return GitProcessResult(
        argv=command,
        returncode=returncode,
        stdout=bytes(output),
        stderr=bytes(errors),
    )


def _assert_read_only_git_command(arguments: Sequence[str]) -> None:
    if not arguments or arguments[0] not in _ALLOWED_GIT_SUBCOMMANDS:
        raise ValueError("Git command is outside the fixed read-only allowlist")
    command = arguments[0]
    if command == "cat-file" and tuple(arguments) != ("cat-file", "--batch"):
        raise ValueError("only raw cat-file batch reads are allowed")
    if command == "ls-tree":
        fixed_prefix = ("ls-tree", "-r", "-z", "--full-tree")
        object_name = arguments[-1] if len(arguments) == 5 else ""
        if (
            tuple(arguments[:4]) != fixed_prefix
            or len(object_name) not in {40, 64}
            or any(character not in "0123456789abcdef" for character in object_name)
        ):
            raise ValueError("only a fixed NUL-safe committed-tree object read is allowed")
    if command == "for-each-ref" and tuple(arguments) != (
        "for-each-ref",
        "--format=%(refname)",
        "refs/replace",
    ):
        raise ValueError("only replace-ref inspection is allowed")
    if command == "rev-parse":
        allowed_rev_parse = {
            (
                "rev-parse",
                "--is-inside-work-tree",
                "--is-bare-repository",
                "--git-dir",
                "--git-common-dir",
            ),
            ("rev-parse", "HEAD^{commit}", "HEAD^{tree}"),
        }
        if tuple(arguments) not in allowed_rev_parse:
            raise ValueError("rev-parse invocation is outside the fixed shape probes")
    if command == "config":
        options = set(arguments[1:])
        if "--local" not in options or "--no-includes" not in options:
            raise ValueError("Git config reads must be local and must disable includes")
        if not options.intersection({"--get", "--get-regexp", "--get-all"}):
            raise ValueError("Git config invocation is not a read operation")
        forbidden = {
            "--add",
            "--append",
            "--edit",
            "--remove-section",
            "--rename-section",
            "--unset",
            "--unset-all",
        }
        if options.intersection(forbidden):
            raise ValueError("Git config mutation is forbidden")


class GitCommandRunner:
    """Execute the module's small read-only Git vocabulary under hard bounds."""

    def __init__(
        self,
        *,
        git_executable: str = "/usr/bin/git",
        bwrap_executable: str = "/usr/bin/bwrap",
        sandbox_mode: GitSandboxMode = GitSandboxMode.REQUIRED,
        timeout_seconds: float = 30.0,
        max_stderr_bytes: int = 64 * 1_024,
        service_runner: GitServiceRunner | None = None,
    ) -> None:
        if not isinstance(sandbox_mode, GitSandboxMode):
            raise TypeError("sandbox_mode must be a GitSandboxMode")
        if (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or not math.isfinite(float(timeout_seconds))
            or timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be positive")
        if (
            not isinstance(max_stderr_bytes, int)
            or isinstance(max_stderr_bytes, bool)
            or max_stderr_bytes <= 0
        ):
            raise ValueError("max_stderr_bytes must be positive")
        if service_runner is not None and not callable(getattr(service_runner, "run", None)):
            raise TypeError("service_runner must implement the Git service runner protocol")
        self.git_executable = git_executable
        self.bwrap_executable = bwrap_executable
        self.sandbox_mode = sandbox_mode
        self.timeout_seconds = timeout_seconds
        self.max_stderr_bytes = max_stderr_bytes
        self.service_runner = (
            TransientServiceRunner() if service_runner is None else service_runner
        )
        self._repository_fd: int | None = None
        self._repository_identity: tuple[int, int] | None = None

    @contextmanager
    def bind_repository(self, root_fd: int) -> Iterator[None]:
        """Retain one exact repository directory across every Git invocation."""

        if self._repository_fd is not None:
            raise RuntimeError("Git repository authority is already bound")
        retained = os.dup(root_fd)
        metadata = os.fstat(retained)
        if not stat.S_ISDIR(metadata.st_mode):
            os.close(retained)
            raise ValueError("Git repository authority must be a directory")
        self._repository_fd = retained
        self._repository_identity = (metadata.st_dev, metadata.st_ino)
        try:
            yield
        finally:
            self._repository_fd = None
            self._repository_identity = None
            os.close(retained)

    @staticmethod
    def _git_argv(git_executable: str, arguments: Sequence[str]) -> tuple[str, ...]:
        _assert_read_only_git_command(arguments)
        prefix: list[str] = [git_executable, "--no-optional-locks"]
        for setting in _READ_ONLY_GIT_CONFIG:
            prefix.extend(("-c", setting))
        return (*prefix, *arguments)

    def _sandbox_available(self) -> bool:
        try:
            metadata = os.stat(self.bwrap_executable, follow_symlinks=True)
        except OSError:
            return False
        return stat.S_ISREG(metadata.st_mode) and os.access(self.bwrap_executable, os.X_OK)

    def _sandbox_argv(
        self,
        repository: Path,
        git_argv: Sequence[str],
        environment: Mapping[str, str],
    ) -> tuple[str, ...]:
        resolved_git = Path(self.git_executable).resolve(strict=True)
        if not resolved_git.is_relative_to("/usr"):
            raise fail(
                StopReason.SANDBOX_SETUP_FAILURE,
                "required Git executable is outside the reviewed /usr runtime mount",
            )
        arguments: list[str] = [
            self.bwrap_executable,
            "--unshare-user",
            "--unshare-pid",
            "--as-pid-1",
            "--unshare-ipc",
            "--unshare-uts",
            "--unshare-cgroup",
            "--unshare-net",
            "--cap-drop",
            "ALL",
            "--die-with-parent",
            "--new-session",
            "--tmpfs",
            "/",
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "usr/bin",
            "/bin",
            "--symlink",
            "usr/lib",
            "/lib",
            "--symlink",
            "usr/lib64",
            "/lib64",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--dir",
            "/source",
            "--ro-bind",
            os.fspath(repository),
            "/source",
            "--dir",
            "/nonexistent",
            "--chdir",
            "/source",
            "--remount-ro",
            "/",
            "--clearenv",
        ]
        for key, value in sorted(environment.items()):
            arguments.extend(("--setenv", key, value))
        arguments.extend(git_argv)
        return tuple(arguments)

    def run(
        self,
        repository: Path,
        arguments: Sequence[str],
        *,
        stdin_data: bytes = b"",
        max_stdout_bytes: int = DEFAULT_MAX_AGENT_OUTPUT_BYTES,
        allowed_returncodes: Iterable[int] = (0,),
    ) -> GitProcessResult:
        """Run a reviewed Git read; untrusted values never become shell text."""

        _assert_read_only_git_command(arguments)
        if not isinstance(stdin_data, bytes):
            raise TypeError("Git stdin must be bytes")
        if (
            not isinstance(max_stdout_bytes, int)
            or isinstance(max_stdout_bytes, bool)
            or max_stdout_bytes < 0
        ):
            raise ValueError("max_stdout_bytes must be a non-negative integer")
        allowed = frozenset(allowed_returncodes)
        if not allowed:
            raise ValueError("allowed_returncodes must not be empty")
        environment = sanitized_git_environment()
        git_argv = self._git_argv(self.git_executable, arguments)
        use_sandbox = self.sandbox_mode is not GitSandboxMode.DISABLED
        if use_sandbox and not self._sandbox_available():
            if self.sandbox_mode is GitSandboxMode.REQUIRED:
                raise fail(
                    StopReason.SANDBOX_SETUP_FAILURE,
                    "required no-network Bubblewrap executable is unavailable",
                )
            use_sandbox = False

        if use_sandbox:
            try:
                argv = self._sandbox_argv(repository, git_argv, environment)
            except (OSError, RuntimeError) as exc:
                if self.sandbox_mode is GitSandboxMode.REQUIRED:
                    raise fail(
                        StopReason.SANDBOX_SETUP_FAILURE,
                        "required no-network Bubblewrap command could not be constructed",
                    ) from exc
                argv = git_argv
                use_sandbox = False
        else:
            argv = git_argv

        if use_sandbox:
            service_limits = ServiceLimits(
                runtime_max_seconds=max(1, math.ceil(self.timeout_seconds)),
                output_max_bytes=max_stdout_bytes + self.max_stderr_bytes,
            )
            # Fast Git reads may otherwise finish and be collected before the
            # parent can inspect their transient-unit properties.  This tiny
            # reviewed gate blocks as the service main process until
            # TransientServiceRunner has completed that inspection, then execs
            # Bubblewrap in-place while preserving the remaining Git stdin.
            service_command = (
                "/usr/bin/python3",
                "-I",
                "-B",
                "-c",
                _SERVICE_GATE_CODE,
                os.fspath(repository),
                str(
                    self._repository_identity[0]
                    if self._repository_identity is not None
                    else os.stat(repository, follow_symlinks=False).st_dev
                ),
                str(
                    self._repository_identity[1]
                    if self._repository_identity is not None
                    else os.stat(repository, follow_symlinks=False).st_ino
                ),
                *tuple(argv),
            )
            try:
                service = self.service_runner.run(
                    service_command,
                    role="git",
                    input_bytes=_SERVICE_GATE_MARKER + stdin_data,
                    timeout_seconds=self.timeout_seconds,
                    limits=service_limits,
                )
            except AgentLoopError as exc:
                if exc.reason is StopReason.AGENT_OUTPUT_LIMIT:
                    raise fail(
                        StopReason.GIT_POLICY_OR_OUTPUT_FAILURE,
                        "hardened Git combined output exceeded its byte limit",
                    ) from exc
                if exc.reason is StopReason.SERVICE_LIFECYCLE_MISMATCH:
                    raise fail(
                        StopReason.SANDBOX_SETUP_FAILURE,
                        "required Git transient service failed its lifecycle contract",
                    ) from exc
                raise
            except (OSError, subprocess.SubprocessError) as exc:
                raise fail(
                    StopReason.SANDBOX_SETUP_FAILURE,
                    "required Git transient service could not start",
                ) from exc
            if not service.cgroup_empty:
                raise fail(
                    StopReason.SANDBOX_SETUP_FAILURE,
                    "required Git transient service did not prove cgroup emptiness",
                )
            process = service.process
            if process.output_limited:
                raise fail(
                    StopReason.GIT_POLICY_OR_OUTPUT_FAILURE,
                    "hardened Git combined output exceeded its byte limit",
                )
            if process.timed_out:
                raise fail(
                    StopReason.GIT_POLICY_OR_OUTPUT_FAILURE,
                    "hardened Git command exceeded its monotonic timeout",
                )
            if len(process.stdout) > max_stdout_bytes:
                raise fail(
                    StopReason.GIT_POLICY_OR_OUTPUT_FAILURE,
                    "hardened Git stdout exceeded its byte limit",
                )
            if len(process.stderr) > self.max_stderr_bytes:
                raise fail(
                    StopReason.GIT_POLICY_OR_OUTPUT_FAILURE,
                    "hardened Git stderr exceeded its byte limit",
                )
            result = GitProcessResult(
                argv=tuple(argv),
                returncode=process.returncode,
                stdout=process.stdout,
                stderr=process.stderr,
            )
        else:
            cwd = (
                Path(f"/proc/{os.getpid()}/fd/{self._repository_fd}")
                if self._repository_fd is not None
                else repository
            )
            result = _bounded_process(
                argv,
                cwd=cwd,
                environment=environment,
                stdin_data=stdin_data,
                max_stdout_bytes=max_stdout_bytes,
                max_stderr_bytes=self.max_stderr_bytes,
                timeout_seconds=self.timeout_seconds,
            )
        if result.returncode not in allowed:
            detail = _safe_detail(result.stderr)
            if use_sandbox and result.returncode in {123, 124, 125}:
                raise fail(
                    StopReason.SANDBOX_SETUP_FAILURE,
                    "required Git repository descriptor binding failed before launch",
                )
            if use_sandbox and detail.startswith("bwrap:"):
                raise fail(
                    StopReason.SANDBOX_SETUP_FAILURE,
                    f"required no-network Bubblewrap setup failed: {detail}",
                )
            raise fail(
                StopReason.GIT_POLICY_OR_OUTPUT_FAILURE,
                f"hardened Git command failed with status {result.returncode}: {detail}",
            )
        return result


def _validate_oid(raw: bytes, *, context: str) -> str:
    if len(raw) not in {40, 64} or any(value not in _HEX_BYTES for value in raw):
        raise fail(
            StopReason.GIT_POLICY_OR_OUTPUT_FAILURE,
            f"{context} returned a non-canonical object identifier",
        )
    return raw.decode("ascii")


def _parse_ls_tree(data: bytes, *, limits: Limits) -> tuple[GitTreeEntry, ...]:
    if not data:
        return ()
    if not data.endswith(b"\x00"):
        raise fail(
            StopReason.GIT_POLICY_OR_OUTPUT_FAILURE,
            "NUL-safe ls-tree output ended without a record terminator",
        )
    records = data[:-1].split(b"\x00")
    if len(records) > limits.max_files:
        raise fail(StopReason.GIT_POLICY_OR_OUTPUT_FAILURE, "ls-tree exceeds max_files")
    entries: list[GitTreeEntry] = []
    seen_paths: set[bytes] = set()
    for record in records:
        header, separator, path = record.partition(b"\t")
        fields = header.split(b" ")
        if separator != b"\t" or len(fields) != 3:
            raise fail(
                StopReason.GIT_POLICY_OR_OUTPUT_FAILURE,
                "ls-tree emitted a malformed NUL record",
            )
        raw_mode, raw_type, raw_oid = fields
        try:
            mode = int(raw_mode, 8)
        except ValueError as exc:
            raise fail(
                StopReason.GIT_POLICY_OR_OUTPUT_FAILURE,
                "ls-tree emitted a non-octal mode",
            ) from exc
        if raw_mode not in {b"100644", b"100755", b"120000"}:
            if raw_mode == b"160000" or raw_type == b"commit":
                raise fail(
                    StopReason.REPOSITORY_SHAPE_UNSUPPORTED,
                    f"committed HEAD contains a submodule at {display_path(path)}",
                )
            raise fail(
                StopReason.REPOSITORY_SHAPE_UNSUPPORTED,
                f"committed HEAD contains unsupported mode {raw_mode!r}",
            )
        if raw_type != b"blob":
            raise fail(
                StopReason.REPOSITORY_SHAPE_UNSUPPORTED,
                "committed HEAD contains a non-blob leaf",
            )
        if (
            not path
            or path.startswith(b"/")
            or b"\x00" in path
            or any(component in {b"", b".", b".."} for component in path.split(b"/"))
        ):
            raise fail(
                StopReason.REPOSITORY_SHAPE_UNSUPPORTED,
                "committed HEAD contains an unsafe or ambiguous path",
            )
        if any(component == b".git" for component in path.split(b"/")):
            raise fail(
                StopReason.REPOSITORY_SHAPE_UNSUPPORTED,
                f"committed HEAD contains nested Git metadata at {display_path(path)}",
            )
        if len(path) > limits.max_path_bytes or len(path.split(b"/")) > limits.max_path_depth:
            raise fail(
                StopReason.GIT_POLICY_OR_OUTPUT_FAILURE,
                f"committed path exceeds configured bounds: {display_path(path)}",
            )
        if path in seen_paths:
            raise fail(StopReason.GIT_POLICY_OR_OUTPUT_FAILURE, "ls-tree emitted a duplicate path")
        seen_paths.add(path)
        entries.append(
            GitTreeEntry(
                path=path,
                mode=mode,
                object_type="blob",
                object_id=_validate_oid(raw_oid, context="ls-tree"),
            )
        )
    return tuple(entries)


def _parse_cat_file_batch(
    data: bytes,
    object_ids: Sequence[str],
    *,
    max_file_bytes: int,
) -> dict[str, bytes]:
    position = 0
    blobs: dict[str, bytes] = {}
    for expected in object_ids:
        newline = data.find(b"\n", position)
        if newline < 0 or newline - position > 256:
            raise fail(
                StopReason.GIT_POLICY_OR_OUTPUT_FAILURE,
                "cat-file batch emitted a malformed header",
            )
        header = data[position:newline]
        position = newline + 1
        fields = header.split(b" ")
        if len(fields) == 2 and fields[1] in {b"missing", b"ambiguous"}:
            raise fail(
                StopReason.REPOSITORY_SHAPE_UNSUPPORTED,
                f"committed HEAD object {expected} is missing",
            )
        if len(fields) != 3:
            raise fail(
                StopReason.GIT_POLICY_OR_OUTPUT_FAILURE,
                "cat-file batch emitted an invalid object header",
            )
        observed = _validate_oid(fields[0], context="cat-file")
        if observed != expected or fields[1] != b"blob":
            raise fail(
                StopReason.GIT_POLICY_OR_OUTPUT_FAILURE,
                "cat-file batch object identity or type did not match its request",
            )
        try:
            size = int(fields[2])
        except ValueError as exc:
            raise fail(
                StopReason.GIT_POLICY_OR_OUTPUT_FAILURE,
                "cat-file batch emitted a non-numeric object size",
            ) from exc
        if size < 0 or size > max_file_bytes:
            raise fail(
                StopReason.GIT_POLICY_OR_OUTPUT_FAILURE,
                f"committed blob {expected} exceeds max_file_bytes",
            )
        end = position + size
        if end >= len(data) or data[end : end + 1] != b"\n":
            raise fail(
                StopReason.GIT_POLICY_OR_OUTPUT_FAILURE,
                "cat-file batch payload was truncated or lacked its delimiter",
            )
        blobs[expected] = data[position:end]
        position = end + 1
    if position != len(data):
        raise fail(
            StopReason.GIT_POLICY_OR_OUTPUT_FAILURE,
            "cat-file batch emitted unrequested trailing output",
        )
    return blobs


def _source_witness_once(repository_fd: int, *, max_entries: int) -> _SourceWitness:
    entries: list[_WitnessEntry] = []
    nested: list[bytes] = []
    stack: list[tuple[bytes, int]] = []
    try:
        filesystem = ConfinedFilesystem.from_fd(repository_fd)
    except (OSError, ValueError) as exc:
        raise fail(
            StopReason.REPOSITORY_SHAPE_UNSUPPORTED,
            "source repository cannot be opened through the confined filesystem",
        ) from exc
    with filesystem:
        stack.append((b"", filesystem.open_directory()))
        try:
            while stack:
                relative, directory_fd = stack.pop()
                try:
                    try:
                        with os.scandir(directory_fd) as iterator:
                            children = sorted(
                                (os.fsencode(child.name) for child in iterator),
                                reverse=True,
                            )
                    except OSError as exc:
                        raise fail(
                            StopReason.REPOSITORY_SHAPE_UNSUPPORTED,
                            f"source repository cannot be witnessed safely: errno {exc.errno}",
                        ) from exc
                    for name in children:
                        child_relative = name if not relative else relative + b"/" + name
                        try:
                            metadata = os.stat(
                                name,
                                dir_fd=directory_fd,
                                follow_symlinks=False,
                            )
                        except OSError as exc:
                            raise fail(
                                StopReason.REPOSITORY_SHAPE_UNSUPPORTED,
                                "source repository changed during witness capture: "
                                f"errno {exc.errno}",
                            ) from exc
                        entries.append(
                            _WitnessEntry(
                                path=child_relative,
                                mode=metadata.st_mode,
                                size=metadata.st_size,
                                mtime_ns=metadata.st_mtime_ns,
                                ctime_ns=metadata.st_ctime_ns,
                                inode=metadata.st_ino,
                                device=metadata.st_dev,
                                links=metadata.st_nlink,
                            )
                        )
                        if len(entries) > max_entries:
                            raise fail(
                                StopReason.GIT_POLICY_OR_OUTPUT_FAILURE,
                                "source immutability witness exceeds its entry bound",
                            )
                        if name == b".git" and child_relative != b".git":
                            nested.append(child_relative)
                        if not stat.S_ISDIR(metadata.st_mode):
                            continue
                        try:
                            child_fd = open_beneath(
                                directory_fd,
                                name,
                                os.O_RDONLY | os.O_DIRECTORY,
                            )
                        except AgentLoopError as exc:
                            raise fail(
                                StopReason.REPOSITORY_SHAPE_UNSUPPORTED,
                                "source repository changed during confined directory traversal",
                            ) from exc
                        try:
                            opened = os.fstat(child_fd)
                        except BaseException:
                            os.close(child_fd)
                            raise
                        expected_identity = (
                            metadata.st_mode,
                            metadata.st_size,
                            metadata.st_mtime_ns,
                            metadata.st_ctime_ns,
                            metadata.st_ino,
                            metadata.st_dev,
                            metadata.st_nlink,
                        )
                        opened_identity = (
                            opened.st_mode,
                            opened.st_size,
                            opened.st_mtime_ns,
                            opened.st_ctime_ns,
                            opened.st_ino,
                            opened.st_dev,
                            opened.st_nlink,
                        )
                        if opened_identity != expected_identity:
                            os.close(child_fd)
                            raise fail(
                                StopReason.REPOSITORY_SHAPE_UNSUPPORTED,
                                "source directory identity changed during witness capture",
                            )
                        stack.append((child_relative, child_fd))
                finally:
                    os.close(directory_fd)
        finally:
            for _, directory_fd in stack:
                os.close(directory_fd)
    return _SourceWitness(
        entries=tuple(sorted(entries, key=lambda entry: entry.path)),
        nested_git_paths=tuple(sorted(nested)),
    )


def _source_witness(repository_fd: int, *, max_entries: int) -> _SourceWitness:
    """Capture two identical descriptor-rooted passes before trusting a witness."""

    first = _source_witness_once(repository_fd, max_entries=max_entries)
    second = _source_witness_once(repository_fd, max_entries=max_entries)
    if first != second:
        raise fail(
            StopReason.OUT_OF_BAND_CHANGE,
            "source repository changed during stable witness capture",
        )
    return second


def _canonical_repository_root(
    repository: str | os.PathLike[str],
) -> tuple[Path, tuple[int, int]]:
    try:
        root = Path(repository).resolve(strict=True)
        metadata = root.stat(follow_symlinks=False)
    except OSError as exc:
        raise fail(
            StopReason.REPOSITORY_SHAPE_UNSUPPORTED,
            f"source repository root is unavailable: errno {exc.errno}",
        ) from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise fail(StopReason.REPOSITORY_SHAPE_UNSUPPORTED, "source repository is not a directory")
    git_control = root / ".git"
    try:
        git_metadata = git_control.stat(follow_symlinks=False)
    except FileNotFoundError as exc:
        raise fail(
            StopReason.REPOSITORY_SHAPE_UNSUPPORTED,
            "source is bare, linked, or lacks a .git directory",
        ) from exc
    except OSError as exc:
        raise fail(
            StopReason.REPOSITORY_SHAPE_UNSUPPORTED,
            f"source .git directory is unavailable: errno {exc.errno}",
        ) from exc
    if not stat.S_ISDIR(git_metadata.st_mode) or stat.S_ISLNK(git_metadata.st_mode):
        raise fail(
            StopReason.REPOSITORY_SHAPE_UNSUPPORTED,
            "linked-worktree and indirect .git control paths are unsupported",
        )
    objects = git_control / "objects"
    try:
        object_metadata = objects.stat(follow_symlinks=False)
    except OSError as exc:
        raise fail(
            StopReason.REPOSITORY_SHAPE_UNSUPPORTED,
            f"source object directory is unavailable: errno {exc.errno}",
        ) from exc
    if not stat.S_ISDIR(object_metadata.st_mode) or stat.S_ISLNK(object_metadata.st_mode):
        raise fail(
            StopReason.REPOSITORY_SHAPE_UNSUPPORTED,
            "source object directory is indirect or unsupported",
        )
    return root, (metadata.st_dev, metadata.st_ino)


def _require_repository_path_identity(repository: Path, repository_fd: int) -> None:
    """Ensure the operator-selected pathname still names the retained root."""

    try:
        named = os.stat(repository, follow_symlinks=False)
        retained = os.fstat(repository_fd)
    except OSError as exc:
        raise fail(
            StopReason.OUT_OF_BAND_CHANGE,
            f"source repository root changed during extraction: errno {exc.errno}",
        ) from exc
    if (
        not stat.S_ISDIR(named.st_mode)
        or (named.st_dev, named.st_ino) != (retained.st_dev, retained.st_ino)
    ):
        raise fail(
            StopReason.OUT_OF_BAND_CHANGE,
            "source repository pathname no longer names the retained root",
        )


def _config_value(
    runner: GitCommandRunner,
    repository: Path,
    key: str,
) -> bytes | None:
    result = runner.run(
        repository,
        ("config", "--local", "--no-includes", "--get", key),
        max_stdout_bytes=64 * 1_024,
        allowed_returncodes=(0, 1),
    )
    if result.returncode == 1:
        return None
    return result.stdout.rstrip(b"\n")


def _reject_structural_config(runner: GitCommandRunner, repository: Path) -> None:
    core_bare = _config_value(runner, repository, "core.bare")
    if core_bare not in {None, b"false"}:
        raise fail(StopReason.REPOSITORY_SHAPE_UNSUPPORTED, "core.bare is not false")
    for key in ("core.worktree", "extensions.partialClone"):
        if _config_value(runner, repository, key) is not None:
            raise fail(
                StopReason.REPOSITORY_SHAPE_UNSUPPORTED,
                f"unsupported structural Git configuration: {key}",
            )
    for key in ("extensions.worktreeConfig", "extensions.relativeWorktrees"):
        if _config_value(runner, repository, key) not in {None, b"false"}:
            raise fail(
                StopReason.REPOSITORY_SHAPE_UNSUPPORTED,
                f"unsupported structural Git configuration: {key}",
            )

    regexp = runner.run(
        repository,
        (
            "config",
            "--local",
            "--no-includes",
            "--get-regexp",
            r"^(remote\..*\.promisor|include\.path|includeIf\..*\.path)$",
        ),
        max_stdout_bytes=64 * 1_024,
        allowed_returncodes=(0, 1),
    )
    if regexp.returncode == 0 and regexp.stdout:
        raise fail(
            StopReason.REPOSITORY_SHAPE_UNSUPPORTED,
            "promisor or external include configuration is unsupported",
        )


def _reject_alternates(repository_fd: int) -> None:
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        git_descriptor = os.open(".git", directory_flags, dir_fd=repository_fd)
    except OSError as exc:
        raise fail(
            StopReason.REPOSITORY_SHAPE_UNSUPPORTED,
            f"Git control directory cannot be opened safely: errno {exc.errno}",
        ) from exc
    try:
        objects_descriptor = os.open("objects", directory_flags, dir_fd=git_descriptor)
    except OSError as exc:
        os.close(git_descriptor)
        raise fail(
            StopReason.REPOSITORY_SHAPE_UNSUPPORTED,
            f"object store cannot be opened safely: errno {exc.errno}",
        ) from exc
    try:
        try:
            info_descriptor = os.open("info", directory_flags, dir_fd=objects_descriptor)
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                return
            raise fail(
                StopReason.REPOSITORY_SHAPE_UNSUPPORTED,
                f"object info directory cannot be opened safely: errno {exc.errno}",
            ) from exc
        try:
            for name in ("alternates", "http-alternates"):
                try:
                    descriptor = os.open(
                        name,
                        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                        dir_fd=info_descriptor,
                    )
                except OSError as exc:
                    if exc.errno == errno.ENOENT:
                        continue
                    raise fail(
                        StopReason.REPOSITORY_SHAPE_UNSUPPORTED,
                        f"object alternate metadata cannot be opened safely: errno {exc.errno}",
                    ) from exc
                try:
                    metadata = os.fstat(descriptor)
                    if not stat.S_ISREG(metadata.st_mode):
                        raise fail(
                            StopReason.REPOSITORY_SHAPE_UNSUPPORTED,
                            "object alternate metadata has an unsafe file type",
                        )
                    content = os.read(descriptor, 4_097)
                    if len(content) > 4_096:
                        raise fail(
                            StopReason.REPOSITORY_SHAPE_UNSUPPORTED,
                            "object alternate metadata exceeds its bound",
                        )
                finally:
                    os.close(descriptor)
                if content.strip():
                    raise fail(
                        StopReason.REPOSITORY_SHAPE_UNSUPPORTED,
                        "object alternates are unsupported in version 1",
                    )
        finally:
            os.close(info_descriptor)
    finally:
        os.close(objects_descriptor)
        os.close(git_descriptor)


def _verify_basic_shape(
    runner: GitCommandRunner,
    repository: Path,
    repository_fd: int,
) -> tuple[str, str]:
    # This command family explicitly disables includes, so hostile include.path
    # values are rejected before a general Git command is allowed to load them.
    _reject_structural_config(runner, repository)
    shape = runner.run(
        repository,
        (
            "rev-parse",
            "--is-inside-work-tree",
            "--is-bare-repository",
            "--git-dir",
            "--git-common-dir",
        ),
        max_stdout_bytes=4_096,
    )
    lines = shape.stdout.splitlines()
    if lines != [b"true", b"false", b".git", b".git"]:
        raise fail(
            StopReason.REPOSITORY_SHAPE_UNSUPPORTED,
            "source is bare, linked, nested, or has an unexpected common directory",
        )
    _reject_alternates(repository_fd)

    replacements = runner.run(
        repository,
        ("for-each-ref", "--format=%(refname)", "refs/replace"),
        max_stdout_bytes=64 * 1_024,
    )
    if replacements.stdout:
        raise fail(StopReason.REPOSITORY_SHAPE_UNSUPPORTED, "replace refs are unsupported")

    try:
        resolved = runner.run(
            repository,
            ("rev-parse", "HEAD^{commit}", "HEAD^{tree}"),
            max_stdout_bytes=1_024,
        )
    except AgentLoopError as exc:
        if exc.reason is StopReason.GIT_POLICY_OR_OUTPUT_FAILURE:
            raise fail(
                StopReason.REPOSITORY_SHAPE_UNSUPPORTED,
                "HEAD is absent or invalid",
            ) from exc
        raise
    object_ids = resolved.stdout.splitlines()
    if len(object_ids) != 2:
        raise fail(StopReason.REPOSITORY_SHAPE_UNSUPPORTED, "HEAD is absent or invalid")
    return (
        _validate_oid(object_ids[0], context="HEAD commit resolution"),
        _validate_oid(object_ids[1], context="HEAD tree resolution"),
    )


def extract_committed_head(
    repository: str | os.PathLike[str],
    blobs: BlobWriter,
    *,
    limits: Limits | None = None,
    runner: GitCommandRunner | None = None,
    max_witness_entries: int = 200_000,
) -> GitSourceSnapshot:
    """Extract committed ``HEAD`` into the canonical manifest/blob interface.

    The checkout, index, ignore rules, filters, attributes, and staging state are
    deliberately never consulted as subject data.
    """

    selected_limits = limits or Limits()
    if not isinstance(selected_limits, Limits):
        raise TypeError("limits must be a Limits instance")
    if not isinstance(blobs, BlobWriter):
        raise TypeError("blobs must implement BlobWriter")
    if max_witness_entries <= 0:
        raise ValueError("max_witness_entries must be positive")
    selected_runner = runner or GitCommandRunner()
    if not isinstance(selected_runner, GitCommandRunner):
        raise TypeError("runner must be a GitCommandRunner")

    root, expected_root_identity = _canonical_repository_root(repository)
    repository_authority = ConfinedFilesystem.open(root)
    retained_root = os.fstat(repository_authority.fileno())
    if (retained_root.st_dev, retained_root.st_ino) != expected_root_identity:
        repository_authority.close()
        raise fail(
            StopReason.OUT_OF_BAND_CHANGE,
            "source repository root changed while its authority was acquired",
        )
    repository_binding = selected_runner.bind_repository(repository_authority.fileno())
    try:
        repository_binding.__enter__()
    except BaseException:
        repository_authority.close()
        raise
    try:
        _require_repository_path_identity(root, repository_authority.fileno())
        before = _source_witness(
            repository_authority.fileno(),
            max_entries=max_witness_entries,
        )
    except BaseException:
        repository_binding.__exit__(None, None, None)
        repository_authority.close()
        raise
    if before.nested_git_paths:
        rendered = ", ".join(display_path(path) for path in before.nested_git_paths[:8])
        repository_binding.__exit__(None, None, None)
        repository_authority.close()
        raise fail(
            StopReason.REPOSITORY_SHAPE_UNSUPPORTED,
            f"nested Git repository metadata is unsupported: {rendered}",
        )

    try:
        try:
            revision, tree_object_id = _verify_basic_shape(
                selected_runner,
                root,
                repository_authority.fileno(),
            )
            tree_output_bound = (
                selected_limits.max_files * (selected_limits.max_path_bytes + 128) + 1
            )
            tree_result = selected_runner.run(
                root,
                ("ls-tree", "-r", "-z", "--full-tree", tree_object_id),
                max_stdout_bytes=tree_output_bound,
            )
            tree_entries = _parse_ls_tree(tree_result.stdout, limits=selected_limits)

            object_ids = tuple(dict.fromkeys(entry.object_id for entry in tree_entries))
            batch_input = b"".join(
                object_id.encode("ascii") + b"\n" for object_id in object_ids
            )
            batch_output_bound = (
                selected_limits.max_total_subject_bytes + len(object_ids) * 160 + 1
            )
            batch_result = selected_runner.run(
                root,
                ("cat-file", "--batch"),
                stdin_data=batch_input,
                max_stdout_bytes=batch_output_bound,
            )
            object_data = _parse_cat_file_batch(
                batch_result.stdout,
                object_ids,
                max_file_bytes=selected_limits.max_file_bytes,
            )

            for entry in tree_entries:
                if entry.mode != SYMLINK_MODE:
                    continue
                target = object_data[entry.object_id]
                if not target or b"\x00" in target or len(target) > selected_limits.max_path_bytes:
                    raise fail(
                        StopReason.UNSAFE_OR_AMBIGUOUS_PATH,
                        "committed symlink has an unsafe literal target: "
                        f"{display_path(entry.path)}",
                    )

            scan_records = (
                ScanRecord(
                    path=entry.path,
                    kind=(
                        EntryKind.SYMLINK
                        if entry.mode == SYMLINK_MODE
                        else EntryKind.REGULAR
                    ),
                    mode=entry.mode,
                    payload=object_data[entry.object_id],
                )
                for entry in tree_entries
            )
            try:
                manifest = build_manifest_from_scan(scan_records, blobs, limits=selected_limits)
            except (TypeError, ValueError) as exc:
                raise fail(
                    StopReason.GIT_POLICY_OR_OUTPUT_FAILURE,
                    "committed tree cannot be represented by the canonical manifest",
                ) from exc
        except AgentLoopError as exc:
            if exc.reason is StopReason.GIT_POLICY_OR_OUTPUT_FAILURE and (
                "missing" in exc.detail or "HEAD" in exc.detail
            ):
                raise fail(StopReason.REPOSITORY_SHAPE_UNSUPPORTED, exc.detail) from exc
            raise
    finally:
        try:
            after = _source_witness(
                repository_authority.fileno(),
                max_entries=max_witness_entries,
            )
            _require_repository_path_identity(root, repository_authority.fileno())
            if before != after:
                raise fail(
                    StopReason.OUT_OF_BAND_CHANGE,
                    "source checkout or Git metadata changed during committed-tree extraction",
                )
        finally:
            repository_binding.__exit__(None, None, None)
            repository_authority.close()
    return GitSourceSnapshot(
        revision=revision,
        tree_object_id=tree_object_id,
        manifest=manifest,
    )


__all__ = [
    "GitCommandRunner",
    "GitProcessResult",
    "GitSandboxMode",
    "GitSourceSnapshot",
    "GitTreeEntry",
    "extract_committed_head",
    "sanitized_git_environment",
]
