#!/bin/bash
set -euo pipefail
umask 077

BOUNDARY_SCRIPT_PATH=$(/usr/bin/readlink -f -- "$0")
BOUNDARY_SUPPORT_DIR=$(/usr/bin/dirname -- "$BOUNDARY_SCRIPT_PATH")
BOUNDARY_REPO_ROOT=$(/usr/bin/readlink -f -- "$BOUNDARY_SUPPORT_DIR/../..")
BOUNDARY_SOURCE="$BOUNDARY_SUPPORT_DIR/agent-loop-claude-boundary-attest.c"
BOUNDARY_POLICY="$BOUNDARY_SUPPORT_DIR/managed-settings.json"
BOUNDARY_POLICY_DIR=/etc/claude-code
BOUNDARY_POLICY_TARGET=/etc/claude-code/managed-settings.json
BOUNDARY_HELPER_DIR=/usr/local/libexec
BOUNDARY_HELPER_TARGET=/usr/local/libexec/agent-loop-claude-boundary-attest
BOUNDARY_MARKER='AGENT_LOOP_MANAGED_CLAUDE_BOUNDARY_OK:reviewed-managed-boundary-v1:credential_absent:scrub=1'

if [ "$#" -gt 1 ] || { [ "$#" -eq 1 ] && [ "$1" != "--check" ]; }; then
  echo "usage: $0 [--check]" >&2
  exit 2
fi

# The reviewed assets exist in exactly two supported layouts.  A source tree
# keeps the import package under <repository>/src.  A pipx-installed wheel
# places this data script under <prefix>/share/agent-loop and the package under
# the pinned CPython 3.14 site-packages directory in the same prefix.  Resolve
# only those co-located roots; never fall back to an ambient user or system
# package when this installer is about to validate administrator-bound assets.
boundary_runtime_root_is_complete() {
  [ -d "$1" ] && [ ! -L "$1" ] && \
    [ -d "$1/agent_loop" ] && [ ! -L "$1/agent_loop" ] && \
    [ -f "$1/agent_loop/__init__.py" ] && \
    [ ! -L "$1/agent_loop/__init__.py" ] && \
    [ -f "$1/agent_loop/claude_managed_policy.py" ] && \
    [ ! -L "$1/agent_loop/claude_managed_policy.py" ]
}

BOUNDARY_RUNTIME_ROOT="$BOUNDARY_REPO_ROOT/src"
if ! boundary_runtime_root_is_complete "$BOUNDARY_RUNTIME_ROOT"; then
  case "$BOUNDARY_REPO_ROOT" in
    */share/agent-loop)
      BOUNDARY_INSTALL_PREFIX=${BOUNDARY_REPO_ROOT%/share/agent-loop}
      BOUNDARY_RUNTIME_ROOT="$BOUNDARY_INSTALL_PREFIX/lib/python3.14/site-packages"
      ;;
    *)
      echo "managed Claude installer is outside a reviewed source or wheel layout" >&2
      exit 1
      ;;
  esac
  if [ -z "$BOUNDARY_INSTALL_PREFIX" ] || \
    ! boundary_runtime_root_is_complete "$BOUNDARY_RUNTIME_ROOT"; then
    echo "co-installed agent_loop Python 3.14 runtime is missing or symbolic" >&2
    exit 1
  fi
fi

for BOUNDARY_TOOL in \
  /usr/bin/cc \
  /usr/bin/dirname \
  /usr/bin/env \
  /usr/bin/file \
  /usr/bin/grep \
  /usr/bin/install \
  /usr/bin/mktemp \
  /usr/bin/python3.14 \
  /usr/bin/readelf \
  /usr/bin/readlink \
  /usr/bin/rm \
  /usr/bin/sudo \
  /usr/bin/test
do
  if [ ! -x "$BOUNDARY_TOOL" ]; then
    echo "required reviewed tool is missing: $BOUNDARY_TOOL" >&2
    exit 1
  fi
done

for BOUNDARY_INPUT in "$BOUNDARY_SOURCE" "$BOUNDARY_POLICY"; do
  if [ ! -f "$BOUNDARY_INPUT" ] || [ -L "$BOUNDARY_INPUT" ]; then
    echo "reviewed boundary input is missing or symbolic: $BOUNDARY_INPUT" >&2
    exit 1
  fi
done

BOUNDARY_BUILD_ROOT=$(/usr/bin/mktemp -d /tmp/agent-loop-claude-boundary.XXXXXX)
case "$BOUNDARY_BUILD_ROOT" in
  /tmp/agent-loop-claude-boundary.??????) ;;
  *)
    echo "mktemp returned an unexpected build path" >&2
    exit 1
    ;;
esac

cleanup_boundary_build() {
  case "$BOUNDARY_BUILD_ROOT" in
    /tmp/agent-loop-claude-boundary.??????)
      if [ -d "$BOUNDARY_BUILD_ROOT" ] && [ ! -L "$BOUNDARY_BUILD_ROOT" ]; then
        /usr/bin/rm -rf -- "$BOUNDARY_BUILD_ROOT"
      fi
      ;;
  esac
}
trap cleanup_boundary_build EXIT HUP INT TERM

BOUNDARY_HELPER_BUILD="$BOUNDARY_BUILD_ROOT/agent-loop-claude-boundary-attest"
BOUNDARY_STDOUT="$BOUNDARY_BUILD_ROOT/probe.stdout"
BOUNDARY_STDERR="$BOUNDARY_BUILD_ROOT/probe.stderr"

/usr/bin/cc \
  -std=c11 \
  -O2 \
  -Wall \
  -Wextra \
  -Werror \
  -pedantic \
  -static \
  -s \
  -o "$BOUNDARY_HELPER_BUILD" \
  "$BOUNDARY_SOURCE"

if ! /usr/bin/file --brief "$BOUNDARY_HELPER_BUILD" | /usr/bin/grep -q 'ELF.*statically linked'; then
  echo "managed Claude helper is not a static ELF" >&2
  exit 1
fi
if /usr/bin/readelf -l "$BOUNDARY_HELPER_BUILD" | /usr/bin/grep -q 'INTERP'; then
  echo "managed Claude helper unexpectedly has a dynamic interpreter" >&2
  exit 1
fi

set +e
/usr/bin/env -i \
  CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1 \
  "$BOUNDARY_HELPER_BUILD" \
  >"$BOUNDARY_STDOUT" \
  2>"$BOUNDARY_STDERR" <<'JSON'
{"hook_event_name":"SessionStart","source":"startup","cwd":"/runtime/critic-cwd"}
JSON
BOUNDARY_SUCCESS_STATUS=$?
set -e
if [ "$BOUNDARY_SUCCESS_STATUS" -ne 2 ] || [ -s "$BOUNDARY_STDOUT" ] || \
  [ "$(/usr/bin/python3.14 -c 'import pathlib,sys; sys.stdout.write(pathlib.Path(sys.argv[1]).read_text("ascii"))' "$BOUNDARY_STDERR")" != "$BOUNDARY_MARKER" ]; then
  echo "managed Claude helper clean-environment probe failed" >&2
  exit 1
fi

set +e
/usr/bin/env -i \
  CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1 \
  CLAUDE_CODE_OAUTH_TOKEN=must-not-cross \
  "$BOUNDARY_HELPER_BUILD" \
  >"$BOUNDARY_STDOUT" \
  2>"$BOUNDARY_STDERR" <<'JSON'
{"hook_event_name":"SessionStart","source":"startup","cwd":"/runtime/critic-cwd"}
JSON
BOUNDARY_FAILURE_STATUS=$?
set -e
if [ "$BOUNDARY_FAILURE_STATUS" -ne 3 ] || [ -s "$BOUNDARY_STDOUT" ] || [ -s "$BOUNDARY_STDERR" ]; then
  echo "managed Claude helper credential-rejection probe failed" >&2
  exit 1
fi

/usr/bin/env -i \
  PATH=/usr/bin:/bin \
  LANG=C.UTF-8 \
  PYTHONPATH="$BOUNDARY_RUNTIME_ROOT" \
  BOUNDARY_RUNTIME_ROOT="$BOUNDARY_RUNTIME_ROOT" \
  BOUNDARY_POLICY="$BOUNDARY_POLICY" \
  /usr/bin/python3.14 -P -S - <<'PY'
import json
import os
from pathlib import Path

import agent_loop.claude_managed_policy as managed_policy


runtime_root = Path(os.environ["BOUNDARY_RUNTIME_ROOT"])
expected_module = (runtime_root / "agent_loop" / "claude_managed_policy.py").resolve(
    strict=True
)
observed_module = Path(managed_policy.__file__).resolve(strict=True)
if observed_module != expected_module:
    raise SystemExit("managed Claude policy module came from an unexpected runtime")


def _closed(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON property")
        result[key] = value
    return result


path = Path(os.environ["BOUNDARY_POLICY"])
with path.open("r", encoding="utf-8") as stream:
    observed = json.load(stream, object_pairs_hook=lambda pairs: _closed(pairs))
if observed != managed_policy.managed_claude_policy_document():
    raise SystemExit("managed-settings.json differs from the operational policy document")
PY

if [ "${1:-}" = "--check" ]; then
  echo "managed Claude boundary inputs and static helper passed offline checks"
  exit 0
fi

if [ -e "$BOUNDARY_POLICY_DIR" ] || [ -L "$BOUNDARY_POLICY_DIR" ]; then
  echo "refusing to replace existing $BOUNDARY_POLICY_DIR" >&2
  exit 1
fi
if [ -e "$BOUNDARY_HELPER_TARGET" ] || [ -L "$BOUNDARY_HELPER_TARGET" ]; then
  echo "refusing to replace existing $BOUNDARY_HELPER_TARGET" >&2
  exit 1
fi

echo "Administrator authentication is required to install two fixed root-owned assets."
/usr/bin/sudo -v

if /usr/bin/sudo /usr/bin/test -e "$BOUNDARY_POLICY_DIR" || \
  /usr/bin/sudo /usr/bin/test -L "$BOUNDARY_POLICY_DIR" || \
  /usr/bin/sudo /usr/bin/test -e "$BOUNDARY_HELPER_TARGET" || \
  /usr/bin/sudo /usr/bin/test -L "$BOUNDARY_HELPER_TARGET"; then
  echo "a managed Claude target appeared during authorization; refusing installation" >&2
  exit 1
fi

# `/usr/local/libexec` is a shared administrator directory.  Never normalize an
# existing directory with `install -d`: doing so would silently chmod/chown
# state owned by other software.  Walk the fixed ancestry by descriptor,
# require the exact safe metadata production accepts, and create only the
# missing final directory.  `mkdirat` is atomic; an appearance race is reopened
# and subjected to the same checks rather than overwritten.
/usr/bin/sudo /usr/bin/env -i \
  PATH=/usr/bin:/bin \
  LANG=C.UTF-8 \
  /usr/bin/python3.14 - "$BOUNDARY_HELPER_DIR" <<'PY'
import errno
import os
import stat
import sys


target = sys.argv[1]
if target != "/usr/local/libexec":
    raise SystemExit("refusing an unexpected managed-helper directory")


def verify_directory(descriptor: int, *, final: bool) -> None:
    info = os.fstat(descriptor)
    expected_modes = {0o755} if final else {0o555, 0o755}
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or info.st_gid != 0
        or stat.S_IMODE(info.st_mode) not in expected_modes
        or info.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)
    ):
        raise SystemExit("managed-helper directory metadata is unsafe")
    try:
        attributes = os.listxattr(descriptor)
    except OSError as exc:
        raise SystemExit("managed-helper directory metadata cannot be verified") from exc
    if attributes:
        raise SystemExit("managed-helper directory has unsupported extended metadata")


flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
current = os.open("/", flags)
try:
    verify_directory(current, final=False)
    for component in ("usr", "local"):
        following = os.open(component, flags, dir_fd=current)
        try:
            verify_directory(following, final=False)
        except BaseException:
            os.close(following)
            raise
        os.close(current)
        current = following

    try:
        helper_directory = os.open("libexec", flags, dir_fd=current)
    except OSError as exc:
        if exc.errno != errno.ENOENT:
            raise SystemExit("managed-helper directory cannot be opened safely") from exc
        previous_umask = os.umask(0o022)
        try:
            try:
                os.mkdir("libexec", mode=0o755, dir_fd=current)
            except FileExistsError:
                pass
        finally:
            os.umask(previous_umask)
        os.fsync(current)
        try:
            helper_directory = os.open("libexec", flags, dir_fd=current)
        except OSError as reopen_error:
            raise SystemExit(
                "managed-helper directory cannot be reopened after creation"
            ) from reopen_error
    try:
        verify_directory(helper_directory, final=True)
    finally:
        os.close(helper_directory)
finally:
    os.close(current)
PY
/usr/bin/sudo /usr/bin/install \
  -o root -g root -m 0555 \
  "$BOUNDARY_HELPER_BUILD" \
  "$BOUNDARY_HELPER_TARGET"
/usr/bin/sudo /usr/bin/install -d -o root -g root -m 0755 "$BOUNDARY_POLICY_DIR"
/usr/bin/sudo /usr/bin/install \
  -o root -g root -m 0444 \
  "$BOUNDARY_POLICY" \
  "$BOUNDARY_POLICY_TARGET"

/usr/bin/env -i \
  PATH=/usr/bin:/bin \
  LANG=C.UTF-8 \
  PYTHONPATH="$BOUNDARY_RUNTIME_ROOT" \
  BOUNDARY_RUNTIME_ROOT="$BOUNDARY_RUNTIME_ROOT" \
  /usr/bin/python3.14 -P -S - <<'PY'
import os
from pathlib import Path

import agent_loop.claude_managed_policy as managed_policy


runtime_root = Path(os.environ["BOUNDARY_RUNTIME_ROOT"])
expected_module = (runtime_root / "agent_loop" / "claude_managed_policy.py").resolve(
    strict=True
)
observed_module = Path(managed_policy.__file__).resolve(strict=True)
if observed_module != expected_module:
    raise SystemExit("managed Claude inspector came from an unexpected runtime")

boundary = managed_policy.inspect_managed_claude_boundary()
if not boundary.policy_sha256 or not boundary.helper_sha256:
    raise SystemExit("managed Claude boundary did not produce closure witnesses")
print("managed Claude boundary installed and production inspection passed")
PY
