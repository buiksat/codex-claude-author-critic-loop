"""Fixed probe payloads used by the installed live qualification command.

These strings are production compatibility probes, not test fixtures.  Keeping
them in the wheel lets ``agent-loop qualify`` exercise the installed runtime
without importing pytest or requiring a source checkout.
"""

from __future__ import annotations

HOST_RUNTIME_PROBE = r"""
import ctypes
import errno
import json
import os
import resource
import socket
import time
from pathlib import Path


def denied_open(path):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    except OSError as exc:
        return {"denied": True, "errno": exc.errno}
    else:
        os.close(descriptor)
        return {"denied": False, "errno": 0}


def denied_list(path):
    try:
        os.listdir(path)
    except OSError as exc:
        return {"denied": True, "errno": exc.errno}
    return {"denied": False, "errno": 0}


def network(host, port, kind):
    stream = socket.socket(socket.AF_INET, kind)
    stream.settimeout(0.25)
    try:
        stream.connect((host, port))
        if kind == socket.SOCK_DGRAM:
            stream.send(b"agent-loop-qualification")
    except OSError as exc:
        return {"denied": True, "errno": exc.errno}
    finally:
        stream.close()
    return {"denied": False, "errno": 0}


parent = os.getppid()
libc = ctypes.CDLL(None, use_errno=True)
ctypes.set_errno(0)
ptrace_result = libc.ptrace(16, parent, None, None)
ptrace = {"denied": ptrace_result != 0, "errno": ctypes.get_errno()}
if ptrace_result == 0:
    libc.ptrace(17, parent, None, None)

child = os.fork()
if child == 0:
    os.setsid()
    time.sleep(120)
    os._exit(0)

report = {
    "network": {
        "public_tcp": network("1.1.1.1", 443, socket.SOCK_STREAM),
        "private_tcp": network("10.0.0.1", 9, socket.SOCK_STREAM),
        "loopback_tcp": network("127.0.0.1", 9, socket.SOCK_STREAM),
        "public_udp": network("1.1.1.1", 53, socket.SOCK_DGRAM),
    },
    "process": {
        "environ": denied_open(f"/proc/{parent}/environ"),
        "fd": denied_list(f"/proc/{parent}/fd"),
        "mem": denied_open(f"/proc/{parent}/mem"),
        "ptrace": ptrace,
    },
    "limits": {
        "nofile": list(resource.getrlimit(resource.RLIMIT_NOFILE)),
        "fsize": list(resource.getrlimit(resource.RLIMIT_FSIZE)),
        "core": list(resource.getrlimit(resource.RLIMIT_CORE)),
    },
    "sensitive_environment": sorted(
        key for key in os.environ
        if any(word in key.upper() for word in ("TOKEN", "API_KEY", "CREDENTIAL", "AUTH"))
    ),
    "git_present": Path("/workspace/.git").exists(),
}
Path("/workspace/qualification-host.json").write_text(
    json.dumps(report, sort_keys=True), encoding="utf-8"
)
"""


AUTHOR_PROBE = r"""
from __future__ import annotations

import ctypes
import json
import os
import socket
import stat
import subprocess
import sys
from pathlib import Path

phase = sys.argv[1]


def write_probe(path: str) -> dict[str, object]:
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc:
        return {"allowed": False, "errno": exc.errno}
    os.close(descriptor)
    try:
        os.unlink(path)
    except OSError:
        pass
    return {"allowed": True, "errno": 0}


def read_probe(path: str) -> dict[str, object]:
    try:
        with open(path, "rb") as stream:
            stream.read(1)
    except OSError as exc:
        return {"allowed": False, "errno": exc.errno}
    return {"allowed": True, "errno": 0}


def list_probe(path: str) -> dict[str, object]:
    try:
        os.listdir(path)
    except OSError as exc:
        return {"allowed": False, "errno": exc.errno}
    return {"allowed": True, "errno": 0}


def git_guard_probe() -> dict[str, object]:
    # Describe Codex's inert synthetic .git guard, not source metadata.
    path = "/workspace/.git"
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        return {"present": False, "errno": exc.errno}
    try:
        entries: list[str] | None = sorted(os.listdir(path))
        list_errno = 0
    except OSError as exc:
        entries = None
        list_errno = exc.errno
    mounts = []
    try:
        with open("/proc/self/mountinfo", encoding="ascii") as stream:
            for line in stream:
                left, separator, right = line.partition(" - ")
                left_fields = left.split()
                right_fields = right.split()
                if (
                    separator
                    and len(left_fields) >= 6
                    and len(right_fields) >= 3
                    and left_fields[4] == path
                ):
                    mounts.append(
                        {
                            "filesystem": right_fields[0],
                            "mount_options": left_fields[5].split(","),
                            "super_options": right_fields[2].split(","),
                        }
                    )
    except OSError:
        mounts = []
    try:
        git_result = subprocess.run(
            ["/usr/bin/git", "-C", "/workspace", "rev-parse", "--git-dir"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=2,
        )
        git_returncode = git_result.returncode
        git_recognized = git_result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        git_returncode = None
        git_recognized = None
    return {
        "present": True,
        "directory": stat.S_ISDIR(metadata.st_mode),
        "symlink": stat.S_ISLNK(metadata.st_mode),
        "mode": stat.S_IMODE(metadata.st_mode),
        "entries": entries,
        "list_errno": list_errno,
        "mounts": mounts,
        "git_recognized": git_recognized,
        "git_returncode": git_returncode,
        "head_read": read_probe(f"{path}/HEAD"),
        "write": write_probe(f"{path}/agent-loop-qualification-probe"),
    }


def parent_pid(pid: int) -> tuple[int | None, dict[str, object] | None]:
    if pid == 1:
        return 0, None
    entry = procfs_processes.get(pid) if procfs_processes is not None else None
    if entry is None:
        return None, {"pid": pid, "errno": errno.ENOENT}
    status = entry[1]
    for line in status.splitlines():
        if line.startswith("PPid:"):
            procfs_parent = line.split(":", 1)[1].strip()
            if procfs_parent == "0":
                return 0, None
            namespace_parent = procfs_label_to_namespace_pid.get(procfs_parent)
            if namespace_parent is None:
                return None, {"pid": pid, "errno": errno.ENOENT}
            return namespace_parent, None
    return None, {"pid": pid, "errno": 0}


def process_name(pid: int) -> str:
    entry = procfs_processes.get(pid) if procfs_processes is not None else None
    if entry is None:
        return "unavailable"
    try:
        return Path(f"/proc/{entry[0]}/comm").read_text(encoding="ascii").strip()
    except OSError:
        return "unavailable"


def procfs_snapshot() -> dict[int, tuple[str, str]] | None:
    # A procfs inherited across nested PID namespaces may enumerate directory
    # entries using an ancestor namespace's PIDs even though getpid(), PPid,
    # and direct /proc/<pid> lookups use the caller's namespace. NSpid is the
    # kernel-provided mapping; its final component is the PID in the innermost
    # namespace visible to this probe. Require a stable two-sided directory
    # snapshot so an exiting process cannot silently evade attestation.

    for _attempt in range(3):
        try:
            before = sorted(
                name for name in os.listdir("/proc") if name.isascii() and name.isdigit()
            )
        except OSError:
            return None
        mapped = {}
        retry = False
        for name in before:
            try:
                status = Path(f"/proc/{name}/status").read_text(encoding="ascii")
            except FileNotFoundError:
                retry = True
                break
            except OSError:
                return None
            namespace_pid = None
            for line in status.splitlines():
                field, separator, value = line.partition(":")
                if separator and field == "NSpid":
                    components = value.split()
                    if components and all(item.isascii() and item.isdigit() for item in components):
                        namespace_pid = int(components[-1])
                    break
            if namespace_pid is None or namespace_pid <= 0:
                return None
            if namespace_pid in mapped:
                return None
            mapped[namespace_pid] = (name, status)
        if retry:
            continue
        try:
            after = sorted(
                name for name in os.listdir("/proc") if name.isascii() and name.isdigit()
            )
        except OSError:
            return None
        if before != after:
            continue
        return mapped
    return None


def procfs_label(pid: int) -> str | None:
    entry = procfs_processes.get(pid) if procfs_processes is not None else None
    return entry[0] if entry is not None else None


def procfs_status(pid: int) -> str:
    entry = procfs_processes.get(pid) if procfs_processes is not None else None
    return entry[1] if entry is not None else ""


libc = ctypes.CDLL(None, use_errno=True)


class IOVec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("length", ctypes.c_size_t)]


def sensitive_process_probes(pid: int) -> dict[str, object]:
    label = procfs_label(pid)
    probes = {
        "mem": (
            read_probe(f"/proc/{label}/mem")
            if label is not None
            else {"allowed": False, "errno": errno.ENOENT}
        )
    }
    ctypes.set_errno(0)
    result = libc.ptrace(16, pid, None, None)
    probes["ptrace"] = {"allowed": result == 0, "errno": ctypes.get_errno()}
    if result == 0:
        libc.ptrace(17, pid, None, None)
    local_byte = ctypes.c_char()
    local = IOVec(ctypes.addressof(local_byte), 1)
    remote = IOVec(1, 1)
    ctypes.set_errno(0)
    result = libc.process_vm_readv(pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
    probes["process_vm_readv"] = {"allowed": result >= 0, "errno": ctypes.get_errno()}
    try:
        pidfd = os.pidfd_open(pid)
    except OSError as exc:
        probes["pidfd_getfd"] = {"allowed": False, "errno": exc.errno}
    else:
        try:
            ctypes.set_errno(0)
            duplicate = libc.syscall(438, pidfd, 1, 0)
            probes["pidfd_getfd"] = {
                "allowed": duplicate >= 0,
                "errno": ctypes.get_errno(),
            }
            if duplicate >= 0:
                os.close(duplicate)
        finally:
            os.close(pidfd)
    return probes


def bwrap_environment_probe(pid: int) -> dict[str, object]:
    allowed_values = {
        "CODEX_CI": {"1"},
        "CODEX_PERMISSION_PROFILE": {"agent_loop_author"},
        "CODEX_SANDBOX_NETWORK_DISABLED": {"1"},
        "COLORTERM": {""},
        "GH_PAGER": {"cat"},
        "GIT_PAGER": {"cat"},
        "HOME": {"/runtime/home"},
        "LANG": {"C.UTF-8"},
        "LC_ALL": {"C.UTF-8"},
        "LC_CTYPE": {"C.UTF-8"},
        "NO_COLOR": {"1"},
        "PAGER": {"cat"},
        "PATH": {
            "/usr/local/bin:/usr/bin:/bin",
            "/opt/agent-loop-tools/codex-package/node_modules/@openai/"
            "codex-linux-x64/vendor/x86_64-unknown-linux-musl/codex-path:"
            "/usr/local/bin:/usr/bin:/bin",
        },
        "PWD": {"/runtime/author-cwd", "/workspace"},
        "SHLVL": {"0", "1"},
        "TERM": {"dumb"},
        "TMPDIR": {"/runtime/tmp"},
        "_": {"/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/python3", "/usr/bin/sh"},
    }
    allowlisted_names = sorted((*allowed_values, "CODEX_THREAD_ID"))
    required_names = sorted(
        {
            "CODEX_CI",
            "CODEX_PERMISSION_PROFILE",
            "CODEX_SANDBOX_NETWORK_DISABLED",
            "CODEX_THREAD_ID",
            "HOME",
            "LANG",
            "PATH",
            "TMPDIR",
        }
    )
    label = procfs_label(pid)
    if label is None:
        return {
            "readable": False,
            "errno": errno.ENOENT,
            "allowlisted_names": allowlisted_names,
            "required_names": required_names,
            "matches_allowlist": False,
            "name_count": 0,
        }
    try:
        raw = Path(f"/proc/{label}/environ").read_bytes()
    except OSError as exc:
        return {
            "readable": False,
            "errno": exc.errno,
            "allowlisted_names": allowlisted_names,
            "required_names": required_names,
            "matches_allowlist": False,
            "name_count": 0,
        }
    values = {}
    well_formed = True
    for item in raw.split(b"\0"):
        if not item:
            continue
        name, separator, value = item.partition(b"=")
        try:
            decoded = name.decode("ascii")
            decoded_value = value.decode("utf-8")
        except UnicodeDecodeError:
            decoded = ""
            decoded_value = ""
            well_formed = False
        if not separator or not decoded or decoded in values:
            well_formed = False
        values[decoded] = decoded_value
    thread_id = values.get("CODEX_THREAD_ID", "")
    thread_shape_matches = (
        len(thread_id) == 36
        and tuple(index for index, character in enumerate(thread_id) if character == "-")
        == (8, 13, 18, 23)
        and all(
            character in "0123456789abcdef"
            for character in thread_id.replace("-", "")
        )
    )
    names = set(values)
    values_match = thread_shape_matches and all(
        name == "CODEX_THREAD_ID" or value in allowed_values.get(name, set())
        for name, value in values.items()
    )
    return {
        "readable": True,
        "errno": 0,
        "allowlisted_names": allowlisted_names,
        "required_names": required_names,
        "matches_allowlist": (
            well_formed
            and set(required_names) <= names <= set(allowlisted_names)
            and values_match
        ),
        "name_count": len(names),
    }


def bwrap_fd_probe(pid: int) -> dict[str, object]:
    classes = {"dev_null": 0, "eventfd": 0, "pipe": 0}
    unexpected_count = 0
    label = procfs_label(pid)
    if label is None:
        return {
            "readable": False,
            "errno": errno.ENOENT,
            "count": 0,
            "classes": classes,
            "unexpected_count": 0,
        }
    try:
        names = os.listdir(f"/proc/{label}/fd")
    except OSError as exc:
        return {
            "readable": False,
            "errno": exc.errno,
            "count": 0,
            "classes": classes,
            "unexpected_count": 0,
        }
    for name in names:
        if not name.isascii() or not name.isdigit():
            unexpected_count += 1
            continue
        descriptor = int(name)
        try:
            target = os.readlink(f"/proc/{label}/fd/{name}")
        except OSError:
            unexpected_count += 1
            continue
        if descriptor == 0 and target == "/dev/null":
            classes["dev_null"] += 1
        elif (
            descriptor in {1, 2}
            and target.startswith("pipe:[")
            and target.endswith("]")
            and target[6:-1].isdigit()
        ):
            classes["pipe"] += 1
        elif descriptor >= 3 and target == "anon_inode:[eventfd]":
            classes["eventfd"] += 1
        else:
            # Never copy an unexpected target into the retained report.
            unexpected_count += 1
    return {
        "readable": True,
        "errno": 0,
        "count": len(names),
        "classes": classes,
        "unexpected_count": unexpected_count,
    }


def link_matches(path: str, expected: str) -> dict[str, object]:
    try:
        observed = os.readlink(path)
    except OSError as exc:
        return {"matches": False, "errno": exc.errno}
    return {"matches": observed == expected, "errno": 0}


def link_matches_any(path: str, expected: tuple[str, ...]) -> dict[str, object]:
    try:
        observed = os.readlink(path)
    except OSError as exc:
        return {"matches": False, "errno": exc.errno}
    return {"matches": observed in expected, "errno": 0}


def model_shell_probe(pid: int, comm: str) -> dict[str, object]:
    executable_allowlists = {
        "bash": ("/bin/bash", "/usr/bin/bash"),
        "dash": ("/bin/dash", "/usr/bin/dash"),
        "sh": ("/bin/dash", "/bin/sh", "/usr/bin/dash", "/usr/bin/sh"),
    }
    parent, denied = parent_pid(pid)
    status = procfs_status(pid)
    label = procfs_label(pid)
    no_new_privs = None
    for line in status.splitlines():
        name, separator, value = line.partition(":")
        if separator and name == "NoNewPrivs":
            no_new_privs = 1 if value.strip() == "1" else None
    return {
        "pid": pid,
        "ppid": parent,
        "parent_lookup_denied": denied,
        "comm": comm,
        "no_new_privs": no_new_privs,
        "executable": link_matches_any(
            f"/proc/{label}/exe" if label is not None else "/proc/missing/exe",
            executable_allowlists.get(comm, ()),
        ),
        "same_pid_namespace": link_matches(
            f"/proc/{label}/ns/pid" if label is not None else "/proc/missing/ns/pid",
            os.readlink("/proc/self/ns/pid"),
        ),
    }


def bwrap_init_probe(pid: int, comm: str) -> dict[str, object]:
    parent, denied = parent_pid(pid)
    status = procfs_status(pid)
    label = procfs_label(pid)
    fields = {}
    for line in status.splitlines():
        name, separator, value = line.partition(":")
        if separator and name in {"NSpid", "NoNewPrivs"}:
            fields[name] = value.strip()
    namespace_components = fields.get("NSpid", "").split()
    namespace_pid = (
        int(namespace_components[-1])
        if namespace_components
        and all(item.isascii() and item.isdigit() for item in namespace_components)
        else None
    )
    return {
        "pid": pid,
        "ppid": parent,
        "parent_lookup_denied": denied,
        "comm": comm,
        "namespace_pid": namespace_pid,
        "no_new_privs": 1 if fields.get("NoNewPrivs") == "1" else None,
        "executable": link_matches(
            f"/proc/{label}/exe" if label is not None else "/proc/missing/exe",
            "/usr/bin/bwrap",
        ),
        "same_pid_namespace": link_matches(
            f"/proc/{label}/ns/pid" if label is not None else "/proc/missing/ns/pid",
            os.readlink("/proc/self/ns/pid"),
        ),
        "environment": bwrap_environment_probe(pid),
        "fds": bwrap_fd_probe(pid),
        "probes": sensitive_process_probes(pid),
    }


procfs_processes = procfs_snapshot()
procfs_label_to_namespace_pid = (
    {label: pid for pid, (label, _status) in procfs_processes.items()}
    if procfs_processes is not None
    else {}
)

ancestors = []
enumeration_denied = None
pid = os.getppid()
seen = set()
while pid > 0 and pid not in seen:
    seen.add(pid)
    ancestors.append({"pid": pid, "comm": process_name(pid)})
    pid, denied = parent_pid(pid)
    if denied is not None:
        enumeration_denied = denied
        break
    assert pid is not None

shell_names = {"bash", "dash", "sh"}
model_shell_chain = []
while (
    ancestors
    and len(model_shell_chain) < 4
    and ancestors[0]["comm"] in shell_names
):
    shell = ancestors.pop(0)
    model_shell_chain.append(model_shell_probe(shell["pid"], shell["comm"]))

inner_sandbox_init = None
if len(ancestors) == 1 and ancestors[0] == {"pid": 1, "comm": "bwrap"}:
    inner_sandbox_init = bwrap_init_probe(1, "bwrap")
    ancestors.clear()

visible_pids = sorted(procfs_processes) if procfs_processes is not None else None

workspace_file = Path(f"/workspace/workspace-{phase}.txt")
workspace_file.write_text("bounded workspace write succeeded\n", encoding="utf-8")

unix_path = f"/workspace/profile-{phase}.sock"
unix_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    try:
        unix_socket.bind(unix_path)
    except OSError as exc:
        unix_result = {"allowed": False, "errno": exc.errno}
    else:
        unix_result = {"allowed": True, "errno": 0}
finally:
    unix_socket.close()
    try:
        os.unlink(unix_path)
    except OSError:
        pass


def network_probe(host: str, port: int, kind: int) -> dict[str, object]:
    try:
        stream = socket.socket(socket.AF_INET, kind)
    except OSError as exc:
        # The pinned permission profile can deny socket creation itself.  A
        # denied create and a denied connect are equally valid no-network
        # evidence for the untrusted command boundary.
        return {"allowed": False, "errno": exc.errno}
    stream.settimeout(0.5)
    try:
        try:
            stream.connect((host, port))
            if kind == socket.SOCK_DGRAM:
                stream.send(b"agent-loop-network-probe")
        except OSError as exc:
            return {"allowed": False, "errno": exc.errno}
        return {"allowed": True, "errno": 0}
    finally:
        stream.close()


network = {
    "tcp_public": network_probe("1.1.1.1", 443, socket.SOCK_STREAM),
    "tcp_loopback": network_probe("127.0.0.1", 9, socket.SOCK_STREAM),
    "tcp_private": network_probe("10.0.0.1", 9, socket.SOCK_STREAM),
    "udp_public": network_probe("1.1.1.1", 53, socket.SOCK_DGRAM),
    "udp_loopback": network_probe("127.0.0.1", 9, socket.SOCK_DGRAM),
    "udp_private": network_probe("10.0.0.1", 9, socket.SOCK_DGRAM),
}
try:
    socket.getaddrinfo("example.com", 443)
except OSError as exc:
    network["dns"] = {"allowed": False, "errno": exc.errno}
else:
    network["dns"] = {"allowed": True, "errno": 0}

report = {
    "phase": phase,
    "workspace_write": {"allowed": workspace_file.is_file(), "errno": 0},
    "root_write": write_probe(f"/agent-loop-profile-{phase}"),
    "slash_tmp_write": write_probe(f"/tmp/agent-loop-profile-{phase}"),
    "runtime_tmp_write": write_probe(f"/runtime/tmp/agent-loop-profile-{phase}"),
    "artifacts_write": write_probe(f"/runtime/artifacts/agent-loop-profile-{phase}"),
    "control_read": read_probe("/control/codex-home/auth.json"),
    "unix_socket": unix_result,
    "network": network,
    "protected_reads": {
        "AGENTS.md": read_probe("/workspace/AGENTS.md"),
        "AGENTS.override.md": read_probe("/workspace/AGENTS.override.md"),
        ".codex/AGENTS.md": read_probe("/workspace/.codex/AGENTS.md"),
    },
    "sensitive_environment_keys": sorted(
        name for name in os.environ
        if any(word in name.upper() for word in ("TOKEN", "API_KEY", "CREDENTIAL", "AUTH"))
    ),
    # ``:workspace`` deliberately overlays an empty, read-only .git directory.
    # The exported SubjectManifest is checked separately for any real .git
    # entry; this report proves the in-command marker is inert.
    "git_guard": git_guard_probe(),
    "self_pid": os.getpid(),
    "self_ppid": os.getppid(),
    "visible_pids": visible_pids,
    "model_shell_chain": model_shell_chain,
    "inner_sandbox_init": inner_sandbox_init,
    "ancestry_enumeration_denied": enumeration_denied,
    "trusted_control_ancestry": [
        {
            "pid": item["pid"],
            "comm": item["comm"],
            "probes": sensitive_process_probes(item["pid"]),
        }
        for item in ancestors
    ],
}
Path(f"/workspace/profile-report-{phase}.json").write_text(
    json.dumps(report, sort_keys=True), encoding="utf-8"
)
"""


__all__ = ["AUTHOR_PROBE", "HOST_RUNTIME_PROBE"]
