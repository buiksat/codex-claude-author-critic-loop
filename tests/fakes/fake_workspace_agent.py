#!/usr/bin/python3
"""Configurable no-network workspace/process fake for Phase 3 integration tests."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path


def _write(path: str, data: bytes) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)


def _wait_for(path: Path) -> None:
    deadline = time.monotonic() + 2.0
    while not path.exists():
        if time.monotonic() >= deadline:
            raise RuntimeError("fake descendant did not start")
        time.sleep(0.001)


def main() -> int:
    if len(sys.argv) != 2:
        return 64
    scenario = sys.argv[1]

    if scenario == "allowed":
        _write("src/allowed.txt", b"allowed revision\n")
    elif scenario == "protected":
        _write("AGENTS.md", b"hostile instruction mutation\n")
    elif scenario == "ignored":
        _write(".gitignore", b"ignored/**\n")
        _write("ignored/generated.txt", b"still authoritative\n")
    elif scenario == "secret-like":
        _write("secret.txt", b"fake-matrix-secret")
    elif scenario == "oversized":
        _write("oversized.bin", b"o" * 4_096)
    elif scenario == "binary":
        _write("binary.dat", b"\x00\xffbinary\x00payload")
    elif scenario == "symlink":
        os.symlink(b"../literal-target", b"link")
    elif scenario == "hard-link":
        _write("hardlink/source", b"same inode")
        os.link("hardlink/source", "hardlink/alias")
    elif scenario == "special":
        os.mkfifo("special.fifo", 0o600)
    elif scenario == "many-files":
        for index in range(10):
            _write(f"many/{index:02d}.txt", b"x")
    elif scenario == "fork":
        marker = Path("fork-child.pid")
        if os.fork() == 0:
            marker.write_text(str(os.getpid()), encoding="ascii")
            while True:
                time.sleep(1)
        _wait_for(marker)
    elif scenario == "daemon":
        marker = Path("daemon-child.pid")
        if os.fork() == 0:
            os.setsid()
            if os.fork() != 0:
                os._exit(0)
            marker.write_text(str(os.getpid()), encoding="ascii")
            while True:
                time.sleep(1)
        _wait_for(marker)
    elif scenario == "hang":
        time.sleep(60)
    elif scenario == "output-limit":
        os.write(1, b"x" * 1_000_000)
    elif scenario == "nonzero":
        print("deterministic fake failure", file=sys.stderr)
        return 7
    elif scenario in {"revision-one", "revision-one-repeat"}:
        _write("app.py", b"value = 1\n")
    elif scenario == "revision-two":
        _write("app.py", b"value = 2\n")
    else:
        return 64
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
