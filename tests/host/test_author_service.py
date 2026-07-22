from __future__ import annotations

import os

import pytest

from agent_loop.author_service import (
    AUTHOR_SERVICE_BUILD_ID,
    AUTHOR_SERVICE_PROTOCOL,
    AUTHOR_SERVICE_SOCKET,
    inspect_fixed_author_service,
)
from agent_loop.service import run_bounded_process


@pytest.mark.host
def test_076_fixed_author_manager_is_root_owned_bound_and_live() -> None:
    if os.environ.get("AGENT_LOOP_ALLOW_LIVE") != "1":
        pytest.skip("fixed author-manager qualification is part of the opt-in live gate")

    unauthorized = run_bounded_process(
        (
            "/usr/bin/systemd-run",
            "--no-ask-password",
            "--wait",
            "--collect",
            "--quiet",
            "--service-type=exec",
            f"--unit=agent-loop-unauthorized-{os.getpid()}.service",
            "/usr/bin/true",
        ),
        timeout_seconds=10,
        output_max_bytes=64 * 1024,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
    )
    assert unauthorized.returncode != 0
    assert not unauthorized.timed_out and not unauthorized.output_limited

    provenance = inspect_fixed_author_service(probe=True)
    assert provenance.protocol == AUTHOR_SERVICE_PROTOCOL
    assert provenance.build_id == AUTHOR_SERVICE_BUILD_ID
    assert provenance.authorized_uid == os.geteuid() > 0
    assert provenance.socket_path == AUTHOR_SERVICE_SOCKET
    assert provenance.socket_owner_uid == os.geteuid()
    assert provenance.socket_mode == 0o600
    assert provenance.broker_probe
    for digest in (
        provenance.socket_unit_sha256,
        provenance.broker_unit_sha256,
        provenance.socket_dropin_sha256,
        provenance.config_sha256,
        provenance.install_record_sha256,
        provenance.runtime_closure_sha256,
        provenance.wheel_sha256,
        provenance.codex_closure_sha256,
        provenance.effective_units_sha256,
    ):
        assert len(digest) == 64
        int(digest, 16)
