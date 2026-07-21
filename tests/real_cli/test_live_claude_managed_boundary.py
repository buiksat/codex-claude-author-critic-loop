from __future__ import annotations

import time
from pathlib import Path

import pytest

from agent_loop.artifacts import ArtifactStore, ContentAddressedBlobStore
from agent_loop.claude_managed_policy import (
    MANAGED_CLAUDE_BOUNDARY_MARKER,
    MANAGED_CLAUDE_HELPER_TARGET,
    MANAGED_CLAUDE_POLICY_TARGET,
)
from agent_loop.credentials import load_claude_setup_token
from agent_loop.declassify import ValidationCriticEvidence
from agent_loop.manifests import SubjectManifest
from agent_loop.prompts import ReviewBundle, build_review_bundle
from agent_loop.runner import CriticRequest
from agent_loop.runtime_adapters import SandboxExecutor, SandboxedClaudeCriticAdapter
from agent_loop.schemas import ApprovalContext
from tests.real_cli.live_support import (
    RecordingService,
    launched_bwrap_argv,
    require_live,
    require_paid_confirmation,
    required_directory,
    required_identifier,
    required_install,
    required_managed_claude_boundary,
    required_value,
)

pytestmark = pytest.mark.real_cli


def _bundle(blobs: ContentAddressedBlobStore) -> ReviewBundle:
    subject = SubjectManifest.empty()
    return build_review_bundle(
        task="Managed Claude boundary smoke test; no source changes are present.",
        base=subject,
        subject=subject,
        semantic_changes=(),
        opaque_changes=(),
        blobs=blobs,
        validation=ValidationCriticEvidence(1, subject.fingerprint, True, ()),
        protected_patterns=(),
        opaque_patterns=(),
    )


def test_049_live_managed_claude_child_is_scrubbed_confined_and_attested(
    tmp_path: Path,
) -> None:
    require_live()
    managed_boundary = required_managed_claude_boundary()
    credential_id = required_identifier("AGENT_LOOP_CLAUDE_CREDENTIAL_ID")
    state_home = required_directory("AGENT_LOOP_STATE_HOME")
    marker = MANAGED_CLAUDE_BOUNDARY_MARKER.encode("ascii")
    require_paid_confirmation("claude")
    install = required_install("claude")
    model = required_value("AGENT_LOOP_CLAUDE_MODEL")
    effort = required_value("AGENT_LOOP_CLAUDE_EFFORT")
    token = load_claude_setup_token(credential_id, state_home=state_home)

    config_dir = tmp_path / "claude-config"
    config_dir.mkdir(mode=0o700)
    service = RecordingService()
    with ArtifactStore.create(tmp_path / "artifacts") as artifacts:
        blobs = ContentAddressedBlobStore(artifacts)
        executor = SandboxExecutor(blobs, service=service)
        adapter = SandboxedClaudeCriticAdapter(
            executor,
            token,
            install_mount=install.mount,
            executable=install.sandbox_executable,
            config_dir=config_dir,
            managed_boundary=managed_boundary,
            timeout_seconds=360,
            model=model,
            effort=effort,
        )
        turn = adapter.review(
            CriticRequest(
                1,
                _bundle(blobs),
                ApprovalContext(True, True, True),
                time.monotonic() + 420,
            )
        )

    assert turn.observed_model == model
    assert turn.observed_effort == effort
    assert service.roles == ["critic"]
    assert len(service.requests) == 1 and len(service.results) == 1
    request = service.requests[0]
    result = service.results[0]
    assert request.manifest == SubjectManifest.empty()
    assert result.candidate == SubjectManifest.empty()
    assert request.environment["CLAUDE_CODE_SUBPROCESS_ENV_SCRUB"] == "1"
    assert "CLAUDE_CODE_RETRY_WATCHDOG" not in request.environment

    raw_control_output = result.process.stdout + result.process.stderr
    if token.encode("utf-8") in raw_control_output:
        pytest.fail("dedicated Claude credential entered captured managed-control output")
    assert marker in result.process.stderr

    assert len(service.commands) == 1
    command = launched_bwrap_argv(service.commands[0])
    read_only_targets = [
        command[index + 2]
        for index, item in enumerate(command[:-2])
        if item == "--ro-bind"
    ]
    assert read_only_targets.count(MANAGED_CLAUDE_POLICY_TARGET) == 1
    assert read_only_targets.count(MANAGED_CLAUDE_HELPER_TARGET) == 1
    writable_targets = [
        command[index + 2]
        for index, item in enumerate(command[:-2])
        if item == "--bind"
    ]
    assert MANAGED_CLAUDE_POLICY_TARGET not in writable_targets
    assert MANAGED_CLAUDE_HELPER_TARGET not in writable_targets
    for boundary in (
        "--unshare-user",
        "--unshare-pid",
        "--as-pid-1",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup",
    ):
        assert boundary in command
    # The managed process is trusted control plane: it shares Claude's reviewed
    # egress, while Bubblewrap/systemd/PID cleanup still confine everything else.
    assert "--unshare-net" not in command
    assert result.cleanup.namespace_empty is True
