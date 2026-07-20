from __future__ import annotations

import json
import os
import stat
from dataclasses import replace
from pathlib import Path

import pytest

from agent_loop.capabilities import (
    CAPABILITY_RECEIPT_SCHEMA_VERSION,
    MAX_CAPABILITY_RECEIPT_VALIDITY_SECONDS,
    REQUIRED_ACCEPTANCE_GATES,
    AcceptanceGate,
    CapabilityReceiptError,
    HostCapabilityBinding,
    LiveCapabilityBinding,
    ToolCapabilityBinding,
    verify_live_capability_receipt,
    write_successful_live_capability_receipt,
)


ISSUED = 2_000_000_000


def _binding() -> LiveCapabilityBinding:
    return LiveCapabilityBinding(
        host=HostCapabilityBinding(
            os_id="ubuntu",
            os_version="26.04",
            machine="x86_64",
            kernel="6.17.0-8-generic",
            python="3.14.0",
            git="git version 2.53.0",
            systemd="systemd 259 (259.5-0ubuntu3)",
            bash="GNU bash, version 5.3.3(1)-release",
            bubblewrap_package_version="0.11.1-1ubuntu0.1",
            bubblewrap_upstream_version="0.11.1",
            bubblewrap_executable_sha256="a" * 64,
            python_executable_sha256="9" * 64,
            runtime_closure_sha256="8" * 64,
            openat2=True,
            namespace_probe=True,
            transient_service_probe=True,
        ),
        codex=ToolCapabilityBinding(
            version="codex-cli 0.144.6",
            executable_sha256="b" * 64,
            install_closure_sha256="c" * 64,
            credential_id="codex-account",
            requested_model="gpt-5.4-codex",
            requested_effort="high",
        ),
        claude=ToolCapabilityBinding(
            version="2.1.215 (Claude Code)",
            executable_sha256="d" * 64,
            credential_id="claude-account",
            requested_model="claude-opus-4-6",
            requested_effort="medium",
        ),
    )


def _write(path: Path, binding: LiveCapabilityBinding | None = None) -> None:
    write_successful_live_capability_receipt(
        path,
        _binding() if binding is None else binding,
        successful_gates=REQUIRED_ACCEPTANCE_GATES,
        issued_at_unix=ISSUED,
        valid_for_seconds=3600,
    )


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii") + b"\n"


def test_private_atomic_writer_round_trips_complete_exact_receipt(tmp_path: Path) -> None:
    path = tmp_path / "capabilities" / "live-v1.json"
    binding = _binding()

    written = write_successful_live_capability_receipt(
        path,
        binding,
        successful_gates=REQUIRED_ACCEPTANCE_GATES,
        issued_at_unix=ISSUED,
        valid_for_seconds=3600,
    )
    verified = verify_live_capability_receipt(path, binding, now_unix=ISSUED + 1)

    assert verified == written
    assert verified.schema_version == CAPABILITY_RECEIPT_SCHEMA_VERSION
    assert verified.acceptance_gates == REQUIRED_ACCEPTANCE_GATES
    assert stat.S_IMODE(os.lstat(path.parent).st_mode) == 0o700
    assert stat.S_IMODE(os.lstat(path).st_mode) == 0o600
    assert os.lstat(path).st_nlink == 1
    assert not list(path.parent.glob(".agent-loop-tmp-*"))
    encoded = json.loads(path.read_text(encoding="ascii"))
    assert encoded["tools"]["codex"]["install_closure_sha256"] == "c" * 64
    assert "install_closure_sha256" not in encoded["tools"]["claude"]


def test_private_writer_can_durably_replace_an_existing_private_receipt(
    tmp_path: Path,
) -> None:
    path = tmp_path / "capabilities" / "live-v1.json"
    _write(path)
    changed = replace(
        _binding(),
        codex=replace(_binding().codex, credential_id="renewed-codex-account"),
    )

    write_successful_live_capability_receipt(
        path,
        changed,
        successful_gates=REQUIRED_ACCEPTANCE_GATES,
        issued_at_unix=ISSUED + 100,
        valid_for_seconds=3600,
    )

    assert verify_live_capability_receipt(path, changed, now_unix=ISSUED + 101).binding == changed


@pytest.mark.parametrize(
    "successful_gates",
    [
        (),
        REQUIRED_ACCEPTANCE_GATES[:-1],
        tuple(reversed(REQUIRED_ACCEPTANCE_GATES)),
        (*REQUIRED_ACCEPTANCE_GATES, AcceptanceGate.CUSTOM_PROFILE),
    ],
)
def test_writer_refuses_partial_reordered_or_duplicate_success_claims(
    tmp_path: Path,
    successful_gates: tuple[AcceptanceGate, ...],
) -> None:
    path = tmp_path / "capabilities" / "live-v1.json"
    with pytest.raises(ValueError, match="complete ordered"):
        write_successful_live_capability_receipt(
            path,
            _binding(),
            successful_gates=successful_gates,
            issued_at_unix=ISSUED,
        )
    assert not path.exists()


def test_receipt_binds_every_security_relevant_live_selection(tmp_path: Path) -> None:
    path = tmp_path / "capabilities" / "live-v1.json"
    binding = _binding()
    _write(path, binding)
    mismatches = (
        replace(binding, host=replace(binding.host, kernel="different-kernel")),
        replace(binding, host=replace(binding.host, os_version="26.04.1")),
        replace(binding, host=replace(binding.host, runtime_closure_sha256="7" * 64)),
        replace(binding, codex=replace(binding.codex, version="codex-cli 0.144.7")),
        replace(binding, codex=replace(binding.codex, executable_sha256="e" * 64)),
        replace(binding, codex=replace(binding.codex, install_closure_sha256="f" * 64)),
        replace(binding, codex=replace(binding.codex, credential_id="other-codex")),
        replace(binding, codex=replace(binding.codex, requested_model="gpt-other")),
        replace(binding, codex=replace(binding.codex, requested_effort="medium")),
        replace(binding, claude=replace(binding.claude, version="2.1.216 (Claude Code)")),
        replace(binding, claude=replace(binding.claude, executable_sha256="1" * 64)),
        replace(binding, claude=replace(binding.claude, install_closure_sha256="2" * 64)),
        replace(binding, claude=replace(binding.claude, credential_id="other-claude")),
        replace(binding, claude=replace(binding.claude, requested_model="claude-other")),
        replace(binding, claude=replace(binding.claude, requested_effort="high")),
    )

    for mismatch in mismatches:
        with pytest.raises(CapabilityReceiptError, match="exact binding"):
            verify_live_capability_receipt(path, mismatch, now_unix=ISSUED + 1)


def test_receipt_rejects_future_expired_and_too_old_claims(tmp_path: Path) -> None:
    path = tmp_path / "capabilities" / "live-v1.json"
    binding = _binding()
    _write(path, binding)

    with pytest.raises(CapabilityReceiptError, match="future"):
        verify_live_capability_receipt(path, binding, now_unix=ISSUED - 1)
    with pytest.raises(CapabilityReceiptError, match="stale"):
        verify_live_capability_receipt(path, binding, now_unix=ISSUED + 3600)
    with pytest.raises(CapabilityReceiptError, match="stale"):
        verify_live_capability_receipt(
            path,
            binding,
            now_unix=ISSUED + 11,
            max_age_seconds=10,
        )


@pytest.mark.parametrize("invalid_lifetime", [0, -1, True, 1.5, 604_801])
def test_writer_rejects_invalid_or_overlong_lifetime(
    tmp_path: Path,
    invalid_lifetime: object,
) -> None:
    with pytest.raises(ValueError, match="valid_for_seconds"):
        write_successful_live_capability_receipt(
            tmp_path / "capabilities" / "live-v1.json",
            _binding(),
            successful_gates=REQUIRED_ACCEPTANCE_GATES,
            issued_at_unix=ISSUED,
            valid_for_seconds=invalid_lifetime,  # type: ignore[arg-type]
        )


def test_unknown_missing_duplicate_and_noncanonical_json_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "capabilities" / "live-v1.json"
    binding = _binding()
    _write(path, binding)
    valid = json.loads(path.read_bytes())

    mutations: list[bytes] = []
    unknown_top = dict(valid)
    unknown_top["unknown"] = True
    mutations.append(_canonical_json(unknown_top))

    unknown_nested = json.loads(json.dumps(valid))
    unknown_nested["tools"]["codex"]["ambient_config"] = "allowed"
    mutations.append(_canonical_json(unknown_nested))

    missing_nested = json.loads(json.dumps(valid))
    del missing_nested["host"]["kernel"]
    mutations.append(_canonical_json(missing_nested))

    wrong_schema = dict(valid)
    wrong_schema["schema_version"] = CAPABILITY_RECEIPT_SCHEMA_VERSION + 1
    mutations.append(_canonical_json(wrong_schema))

    missing_gate = dict(valid)
    missing_gate["acceptance_gates"] = missing_gate["acceptance_gates"][:-1]
    mutations.append(_canonical_json(missing_gate))

    unknown_gate = dict(valid)
    unknown_gate["acceptance_gates"] = [*unknown_gate["acceptance_gates"], "99-unknown"]
    mutations.append(_canonical_json(unknown_gate))

    canonical = _canonical_json(valid)
    mutations.append(
        canonical.replace(
            b'"schema_version":1',
            b'"schema_version":1,"schema_version":1',
        )
    )
    mutations.append(json.dumps(valid, indent=2, sort_keys=True).encode("ascii") + b"\n")

    for mutation in mutations:
        path.write_bytes(mutation)
        with pytest.raises(CapabilityReceiptError):
            verify_live_capability_receipt(path, binding, now_unix=ISSUED + 1)


def test_verifier_rejects_permissive_file_and_directory_modes(tmp_path: Path) -> None:
    path = tmp_path / "capabilities" / "live-v1.json"
    binding = _binding()
    _write(path, binding)

    path.chmod(0o640)
    with pytest.raises(CapabilityReceiptError, match="private single-link"):
        verify_live_capability_receipt(path, binding, now_unix=ISSUED + 1)

    path.chmod(0o600)
    path.parent.chmod(0o750)
    with pytest.raises(CapabilityReceiptError, match="directory is not private"):
        verify_live_capability_receipt(path, binding, now_unix=ISSUED + 1)


def test_verifier_rejects_symlinks_and_hard_links(tmp_path: Path) -> None:
    path = tmp_path / "capabilities" / "live-v1.json"
    binding = _binding()
    _write(path, binding)

    link = path.parent / "linked.json"
    link.symlink_to(path.name)
    with pytest.raises(CapabilityReceiptError, match="private single-link"):
        verify_live_capability_receipt(link, binding, now_unix=ISSUED + 1)

    link.unlink()
    os.link(path, link)
    with pytest.raises(CapabilityReceiptError, match="private single-link"):
        verify_live_capability_receipt(path, binding, now_unix=ISSUED + 1)


def test_intermediate_directory_symlink_is_never_followed(tmp_path: Path) -> None:
    real = tmp_path / "real"
    path = real / "live-v1.json"
    binding = _binding()
    _write(path, binding)
    redirect = tmp_path / "redirect"
    redirect.symlink_to(real, target_is_directory=True)

    with pytest.raises(CapabilityReceiptError, match="without symlinks"):
        verify_live_capability_receipt(
            redirect / "live-v1.json",
            binding,
            now_unix=ISSUED + 1,
        )


def test_writer_rejects_existing_symlink_without_touching_its_target(tmp_path: Path) -> None:
    directory = tmp_path / "capabilities"
    directory.mkdir(mode=0o700)
    target = directory / "target"
    target.write_bytes(b"do not replace")
    target.chmod(0o600)
    receipt_path = directory / "live-v1.json"
    receipt_path.symlink_to(target.name)

    with pytest.raises(CapabilityReceiptError, match="existing.*private regular"):
        _write(receipt_path)

    assert target.read_bytes() == b"do not replace"
    assert receipt_path.is_symlink()


def test_writer_rejects_existing_permissive_or_hard_linked_file(tmp_path: Path) -> None:
    directory = tmp_path / "capabilities"
    directory.mkdir(mode=0o700)
    receipt_path = directory / "live-v1.json"
    receipt_path.write_bytes(b"old")
    receipt_path.chmod(0o644)

    with pytest.raises(CapabilityReceiptError, match="existing.*private regular"):
        _write(receipt_path)

    receipt_path.chmod(0o600)
    os.link(receipt_path, directory / "second-link")
    with pytest.raises(CapabilityReceiptError, match="existing.*private regular"):
        _write(receipt_path)


@pytest.mark.parametrize(
    "path",
    ["relative/receipt.json", "/tmp/../tmp/receipt.json", "/receipt.json"],
)
def test_receipt_paths_must_be_normalized_absolute_and_privately_nested(path: str) -> None:
    with pytest.raises(ValueError):
        verify_live_capability_receipt(path, _binding(), now_unix=ISSUED)


def test_constructor_rejects_unproven_host_probe_flags_and_unsafe_hashes() -> None:
    host = _binding().host
    with pytest.raises(CapabilityReceiptError, match="must be true"):
        replace(host, namespace_probe=False)
    with pytest.raises(CapabilityReceiptError, match="SHA-256"):
        replace(_binding().codex, executable_sha256="not-a-digest")


def test_validity_ceiling_is_explicitly_short_lived() -> None:
    assert MAX_CAPABILITY_RECEIPT_VALIDITY_SECONDS == 7 * 24 * 60 * 60
