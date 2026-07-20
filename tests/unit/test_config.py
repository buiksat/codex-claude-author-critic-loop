from pathlib import Path

import pytest

from agent_loop.config import load_project_config, project_config_from_mapping
from agent_loop.constants import DEFAULT_PROTECTED_PATTERNS, Limits


def test_defaults_are_conservative() -> None:
    config = project_config_from_mapping({})
    assert config.max_rounds == 3
    assert set(DEFAULT_PROTECTED_PATTERNS) <= set(config.protected_paths)
    assert config.checks == ()


def test_project_config_reader_rejects_an_intermediate_symlink(tmp_path: Path) -> None:
    actual = tmp_path / "actual"
    actual.mkdir()
    (actual / "project.toml").write_text("schema_version = 1\n", encoding="utf-8")
    (tmp_path / "linked").symlink_to(actual, target_is_directory=True)

    with pytest.raises(ValueError, match="cannot be read safely"):
        load_project_config(tmp_path / "linked" / "project.toml")


def test_configuration_can_add_but_not_remove_protection() -> None:
    config = project_config_from_mapping({"protected_paths": ["scripts/ci/**"]})
    assert "scripts/ci/**" in config.protected_paths
    assert ".codex/**" in config.protected_paths


def test_unknown_keys_and_unsafe_patterns_fail_closed() -> None:
    with pytest.raises(ValueError, match="unknown"):
        project_config_from_mapping({"network": True})
    with pytest.raises(ValueError, match="relative"):
        project_config_from_mapping({"discard_only_paths": ["/tmp/cache"]})
    with pytest.raises(ValueError, match="ambiguous"):
        project_config_from_mapping({"discard_only_paths": ["build/../secret"]})


def test_protected_opt_ins_are_exact_non_git_paths_and_opaque_assertions_are_recorded() -> None:
    config = project_config_from_mapping(
        {
            "protected_opt_in_paths": ["AGENTS.md"],
            "opaque_nonsemantic_paths": ["generated/attestation.json"],
        }
    )
    assert config.protected_opt_in_paths == ("AGENTS.md",)
    assert config.opaque_nonsemantic_paths == ("generated/attestation.json",)
    with pytest.raises(ValueError, match="exact paths"):
        project_config_from_mapping({"protected_opt_in_paths": ["**/AGENTS.md"]})
    with pytest.raises(ValueError, match="Git control"):
        project_config_from_mapping({"protected_opt_in_paths": [".git/config"]})
    with pytest.raises(ValueError, match="Git control"):
        project_config_from_mapping({"protected_opt_in_paths": ["nested/.git"]})


def test_configuration_path_collections_and_patterns_are_strictly_bounded() -> None:
    with pytest.raises(ValueError, match="item-count bound"):
        project_config_from_mapping(
            {"opaque_nonsemantic_paths": [f"metadata/{index}" for index in range(257)]}
        )
    with pytest.raises(ValueError, match="path-pattern bound"):
        project_config_from_mapping({"discard_only_paths": ["x" * 4_097]})
    with pytest.raises(ValueError, match="path-pattern bound"):
        project_config_from_mapping(
            {"review_context_paths": ["/".join("x" for _ in range(129))]}
        )


def test_limits_may_only_tighten_defaults() -> None:
    config = project_config_from_mapping({"limits": {"max_files": 10}})
    assert config.limits.max_files == 10
    with pytest.raises(ValueError, match="tighten"):
        project_config_from_mapping({"limits": {"max_files": Limits().max_files + 1}})
    with pytest.raises(ValueError, match="tighten"):
        project_config_from_mapping(
            {"limits": {"reserved_output_tokens": Limits().reserved_output_tokens - 1}}
        )


def test_larger_output_reserve_requires_a_matching_tighter_input_ceiling() -> None:
    defaults = Limits()
    config = project_config_from_mapping(
        {
            "limits": {
                "max_estimated_input_tokens": defaults.max_estimated_input_tokens - 1,
                "reserved_output_tokens": defaults.reserved_output_tokens + 1,
            }
        }
    )
    assert config.limits.reserved_output_tokens == defaults.reserved_output_tokens + 1
    with pytest.raises(ValueError, match="context budget"):
        project_config_from_mapping(
            {"limits": {"reserved_output_tokens": defaults.reserved_output_tokens + 1}}
        )


def test_credential_identifiers_are_not_paths() -> None:
    with pytest.raises(ValueError, match="safe identifier"):
        project_config_from_mapping({"codex_credential_id": "../default"})


@pytest.mark.parametrize("mount", ["/", "//host/share", "/opt/../etc", "/opt/tools/"])
def test_toolchain_mounts_cannot_name_broad_or_noncanonical_roots(mount: str) -> None:
    with pytest.raises(ValueError, match="normalized absolute"):
        project_config_from_mapping({"read_only_toolchain_mounts": [mount]})
