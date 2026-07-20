# plan-v1.0 implementation status

This document is implementation evidence for the frozen `PLAN.md`; it does not replace or amend
that specification. A status is `passed` only after executable coverage for every claimed clause
ran successfully. `partial; live blocked` means deterministic coverage passed but a pinned-CLI
behavioral clause remains unproved. A skip, xfail, simulation, or partial probe is never counted as
completion.

The post-audit collection contains 542 tests. The portable matrix passed 516 tests with 26
host/real-CLI tests deselected; the host-marked matrix passed 22 tests; and the complete non-real-CLI
matrix passed 538 tests with four real-CLI tests deselected. Two separately selected non-model Codex
CLI probes passed. The credentialed Codex author and Claude critic nodes were not run. These counts
do not turn the partial or blocked contracts below into passed contracts.

## Detected environment

| Component | Detected | Frozen target | Result |
|---|---|---|---|
| OS | Ubuntu 26.04 LTS (Resolute), x86_64 | Ubuntu 26.04, x86_64 | compatible |
| Kernel | Linux 7.0.0-28-generic | reviewed Ubuntu 26.04 kernel | compatible; probes passed |
| Python | CPython 3.14.4 | CPython 3.14.4 | compatible |
| Git | 2.53.0 | 2.53.0 | compatible |
| Bash | 5.3.x | 5.3.x | compatible |
| Bubblewrap | upstream 0.11.1; package `0.11.1-1ubuntu0.1`; `/usr/bin/bwrap`, root:root, mode `0755`, SHA-256 `0abea81db798ebf6b4742ac0664802d97521547a353c2a0dbdc21d76cbbfd2c0` | exact patched non-setuid build | compatible; provenance and negative probes passed |
| systemd user manager | systemd 259; user manager running | transient user services on 259 | compatible; lifecycle/resource probes passed |
| Codex CLI | 0.144.6 | 0.144.6 | version/help and non-model prompt-input probes passed; paid first/resume probe blocked |
| Claude Code | 2.1.215 | 2.1.215 | executable preflight compatible; managed paid critic probe blocked |
| Namespace/runtime | user/PID/IPC/UTS/network namespaces, full tmpfs, PID 1 supervisor | required | target-host suite passed |

The repository was clean at implementation start. `PLAN.md` remains the `plan-v1.0` content at
`6b16d5601b1aad7689d18cbd3802c9244c68444f`, with SHA-256
`bebccf00360b38e4285f7d06bbaa1e5a3af5c4e0d692b183d1f6a905c67825eb`; it was not edited. No
credential store or ambient CLI home was inspected, and no paid/live model call, installer, fetch,
commit, push, PR, publication, or remote mutation was performed.

## Phase checklist

- [ ] Phase 1: canonical subject runtime — manifest, confined filesystem, hardened Git reader,
  policy, Git-less materialization, and diagnostic projection pass their pytest coverage. The phase
  is not declared complete because the required Ruff and strict-mypy gates could not run on this
  host.
- [ ] Phase 2: containment prototype — the sole Bubblewrap plus transient-systemd backend passes all
  22 `host`-marked tests, including resource stress, process isolation, network denial, and cleanup.
  The phase is not declared complete because the required formatting/lint/type gates could not run.
- [ ] Phase 3: fake agents and deterministic control plane — configurable executable fakes cover
  the required mutation/process families, credential refresh and mid-refresh crash, Claude
  verdict/protocol/retry families, delayed completion, successful final-round revision, and exact
  repeat/stall behavior. Fine-grained schema cases are additionally enforced compositionally by the
  local total parser/schema tests. The phase is not declared complete because the required Ruff and
  strict-mypy gates could not run.
- [ ] Phase 4: pinned real-CLI integration — both adapters, exact argv/config parsing, non-model
  Codex probes, and receipt gate are implemented; acceptance 8/33/49/65/66 still requires the two
  explicitly authorized paid smoke-test nodes in one combined host/live pytest session.
- [ ] Phase 5: serial loop and usability — `run`, `status`, and `show`, strict configuration,
  confirmation, artifacts, production receipt enforcement, and wheel metadata are covered with
  deterministic adapters. A clean wheel installation was intentionally not performed, and
  production model execution remains unavailable until Phase 4 mints its receipt.

The implementation paths are present, but `plan-v1.0` remains incomplete and unqualified under its
frozen definition of done. Static-analysis gates, live-dependent clauses, and the clean-install
acceptance step remain outstanding.

## Acceptance-test traceability

| # | Contract | Executable coverage | Status |
|---:|---|---|---|
| 1 | Canonical ignored state | `tests/integration/test_manifest_policy.py::test_001_ignored_author_output_enters_authoritative_validation_subject`, `tests/adversarial/test_filesystem.py::test_001_complete_scan_ignores_no_gitignore_entries`, and `tests/integration/test_runtime_adapters.py::test_001_ignored_runtime_configuration_changes_validation_behavior` | passed |
| 2 | Ignore-rule change | `tests/integration/test_manifest_policy.py::test_002_ignore_rule_change_cannot_hide_existing_or_new_candidate_entry` | passed |
| 3 | Discard-only output | `tests/integration/test_manifest_policy.py::test_003_discard_only_output_is_recorded_but_not_authoritative_or_next_round` | passed |
| 4 | Metadata normalization | `tests/adversarial/test_filesystem.py::test_004_materialization_normalizes_modes_timestamps_and_directories` plus all `test_004_export_rejects_*` cases | passed |
| 5 | Private Git-derived tree | `tests/integration/test_git_source.py::test_005_006_040_private_git_derived_manifest_and_source_immutability` | passed |
| 6 | No staging/raw Git | `tests/integration/test_sandbox_init.py::test_006_git_staging_and_history_fail_in_gitless_materialization` (both `git add` and `git log`) plus `tests/integration/test_git_source.py::test_005_006_040_private_git_derived_manifest_and_source_immutability` | passed |
| 7 | Protected instructions | `tests/integration/test_manifest_policy.py` (`test_007_*`) and `tests/integration/test_codex_client.py::test_007_explicit_instruction_opt_in_relaxes_only_profile_prevention_layer` | passed |
| 8 | Network split | `tests/host/test_network_boundary.py::test_008_network_split_for_no_network_role` plus the two live Codex/Claude nodes below | blocked |
| 9 | Full-tmpfs export | `tests/host/test_sandbox.py` (`test_009_*`) and `tests/integration/test_sandbox_init.py::test_009_materialize_run_cleanup_then_complete_export` | passed |
| 10 | Tmpfs/resource bounds | all eight `test_010_*` cases in `tests/host/test_limits.py` | passed |
| 11 | Patched Bubblewrap | `tests/host/test_platform.py::test_011_patched_bubblewrap` and `tests/unit/test_sandbox.py::test_011_bubblewrap_probe_rejects_setuid_unexpected_hash_and_vulnerable_revision` | passed |
| 12 | Manifest equivalence | `tests/integration/test_manifest_policy.py::test_012_every_consumer_can_bind_to_one_authoritative_fingerprint` and `tests/integration/test_runner.py::test_012_every_round_consumer_observes_one_authoritative_subject` | passed |
| 13 | Happy path | `tests/integration/test_runner.py::test_013_happy_path_uses_real_manifest_bundle_and_schema_layers` | passed |
| 14 | Revision path | `tests/integration/test_runner.py::test_014_revision_uses_exact_thread_and_only_normalized_safe_feedback` | passed |
| 15 | Fatal beats approval | `tests/integration/test_runner.py::test_015_integrity_guard_fatal_dominates_apparent_lgtm` | passed |
| 16 | Late approval | `tests/integration/test_runner.py::test_016_lgtm_completed_after_monotonic_deadline_is_timeout` | passed |
| 17 | Final-round success | `tests/integration/test_runner.py::test_017_success_on_exact_final_allowed_round_precedes_cap` | passed |
| 18 | Fatal latch | `tests/unit/test_state_machine.py::test_018_fatal_latch_is_monotonic` | passed |
| 19 | Baseline infrastructure failure | `tests/integration/test_runner.py::test_019_baseline_infrastructure_failure_stops_before_agents` | passed |
| 20 | Baseline ordinary failure | `tests/unit/test_validation.py::test_020_baseline_ordinary_failure` and `tests/integration/test_runner.py::test_020_ordinary_baseline_failure_remains_reviewable_and_nonregressing` | passed |
| 21 | Regression classification | `tests/unit/test_validation.py::test_021_regression_classification` | passed |
| 22 | Frozen validation subject | `tests/integration/test_runner.py::test_022_validation_and_critic_consume_one_frozen_authoritative_subject` | passed |
| 23 | Validation mutation | `tests/unit/test_validation.py::test_023_validation_mutation` and `tests/integration/test_runtime_adapters.py::test_validation_authoritative_mutation_is_visible_to_upstream_policy` | passed |
| 24 | Allowed validation output | `tests/unit/test_validation.py::test_024_allowed_validation_output` and `tests/integration/test_runtime_adapters.py::test_validation_runs_fixed_checks_sequentially_in_one_fresh_tmpfs` | passed |
| 25 | Protected harness | `tests/integration/test_manifest_policy.py` (`test_025_*`) | passed |
| 26 | Test failure feedback | `tests/integration/test_declassify.py::test_026_test_failure_feedback` plus `tests/integration/test_runner.py::test_014_revision_uses_exact_thread_and_only_normalized_safe_feedback` | passed |
| 27 | Blocked review | `tests/integration/test_runner.py::test_027_blocked_review_stops_without_another_author_turn` | passed |
| 28 | Failed-validation incoherence | `tests/integration/test_runner.py::test_028_lgtm_with_failed_validation_is_rejected_by_real_semantics` | passed |
| 29 | Descendant cleanup | both `test_029_*` cases in `tests/host/test_service_cleanup.py` and `tests/integration/test_sandbox_init.py::test_029_setsid_descendant_is_killed_and_reaped_before_export` | passed |
| 30 | Process introspection | all four `test_030_*` cases in `tests/host/test_process_isolation.py` | passed |
| 31 | Sanitized Codex home | all `test_031_*` cases in `tests/integration/test_codex_client.py` | passed |
| 32 | Codex auth isolation | all `test_032_*` cases in `tests/integration/test_credentials.py`; the generated-command read/environment clause is also asserted by the unrun live `test_033_065_066_*` node | partial; live blocked |
| 33 | Custom profile | `tests/real_cli/test_live_codex_acceptance.py::test_033_065_066_live_profile_gitless_exact_resume_and_marker_isolation` | blocked |
| 34 | Explicit session routing | both `test_034_*` cases in `tests/integration/test_codex_client.py` | passed |
| 35 | No interrupted resume | `tests/integration/test_runner.py::test_035_interruption_preserves_finish_evidence_and_new_run_starts_fresh` | passed |
| 36 | Credential crash recovery | all `test_036_*` cases in `tests/integration/test_credentials.py` | passed |
| 37 | Hostile Git environment | `tests/integration/test_git_source.py::test_037_038_hostile_git_environment_and_config_never_execute` | passed |
| 38 | Hostile Git config | `tests/integration/test_git_source.py::test_037_038_hostile_git_environment_and_config_never_execute` and `tests/unit/test_git_source.py::test_038_only_fixed_read_only_git_commands_are_admitted` | passed |
| 39 | Repository shapes | all `test_039_*` cases in `tests/integration/test_git_source.py` and `tests/unit/test_git_source.py` | passed |
| 40 | Git immutability | all `test_040_*` cases in `tests/integration/test_git_source.py`, including root-swap and source-mutation races | passed |
| 41 | Delta coverage | `tests/unit/test_manifests.py::test_041_delta_covers_create_delete_modify_rename_binary_mode_symlink_and_ignored` and `tests/unit/test_manifests.py::test_041_rename_pairing_is_deterministic_with_duplicate_content` | passed |
| 42 | Final-component symlink | `tests/adversarial/test_filesystem.py::test_042_symlink_capture_records_only_literal_target` | passed |
| 43 | Intermediate race | both `test_043_*` cases in `tests/adversarial/test_openat2.py` | passed |
| 44 | Magic-link escape | `tests/adversarial/test_openat2.py::test_044_proc_magic_link_is_rejected` | passed |
| 45 | Hard-link escape | `tests/adversarial/test_filesystem.py::test_045_hard_link_is_rejected_before_content_capture` | passed |
| 46 | Special files | all `test_046_*` cases in `tests/adversarial/test_filesystem.py` | passed |
| 47 | Arbitrary path bytes | `tests/unit/test_manifests.py::test_047_arbitrary_path_bytes_round_trip_losslessly` and all `test_047_*` cases in `tests/adversarial/test_openat2.py` | passed |
| 48 | Critic isolation | `tests/integration/test_claude_client.py::test_048_critic_invocation_is_tool_disabled_and_fresh` and `tests/integration/test_runtime_adapters.py::test_048_claude_adapter_uses_empty_subject_bundle_stdin_and_dedicated_mounts` | passed |
| 49 | Managed Claude boundary | `tests/real_cli/test_live_claude_managed_boundary.py::test_049_live_managed_claude_child_is_scrubbed_confined_and_attested` | blocked |
| 50 | Hostile Claude project config | `tests/integration/test_claude_client.py::test_050_hostile_claude_project_config_is_not_in_environment_or_cwd` | passed |
| 51 | Retry budget | all `test_051_*` cases in `tests/integration/test_claude_client.py` prove exact environment settings, bounded simulated schema retry, and typed exhaustion; pinned Claude API/schema retry behavior was not exercised | partial; live behavior unproved |
| 52 | Schema semantics | all `test_052_*` cases in `tests/unit/test_schemas.py` plus `tests/unit/test_schema_documents.py::test_packaged_critic_schema_matches_operational_schema` | passed |
| 53 | Bundle budgets | `tests/unit/test_prompts.py::test_053_bundle_budgets`, `test_053_changed_file_limit_withholds_the_complete_semantic_delta`, `test_053_findings_limit_fails_before_bundle_construction`, `test_053_task_field_limit_fails_before_bundle_construction`, and `test_053_byte_and_estimated_input_limits_are_independent` cover file, finding, field, byte, estimated-token, and output-reserve limits | passed |
| 54 | Review limitation | `tests/unit/test_prompts.py::test_054_review_limitation_recorded` and `tests/unit/test_prompts.py::test_054_configured_context_obeys_sensitive_path_rules` | passed |
| 55 | Hostile return path | `tests/adversarial/test_prompts.py::test_055_hostile_return_path` | passed |
| 56 | Validation declassification | `tests/integration/test_declassify.py::test_056_validation_declassification` and `tests/integration/test_runner.py::test_056_private_raw_validation_and_declassified_critic_artifacts_are_split` | passed |
| 57 | Exact-state stall | both `test_057_*` cases in `tests/unit/test_progress.py` and `tests/integration/test_runner.py::test_057_two_identical_normalized_non_success_states_stall` | passed |
| 58 | Round cap | `tests/integration/test_runner.py::test_058_nonconvergence_at_cap_returns_round_cap_after_second_review` | passed |
| 59 | Private state | all `test_059_*` cases in `tests/adversarial/test_artifacts.py` | passed |
| 60 | Out-of-band edit | `tests/integration/test_workflow.py::test_060_production_composition_detects_live_authoritative_tree_tampering` | passed |
| 61 | Source isolation | `tests/integration/test_git_source.py::test_061_dirty_staged_untracked_and_ignored_checkout_state_is_excluded` | passed |
| 62 | No publication | `tests/integration/test_runner.py::test_062_runner_has_no_publication_side_effect_and_prompts_prohibit_it` | passed |
| 63 | Stable exits | `tests/unit/test_errors.py::test_063_stable_exits` exhaustively compares every `StopReason` member with its documented stable category | passed |
| 64 | Model record | `tests/integration/test_runner.py::test_064_exact_requested_model_and_effort_must_match_observed_facts` and `tests/unit/test_schema_documents.py::test_064_run_record_contains_requested_and_observed_models_effort_usage_and_cost` | passed |
| 65 | Git-less first turn and resume | `tests/real_cli/test_live_codex_acceptance.py::test_033_065_066_live_profile_gitless_exact_resume_and_marker_isolation` | blocked |
| 66 | Project-instruction isolation | `tests/real_cli/test_codex_cli.py::test_066_pinned_prompt_input_probe_ignores_additional_root_instructions` passed; combined first/resume live node remains | blocked |
| 67 | Auth refresh persistence and serialization | both `test_067_*` cases in `tests/integration/test_credentials.py` plus `tests/integration/test_runtime_adapters.py::test_067_external_fake_refresh_is_reconciled_before_adapter_returns` | passed |
| 68 | Withheld semantic delta | `tests/unit/test_prompts.py` (`test_068_*`) and both counterfactual `test_068_*` cases in `tests/integration/test_runner.py` | passed |
| 69 | Validation-log exfiltration | `tests/adversarial/test_declassify.py::test_069_validation_log_exfiltration` and the exact/split/base64/lowercase-hex/uppercase-hex parameterizations of `tests/integration/test_runner.py::test_069_secret_forms_never_cross_validation_to_either_agent` | passed |
| 70 | Diagnostic patch correctness | `tests/unit/test_diagnostic_patch.py::test_070_projection_exactly_covers_all_manifest_change_shapes_and_hashes` | passed |
| 71 | Transient-service lifecycle | `tests/host/test_service.py::test_071_transient_service_lifecycle` | passed |
| 72 | Claude automation token | all `test_072_*` cases in `tests/integration/test_credentials.py` and `tests/integration/test_runtime_adapters.py::test_072_claude_token_encoding_cannot_enter_retained_envelope`; real managed-child scrubbing is asserted only by the unrun live gate 49 | partial; live blocked |

The matrix therefore records 64 passed contracts, three partial contracts, and five blocked
contracts. Partial and blocked contracts are not completion.

The blocked and partial rows have deterministic adapter and negative-policy coverage. Their
unproved portions require real trusted-control model egress, generated-command behavior from the
pinned Codex service, the real managed Claude child, or (for acceptance 51) a pinned-Claude retry
behavior probe. Local simulation is not treated as completion.

## Implementation decisions within non-normative freedom

- Runtime implementation uses the Python standard library. Total local parsers enforce the
  versioned JSON documents at runtime; the development suite additionally validates those documents
  with `jsonschema` Draft 2020-12.
- Canonical manifest and blob hashes use SHA-256. Canonical manifest bytes use a versioned,
  length-prefixed binary encoding over raw path and symlink-target bytes. JSON artifacts retain
  base64 identity plus deterministic safe display strings.
- Git source authority, reviewed mount roots, and retained closure traversal are descriptor-bound.
  Component-wise `openat2`/no-follow checks, stable metadata witnesses, exact-fd Bubblewrap binds,
  and private read-only closure snapshots close pathname replacement races before launch.
- The runtime provenance digest covers Python source only and rejects executable shadow payloads;
  harmless `__pycache__/*.pyc` files and install location do not alter the receipt binding. The
  sandbox imports the reviewed runtime through a source-only loader.
- Validation runs all fixed checks sequentially inside one fresh full-tmpfs workspace, cleans
  descendants between checks, stops only at a terminal infrastructure/timeout/output condition, and
  exports one final mutation manifest. Output-limit evidence is journaled before its typed stop.
- Predeclared opaque paths require a durable operator assertion and an exact baseline/current
  counterfactual validation-behavior proof before any delta may be omitted from Claude's bundle.
- Before credentials are loaded, committed-source blobs remain in a bounded memory-only store and
  durable run metadata contains only content-free pending markers. Configuration, task, source, and
  structural fingerprints are released only after the initial and post-preparation credential
  generations are scanned; a colliding fingerprint is withheld from operator output.
- Every newly observed Codex credential generation is checked against generated configuration and
  the complete retained tree before the transaction is accepted. Final reconciliation repeats that
  barrier over all historical/current generations before credential completion.
- Credential-tainted or unclassifiable evidence is whole-run withheld. A zero-byte per-run latch in
  a private, structurally separate control directory is persisted before erasure; a reentrant
  process lock plus per-run `flock` serializes the latch with artifact and production retained-tree
  operations. Reopen replays interrupted erasure and refuses access. A transient marker failure is
  retried after best-effort erasure; even persistent marker failure still attempts complete erasure
  and returns a fatal credential-refresh error.
- The live receipt names all eleven target-host/live acceptance gates and can be written only from a
  single clean pytest session. Its per-session ledger rejects skips, xfails, xpasses, failures,
  missing phases, stale observations, selector mismatch, or changed install/runtime closure.
- Rename diagnostics are deterministic delete/create pairs with matching kind, mode, and content
  identity; canonical manifests do not claim Git rename history.

## Remaining prerequisites, implementation work, and exact reproduction

The receipt-bound live proof requires deliberate operator action:

1. Provision the two private credential identifiers and exact install roots described in `README.md`.
2. Have an administrator provision the reviewed Claude managed hook/status/file-suggestion process
   and its non-secret `attested-v1` marker.
3. Review the displayed accounts, exact models/efforts, expected two Codex calls plus one Claude
   call, timeouts, and cost; then set both `AGENT_LOOP_CONFIRM_PAID_*` variables.
4. Export every exact selector in the README and run this single command on the frozen host:

   ```bash
   python3.14 -m pytest -q tests/host tests/real_cli
   ```

Running individual live nodes is useful for diagnosis but cannot mint a production receipt. The
combined session must have zero skips, xfails, xpasses, failures, or missing required phases. A
receipt is necessary for production execution, but is not evidence for the acceptance-51 retry
clause and does not complete the static-analysis or clean-install work.

Ruff, mypy, Hypothesis, and pytest-cov are not installed on this host. The importable `build`
namespace also lacks its executable `build.__main__` frontend. No package was fetched to add any of
them; the offline wheel proof instead used the installed pinned setuptools through pip with index,
cache, build isolation, and dependency resolution disabled. This demonstrates a local wheel build,
not a clean installation or an artifact-hash lock for the build dependency. Once the development
tools are provided through a reviewed dependency workflow, run:

```bash
ruff format --check .
ruff check .
mypy src tests
```

The executable-fake Phase 3 matrix covers the required behavior families; fine-grained invalid
Claude schema fields are enforced compositionally by the same local parser/schema layer rather than
claimed as one fake process per rule. Acceptance 51 still needs an explicit pinned-Claude
behavioral proof before its simulated retry coverage can be promoted to passed. Finally, build and
install the reviewed wheel in a clean environment and verify exactly `run`, `status`, and `show`;
the existing offline wheel build alone does not satisfy that definition-of-done clause.

## Check log

| Date | Command | Result |
|---|---|---|
| 2026-07-19 | environment/version/provenance inspection | passed; exact values recorded above |
| 2026-07-20 | `python3.14 -m pytest --collect-only -q` | passed; 542 tests collected |
| 2026-07-20 | `python3.14 -m pytest -q -m 'not host and not real_cli'` | passed; 516 passed, 26 deselected |
| 2026-07-20 | `python3.14 -m pytest -q -m host` | passed; 22 passed, 520 deselected |
| 2026-07-20 | `python3.14 -m pytest -q tests/host` | passed; 21 passed |
| 2026-07-19 | `AGENT_LOOP_ALLOW_LIVE=1 AGENT_LOOP_CODEX_CREDENTIAL_ID=nonmodel-probe AGENT_LOOP_CODEX_PATH=/home/bahram/.npm-global/lib/node_modules/@openai/codex/bin/codex.js python3.14 -m pytest -q tests/real_cli/test_codex_cli.py::test_pinned_codex_non_model_version_and_help_capabilities tests/real_cli/test_codex_cli.py::test_066_pinned_prompt_input_probe_ignores_additional_root_instructions` | passed; 2 passed |
| 2026-07-20 | `python3.14 -m pytest -q -m 'not real_cli'` | passed; 538 passed, 4 deselected |
| 2026-07-20 | `python3.14 -m compileall -q src tests` | passed |
| 2026-07-19 | `python3.14 -m build` | blocked; installed namespace has no `build.__main__`; no install attempted |
| 2026-07-20 | `PIP_NO_INDEX=1 python3.14 -m pip wheel . --no-cache-dir --no-build-isolation --no-deps --wheel-dir "$(mktemp -d)"` | passed; wheel built offline and packaged the frozen plan, status, schemas, and console entry point; no clean install performed |
| 2026-07-19 | wheel content inspection and `PYTHONPATH=src python3.14 -m agent_loop.cli --help` | passed; package data present and exactly `run`, `status`, `show` exposed |

The credentialed Codex/Claude smoke nodes were not run. Their blocked status is intentional until
the external prerequisites above are supplied and paid traffic is explicitly authorized.
